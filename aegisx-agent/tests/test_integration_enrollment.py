"""
End-to-end agent integration test against a fake AegisX server.

Spins up a real HTTP server that implements the /api/v1/endpoints contract
(enroll, heartbeat, events) and drives the agent's actual Transport, enrollment,
state store, and offline buffer against it — exercising the real networking,
auth headers, retry path, and buffering code (no mocks of the agent internals).
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from aegisx_agent.config import Config
from aegisx_agent.state import StateStore
from aegisx_agent.transport import Transport, TransportError
from aegisx_agent.enrollment import ensure_enrolled
from aegisx_agent.buffer import EventBuffer


VALID_ENROLL_TOKEN = "enroll-secret-123"


class _Handler(BaseHTTPRequestHandler):
    received_events = []
    heartbeats = []
    issued = {}
    fail_events_times = 0  # transient failures to simulate before succeeding

    def log_message(self, *args):
        pass  # silence

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n) or b"{}")

    def do_POST(self):
        path = self.path
        if path.endswith("/endpoints/enroll"):
            body = self._read_body()
            if body.get("enrollment_token") != VALID_ENROLL_TOKEN:
                return self._json(401, {"detail": "bad token"})
            _Handler.issued = {"agent_id": "AGT-TEST01", "agent_token": "agent-cred-xyz"}
            return self._json(201, {
                "agent_id": "AGT-TEST01",
                "agent_token": "agent-cred-xyz",
                "heartbeat_interval_seconds": 30,
                "server_time": "2026-09-03T12:00:00Z",
            })

        # Auth-protected routes
        auth = self.headers.get("Authorization", "")
        agent_id = self.headers.get("X-Agent-Id", "")
        if agent_id != _Handler.issued.get("agent_id") or \
                auth != f"Bearer {_Handler.issued.get('agent_token')}":
            return self._json(401, {"detail": "auth failed"})

        if path.endswith("/endpoints/heartbeat"):
            _Handler.heartbeats.append(self._read_body())
            return self._json(200, {"agent_id": agent_id, "status": "online",
                                    "server_time": "2026-09-03T12:00:00Z",
                                    "heartbeat_interval_seconds": 30})

        if path.endswith("/endpoints/events"):
            if _Handler.fail_events_times > 0:
                _Handler.fail_events_times -= 1
                return self._json(503, {"detail": "unavailable"})
            body = self._read_body()
            _Handler.received_events.extend(body.get("events", []))
            return self._json(202, {"accepted": len(body.get("events", [])), "agent_id": agent_id})

        return self._json(404, {"detail": "not found"})


@pytest.fixture
def server():
    _Handler.received_events = []
    _Handler.heartbeats = []
    _Handler.issued = {}
    _Handler.fail_events_times = 0
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def _config(server_url, tmp_path, token=VALID_ENROLL_TOKEN):
    return Config.from_dict({
        "server": {"url": server_url},
        "agent": {"batch_size": 10, "buffer_max_events": 100},
        "enrollment": {"token": token},
        "state_dir": str(tmp_path),
    })


def test_full_enroll_heartbeat_and_event_flow(server, tmp_path):
    cfg = _config(server, tmp_path)
    cfg.validate()
    log = _NullLog()
    transport = Transport(cfg, log)
    store = StateStore(cfg.state_dir)

    # 1. Enrollment persists a real credential.
    creds = ensure_enrolled(cfg, store, transport, log)
    assert creds.agent_id == "AGT-TEST01"
    assert store.load().enrolled is True

    # 2. Heartbeat is accepted with the auth headers.
    hb = transport.heartbeat(creds, {"status": "healthy", "queued_events": 0})
    assert hb["status"] == "online"
    assert len(_Handler.heartbeats) == 1

    # 3. Events flow from the buffer to the server.
    buf = EventBuffer(str(tmp_path / "buffer.jsonl"), max_events=100)
    buf.enqueue({"event_type": "process_creation", "process": "powershell.exe",
                 "timestamp": "2026-09-03T12:00:00Z"})
    batch = buf.peek_batch(10)
    resp = transport.send_events(creds, batch)
    buf.commit(len(batch))
    assert resp["accepted"] == 1
    assert buf.size == 0
    assert _Handler.received_events[0]["process"] == "powershell.exe"


def test_re_enroll_is_skipped_when_state_present(server, tmp_path):
    cfg = _config(server, tmp_path)
    log = _NullLog()
    transport = Transport(cfg, log)
    store = StateStore(cfg.state_dir)
    ensure_enrolled(cfg, store, transport, log)
    # Second call must not require the token again.
    cfg.enrollment_token = None
    creds2 = ensure_enrolled(cfg, store, transport, log)
    assert creds2.agent_id == "AGT-TEST01"


def test_transport_retries_transient_then_succeeds(server, tmp_path):
    cfg = _config(server, tmp_path)
    log = _NullLog()
    transport = Transport(cfg, log)
    store = StateStore(cfg.state_dir)
    creds = ensure_enrolled(cfg, store, transport, log)

    _Handler.fail_events_times = 2  # first two /events calls return 503
    resp = transport.send_events(creds, [{"event_type": "eventlog",
                                          "timestamp": "2026-09-03T12:00:00Z"}])
    assert resp["accepted"] == 1  # succeeded after retries


def test_bad_enroll_token_raises(server, tmp_path):
    cfg = _config(server, tmp_path, token="wrong-token")
    log = _NullLog()
    transport = Transport(cfg, log)
    store = StateStore(cfg.state_dir)
    with pytest.raises(Exception):
        ensure_enrolled(cfg, store, transport, log)


class _NullLog:
    def info(self, *a, **k): pass
    def warning(self, *a, **k): pass
    def error(self, *a, **k): pass
