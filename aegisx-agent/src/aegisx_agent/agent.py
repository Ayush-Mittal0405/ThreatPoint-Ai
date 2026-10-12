"""
Agent runtime — ties config, enrollment, collectors, buffering, transport and
heartbeat into a single cooperative loop.

Responsibilities (see task spec §5.1):
  start automatically, load config, authenticate/enroll, collect telemetry,
  normalize, buffer when offline, send securely, heartbeat, retry with backoff,
  stay lightweight, log operations, and shut down gracefully.
"""
from __future__ import annotations

import socket
import threading
import time
from datetime import datetime, timezone
from typing import List, Optional

from . import __version__
from .buffer import EventBuffer
from .config import Config
from .enrollment import ensure_enrolled
from .health import self_cpu_percent, self_memory_percent
from .normalize import normalize_event
from .state import StateStore
from .transport import AgentCredentials, PermanentError, Transport, TransportError
from .collectors import (
    ProcessCollector, NetworkCollector, EventLogCollector, PersistenceCollector,
)


class AgentRunner:
    def __init__(self, config: Config, logger, transport: Optional[Transport] = None):
        config.validate()
        self.config = config
        self.log = logger
        self.hostname = socket.gethostname()
        self.store = StateStore(config.state_dir)
        self.transport = transport or Transport(config, logger)
        self.buffer = EventBuffer(
            path=str(__import__("pathlib").Path(config.state_dir) / "buffer.jsonl"),
            max_events=config.agent.buffer_max_events,
        )
        self.creds: Optional[AgentCredentials] = None
        self._stop = threading.Event()
        self.collectors = self._build_collectors()

    def _build_collectors(self) -> list:
        c = self.config.collectors
        built = []
        if c.process:
            built.append(ProcessCollector(self.log, include_command_line=True))
        if c.network:
            built.append(NetworkCollector(self.log))
        if c.eventlog or c.authentication:
            built.append(EventLogCollector(self.log))
        if c.persistence:
            built.append(PersistenceCollector(self.log))
        active = [col for col in built if col.supported]
        self.log.info("Collectors enabled: %s",
                      ", ".join(col.name for col in active) or "(none supported on this platform)")
        return active

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def stop(self) -> None:
        self.log.info("Shutdown requested")
        self._stop.set()

    def run(self) -> None:
        self.log.info("AegisX agent %s starting on host %s", __version__, self.hostname)
        self.creds = ensure_enrolled(self.config, self.store, self.transport, self.log)

        next_collect = 0.0
        next_flush = 0.0
        next_heartbeat = 0.0

        while not self._stop.is_set():
            now = time.monotonic()
            try:
                if now >= next_collect:
                    self._do_collect()
                    next_collect = now + self.config.agent.collect_interval_seconds
                if now >= next_flush:
                    self._do_flush()
                    next_flush = now + self.config.agent.flush_interval_seconds
                if now >= next_heartbeat:
                    self._do_heartbeat()
                    next_heartbeat = now + self.config.agent.heartbeat_interval_seconds
            except Exception as exc:  # pragma: no cover - loop must never die
                self.log.error("main loop error: %s", exc)

            self._stop.wait(1.0)

        self._graceful_shutdown()

    # ── Work units ────────────────────────────────────────────────────────────

    def _do_collect(self) -> None:
        collected = 0
        for col in self.collectors:
            for raw in col.safe_collect():
                self.buffer.enqueue(normalize_event(raw, default_host=self.hostname))
                collected += 1
        if collected:
            self.log.info("Collected %d events (buffer=%d)", collected, self.buffer.size)
            self.buffer.persist()

    def _do_flush(self) -> None:
        if not self.creds or self.buffer.size == 0:
            return
        batch = self.buffer.peek_batch(self.config.agent.batch_size)
        try:
            resp = self.transport.send_events(self.creds, batch)
        except PermanentError as exc:
            # e.g. auth revoked or malformed batch — drop this batch to avoid a poison loop.
            self.log.error("Dropping %d events after permanent error: %s", len(batch), exc)
            self.buffer.commit(len(batch))
            self.buffer.persist()
            return
        except TransportError as exc:
            self.log.warning("Server unavailable, %d events buffered: %s", self.buffer.size, exc)
            return
        accepted = resp.get("accepted", len(batch))
        self.buffer.commit(len(batch))
        self.buffer.persist()
        self.log.info("Uploaded %d events (buffer=%d)", accepted, self.buffer.size)

    def _do_heartbeat(self) -> None:
        if not self.creds:
            return
        body = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_version": __version__,
            "status": "healthy",
            "cpu_usage_pct": self_cpu_percent(),
            "memory_usage_pct": self_memory_percent(),
            "queued_events": self.buffer.size,
        }
        try:
            resp = self.transport.heartbeat(self.creds, body)
            self.log.info("Heartbeat ok (server status=%s, buffer=%d)",
                          resp.get("status"), self.buffer.size)
        except PermanentError as exc:
            self.log.error("Heartbeat rejected: %s", exc)
        except TransportError as exc:
            self.log.warning("Heartbeat failed (will retry): %s", exc)

    def _graceful_shutdown(self) -> None:
        self.log.info("Flushing buffer before exit (%d queued)", self.buffer.size)
        try:
            self._do_flush()
        except Exception:
            pass
        self.buffer.persist()
        self.log.info("AegisX agent stopped")
