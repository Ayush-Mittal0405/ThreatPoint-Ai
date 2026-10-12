"""
Unit tests for the endpoint-agent service layer (identity, credentials,
status computation, enrollment-token validity, telemetry mapping).

These are pure functions — no DB or network required, matching the project's
existing test conventions.
"""
import re
from datetime import datetime, timedelta, timezone

import pytest

from app.services import endpoint_agents as svc


# ─── Identity & credentials ───────────────────────────────────────────────────

class TestIdentity:
    def test_agent_id_format(self):
        aid = svc.generate_agent_id()
        assert re.fullmatch(r"AGT-[0-9A-F]{8}", aid)

    def test_agent_ids_unique(self):
        ids = {svc.generate_agent_id() for _ in range(500)}
        assert len(ids) == 500  # collision-resistant

    def test_secret_token_is_high_entropy(self):
        t1, t2 = svc.generate_secret_token(), svc.generate_secret_token()
        assert t1 != t2
        assert len(t1) >= 32

    def test_hash_is_deterministic_and_hex(self):
        h = svc.hash_token("hello")
        assert h == svc.hash_token("hello")
        assert re.fullmatch(r"[0-9a-f]{64}", h)

    def test_hash_does_not_contain_plaintext(self):
        secret = "super-secret-token"
        assert secret not in svc.hash_token(secret)

    def test_verify_token_roundtrip(self):
        token = svc.generate_secret_token()
        h = svc.hash_token(token)
        assert svc.verify_token(token, h) is True
        assert svc.verify_token("wrong", h) is False

    def test_verify_token_rejects_empty(self):
        assert svc.verify_token("", "abc") is False
        assert svc.verify_token("abc", "") is False


# ─── Status computation ───────────────────────────────────────────────────────

class TestStatus:
    def _now(self):
        return datetime(2026, 9, 3, 12, 0, 0, tzinfo=timezone.utc)

    def test_recent_heartbeat_is_online(self):
        last = self._now() - timedelta(seconds=10)
        s = svc.compute_status(last, now=self._now(), warning_after_s=90, offline_after_s=180)
        assert s == "online"

    def test_stale_heartbeat_is_warning(self):
        last = self._now() - timedelta(seconds=100)
        s = svc.compute_status(last, now=self._now(), warning_after_s=90, offline_after_s=180)
        assert s == "warning"

    def test_very_stale_heartbeat_is_offline(self):
        last = self._now() - timedelta(seconds=300)
        s = svc.compute_status(last, now=self._now(), warning_after_s=90, offline_after_s=180)
        assert s == "offline"

    def test_unhealthy_health_flag(self):
        last = self._now() - timedelta(seconds=10)
        s = svc.compute_status(last, now=self._now(), warning_after_s=90, offline_after_s=180,
                               health="unhealthy")
        assert s == "unhealthy"

    def test_revoked_wins(self):
        last = self._now() - timedelta(seconds=10)
        s = svc.compute_status(last, now=self._now(), warning_after_s=90, offline_after_s=180,
                               revoked=True)
        assert s == "revoked"

    def test_naive_last_seen_is_handled(self):
        last = datetime(2026, 9, 3, 11, 59, 50)  # naive
        s = svc.compute_status(last, now=self._now(), warning_after_s=90, offline_after_s=180)
        assert s == "online"


# ─── Enrollment token validity ────────────────────────────────────────────────

class TestEnrollmentTokenValidity:
    def _future(self):
        return datetime.now(timezone.utc) + timedelta(hours=1)

    def test_valid_token(self):
        assert svc.is_enrollment_token_valid(
            revoked=False, used_count=0, max_uses=1, expires_at=self._future()) is True

    def test_expired_token(self):
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        assert svc.is_enrollment_token_valid(
            revoked=False, used_count=0, max_uses=1, expires_at=past) is False

    def test_used_up_token(self):
        assert svc.is_enrollment_token_valid(
            revoked=False, used_count=1, max_uses=1, expires_at=self._future()) is False

    def test_revoked_token(self):
        assert svc.is_enrollment_token_valid(
            revoked=True, used_count=0, max_uses=1, expires_at=self._future()) is False

    def test_multi_use_token(self):
        assert svc.is_enrollment_token_valid(
            revoked=False, used_count=3, max_uses=10, expires_at=self._future()) is True


# ─── Telemetry mapping ────────────────────────────────────────────────────────

class TestTelemetryMapping:
    def test_maps_dict_event_and_tags_agent(self):
        ev = {
            "event_type": "Process_Creation",
            "timestamp": "2026-09-03T12:00:00Z",
            "process": "powershell.exe",
            "parent_process": "winword.exe",
            "command_line": "powershell -enc AAAA",
        }
        raw = svc.agent_event_to_raw_dict(ev, "AGT-DEADBEEF")
        assert raw["agent_id"] == "AGT-DEADBEEF"
        assert raw["source"] == svc.AGENT_SOURCE
        assert raw["event_type"] == "process_creation"  # normalized to lower
        assert raw["process"] == "powershell.exe"

    def test_maps_object_event(self):
        class E:
            event_type = "network_connection"
            timestamp = "2026-09-03T12:00:00Z"
            dst_ip = "185.220.101.5"
            dst_port = 4444
        raw = svc.agent_event_to_raw_dict(E(), "AGT-1")
        assert raw["dst_port"] == 4444
        assert raw["event_type"] == "network_connection"

    def test_canonical_event_types_present(self):
        assert "process_creation" in svc.CANONICAL_EVENT_TYPES
        assert "network_connection" in svc.CANONICAL_EVENT_TYPES
        assert "authentication" in svc.CANONICAL_EVENT_TYPES
