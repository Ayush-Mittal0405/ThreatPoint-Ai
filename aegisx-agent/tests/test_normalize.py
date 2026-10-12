from datetime import datetime, timezone

from aegisx_agent.normalize import normalize_event, CANONICAL_EVENT_TYPES


def test_lowercases_event_type_and_sets_defaults():
    out = normalize_event({"event_type": "Process_Creation"}, default_host="HOST-1")
    assert out["event_type"] == "process_creation"
    assert out["severity"] == "info"
    assert out["host"] == "HOST-1"
    assert "timestamp" in out


def test_datetime_timestamp_becomes_iso():
    ts = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)
    out = normalize_event({"event_type": "eventlog", "timestamp": ts})
    assert out["timestamp"].startswith("2026-09-03T12:00")


def test_unknown_keys_moved_to_raw():
    out = normalize_event({"event_type": "network_connection", "weird_field": 7, "raw": {"a": 1}})
    assert out["raw"]["weird_field"] == 7
    assert out["raw"]["a"] == 1


def test_dst_port_coerced_to_int():
    out = normalize_event({"event_type": "network_connection", "dst_port": "4444"})
    assert out["dst_port"] == 4444


def test_bad_dst_port_becomes_none():
    out = normalize_event({"event_type": "network_connection", "dst_port": "notaport"})
    assert out["dst_port"] is None


def test_canonical_types_align_with_server():
    # Sanity: agent-side canonical set matches the server's documented set.
    assert {"process_creation", "network_connection", "authentication",
            "persistence"} <= CANONICAL_EVENT_TYPES
