"""
Unit tests for the normalization service.
"""
import pytest
from datetime import datetime, timezone

from app.services.normalization import _make_event_id, _normalize
from app.schemas.telemetry import RawEventIn


def _make_raw(**kwargs) -> RawEventIn:
    defaults = {
        "source": "sysmon",
        "event_type": "process_creation",
        "timestamp": datetime(2026, 8, 18, 10, 0, 0, tzinfo=timezone.utc),
        "host": "LAB-WIN-01",
        "user": "lab-user",
        "process": "powershell.exe",
        "parent_process": "winword.exe",
        "command_line": "-enc SGVsbG8=",
    }
    defaults.update(kwargs)
    return RawEventIn(**defaults)


class TestEventId:
    def test_same_inputs_same_id(self):
        e1 = _make_raw()
        e2 = _make_raw()
        assert _make_event_id(e1) == _make_event_id(e2)

    def test_different_host_different_id(self):
        e1 = _make_raw(host="HOST-A")
        e2 = _make_raw(host="HOST-B")
        assert _make_event_id(e1) != _make_event_id(e2)

    def test_different_cmd_different_id(self):
        e1 = _make_raw(command_line="cmd1")
        e2 = _make_raw(command_line="cmd2")
        assert _make_event_id(e1) != _make_event_id(e2)

    def test_id_is_32_chars(self):
        e = _make_raw()
        assert len(_make_event_id(e)) == 32


class TestNormalize:
    def test_source_lowercased(self):
        e = _make_raw(source="SYSMON")
        n = _normalize(e)
        assert n.source == "sysmon"

    def test_event_type_lowercased(self):
        e = _make_raw(event_type="Process_Creation")
        n = _normalize(e)
        assert n.event_type == "process_creation"

    def test_timezone_added_if_missing(self):
        naive_ts = datetime(2026, 8, 18, 10, 0, 0)
        e = _make_raw(timestamp=naive_ts)
        n = _normalize(e)
        assert n.timestamp.tzinfo is not None

    def test_fields_preserved(self):
        e = _make_raw()
        n = _normalize(e)
        assert n.host == "LAB-WIN-01"
        assert n.user == "lab-user"
        assert n.process == "powershell.exe"
        assert n.parent_process == "winword.exe"
        assert n.command_line == "-enc SGVsbG8="

    def test_raw_preserved(self):
        e = _make_raw()
        e.raw = {"key": "value"}
        n = _normalize(e)
        assert n.raw == {"key": "value"}
