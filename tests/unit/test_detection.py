"""
Unit tests for the Detection Engine.
Tests all 5 built-in behavioral rules.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timezone

from app.detection.engine import DetectionEngine, _builtin_behavioral_rules
from app.models.models import NormalizedEvent


def _make_event(**kwargs) -> NormalizedEvent:
    """Helper to create a NormalizedEvent with defaults."""
    defaults = {
        "id": None,
        "event_id": "test-001",
        "timestamp": datetime.now(timezone.utc),
        "source": "sysmon",
        "event_type": "process_creation",
        "host": "LAB-WIN-01",
        "user": "lab-user",
        "process": None,
        "parent_process": None,
        "command_line": None,
        "file_path": None,
        "hash_md5": None,
        "hash_sha256": None,
        "src_ip": None,
        "dst_ip": None,
        "dst_port": None,
        "domain": None,
        "raw": None,
    }
    defaults.update(kwargs)
    return NormalizedEvent(**defaults)



class TestOfficeSpawnsShell:
    def test_word_spawns_powershell(self):
        rules = _builtin_behavioral_rules()
        rule = next(r for r in rules if "Office" in r["title"])
        ev = _make_event(parent_process="winword.exe", process="powershell.exe")
        assert rule["matcher"](ev) is True

    def test_excel_spawns_cmd(self):
        rules = _builtin_behavioral_rules()
        rule = next(r for r in rules if "Office" in r["title"])
        ev = _make_event(parent_process="excel.exe", process="cmd.exe")
        assert rule["matcher"](ev) is True

    def test_normal_process_not_flagged(self):
        rules = _builtin_behavioral_rules()
        rule = next(r for r in rules if "Office" in r["title"])
        ev = _make_event(parent_process="explorer.exe", process="notepad.exe")
        assert rule["matcher"](ev) is False

    def test_wrong_event_type_not_flagged(self):
        rules = _builtin_behavioral_rules()
        rule = next(r for r in rules if "Office" in r["title"])
        ev = _make_event(event_type="network_connection", parent_process="winword.exe", process="powershell.exe")
        assert rule["matcher"](ev) is False


class TestEncodedPowerShell:
    def test_encoded_command_flagged(self):
        rules = _builtin_behavioral_rules()
        rule = next(r for r in rules if "Encoded" in r["title"])
        ev = _make_event(process="powershell.exe", command_line="powershell.exe -enc SGVsbG8gV29ybGQ=")
        assert rule["matcher"](ev) is True

    def test_encodedcommand_long_form(self):
        rules = _builtin_behavioral_rules()
        rule = next(r for r in rules if "Encoded" in r["title"])
        ev = _make_event(process="powershell.exe", command_line="powershell -EncodedCommand SGVs")
        assert rule["matcher"](ev) is True

    def test_normal_powershell_not_flagged(self):
        rules = _builtin_behavioral_rules()
        rule = next(r for r in rules if "Encoded" in r["title"])
        ev = _make_event(process="powershell.exe", command_line="powershell.exe -NoProfile Get-Date")
        assert rule["matcher"](ev) is False


class TestSuspiciousOutboundPort:
    def test_port_4444_flagged(self):
        rules = _builtin_behavioral_rules()
        rule = next(r for r in rules if "C2 Port" in r["title"])
        ev = _make_event(event_type="network_connection", dst_port=4444)
        assert rule["matcher"](ev) is True

    def test_port_1337_flagged(self):
        rules = _builtin_behavioral_rules()
        rule = next(r for r in rules if "C2 Port" in r["title"])
        ev = _make_event(event_type="network_connection", dst_port=1337)
        assert rule["matcher"](ev) is True

    def test_port_443_not_flagged(self):
        rules = _builtin_behavioral_rules()
        rule = next(r for r in rules if "C2 Port" in r["title"])
        ev = _make_event(event_type="network_connection", dst_port=443)
        assert rule["matcher"](ev) is False


class TestSuspiciousExecutablePath:
    def test_temp_path_flagged(self):
        rules = _builtin_behavioral_rules()
        rule = next(r for r in rules if "Suspicious Path" in r["title"])
        ev = _make_event(file_path="C:\\Users\\user\\AppData\\payload.exe")
        assert rule["matcher"](ev) is True

    def test_normal_path_not_flagged(self):
        rules = _builtin_behavioral_rules()
        rule = next(r for r in rules if "Suspicious Path" in r["title"])
        ev = _make_event(file_path="C:\\Windows\\System32\\notepad.exe")
        assert rule["matcher"](ev) is False

    def test_no_path_not_flagged(self):
        rules = _builtin_behavioral_rules()
        rule = next(r for r in rules if "Suspicious Path" in r["title"])
        ev = _make_event(file_path=None)
        assert rule["matcher"](ev) is False
