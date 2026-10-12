"""
Unit tests for Microsoft Defender for Endpoint Collector.
"""
import pytest
from collectors.edr.defender_collector import (
    normalize_defender_event,
    DefenderCollector,
    SAMPLE_DEFENDER_LOGS,
)


class TestDefenderCollector:
    def test_normalize_device_process_event(self):
        raw = {
            "TableName": "DeviceProcessEvents",
            "ActionType": "ProcessCreated",
            "Timestamp": "2026-08-30T00:00:00Z",
            "DeviceName": "CORP-WIN11-DEV",
            "AccountName": "alex",
            "FileName": "cmd.exe",
            "InitiatingProcessFileName": "explorer.exe",
            "ProcessCommandLine": "cmd.exe /c whoami",
            "SHA256": "abcdef123456",
        }
        event = normalize_defender_event(raw)
        assert event["source"] == "microsoft_defender_edr"
        assert event["event_type"] == "process_created"
        assert event["host"] == "CORP-WIN11-DEV"
        assert event["user"] == "alex"
        assert event["process"] == "cmd.exe"
        assert event["parent_process"] == "explorer.exe"
        assert event["command_line"] == "cmd.exe /c whoami"
        assert event["hash"] == "abcdef123456"

    def test_normalize_device_network_event(self):
        raw = {
            "TableName": "DeviceNetworkEvents",
            "ActionType": "ConnectionSuccess",
            "Timestamp": "2026-08-30T00:01:00Z",
            "DeviceName": "CORP-WIN11-DEV",
            "AccountName": "alex",
            "FileName": "curl.exe",
            "LocalIP": "192.168.1.10",
            "LocalPort": 51000,
            "RemoteIP": "185.220.101.5",
            "RemotePort": 443,
        }
        event = normalize_defender_event(raw)
        assert event["event_type"] == "network_connection"
        assert event["src_ip"] == "192.168.1.10"
        assert event["dst_ip"] == "185.220.101.5"
        assert event["dst_port"] == 443

    def test_normalize_device_logon_event(self):
        raw = {
            "TableName": "DeviceLogonEvents",
            "ActionType": "LogonFailed",
            "Timestamp": "2026-08-30T00:02:00Z",
            "DeviceName": "CORP-WIN11-DEV",
            "AccountName": "guest",
        }
        event = normalize_defender_event(raw)
        assert event["event_type"] == "user_logon_failed"
        assert event["user"] == "guest"

    def test_defender_collector_dry_run(self):
        collector = DefenderCollector(dry_run=True)
        stats = collector.run_once()
        assert stats["events_found"] == len(SAMPLE_DEFENDER_LOGS)
        assert stats["events_shipped"] == len(SAMPLE_DEFENDER_LOGS)
