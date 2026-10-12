"""
Unit tests for CrowdStrike Falcon EDR Collector.
"""
import pytest
from collectors.edr.crowdstrike_collector import (
    normalize_crowdstrike_event,
    CrowdStrikeCollector,
    SAMPLE_CROWDSTRIKE_LOGS,
)


class TestCrowdStrikeCollector:
    def test_normalize_process_rollup(self):
        raw = {
            "metadata": {"eventType": "ProcessRollup2"},
            "event": {
                "ComputerName": "CORP-WIN-99",
                "UserName": "jdoe",
                "ImageFileName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "ParentBaseFileName": "winword.exe",
                "CommandLine": "powershell.exe -ep bypass -file evil.ps1",
                "SHA256HashData": "aabbcc112233",
            },
        }
        event = normalize_crowdstrike_event(raw)
        assert event["source"] == "crowdstrike_edr"
        assert event["event_type"] == "process_created"
        assert event["host"] == "CORP-WIN-99"
        assert event["user"] == "jdoe"
        assert event["process"] == "powershell.exe"
        assert event["parent_process"] == "winword.exe"
        assert event["hash"] == "aabbcc112233"

    def test_normalize_network_connection(self):
        raw = {
            "metadata": {"eventType": "NetworkConnectIP4"},
            "event": {
                "ComputerName": "CORP-WIN-99",
                "UserName": "jdoe",
                "LocalAddressIP4": "10.0.0.5",
                "LocalPort": 51234,
                "RemoteAddressIP4": "185.220.101.5",
                "RemotePort": 4444,
            },
        }
        event = normalize_crowdstrike_event(raw)
        assert event["event_type"] == "network_connection"
        assert event["src_ip"] == "10.0.0.5"
        assert event["src_port"] == 51234
        assert event["dst_ip"] == "185.220.101.5"
        assert event["dst_port"] == 4444

    def test_normalize_host_isolation(self):
        raw = {
            "metadata": {"eventType": "HostIsolation"},
            "event": {"ComputerName": "CORP-WIN-99", "UserName": "SYSTEM"},
        }
        event = normalize_crowdstrike_event(raw)
        assert event["event_type"] == "host_containment"

    def test_crowdstrike_collector_dry_run(self):
        collector = CrowdStrikeCollector(dry_run=True)
        stats = collector.run_once()
        assert stats["events_found"] == len(SAMPLE_CROWDSTRIKE_LOGS)
        assert stats["events_shipped"] == len(SAMPLE_CROWDSTRIKE_LOGS)
