"""
Unit tests for SentinelOne Singularity EDR Collector.
"""
import pytest
from collectors.edr.sentinelone_collector import (
    normalize_sentinelone_event,
    SentinelOneCollector,
    SAMPLE_S1_LOGS,
)


class TestSentinelOneCollector:
    def test_normalize_process_creation(self):
        raw = {
            "eventType": "Process Creation",
            "createdAt": "2026-08-30T00:00:00Z",
            "agentDetectionInfo": {"agentComputerName": "HR-WORKSTATION-01"},
            "processInfo": {
                "processName": "powershell.exe",
                "parentProcessName": "excel.exe",
                "processUser": "hr_user",
                "commandLine": "powershell.exe -w hidden -c (New-Object Net.WebClient)...",
                "sha256": "11223344556677889900aabbccddeeff",
            },
        }
        event = normalize_sentinelone_event(raw)
        assert event["source"] == "sentinelone_edr"
        assert event["event_type"] == "process_created"
        assert event["host"] == "HR-WORKSTATION-01"
        assert event["user"] == "hr_user"
        assert event["process"] == "powershell.exe"
        assert event["parent_process"] == "excel.exe"
        assert event["hash"] == "11223344556677889900aabbccddeeff"

    def test_normalize_ip_connect(self):
        raw = {
            "eventType": "IP Connect",
            "createdAt": "2026-08-30T00:01:00Z",
            "agentDetectionInfo": {"agentComputerName": "HR-WORKSTATION-01"},
            "processInfo": {"processName": "powershell.exe", "processUser": "hr_user"},
            "networkInfo": {"srcIp": "10.0.1.50", "srcPort": 49999, "dstIp": "185.220.101.5", "dstPort": 4444},
        }
        event = normalize_sentinelone_event(raw)
        assert event["event_type"] == "network_connection"
        assert event["src_ip"] == "10.0.1.50"
        assert event["src_port"] == 49999
        assert event["dst_ip"] == "185.220.101.5"
        assert event["dst_port"] == 4444

    def test_normalize_threat_mitigation(self):
        raw = {
            "eventType": "Threat Mitigation",
            "createdAt": "2026-08-30T00:02:00Z",
            "agentDetectionInfo": {"agentComputerName": "HR-WORKSTATION-01"},
            "mitigationStatus": "success",
        }
        event = normalize_sentinelone_event(raw)
        assert event["event_type"] == "host_containment"

    def test_sentinelone_collector_dry_run(self):
        collector = SentinelOneCollector(dry_run=True)
        stats = collector.run_once()
        assert stats["events_found"] == len(SAMPLE_S1_LOGS)
        assert stats["events_shipped"] == len(SAMPLE_S1_LOGS)
