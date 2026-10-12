"""
SentinelOne Singularity EDR & Deep Visibility Telemetry Collector.

Collects and parses SentinelOne Deep Visibility query events and threat alerts,
normalizing process lifecycles, network socket events, and automated mitigations
into the AegisX NormalizedEvent schema.

Supported SentinelOne Event Types:
  - Process Creation: Endpoint process tree spawning (T1059)
  - IP Connect: Inbound / outbound network traffic (T1571)
  - DNS Query: Domain name resolution (T1071.004)
  - Threat Mitigation: Automated agent isolation / kill quarantine
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

try:
    import structlog
    log = structlog.get_logger()
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO)
    _std_log = logging.getLogger("sentinelone_collector")
    class _LoggerWrapper:
        def info(self, msg, **kwargs):
            kw_str = " ".join(f"{k}={v}" for k, v in kwargs.items())
            _std_log.info(f"{msg} {kw_str}".strip())
        def warning(self, msg, **kwargs):
            kw_str = " ".join(f"{k}={v}" for k, v in kwargs.items())
            _std_log.warning(f"{msg} {kw_str}".strip())
        def error(self, msg, **kwargs):
            kw_str = " ".join(f"{k}={v}" for k, v in kwargs.items())
            _std_log.error(f"{msg} {kw_str}".strip())
    log = _LoggerWrapper()


S1_EVENT_MAP = {
    "Process Creation": "process_created",
    "PROCESS_CREATION": "process_created",
    "IP Connect": "network_connection",
    "NETWORK_ACTION": "network_connection",
    "DNS Query": "dns_query",
    "DNS_ACTION": "dns_query",
    "File Creation": "file_event",
    "FILE_CREATION": "file_event",
    "Threat Mitigation": "host_containment",
    "AGENT_QUARANTINE": "host_containment",
}


def normalize_sentinelone_event(raw: Dict[str, Any], default_host: str = "s1-endpoint") -> Optional[Dict[str, Any]]:
    """Normalize a SentinelOne event into AegisX NormalizedEvent format."""
    event_type_s1 = raw.get("eventType") or raw.get("activityType") or "Process Creation"
    event_type = S1_EVENT_MAP.get(event_type_s1, "edr_event")

    # Agent & Host info
    agent_info = raw.get("agentDetectionInfo", {}) or raw.get("agentInfo", {})
    host = agent_info.get("agentComputerName") or raw.get("endpointName") or default_host

    # Process info
    proc_info = raw.get("processInfo", {})
    user = proc_info.get("processUser") or raw.get("user") or "SYSTEM"
    process = proc_info.get("processName") or raw.get("processName")
    parent_process = proc_info.get("parentProcessName") or raw.get("parentProcessName")
    cmd_line = proc_info.get("commandLine") or raw.get("commandLine")
    sha256 = proc_info.get("sha256") or raw.get("sha256")

    # Network info
    net_info = raw.get("networkInfo", {})
    src_ip = net_info.get("srcIp") or raw.get("srcIp")
    src_port = net_info.get("srcPort") or raw.get("srcPort")
    dst_ip = net_info.get("dstIp") or raw.get("dstIp")
    dst_port = net_info.get("dstPort") or raw.get("dstPort")

    timestamp = raw.get("createdAt") or raw.get("timestamp") or datetime.now(timezone.utc).isoformat()

    return {
        "source": "sentinelone_edr",
        "event_type": event_type,
        "timestamp": str(timestamp),
        "host": host,
        "user": user,
        "process": process,
        "parent_process": parent_process,
        "command_line": cmd_line,
        "src_ip": src_ip,
        "src_port": int(src_port) if src_port else None,
        "dst_ip": dst_ip,
        "dst_port": int(dst_port) if dst_port else None,
        "hash": sha256,
        "raw": {
            "s1_event_type": event_type_s1,
            "threat_id": raw.get("threatId"),
            "agent_id": agent_info.get("agentId"),
            "mitigation_status": raw.get("mitigationStatus"),
        },
    }


# ── Sample Synthetic SentinelOne Logs ─────────────────────────────────────────

SAMPLE_S1_LOGS: List[Dict[str, Any]] = [
    {
        "eventType": "Process Creation",
        "threatId": "s1-th-8821",
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "agentDetectionInfo": {"agentComputerName": "FINANCE-PC-01", "agentId": "agent-00123"},
        "processInfo": {
            "processName": "powershell.exe",
            "parentProcessName": "winword.exe",
            "processUser": "finance_analyst",
            "commandLine": "powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgA...",
            "sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
        },
    },
    {
        "eventType": "IP Connect",
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "agentDetectionInfo": {"agentComputerName": "FINANCE-PC-01"},
        "processInfo": {"processName": "powershell.exe", "processUser": "finance_analyst"},
        "networkInfo": {"srcIp": "10.0.4.12", "srcPort": 52100, "dstIp": "185.220.101.5", "dstPort": 4444},
    },
    {
        "eventType": "Threat Mitigation",
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "agentDetectionInfo": {"agentComputerName": "FINANCE-PC-01"},
        "mitigationStatus": "network_quarantine_success",
    },
]


class SentinelOneCollector:
    """Collects and ingests SentinelOne telemetry into AegisX."""

    def __init__(
        self,
        api_url: str = "http://localhost:8000",
        log_file: Optional[str] = None,
        batch_size: int = 50,
        dry_run: bool = False,
    ):
        self.api_url = api_url.rstrip("/")
        self.ingest_endpoint = f"{self.api_url}/api/v1/telemetry/ingest"
        self.log_file = log_file
        self.batch_size = batch_size
        self.dry_run = dry_run

    def fetch_logs(self) -> List[Dict[str, Any]]:
        """Fetch logs from JSON file or return sample attack set."""
        if self.log_file and os.path.exists(self.log_file):
            try:
                with open(self.log_file, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    if content.startswith("["):
                        return json.loads(content)
                    else:
                        return [json.loads(line) for line in content.splitlines() if line.strip()]
            except Exception as exc:
                log.error("Failed reading SentinelOne log file", error=str(exc))
                return []

        return SAMPLE_S1_LOGS

    def run_once(self) -> Dict[str, int]:
        """Normalize and forward SentinelOne logs to AegisX."""
        raw_logs = self.fetch_logs()
        events = []
        for raw in raw_logs:
            ev = normalize_sentinelone_event(raw)
            if ev:
                events.append(ev)

        if not events:
            return {"events_found": 0, "events_shipped": 0}

        if self.dry_run:
            log.info("Dry-run: skipping SentinelOne HTTP dispatch", count=len(events))
            for e in events[:2]:
                log.info("Sample SentinelOne event", event_type=e["event_type"], process=e.get("process"), host=e.get("host"))
            return {"events_found": len(events), "events_shipped": len(events)}

        shipped = 0
        with httpx.Client(timeout=10.0) as client:
            for i in range(0, len(events), self.batch_size):
                chunk = events[i : i + self.batch_size]
                try:
                    res = client.post(self.ingest_endpoint, json={"events": chunk})
                    res.raise_for_status()
                    shipped += len(chunk)
                    log.info("Shipped SentinelOne batch", count=len(chunk), status=res.status_code)
                except Exception as exc:
                    log.error("Failed shipping SentinelOne batch", error=str(exc), count=len(chunk))

        return {"events_found": len(events), "events_shipped": shipped}


def main():
    parser = argparse.ArgumentParser(description="AegisX SentinelOne EDR Telemetry Collector")
    parser.add_argument("--api", default="http://localhost:8000", help="AegisX API URL")
    parser.add_argument("--file", default=None, help="Path to SentinelOne JSON log file")
    parser.add_argument("--batch-size", type=int, default=50, help="Batch size")
    parser.add_argument("--dry-run", action="store_true", help="Print without sending")
    parser.add_argument("--once", action="store_true", default=True, help="Run single pass and exit")

    args = parser.parse_args()

    collector = SentinelOneCollector(
        api_url=args.api,
        log_file=args.file,
        batch_size=args.batch_size,
        dry_run=args.dry_run,
    )

    stats = collector.run_once()
    print(f"SentinelOne collection pass complete: {stats}")


if __name__ == "__main__":
    main()
