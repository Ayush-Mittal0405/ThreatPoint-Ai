"""
Microsoft Defender for Endpoint (MDE) Telemetry Collector.

Collects and normalizes Microsoft Defender Advanced Hunting telemetry events
(DeviceProcessEvents, DeviceNetworkEvents, DeviceLogonEvents, DeviceFileEvents)
into the AegisX NormalizedEvent schema.

Targeted MITRE ATT&CK Techniques:
  - T1059.001: PowerShell execution
  - T1566.001: Spearphishing Attachment (Office spawning child processes)
  - T1071: Standard Application Layer Protocols
  - T1078: Valid Accounts
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
    _std_log = logging.getLogger("defender_collector")
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


DEFENDER_ACTION_MAP = {
    "ProcessCreated": "process_created",
    "ConnectionSuccess": "network_connection",
    "ConnectionFailed": "network_connection",
    "DnsQuery": "dns_query",
    "LogonSuccess": "user_logon",
    "LogonFailed": "user_logon_failed",
    "FileCreated": "file_event",
    "FileModified": "file_event",
}


def normalize_defender_event(raw: Dict[str, Any], default_host: str = "mde-endpoint") -> Optional[Dict[str, Any]]:
    """Normalize a Microsoft Defender Advanced Hunting event into AegisX format."""
    action_type = raw.get("ActionType") or raw.get("action_type") or "ProcessCreated"
    table_name = raw.get("TableName") or "DeviceProcessEvents"

    event_type = DEFENDER_ACTION_MAP.get(action_type)
    if not event_type:
        if "Process" in table_name:
            event_type = "process_created"
        elif "Network" in table_name:
            event_type = "network_connection"
        elif "Logon" in table_name:
            event_type = "user_logon"
        else:
            event_type = "edr_event"

    host = raw.get("DeviceName") or default_host
    user = raw.get("AccountName") or raw.get("InitiatingProcessAccountName") or "SYSTEM"

    # Process details
    process = raw.get("FileName") or raw.get("process")
    parent_process = raw.get("InitiatingProcessFileName") or raw.get("parent_process")
    cmd_line = raw.get("ProcessCommandLine") or raw.get("InitiatingProcessCommandLine")
    sha256 = raw.get("SHA256") or raw.get("InitiatingProcessSHA256")

    # Network details
    src_ip = raw.get("LocalIP")
    src_port = raw.get("LocalPort")
    dst_ip = raw.get("RemoteIP")
    dst_port = raw.get("RemotePort")

    timestamp = raw.get("Timestamp") or datetime.now(timezone.utc).isoformat()

    return {
        "source": "microsoft_defender_edr",
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
            "mde_table": table_name,
            "action_type": action_type,
            "device_id": raw.get("DeviceId"),
            "report_id": raw.get("ReportId"),
        },
    }


# ── Sample Synthetic Defender Logs ────────────────────────────────────────────

SAMPLE_DEFENDER_LOGS: List[Dict[str, Any]] = [
    {
        "TableName": "DeviceProcessEvents",
        "ActionType": "ProcessCreated",
        "Timestamp": datetime.now(timezone.utc).isoformat(),
        "DeviceName": "CORP-WIN11-04",
        "AccountName": "victim_analyst",
        "FileName": "powershell.exe",
        "InitiatingProcessFileName": "winword.exe",
        "ProcessCommandLine": "powershell.exe -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==",
        "SHA256": "3a0b1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
        "DeviceId": "mde-dev-001",
    },
    {
        "TableName": "DeviceNetworkEvents",
        "ActionType": "ConnectionSuccess",
        "Timestamp": datetime.now(timezone.utc).isoformat(),
        "DeviceName": "CORP-WIN11-04",
        "AccountName": "victim_analyst",
        "FileName": "powershell.exe",
        "RemoteIP": "185.220.101.5",
        "RemotePort": 4444,
        "LocalIP": "10.0.1.20",
        "LocalPort": 53040,
    },
]


class DefenderCollector:
    """Collects and forwards Microsoft Defender EDR logs to AegisX."""

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
        """Read logs from file or return sample attack stream."""
        if self.log_file and os.path.exists(self.log_file):
            try:
                with open(self.log_file, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    if content.startswith("["):
                        return json.loads(content)
                    else:
                        return [json.loads(line) for line in content.splitlines() if line.strip()]
            except Exception as exc:
                log.error("Failed reading Defender log file", error=str(exc))
                return []

        return SAMPLE_DEFENDER_LOGS

    def run_once(self) -> Dict[str, int]:
        """Normalize and forward Defender events."""
        raw_logs = self.fetch_logs()
        events = []
        for raw in raw_logs:
            ev = normalize_defender_event(raw)
            if ev:
                events.append(ev)

        if not events:
            return {"events_found": 0, "events_shipped": 0}

        if self.dry_run:
            log.info("Dry-run: skipping Defender HTTP dispatch", count=len(events))
            for e in events[:2]:
                log.info("Sample Defender event", event_type=e["event_type"], process=e.get("process"), host=e.get("host"))
            return {"events_found": len(events), "events_shipped": len(events)}

        shipped = 0
        with httpx.Client(timeout=10.0) as client:
            for i in range(0, len(events), self.batch_size):
                chunk = events[i : i + self.batch_size]
                try:
                    res = client.post(self.ingest_endpoint, json={"events": chunk})
                    res.raise_for_status()
                    shipped += len(chunk)
                    log.info("Shipped Defender batch", count=len(chunk), status=res.status_code)
                except Exception as exc:
                    log.error("Failed shipping Defender batch", error=str(exc), count=len(chunk))

        return {"events_found": len(events), "events_shipped": shipped}


def main():
    parser = argparse.ArgumentParser(description="AegisX Microsoft Defender EDR Telemetry Collector")
    parser.add_argument("--api", default="http://localhost:8000", help="AegisX API URL")
    parser.add_argument("--file", default=None, help="Path to Defender JSON log file")
    parser.add_argument("--batch-size", type=int, default=50, help="Batch size")
    parser.add_argument("--dry-run", action="store_true", help="Print without sending")
    parser.add_argument("--once", action="store_true", default=True, help="Run single pass and exit")

    args = parser.parse_args()

    collector = DefenderCollector(
        api_url=args.api,
        log_file=args.file,
        batch_size=args.batch_size,
        dry_run=args.dry_run,
    )

    stats = collector.run_once()
    print(f"Microsoft Defender collection pass complete: {stats}")


if __name__ == "__main__":
    main()
