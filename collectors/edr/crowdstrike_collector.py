"""
CrowdStrike Falcon EDR Telemetry Collector.

Ingests and normalizes CrowdStrike Falcon FDR (Falcon Data Replicator) and
Event Streams JSON logs into the AegisX NormalizedEvent schema.

Supported CrowdStrike Events:
  - ProcessRollup2: Process creation & parent-child trees (T1059)
  - NetworkConnectIP4: Inbound & outbound network socket connections (T1571)
  - DnsRequest: DNS domain resolutions (T1071.004)
  - UserLogon / UserLogonFailed: Endpoint authentication events (T1078)
  - HostIsolation: Agent network containment actions
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
    _std_log = logging.getLogger("crowdstrike_collector")
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


CROWDSTRIKE_EVENT_MAP = {
    "ProcessRollup2": "process_created",
    "SyntheticProcessRollup2": "process_created",
    "NetworkConnectIP4": "network_connection",
    "NetworkConnectIP6": "network_connection",
    "DnsRequest": "dns_query",
    "UserLogon": "user_logon",
    "UserLogonFailed": "user_logon_failed",
    "HostIsolation": "host_containment",
}


def normalize_crowdstrike_event(raw: Dict[str, Any], default_host: str = "falcon-sensor") -> Optional[Dict[str, Any]]:
    """Normalize a CrowdStrike Falcon JSON event into AegisX NormalizedEvent format."""
    event_data = raw.get("event", raw)
    meta = raw.get("metadata", {})
    event_name = meta.get("eventType") or event_data.get("name") or raw.get("eventType", "ProcessRollup2")

    event_type = CROWDSTRIKE_EVENT_MAP.get(event_name, "edr_event")

    host = (
        event_data.get("ComputerName")
        or event_data.get("aid")
        or default_host
    )
    user = (
        event_data.get("UserName")
        or event_data.get("UserSid")
        or "SYSTEM"
    )

    # Process details
    image_file = event_data.get("ImageFileName") or ""
    process_name = image_file.replace("\\", "/").split("/")[-1] if image_file else None
    parent_file = event_data.get("ParentBaseFileName") or ""
    parent_name = parent_file.replace("\\", "/").split("/")[-1] if parent_file else None
    command_line = event_data.get("CommandLine")

    # Network details
    src_ip = event_data.get("LocalAddressIP4")
    src_port = event_data.get("LocalPort")
    dst_ip = event_data.get("RemoteAddressIP4")
    dst_port = event_data.get("RemotePort")
    sha256 = event_data.get("SHA256HashData")

    timestamp = raw.get("timestamp") or datetime.now(timezone.utc).isoformat()
    if isinstance(timestamp, (int, float)):
        timestamp = datetime.fromtimestamp(timestamp / 1000.0, tz=timezone.utc).isoformat()

    return {
        "source": "crowdstrike_edr",
        "event_type": event_type,
        "timestamp": str(timestamp),
        "host": host,
        "user": user,
        "process": process_name,
        "parent_process": parent_name,
        "command_line": command_line,
        "src_ip": src_ip,
        "src_port": int(src_port) if src_port else None,
        "dst_ip": dst_ip,
        "dst_port": int(dst_port) if dst_port else None,
        "hash": sha256,
        "raw": {
            "falcon_event_name": event_name,
            "aid": event_data.get("aid"),
            "target_process_id": event_data.get("TargetProcessId"),
            "parent_process_id": event_data.get("ParentProcessId"),
            "domain_name": event_data.get("DomainName"),
        },
    }


# ── Sample Synthetic CrowdStrike Logs ─────────────────────────────────────────

SAMPLE_CROWDSTRIKE_LOGS: List[Dict[str, Any]] = [
    {
        "metadata": {"eventType": "ProcessRollup2", "version": "1.0"},
        "event": {
            "aid": "f0123456789abcdef",
            "ComputerName": "CORP-LAPTOP-42",
            "UserName": "victim_engineer",
            "ImageFileName": "C:\\Windows\\System32\\cmd.exe",
            "ParentBaseFileName": "excel.exe",
            "CommandLine": "cmd.exe /c powershell -enc SABFAFgAIAAo...",
            "SHA256HashData": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "TargetProcessId": 4820,
            "ParentProcessId": 2104,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    },
    {
        "metadata": {"eventType": "NetworkConnectIP4", "version": "1.0"},
        "event": {
            "aid": "f0123456789abcdef",
            "ComputerName": "CORP-LAPTOP-42",
            "UserName": "victim_engineer",
            "LocalAddressIP4": "10.0.1.15",
            "LocalPort": 49152,
            "RemoteAddressIP4": "185.220.101.5",
            "RemotePort": 4444,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    },
]


class CrowdStrikeCollector:
    """Collects and forwards CrowdStrike Falcon EDR logs to AegisX."""

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
                log.error("Failed reading CrowdStrike log file", error=str(exc))
                return []

        return SAMPLE_CROWDSTRIKE_LOGS

    def run_once(self) -> Dict[str, int]:
        """Normalize and transmit CrowdStrike EDR events."""
        raw_logs = self.fetch_logs()
        events = []
        for raw in raw_logs:
            ev = normalize_crowdstrike_event(raw)
            if ev:
                events.append(ev)

        if not events:
            return {"events_found": 0, "events_shipped": 0}

        if self.dry_run:
            log.info("Dry-run: skipping CrowdStrike HTTP dispatch", count=len(events))
            for e in events[:2]:
                log.info("Sample CrowdStrike event", event_type=e["event_type"], process=e.get("process"), host=e.get("host"))
            return {"events_found": len(events), "events_shipped": len(events)}

        shipped = 0
        with httpx.Client(timeout=10.0) as client:
            for i in range(0, len(events), self.batch_size):
                chunk = events[i : i + self.batch_size]
                try:
                    res = client.post(self.ingest_endpoint, json={"events": chunk})
                    res.raise_for_status()
                    shipped += len(chunk)
                    log.info("Shipped CrowdStrike batch", count=len(chunk), status=res.status_code)
                except Exception as exc:
                    log.error("Failed shipping CrowdStrike batch", error=str(exc), count=len(chunk))

        return {"events_found": len(events), "events_shipped": shipped}


def main():
    parser = argparse.ArgumentParser(description="AegisX CrowdStrike Falcon EDR Telemetry Collector")
    parser.add_argument("--api", default="http://localhost:8000", help="AegisX API URL")
    parser.add_argument("--file", default=None, help="Path to CrowdStrike JSON log file")
    parser.add_argument("--batch-size", type=int, default=50, help="Batch size")
    parser.add_argument("--dry-run", action="store_true", help="Print without sending")
    parser.add_argument("--once", action="store_true", default=True, help="Run single pass and exit")

    args = parser.parse_args()

    collector = CrowdStrikeCollector(
        api_url=args.api,
        log_file=args.file,
        batch_size=args.batch_size,
        dry_run=args.dry_run,
    )

    stats = collector.run_once()
    print(f"CrowdStrike collection pass complete: {stats}")


if __name__ == "__main__":
    main()
