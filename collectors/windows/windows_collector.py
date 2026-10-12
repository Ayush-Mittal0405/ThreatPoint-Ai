"""
Windows Telemetry Collector — reads Windows Event Log and Sysmon events
and ships them to the AegisX ingestion API.

Usage:
    python windows_collector.py --api http://localhost:8000 --channels Security,System

Requires: pywin32 (pip install pywin32) — Windows only.
Optionally ships Sysmon events from Microsoft-Windows-Sysmon/Operational.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

import httpx
import structlog

log = structlog.get_logger()

# ── Event Channel → AegisX source mapping ────────────────────────────────────
CHANNEL_SOURCE_MAP = {
    "Security": "winlog_security",
    "System": "winlog_system",
    "Application": "winlog_application",
    "Microsoft-Windows-Sysmon/Operational": "sysmon",
}

# ── Windows Event ID → AegisX event_type mapping ─────────────────────────────
EVENT_TYPE_MAP = {
    # Security channel
    4624: "user_logon",
    4625: "user_logon_failed",
    4634: "user_logoff",
    4648: "user_logon_explicit",
    4720: "user_account_created",
    4732: "user_account_change",   # added to group
    4756: "user_account_change",   # added to universal group
    4688: "process_creation",
    4689: "process_termination",
    4663: "file_access",
    4697: "service_installed",
    # Sysmon
    1: "process_creation",
    3: "network_connection",
    7: "image_loaded",
    8: "create_remote_thread",
    11: "file_created",
    12: "registry_event",
    13: "registry_event",
    22: "dns_query",
    23: "file_deleted",
}


def _try_import_win32():
    """Guard for non-Windows environments."""
    try:
        import win32evtlog
        import win32evtlogutil
        import winerror
        return win32evtlog, win32evtlogutil, winerror
    except ImportError:
        log.error("pywin32 not installed. Run: pip install pywin32")
        sys.exit(1)


def _parse_event(event, channel: str) -> Optional[Dict]:
    """Extract fields from a win32evtlog event object."""
    try:
        eid = event.EventID & 0xFFFF
        event_type = EVENT_TYPE_MAP.get(eid, f"raw_{eid}")
        source = CHANNEL_SOURCE_MAP.get(channel, "winlog_unknown")

        ts = event.TimeGenerated
        if hasattr(ts, "timestamp"):
            timestamp = datetime.fromtimestamp(ts.timestamp(), tz=timezone.utc).isoformat()
        else:
            timestamp = datetime.now(tz=timezone.utc).isoformat()

        # Raw strings (vary by event ID)
        strings = list(event.StringInserts or [])

        record: Dict = {
            "source": source,
            "event_type": event_type,
            "timestamp": timestamp,
            "host": event.ComputerName,
            "raw": {
                "event_id": eid,
                "channel": channel,
                "strings": strings,
                "record_number": event.RecordNumber,
            },
        }

        # Map specific fields by event ID
        if eid == 4624 and len(strings) >= 6:
            record["user"] = strings[5]
            record["src_ip"] = strings[18] if len(strings) > 18 else None
        elif eid == 4625 and len(strings) >= 6:
            record["user"] = strings[5]
            record["src_ip"] = strings[19] if len(strings) > 19 else None
        elif eid == 4688 and len(strings) >= 6:
            record["process"] = strings[5]
            record["parent_process"] = strings[13] if len(strings) > 13 else None
            record["command_line"] = strings[8] if len(strings) > 8 else None
            record["user"] = strings[1] if len(strings) > 1 else None
        elif eid == 1:  # Sysmon process creation
            # Sysmon 1 strings: UtcTime, ProcessGuid, ProcessId, Image, FileVersion,
            #   Description, Product, Company, OriginalFileName, CommandLine,
            #   CurrentDirectory, User, LogonGuid, LogonId, TerminalSessionId,
            #   IntegrityLevel, Hashes, ParentProcessGuid, ParentProcessId,
            #   ParentImage, ParentCommandLine, ParentUser
            if len(strings) >= 21:
                record["process"] = strings[3].split("\\")[-1] if strings[3] else None
                record["command_line"] = strings[9]
                record["user"] = strings[11]
                record["parent_process"] = strings[19].split("\\")[-1] if strings[19] else None
                raw_hashes = strings[16] or ""
                for part in raw_hashes.split(","):
                    if "SHA256=" in part:
                        record["hash_sha256"] = part.split("=", 1)[1]
                    elif "MD5=" in part:
                        record["hash_md5"] = part.split("=", 1)[1]
        elif eid == 3:  # Sysmon network connection
            if len(strings) >= 15:
                record["process"] = strings[3].split("\\")[-1] if strings[3] else None
                record["user"] = strings[11]
                record["src_ip"] = strings[8]
                record["dst_ip"] = strings[13]
                record["dst_port"] = int(strings[14]) if strings[14].isdigit() else None
                record["domain"] = strings[12] if len(strings) > 12 else None

        return record
    except Exception as exc:
        log.warning("Failed to parse event", error=str(exc))
        return None


class WindowsCollector:
    """Reads Windows Event Log and ships events to AegisX."""

    def __init__(self, api_url: str, channels: List[str], batch_size: int = 50, poll_interval: int = 5):
        self.api_url = api_url.rstrip("/")
        self.channels = channels
        self.batch_size = batch_size
        self.poll_interval = poll_interval
        self._cursors: Dict[str, int] = {}  # channel → last record number

    def run(self):
        """Main polling loop."""
        win32evtlog, _, _ = _try_import_win32()
        log.info("Windows collector starting", channels=self.channels, api=self.api_url)

        while True:
            for channel in self.channels:
                try:
                    events = self._read_channel(win32evtlog, channel)
                    if events:
                        self._ship(events)
                except Exception as exc:
                    log.error("Channel read failed", channel=channel, error=str(exc))
            time.sleep(self.poll_interval)

    def _read_channel(self, win32evtlog, channel: str) -> List[Dict]:
        """Read new events from a Windows Event Log channel."""
        last_record = self._cursors.get(channel, 0)
        handle = win32evtlog.OpenEventLog(None, channel)
        events_out = []

        try:
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            raw_events = win32evtlog.ReadEventLog(handle, flags, 0)

            for ev in raw_events:
                if ev.RecordNumber <= last_record:
                    continue
                parsed = _parse_event(ev, channel)
                if parsed:
                    events_out.append(parsed)
                    last_record = max(last_record, ev.RecordNumber)

            self._cursors[channel] = last_record
        finally:
            win32evtlog.CloseEventLog(handle)

        return events_out

    def _ship(self, events: List[Dict]):
        """POST events to the AegisX ingestion API in batches."""
        for i in range(0, len(events), self.batch_size):
            batch = events[i : i + self.batch_size]
            try:
                resp = httpx.post(
                    f"{self.api_url}/api/v1/telemetry/ingest",
                    json={"events": batch},
                    timeout=30.0,
                )
                resp.raise_for_status()
                log.info("Batch shipped", count=len(batch))
            except Exception as exc:
                log.error("Ship failed", count=len(batch), error=str(exc))


def main():
    parser = argparse.ArgumentParser(description="AegisX Windows Telemetry Collector")
    parser.add_argument("--api", default="http://localhost:8000", help="AegisX API base URL")
    parser.add_argument(
        "--channels",
        default="Security,Microsoft-Windows-Sysmon/Operational",
        help="Comma-separated event log channels",
    )
    parser.add_argument("--batch-size", type=int, default=50)
    parser.add_argument("--poll-interval", type=int, default=5, help="Seconds between polls")
    args = parser.parse_args()

    channels = [c.strip() for c in args.channels.split(",")]
    collector = WindowsCollector(
        api_url=args.api,
        channels=channels,
        batch_size=args.batch_size,
        poll_interval=args.poll_interval,
    )
    collector.run()


if __name__ == "__main__":
    main()
