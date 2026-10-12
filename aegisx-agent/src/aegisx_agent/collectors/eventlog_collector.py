"""
Windows Security event-log collector (authentication telemetry).

Uses the built-in `wevtutil` CLI (no third-party dependency) to read logon
events from the Security channel and emits `authentication` events. Tracks the
last EventRecordID so each record is reported once. Windows-only; no-ops
elsewhere so the same agent code runs cross-platform.

Relevant Windows Security Event IDs:
  4624 successful logon        4625 failed logon
  4634 logoff                  4647 user-initiated logoff
  4672 special privileges      4720 account created      4726 account deleted
  4740 account lockout
"""
from __future__ import annotations

import os
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .base import Collector

_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

_EVENT_MAP = {
    "4624": ("authentication", "info", "Successful logon"),
    "4625": ("authentication", "warning", "Failed logon"),
    "4634": ("authentication", "info", "Logoff"),
    "4647": ("authentication", "info", "User-initiated logoff"),
    "4672": ("authentication", "info", "Special privileges assigned"),
    "4720": ("user_account_change", "warning", "User account created"),
    "4726": ("user_account_change", "warning", "User account deleted"),
    "4740": ("authentication", "warning", "Account lockout"),
}
_QUERY_IDS = " or ".join(f"EventID={eid}" for eid in _EVENT_MAP)


class EventLogCollector(Collector):
    name = "eventlog"
    supported = os.name == "nt"

    def __init__(self, logger=None, max_per_poll: int = 50):
        super().__init__(logger)
        self.max_per_poll = max_per_poll
        self._last_record_id: Optional[int] = None
        self._primed = False

    def collect(self) -> List[Dict[str, Any]]:
        xml_text = self._query_security_log()
        if not xml_text:
            return []

        events: List[Dict[str, Any]] = []
        max_seen = self._last_record_id or 0
        # wevtutil emits a stream of <Event> elements; wrap them in a root.
        try:
            root = ET.fromstring(f"<Events>{xml_text}</Events>")
        except ET.ParseError:
            return []

        for ev in root.findall("e:Event", _NS):
            parsed = self._parse_event(ev)
            if parsed is None:
                continue
            record_id, event = parsed
            max_seen = max(max_seen, record_id)
            if self._last_record_id is not None and record_id <= self._last_record_id:
                continue
            if self._primed:
                events.append(event)

        self._last_record_id = max_seen
        self._primed = True
        return events

    # ── Internals ─────────────────────────────────────────────────────────────

    def _query_security_log(self) -> Optional[str]:
        cmd = [
            "wevtutil", "qe", "Security",
            f"/q:*[System[({_QUERY_IDS})]]",
            "/f:xml", "/rd:true", f"/c:{self.max_per_poll}",
        ]
        try:
            out = subprocess.run(
                cmd, capture_output=True, text=True, timeout=20,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None
        if out.returncode != 0:
            return None
        return out.stdout

    def _parse_event(self, ev: ET.Element) -> Optional[tuple]:
        system = ev.find("e:System", _NS)
        if system is None:
            return None
        eid_el = system.find("e:EventID", _NS)
        rec_el = system.find("e:EventRecordID", _NS)
        time_el = system.find("e:TimeCreated", _NS)
        if eid_el is None or rec_el is None:
            return None
        eid = (eid_el.text or "").strip()
        mapping = _EVENT_MAP.get(eid)
        if mapping is None:
            return None
        try:
            record_id = int(rec_el.text or "0")
        except ValueError:
            return None

        event_type, severity, desc = mapping
        ts = time_el.get("SystemTime") if time_el is not None else None

        data: Dict[str, str] = {}
        edata = ev.find("e:EventData", _NS)
        if edata is not None:
            for d in edata.findall("e:Data", _NS):
                name = d.get("Name")
                if name:
                    data[name] = (d.text or "").strip()

        event = {
            "event_type": event_type,
            "timestamp": ts or datetime.now(timezone.utc).isoformat(),
            "severity": severity,
            "user": data.get("TargetUserName") or data.get("SubjectUserName"),
            "src_ip": data.get("IpAddress") if data.get("IpAddress") not in ("-", "") else None,
            "raw": {
                "windows_event_id": eid,
                "description": desc,
                "logon_type": data.get("LogonType"),
                "target_group": data.get("TargetUserName"),
                "record_id": record_id,
            },
        }
        return record_id, event
