"""
Detection engine — evaluates normalized events against loaded rules
and produces Alert records.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import List, Optional

import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.models import NormalizedEvent, DetectionRule, Alert, AlertEvent

log = structlog.get_logger()


def _make_alert_id() -> str:
    return f"ALT-{uuid.uuid4().hex[:12].upper()}"


class DetectionEngine:
    """
    Phase 1/2 detection engine.

    Supports:
    - Behavioral pattern matching (Python-based rules)
    - IOC matching (IP / domain / hash lists)

    Sigma/YARA execution will be added in Phase 2.
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        # Built-in behavioral rules (expandable)
        self._rules = _builtin_behavioral_rules()

    async def evaluate_event(self, event: NormalizedEvent) -> List[Alert]:
        """Run all enabled rules against an event. Returns generated alerts."""
        alerts: List[Alert] = []

        for rule in self._rules:
            if rule.get("enabled", True) and rule["matcher"](event):
                alert = Alert(
                    id=uuid.uuid4(),
                    alert_id=_make_alert_id(),
                    title=rule["title"],
                    description=rule.get("description"),
                    severity=rule["severity"],
                    status="open",
                    host=event.host,
                    user=event.user,
                    agent_id=getattr(event, "agent_id", None),
                    mitre_techniques=rule.get("mitre"),
                )
                self.db.add(alert)
                await self.db.flush()

                # Link event → alert
                assoc = AlertEvent(alert_id=alert.id, event_id=event.id)
                self.db.add(assoc)
                await self.db.flush()

                alerts.append(alert)
                log.info(
                    "Alert created",
                    alert_id=alert.alert_id,
                    rule=rule["title"],
                    host=event.host,
                )

        return alerts


# ─── Built-in Behavioral Rules ────────────────────────────────────────────────

def _builtin_behavioral_rules() -> List[dict]:
    """
    Python-callable matchers for Phase 1.
    Each rule is a dict with title, severity, mitre list, and a matcher function.
    """

    def office_spawns_shell(e: NormalizedEvent) -> bool:
        """Office application spawning a scripting host."""
        office = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
        shells = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
        return (
            e.event_type == "process_creation"
            and e.parent_process is not None
            and e.parent_process.lower() in office
            and e.process is not None
            and e.process.lower() in shells
        )

    def encoded_powershell(e: NormalizedEvent) -> bool:
        """PowerShell with encoded command (-enc / -EncodedCommand)."""
        if e.event_type != "process_creation":
            return False
        if not e.process or "powershell" not in e.process.lower():
            return False
        cmd = (e.command_line or "").lower()
        return bool(re.search(r"-en(?:c|codedcommand)\s", cmd))

    def suspicious_outbound_port(e: NormalizedEvent) -> bool:
        """Outbound connection to uncommon C2-like ports."""
        c2_ports = {4444, 4445, 8443, 8080, 9001, 1337, 31337}
        return (
            e.event_type == "network_connection"
            and e.dst_port in c2_ports
        )

    def new_local_admin(e: NormalizedEvent) -> bool:
        """User added to local Administrators group."""
        return (
            e.event_type == "user_account_change"
            and "administrators" in (e.raw or {}).get("target_group", "").lower()
        )

    def suspicious_executable_location(e: NormalizedEvent) -> bool:
        """Executable running from temp/user directories."""
        suspicious_paths = [r"\\temp\\", r"\\tmp\\", r"\\appdata\\", r"\\downloads\\"]
        if e.event_type != "process_creation" or not e.file_path:
            return False
        fp = e.file_path.lower()
        return any(re.search(p, fp) for p in suspicious_paths)

    return [
        {
            "title": "Office Application Spawns Scripting Host",
            "description": "A Microsoft Office process spawned a scripting host, which may indicate a macro-based attack.",
            "severity": "high",
            "mitre": ["T1566.001", "T1059.001"],
            "matcher": office_spawns_shell,
        },
        {
            "title": "Encoded PowerShell Command Execution",
            "description": "PowerShell was executed with an encoded command argument, a common evasion technique.",
            "severity": "medium",
            "mitre": ["T1059.001", "T1027"],
            "matcher": encoded_powershell,
        },
        {
            "title": "Suspicious Outbound Connection to Known C2 Port",
            "description": "An outbound network connection was made to a port commonly used for command and control.",
            "severity": "high",
            "mitre": ["T1571"],
            "matcher": suspicious_outbound_port,
        },
        {
            "title": "User Added to Administrators Group",
            "description": "A user account was added to the local Administrators group.",
            "severity": "high",
            "mitre": ["T1098"],
            "matcher": new_local_admin,
        },
        {
            "title": "Executable Running from Suspicious Path",
            "description": "A process was launched from a temporary or user-writable directory.",
            "severity": "medium",
            "mitre": ["T1036.005"],
            "matcher": suspicious_executable_location,
        },
    ]
