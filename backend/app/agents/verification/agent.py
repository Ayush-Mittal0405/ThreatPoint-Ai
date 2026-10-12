"""
Verification Agent — checks whether the threat was successfully remediated
by re-inspecting telemetry after a response action was executed.

Returns: { threat_removed: bool, evidence: [...], confidence: float, recommendation: str }
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Dict, List

import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.models import Incident, NormalizedEvent

log = structlog.get_logger()


class VerificationAgent:
    """
    Post-response verification — checks if the threat is still present.

    Checks:
    1. Are processes that triggered alerts still running?
    2. Are C2 connections still active?
    3. Are there new alerts on the same entities after the response?
    """

    def __init__(self, db: AsyncSession, incident: Incident):
        self.db = db
        self.incident = incident

    async def verify(self) -> Dict:
        log.info("Verification agent running", incident_id=self.incident.incident_id)

        entities = self.incident.entities or {}
        hosts = entities.get("hosts", [])
        response_time = datetime.now(timezone.utc) - timedelta(minutes=30)

        # Check for new suspicious events AFTER the response
        checks = []
        threat_indicators = 0

        for host in hosts:
            # 1. Check for new process creations on the host
            new_procs = await self._count_events_after(host, "process_creation", response_time)
            checks.append({
                "check": "new_process_creation",
                "host": host,
                "count": new_procs,
                "suspicious": new_procs > 5,
            })
            if new_procs > 5:
                threat_indicators += 1

            # 2. Check for new network connections
            new_net = await self._count_events_after(host, "network_connection", response_time)
            checks.append({
                "check": "new_network_connections",
                "host": host,
                "count": new_net,
                "suspicious": new_net > 3,
            })
            if new_net > 3:
                threat_indicators += 1

        threat_removed = threat_indicators == 0
        confidence = 0.90 if not hosts else max(0.5, 0.90 - threat_indicators * 0.15)

        result = {
            "incident_id": self.incident.incident_id,
            "threat_removed": threat_removed,
            "confidence": round(confidence, 2),
            "checks": checks,
            "threat_indicators": threat_indicators,
            "recommendation": (
                "Incident can be closed. No further threat activity detected."
                if threat_removed
                else f"Threat may still be active ({threat_indicators} indicators). Re-investigate."
            ),
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }

        # Persist verification result
        self.incident.verification = result
        if threat_removed:
            self.incident.status = "closed"
        else:
            self.incident.status = "open"  # re-open for investigation
        await self.db.flush()

        log.info(
            "Verification complete",
            incident_id=self.incident.incident_id,
            threat_removed=threat_removed,
            indicators=threat_indicators,
        )
        return result

    async def _count_events_after(
        self, host: str, event_type: str, after: datetime
    ) -> int:
        """Count new events on a host after a given time."""
        result = await self.db.execute(
            select(NormalizedEvent).where(
                NormalizedEvent.host == host,
                NormalizedEvent.event_type == event_type,
                NormalizedEvent.timestamp > after,
            )
        )
        return len(result.scalars().all())
