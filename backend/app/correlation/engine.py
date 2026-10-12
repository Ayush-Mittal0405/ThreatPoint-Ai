"""
Alert Correlation Engine — groups related alerts into incidents.
Correlation dimensions: temporal, entity (host/user/IP), and MITRE tactic.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Optional

import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.models import Alert, Incident

log = structlog.get_logger()

# Alerts within this window are candidates for correlation
CORRELATION_WINDOW_MINUTES = 30


def _make_incident_id() -> str:
    return f"INC-{uuid.uuid4().hex[:8].upper()}"


def _severity_rank(s: str) -> int:
    return {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(s.lower(), 0)


class CorrelationEngine:
    """
    Phase 3 — correlate open alerts into incidents.

    Strategy:
    1. Find all open alerts not yet assigned to an incident.
    2. Group by shared host OR user within the time window.
    3. Create or update an Incident for each cluster.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def correlate_pending_alerts(self) -> List[Incident]:
        """Correlate all open, uncorrelated alerts. Returns new/updated incidents."""
        # Load open, unassigned alerts
        result = await self.db.execute(
            select(Alert).where(
                Alert.status == "open",
                Alert.incident_id == None,  # noqa: E711
            ).order_by(Alert.created_at)
        )
        alerts: List[Alert] = list(result.scalars().all())

        if not alerts:
            return []

        clusters = self._cluster_by_entity(alerts)
        incidents = []

        for cluster in clusters:
            if len(cluster) == 0:
                continue
            incident = await self._create_incident_from_cluster(cluster)
            incidents.append(incident)

        log.info("Correlation complete", clusters=len(clusters), incidents=len(incidents))
        return incidents

    def _cluster_by_entity(self, alerts: List[Alert]) -> List[List[Alert]]:
        """
        Group alerts into clusters where members share a host or user
        AND fall within CORRELATION_WINDOW_MINUTES of each other.
        """
        clustered: List[List[Alert]] = []
        used: set = set()

        for i, alert in enumerate(alerts):
            if id(alert) in used:
                continue
            cluster = [alert]
            used.add(id(alert))

            for j, other in enumerate(alerts):
                if i == j or id(other) in used:
                    continue
                if self._should_correlate(alert, other):
                    cluster.append(other)
                    used.add(id(other))

            clustered.append(cluster)

        return clustered

    def _should_correlate(self, a: Alert, b: Alert) -> bool:
        """True when two alerts share entity context and are temporally close."""
        # Temporal check
        delta = abs((a.created_at - b.created_at).total_seconds())
        if delta > CORRELATION_WINDOW_MINUTES * 60:
            return False

        # Entity overlap: same host
        if a.host and b.host and a.host.lower() == b.host.lower():
            return True

        # Entity overlap: same user
        if a.user and b.user and a.user.lower() == b.user.lower():
            return True

        return False

    async def _create_incident_from_cluster(self, cluster: List[Alert]) -> Incident:
        """Create an Incident from a cluster of correlated alerts."""
        hosts = list({a.host for a in cluster if a.host})
        users = list({a.user for a in cluster if a.user})
        techniques = list({t for a in cluster for t in (a.mitre_techniques or [])})

        # Highest severity wins
        max_sev = max(cluster, key=lambda a: _severity_rank(a.severity)).severity

        title = f"Correlated incident: {len(cluster)} alerts on {', '.join(hosts) or 'unknown host'}"

        incident = Incident(
            id=uuid.uuid4(),
            incident_id=_make_incident_id(),
            title=title,
            status="open",
            severity=max_sev,
            entities={"hosts": hosts, "users": users},
            mitre_techniques=techniques,
        )
        self.db.add(incident)
        await self.db.flush()

        # Link alerts
        for alert in cluster:
            alert.incident_id = incident.id
            alert.status = "in_incident"

        await self.db.flush()
        log.info(
            "Incident created",
            incident_id=incident.incident_id,
            alerts=len(cluster),
            severity=max_sev,
        )
        return incident


# ── Module-level helpers (testable without DB) ────────────────────────────────

def _cluster_alerts(alerts: list) -> list:
    """
    Pure function — cluster alert dicts by entity + temporal proximity.
    Accepts dicts with keys: host, user, created_at.
    Returns a list of clusters (each cluster is a list of alert dicts).
    """
    clustered = []
    used = set()

    for i, alert in enumerate(alerts):
        aid = id(alert)
        if aid in used:
            continue
        cluster = [alert]
        used.add(aid)

        for j, other in enumerate(alerts):
            if i == j or id(other) in used:
                continue
            if _should_correlate_dicts(alert, other):
                cluster.append(other)
                used.add(id(other))

        clustered.append(cluster)

    return clustered


def _should_correlate_dicts(a: dict, b: dict) -> bool:
    """Check if two alert dicts should be correlated."""
    # Temporal
    delta = abs((a["created_at"] - b["created_at"]).total_seconds())
    if delta > CORRELATION_WINDOW_MINUTES * 60:
        return False
    # Host match
    if a.get("host") and b.get("host") and a["host"].lower() == b["host"].lower():
        return True
    # User match
    if a.get("user") and b.get("user") and a["user"].lower() == b["user"].lower():
        return True
    return False


def _incident_severity(alerts: list) -> str:
    """Determine incident severity from a list of alert dicts or ORM objects."""
    def get_sev(a):
        return a.severity if hasattr(a, "severity") else a.get("severity", "low")
    return max((get_sev(a) for a in alerts), key=_severity_rank, default="low")
