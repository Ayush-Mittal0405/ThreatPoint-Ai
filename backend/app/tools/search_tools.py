"""
Search tools — query the telemetry database for investigative evidence.
All methods return plain dicts (JSON-serializable).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from app.models.models import NormalizedEvent, Incident

log = structlog.get_logger()


class SearchTools:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def search_endpoint_events(
        self,
        host: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 20,
    ) -> Dict:
        """Search endpoint telemetry events."""
        q = select(NormalizedEvent).order_by(NormalizedEvent.timestamp.desc())
        if host:
            q = q.where(NormalizedEvent.host.ilike(f"%{host}%"))
        if event_type:
            q = q.where(NormalizedEvent.event_type == event_type)
        q = q.limit(min(limit, 100))

        result = await self.db.execute(q)
        events = result.scalars().all()

        return {
            "count": len(events),
            "events": [
                {
                    "event_id": e.event_id,
                    "timestamp": e.timestamp.isoformat(),
                    "source": e.source,
                    "event_type": e.event_type,
                    "host": e.host,
                    "user": e.user,
                    "process": e.process,
                    "parent_process": e.parent_process,
                    "command_line": e.command_line,
                    "src_ip": e.src_ip,
                    "dst_ip": e.dst_ip,
                    "dst_port": e.dst_port,
                }
                for e in events
            ],
        }

    async def search_process_tree(
        self,
        host: Optional[str] = None,
        process_name: Optional[str] = None,
        limit: int = 30,
    ) -> Dict:
        """Get process creation events to reconstruct parent-child tree."""
        q = select(NormalizedEvent).where(
            NormalizedEvent.event_type == "process_creation"
        ).order_by(NormalizedEvent.timestamp.desc())

        if host:
            q = q.where(NormalizedEvent.host.ilike(f"%{host}%"))
        if process_name:
            q = q.where(NormalizedEvent.process.ilike(f"%{process_name}%"))
        q = q.limit(min(limit, 100))

        result = await self.db.execute(q)
        events = result.scalars().all()

        # Build adjacency list
        tree: Dict[str, List] = {}
        for e in events:
            parent = e.parent_process or "unknown"
            proc = e.process or "unknown"
            tree.setdefault(parent, [])
            tree[parent].append({
                "process": proc,
                "command_line": e.command_line,
                "timestamp": e.timestamp.isoformat(),
                "host": e.host,
                "user": e.user,
            })

        return {"host": host, "process_filter": process_name, "tree": tree, "total_events": len(events)}

    async def search_network_events(
        self,
        host: Optional[str] = None,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        limit: int = 20,
    ) -> Dict:
        """Search network connection telemetry."""
        q = select(NormalizedEvent).where(
            NormalizedEvent.event_type == "network_connection"
        ).order_by(NormalizedEvent.timestamp.desc())

        if host:
            q = q.where(NormalizedEvent.host.ilike(f"%{host}%"))
        if src_ip:
            q = q.where(NormalizedEvent.src_ip == src_ip)
        if dst_ip:
            q = q.where(NormalizedEvent.dst_ip == dst_ip)
        q = q.limit(min(limit, 100))

        result = await self.db.execute(q)
        events = result.scalars().all()

        return {
            "count": len(events),
            "connections": [
                {
                    "timestamp": e.timestamp.isoformat(),
                    "host": e.host,
                    "src_ip": e.src_ip,
                    "dst_ip": e.dst_ip,
                    "dst_port": e.dst_port,
                    "domain": e.domain,
                    "process": e.process,
                }
                for e in events
            ],
        }

    async def search_user_activity(
        self,
        username: Optional[str] = None,
        host: Optional[str] = None,
        limit: int = 20,
    ) -> Dict:
        """Search user authentication and account events."""
        q = select(NormalizedEvent).where(
            NormalizedEvent.event_type.in_([
                "user_logon", "user_logoff", "user_logon_failed",
                "user_account_change", "privilege_escalation",
            ])
        ).order_by(NormalizedEvent.timestamp.desc())

        if username:
            q = q.where(NormalizedEvent.user.ilike(f"%{username}%"))
        if host:
            q = q.where(NormalizedEvent.host.ilike(f"%{host}%"))
        q = q.limit(min(limit, 100))

        result = await self.db.execute(q)
        events = result.scalars().all()

        return {
            "count": len(events),
            "activity": [
                {
                    "timestamp": e.timestamp.isoformat(),
                    "event_type": e.event_type,
                    "user": e.user,
                    "host": e.host,
                    "src_ip": e.src_ip,
                }
                for e in events
            ],
        }

    async def search_historical_incidents(
        self,
        host: Optional[str] = None,
        mitre_technique: Optional[str] = None,
        limit: int = 5,
    ) -> Dict:
        """Find historical incidents similar to the current one."""
        q = select(Incident).where(
            Incident.status.in_(["closed", "responded"])
        ).order_by(Incident.created_at.desc())

        result = await self.db.execute(q)
        incidents = result.scalars().all()

        matches = []
        for inc in incidents:
            if host and inc.entities:
                if host not in str(inc.entities.get("hosts", [])):
                    continue
            if mitre_technique and inc.mitre_techniques:
                if mitre_technique not in inc.mitre_techniques:
                    continue
            matches.append({
                "incident_id": inc.incident_id,
                "title": inc.title,
                "severity": inc.severity,
                "status": inc.status,
                "mitre_techniques": inc.mitre_techniques,
                "created_at": inc.created_at.isoformat(),
            })
            if len(matches) >= limit:
                break

        return {"count": len(matches), "historical_incidents": matches}
