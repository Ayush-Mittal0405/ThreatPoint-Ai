"""
Telemetry normalization service — converts raw events to NormalizedEvent rows.
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import timezone
from typing import List

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import NormalizedEvent
from app.schemas.telemetry import RawEventIn

log = structlog.get_logger()


def _make_event_id(event: RawEventIn) -> str:
    """Deterministic event ID so duplicates are caught at ingest."""
    agent_id = getattr(event, "agent_id", None)
    key = f"{event.source}|{agent_id}|{event.event_type}|{event.timestamp.isoformat()}|{event.host}|{event.process}|{event.command_line}"
    return hashlib.sha256(key.encode()).hexdigest()[:32]


def _normalize(raw: RawEventIn) -> NormalizedEvent:
    """Apply normalization rules and return an ORM object."""
    event_id = _make_event_id(raw)
    ts = raw.timestamp
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)

    return NormalizedEvent(
        id=uuid.uuid4(),
        event_id=event_id,
        timestamp=ts,
        source=raw.source.lower().strip(),
        event_type=raw.event_type.lower().strip(),
        agent_id=getattr(raw, "agent_id", None),
        host=raw.host,
        user=raw.user,
        process=raw.process,
        parent_process=raw.parent_process,
        command_line=raw.command_line,
        file_path=raw.file_path,
        hash_md5=raw.hash_md5,
        hash_sha256=raw.hash_sha256,
        src_ip=raw.src_ip,
        dst_ip=raw.dst_ip,
        dst_port=raw.dst_port,
        domain=raw.domain,
        raw=raw.raw,
    )
def normalize_event(raw: dict | RawEventIn) -> NormalizedEvent:
    """Convenience helper to normalize either a dict or a RawEventIn model."""
    if isinstance(raw, dict):
        raw = RawEventIn(**raw)
    return _normalize(raw)

class NormalizationService:
    """Normalize and persist a batch of raw events."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def ingest_batch(self, events: List[RawEventIn]) -> List[str]:
        """
        Normalize and bulk-insert events.
        Returns list of accepted event_ids.
        """
        normalized = [_normalize(e) for e in events]
        event_ids = [n.event_id for n in normalized]

        # Upsert strategy: ignore duplicates
        for n in normalized:
            try:
                self.db.add(n)
                await self.db.flush()
            except Exception:
                await self.db.rollback()
                log.warning("Duplicate event skipped", event_id=n.event_id)

        log.info("Events ingested", count=len(normalized))
        return event_ids
