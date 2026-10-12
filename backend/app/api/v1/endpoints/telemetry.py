"""
Telemetry ingestion endpoints.

POST /api/v1/telemetry/ingest       — ingest a batch of raw events
POST /api/v1/telemetry/ingest/single — ingest a single raw event
GET  /api/v1/telemetry/events        — list normalized events (paginated)
GET  /api/v1/telemetry/events/{id}   — single event detail
"""
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.database import get_db
from app.schemas.telemetry import RawEventIn, RawEventBatch, EventOut, IngestResponse
from app.services.normalization import NormalizationService
from app.detection.engine import DetectionEngine
from app.correlation.engine import CorrelationEngine
from app.models.models import NormalizedEvent

router = APIRouter()


async def _run_pipeline(events_in: List[RawEventIn], db: AsyncSession):
    """Normalize → Detect → Correlate pipeline (runs in background)."""
    norm_svc = NormalizationService(db)
    event_ids = await norm_svc.ingest_batch(events_in)

    # Load stored events and run detection
    result = await db.execute(
        select(NormalizedEvent).where(NormalizedEvent.event_id.in_(event_ids))
    )
    stored = list(result.scalars().all())

    det_engine = DetectionEngine(db)
    for event in stored:
        await det_engine.evaluate_event(event)

    # Correlate any new open alerts into incidents
    corr_engine = CorrelationEngine(db)
    await corr_engine.correlate_pending_alerts()

    await db.commit()


@router.post("/ingest", response_model=IngestResponse, status_code=202)
async def ingest_batch(
    payload: RawEventBatch,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Ingest a batch of raw security events.
    Events are normalized, detected against, and correlated asynchronously.
    """
    background_tasks.add_task(_run_pipeline, payload.events, db)
    return IngestResponse(
        accepted=len(payload.events),
        event_ids=[f"pending-{i}" for i in range(len(payload.events))],
    )


@router.post("/ingest/single", response_model=IngestResponse, status_code=202)
async def ingest_single(
    event: RawEventIn,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Ingest a single raw security event."""
    background_tasks.add_task(_run_pipeline, [event], db)
    return IngestResponse(accepted=1, event_ids=["pending-0"])


@router.get("/events", response_model=List[EventOut])
async def list_events(
    source: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    host: Optional[str] = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """List normalized events with optional filters."""
    q = select(NormalizedEvent).order_by(NormalizedEvent.timestamp.desc())
    if source:
        q = q.where(NormalizedEvent.source == source)
    if event_type:
        q = q.where(NormalizedEvent.event_type == event_type)
    if host:
        q = q.where(NormalizedEvent.host.ilike(f"%{host}%"))
    q = q.limit(limit).offset(offset)

    result = await db.execute(q)
    return list(result.scalars().all())


@router.get("/events/{event_id}", response_model=EventOut)
async def get_event(event_id: UUID, db: AsyncSession = Depends(get_db)):
    """Get a single normalized event by UUID."""
    result = await db.execute(
        select(NormalizedEvent).where(NormalizedEvent.id == event_id)
    )
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event
