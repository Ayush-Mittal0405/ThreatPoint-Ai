"""
Alert management endpoints.

GET   /api/v1/alerts              — list alerts
GET   /api/v1/alerts/{id}         — single alert detail
PATCH /api/v1/alerts/{id}/status  — update alert status
"""
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.models.models import Alert
from app.schemas.telemetry import AlertOut

router = APIRouter()


class AlertStatusUpdate(BaseModel):
    status: str  # open | closed | false_positive | in_incident


@router.get("", response_model=List[AlertOut])
async def list_alerts(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    host: Optional[str] = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """List alerts with optional filters."""
    q = select(Alert).order_by(Alert.created_at.desc())
    if status:
        q = q.where(Alert.status == status)
    if severity:
        q = q.where(Alert.severity == severity)
    if host:
        q = q.where(Alert.host.ilike(f"%{host}%"))
    q = q.limit(limit).offset(offset)

    result = await db.execute(q)
    return list(result.scalars().all())


@router.get("/{alert_id}", response_model=AlertOut)
async def get_alert(alert_id: UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/{alert_id}/status", response_model=AlertOut)
async def update_alert_status(
    alert_id: UUID,
    body: AlertStatusUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update alert status (analyst action)."""
    valid = {"open", "closed", "false_positive", "in_incident"}
    if body.status not in valid:
        raise HTTPException(status_code=422, detail=f"status must be one of {valid}")

    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = body.status
    await db.commit()
    await db.refresh(alert)
    return alert
