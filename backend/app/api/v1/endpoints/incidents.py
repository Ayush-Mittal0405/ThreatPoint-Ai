"""
Incident management endpoints.

GET  /api/v1/incidents            — list incidents
GET  /api/v1/incidents/{id}       — incident detail (with alerts, evidence)
GET  /api/v1/incidents/{id}/trace — AI investigation trace
PATCH /api/v1/incidents/{id}/status
"""
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models.models import Incident, AgentTrace
from app.schemas.telemetry import IncidentOut, IncidentListOut

router = APIRouter()


class IncidentStatusUpdate(BaseModel):
    status: str  # open | investigating | responded | closed | false_positive


class AgentTraceOut(BaseModel):
    id: UUID
    agent_name: str
    step: int
    action: str
    tool_name: Optional[str]
    tool_args: Optional[dict]
    reasoning: Optional[str]
    success: bool
    error: Optional[str]

    model_config = {"from_attributes": True}


@router.get("", response_model=IncidentListOut)
async def list_incidents(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(20, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """List incidents, newest first."""
    q = select(Incident).order_by(Incident.created_at.desc())
    if status:
        q = q.where(Incident.status == status)
    if severity:
        q = q.where(Incident.severity == severity)

    count_result = await db.execute(select(Incident))
    total = len(list(count_result.scalars().all()))

    q = q.limit(limit).offset(offset)
    result = await db.execute(q)
    incidents = list(result.scalars().all())

    return IncidentListOut(total=total, incidents=incidents)


@router.get("/{incident_id}", response_model=IncidentOut)
async def get_incident(incident_id: UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Incident).where(Incident.id == incident_id)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.get("/{incident_id}/trace", response_model=List[AgentTraceOut])
async def get_investigation_trace(incident_id: UUID, db: AsyncSession = Depends(get_db)):
    """Return the ordered AI investigation trace for an incident."""
    result = await db.execute(
        select(AgentTrace)
        .where(AgentTrace.incident_id == incident_id)
        .order_by(AgentTrace.step)
    )
    return list(result.scalars().all())


@router.patch("/{incident_id}/status", response_model=IncidentOut)
async def update_incident_status(
    incident_id: UUID,
    body: IncidentStatusUpdate,
    db: AsyncSession = Depends(get_db),
):
    valid = {"open", "investigating", "responded", "closed", "false_positive"}
    if body.status not in valid:
        raise HTTPException(status_code=422, detail=f"status must be one of {valid}")

    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident.status = body.status
    await db.commit()
    await db.refresh(incident)
    return incident
