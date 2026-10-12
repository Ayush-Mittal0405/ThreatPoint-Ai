"""
Agent trigger endpoints.

POST /api/v1/agents/investigate/{incident_id}  — trigger full AI investigation
GET  /api/v1/agents/investigate/{incident_id}/status — check investigation status
"""
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.models.models import Incident
from app.agents.orchestrator.orchestrator import AgentOrchestrator
from app.worker import enqueue_investigation

router = APIRouter()


class InvestigationStatus(BaseModel):
    incident_id: str
    status: str
    message: str
    job_id: Optional[str] = None


@router.post("/investigate/{incident_id}", response_model=InvestigationStatus)
async def trigger_investigation(
    incident_id: UUID,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Trigger the AI investigation pipeline for an incident.
    Attempts to enqueue to ARQ Redis worker queue; falls back to BackgroundTasks.
    Runs asynchronously — poll /status or read the incident trace.
    """
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    if incident.status == "investigating":
        return InvestigationStatus(
            incident_id=incident.incident_id,
            status="already_running",
            message="An investigation is already in progress for this incident.",
        )

    # Mark as investigating immediately
    incident.status = "investigating"
    await db.commit()

    # Attempt ARQ queue dispatch
    job_id = await enqueue_investigation(str(incident_id))
    if job_id:
        return InvestigationStatus(
            incident_id=incident.incident_id,
            status="queued",
            message="AI investigation queued in background worker. Check /trace for progress.",
            job_id=job_id,
        )

    # Fallback to local background task execution
    orchestrator = AgentOrchestrator(db)
    background_tasks.add_task(orchestrator.investigate, str(incident_id))

    return InvestigationStatus(
        incident_id=incident.incident_id,
        status="started",
        message="AI investigation started via background task. Check /trace for progress.",
    )


@router.get("/investigate/{incident_id}/status", response_model=InvestigationStatus)
async def investigation_status(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    return InvestigationStatus(
        incident_id=incident.incident_id,
        status=incident.status,
        message=f"Incident is currently {incident.status}.",
    )
