"""
Attack Story API endpoints.

GET  /api/v1/attack-story/{incident_id}         — get stored attack story
POST /api/v1/attack-story/{incident_id}/generate — regenerate attack story
"""
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.models.models import Incident
from app.agents.attack_story.agent import AttackStoryAgent

router = APIRouter()


@router.get("/{incident_id}")
async def get_attack_story(incident_id: UUID, db: AsyncSession = Depends(get_db)):
    """Return the stored attack story for an incident."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if not incident.attack_story:
        raise HTTPException(status_code=404, detail="Attack story not yet generated. POST to /generate first.")
    return incident.attack_story


@router.post("/{incident_id}/generate")
async def generate_attack_story(incident_id: UUID, db: AsyncSession = Depends(get_db)):
    """Trigger attack story generation for an incident."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    agent = AttackStoryAgent(db, incident)
    story = await agent.run()
    await db.commit()
    return story
