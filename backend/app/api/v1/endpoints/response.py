"""
Response workflow endpoints — recommendation, approval, execution, verification.

POST /api/v1/response/{incident_id}/recommend  — get AI response recommendations
POST /api/v1/response/{incident_id}/approve    — human approves a recommendation
POST /api/v1/response/{incident_id}/execute    — execute an approved action (lab-safe only)
POST /api/v1/response/{incident_id}/verify     — run verification agent
GET  /api/v1/response/{incident_id}/status     — get current response status
"""
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.models.models import Incident
from app.agents.response.agent import ResponseAgent
from app.agents.verification.agent import VerificationAgent

router = APIRouter()


class ApprovalRequest(BaseModel):
    action_index: int        # index in the recommendations list
    analyst_note: str = ""


class ExecutionRequest(BaseModel):
    action_index: int
    confirm: bool = False    # safety gate — must be True


@router.post("/{incident_id}/recommend")
async def get_recommendations(incident_id: UUID, db: AsyncSession = Depends(get_db)):
    """Generate AI response recommendations for an incident."""
    incident = await _get_incident(incident_id, db)
    agent = ResponseAgent(db, incident)
    result = await agent.recommend()
    await db.commit()
    return result


@router.post("/{incident_id}/approve")
async def approve_recommendation(
    incident_id: UUID,
    body: ApprovalRequest,
    db: AsyncSession = Depends(get_db),
):
    """Human analyst approves a specific recommended action."""
    incident = await _get_incident(incident_id, db)
    recs = incident.recommendations or []

    if body.action_index >= len(recs):
        raise HTTPException(status_code=400, detail="Invalid action index")

    # Mark as approved (immutable list — copy and update)
    recs = list(recs)
    recs[body.action_index] = {
        **recs[body.action_index],
        "approved": True,
        "analyst_note": body.analyst_note,
    }
    incident.recommendations = recs
    await db.commit()

    return {
        "approved": True,
        "action": recs[body.action_index],
        "message": "Action approved. Call /execute to run it.",
    }


@router.post("/{incident_id}/execute")
async def execute_action(
    incident_id: UUID,
    body: ExecutionRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Execute an approved response action (lab-safe stub).
    Requires human approval first and confirm=True safety gate.
    """
    if not body.confirm:
        raise HTTPException(status_code=400, detail="Set confirm=True to execute.")

    incident = await _get_incident(incident_id, db)
    recs = incident.recommendations or []

    if body.action_index >= len(recs):
        raise HTTPException(status_code=400, detail="Invalid action index")

    action = recs[body.action_index]
    if not action.get("approved"):
        raise HTTPException(
            status_code=403,
            detail="Action not approved. Call /approve first.",
        )

    # Lab-safe execution stub (real implementation requires endpoint agent)
    result = _lab_execute(action)

    recs = list(recs)
    recs[body.action_index] = {**action, "executed": True, "execution_result": result}
    incident.recommendations = recs
    await db.commit()
    return result


@router.post("/{incident_id}/verify")
async def verify_remediation(incident_id: UUID, db: AsyncSession = Depends(get_db)):
    """Run the Verification Agent to check if the threat was remediated."""
    incident = await _get_incident(incident_id, db)
    agent = VerificationAgent(db, incident)
    result = await agent.verify()
    await db.commit()
    return result


@router.get("/{incident_id}/status")
async def response_status(incident_id: UUID, db: AsyncSession = Depends(get_db)):
    """Get current response and verification status."""
    incident = await _get_incident(incident_id, db)
    return {
        "incident_id": incident.incident_id,
        "status": incident.status,
        "recommendations": incident.recommendations or [],
        "verification": incident.verification,
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _get_incident(incident_id: UUID, db: AsyncSession) -> Incident:
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


def _lab_execute(action: dict) -> dict:
    """
    Lab-safe execution stub.
    In production this would call an endpoint agent / SOAR integration.
    Currently logs the action and returns a simulated success.
    """
    return {
        "action": action.get("action"),
        "target": action.get("target"),
        "status": "simulated_success",
        "message": (
            f"[LAB SIMULATION] Would execute '{action.get('action')}' on '{action.get('target')}'. "
            "Configure an endpoint agent for real execution."
        ),
    }
