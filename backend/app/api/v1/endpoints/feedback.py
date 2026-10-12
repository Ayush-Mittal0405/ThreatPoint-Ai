"""
Analyst Continuous Learning Feedback API endpoints.

POST /api/v1/feedback/{incident_id} — submit analyst rating & corrections
GET  /api/v1/feedback/{incident_id} — retrieve feedback for incident
GET  /api/v1/feedback/stats        — aggregated analyst feedback metrics
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.database import get_db
from app.models.models import Incident, AnalystFeedback

router = APIRouter()


class FeedbackIn(BaseModel):
    rating: int = Field(ge=1, le=5, description="1 to 5 star rating")
    is_false_positive: bool = False
    category: Optional[str] = Field(
        default="accurate",
        description="Category: accurate | missed_evidence | wrong_triage | wrong_remediation",
    )
    analyst_note: Optional[str] = None
    corrected_severity: Optional[str] = None


class FeedbackOut(BaseModel):
    id: str
    incident_id: str
    rating: int
    is_false_positive: bool
    category: Optional[str]
    analyst_note: Optional[str]
    corrected_severity: Optional[str]
    created_at: str


@router.post("/{incident_id}", response_model=FeedbackOut)
async def submit_feedback(
    incident_id: UUID,
    body: FeedbackIn,
    db: AsyncSession = Depends(get_db),
):
    """Submit analyst review and continuous learning feedback for an incident."""
    res = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = res.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    feedback_record = AnalystFeedback(
        id=uuid.uuid4(),
        incident_id=incident.id,
        rating=body.rating,
        is_false_positive=body.is_false_positive,
        category=body.category,
        analyst_note=body.analyst_note,
        corrected_severity=body.corrected_severity,
        created_at=datetime.now(timezone.utc),
    )
    db.add(feedback_record)

    # Update incident state
    feedback_dict = {
        "rating": body.rating,
        "is_false_positive": body.is_false_positive,
        "category": body.category,
        "analyst_note": body.analyst_note,
        "corrected_severity": body.corrected_severity,
        "submitted_at": datetime.now(timezone.utc).isoformat(),
    }
    incident.analyst_feedback = feedback_dict

    if body.is_false_positive:
        incident.status = "false_positive"
    if body.corrected_severity:
        incident.severity = body.corrected_severity

    await db.commit()

    return FeedbackOut(
        id=str(feedback_record.id),
        incident_id=str(incident.id),
        rating=feedback_record.rating,
        is_false_positive=feedback_record.is_false_positive,
        category=feedback_record.category,
        analyst_note=feedback_record.analyst_note,
        corrected_severity=feedback_record.corrected_severity,
        created_at=feedback_record.created_at.isoformat(),
    )


@router.get("/stats")
async def feedback_stats(db: AsyncSession = Depends(get_db)) -> Dict[str, Any]:
    """Retrieve aggregated analyst continuous learning statistics."""
    result = await db.execute(select(AnalystFeedback))
    records: List[AnalystFeedback] = list(result.scalars().all())

    total = len(records)
    if total == 0:
        return {
            "total_feedback": 0,
            "average_rating": 5.0,
            "false_positive_rate": 0.0,
            "categories": {"accurate": 0, "missed_evidence": 0, "wrong_triage": 0, "wrong_remediation": 0},
            "note": "No analyst feedback recorded yet.",
        }

    avg_rating = round(sum(r.rating for r in records) / total, 2)
    fp_count = sum(1 for r in records if r.is_false_positive)
    fp_rate = round(fp_count / total, 2)

    categories: Dict[str, int] = {}
    for r in records:
        cat = r.category or "accurate"
        categories[cat] = categories.get(cat, 0) + 1

    return {
        "total_feedback": total,
        "average_rating": avg_rating,
        "false_positive_rate": fp_rate,
        "categories": categories,
    }


@router.get("/{incident_id}")
async def get_incident_feedback(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> Optional[Dict[str, Any]]:
    """Retrieve the latest analyst feedback for an incident."""
    res = await db.execute(
        select(AnalystFeedback)
        .where(AnalystFeedback.incident_id == incident_id)
        .order_by(AnalystFeedback.created_at.desc())
    )
    feedback = res.scalars().first()
    if not feedback:
        return None

    return {
        "id": str(feedback.id),
        "incident_id": str(feedback.incident_id),
        "rating": feedback.rating,
        "is_false_positive": feedback.is_false_positive,
        "category": feedback.category,
        "analyst_note": feedback.analyst_note,
        "corrected_severity": feedback.corrected_severity,
        "created_at": feedback.created_at.isoformat(),
    }
