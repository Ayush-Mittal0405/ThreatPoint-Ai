"""
Threat Hunting API endpoints.

POST /api/v1/hunting/hunt      — run a natural-language threat hunt
GET  /api/v1/hunting/recent    — last 10 hunt reports
GET  /api/v1/hunting/{hunt_id} — retrieve a specific hunt report
"""
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.agents.hunting.agent import HuntingAgent

router = APIRouter()

# In-memory hunt store (Phase 7: replace with DB persistence)
_hunt_store: Dict[str, Dict] = {}


class HuntRequest(BaseModel):
    query: str
    context: Optional[Dict[str, Any]] = None   # {host, user, technique, ...}


class HuntSummary(BaseModel):
    hunt_id: str
    query: str
    conclusion: str
    confidence: float
    findings_count: int
    evidence_count: int
    duration_seconds: float
    started_at: str


@router.post("/hunt")
async def run_hunt(
    body: HuntRequest,
    db: AsyncSession = Depends(get_db),
) -> Dict:
    """
    Run a natural-language threat hunt.
    The hunting agent will autonomously search telemetry and return findings.
    """
    agent = HuntingAgent(db)
    report = await agent.hunt(query=body.query, context=body.context)

    # Store for retrieval
    _hunt_store[report["hunt_id"]] = report

    # Keep only last 50
    if len(_hunt_store) > 50:
        oldest_key = next(iter(_hunt_store))
        del _hunt_store[oldest_key]

    return report


@router.get("/recent", response_model=List[HuntSummary])
async def recent_hunts() -> List[HuntSummary]:
    """Return summaries of the last 10 hunt reports."""
    recent = list(reversed(list(_hunt_store.values())))[:10]
    return [
        HuntSummary(
            hunt_id=h["hunt_id"],
            query=h["query"],
            conclusion=h.get("conclusion", ""),
            confidence=h.get("confidence", 0.0),
            findings_count=len(h.get("findings", [])),
            evidence_count=len(h.get("evidence", [])),
            duration_seconds=h.get("duration_seconds", 0.0),
            started_at=h.get("started_at", ""),
        )
        for h in recent
    ]


@router.get("/{hunt_id}")
async def get_hunt(hunt_id: str) -> Dict:
    """Retrieve a specific hunt report by ID."""
    from fastapi import HTTPException
    report = _hunt_store.get(hunt_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Hunt {hunt_id} not found. It may have expired from in-memory store.")
    return report
