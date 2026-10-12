"""
Model Metrics API endpoint.

GET /api/v1/models/metrics  — per-agent precision/recall/F1/hallucination/FP
                               computed from AgentTrace records in DB.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.database import get_db
from app.models.models import AgentTrace

router = APIRouter()

# Agent registry — display names
AGENT_LABELS: Dict[str, str] = {
    "triage":        "Triage Agent",
    "investigation": "Investigation Agent",
    "attack_story":  "Attack Story Agent",
    "response":      "Response Agent",
    "verification":  "Verification Agent",
    "hunting":       "Hunting Agent",
}


@router.get("/metrics")
async def get_model_metrics(
    days: int = 30,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Return per-agent evaluation metrics derived from AgentTrace records.

    Metrics computed:
    - precision  = successful_steps / total_steps  (proxy)
    - recall     = steps_with_result / expected_steps  (proxy)
    - f1         = harmonic mean
    - hallucination_rate = steps where tool call returned 'no_result' / total tool steps
    - false_positive_rate = steps marked failed / total steps (proxy for FP)
    - total_invocations = distinct incident traces per agent
    - avg_latency_ms = avg step duration
    - fp_trend  = daily FP rate for last 7 days
    """
    since = datetime.now(timezone.utc) - timedelta(days=days)

    # Load all agent traces in the window
    result = await db.execute(
        select(AgentTrace).where(AgentTrace.timestamp >= since)
    )
    traces: List[AgentTrace] = list(result.scalars().all())

    # Group by agent
    by_agent: Dict[str, List[AgentTrace]] = {}
    for t in traces:
        by_agent.setdefault(t.agent_name, []).append(t)

    agents_out = []
    for agent_key, label in AGENT_LABELS.items():
        steps = by_agent.get(agent_key, [])

        total     = len(steps) or 1
        successes = sum(1 for s in steps if s.success)
        failures  = total - successes
        tool_steps = [s for s in steps if s.tool_name]
        no_result  = sum(1 for s in tool_steps if s.error and "no_result" in str(s.error).lower())

        precision = round(successes / total, 4)
        recall    = round(min(successes / max(total * 0.9, 1), 1.0), 4)  # proxy
        f1 = round(
            2 * precision * recall / max(precision + recall, 0.001), 4
        )
        hallucination_rate = round(no_result / max(len(tool_steps), 1), 4)
        false_positive_rate = round(failures / total, 4)

        avg_latency = (
            sum(s.duration_ms for s in steps if s.duration_ms) / total
            if steps else 0
        )

        # FP trend: last 7 days (one bucket per day)
        fp_trend = _daily_fp_trend(steps, days=7)

        agents_out.append({
            "agent":               agent_key,
            "label":               label,
            "precision":           precision,
            "recall":              recall,
            "f1":                  f1,
            "hallucination_rate":  hallucination_rate,
            "false_positive_rate": false_positive_rate,
            "total_invocations":   total,
            "avg_latency_ms":      round(avg_latency, 1),
            "fp_trend":            fp_trend,
        })

    return {
        "agents":        agents_out,
        "window_days":   days,
        "generated_at":  datetime.now(timezone.utc).isoformat(),
        "note":          "Metrics derived from AgentTrace records. For accuracy, ensure traces are populated via agent runs.",
    }


def _daily_fp_trend(steps: List[AgentTrace], days: int = 7) -> List[float]:
    """Compute daily false-positive-rate proxies for the last `days` days."""
    now = datetime.now(timezone.utc)
    trend = []
    for d in range(days - 1, -1, -1):
        day_start = now - timedelta(days=d + 1)
        day_end   = now - timedelta(days=d)
        day_steps = [
            s for s in steps
            if s.timestamp and day_start <= s.timestamp < day_end
        ]
        if not day_steps:
            # Carry forward last or use placeholder
            trend.append(trend[-1] if trend else 0.0)
        else:
            failures = sum(1 for s in day_steps if not s.success)
            trend.append(round(failures / len(day_steps), 4))
    return trend
