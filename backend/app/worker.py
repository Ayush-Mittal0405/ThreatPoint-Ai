"""
AegisX Background Worker — ARQ-based async task queue.

Moves long-running agent jobs off the FastAPI request thread.

Usage:
    # Start the worker (runs indefinitely):
    arq app.worker.WorkerSettings

    # Or via the helper script:
    python -m app.worker

ARQ docs: https://arq-docs.helpmanual.io/

Tasks:
  - investigate_incident_task  — runs full Orchestrator pipeline for an incident
  - hunt_task                  — runs HuntingAgent for a natural-language query
  - correlate_alerts_task      — runs CorrelationEngine on pending alerts

Redis config is read from settings.REDIS_URL (default: redis://localhost:6379).
Falls back to a no-op stub when ARQ is not installed, so the app still boots.
"""
from __future__ import annotations

import sys
import asyncio
from datetime import timedelta
from typing import Any, Dict, Optional

import structlog

from app.core.config import settings
from app.core.database import AsyncSessionLocal

log = structlog.get_logger()

# ── ARQ availability guard ────────────────────────────────────────────────────

try:
    import arq
    ARQ_AVAILABLE = True
except ImportError:
    arq = None  # type: ignore
    ARQ_AVAILABLE = False
    log.warning("arq not installed — background worker disabled. Run: pip install arq")


# ── Task: Investigate Incident ────────────────────────────────────────────────

async def investigate_incident_task(ctx: Dict, incident_id: str) -> Dict[str, Any]:
    """
    Run the full agent orchestration pipeline for a given incident.
    Equivalent to POST /agents/investigate/{incident_id} but async/queued.
    """
    log.info("Worker: starting investigation", incident_id=incident_id)
    async with AsyncSessionLocal() as db:
        try:
            from app.agents.orchestrator.orchestrator import AgentOrchestrator
            orchestrator = AgentOrchestrator(db)
            result = await orchestrator.run(incident_id)
            await db.commit()
            log.info("Worker: investigation complete", incident_id=incident_id)
            return {"status": "ok", "incident_id": incident_id, "result": str(result)[:500]}
        except Exception as exc:
            log.error("Worker: investigation failed", incident_id=incident_id, error=str(exc))
            return {"status": "error", "incident_id": incident_id, "error": str(exc)}


# ── Task: Threat Hunt ─────────────────────────────────────────────────────────

async def hunt_task(
    ctx: Dict,
    query: str,
    context: Optional[Dict] = None,
) -> Dict[str, Any]:
    """
    Run the HuntingAgent for a natural-language query in the background.
    Returns a full HuntReport dict.
    """
    log.info("Worker: starting hunt", query=query[:80])
    async with AsyncSessionLocal() as db:
        try:
            from app.agents.hunting.agent import HuntingAgent
            agent = HuntingAgent(db)
            report = await agent.hunt(query=query, context=context)
            log.info("Worker: hunt complete", hunt_id=report.get("hunt_id"), findings=len(report.get("findings", [])))
            return report
        except Exception as exc:
            log.error("Worker: hunt failed", query=query[:80], error=str(exc))
            return {"status": "error", "query": query, "error": str(exc)}


# ── Task: Correlate Alerts ────────────────────────────────────────────────────

async def correlate_alerts_task(ctx: Dict) -> Dict[str, Any]:
    """
    Run the CorrelationEngine to group pending open alerts into incidents.
    Designed to be called on a schedule (e.g., every 5 minutes).
    """
    log.info("Worker: starting correlation run")
    async with AsyncSessionLocal() as db:
        try:
            from app.correlation.engine import CorrelationEngine
            engine = CorrelationEngine(db)
            incidents = await engine.correlate_pending_alerts()
            await db.commit()
            log.info("Worker: correlation complete", new_incidents=len(incidents))
            return {"status": "ok", "incidents_created": len(incidents)}
        except Exception as exc:
            log.error("Worker: correlation failed", error=str(exc))
            return {"status": "error", "error": str(exc)}


# ── Startup / Shutdown ────────────────────────────────────────────────────────

async def startup(ctx: Dict) -> None:
    """Worker startup — initialize shared resources."""
    log.info("AegisX ARQ worker starting", redis=settings.REDIS_URL)


async def shutdown(ctx: Dict) -> None:
    """Worker shutdown — clean up shared resources."""
    log.info("AegisX ARQ worker shutting down")


# ── WorkerSettings ────────────────────────────────────────────────────────────

if ARQ_AVAILABLE:
    class WorkerSettings:
        """ARQ worker configuration — pass to `arq app.worker.WorkerSettings`."""
        functions = [
            investigate_incident_task,
            hunt_task,
            correlate_alerts_task,
        ]
        on_startup  = startup
        on_shutdown = shutdown
        redis_settings = arq.connections.RedisSettings.from_dsn(
            getattr(settings, "REDIS_URL", "redis://localhost:6379")
        )
        max_jobs          = 10
        job_timeout       = 300    # 5 min max per job
        keep_result       = 3600   # keep results 1 hour
        poll_delay        = 0.5    # check queue every 500ms
        retry_jobs        = True
        max_tries         = 3
else:
    class WorkerSettings:  # type: ignore
        """Stub when ARQ not installed."""
        functions = []


# ── Enqueue helpers (used from API endpoints) ─────────────────────────────────

async def enqueue_investigation(incident_id: str) -> Optional[str]:
    """
    Enqueue an investigation task.
    Returns the job ID, or None if ARQ is unavailable.
    """
    if not ARQ_AVAILABLE:
        log.warning("ARQ not available — running investigation synchronously")
        return None
    try:
        redis = await arq.create_pool(WorkerSettings.redis_settings)
        job = await redis.enqueue_job("investigate_incident_task", incident_id)
        await redis.close()
        return job.job_id if job else None
    except Exception as exc:
        log.error("Failed to enqueue investigation", error=str(exc))
        return None


async def enqueue_hunt(query: str, context: Optional[Dict] = None) -> Optional[str]:
    """
    Enqueue a threat hunt task.
    Returns the job ID, or None if ARQ is unavailable.
    """
    if not ARQ_AVAILABLE:
        return None
    try:
        redis = await arq.create_pool(WorkerSettings.redis_settings)
        job = await redis.enqueue_job("hunt_task", query, context)
        await redis.close()
        return job.job_id if job else None
    except Exception as exc:
        log.error("Failed to enqueue hunt", error=str(exc))
        return None


# ── CLI entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not ARQ_AVAILABLE:
        print("ERROR: arq is not installed. Run: pip install arq", file=sys.stderr)
        sys.exit(1)
    arq.run_worker(WorkerSettings)
