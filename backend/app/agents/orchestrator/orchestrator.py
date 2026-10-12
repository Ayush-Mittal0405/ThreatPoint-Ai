"""
Agent Orchestrator — receives an incident, routes it through the agent pipeline,
enforces iteration limits, and records every action to AgentTrace.
"""
from __future__ import annotations

import uuid
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import settings
from app.models.models import Incident, AgentTrace
from app.agents.triage.agent import TriageAgent
from app.agents.investigation.agent import InvestigationAgent

log = structlog.get_logger()


class AgentOrchestrator:
    """
    Central controller for the agentic investigation loop.

    Sequence:
        1. Triage Agent — classify, severity, FP probability
        2. Investigation Agent — evidence collection loop
        3. (Future) Attack Story Agent, Risk Engine, Response Agent
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def investigate(self, incident_uuid: str) -> None:
        """Entry point — runs the full pipeline for one incident."""
        result = await self.db.execute(
            select(Incident).where(Incident.id == uuid.UUID(incident_uuid))
        )
        incident = result.scalar_one_or_none()
        if not incident:
            log.error("Incident not found for investigation", id=incident_uuid)
            return

        log.info("Investigation started", incident_id=incident.incident_id)
        step = 0

        try:
            # ── Step 1: Triage ─────────────────────────────────────────────
            step += 1
            triage = TriageAgent(self.db, incident)
            triage_result = await self._run_agent_step(
                incident, step, "triage", "triage_classification", triage
            )
            if triage_result:
                incident.confidence = triage_result.get("confidence")
                # Store triage result on incident
                incident.investigation_trace = incident.investigation_trace or []
                incident.investigation_trace.append(
                    {"step": step, "agent": "triage", "result": triage_result}
                )

            # ── Step 2: Investigation ───────────────────────────────────────
            step += 1
            inv_agent = InvestigationAgent(
                self.db,
                incident,
                max_iterations=settings.AGENT_MAX_ITERATIONS,
            )
            inv_result = await inv_agent.run(orchestrator=self, step_offset=step)
            if inv_result:
                step = inv_result.get("last_step", step)
                incident.investigation_trace = incident.investigation_trace or []
                incident.investigation_trace.append(
                    {"step": step, "agent": "investigation", "result": inv_result}
                )

            # Mark done
            incident.status = "responded" if inv_result else "open"
            await self.db.commit()
            log.info("Investigation complete", incident_id=incident.incident_id)

        except Exception as exc:
            log.exception("Investigation failed", incident_id=incident.incident_id, error=str(exc))
            incident.status = "open"
            await self.db.commit()

    async def _run_agent_step(
        self,
        incident: Incident,
        step: int,
        agent_name: str,
        action: str,
        agent: Any,
    ) -> Optional[Dict]:
        """Run a single agent step and record trace."""
        start = time.monotonic()
        result = None
        success = True
        error = None

        try:
            result = await agent.run()
        except Exception as exc:
            success = False
            error = str(exc)
            log.warning("Agent step failed", agent=agent_name, step=step, error=error)

        duration_ms = int((time.monotonic() - start) * 1000)

        trace = AgentTrace(
            id=uuid.uuid4(),
            incident_id=incident.id,
            agent_name=agent_name,
            step=step,
            action=action,
            reasoning=str(result) if result else None,
            success=success,
            error=error,
            duration_ms=duration_ms,
        )
        self.db.add(trace)
        await self.db.flush()
        return result

    async def record_tool_call(
        self,
        incident: Incident,
        step: int,
        agent_name: str,
        tool_name: str,
        tool_args: Dict,
        tool_result: Any,
        success: bool = True,
        error: Optional[str] = None,
        duration_ms: Optional[int] = None,
    ) -> None:
        """Record a single tool call to the audit trail."""
        trace = AgentTrace(
            id=uuid.uuid4(),
            incident_id=incident.id,
            agent_name=agent_name,
            step=step,
            action="tool_call",
            tool_name=tool_name,
            tool_args=tool_args,
            tool_result=tool_result if isinstance(tool_result, dict) else {"result": str(tool_result)},
            success=success,
            error=error,
            duration_ms=duration_ms,
        )
        self.db.add(trace)
        await self.db.flush()
