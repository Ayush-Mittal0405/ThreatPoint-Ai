"""
Investigation Agent — the primary evidence-collection loop.

Reasoning cycle:
  1. Form hypothesis from incident context
  2. Identify missing evidence
  3. Select and call a tool
  4. Analyze result
  5. Update hypothesis
  6. Repeat until sufficient evidence or max_iterations reached
"""
from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict, List, Optional, TYPE_CHECKING

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.models import Incident, AgentTrace
from app.tools.registry import ToolRegistry

if TYPE_CHECKING:
    from app.agents.orchestrator.orchestrator import AgentOrchestrator

log = structlog.get_logger()

INVESTIGATION_SYSTEM_PROMPT = """You are an AI security analyst performing an incident investigation.

Your job:
1. Reason about what happened based on available evidence.
2. Identify what evidence is missing.
3. Choose the BEST tool to gather missing evidence.
4. Analyze the tool result.
5. Update your hypothesis.
6. Decide: do you need more evidence, or do you have enough to conclude?

Available tools (call by name):
- search_endpoint_events(host, event_type, limit) — search endpoint telemetry
- search_process_tree(host, process_name) — get parent-child process relationships
- search_network_events(host, src_ip, dst_ip, limit) — search network connections
- search_user_activity(username, host, limit) — search user authentication and actions
- lookup_ip(ip) — threat intelligence for an IP address
- lookup_domain(domain) — threat intelligence for a domain
- lookup_hash(hash_value) — threat intelligence for a file hash
- search_mitre_technique(technique_id) — get MITRE ATT&CK technique details

Rules:
- NEVER invent tool results. Only use what the tool returns.
- NEVER call a write/response tool. You are read-only.
- Output ONLY valid JSON for each reasoning step.
- Stop when you have enough evidence to form a conclusion.

For each step, respond with JSON:
{
  "reasoning": "what I know and what I need",
  "has_enough_evidence": true/false,
  "next_tool": "tool_name or null",
  "tool_args": {"arg": "value"},
  "conclusion": "final summary when has_enough_evidence is true, otherwise null"
}"""


class InvestigationAgent:
    """Primary agentic investigation loop with tool-calling."""

    def __init__(
        self,
        db: AsyncSession,
        incident: Incident,
        max_iterations: int = 10,
    ):
        self.db = db
        self.incident = incident
        self.max_iterations = max_iterations
        self.tool_registry = ToolRegistry(db)
        self._evidence_log: List[Dict] = []

    async def run(
        self,
        orchestrator: Optional["AgentOrchestrator"] = None,
        step_offset: int = 0,
    ) -> Dict:
        """Run the investigation loop. Returns final conclusion dict."""
        log.info(
            "Investigation agent starting",
            incident_id=self.incident.incident_id,
            max_iterations=self.max_iterations,
        )

        context = self._build_initial_context()
        step = step_offset
        conclusion = None

        for iteration in range(self.max_iterations):
            step += 1
            log.info(
                "Investigation iteration",
                iteration=iteration + 1,
                max=self.max_iterations,
            )

            # ── Ask LLM for next reasoning step ───────────────────────────
            llm_response = await self._ask_llm(context)
            if not llm_response:
                log.warning("LLM unavailable, stopping investigation")
                break

            reasoning = llm_response.get("reasoning", "")
            has_enough = llm_response.get("has_enough_evidence", False)
            next_tool = llm_response.get("next_tool")
            tool_args = llm_response.get("tool_args", {})
            conclusion = llm_response.get("conclusion")

            # Record reasoning step
            if orchestrator:
                await orchestrator.record_tool_call(
                    self.incident, step, "investigation",
                    "reasoning", {"iteration": iteration + 1},
                    {"reasoning": reasoning, "has_enough_evidence": has_enough},
                )

            if has_enough or not next_tool:
                log.info("Investigation concluded", iteration=iteration + 1)
                break

            # ── Execute tool ───────────────────────────────────────────────
            tool_start = time.monotonic()
            tool_result = await self.tool_registry.call(next_tool, tool_args)
            tool_duration = int((time.monotonic() - tool_start) * 1000)

            # Record tool call
            if orchestrator:
                await orchestrator.record_tool_call(
                    self.incident, step + 1, "investigation",
                    next_tool, tool_args, tool_result,
                    duration_ms=tool_duration,
                )

            # Add to evidence log and context
            self._evidence_log.append({
                "tool": next_tool,
                "args": tool_args,
                "result": tool_result,
            })
            context = self._update_context(context, next_tool, tool_args, tool_result)
            step += 1

        # Persist summary to incident
        self.incident.recommendations = [{"conclusion": conclusion}] if conclusion else []
        await self.db.flush()

        return {
            "iterations": iteration + 1,
            "evidence_collected": len(self._evidence_log),
            "conclusion": conclusion,
            "last_step": step,
        }

    def _build_initial_context(self) -> str:
        """Build the first context message for the LLM."""
        return json.dumps({
            "incident_id": self.incident.incident_id,
            "title": self.incident.title,
            "severity": self.incident.severity,
            "entities": self.incident.entities or {},
            "mitre_techniques": self.incident.mitre_techniques or [],
            "evidence_so_far": [],
        }, indent=2)

    def _update_context(
        self, context: str, tool: str, args: Dict, result: Any
    ) -> str:
        """Append tool result to the context."""
        try:
            ctx = json.loads(context)
        except Exception:
            ctx = {}
        ctx.setdefault("evidence_so_far", []).append({
            "tool": tool,
            "args": args,
            "result": result,
        })
        return json.dumps(ctx, indent=2)

    async def _ask_llm(self, context: str) -> Optional[Dict]:
        """Send reasoning request to Ollama and parse JSON response."""
        try:
            import httpx
            payload = {
                "model": settings.OLLAMA_MODEL,
                "messages": [
                    {"role": "system", "content": INVESTIGATION_SYSTEM_PROMPT},
                    {"role": "user", "content": context},
                ],
                "stream": False,
                "format": "json",
            }
            async with httpx.AsyncClient(timeout=90.0) as client:
                resp = await client.post(
                    f"{settings.OLLAMA_BASE_URL}/api/chat",
                    json=payload,
                )
                resp.raise_for_status()
                content = resp.json()["message"]["content"]
                return json.loads(content)
        except Exception as exc:
            log.warning("LLM call failed in investigation loop", error=str(exc))
            return None
