"""
Threat Hunting Agent — accepts a natural-language hunt query and
autonomously searches the telemetry database for evidence.

Loop:
  1. LLM generates a structured hypothesis from the NL query
  2. Agent selects the best tool to test each hypothesis
  3. Collects and interprets evidence
  4. Produces a hunting report
"""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.tools.registry import ToolRegistry
from app.rag.retriever import rag_context_for_query

log = structlog.get_logger()

HUNT_SYSTEM = """You are a threat hunter in a security operations center.

Given a natural-language hunting query, you must:
1. Generate a structured hypothesis about what threat behavior to look for.
2. Choose a tool to gather evidence to test your hypothesis.
3. Interpret the tool result and update your hypothesis.
4. Repeat until you have a conclusion.

Available tools (read-only — you may ONLY use these):
- search_endpoint_events(host, event_type, limit) — endpoint telemetry
- search_process_tree(host, process_name) — parent-child process tree
- search_network_events(host, src_ip, dst_ip, limit) — network connections
- search_user_activity(username, host, limit) — user auth and account events
- search_historical_incidents(host, mitre_technique, limit) — past incidents
- lookup_ip(ip) — threat intelligence for an IP
- lookup_domain(domain) — threat intelligence for a domain
- search_mitre_technique(technique_id) — MITRE ATT&CK technique details

Return ONLY valid JSON for each step:
{
  "hypothesis": "what you think is happening",
  "next_tool": "tool_name or null if done",
  "tool_args": {"arg": "value"},
  "findings_so_far": ["finding 1", "finding 2"],
  "done": true/false,
  "conclusion": "final summary if done, else null",
  "confidence": 0.0-1.0,
  "mitre_hypotheses": ["T1059.001"]
}"""


class HuntingAgent:
    """Natural-language threat hunting loop."""

    MAX_ITERATIONS = 8

    def __init__(self, db: AsyncSession):
        self.db = db
        self.tool_registry = ToolRegistry(db)

    async def hunt(self, query: str, context: Optional[Dict] = None) -> Dict:
        """
        Run a threat hunt.

        Args:
            query: Natural-language hunt query
            context: Optional filters {host, user, technique, start_time, end_time}

        Returns:
            Hunt report dict
        """
        hunt_id = f"HUNT-{uuid.uuid4().hex[:8].upper()}"
        log.info("Hunt started", hunt_id=hunt_id, query=query[:80])
        started_at = datetime.now(timezone.utc)

        # Enrich query with RAG context
        rag_context = ""
        try:
            rag_context = await rag_context_for_query(self.db, query, top_k=3)
        except Exception:
            pass

        evidence: List[Dict] = []
        findings: List[str] = []
        mitre_hypotheses: List[str] = []
        conclusion = None
        confidence = 0.0
        iterations = 0

        # Build initial context for LLM
        llm_context = self._build_context(query, context or {}, rag_context, [], [])

        for iteration in range(self.MAX_ITERATIONS):
            iterations += 1

            # Ask LLM for next step
            step = await self._ask_llm(llm_context)
            if not step:
                log.warning("LLM unavailable — using keyword-based hunt fallback")
                step = await self._keyword_hunt_fallback(query, context or {})

            hypothesis  = step.get("hypothesis", "")
            next_tool   = step.get("next_tool")
            tool_args   = step.get("tool_args", {})
            new_findings= step.get("findings_so_far", [])
            done        = step.get("done", False)
            conclusion  = step.get("conclusion")
            confidence  = step.get("confidence", 0.5)
            mitre_hypotheses = step.get("mitre_hypotheses", mitre_hypotheses)

            # Deduplicate findings
            for f in new_findings:
                if f not in findings:
                    findings.append(f)

            if done or not next_tool:
                break

            # Execute tool
            t0 = time.monotonic()
            tool_result = await self.tool_registry.call(next_tool, tool_args)
            elapsed = int((time.monotonic() - t0) * 1000)

            evidence.append({
                "iteration": iteration + 1,
                "tool": next_tool,
                "args": tool_args,
                "result": tool_result,
                "duration_ms": elapsed,
            })

            # Update LLM context
            llm_context = self._build_context(query, context or {}, rag_context, evidence, findings)

        finished_at = datetime.now(timezone.utc)
        report = {
            "hunt_id": hunt_id,
            "query": query,
            "context": context or {},
            "hypothesis": hypothesis if iterations > 0 else query,
            "findings": findings,
            "evidence": evidence,
            "mitre_hypotheses": mitre_hypotheses,
            "conclusion": conclusion or self._default_conclusion(findings, query),
            "confidence": round(confidence, 2),
            "iterations": iterations,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "duration_seconds": round((finished_at - started_at).total_seconds(), 1),
        }

        log.info(
            "Hunt complete",
            hunt_id=hunt_id,
            findings=len(findings),
            evidence_items=len(evidence),
            confidence=confidence,
        )
        return report

    def _build_context(
        self,
        query: str,
        context: Dict,
        rag_context: str,
        evidence: List[Dict],
        findings: List[str],
    ) -> str:
        return json.dumps({
            "hunt_query": query,
            "context_filters": context,
            "relevant_knowledge": rag_context[:1500] if rag_context else None,
            "evidence_so_far": [
                {"tool": e["tool"], "args": e["args"], "result_summary": str(e["result"])[:300]}
                for e in evidence
            ],
            "findings_so_far": findings,
        }, indent=2)

    async def _ask_llm(self, context: str) -> Optional[Dict]:
        """Call Ollama for the next hunt step."""
        try:
            import httpx
            payload = {
                "model": settings.OLLAMA_MODEL,
                "messages": [
                    {"role": "system", "content": HUNT_SYSTEM},
                    {"role": "user", "content": context},
                ],
                "stream": False,
                "format": "json",
            }
            async with httpx.AsyncClient(timeout=90.0) as client:
                resp = await client.post(f"{settings.OLLAMA_BASE_URL}/api/chat", json=payload)
                resp.raise_for_status()
                return json.loads(resp.json()["message"]["content"])
        except Exception as exc:
            log.warning("LLM call failed in hunting loop", error=str(exc))
            return None

    async def _keyword_hunt_fallback(self, query: str, context: Dict) -> Dict:
        """
        Keyword-based fallback hunt when LLM is unavailable.
        Parses common patterns from the query string.
        """
        q = query.lower()
        host = context.get("host")

        if any(w in q for w in ["powershell", "encoded", "exec", "script"]):
            tool = "search_endpoint_events"
            args = {"host": host, "event_type": "process_creation", "limit": 20}
            result = await self.tool_registry.call(tool, args)
            return {
                "hypothesis": "Searching for script/execution activity",
                "next_tool": None,
                "tool_args": {},
                "findings_so_far": [f"Found {result.get('count', 0)} process events"],
                "done": True,
                "conclusion": f"Keyword search for scripting activity complete. Check evidence for details.",
                "confidence": 0.5,
                "mitre_hypotheses": ["T1059.001"],
            }

        if any(w in q for w in ["network", "c2", "connection", "outbound", "port"]):
            tool = "search_network_events"
            args = {"host": host, "limit": 20}
            result = await self.tool_registry.call(tool, args)
            return {
                "hypothesis": "Searching for suspicious network connections",
                "next_tool": None,
                "tool_args": {},
                "findings_so_far": [f"Found {result.get('count', 0)} network events"],
                "done": True,
                "conclusion": "Keyword search for network activity complete. Check evidence.",
                "confidence": 0.5,
                "mitre_hypotheses": ["T1571"],
            }

        return {
            "hypothesis": query,
            "next_tool": "search_endpoint_events",
            "tool_args": {"host": host, "limit": 20},
            "findings_so_far": [],
            "done": False,
            "conclusion": None,
            "confidence": 0.4,
            "mitre_hypotheses": [],
        }

    @staticmethod
    def _default_conclusion(findings: List[str], query: str) -> str:
        if not findings:
            return f"No significant findings for query: '{query}'. The environment may be clean, or the threat may not match current telemetry."
        return f"Hunt complete. {len(findings)} finding(s) identified. Review evidence for full details."
