"""
Attack Story Agent — transforms correlated evidence into an evidence-backed
incident narrative mapped to MITRE ATT&CK tactics.

Output structure:
  {
    "title": str,
    "summary": str,                    # LLM-generated narrative
    "timeline": [...],                 # Ordered attack stages
    "graph": {...},                    # Entity relationship graph (JSON)
    "mitre_coverage": [...],           # All techniques identified
    "confidence": float,
    "risk_score": dict
  }
"""
from __future__ import annotations

import json
from typing import Dict, List, Optional

import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import settings
from app.models.models import Incident, NormalizedEvent, Alert
from app.knowledge_graph.graph import SecurityGraph, build_graph_from_events
from app.risk.engine import RiskEngine
from app.rag.retriever import rag_context_for_query

log = structlog.get_logger()

ATTACK_STORY_SYSTEM = """You are an expert security analyst writing an incident report.

Given the incident evidence (events, alerts, entities, MITRE techniques), produce:
1. A concise executive summary (3-5 sentences) explaining what happened, who was affected, and the likely threat actor objective.
2. An ordered attack timeline as a JSON list of stages, each with:
   - stage: (e.g. "Initial Access", "Execution", "Persistence")
   - description: what happened
   - evidence: list of evidence IDs or event types
   - technique_id: MITRE ID if applicable
   - confidence: 0.0-1.0

Return ONLY valid JSON:
{
  "summary": "...",
  "timeline": [...]
}"""


class AttackStoryAgent:
    """Generates attack story narrative from incident evidence."""

    def __init__(self, db: AsyncSession, incident: Incident):
        self.db = db
        self.incident = incident
        self.risk_engine = RiskEngine()

    async def run(self) -> Dict:
        log.info("Attack story agent running", incident_id=self.incident.incident_id)

        # 1. Load all events linked to this incident's alerts
        events = await self._load_incident_events()

        # 2. Build entity graph
        event_dicts = [self._event_to_dict(e) for e in events]
        graph = build_graph_from_events(event_dicts)

        # 3. Build MITRE-ordered timeline (deterministic pass)
        det_timeline = self._build_deterministic_timeline(events)

        # 4. Calculate risk score
        network_evts = [e for e in event_dicts if e.get("event_type") == "network_connection"]
        proc_evts    = [e for e in event_dicts if e.get("event_type") == "process_creation"]
        risk = self.risk_engine.calculate(
            process_events=proc_evts,
            network_events=network_evts,
            mitre_techniques=self.incident.mitre_techniques or [],
        )

        # 5. Enrich with RAG context
        rag_context = ""
        if self.incident.mitre_techniques:
            q = f"Attack techniques: {', '.join(self.incident.mitre_techniques or [])}"
            try:
                rag_context = await rag_context_for_query(self.db, q, top_k=3, source_filter="mitre")
            except Exception:
                pass

        # 6. Generate LLM narrative
        llm_result = await self._generate_narrative(det_timeline, rag_context)

        # 7. Assemble final story
        story = {
            "title": self.incident.title,
            "summary": llm_result.get("summary", self._fallback_summary()),
            "timeline": llm_result.get("timeline", det_timeline),
            "graph": graph.to_json(),
            "graph_summary": graph.summary(),
            "mitre_coverage": self.incident.mitre_techniques or [],
            "confidence": self._calc_confidence(events),
            "risk_score": risk,
            "evidence_count": len(events),
        }

        # 8. Persist to incident
        self.incident.attack_story = story
        self.incident.risk_score = risk["total"]
        await self.db.flush()

        log.info(
            "Attack story complete",
            incident_id=self.incident.incident_id,
            timeline_stages=len(story["timeline"]),
            risk=risk["total"],
        )
        return story

    # ── Private helpers ───────────────────────────────────────────────────────

    async def _load_incident_events(self) -> List[NormalizedEvent]:
        """Load all normalized events linked to this incident via alerts."""
        result = await self.db.execute(
            select(Alert).where(Alert.incident_id == self.incident.id)
        )
        alerts = result.scalars().all()
        events: List[NormalizedEvent] = []
        for alert in alerts:
            for event in alert.events:
                events.append(event)
        # Deduplicate
        seen = set()
        unique = []
        for e in events:
            if e.id not in seen:
                seen.add(e.id)
                unique.append(e)
        return sorted(unique, key=lambda e: e.timestamp)

    @staticmethod
    def _event_to_dict(e: NormalizedEvent) -> Dict:
        return {
            "event_id": e.event_id,
            "timestamp": e.timestamp.isoformat(),
            "event_type": e.event_type,
            "host": e.host,
            "user": e.user,
            "process": e.process,
            "parent_process": e.parent_process,
            "command_line": e.command_line,
            "src_ip": e.src_ip,
            "dst_ip": e.dst_ip,
            "dst_port": e.dst_port,
            "domain": e.domain,
        }

    @staticmethod
    def _build_deterministic_timeline(events: List[NormalizedEvent]) -> List[Dict]:
        """
        Build a MITRE-tactic ordered timeline from events without LLM.
        Maps event types to ATT&CK kill-chain stages.
        """
        STAGE_MAP = {
            "user_logon_failed": ("Initial Access", "T1078"),
            "user_logon":        ("Initial Access", None),
            "process_creation":  ("Execution",      "T1059"),
            "file_created":      ("Defense Evasion","T1036"),
            "network_connection":("Command and Control", "T1571"),
            "user_account_change":("Persistence",   "T1098"),
            "dns_query":         ("Command and Control", None),
            "registry_event":    ("Persistence",    "T1547"),
        }
        stages: Dict[str, Dict] = {}
        for ev in events:
            stage_info = STAGE_MAP.get(ev.event_type)
            if not stage_info:
                continue
            stage_name, technique = stage_info
            if stage_name not in stages:
                stages[stage_name] = {
                    "stage": stage_name,
                    "description": f"{stage_name} activity detected on {ev.host or 'unknown host'}",
                    "evidence": [],
                    "technique_id": technique,
                    "confidence": 0.75,
                    "timestamp": ev.timestamp.isoformat(),
                }
            stages[stage_name]["evidence"].append(ev.event_id)

        # Order by kill-chain sequence
        ORDER = ["Initial Access", "Execution", "Persistence", "Privilege Escalation",
                 "Defense Evasion", "Credential Access", "Discovery",
                 "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"]
        return [stages[s] for s in ORDER if s in stages]

    def _fallback_summary(self) -> str:
        ents = self.incident.entities or {}
        hosts = ", ".join(ents.get("hosts", ["unknown host"]))
        techs = ", ".join((self.incident.mitre_techniques or [])[:3])
        return (
            f"Security incident affecting {hosts}. "
            f"Detected techniques: {techs or 'unknown'}. "
            f"Severity: {self.incident.severity}. "
            "Full narrative requires LLM — configure Ollama to enable."
        )

    def _calc_confidence(self, events: List) -> float:
        """Higher evidence count = higher confidence, capped at 0.95."""
        return min(0.50 + len(events) * 0.03, 0.95)

    async def _generate_narrative(self, timeline: List[Dict], rag_context: str) -> Dict:
        """Use LLM to generate human-readable narrative."""
        context_str = json.dumps({
            "incident_id": self.incident.incident_id,
            "title": self.incident.title,
            "severity": self.incident.severity,
            "entities": self.incident.entities,
            "mitre_techniques": self.incident.mitre_techniques,
            "timeline_stages": [s["stage"] for s in timeline],
            "relevant_knowledge": rag_context[:2000] if rag_context else None,
        }, indent=2)

        try:
            import httpx
            payload = {
                "model": settings.OLLAMA_MODEL,
                "messages": [
                    {"role": "system", "content": ATTACK_STORY_SYSTEM},
                    {"role": "user", "content": context_str},
                ],
                "stream": False,
                "format": "json",
            }
            async with httpx.AsyncClient(timeout=90.0) as client:
                resp = await client.post(f"{settings.OLLAMA_BASE_URL}/api/chat", json=payload)
                resp.raise_for_status()
                content = resp.json()["message"]["content"]
                return json.loads(content)
        except Exception as exc:
            log.warning("LLM narrative failed", error=str(exc))
            return {"summary": self._fallback_summary(), "timeline": timeline}
