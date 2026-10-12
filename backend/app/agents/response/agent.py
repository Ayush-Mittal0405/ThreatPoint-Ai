"""
Response Agent — operates in RECOMMENDATION MODE only.

The agent produces a ranked list of response actions with:
  - action type
  - target entity
  - reason (evidence-backed)
  - expected impact
  - risk level
  - requires_human_approval (always True for write actions)

Autonomous execution is DISABLED unless explicitly enabled per action
via the human approval workflow.
"""
from __future__ import annotations

import json
from typing import Dict, List, Optional

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.models import Incident

log = structlog.get_logger()

# Response action catalog
ACTION_CATALOG = {
    "isolate_endpoint": {
        "description": "Isolate endpoint from network to contain threat",
        "risk": "high",
        "reversible": True,
        "requires_approval": True,
    },
    "kill_process": {
        "description": "Terminate malicious process",
        "risk": "medium",
        "reversible": False,
        "requires_approval": True,
    },
    "quarantine_file": {
        "description": "Quarantine malicious file",
        "risk": "low",
        "reversible": True,
        "requires_approval": True,
    },
    "block_ip": {
        "description": "Block outbound connection to malicious IP",
        "risk": "low",
        "reversible": True,
        "requires_approval": True,
    },
    "disable_account": {
        "description": "Disable compromised user account",
        "risk": "high",
        "reversible": True,
        "requires_approval": True,
    },
    "reset_password": {
        "description": "Force password reset for compromised account",
        "risk": "low",
        "reversible": False,
        "requires_approval": True,
    },
}

RESPONSE_SYSTEM = """You are a security incident responder.
Given an incident with risk score and evidence, recommend the minimum set of
response actions to contain and remediate the threat.

Rules:
- Base recommendations ONLY on provided evidence.
- Order actions by priority (most urgent first).
- Every action must have a reason tied to specific evidence.
- Do NOT recommend actions not in the approved action catalog.
- Approved actions: isolate_endpoint, kill_process, quarantine_file, block_ip, disable_account, reset_password

Return ONLY valid JSON:
{
  "recommendations": [
    {
      "action": "action_name",
      "target": "entity to act on",
      "reason": "evidence-based explanation",
      "expected_impact": "what this will achieve",
      "priority": 1
    }
  ],
  "overall_rationale": "brief explanation of response strategy"
}"""


class ResponseAgent:
    """Generates evidence-based response recommendations. Never auto-executes."""

    def __init__(self, db: AsyncSession, incident: Incident):
        self.db = db
        self.incident = incident

    async def recommend(self) -> Dict:
        """Generate response recommendations for the incident."""
        log.info("Response agent generating recommendations", incident_id=self.incident.incident_id)

        # Try LLM-based recommendations
        llm_result = await self._llm_recommend()
        if llm_result:
            recommendations = llm_result.get("recommendations", [])
            rationale = llm_result.get("overall_rationale", "")
        else:
            # Deterministic fallback based on severity + entities
            recommendations = self._heuristic_recommend()
            rationale = "Heuristic recommendations based on severity and detected techniques."

        # Enrich with catalog metadata + add approval flag
        enriched = []
        for rec in recommendations:
            action_meta = ACTION_CATALOG.get(rec.get("action"), {})
            enriched.append({
                **rec,
                "risk_level": action_meta.get("risk", "unknown"),
                "reversible": action_meta.get("reversible", True),
                "requires_human_approval": True,  # ALWAYS
                "approved": False,
                "executed": False,
                "execution_result": None,
            })

        result = {
            "incident_id": self.incident.incident_id,
            "recommendations": enriched,
            "overall_rationale": rationale,
            "source": "llm" if llm_result else "heuristic",
            "total_actions": len(enriched),
        }

        # Persist to incident
        self.incident.recommendations = enriched
        await self.db.flush()
        return result

    def _heuristic_recommend(self) -> List[Dict]:
        """Fallback deterministic recommendations."""
        recs = []
        entities = self.incident.entities or {}
        techniques = self.incident.mitre_techniques or []
        risk = self.incident.risk_score or 0

        if risk >= 80 and entities.get("hosts"):
            recs.append({
                "action": "isolate_endpoint",
                "target": entities["hosts"][0],
                "reason": f"Critical/high risk score ({risk}/100) with active malicious behavior detected.",
                "expected_impact": "Prevent lateral movement and C2 communication.",
                "priority": 1,
            })

        if "T1571" in techniques and entities.get("hosts"):
            recs.append({
                "action": "block_ip",
                "target": "Detected C2 IP",
                "reason": "Non-standard port C2 communication detected (T1571).",
                "expected_impact": "Break C2 channel.",
                "priority": 2,
            })

        if "T1098" in techniques and entities.get("users"):
            recs.append({
                "action": "disable_account",
                "target": entities["users"][0],
                "reason": "Account manipulation technique (T1098) detected.",
                "expected_impact": "Prevent unauthorized privilege escalation.",
                "priority": 3,
            })

        return recs

    async def _llm_recommend(self) -> Optional[Dict]:
        """Call LLM for recommendations."""
        try:
            import httpx
            context = json.dumps({
                "incident_id": self.incident.incident_id,
                "severity": self.incident.severity,
                "risk_score": self.incident.risk_score,
                "entities": self.incident.entities,
                "mitre_techniques": self.incident.mitre_techniques,
                "attack_story_summary": (self.incident.attack_story or {}).get("summary"),
            }, indent=2)

            payload = {
                "model": settings.OLLAMA_MODEL,
                "messages": [
                    {"role": "system", "content": RESPONSE_SYSTEM},
                    {"role": "user", "content": context},
                ],
                "stream": False, "format": "json",
            }
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(f"{settings.OLLAMA_BASE_URL}/api/chat", json=payload)
                resp.raise_for_status()
                return json.loads(resp.json()["message"]["content"])
        except Exception as exc:
            log.warning("LLM response recommendation failed", error=str(exc))
            return None
