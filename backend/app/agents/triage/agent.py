"""
Triage Agent — classifies an incident and estimates severity and FP probability.

Uses the configured LLM (Ollama local or OpenAI-compatible) to reason
over the incident context. Falls back to deterministic heuristics if LLM
is unavailable.
"""
from __future__ import annotations

import json
from typing import Dict

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.models import Incident

log = structlog.get_logger()

TRIAGE_SYSTEM_PROMPT = """You are a security operations center (SOC) triage analyst.
Your job is to analyze a security incident and return a structured JSON classification.

Rules:
- Base your assessment only on the provided evidence. Do not invent data.
- classification must be one of: benign, suspicious, malicious
- severity must be one of: informational, low, medium, high, critical
- false_positive_probability must be a float between 0.0 and 1.0
- confidence must be a float between 0.0 and 1.0
- investigation_required must be true if classification is suspicious or malicious

Return ONLY valid JSON, no markdown, no explanation outside the JSON."""

TRIAGE_USER_TEMPLATE = """Incident ID: {incident_id}
Title: {title}
Severity: {severity}
Number of alerts: {alert_count}
Entities: {entities}
MITRE Techniques: {mitre_techniques}
Description: {description}

Classify this incident and return JSON with keys:
classification, severity, confidence, false_positive_probability, investigation_required, reasoning"""


def _heuristic_triage(incident: Incident) -> Dict:
    """Fallback deterministic triage when LLM is unavailable."""
    sev_map = {"critical": 0.05, "high": 0.15, "medium": 0.30, "low": 0.50}
    fp_prob = sev_map.get(incident.severity, 0.40)
    classification = "malicious" if incident.severity in ("critical", "high") else "suspicious"
    return {
        "classification": classification,
        "severity": incident.severity,
        "confidence": 0.65,
        "false_positive_probability": fp_prob,
        "investigation_required": True,
        "reasoning": "Heuristic triage (LLM unavailable). Based on severity level.",
        "source": "heuristic",
    }


async def _llm_triage(incident: Incident) -> Dict:
    """Call the configured LLM for triage."""
    try:
        import httpx
        prompt = TRIAGE_USER_TEMPLATE.format(
            incident_id=incident.incident_id,
            title=incident.title,
            severity=incident.severity,
            alert_count=len(incident.alerts) if incident.alerts else 0,
            entities=json.dumps(incident.entities or {}),
            mitre_techniques=json.dumps(incident.mitre_techniques or []),
            description=incident.description or "No description available.",
        )

        payload = {
            "model": settings.OLLAMA_MODEL,
            "messages": [
                {"role": "system", "content": TRIAGE_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "format": "json",
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                f"{settings.OLLAMA_BASE_URL}/api/chat",
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
            content = data["message"]["content"]
            result = json.loads(content)
            result["source"] = "llm"
            return result

    except Exception as exc:
        log.warning("LLM triage failed, using heuristic", error=str(exc))
        return None


class TriageAgent:
    """Alert triage agent — classifies incident + estimates severity and FP probability."""

    def __init__(self, db: AsyncSession, incident: Incident):
        self.db = db
        self.incident = incident

    async def run(self) -> Dict:
        log.info("Triage agent running", incident_id=self.incident.incident_id)

        result = await _llm_triage(self.incident)
        if not result:
            result = _heuristic_triage(self.incident)

        log.info(
            "Triage complete",
            incident_id=self.incident.incident_id,
            classification=result.get("classification"),
            confidence=result.get("confidence"),
        )
        return result
