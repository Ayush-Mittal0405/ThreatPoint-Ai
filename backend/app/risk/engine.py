"""
Deterministic Risk Engine — calculates a 0-100 risk score from telemetry signals.
The LLM is NOT the authority for risk scoring; this engine is.

Risk Score = sum of weighted component scores.

Components:
  1. Threat Intelligence     (max 20)
  2. Process Behavior        (max 15)
  3. Network Behavior        (max 18)
  4. Identity Anomaly        (max 10)
  5. Asset Criticality       (max 15)
  6. MITRE Technique Severity(max 12)
  7. Historical Similarity   (max 10)
  Total max = 100
"""
from __future__ import annotations

from typing import Dict, List, Optional

import structlog

log = structlog.get_logger()

# Risk level thresholds (from spec Section 14)
RISK_LEVELS = [
    (81, "critical"),
    (61, "high"),
    (41, "medium"),
    (21, "low"),
    (0, "informational"),
]

# MITRE technique severity weights
MITRE_SEVERITY: Dict[str, int] = {
    "T1059.001": 10,  # PowerShell
    "T1566.001": 12,  # Spearphishing
    "T1027": 7,       # Obfuscation
    "T1571": 9,       # Non-standard port
    "T1098": 11,      # Account manipulation
    "T1036.005": 6,   # Masquerading
    "DEFAULT": 5,
}


def _risk_level(score: float) -> str:
    for threshold, level in RISK_LEVELS:
        if score >= threshold:
            return level
    return "informational"


class RiskEngine:
    """
    Deterministic risk calculator.
    All inputs must come from verified evidence, not LLM guesses.
    """

    def calculate(
        self,
        threat_intel: Optional[Dict] = None,
        process_events: Optional[List[Dict]] = None,
        network_events: Optional[List[Dict]] = None,
        user_events: Optional[List[Dict]] = None,
        mitre_techniques: Optional[List[str]] = None,
        asset_critical: bool = False,
        historical_matches: int = 0,
    ) -> Dict:
        """
        Calculate a risk score. All parameters are optional;
        missing evidence means zero for that component.
        """
        scores = {}

        # 1. Threat Intelligence (max 20)
        ti_score = 0
        if threat_intel:
            if threat_intel.get("malicious"):
                ti_score = 20
            elif any(
                src.get("abuse_confidence_score", 0) > 30
                or src.get("pulse_count", 0) > 0
                for src in threat_intel.get("sources", {}).values()
                if isinstance(src, dict)
            ):
                ti_score = 12
        scores["threat_intelligence"] = min(ti_score, 20)

        # 2. Process Behavior (max 15)
        proc_score = 0
        if process_events:
            suspicious_parents = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
            high_risk_children = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
            for ev in process_events:
                parent = (ev.get("parent_process") or "").lower()
                child = (ev.get("process") or "").lower()
                if parent in suspicious_parents and child in high_risk_children:
                    proc_score += 15
                    break
                elif child in high_risk_children and "enc" in (ev.get("command_line") or "").lower():
                    proc_score += 10
        scores["process_behavior"] = min(proc_score, 15)

        # 3. Network Behavior (max 18)
        net_score = 0
        if network_events:
            c2_ports = {4444, 4445, 8443, 8080, 9001, 1337, 31337}
            for ev in network_events:
                if ev.get("dst_port") in c2_ports:
                    net_score += 18
                    break
                elif ev.get("dst_port") and ev.get("dst_port") not in {80, 443, 53}:
                    net_score += 5
        scores["network_behavior"] = min(net_score, 18)

        # 4. Identity Anomaly (max 10)
        id_score = 0
        if user_events:
            failed = sum(1 for e in user_events if e.get("event_type") == "user_logon_failed")
            priv_esc = sum(1 for e in user_events if e.get("event_type") == "privilege_escalation")
            id_score = min(failed * 2 + priv_esc * 5, 10)
        scores["identity_anomaly"] = id_score

        # 5. Asset Criticality (max 15)
        scores["asset_criticality"] = 15 if asset_critical else 5

        # 6. MITRE Technique Severity (max 12)
        mitre_score = 0
        for tech in (mitre_techniques or []):
            mitre_score = max(mitre_score, MITRE_SEVERITY.get(tech, MITRE_SEVERITY["DEFAULT"]))
        scores["mitre_severity"] = min(mitre_score, 12)

        # 7. Historical Similarity (max 10)
        scores["historical_similarity"] = min(historical_matches * 3, 10)

        total = sum(scores.values())
        total = min(total, 100)

        result = {
            "total": round(total, 1),
            "level": _risk_level(total),
            "components": scores,
            "max_possible": 100,
        }

        log.info("Risk score calculated", total=total, level=result["level"])
        return result
