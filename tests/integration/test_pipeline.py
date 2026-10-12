"""
Integration test for the full AegisX pipeline:
  Ingest / Normalize -> Detection Rules -> Alert Correlation -> Risk Scoring -> Knowledge Graph
"""
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock

from app.services.normalization import normalize_event
from app.detection.engine import DetectionEngine, _builtin_behavioral_rules
from app.correlation.engine import _cluster_alerts, _incident_severity
from app.risk.engine import RiskEngine
from app.knowledge_graph.graph import build_graph_from_events, NODE_HOST, NODE_PROCESS, NODE_IP
from app.models.models import NormalizedEvent


def test_full_pipeline_attack_scenario():
    """
    Scenario: Multi-stage cyber attack
      Stage 1: Phishing Word doc executes and spawns PowerShell with encoded payload.
      Stage 2: PowerShell establishes C2 connection to known malicious IP on port 4444.
      Stage 3: Sudo/admin privilege escalation account modification.
    """
    now = datetime(2026, 8, 29, 12, 0, 0, tzinfo=timezone.utc)

    # ── 1. Telemetry Ingestion & Normalization ─────────────────────────────────
    raw_events = [
        {
            "source": "sysmon",
            "event_type": "process_creation",
            "timestamp": now.isoformat(),
            "host": "LAB-WIN-01",
            "user": "victim_user",
            "process": "powershell.exe",
            "parent_process": "winword.exe",
            "command_line": "powershell.exe -enc SQBFAFgAIAA...",
        },
        {
            "source": "sysmon",
            "event_type": "network_connection",
            "timestamp": (now + timedelta(seconds=15)).isoformat(),
            "host": "LAB-WIN-01",
            "user": "victim_user",
            "process": "powershell.exe",
            "src_ip": "10.0.0.15",
            "dst_ip": "185.220.101.5",
            "dst_port": 4444,
        },
        {
            "source": "winlog_security",
            "event_type": "user_account_change",
            "timestamp": (now + timedelta(minutes=3)).isoformat(),
            "host": "LAB-WIN-01",
            "user": "SYSTEM",
            "raw": {"target_user": "backdoor_admin"},
        }
    ]

    normalized_events = []
    for raw in raw_events:
        ev = normalize_event(raw)
        assert ev.event_id is not None
        assert ev.source in ("sysmon", "winlog_security")
        normalized_events.append(ev)

    assert len(normalized_events) == 3

    # ── 2. Detection Engine Rule Evaluation ───────────────────────────────────
    fired_alerts = []
    rules = _builtin_behavioral_rules()

    for event in normalized_events:
        for rule in rules:
            if rule["matcher"](event):
                fired_alerts.append({
                    "alert_id": f"ALT-{len(fired_alerts)+1}",
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "host": event.host,
                    "user": event.user,
                    "mitre_techniques": rule.get("mitre", []),
                    "created_at": event.timestamp,
                })

    # Assert rules caught the malicious behavior
    alert_titles = [a["title"] for a in fired_alerts]
    assert any("Office Application Spawns Scripting Host" in t for t in alert_titles)
    assert any("Encoded PowerShell Command Execution" in t for t in alert_titles)
    assert any("Suspicious Outbound Connection to Known C2 Port" in t for t in alert_titles)


    # ── 3. Correlation Engine Clustering ─────────────────────────────────────
    clusters = _cluster_alerts(fired_alerts)
    assert len(clusters) == 1  # All alerts share host 'LAB-WIN-01' and temporal window
    assert len(clusters[0]) >= 3

    incident_sev = _incident_severity(clusters[0])
    assert incident_sev in ("critical", "high")

    # ── 4. Risk Engine Multi-factor Scoring ───────────────────────────────────
    risk_engine = RiskEngine()
    proc_dicts = [
        {"parent_process": "winword.exe", "process": "powershell.exe", "command_line": "-enc ..."}
    ]
    net_dicts = [{"dst_port": 4444, "dst_ip": "185.220.101.5"}]
    mitre_techniques = list({t for a in fired_alerts for t in a["mitre_techniques"]})

    risk_result = risk_engine.calculate(
        threat_intel={"malicious": True},
        process_events=proc_dicts,
        network_events=net_dicts,
        mitre_techniques=mitre_techniques,
        asset_critical=True,
    )

    assert risk_result["total"] >= 75  # High / Critical risk
    assert risk_result["level"] in ("high", "critical")
    assert risk_result["components"]["process_behavior"] > 0
    assert risk_result["components"]["network_behavior"] > 0
    assert risk_result["components"]["threat_intelligence"] == 20

    # ── 5. Knowledge Graph Construction ──────────────────────────────────────
    graph_events = [
        {
            "event_type": "process_creation",
            "host": "LAB-WIN-01",
            "parent_process": "winword.exe",
            "process": "powershell.exe",
            "command_line": "-enc SQBFAFgAIAA...",
            "user": "victim_user",
            "timestamp": now.isoformat(),
        },
        {
            "event_type": "network_connection",
            "host": "LAB-WIN-01",
            "process": "powershell.exe",
            "dst_ip": "185.220.101.5",
            "dst_port": 4444,
            "domain": None,
            "timestamp": (now + timedelta(seconds=15)).isoformat(),
        }
    ]

    kg = build_graph_from_events(graph_events)
    kg_json = kg.to_json()
    assert len(kg_json["nodes"]) >= 3
    assert len(kg_json["edges"]) >= 2
    node_labels = [n["label"] for n in kg_json["nodes"]]
    assert "LAB-WIN-01" in node_labels
    assert any("powershell.exe" in n for n in node_labels)
    assert "185.220.101.5" in node_labels
