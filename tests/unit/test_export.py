"""
Unit tests for the Executive Incident Report Export API (Markdown and HTML).
"""
import asyncio
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.endpoints.export import (
    _build_markdown_report,
    _build_html_report,
    export_incident_markdown,
    export_incident_html,
)
from app.models.models import Incident, AgentTrace, Alert


class TestIncidentExport:
    @pytest.fixture
    def mock_incident_bundle(self):
        inc_id = uuid.uuid4()
        inc = Incident(
            id=inc_id,
            incident_id="INC-2041",
            title="Office Document Spawns PowerShell C2",
            description="Phishing attachment triggered remote reverse shell.",
            status="investigating",
            severity="critical",
            risk_score=88.5,
            confidence=0.95,
            entities={"hosts": ["LAB-WIN-01"], "users": ["alice"], "ips": ["185.220.101.5"]},
            mitre_techniques=["T1566.001", "T1059.001", "T1027"],
            attack_story={
                "executive_summary": "Active C2 beaconing detected from LAB-WIN-01.",
                "kill_chain_phases": [
                    {"phase": "Initial Access", "technique": "T1566.001", "details": "Phishing Word doc"},
                    {"phase": "Execution", "technique": "T1059.001", "details": "PowerShell payload"},
                ],
            },
            recommendations=[
                {"action": "isolate_endpoint", "target": "LAB-WIN-01", "reason": "Stop lateral spread", "requires_human_approval": True}
            ],
            analyst_feedback={"rating": 5, "category": "accurate", "analyst_note": "Great autonomous investigation."},
            created_at=datetime.now(timezone.utc),
        )

        trace = AgentTrace(
            step=1,
            agent_name="triage",
            action="triage_classification",
            tool_name="triage_event",
            reasoning="Classified as critical based on encoded command line.",
            duration_ms=450,
            success=True,
        )

        alert = Alert(
            alert_id="ALT-101",
            title="Suspicious PowerShell Spawn",
            severity="critical",
            created_at=datetime.now(timezone.utc),
        )

        return inc, [trace], [alert]

    def test_build_markdown_report_structure(self, mock_incident_bundle):
        inc, traces, alerts = mock_incident_bundle
        md = _build_markdown_report(inc, traces, alerts)

        assert "INC-2041" in md
        assert "Office Document Spawns PowerShell C2" in md
        assert "88.5 / 100" in md
        assert "LAB-WIN-01" in md
        assert "185.220.101.5" in md
        assert "T1566.001" in md
        assert "isolate_endpoint" in md
        assert "5 / 5 Stars" in md
        assert "Great autonomous investigation." in md

    def test_build_html_report_structure(self, mock_incident_bundle):
        inc, traces, alerts = mock_incident_bundle
        html = _build_html_report(inc, traces, alerts)

        assert "<!DOCTYPE html>" in html
        assert "AegisX Report — INC-2041" in html
        assert "Office Document Spawns PowerShell C2" in html
        assert "@media print" in html
        assert "88.5 / 100" in html

    def test_export_endpoints(self, mock_incident_bundle):
        async def _run():
            inc, traces, alerts = mock_incident_bundle

            mock_db = AsyncMock()
            mock_inc_res = MagicMock()
            mock_inc_res.scalar_one_or_none.return_value = inc
            mock_trace_res = MagicMock()
            mock_trace_res.scalars.return_value.all.return_value = traces
            mock_alert_res = MagicMock()
            mock_alert_res.scalars.return_value.all.return_value = alerts

            mock_db.execute.side_effect = [mock_inc_res, mock_trace_res, mock_alert_res]

            md_res = await export_incident_markdown(incident_id=inc.id, db=mock_db)
            assert md_res.media_type == "text/markdown; charset=utf-8"
            assert "attachment;" in md_res.headers.get("content-disposition", "")
            assert "INC-2041" in md_res.body.decode("utf-8")

            # Reset side effects for HTML export call
            mock_db.execute.side_effect = [mock_inc_res, mock_trace_res, mock_alert_res]
            html_res = await export_incident_html(incident_id=inc.id, db=mock_db)
            assert "text/html" in html_res.media_type
            assert "INC-2041" in html_res.body.decode("utf-8")
        asyncio.run(_run())
