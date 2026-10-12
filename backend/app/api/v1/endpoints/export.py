"""
Executive Incident Report Export API.

GET /api/v1/incidents/{incident_id}/export/markdown — Download structured Markdown report
GET /api/v1/incidents/{incident_id}/export/html     — Printable HTML/PDF report
GET /api/v1/incidents/{incident_id}/export/json     — Full incident data package
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import HTMLResponse, PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.models.models import Incident, AgentTrace, Alert

router = APIRouter()


def _build_markdown_report(incident: Incident, traces: List[AgentTrace], alerts: List[Alert]) -> str:
    """Generate professional executive markdown report for an incident."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    created_str = incident.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if incident.created_at else "N/A"

    entities = incident.entities or {}
    hosts = ", ".join(entities.get("hosts", [])) or "None identified"
    users = ", ".join(entities.get("users", [])) or "None identified"
    ips = ", ".join(entities.get("ips", [])) or "None identified"
    mitre_list = incident.mitre_techniques or []

    story = incident.attack_story or {}
    exec_summary = story.get("executive_summary", incident.description or "Investigation in progress.")
    phases = story.get("kill_chain_phases", [])

    recs = incident.recommendations or []
    feedback = incident.analyst_feedback or {}

    md = f"""# AegisX Incident Investigation Report
**Incident ID:** `{incident.incident_id}`  
**Report Generated:** {now_str}  
**Classification:** AegisX Autonomous SOC Confidential

---

## 1. Executive Summary

| Attribute | Details |
|---|---|
| **Title** | {incident.title} |
| **Severity** | **{incident.severity.upper()}** |
| **Status** | `{incident.status}` |
| **Deterministic Risk Score** | **{incident.risk_score or 'N/A'} / 100** |
| **AI Confidence** | {round((incident.confidence or 0.9) * 100, 1)}% |
| **Incident Created** | {created_str} |

### Summary Narrative
{exec_summary}

---

## 2. Affected Assets & Entity Scope

- **Affected Hosts:** `{hosts}`
- **Compromised / Target Accounts:** `{users}`
- **External Attacker Infrastructure:** `{ips}`

---

## 3. MITRE ATT&CK Matrix

| Technique ID | Phase | Description |
|---|---|---|
"""
    if mitre_list:
        for t in mitre_list:
            md += f"| `{t}` | Kill-Chain Execution | Automated detection & agent verified |\n"
    else:
        md += "| None | — | No specific techniques mapped |\n"

    md += """
---

## 4. Attack Story & Kill-Chain Phases
"""
    if phases:
        for p in phases:
            md += f"### {p.get('phase', 'Phase')}: `{p.get('technique', 'N/A')}`\n"
            md += f"{p.get('details', '')}\n\n"
    else:
        md += "Attack story reconstruction pending or in progress.\n\n"

    md += """---

## 5. Security Alerts Triggered
"""
    if alerts:
        md += "| Alert ID | Title | Severity | Timestamp |\n|---|---|---|---|\n"
        for a in alerts:
            ts = a.created_at.strftime("%H:%M:%S") if a.created_at else "—"
            md += f"| `{a.alert_id}` | {a.title} | `{a.severity}` | {ts} |\n"
    else:
        md += "No linked security alerts.\n"

    md += """
---

## 6. AI Agent Investigation Audit Trail

| Step | Agent | Action / Tool | Result / Reasoning | Duration |
|---|---|---|---|---|
"""
    if traces:
        for t in traces:
            tool = t.tool_name or t.action
            reason = (t.reasoning or "").replace("\n", " ")[:80] or "Executed successfully"
            dur = f"{t.duration_ms}ms" if t.duration_ms else "—"
            md += f"| {t.step} | `{t.agent_name}` | `{tool}` | {reason} | {dur} |\n"
    else:
        md += "| 1 | `orchestrator` | `initial_triage` | Incident queued for investigation | — |\n"

    md += """
---

## 7. Recommended & Executed Response Actions
"""
    if recs:
        for r in recs:
            action = r.get("action", "action")
            target = r.get("target", "system")
            reason = r.get("reason", "")
            req_appr = "Yes" if r.get("requires_human_approval", True) else "No"
            md += f"- **Action:** `{action}` on `{target}`  \n  *Reason:* {reason}  \n  *Human Approval Gate:* {req_appr}\n"
    else:
        md += "No automated response actions generated.\n"

    if feedback:
        md += f"""
---

## 8. Analyst Review & Continuous Learning
- **Analyst Rating:** {feedback.get('rating', 'N/A')} / 5 Stars
- **Category:** `{feedback.get('category', 'N/A')}`
- **False Positive:** {'Yes' if feedback.get('is_false_positive') else 'No'}
- **Analyst Notes:** {feedback.get('analyst_note', 'None provided')}
"""

    md += "\n---\n*Report generated autonomously by AegisX Security Operations Center.*"
    return md


def _build_html_report(incident: Incident, traces: List[AgentTrace], alerts: List[Alert]) -> str:
    """Generate styled printable HTML report with print-ready CSS styling."""
    md_content = _build_markdown_report(incident, traces, alerts)

    # Basic markdown-to-HTML conversion for common elements
    import html
    escaped_title = html.escape(incident.title)
    sev_color = "#ff4d6d" if incident.severity == "critical" else "#f97316" if incident.severity == "high" else "#facc15"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AegisX Report — {incident.incident_id}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');
  :root {{
    --bg: #090d16;
    --card: #0f172a;
    --border: #1e293b;
    --text: #f1f5f9;
    --text-muted: #94a3b8;
    --accent: #63b3ed;
  }}
  body {{
    font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    background: var(--bg);
    color: var(--text);
    padding: 40px;
    max-width: 900px;
    margin: 0 auto;
    line-height: 1.6;
  }}
  .header {{
    border-bottom: 2px solid var(--border);
    padding-bottom: 20px;
    margin-bottom: 30px;
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
  }}
  .logo {{ font-size: 20px; font-weight: 800; color: #fff; }}
  .logo span {{ color: var(--accent); }}
  .badge {{
    background: rgba(255, 77, 109, 0.15);
    color: {sev_color};
    border: 1px solid {sev_color};
    padding: 4px 10px;
    border-radius: 6px;
    font-weight: 700;
    font-size: 12px;
    text-transform: uppercase;
  }}
  h1, h2, h3 {{ color: #fff; font-weight: 700; }}
  h2 {{ border-bottom: 1px solid var(--border); padding-bottom: 8px; margin-top: 32px; font-size: 18px; }}
  table {{ width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 13px; }}
  th, td {{ border: 1px solid var(--border); padding: 10px 14px; text-align: left; }}
  th {{ background: var(--card); color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 11px; }}
  code, .mono {{ font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--accent); }}
  .summary-box {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin: 16px 0; }}
  @media print {{
    body {{ background: #fff; color: #000; padding: 20px; }}
    .header, h2, table, th, td {{ border-color: #ccc; }}
    th, .summary-box {{ background: #f8fafc; color: #000; }}
    code, .mono {{ color: #0284c7; }}
    .no-print {{ display: none; }}
  }}
</style>
</head>
<body>
<div class="no-print" style="margin-bottom: 20px; display: flex; gap: 10px;">
  <button onclick="window.print()" style="background: var(--accent); color: #000; border: none; padding: 8px 16px; border-radius: 6px; font-weight: 700; cursor: pointer;">Print / Save as PDF</button>
  <button onclick="window.close()" style="background: transparent; color: var(--text-muted); border: 1px solid var(--border); padding: 8px 16px; border-radius: 6px; cursor: pointer;">Close</button>
</div>

<div class="header">
  <div>
    <div class="logo">Aegis<span>X</span> SOC Platform</div>
    <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">Incident Investigation Dossier</div>
  </div>
  <div style="text-align: right;">
    <div class="mono" style="font-size: 13px; font-weight: 700;">{incident.incident_id}</div>
    <div style="margin-top: 6px;"><span class="badge">{incident.severity}</span></div>
  </div>
</div>

<h1>{escaped_title}</h1>

<div class="summary-box">
  <strong>Executive Summary:</strong><br>
  {html.escape(incident.attack_story.get("executive_summary", incident.description or "Investigation completed.")) if incident.attack_story else html.escape(incident.description or "Investigation in progress.")}
</div>

<h2>Incident Metrics & Scope</h2>
<table>
  <tr><th>Risk Score</th><td><strong>{incident.risk_score or 'N/A'} / 100</strong></td><th>Status</th><td><code>{incident.status}</code></td></tr>
  <tr><th>Affected Hosts</th><td><code>{html.escape(str(incident.entities.get('hosts', ['None'])) if incident.entities else 'None')}</code></td><th>Target Users</th><td><code>{html.escape(str(incident.entities.get('users', ['None'])) if incident.entities else 'None')}</code></td></tr>
</table>

<h2>MITRE ATT&CK Matrix</h2>
<table>
  <thead><tr><th>Technique</th><th>Stage</th><th>Detection Source</th></tr></thead>
  <tbody>
    {"".join(f"<tr><td><code>{t}</code></td><td>Kill Chain</td><td>Behavioral Detection / Agent Analysis</td></tr>" for t in (incident.mitre_techniques or [])) or "<tr><td colspan='3'>None mapped</td></tr>"}
  </tbody>
</table>

<h2>AI Investigation Trace Audit</h2>
<table>
  <thead><tr><th>Step</th><th>Agent</th><th>Action / Tool</th><th>Duration</th></tr></thead>
  <tbody>
    {"".join(f"<tr><td>{t.step}</td><td><code>{t.agent_name}</code></td><td><code>{t.tool_name or t.action}</code></td><td>{t.duration_ms or 0}ms</td></tr>" for t in traces) or "<tr><td colspan='4'>No execution traces</td></tr>"}
  </tbody>
</table>

<div style="margin-top: 40px; border-top: 1px solid var(--border); padding-top: 12px; font-size: 11px; color: var(--text-muted); display: flex; justify-content: space-between;">
  <span>AegisX Autonomous Incident Dossier</span>
  <span>Generated on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</span>
</div>
</body>
</html>
"""
    return html_content


@router.get("/{incident_id}/export/markdown")
async def export_incident_markdown(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Download executive incident investigation report in Markdown format."""
    res = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = res.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Fetch traces & alerts
    trace_res = await db.execute(
        select(AgentTrace).where(AgentTrace.incident_id == incident_id).order_by(AgentTrace.step)
    )
    traces = list(trace_res.scalars().all())

    alert_res = await db.execute(
        select(Alert).where(Alert.incident_id == incident_id)
    )
    alerts = list(alert_res.scalars().all())

    report_md = _build_markdown_report(incident, traces, alerts)

    filename = f"{incident.incident_id}_investigation_report.md"
    return PlainTextResponse(
        content=report_md,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{incident_id}/export/html", response_class=HTMLResponse)
async def export_incident_html(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """View styled, print-ready HTML incident investigation report."""
    res = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = res.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    trace_res = await db.execute(
        select(AgentTrace).where(AgentTrace.incident_id == incident_id).order_by(AgentTrace.step)
    )
    traces = list(trace_res.scalars().all())

    alert_res = await db.execute(
        select(Alert).where(Alert.incident_id == incident_id)
    )
    alerts = list(alert_res.scalars().all())

    return HTMLResponse(content=_build_html_report(incident, traces, alerts))
