"""
Unit tests for the Threat Hunting Agent.
Tests the autonomous hunting loop, keyword fallback heuristics, and report generation.
"""
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.agents.hunting.agent import HuntingAgent


def test_keyword_hunt_fallback_powershell():
    async def _run():
        mock_db = AsyncMock()
        agent = HuntingAgent(mock_db)
        agent.tool_registry.call = AsyncMock(return_value={"count": 3, "events": [{"process": "powershell.exe"}]})

        step = await agent._keyword_hunt_fallback("find encoded powershell executions", {"host": "LAB-WIN-01"})
        assert step["done"] is True
        assert "T1059.001" in step["mitre_hypotheses"]
        assert len(step["findings_so_far"]) > 0
        agent.tool_registry.call.assert_called_once_with(
            "search_endpoint_events",
            {"host": "LAB-WIN-01", "event_type": "process_creation", "limit": 20},
        )
    asyncio.run(_run())


def test_keyword_hunt_fallback_network():
    async def _run():
        mock_db = AsyncMock()
        agent = HuntingAgent(mock_db)
        agent.tool_registry.call = AsyncMock(return_value={"count": 2, "events": [{"dst_ip": "185.1.1.1"}]})

        step = await agent._keyword_hunt_fallback("hunt for outbound c2 network connection", {"host": "DC-01"})
        assert step["done"] is True
        assert "T1571" in step["mitre_hypotheses"]
        assert "network" in step["hypothesis"].lower()
        agent.tool_registry.call.assert_called_once_with(
            "search_network_events",
            {"host": "DC-01", "limit": 20},
        )
    asyncio.run(_run())


def test_hunt_loop_with_llm_flow():
    async def _run():
        mock_db = AsyncMock()
        agent = HuntingAgent(mock_db)
        agent.tool_registry.call = AsyncMock(return_value={"results": ["found malicious process"]})

        responses = [
            {
                "hypothesis": "Checking for suspicious process tree",
                "next_tool": "search_process_tree",
                "tool_args": {"host": "LAB-WIN-01", "process_name": "winword.exe"},
                "findings_so_far": ["Word opened shell"],
                "done": False,
                "confidence": 0.6,
                "mitre_hypotheses": ["T1566.001"],
            },
            {
                "hypothesis": "Confirmed macro execution",
                "next_tool": None,
                "tool_args": {},
                "findings_so_far": ["Word opened shell", "Macro dropped payload"],
                "done": True,
                "conclusion": "Threat confirmed on LAB-WIN-01",
                "confidence": 0.95,
                "mitre_hypotheses": ["T1566.001", "T1059.001"],
            },
        ]
        agent._ask_llm = AsyncMock(side_effect=responses)

        report = await agent.hunt("investigate office macro behavior", {"host": "LAB-WIN-01"})
        assert report["hunt_id"].startswith("HUNT-")
        assert len(report["findings"]) >= 2
        assert len(report["evidence"]) == 1
        assert report["confidence"] == 0.95
        assert "T1566.001" in report["mitre_hypotheses"]
        assert report["conclusion"] == "Threat confirmed on LAB-WIN-01"
    asyncio.run(_run())


def test_default_conclusion_empty():
    conclusion = HuntingAgent._default_conclusion([], "query xyz")
    assert "No significant findings" in conclusion


def test_default_conclusion_with_findings():
    conclusion = HuntingAgent._default_conclusion(["Finding A", "Finding B"], "query xyz")
    assert "2 finding(s) identified" in conclusion
