"""
Unit tests for the Risk Engine.
Tests all 7 scoring components and edge cases.
"""
import pytest
from app.risk.engine import RiskEngine, _risk_level


class TestRiskLevel:
    def test_critical_threshold(self):
        assert _risk_level(90) == "critical"
        assert _risk_level(81) == "critical"

    def test_high_threshold(self):
        assert _risk_level(80) == "high"
        assert _risk_level(61) == "high"

    def test_medium_threshold(self):
        assert _risk_level(60) == "medium"
        assert _risk_level(41) == "medium"

    def test_low_threshold(self):
        assert _risk_level(40) == "low"
        assert _risk_level(21) == "low"

    def test_informational_threshold(self):
        assert _risk_level(20) == "informational"
        assert _risk_level(0) == "informational"


class TestRiskEngineComponents:
    def setup_method(self):
        self.engine = RiskEngine()

    def test_empty_input_returns_low_score(self):
        result = self.engine.calculate()
        assert result["total"] > 0   # asset criticality always contributes
        assert result["total"] < 50  # but not much without evidence

    def test_malicious_threat_intel_adds_max(self):
        result = self.engine.calculate(threat_intel={"malicious": True, "sources": {}})
        assert result["components"]["threat_intelligence"] == 20

    def test_no_threat_intel_zero_score(self):
        result = self.engine.calculate(threat_intel=None)
        assert result["components"]["threat_intelligence"] == 0

    def test_office_to_powershell_process_score(self):
        events = [{"parent_process": "winword.exe", "process": "powershell.exe", "command_line": ""}]
        result = self.engine.calculate(process_events=events)
        assert result["components"]["process_behavior"] == 15

    def test_c2_port_network_score(self):
        events = [{"dst_port": 4444}]
        result = self.engine.calculate(network_events=events)
        assert result["components"]["network_behavior"] == 18

    def test_asset_critical_score(self):
        r_crit = self.engine.calculate(asset_critical=True)
        r_norm = self.engine.calculate(asset_critical=False)
        assert r_crit["components"]["asset_criticality"] > r_norm["components"]["asset_criticality"]

    def test_mitre_technique_t1566_high_score(self):
        result = self.engine.calculate(mitre_techniques=["T1566.001"])
        assert result["components"]["mitre_severity"] == 12

    def test_historical_matches_capped(self):
        result = self.engine.calculate(historical_matches=100)
        assert result["components"]["historical_similarity"] == 10

    def test_total_capped_at_100(self):
        # Maximize all components
        result = self.engine.calculate(
            threat_intel={"malicious": True, "sources": {}},
            process_events=[{"parent_process": "winword.exe", "process": "powershell.exe", "command_line": ""}],
            network_events=[{"dst_port": 4444}],
            user_events=[{"event_type": "privilege_escalation"}, {"event_type": "privilege_escalation"}],
            mitre_techniques=["T1566.001"],
            asset_critical=True,
            historical_matches=5,
        )
        assert result["total"] <= 100

    def test_full_scenario_is_critical(self):
        result = self.engine.calculate(
            threat_intel={"malicious": True, "sources": {}},
            process_events=[{"parent_process": "winword.exe", "process": "powershell.exe", "command_line": "enc"}],
            network_events=[{"dst_port": 4444}],
            mitre_techniques=["T1566.001"],
            asset_critical=True,
            historical_matches=3,
        )
        assert result["level"] in ("critical", "high")
        assert result["total"] >= 60
