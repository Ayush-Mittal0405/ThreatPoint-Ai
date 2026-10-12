"""
Unit tests for Red Team Attack Simulator.
"""
import pytest
from scripts.simulation.attack_simulator import (
    build_scenario_1,
    build_scenario_2,
    build_scenario_3,
    AttackSimulator,
)


class TestAttackSimulator:
    def test_build_scenario_1_phishing_macro(self):
        events = build_scenario_1(host="TEST-WIN-01", user="test.user")
        assert len(events) == 4
        assert events[0]["process"] == "winword.exe"
        assert events[1]["process"] == "powershell.exe"
        assert events[2]["event_type"] == "network_connection"
        assert events[2]["dst_port"] == 4444
        assert events[3]["process"] == "whoami.exe"

    def test_build_scenario_2_cloud_compromise(self):
        events = build_scenario_2(user="admin@enterprise.com")
        assert len(events) == 3
        assert events[0]["source"] == "okta_identity"
        assert events[1]["source"] == "gcp_cloud_audit"
        assert events[2]["source"] == "aws_cloudtrail"

    def test_build_scenario_3_ransomware_staging(self):
        events = build_scenario_3(host="DB-SERVER-01")
        assert len(events) == 3
        assert events[0]["process"] == "vssadmin.exe"
        assert events[1]["process"] == "bcdedit.exe"
        assert events[2]["event_type"] == "file_event"

    def test_simulator_dry_run_scenarios(self):
        sim = AttackSimulator(dry_run=True)
        res1 = sim.run_scenario(1, interval_seconds=0)
        assert res1["shipped"] == 4

        res2 = sim.run_scenario(2, interval_seconds=0)
        assert res2["shipped"] == 3

        res3 = sim.run_scenario(3, interval_seconds=0)
        assert res3["shipped"] == 3
