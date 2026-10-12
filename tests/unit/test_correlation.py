"""
Unit tests for the Correlation Engine.
Tests entity grouping, temporal window, and incident creation logic.
"""
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from app.correlation.engine import CorrelationEngine, _cluster_alerts


def _make_alert(host="LAB-WIN-01", user="lab-user", dt_offset_min=0, severity="high"):
    """Helper to create a minimal alert dict."""
    return {
        "id": uuid4(),
        "alert_id": f"ALT-{uuid4().hex[:8].upper()}",
        "host": host,
        "user": user,
        "severity": severity,
        "mitre_techniques": ["T1059.001"],
        "created_at": datetime(2026, 8, 18, 10, 0, 0, tzinfo=timezone.utc) + timedelta(minutes=dt_offset_min),
    }


class TestClusterAlerts:
    def test_same_host_same_cluster(self):
        alerts = [_make_alert("HOST-A"), _make_alert("HOST-A")]
        clusters = _cluster_alerts(alerts)
        assert len(clusters) == 1

    def test_different_hosts_different_clusters(self):
        alerts = [_make_alert(host="HOST-A", user="alice"), _make_alert(host="HOST-B", user="bob")]
        clusters = _cluster_alerts(alerts)
        assert len(clusters) == 2


    def test_same_user_same_cluster(self):
        alerts = [
            _make_alert(host="HOST-A", user="alice"),
            _make_alert(host="HOST-B", user="alice"),
        ]
        clusters = _cluster_alerts(alerts)
        # Same user → same cluster (user entity match)
        assert len(clusters) == 1

    def test_temporal_window_within_30min(self):
        alerts = [
            _make_alert(dt_offset_min=0),
            _make_alert(dt_offset_min=15),
            _make_alert(dt_offset_min=29),
        ]
        clusters = _cluster_alerts(alerts)
        assert len(clusters) == 1

    def test_temporal_window_outside_30min(self):
        alerts = [
            _make_alert(dt_offset_min=0),
            _make_alert(dt_offset_min=60),
        ]
        clusters = _cluster_alerts(alerts)
        # More than 30 min apart with no entity overlap
        assert len(clusters) == 2

    def test_minimum_two_alerts_per_cluster(self):
        """A single alert should still form a cluster of one."""
        alerts = [_make_alert()]
        clusters = _cluster_alerts(alerts)
        assert len(clusters) == 1
        assert len(clusters[0]) == 1

    def test_empty_alerts_empty_clusters(self):
        assert _cluster_alerts([]) == []

    def test_mixed_severities_preserved(self):
        alerts = [
            _make_alert(severity="critical"),
            _make_alert(severity="low"),
        ]
        clusters = _cluster_alerts(alerts)
        # Both on same host/user → one cluster, 2 alerts
        assert sum(len(c) for c in clusters) == 2


class TestIncidentSeverity:
    def test_critical_alert_makes_critical_incident(self):
        from app.correlation.engine import _incident_severity
        alerts = [_make_alert(severity="critical"), _make_alert(severity="low")]
        assert _incident_severity(alerts) == "critical"

    def test_high_only_makes_high_incident(self):
        from app.correlation.engine import _incident_severity
        alerts = [_make_alert(severity="high"), _make_alert(severity="medium")]
        assert _incident_severity(alerts) == "high"

    def test_medium_only_makes_medium_incident(self):
        from app.correlation.engine import _incident_severity
        alerts = [_make_alert(severity="medium"), _make_alert(severity="low")]
        assert _incident_severity(alerts) == "medium"
