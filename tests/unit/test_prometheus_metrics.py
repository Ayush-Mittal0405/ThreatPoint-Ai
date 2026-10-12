"""
Unit tests for Prometheus metrics collection and exposition generator.
"""
import pytest
from app.core.metrics import PrometheusRegistry


class TestPrometheusMetrics:
    def test_record_events_ingested(self):
        reg = PrometheusRegistry()
        reg.record_event_ingested(source="windows_sysmon", event_type="process_created", count=5)
        reg.record_event_ingested(source="windows_sysmon", event_type="process_created", count=3)
        reg.record_event_ingested(source="zeek_network", event_type="dns_query", count=12)

        expo = reg.generate_exposition()
        assert '# TYPE aegisx_events_ingested_total counter' in expo
        assert 'aegisx_events_ingested_total{source="windows_sysmon",event_type="process_created"} 8' in expo
        assert 'aegisx_events_ingested_total{source="zeek_network",event_type="dns_query"} 12' in expo

    def test_record_alerts_and_incidents(self):
        reg = PrometheusRegistry()
        reg.record_alert_generated(severity="critical", rule_id="OFFICE_SPAWNS_POWERSHELL")
        reg.record_incident_created(severity="critical", status="investigating")

        expo = reg.generate_exposition()
        assert 'aegisx_alerts_generated_total{severity="critical",rule_id="OFFICE_SPAWNS_POWERSHELL"} 1' in expo
        assert 'aegisx_incidents_total{severity="critical",status="investigating"} 1' in expo

    def test_record_agent_executions(self):
        reg = PrometheusRegistry()
        reg.record_agent_execution(agent_name="investigation", duration_sec=1.45, success=True)
        reg.record_agent_execution(agent_name="investigation", duration_sec=2.15, success=True)

        expo = reg.generate_exposition()
        assert 'aegisx_agent_execution_count{agent="investigation",success="true"} 2' in expo
        assert 'aegisx_agent_execution_seconds_total{agent="investigation",success="true"} 3.6' in expo

    def test_record_http_requests(self):
        reg = PrometheusRegistry()
        reg.record_http_request(method="GET", path="/api/v1/incidents", status_code=200, duration_sec=0.045)
        reg.record_http_request(method="POST", path="/api/v1/telemetry/ingest", status_code=200, duration_sec=0.012)

        expo = reg.generate_exposition()
        assert 'aegisx_http_requests_total{method="GET",path="/api/v1/incidents",status="200"} 1' in expo
        assert 'aegisx_http_requests_total{method="POST",path="/api/v1/telemetry/ingest",status="200"} 1' in expo
