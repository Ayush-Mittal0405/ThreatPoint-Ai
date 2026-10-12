"""
AegisX Prometheus Metrics Collector & Exposition Generator.

Tracks operational telemetry, security detection throughput, AI agent execution
durations, and HTTP request latencies in standard Prometheus format.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Dict, Tuple


class PrometheusRegistry:
    """Thread-safe in-memory metrics registry formatted for Prometheus scraping."""

    def __init__(self):
        self._lock = threading.Lock()
        self._events_ingested: Dict[Tuple[str, str], int] = defaultdict(int)
        self._alerts_generated: Dict[Tuple[str, str], int] = defaultdict(int)
        self._incidents_created: Dict[Tuple[str, str], int] = defaultdict(int)
        self._agent_executions: Dict[Tuple[str, str], Tuple[int, float]] = defaultdict(lambda: (0, 0.0))
        self._http_requests: Dict[Tuple[str, str, int], int] = defaultdict(int)
        self._http_duration_sum: Dict[Tuple[str, str], float] = defaultdict(float)
        self._http_duration_count: Dict[Tuple[str, str], int] = defaultdict(int)

    def record_event_ingested(self, source: str, event_type: str, count: int = 1) -> None:
        with self._lock:
            self._events_ingested[(source, event_type)] += count

    def record_alert_generated(self, severity: str, rule_id: str) -> None:
        with self._lock:
            self._alerts_generated[(severity, rule_id)] += 1

    def record_incident_created(self, severity: str, status: str) -> None:
        with self._lock:
            self._incidents_created[(severity, status)] += 1

    def record_agent_execution(self, agent_name: str, duration_sec: float, success: bool = True) -> None:
        key = (agent_name, "true" if success else "false")
        with self._lock:
            count, total_time = self._agent_executions[key]
            self._agent_executions[key] = (count + 1, total_time + duration_sec)

    def record_http_request(self, method: str, path: str, status_code: int, duration_sec: float) -> None:
        with self._lock:
            self._http_requests[(method, path, status_code)] += 1
            self._http_duration_sum[(method, path)] += duration_sec
            self._http_duration_count[(method, path)] += 1

    def generate_exposition(self) -> str:
        """Render all metrics in standard Prometheus line protocol."""
        lines = []

        # 1. Ingested Events
        lines.append("# HELP aegisx_events_ingested_total Total normalized events ingested.")
        lines.append("# TYPE aegisx_events_ingested_total counter")
        with self._lock:
            for (source, event_type), val in self._events_ingested.items():
                lines.append(f'aegisx_events_ingested_total{{source="{source}",event_type="{event_type}"}} {val}')

        # 2. Alerts Generated
        lines.append("# HELP aegisx_alerts_generated_total Total detection alerts triggered.")
        lines.append("# TYPE aegisx_alerts_generated_total counter")
        with self._lock:
            for (severity, rule_id), val in self._alerts_generated.items():
                lines.append(f'aegisx_alerts_generated_total{{severity="{severity}",rule_id="{rule_id}"}} {val}')

        # 3. Incidents
        lines.append("# HELP aegisx_incidents_total Total security incidents correlated.")
        lines.append("# TYPE aegisx_incidents_total counter")
        with self._lock:
            for (severity, status), val in self._incidents_created.items():
                lines.append(f'aegisx_incidents_total{{severity="{severity}",status="{status}"}} {val}')

        # 4. Agent Executions
        lines.append("# HELP aegisx_agent_execution_seconds_total Total duration of agent investigations.")
        lines.append("# TYPE aegisx_agent_execution_seconds_total counter")
        lines.append("# HELP aegisx_agent_execution_count Total count of agent investigations.")
        lines.append("# TYPE aegisx_agent_execution_count counter")
        with self._lock:
            for (agent_name, success), (count, total_time) in self._agent_executions.items():
                lines.append(f'aegisx_agent_execution_seconds_total{{agent="{agent_name}",success="{success}"}} {round(total_time, 4)}')
                lines.append(f'aegisx_agent_execution_count{{agent="{agent_name}",success="{success}"}} {count}')

        # 5. HTTP Requests
        lines.append("# HELP aegisx_http_requests_total Total HTTP requests handled by AegisX.")
        lines.append("# TYPE aegisx_http_requests_total counter")
        with self._lock:
            for (method, path, status_code), count in self._http_requests.items():
                lines.append(f'aegisx_http_requests_total{{method="{method}",path="{path}",status="{status_code}"}} {count}')

        lines.append("")
        return "\n".join(lines)


# Global singleton metrics registry
metrics = PrometheusRegistry()
