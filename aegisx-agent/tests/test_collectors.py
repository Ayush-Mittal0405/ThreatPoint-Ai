"""Collector behaviour tests (platform-tolerant)."""
import os

import pytest

from aegisx_agent.collectors import (
    ProcessCollector, NetworkCollector, EventLogCollector, PersistenceCollector,
)

psutil = pytest.importorskip("psutil")


def test_process_collector_primes_then_returns_list():
    col = ProcessCollector()
    first = col.collect()      # priming pass — baseline only
    assert first == []
    second = col.collect()     # returns a list of new-process events (possibly empty)
    assert isinstance(second, list)
    for ev in second:
        assert ev["event_type"] == "process_creation"
        assert "process" in ev


def test_network_collector_shape():
    col = NetworkCollector()
    col.collect()              # prime
    events = col.collect()
    assert isinstance(events, list)
    for ev in events:
        assert ev["event_type"] == "network_connection"
        assert ev["dst_ip"]


def test_safe_collect_never_raises():
    class Boom(ProcessCollector):
        def collect(self):
            raise RuntimeError("boom")
    assert Boom().safe_collect() == []


def test_windows_only_collectors_declare_support():
    is_windows = os.name == "nt"
    assert EventLogCollector().supported == is_windows
    assert PersistenceCollector().supported == is_windows
    # On non-Windows they must no-op via safe_collect.
    if not is_windows:
        assert EventLogCollector().safe_collect() == []
        assert PersistenceCollector().safe_collect() == []
