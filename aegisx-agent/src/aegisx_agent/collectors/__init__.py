"""Telemetry collectors for the AegisX endpoint agent."""
from .base import Collector
from .process_collector import ProcessCollector
from .network_collector import NetworkCollector
from .eventlog_collector import EventLogCollector
from .persistence_collector import PersistenceCollector

__all__ = [
    "Collector",
    "ProcessCollector",
    "NetworkCollector",
    "EventLogCollector",
    "PersistenceCollector",
]
