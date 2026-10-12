"""
Unit tests for the Security Knowledge Graph.
Tests entity addition, relationship creation, process chains, and attack paths.
"""
import pytest
from app.knowledge_graph.graph import SecurityGraph, build_graph_from_events, NODE_HOST, NODE_PROCESS, NODE_IP


class TestSecurityGraph:
    def setup_method(self):
        self.g = SecurityGraph()

    def test_add_entity_returns_node_id(self):
        nid = self.g.add_entity("LAB-WIN-01", NODE_HOST)
        assert nid == f"{NODE_HOST}:LAB-WIN-01"

    def test_add_entity_twice_no_duplicate(self):
        self.g.add_entity("LAB-WIN-01", NODE_HOST)
        self.g.add_entity("LAB-WIN-01", NODE_HOST)
        if self.g.G is not None:
            assert self.g.G.number_of_nodes() == 1

    def test_add_relationship_creates_edge(self):
        n1 = self.g.add_entity("A", NODE_HOST)
        n2 = self.g.add_entity("B", NODE_HOST)
        self.g.add_relationship(n1, n2, "connected_to")
        if self.g.G is not None:
            assert self.g.G.has_edge(n1, n2)

    def test_add_process_chain(self):
        self.g.add_process_chain("LAB-WIN-01", "winword.exe", "powershell.exe")
        if self.g.G is None:
            return
        assert self.g.G.number_of_nodes() >= 3
        assert self.g.G.number_of_edges() >= 2

    def test_add_network_connection(self):
        self.g.add_network_connection("LAB-WIN-01", "powershell.exe", "185.1.2.3", 4444)
        if self.g.G is None:
            return
        assert any("185.1.2.3" in n for n in self.g.G.nodes())

    def test_to_json_structure(self):
        self.g.add_entity("HOST", NODE_HOST)
        j = self.g.to_json()
        assert "nodes" in j
        assert "edges" in j

    def test_summary_returns_dict(self):
        self.g.add_entity("HOST", NODE_HOST)
        s = self.g.summary()
        if self.g.G is not None:
            assert "nodes" in s
            assert s["nodes"] >= 1


class TestBuildGraphFromEvents:
    def test_process_creation_builds_chain(self):
        events = [{
            "event_type": "process_creation",
            "host": "LAB-WIN-01",
            "parent_process": "winword.exe",
            "process": "powershell.exe",
            "command_line": "-enc SGVs",
            "user": "lab-user",
            "timestamp": "2026-08-18T10:00:00+00:00",
        }]
        g = build_graph_from_events(events)
        if g.G is None:
            return
        assert g.G.number_of_nodes() >= 2

    def test_network_connection_adds_ip(self):
        events = [{
            "event_type": "network_connection",
            "host": "LAB-WIN-01",
            "process": "powershell.exe",
            "dst_ip": "185.1.2.3",
            "dst_port": 4444,
            "domain": None,
            "timestamp": "2026-08-18T10:01:00+00:00",
        }]
        g = build_graph_from_events(events)
        if g.G is None:
            return
        assert any("185.1.2.3" in n for n in g.G.nodes())

    def test_empty_events_empty_graph(self):
        g = build_graph_from_events([])
        j = g.to_json()
        assert j["nodes"] == []
        assert j["edges"] == []

    def test_multiple_events_build_connected_graph(self):
        events = [
            {"event_type": "process_creation", "host": "H1", "parent_process": "winword.exe", "process": "powershell.exe", "command_line": "", "user": "alice", "timestamp": "2026-08-18T10:00:00+00:00"},
            {"event_type": "network_connection", "host": "H1", "process": "powershell.exe", "dst_ip": "10.0.0.1", "dst_port": 443, "domain": None, "timestamp": "2026-08-18T10:01:00+00:00"},
        ]
        g = build_graph_from_events(events)
        if g.G is None:
            return
        assert g.G.number_of_nodes() >= 3
