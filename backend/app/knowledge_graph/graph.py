"""
Security Knowledge Graph — NetworkX-backed entity relationship graph.

Tracks relationships between:
  - Incidents ↔ Alerts
  - Hosts ↔ Processes ↔ Users
  - IPs ↔ Domains
  - Techniques ↔ Tactics

Used by: Attack Story Agent, Threat Hunting Agent, Similar Incident Discovery.
Phase 6: Replace NetworkX with Neo4j for persistent, queryable graph.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

import structlog

try:
    import networkx as nx
    NX_AVAILABLE = True
except ImportError:
    NX_AVAILABLE = False
    nx = None

log = structlog.get_logger()

# Node type constants
NODE_HOST      = "host"
NODE_USER      = "user"
NODE_PROCESS   = "process"
NODE_IP        = "ip"
NODE_DOMAIN    = "domain"
NODE_FILE      = "file"
NODE_TECHNIQUE = "mitre_technique"
NODE_TACTIC    = "mitre_tactic"
NODE_INCIDENT  = "incident"
NODE_ALERT     = "alert"

# Edge type constants
EDGE_SPAWNED     = "spawned"
EDGE_CONNECTED   = "connected_to"
EDGE_USED_BY     = "used_by"
EDGE_PERFORMED   = "performed"
EDGE_PART_OF     = "part_of"
EDGE_MAPS_TO     = "maps_to"
EDGE_ASSOCIATED  = "associated_with"


class SecurityGraph:
    """
    In-memory entity relationship graph for one incident investigation.
    Built from telemetry events and enrichment results.
    """

    def __init__(self):
        if not NX_AVAILABLE:
            log.warning("networkx not installed — graph disabled. Run: pip install networkx")
        self.G = nx.DiGraph() if NX_AVAILABLE else None

    def add_entity(
        self,
        entity_id: str,
        entity_type: str,
        **attrs: Any,
    ) -> str:
        """Add or update a node. Returns the node ID."""
        if self.G is None:
            return entity_id
        node_id = f"{entity_type}:{entity_id}"
        self.G.add_node(node_id, type=entity_type, label=entity_id, **attrs)
        return node_id

    def add_relationship(
        self,
        from_id: str,
        to_id: str,
        rel_type: str,
        **attrs: Any,
    ) -> None:
        """Add a directed edge between two node IDs."""
        if self.G is None:
            return
        self.G.add_edge(from_id, to_id, type=rel_type, **attrs)

    def add_process_chain(
        self,
        host: str,
        parent: str,
        child: str,
        command_line: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> None:
        """Record a parent → child process relationship."""
        h_id  = self.add_entity(host,   NODE_HOST,    host=host)
        p_id  = self.add_entity(f"{host}:{parent}", NODE_PROCESS, name=parent, host=host)
        c_id  = self.add_entity(f"{host}:{child}",  NODE_PROCESS, name=child,  host=host, command_line=command_line)
        self.add_relationship(h_id,  p_id, EDGE_ASSOCIATED)
        self.add_relationship(p_id,  c_id, EDGE_SPAWNED, timestamp=timestamp)

    def add_network_connection(
        self,
        host: str,
        process: str,
        dst_ip: str,
        dst_port: Optional[int] = None,
        domain: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> None:
        """Record a process → IP network connection."""
        p_id  = self.add_entity(f"{host}:{process}", NODE_PROCESS, name=process, host=host)
        ip_id = self.add_entity(dst_ip, NODE_IP, ip=dst_ip)
        self.add_relationship(p_id, ip_id, EDGE_CONNECTED, port=dst_port, timestamp=timestamp)
        if domain:
            d_id = self.add_entity(domain, NODE_DOMAIN, domain=domain)
            self.add_relationship(ip_id, d_id, EDGE_ASSOCIATED)

    def add_mitre_mapping(self, entity_id: str, technique_id: str, tactic: Optional[str] = None) -> None:
        """Link an entity (process, alert) to a MITRE technique."""
        t_id  = self.add_entity(technique_id, NODE_TECHNIQUE, technique_id=technique_id)
        self.add_relationship(entity_id, t_id, EDGE_MAPS_TO)
        if tactic:
            tac_id = self.add_entity(tactic, NODE_TACTIC, tactic=tactic)
            self.add_relationship(t_id, tac_id, EDGE_PART_OF)

    def get_attack_path(self, start_type: str = NODE_HOST) -> List[List[str]]:
        """Find the longest paths from host nodes — represents attack progression."""
        if self.G is None:
            return []
        start_nodes = [n for n, d in self.G.nodes(data=True) if d.get("type") == start_type]
        paths = []
        for s in start_nodes:
            for t in self.G.nodes():
                if s != t:
                    try:
                        path = nx.shortest_path(self.G, s, t)
                        if len(path) > 2:
                            paths.append(path)
                    except nx.NetworkXNoPath:
                        pass
        # Return unique paths, longest first
        seen = set()
        unique = []
        for p in sorted(paths, key=len, reverse=True):
            key = tuple(p)
            if key not in seen:
                seen.add(key)
                unique.append(p)
        return unique[:10]

    def to_json(self) -> Dict:
        """Serialize the graph to a JSON-compatible dict for storage."""
        if self.G is None:
            return {"nodes": [], "edges": []}
        nodes = [
            {"id": n, **dict(d)}
            for n, d in self.G.nodes(data=True)
        ]
        edges = [
            {"from": u, "to": v, **dict(d)}
            for u, v, d in self.G.edges(data=True)
        ]
        return {"nodes": nodes, "edges": edges}

    def summary(self) -> Dict:
        """Return a summary of graph statistics."""
        if self.G is None:
            return {}
        return {
            "nodes": self.G.number_of_nodes(),
            "edges": self.G.number_of_edges(),
            "node_types": dict(_count_by_attr(self.G, "type")),
            "connected_components": nx.number_weakly_connected_components(self.G),
        }


def _count_by_attr(G, attr: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for _, data in G.nodes(data=True):
        val = data.get(attr, "unknown")
        counts[val] = counts.get(val, 0) + 1
    return counts


def build_graph_from_events(events: List[Dict]) -> SecurityGraph:
    """
    Build a SecurityGraph from a list of normalized event dicts.
    Used by the Attack Story Agent to construct the entity graph.
    """
    graph = SecurityGraph()
    for ev in events:
        et = ev.get("event_type", "")
        host = ev.get("host", "unknown")

        if et == "process_creation":
            parent = ev.get("parent_process") or "unknown"
            child  = ev.get("process") or "unknown"
            graph.add_process_chain(
                host=host, parent=parent, child=child,
                command_line=ev.get("command_line"),
                timestamp=ev.get("timestamp"),
            )
            if ev.get("user"):
                u_id = graph.add_entity(ev["user"], NODE_USER, user=ev["user"])
                p_id = f"{NODE_PROCESS}:{host}:{parent}"
                graph.add_relationship(u_id, p_id, EDGE_PERFORMED)

        elif et == "network_connection":
            process = ev.get("process", "unknown")
            dst_ip  = ev.get("dst_ip")
            if dst_ip:
                graph.add_network_connection(
                    host=host, process=process,
                    dst_ip=dst_ip, dst_port=ev.get("dst_port"),
                    domain=ev.get("domain"), timestamp=ev.get("timestamp"),
                )

    return graph
