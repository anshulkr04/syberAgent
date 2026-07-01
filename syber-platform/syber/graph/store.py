"""
Security Knowledge Graph (spec section 6).

The spec uses Neo4j Enterprise with the GDS library for Dijkstra, Yen's
k-shortest-paths, and betweenness centrality. To keep the platform runnable
without a Neo4j cluster, this module implements the identical attack-path
analysis on an in-memory NetworkX DiGraph:

  * Dijkstra single source->target           -> nx.dijkstra_path (spec 6.2)
  * Yen's k-shortest simple paths            -> nx.shortest_simple_paths (this
    IS Yen's algorithm; guarantees k lowest-cost *simple* paths, spec 6.2)
  * Betweenness centrality                   -> nx.betweenness_centrality

A NEO4J_URI env var switches to a real Neo4j backend if the driver is present;
otherwise everything runs in-memory. The node/edge schema matches spec 6.1.
"""
from __future__ import annotations

import itertools
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import networkx as nx


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# Severity -> numeric weight for host risk scoring.
_SEV_WEIGHT = {"critical": 10.0, "high": 6.0, "medium": 3.0, "low": 1.0, "info": 0.2, "unknown": 0.5}


@dataclass
class GraphContext:
    entity_id: str
    neighbors: list[dict[str, Any]]
    attack_paths: list[dict[str, Any]]
    blast_radius_count: int
    top_betweenness: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "neighbors": self.neighbors,
            "attack_paths": self.attack_paths,
            "blast_radius_count": self.blast_radius_count,
            "top_betweenness": self.top_betweenness,
        }


class KnowledgeGraph:
    """In-memory attack graph honouring the spec 6.1 schema."""

    def __init__(self) -> None:
        self.g = nx.DiGraph()

    # -- mutation ----------------------------------------------------------- #
    def add_node(self, node_id: str, label: str, **props: Any) -> None:
        """Upsert a node with provenance: first_seen is set once, last_seen and
        any non-null props are updated on every observation (idempotent MERGE)."""
        now = _now()
        props = {k: v for k, v in props.items() if v is not None}
        if self.g.has_node(node_id):
            self.g.nodes[node_id].update(props)
            self.g.nodes[node_id]["label"] = label
            self.g.nodes[node_id]["last_seen"] = now
        else:
            self.g.add_node(node_id, label=label, first_seen=now, last_seen=now, **props)

    def add_edge(self, src: str, dst: str, edge_type: str, edge_weight: float = 1.0, **props: Any) -> None:
        self.g.add_edge(src, dst, edge_type=edge_type, edge_weight=edge_weight, **props)

    def has(self, node_id: str) -> bool:
        return self.g.has_node(node_id)

    # -- queries ------------------------------------------------------------ #
    def neighbors(self, node_id: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if not self.g.has_node(node_id):
            return out
        for _, dst, data in self.g.out_edges(node_id, data=True):
            out.append({"direction": "out", "node": dst, "edge_type": data.get("edge_type"),
                        "label": self.g.nodes[dst].get("label")})
        for src, _, data in self.g.in_edges(node_id, data=True):
            out.append({"direction": "in", "node": src, "edge_type": data.get("edge_type"),
                        "label": self.g.nodes[src].get("label")})
        return out

    def dijkstra(self, source: str, target: str) -> dict[str, Any] | None:
        """Minimum-cost single path (spec 6.2 gds.shortestPath.dijkstra)."""
        if not (self.g.has_node(source) and self.g.has_node(target)):
            return None
        try:
            cost, path = nx.single_source_dijkstra(self.g, source, target, weight="edge_weight")
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None
        return {"path": path, "total_cost": cost, "steps": self._annotate(path)}

    def yens_k_shortest(self, source: str, target: str, k: int = 5) -> list[dict[str, Any]]:
        """k lowest-cost simple paths (spec 6.2 gds.shortestPath.yens)."""
        if not (self.g.has_node(source) and self.g.has_node(target)):
            return []
        paths: list[dict[str, Any]] = []
        try:
            gen = nx.shortest_simple_paths(self.g, source, target, weight="edge_weight")
            for path in itertools.islice(gen, k):
                cost = sum(
                    self.g[u][v]["edge_weight"] for u, v in zip(path, path[1:])
                )
                paths.append({"path": path, "total_cost": cost, "steps": self._annotate(path)})
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []
        return sorted(paths, key=lambda p: p["total_cost"])

    def betweenness_top(self, limit: int = 20) -> list[dict[str, Any]]:
        """Pivot nodes for remediation prioritisation (spec 6.2)."""
        scores = nx.betweenness_centrality(self.g, weight="edge_weight")
        ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)[:limit]
        return [
            {"node": n, "hostname": self.g.nodes[n].get("hostname", n),
             "label": self.g.nodes[n].get("label"), "score": round(s, 4)}
            for n, s in ranked if s > 0
        ]

    def blast_radius(self, source: str) -> int:
        """Count of nodes reachable from source (attack surface, spec 3.2)."""
        if not self.g.has_node(source):
            return 0
        return len(nx.descendants(self.g, source))

    def critical_targets(self) -> list[str]:
        """Nodes flagged high-criticality / CII — candidate attack endpoints."""
        return [
            n for n, d in self.g.nodes(data=True)
            if str(d.get("criticality", "")).lower() in {"critical", "cii", "high"}
        ]

    # -- reachability / foothold state (attack-graph layer, MulVAL) ---------- #
    def reachable_from(self, host: str) -> list[str]:
        """Hosts ``host`` can reach via CAN_REACH edges (MulVAL hacl)."""
        if not self.g.has_node(host):
            return []
        return [dst for _, dst, d in self.g.out_edges(host, data=True)
                if d.get("edge_type") == "CAN_REACH"]

    def compromised_hosts(self) -> list[str]:
        """Hosts on which a foothold has been recorded (execCode)."""
        return [n for n, d in self.g.nodes(data=True)
                if d.get("label") == "Host" and d.get("compromised")]

    def lateral_frontier(self) -> list[str]:
        """Hosts that are reachable but not yet compromised — the lateral-movement
        frontier a parallel fleet should fan out across next."""
        return [n for n, d in self.g.nodes(data=True)
                if d.get("label") == "Host" and d.get("reachable") and not d.get("compromised")]

    def get_context(self, entity_id: str, k_paths: int = 5) -> GraphContext:
        """Assemble the full graph context for the get_graph_context tool."""
        targets = [t for t in self.critical_targets() if t != entity_id]
        attack_paths: list[dict[str, Any]] = []
        for tgt in targets:
            for p in self.yens_k_shortest(entity_id, tgt, k=k_paths):
                attack_paths.append({"target": tgt, **p})
        attack_paths.sort(key=lambda p: p["total_cost"])
        return GraphContext(
            entity_id=entity_id,
            neighbors=self.neighbors(entity_id),
            attack_paths=attack_paths[:k_paths],
            blast_radius_count=self.blast_radius(entity_id),
            top_betweenness=self.betweenness_top(limit=5),
        )

    # -- rich attack-surface views (the richer graph model) ----------------- #
    def _nodes_by(self, label: str) -> list[str]:
        return [n for n, d in self.g.nodes(data=True) if d.get("label") == label]

    def _typed_neighbors(self, node_id: str, label: str, direction: str = "out") -> list[dict[str, Any]]:
        edges = self.g.out_edges if direction == "out" else self.g.in_edges
        out = []
        for a, b, _ in edges(node_id, data=True):
            other = b if direction == "out" else a
            if self.g.nodes[other].get("label") == label:
                out.append({"id": other, **{k: v for k, v in self.g.nodes[other].items() if k != "label"}})
        return out

    def risk_score(self, host_id: str) -> float:
        """Heuristic host risk: exposure (open ports) + vulnerabilities + missing
        web controls. Used to rank the attack surface."""
        if not self.g.has_node(host_id):
            return 0.0
        ports = self._typed_neighbors(host_id, "Service")
        vulns = self._typed_neighbors(host_id, "Vulnerability")
        web = self._typed_neighbors(host_id, "WebEndpoint")
        score = 1.5 * len(ports)
        score += sum(_SEV_WEIGHT.get(str(v.get("severity", "unknown")).lower(), 0.5) for v in vulns)
        score += 0.5 * len(web)
        # internet-facing / public web service bumps exposure
        if any(p.get("port") in (80, 443, 8080, 8443) for p in ports):
            score += 2.0
        return round(score, 2)

    def exposure_view(self, host_id: str) -> dict[str, Any]:
        """The full attack-surface picture for a host: services, technologies,
        web endpoints, vulnerabilities, certificate, risk score."""
        if not self.g.has_node(host_id):
            return {"host": host_id, "present": False}
        node = self.g.nodes[host_id]
        services = self._typed_neighbors(host_id, "Service")
        return {
            "host": host_id,
            "present": True,
            "ip": node.get("ip"),
            "os": node.get("os"),
            "first_seen": node.get("first_seen"),
            "last_seen": node.get("last_seen"),
            "services": [{"port": s.get("port"), "protocol": s.get("protocol"),
                          "service": s.get("service"), "product": s.get("product"),
                          "version": s.get("version")} for s in services],
            "technologies": [t.get("name") for t in self._typed_neighbors(host_id, "Technology")],
            "web_endpoints": [{"url": w.get("url"), "status": w.get("status")}
                              for w in self._typed_neighbors(host_id, "WebEndpoint")],
            "vulnerabilities": [{"id": v.get("id"), "name": v.get("name"),
                                 "severity": v.get("severity"), "cvss": v.get("cvss")}
                                for v in self._typed_neighbors(host_id, "Vulnerability")],
            "certificate": (self._typed_neighbors(host_id, "Certificate") or [None])[0],
            "risk_score": self.risk_score(host_id),
        }

    def attack_surface(self, limit: int = 10) -> list[dict[str, Any]]:
        """Hosts ranked by risk — the engagement's prioritised attack surface."""
        hosts = self._nodes_by("Host") or self._nodes_by("Asset")
        ranked = sorted(hosts, key=self.risk_score, reverse=True)[:limit]
        out = []
        for h in ranked:
            v = self.exposure_view(h)
            out.append({"host": h, "ip": v.get("ip"), "risk_score": v["risk_score"],
                        "open_ports": len(v.get("services", [])),
                        "vulns": len(v.get("vulnerabilities", [])),
                        "technologies": v.get("technologies", [])[:6]})
        return out

    # -- helpers ------------------------------------------------------------ #
    def _annotate(self, path: list[str]) -> list[dict[str, Any]]:
        steps = []
        for u, v in zip(path, path[1:]):
            data = self.g[u][v]
            steps.append({
                "from": u, "to": v,
                "edge_type": data.get("edge_type"),
                "from_label": self.g.nodes[u].get("label"),
                "to_label": self.g.nodes[v].get("label"),
            })
        return steps


_graph: KnowledgeGraph | None = None


def get_graph() -> KnowledgeGraph:
    """Return the active graph backend: Neo4j when NEO4J_URI is set and reachable
    (spec §6), otherwise the in-memory NetworkX graph (default, fully tested)."""
    global _graph
    if _graph is None:
        from .neo4j_backend import maybe_build_neo4j_graph

        _graph = maybe_build_neo4j_graph() or KnowledgeGraph()
    return _graph
