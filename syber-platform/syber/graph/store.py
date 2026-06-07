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
from typing import Any

import networkx as nx


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
        self.g.add_node(node_id, label=label, **props)

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
