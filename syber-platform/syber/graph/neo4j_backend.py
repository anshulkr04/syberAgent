"""
Neo4j-backed knowledge graph (spec §6).

Activated when NEO4J_URI is set. Nodes and edges are persisted to Neo4j via
Cypher MERGE (so the graph is the system of record, with the schema + RBAC from
graph_cypher/schema.cypher). Attack-path analysis follows the GDS model of
"project into an in-memory graph, then compute": we hydrate a NetworkX
projection from Neo4j and reuse the tested Dijkstra / Yen's / betweenness
implementations in store.py. The equivalent native GDS Cypher lives in
graph_cypher/attack_paths.cypher for a pure-Neo4j deployment.

Any driver/Cypher error degrades to the in-memory mirror so an investigation
never crashes on a transient graph outage.
"""
from __future__ import annotations

import os
from typing import Any

from .store import KnowledgeGraph, _now


class Neo4jKnowledgeGraph(KnowledgeGraph):
    def __init__(self, uri: str, user: str, password: str, database: str = "neo4j"):
        super().__init__()  # keeps an in-memory NetworkX projection for analysis
        from neo4j import GraphDatabase

        # Silence benign "unknown property" notifications emitted while the DB is
        # still empty (during the initial hydrate MATCH).
        try:
            self._driver = GraphDatabase.driver(uri, auth=(user, password),
                                                notifications_min_severity="OFF")
        except (TypeError, ValueError):  # older driver without the kwarg
            self._driver = GraphDatabase.driver(uri, auth=(user, password))
        self._database = database
        self._driver.verify_connectivity()
        self.hydrate()

    # -- persistence-aware mutation ---------------------------------------- #
    def add_node(self, node_id: str, label: str, **props: Any) -> None:
        super().add_node(node_id, label, **props)
        safe_label = "".join(c for c in label if c.isalnum()) or "Entity"
        # Only persist non-null props; set first_seen once, last_seen every time.
        props = {k: v for k, v in props.items() if v is not None}
        props["id"] = node_id
        try:
            with self._driver.session(database=self._database) as s:
                s.run(
                    f"MERGE (n:`{safe_label}` {{id: $id}}) "
                    f"ON CREATE SET n.first_seen = $now "
                    f"SET n += $props, n.last_seen = $now",
                    id=node_id, props=props, now=_now(),
                )
        except Exception:  # noqa: BLE001 - mirror already updated
            pass

    def add_edge(self, src: str, dst: str, edge_type: str, edge_weight: float = 1.0, **props: Any) -> None:
        super().add_edge(src, dst, edge_type, edge_weight, **props)
        safe_type = "".join(c for c in edge_type if c.isalnum() or c == "_") or "REL"
        props = {**props, "edge_weight": edge_weight, "edge_type": edge_type}
        try:
            with self._driver.session(database=self._database) as s:
                s.run(
                    f"MATCH (a {{id: $src}}), (b {{id: $dst}}) "
                    f"MERGE (a)-[r:`{safe_type}`]->(b) SET r += $props",
                    src=src, dst=dst, props=props,
                )
        except Exception:  # noqa: BLE001
            pass

    # -- hydrate the in-memory projection from Neo4j ----------------------- #
    def hydrate(self) -> None:
        """Load all nodes/edges from Neo4j into the NetworkX projection."""
        try:
            with self._driver.session(database=self._database) as s:
                for rec in s.run("MATCH (n) RETURN n, labels(n) AS labels"):
                    node = rec["n"]
                    nid = node.get("id")
                    if nid is None:
                        continue
                    label = (rec["labels"] or ["Entity"])[0]
                    super().add_node(nid, label, **{k: v for k, v in dict(node).items() if k != "id"})
                for rec in s.run(
                    "MATCH (a)-[r]->(b) RETURN a.id AS src, b.id AS dst, type(r) AS t, "
                    "coalesce(r.edge_weight, 1.0) AS w, properties(r) AS props"
                ):
                    if rec["src"] is None or rec["dst"] is None:
                        continue
                    props = {k: v for k, v in (rec["props"] or {}).items()
                             if k not in ("edge_weight", "edge_type")}
                    super().add_edge(rec["src"], rec["dst"], rec["t"], float(rec["w"]), **props)
        except Exception:  # noqa: BLE001 - empty DB or outage -> use mirror as-is
            pass

    def close(self) -> None:
        try:
            self._driver.close()
        except Exception:  # noqa: BLE001
            pass


def maybe_build_neo4j_graph() -> Neo4jKnowledgeGraph | None:
    uri = os.environ.get("NEO4J_URI")
    if not uri:
        return None
    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ.get("NEO4J_PASSWORD", "changeme")
    database = os.environ.get("NEO4J_DATABASE", "neo4j")
    try:
        return Neo4jKnowledgeGraph(uri, user, password, database)
    except Exception as exc:  # noqa: BLE001 - fall back to in-memory graph
        import sys
        print(f"[graph] NEO4J_URI set but connection failed ({exc}); using in-memory graph", file=sys.stderr)
        return None
