"""
get_graph_context in-process MCP tool (spec section 3.4 / 6).

Returns attack paths, blast radius, and top betweenness nodes for an entity,
computed by the KnowledgeGraph (Dijkstra / Yen's / betweenness, spec 6.2).
"""
from __future__ import annotations

from typing import Any

from ..audit.log import get_audit_log
from ..graph.store import get_graph
from .registry import ToolSpec, tool
from .scope_guard import get_current_scope

GET_GRAPH_CONTEXT_PARAMS = {
    "type": "object",
    "properties": {
        "entity_id": {"type": "string", "description": "Entity or asset ID"},
        "k_paths": {"type": "integer", "default": 5, "description": "k for Yen's k-shortest paths"},
    },
    "required": ["entity_id"],
}


@tool("get_graph_context", "Retrieve attack-path graph context for an entity (Neo4j/GDS).", GET_GRAPH_CONTEXT_PARAMS)
def get_graph_context(args: dict[str, Any]) -> dict[str, Any]:
    audit = get_audit_log()
    scope = get_current_scope()
    entity_id = args["entity_id"]

    if not scope.allows_entity(entity_id):
        audit.write_scope_violation("get_graph_context", args)
        return {"error": "ScopeViolation", "message": f"{entity_id} outside scope {scope.investigation_id}"}

    audit.write_tool_call("get_graph_context", args, scope)
    graph = get_graph()
    if not graph.has(entity_id):
        return {"entity_id": entity_id, "note": "entity not present in knowledge graph", "neighbors": []}

    ctx = graph.get_context(entity_id, k_paths=int(args.get("k_paths", 5)))
    return ctx.to_dict()


def get_tool() -> ToolSpec:
    return get_graph_context
