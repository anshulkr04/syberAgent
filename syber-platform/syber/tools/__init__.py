"""
In-process MCP tool server (spec section 3.4 build_tool_server).

Bundles every Syber tool into one server, equivalent to the spec's
create_sdk_mcp_server({"syber-tools": ...}). Tool names are exposed to the LLM
unprefixed here (the OpenAI function-calling layer does not use the SDK's
mcp__server__tool prefix); the orchestrator maps the spec's allowed_tools list.
"""
from __future__ import annotations

from .behaviour import score_behaviour
from .data_lake_tool import query_data_lake
from .findings import publish_finding, request_hitl
from .graph_context import get_graph_context
from .registry import ToolServer, ToolSpec

# Map the spec's mcp__syber-tools__* names to the in-process specs so the
# orchestrator's allowed_tools can use either form.
SPEC_NAME_MAP = {
    "mcp__syber-tools__query_data_lake": "query_data_lake",
    "mcp__syber-tools__get_graph_context": "get_graph_context",
    "mcp__syber-tools__publish_finding": "publish_finding",
    "mcp__syber-tools__request_hitl": "request_hitl",
    "mcp__syber-tools__score_behaviour": "score_behaviour",
}


def normalise_allowed(allowed: list[str]) -> list[str]:
    return [SPEC_NAME_MAP.get(a, a) for a in allowed]


def build_tool_server() -> ToolServer:
    tools: list[ToolSpec] = [
        query_data_lake,
        get_graph_context,
        publish_finding,
        request_hitl,
        score_behaviour,
    ]
    return ToolServer("syber-tools", tools)


__all__ = ["build_tool_server", "normalise_allowed", "SPEC_NAME_MAP"]
