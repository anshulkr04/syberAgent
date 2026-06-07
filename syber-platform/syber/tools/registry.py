"""
In-process tool registry (spec section 3.4).

The Claude Agent SDK serves tools as in-process MCP functions via
`create_sdk_mcp_server`. We mirror that contract with a lightweight registry:
each tool is a Python callable plus a JSON-schema parameter spec. The scope
guard, injection filter, and audit log are invoked *inside* each tool before
the result is returned to the LLM (exactly as the spec's query_data_lake shows).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

ToolHandler = Callable[[dict[str, Any]], dict[str, Any]]


@dataclass
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]  # JSON schema (object)
    handler: ToolHandler

    def to_openai(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


def tool(name: str, description: str, parameters: dict[str, Any]):
    """Decorator mirroring claude_agent_sdk's @tool (spec 3.4)."""

    def wrap(fn: ToolHandler) -> ToolSpec:
        return ToolSpec(name=name, description=description, parameters=parameters, handler=fn)

    return wrap


class ToolServer:
    """Equivalent of create_sdk_mcp_server: a named bundle of tools."""

    def __init__(self, name: str, tools: list[ToolSpec]):
        self.name = name
        self._tools = {t.name: t for t in tools}

    def names(self) -> list[str]:
        return list(self._tools)

    def specs(self, allowed: list[str] | None = None) -> list[dict[str, Any]]:
        items = self._tools.values()
        if allowed is not None:
            items = [t for t in items if t.name in allowed]
        return [t.to_openai() for t in items]

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)
