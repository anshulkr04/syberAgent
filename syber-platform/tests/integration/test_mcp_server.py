"""
MCP server integration test — spawns the Syber MCP server over stdio and drives
it through the real MCP protocol (the same path Claude Code uses), confirming the
component tools are reachable and return correct results.

Run: python -m pytest tests/integration/test_mcp_server.py
(or: python tests/integration/test_mcp_server.py for a verbose live trace)
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

PLUGIN = Path(__file__).resolve().parents[3] / "claude-code" / "plugins" / "syber"
VENV_PY = Path(__file__).resolve().parents[3] / ".venv" / "bin" / "python"


def _server_params() -> StdioServerParameters:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(PLUGIN)
    return StdioServerParameters(
        command=str(VENV_PY),
        args=["-m", "server.syber_mcp"],
        cwd=str(PLUGIN),
        env=env,
    )


async def _drive() -> dict:
    async with stdio_client(_server_params()) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = {t.name for t in (await session.list_tools()).tools}

            start = await session.call_tool("syber_start_investigation", {"seed_demo": True})
            start_txt = start.content[0].text

            graph = await session.call_tool(
                "syber_get_graph_context",
                {"entity_id": "SVC-API-07@dubaipolice.ae", "k_paths": 3})
            behav = await session.call_tool(
                "syber_score_behaviour", {"entity_id": "SVC-API-07@dubaipolice.ae"})
            status = await session.call_tool("syber_backend_status", {})
            return {
                "tools": tools,
                "start": start_txt,
                "graph": graph.content[0].text,
                "behaviour": behav.content[0].text,
                "status": status.content[0].text,
            }


def test_mcp_server_tools_reachable():
    out = asyncio.run(_drive())
    expected = {"syber_start_investigation", "syber_query_data_lake", "syber_get_graph_context",
                "syber_score_behaviour", "syber_publish_finding", "syber_request_hitl",
                "syber_gate_finding", "syber_run_response_playbook", "syber_verify_integrity",
                "syber_backend_status", "syber_run_full_investigation"}
    assert expected <= out["tools"], out["tools"]
    assert "INV-" in out["start"]
    assert "attack_paths" in out["graph"] or "blast_radius" in out["graph"]
    assert "is_anomalous" in out["behaviour"]


if __name__ == "__main__":
    import json

    res = asyncio.run(_drive())
    print("tools:", sorted(res["tools"]))
    for k in ("start", "graph", "behaviour", "status"):
        print(f"\n--- {k} ---\n{res[k][:600]}")
