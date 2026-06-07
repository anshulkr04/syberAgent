"""
Agent loop — the Claude Agent SDK replacement (spec section 3).

The SDK "handles the full agent loop, you define tools and subagents." This
module implements that loop against DeepSeek:

    LLM call -> tool execution -> result injection -> repeat

plus the three SDK capabilities the spec relies on (section 3.1):

  * Parallel subagent dispatch  -> AgentDefinition + the synthetic `Task` tool,
    each subagent running in its own ISOLATED message history. Only the
    subagent's final text returns to the orchestrator (spec 3.3).
  * Automatic context compaction with CLAUDE.md re-read  -> when history grows
    past a budget, older turns are summarised and the system prompt
    (the CLAUDE.md investigative protocol) is re-injected (spec 8.4).
  * Native HITL  -> a tool may raise HumanApprovalRequired to pause the loop.
"""
from __future__ import annotations

import contextvars
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable

from ..config import LLM
from ..tools.registry import ToolServer, ToolSpec
from .client import LLMResponse, get_client
from .exceptions import HumanApprovalRequired

__all__ = ["AgentLoop", "AgentDefinition", "LoopResult", "HumanApprovalRequired"]


@dataclass
class AgentDefinition:
    """A subagent (spec 3.2 `agents=[...]`)."""

    name: str
    description: str
    system_prompt: str
    tools: list[str] = field(default_factory=list)
    model: str = LLM.subagent_model


@dataclass
class LoopResult:
    final_text: str
    turns: int
    tool_invocations: list[dict[str, Any]]
    finding: dict[str, Any] | None = None
    hitl: dict[str, Any] | None = None
    transcript: list[dict[str, Any]] = field(default_factory=list)


# Audit hook: (event_type, data) -> None. Defaults to no-op; the orchestrator
# wires this to the immutable AuditLog (spec 14).
AuditHook = Callable[[str, dict[str, Any]], None]


class AgentLoop:
    def __init__(
        self,
        *,
        system_prompt: str,
        tool_server: ToolServer,
        allowed_tools: list[str],
        model: str,
        agents: list[AgentDefinition] | None = None,
        max_turns: int = LLM.max_turns,
        audit: AuditHook | None = None,
        compaction_budget: int = 60,
    ):
        self.system_prompt = system_prompt
        self.tool_server = tool_server
        self.allowed_tools = list(allowed_tools)
        self.model = model
        self.agents = {a.name: a for a in (agents or [])}
        self.max_turns = max_turns
        self.audit = audit or (lambda *_: None)
        self.compaction_budget = compaction_budget
        self._client = get_client()
        self._invocations: list[dict[str, Any]] = []
        self._finding: dict[str, Any] | None = None

    # ------------------------------------------------------------------ #
    def run(self, prompt: str) -> LoopResult:
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": prompt},
        ]
        tools = self._tool_specs()
        last_text = ""

        for turn in range(1, self.max_turns + 1):
            messages = self._maybe_compact(messages)
            resp: LLMResponse = self._client.chat(
                messages,
                model=self.model,
                tools=tools or None,
                temperature=0.2,
                want_logprobs=False,
            )
            messages.append(resp.raw_message)
            if resp.text:
                last_text = resp.text

            if not resp.tool_calls:
                # Model produced a final answer with no tool calls.
                return LoopResult(
                    final_text=last_text,
                    turns=turn,
                    tool_invocations=self._invocations,
                    finding=self._finding,
                    transcript=messages,
                )

            for call in resp.tool_calls:
                try:
                    result = self._dispatch(call, messages)
                except HumanApprovalRequired as hitl:
                    self.audit("hitl_pause", hitl.payload)
                    return LoopResult(
                        final_text=last_text,
                        turns=turn,
                        tool_invocations=self._invocations,
                        hitl=hitl.payload,
                        transcript=messages,
                    )
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call["id"],
                        "content": json.dumps(result),
                    }
                )

        # Exhausted turns without a terminal answer.
        return LoopResult(
            final_text=last_text or "max_turns_exhausted",
            turns=self.max_turns,
            tool_invocations=self._invocations,
            finding=self._finding,
            transcript=messages,
        )

    # ------------------------------------------------------------------ #
    def _tool_specs(self) -> list[dict[str, Any]]:
        specs = self.tool_server.specs(allowed=self.allowed_tools)
        if self.agents and "Task" in self.allowed_tools:
            specs.append(self._task_tool_spec())
        return specs

    def _task_tool_spec(self) -> dict[str, Any]:
        names = ", ".join(self.agents)
        return {
            "type": "function",
            "function": {
                "name": "Task",
                "description": (
                    "Dispatch a specialised subagent that runs in its own isolated "
                    f"context window. Available subagents: {names}. Returns only the "
                    "subagent's final summary, never its raw tool history."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "subagent_type": {"type": "string", "enum": list(self.agents)},
                        "prompt": {"type": "string", "description": "Task for the subagent"},
                    },
                    "required": ["subagent_type", "prompt"],
                },
            },
        }

    def _dispatch(self, call: dict[str, Any], _messages: list[dict[str, Any]]) -> dict[str, Any]:
        name = call["name"]
        try:
            args = json.loads(call["arguments"]) if call["arguments"] else {}
        except json.JSONDecodeError:
            return {"error": f"invalid JSON arguments for {name}"}

        self.audit("tool_call", {"tool": name, "args": args})

        if name == "Task":
            return self._run_subagent(args)

        spec: ToolSpec | None = self.tool_server.get(name)
        if spec is None or name not in self.allowed_tools:
            return {"error": f"tool '{name}' not permitted"}

        result = spec.handler(args)
        self._invocations.append({"tool": name, "args": args})
        # Capture a published finding so the orchestrator can surface it (spec 3.2).
        if name == "publish_finding" and isinstance(result, dict) and result.get("status") == "published":
            self._finding = result.get("finding")
        return result

    def _run_subagent(self, args: dict[str, Any]) -> dict[str, Any]:
        sub_name = args.get("subagent_type", "")
        definition = self.agents.get(sub_name)
        if definition is None:
            return {"error": f"unknown subagent '{sub_name}'"}

        sub_loop = AgentLoop(
            system_prompt=definition.system_prompt,
            tool_server=self.tool_server,
            allowed_tools=definition.tools,
            model=definition.model,
            agents=None,            # subagents do not spawn further subagents here
            max_turns=min(self.max_turns, 12),
            audit=self.audit,
            compaction_budget=self.compaction_budget,
        )
        self.audit("subagent_dispatch", {"subagent": sub_name})
        result = sub_loop.run(args.get("prompt", ""))
        # Propagate any finding/HITL the subagent produced.
        if result.finding and self._finding is None:
            self._finding = result.finding
        # Only the summarised output crosses the context boundary (spec 3.3).
        return {"subagent": sub_name, "summary": result.final_text}

    def dispatch_parallel(self, tasks: list[tuple[str, str]]) -> dict[str, dict[str, Any]]:
        """Run several subagents simultaneously (spec 3.1 fan-out).

        tasks: list of (subagent_type, prompt). Used by the orchestrator to run
        context_graph_agent and behavioural_analytics_agent at the same time.
        """
        out: dict[str, dict[str, Any]] = {}
        with ThreadPoolExecutor(max_workers=max(1, len(tasks))) as pool:
            futures = {}
            for name, p in tasks:
                # Copy the current context (carries the active InvestigationScope)
                # into the worker thread; contextvars do not propagate otherwise.
                ctx = contextvars.copy_context()
                fut = pool.submit(ctx.run, self._run_subagent, {"subagent_type": name, "prompt": p})
                futures[fut] = name
            for fut in futures:
                name = futures[fut]
                out[name] = fut.result()
        return out

    # ------------------------------------------------------------------ #
    def _maybe_compact(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Summarise old turns and re-read the CLAUDE.md protocol (spec 3.1/8.4)."""
        if len(messages) <= self.compaction_budget:
            return messages

        system = messages[0]
        head = messages[1:3]           # keep the original trigger
        tail = messages[-10:]          # keep recent working context
        middle = messages[3:-10]
        if not middle:
            return messages

        summary_prompt = (
            "Summarise the following investigation steps into a compact set of "
            "established facts, retrieved evidence_refs, and open questions. Be terse.\n\n"
            + "\n".join(
                f"{m.get('role')}: {str(m.get('content'))[:600]}" for m in middle if m.get("content")
            )
        )
        try:
            summary = self._client.complete(summary_prompt, model=LLM.subagent_model, temperature=0.0)
        except Exception:  # noqa: BLE001 - never let compaction crash the loop
            summary = "[compaction summary unavailable]"

        self.audit("context_compaction", {"summarised_turns": len(middle)})
        # Re-read CLAUDE.md by re-injecting the system prompt after the summary.
        return [
            system,
            *head,
            {"role": "assistant", "content": f"[Compacted context]\n{summary}"},
            {"role": "system", "content": self.system_prompt},
            *tail,
        ]
