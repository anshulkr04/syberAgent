"""
Investigation orchestrator (spec section 3.2) — Claude Agent SDK entry point,
reimplemented against DeepSeek via the in-house AgentLoop.

Flow:
  1. Set the investigation scope (scope guard, spec 3.4).
  2. Fan out context_graph_agent + behavioural_analytics_agent in parallel
     (spec 3.1) to build isolated-context summaries.
  3. Run the orchestrator loop, which dispatches the threat_investigator to
     assemble and publish a candidate finding.
  4. Apply the Composite Evidence Score gate (spec 12) with a true two-pass
     self-consistency check before escalation.
  5. If verified and a response playbook matches, run the response orchestrator
     (dry-run + HITL gate by default).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..audit.log import get_audit_log
from ..bus.bus import get_bus
from ..bus.schemas import SecurityEvent
from ..config import LLM, PATHS
from ..llm.agent_loop import AgentLoop
from ..scoring.composite_evidence import compute_ces
from ..tools import build_tool_server, normalise_allowed
from ..tools.findings import get_findings_sink
from ..tools.scope_guard import InvestigationScope, set_current_scope
from .definitions import ALL_SUBAGENTS
from . import prompts


def _load_claude_md() -> str:
    path = PATHS.root / ".claude" / "CLAUDE.md"
    if path.is_file():
        return path.read_text()
    return prompts.DEFAULT_SYSTEM_PROMPT


def run_investigation(trigger_event: dict[str, Any], scope: InvestigationScope) -> dict[str, Any]:
    """Entry point for a security investigation (spec 3.2)."""
    set_current_scope(scope)
    audit = get_audit_log()
    bus = get_bus()
    audit.write("investigation_start", {"investigation_id": scope.investigation_id,
                                        "trigger": trigger_event.get("event_type")})
    # The anomaly that opened this investigation (spec §4.1 anomaly_detected topic).
    bus.publish("anomaly_detected", SecurityEvent(
        event_type="anomaly_detected", originating_agent="behavioural-agent",
        investigation_id=scope.investigation_id, confidence=trigger_event.get("anomaly_score"),
        payload=json.dumps(trigger_event), evidence_refs=[]).sign())

    # Persist state directory (spec 3.2 / 8.4 .investigation_state).
    state_dir = PATHS.state / scope.investigation_id
    state_dir.mkdir(parents=True, exist_ok=True)

    tool_server = build_tool_server()
    system_prompt = prompts.render_system_prompt(_load_claude_md(), scope)

    def audit_hook(event_type: str, data: dict[str, Any]) -> None:
        audit.write(f"sdk_{event_type}", data)

    loop = AgentLoop(
        system_prompt=system_prompt,
        tool_server=tool_server,
        allowed_tools=normalise_allowed([
            "mcp__syber-tools__query_data_lake",
            "mcp__syber-tools__get_graph_context",
            "mcp__syber-tools__publish_finding",
            "mcp__syber-tools__request_hitl",
            "score_behaviour",
            "Task",
        ]),
        model=LLM.orchestrator_model,
        agents=ALL_SUBAGENTS,
        max_turns=LLM.max_turns,
        audit=audit_hook,
    )

    # Step 2: parallel fan-out (spec 3.1).
    entity_id = trigger_event.get("entity_id", "")
    fanout = loop.dispatch_parallel([
        ("context_graph_agent", f"Build attack-path context for entity {entity_id}."),
        ("behavioural_analytics_agent", f"Score behavioural deviation for entity {entity_id}."),
    ])
    _write_progress(state_dir, "fanout", fanout)

    # Step 3: orchestrator loop assembles + publishes the candidate finding.
    prompt = prompts.build_investigation_prompt(trigger_event, scope, fanout)
    result = loop.run(prompt)
    _write_progress(state_dir, "loop", {"turns": result.turns, "hitl": result.hitl})

    if result.hitl:
        audit.write("investigation_hitl", result.hitl)
        return {"status": "escalated_to_hitl", "investigation_id": scope.investigation_id,
                "hitl": result.hitl, "fanout": fanout, "turns": result.turns}

    candidate = result.finding or get_findings_sink().latest()
    if not candidate:
        return {"status": "no_finding", "investigation_id": scope.investigation_id,
                "final_text": result.final_text, "fanout": fanout, "turns": result.turns}

    # Step 4: Composite Evidence Score gate (spec 12).
    ces = _apply_ces_gate(candidate, system_prompt, prompt)
    audit.write("ces_gate", {**ces.to_dict(), "investigation_id": scope.investigation_id})
    _write_progress(state_dir, "ces", ces.to_dict())

    verified = ces.escalate
    # Publish to findings, and to verified_findings when the CES gate passes
    # (spec §4.1 findings / verified_findings topics).
    bus.publish("findings", SecurityEvent(
        event_type="finding", originating_agent="threat-investigator",
        investigation_id=scope.investigation_id, confidence=ces.value,
        payload=json.dumps(candidate, default=str),
        evidence_refs=candidate.get("evidence_refs", [])).sign())
    if verified:
        bus.publish("verified_findings", SecurityEvent(
            event_type="verified_finding", originating_agent="orchestrator",
            investigation_id=scope.investigation_id, confidence=ces.value,
            payload=json.dumps(candidate, default=str),
            evidence_refs=candidate.get("evidence_refs", [])).sign())

    return {
        "status": "verified_finding" if verified else "below_ces_threshold",
        "investigation_id": scope.investigation_id,
        "finding": candidate,
        "ces": ces.to_dict(),
        "fanout": fanout,
        "turns": result.turns,
    }


def _apply_ces_gate(candidate: dict[str, Any], system_prompt: str, prompt: str):
    """Run the CES gate with a genuine two-pass self-consistency (spec 12.2)."""
    from ..scoring.gate import gate_candidate

    return gate_candidate(candidate, system_context=system_prompt[:1500])


def _write_progress(state_dir: Path, stage: str, data: Any) -> None:
    (state_dir / "progress.md").open("a").write(
        f"\n## {stage}\n```json\n{json.dumps(data, default=str, indent=2)}\n```\n"
    )
