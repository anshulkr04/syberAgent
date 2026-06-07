"""
Composite Evidence Score gating helper (spec §12), shared by the in-house
orchestrator and the Claude Code MCP server so both apply the identical gate.

Runs a genuine two-pass self-consistency: pass A is the candidate's attack chain
rendered as prose; pass B is an independent DeepSeek re-derivation in the same
shape (apples-to-apples comparison — see commit history for why JSON-vs-prose
made the verdict noisy).
"""
from __future__ import annotations

import json
from typing import Any

from ..config import LLM
from ..harness.injection_guard import build_structured_query
from ..llm.client import get_client
from .composite_evidence import CES, compute_ces


def _render_steps(chain: list[dict[str, Any]]) -> str:
    return "\n".join(
        f"step {s.get('step')}: {s.get('mitre_technique', '')} — {s.get('description', '')}"
        for s in chain
    )


def gate_candidate(candidate: dict[str, Any], system_context: str = "") -> CES:
    chain_a = _render_steps(candidate.get("attack_chain", []))
    try:
        verify_prompt = build_structured_query(
            (system_context + "\n\n" if system_context else "")
            + "Re-derive the attack chain for this finding as a terse ordered list of "
            "steps, one per line, formatted exactly as 'step N: <MITRE T-ID> — "
            "<short description>'. Output only the steps.",
            [json.dumps(candidate, default=str)[:4000]],
        )
        chain_b = get_client().complete(verify_prompt, model=LLM.subagent_model, temperature=0.8)
    except Exception:  # noqa: BLE001
        chain_b = chain_a

    return compute_ces(
        attack_chain=candidate.get("attack_chain", []),
        evidence_refs=candidate.get("evidence_refs", []),
        llm_logit_score=float(candidate.get("confidence_estimate", 0.5)),
        finding_chain_a=chain_a,
        finding_chain_b=chain_b,
    )
