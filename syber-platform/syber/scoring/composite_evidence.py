"""
Composite Evidence Score gate (spec section 12.2).

CES = w1*S_consistency + w2*S_calibrated + w3*S_selfcheck

  S_consistency : fraction of attack-chain steps backed by >=1 distinct evidence_ref
  S_calibrated  : Platt-calibrated LLM confidence (not the raw logit, spec 12.1)
  S_selfcheck   : cosine agreement between two independent generation passes

Weights (0.45, 0.30, 0.25) and the escalation threshold (0.82) come from the
spec and are centralised in config.THRESHOLDS.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..config import THRESHOLDS
from ..harness import embeddings as emb
from .calibration.fit_platt import load_scaler

_calibrator = None


def _get_calibrator():
    global _calibrator
    if _calibrator is None:
        _calibrator = load_scaler()
    return _calibrator


@dataclass
class CES:
    value: float
    s_consistency: float
    s_calibrated: float
    s_selfcheck: float
    escalate: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "ces": round(self.value, 4),
            "s_consistency": round(self.s_consistency, 4),
            "s_calibrated": round(self.s_calibrated, 4),
            "s_selfcheck": round(self.s_selfcheck, 4),
            "escalate": self.escalate,
            "threshold": THRESHOLDS.ces_escalate,
        }


def _all_distinct(step_refs: list[str], all_refs: list[str]) -> bool:
    return all(r in all_refs for r in step_refs) and len(set(step_refs)) == len(step_refs)


def compute_ces(
    attack_chain: list[dict[str, Any]],
    evidence_refs: list[str],
    llm_logit_score: float,
    finding_chain_a: str,
    finding_chain_b: str,
) -> CES:
    # S1: structural evidence consistency
    corroborated = sum(
        1 for step in attack_chain
        if len(step.get("evidence_refs", [])) >= 1 and _all_distinct(step["evidence_refs"], evidence_refs)
    )
    s_consistency = corroborated / max(len(attack_chain), 1)

    # S2: Platt-calibrated confidence
    s_calibrated = float(_get_calibrator().predict_proba([[llm_logit_score]])[0][1])

    # S3: self-consistency between two independent passes
    s_selfcheck = emb.cosine_similarity(emb.encode(finding_chain_a), emb.encode(finding_chain_b))

    w1, w2, w3 = THRESHOLDS.ces_weights
    value = w1 * s_consistency + w2 * s_calibrated + w3 * s_selfcheck
    return CES(
        value=value,
        s_consistency=s_consistency,
        s_calibrated=s_calibrated,
        s_selfcheck=s_selfcheck,
        escalate=value >= THRESHOLDS.ces_escalate,
    )
