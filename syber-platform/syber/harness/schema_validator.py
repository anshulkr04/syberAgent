"""
Output JSON schema enforcement (spec section 2 harness/schema_validator.py).

Every finding the threat investigator publishes must conform to the contract in
CLAUDE.md (spec 8.4): attack_chain, evidence_refs, mitre_techniques,
confidence_estimate, severity, each chain step labelled confirmed|inferred.
"""
from __future__ import annotations

from typing import Any

from jsonschema import Draft202012Validator

FINDING_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": [
        "investigation_id",
        "attack_chain",
        "evidence_refs",
        "mitre_techniques",
        "confidence_estimate",
        "severity",
    ],
    "properties": {
        "investigation_id": {"type": "string", "minLength": 1},
        "summary": {"type": "string"},
        "attack_chain": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "required": ["step", "description", "status"],
                "properties": {
                    "step": {"type": "integer"},
                    "description": {"type": "string"},
                    "status": {"enum": ["confirmed", "inferred"]},
                    "mitre_technique": {"type": "string"},
                    "evidence_refs": {"type": "array", "items": {"type": "string"}},
                    "timestamp_utc": {"type": "string"},
                },
            },
        },
        "evidence_refs": {"type": "array", "items": {"type": "string"}},
        "mitre_techniques": {
            "type": "array",
            "items": {"type": "string", "pattern": r"^T\d{4}(\.\d{3})?$"},
        },
        "confidence_estimate": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "severity": {"enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
    },
    "additionalProperties": True,
}

_validator = Draft202012Validator(FINDING_SCHEMA)


def validate_finding(finding: dict[str, Any]) -> tuple[bool, list[str]]:
    errors = sorted(_validator.iter_errors(finding), key=lambda e: list(e.path))
    msgs = [f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}" for e in errors]
    return (len(msgs) == 0), msgs


def coerce_and_validate(finding: dict[str, Any]) -> tuple[bool, list[str], dict[str, Any]]:
    """Light normalisation then validate.

    Reconciles the top-level `evidence_refs` to the UNION of itself and every
    step's `evidence_refs`. The finding's evidence is, by definition, the union
    of its steps' evidence — so this keeps the two in sync regardless of how the
    model formatted them, which makes the CES structural-consistency score
    (corroborated steps / total steps) robust to output variance instead of
    collapsing to 0 when the model lists step refs but not top-level refs.
    """
    f = dict(finding)
    if isinstance(f.get("severity"), str):
        f["severity"] = f["severity"].upper()

    step_refs: set[str] = set()
    for step in f.get("attack_chain", []) or []:
        if isinstance(step, dict) and isinstance(step.get("evidence_refs"), list):
            step_refs.update(map(str, step["evidence_refs"]))

    top = set(map(str, f.get("evidence_refs", []) or []))
    f["evidence_refs"] = sorted(top | step_refs)
    ok, msgs = validate_finding(f)
    return ok, msgs, f
