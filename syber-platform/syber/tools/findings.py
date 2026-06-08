"""
publish_finding + request_hitl in-process MCP tools (spec section 3.4 / 3.5).

publish_finding records a CANDIDATE finding after schema validation; the
Composite Evidence Scoring gate (spec 12) is then applied by the orchestrator
before analyst escalation. request_hitl pauses the agent loop for human review.
"""
from __future__ import annotations

from typing import Any

from ..audit.log import get_audit_log
from ..harness.memory_integrity import get_memory_store
from ..harness.schema_validator import coerce_and_validate
from ..llm.exceptions import HumanApprovalRequired
from .registry import ToolSpec, tool
from .scope_guard import get_current_scope


class FindingsSink:
    """In-process stand-in for the Kafka `findings` topic (spec 4.1)."""

    def __init__(self) -> None:
        self.candidates: list[dict[str, Any]] = []

    def publish(self, finding: dict[str, Any]) -> None:
        self.candidates.append(finding)

    def latest(self) -> dict[str, Any] | None:
        return self.candidates[-1] if self.candidates else None


_sink = FindingsSink()


def get_findings_sink() -> FindingsSink:
    return _sink


PUBLISH_FINDING_PARAMS = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "attack_chain": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "step": {"type": "integer"},
                    "description": {"type": "string"},
                    "status": {"type": "string", "enum": ["confirmed", "inferred"]},
                    "mitre_technique": {"type": "string"},
                    "evidence_refs": {"type": "array", "items": {"type": "string"}},
                    "timestamp_utc": {"type": "string"},
                },
                "required": ["step", "description", "status"],
            },
        },
        "evidence_refs": {"type": "array", "items": {"type": "string"}},
        "mitre_techniques": {"type": "array", "items": {"type": "string"}},
        "confidence_estimate": {"type": "number"},
        "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
    },
    "required": ["attack_chain", "evidence_refs", "mitre_techniques", "confidence_estimate", "severity"],
}


@tool("publish_finding", "Publish a forensic finding (candidate) for evidence-score gating.", PUBLISH_FINDING_PARAMS)
def publish_finding(args: dict[str, Any]) -> dict[str, Any]:
    audit = get_audit_log()
    scope = get_current_scope()
    finding = dict(args)
    finding["investigation_id"] = scope.investigation_id

    ok, errors, finding = coerce_and_validate(finding)
    if not ok:
        audit.write("finding_schema_rejected", {"errors": errors}, "schema_validator")
        return {"status": "rejected", "schema_errors": errors}

    _sink.publish(finding)
    audit.write("finding_published", {
        "investigation_id": finding["investigation_id"],
        "severity": finding["severity"],
        "mitre": finding["mitre_techniques"],
        "evidence_ref_count": len(finding["evidence_refs"]),
    }, "threat_investigator")

    # Only privileged agents write memory; the orchestrator owns the candidate.
    try:
        get_memory_store().write(
            {"kind": "candidate_finding", "severity": finding["severity"],
             "mitre": finding["mitre_techniques"]},
            agent_id="orchestrator", investigation_id=finding["investigation_id"],
        )
    except Exception:  # noqa: BLE001 - memory write must not break publishing
        pass

    # Store the finding into the attack-surface graph (graph = source of truth),
    # linked to the host it is about when that host is in scope.
    try:
        from ..graph.model import upsert_finding
        host = next((e for e in scope.allowed_entities if not e.replace(".", "").isdigit()), None)
        upsert_finding(finding, host=host)
    except Exception:  # noqa: BLE001 - graph write must not break publishing
        pass

    return {"status": "published", "finding": finding}


REQUEST_HITL_PARAMS = {
    "type": "object",
    "properties": {
        "reason": {"type": "string"},
        "evidence_so_far": {"type": "array", "items": {"type": "string"}},
        "severity_estimate": {"type": "string"},
    },
    "required": ["reason"],
}


@tool("request_hitl", "Escalate to a human analyst, pausing the investigation.", REQUEST_HITL_PARAMS)
def request_hitl(args: dict[str, Any]) -> dict[str, Any]:
    scope = get_current_scope()
    get_audit_log().write("hitl_request", {"reason": args.get("reason"),
                                           "investigation_id": scope.investigation_id}, "threat_investigator")
    # Pause the agent loop (spec 3.5). The orchestrator resumes after analyst input.
    raise HumanApprovalRequired({
        "investigation_id": scope.investigation_id,
        "reason": args.get("reason"),
        "evidence_so_far": args.get("evidence_so_far", []),
        "severity_estimate": args.get("severity_estimate"),
    })


def publish_tool() -> ToolSpec:
    return publish_finding


def hitl_tool() -> ToolSpec:
    return request_hitl
