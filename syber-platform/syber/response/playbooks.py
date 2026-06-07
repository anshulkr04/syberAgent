"""Response playbook definitions (spec section 13.1)."""
from __future__ import annotations

from typing import Any

CRED_REVOKE_PLAYBOOK: dict[str, Any] = {
    "playbook_id": "P-CRED-REVOKE-01",
    "name": "Service account credential revocation",
    "version": "2.1",
    "approved_by": "dubai_police_soc_manager",
    "approved_at": "2026-03-14T09:00:00Z",
    "trigger_conditions": {
        "finding_severity": ["CRITICAL", "HIGH"],
        "attack_chain_includes": ["T1078", "T1021"],
        "asset_class": ["identity_infrastructure", "CII"],
    },
    "requires_hitl": True,
    "steps": [
        {
            "step_id": "S1",
            "integration": "azure_ad",
            "action": "revoke_session",
            "params": {"principal_id": "{{entity_id}}"},
            "reversible": True,
            "rollback_action": "restore_session",
        },
        {
            "step_id": "S2",
            "integration": "azure_ad",
            "action": "rotate_credentials",
            "params": {"principal_id": "{{entity_id}}", "vault_dest": "cyberark_vault"},
            "reversible": False,
            "depends_on": ["S1"],
        },
        {
            "step_id": "S3",
            "integration": "itsm_servicenow",
            "action": "create_incident",
            "params": {
                "priority": "P1",
                "title": "Critical credential compromise: {{entity_id}}",
                "evidence_refs": "{{evidence_refs}}",
            },
            "reversible": True,
        },
    ],
}


def _base_technique(t: str) -> str:
    """T1078.004 -> T1078 (sub-techniques satisfy a base-technique trigger)."""
    return t.split(".", 1)[0]


def matches_trigger(playbook: dict[str, Any], finding: dict[str, Any]) -> bool:
    """Check whether a finding satisfies a playbook's trigger conditions."""
    cond = playbook.get("trigger_conditions", {})
    if finding.get("severity") not in cond.get("finding_severity", []):
        return False
    techniques = {_base_technique(t) for t in finding.get("mitre_techniques", [])}
    required = {_base_technique(t) for t in cond.get("attack_chain_includes", [])}
    return bool(required & techniques)


ALL_PLAYBOOKS = [CRED_REVOKE_PLAYBOOK]
