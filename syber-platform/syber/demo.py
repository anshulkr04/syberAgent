"""
End-to-end demo (run: python -m syber.demo).

Seeds the SVC-API-07 compromise scenario, scores it with the behavioural
ensemble, then runs a LIVE DeepSeek-driven multi-agent investigation through
the orchestrator, the CES gate, and (if verified) a dry-run response playbook.
"""
from __future__ import annotations

import json
import sys

from .agents.orchestrator import run_investigation
from .analytics.service import score_entity
from .audit.log import get_audit_log
from .config import LLM, assert_configured
from .harness.memory_integrity import get_memory_store
from .response.executor import execute_playbook, mock_integration
from .response.playbooks import CRED_REVOKE_PLAYBOOK, matches_trigger
from .seed_data import ACTOR, build_scenario


def _hr(title: str) -> None:
    print("\n" + "=" * 72 + f"\n{title}\n" + "=" * 72)


def main() -> int:
    assert_configured()
    print(f"LLM provider: DeepSeek (orchestrator={LLM.resolve_model(LLM.orchestrator_model)}, "
          f"subagent={LLM.resolve_model(LLM.subagent_model)})")

    _hr("1. Seeding scenario (graph + data lake + behavioural ensemble)")
    trigger, scope = build_scenario()
    behaviour = score_entity(ACTOR)
    trigger["anomaly_score"] = behaviour["score"]
    print(f"Behavioural ensemble score for {ACTOR}: {behaviour['score']} "
          f"(anomalous={behaviour['is_anomalous']})")
    print(f"  contributing models : {behaviour['contributing_models']}")
    print(f"  top anomalous feats : {behaviour['top_anomalous_features']}")

    _hr("2. Running live multi-agent investigation (DeepSeek)")
    print(f"Investigation: {scope.investigation_id}  scope={sorted(scope.allowed_entities)}")
    result = run_investigation(trigger, scope)

    _hr("3. Investigation result")
    print(f"status: {result['status']}  (turns={result.get('turns')})")
    if result.get("ces"):
        print(f"CES gate: {json.dumps(result['ces'])}")
    finding = result.get("finding")
    if finding:
        print("\nFinding:")
        print(f"  severity   : {finding.get('severity')}")
        print(f"  mitre      : {finding.get('mitre_techniques')}")
        print(f"  confidence : {finding.get('confidence_estimate')}")
        print(f"  evidence   : {finding.get('evidence_refs')}")
        for step in finding.get("attack_chain", []):
            print(f"   [{step.get('status'):9}] step {step.get('step')}: "
                  f"{step.get('mitre_technique','-')} — {step.get('description','')[:80]}")
    if result.get("hitl"):
        print(f"\nHITL escalation: {json.dumps(result['hitl'])}")

    # 4. Response orchestrator (dry-run) if verified + a playbook matches.
    if finding and result["status"] == "verified_finding" and matches_trigger(CRED_REVOKE_PLAYBOOK, finding):
        _hr("4. Response orchestrator (dry-run, HITL-gated in production)")
        integrations = {"azure_ad": mock_integration("azure_ad"),
                        "itsm_servicenow": mock_integration("itsm_servicenow")}
        ctx = {"entity_id": ACTOR, "evidence_refs": ",".join(finding.get("evidence_refs", []))}
        outcome = execute_playbook(CRED_REVOKE_PLAYBOOK, ctx, integrations, dry_run=True)
        print(f"playbook {CRED_REVOKE_PLAYBOOK['playbook_id']}: {outcome}")

    # 5. Integrity checks.
    _hr("5. Integrity verification")
    print(f"audit chain valid : {get_audit_log().verify_chain()}")
    print(f"memory chain valid: {get_memory_store().verify_chain()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
