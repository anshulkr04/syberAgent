"""
Deterministic component integration tests (no LLM spend).

Covers: behavioural ensemble, graph attack paths, response rollback, DLQ retry,
CES gate, audit + memory hash chains, schema validation.

Run: python -m pytest tests/integration/test_components.py   (from syber-platform/)
"""
from __future__ import annotations

import numpy as np

from syber.analytics.service import score_entity
from syber.bus.dead_letter import MAX_RETRIES, process_dlq
from syber.graph.store import get_graph
from syber.harness.schema_validator import validate_finding
from syber.response.executor import (PlaybookExecutionError, execute_playbook,
                                     mock_integration)
from syber.response.playbooks import CRED_REVOKE_PLAYBOOK
from syber.scoring.composite_evidence import compute_ces
from syber.seed_data import ACTOR, CII, build_scenario


def setup_module(_):
    build_scenario()


def test_behavioural_ensemble_flags_anomaly():
    out = score_entity(ACTOR)
    assert out["is_anomalous"] is True
    assert set(out["contributing_models"]) == {"iforest", "lstm", "ocsvm"}


def test_graph_attack_path_to_cii():
    g = get_graph()
    path = g.dijkstra(ACTOR, CII)
    assert path is not None and ACTOR in path["path"] and CII in path["path"]
    yens = g.yens_k_shortest(ACTOR, CII, k=3)
    assert yens and yens[0]["total_cost"] <= yens[-1]["total_cost"]  # ranked


def test_response_rollback_on_failure():
    # Force S2 (rotate_credentials, irreversible) to fail -> S1 must roll back.
    integrations = {
        "azure_ad": mock_integration("azure_ad", fail_actions={"rotate_credentials"}),
        "itsm_servicenow": mock_integration("itsm_servicenow"),
    }
    ctx = {"entity_id": ACTOR, "evidence_refs": "sha256:EV-0001"}
    try:
        execute_playbook(CRED_REVOKE_PLAYBOOK, ctx, integrations, dry_run=False)
        assert False, "expected PlaybookExecutionError"
    except PlaybookExecutionError as e:
        completed_ids = {s["step_id"] for s in e.completed_steps}
        assert "S1" in completed_ids  # S1 ran before S2 failed
    # S1 (revoke_session) should have been rolled back via restore_session.
    actions = [c["action"] for c in integrations["azure_ad"].handler.calls]
    assert "restore_session" in actions


def test_dlq_permanent_failure_after_max_retries():
    republished, alerted = [], []
    events = [{"id": "e1", "retry_count": MAX_RETRIES}, {"id": "e2", "retry_count": 0}]
    res = process_dlq(events, republish=republished.append, alert_admin=alerted.append)
    assert len(res.permanently_failed) == 1 and len(res.republished) == 1
    assert res.republished[0]["retry_count"] == 1


def test_ces_gate_high_evidence():
    chain = [{"step": i, "description": f"s{i}", "status": "confirmed",
              "evidence_refs": [f"sha256:EV-000{i}"]} for i in range(1, 5)]
    refs = [f"sha256:EV-000{i}" for i in range(1, 5)]
    ces = compute_ces(chain, refs, llm_logit_score=0.9,
                      finding_chain_a="auth pivot exfil", finding_chain_b="auth pivot exfil")
    assert ces.s_consistency == 1.0
    assert ces.escalate is True


def test_schema_validation_rejects_bad_finding():
    ok, errs = validate_finding({"investigation_id": "x", "attack_chain": [],
                                 "evidence_refs": [], "mitre_techniques": ["BAD"],
                                 "confidence_estimate": 2.0, "severity": "nope"})
    assert not ok and errs


def test_audit_and_memory_chains_valid():
    from syber.audit.log import get_audit_log
    from syber.harness.memory_integrity import get_memory_store
    get_audit_log().write("test_event", {"k": "v"})
    assert get_audit_log().verify_chain() is True
    get_memory_store().write({"kind": "test"}, agent_id="orchestrator", investigation_id="INV-TEST")
    assert get_memory_store().verify_chain() is True
