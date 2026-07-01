"""
Fleet Phase 8 — verification layer tests (no network, no real tools).

Covers: the evidence ladder + severity mapping, lead classification (Keycloak /
admin console / .git / datastore), the LeadRegistry done-gate (no_open_highvalue_lead),
record_attempt climbing/exhausting, the verify command builders (pure), board
verify-task spawning from leads, and the END-TO-END coordinator behaviour that fixes
the reported failure: an exposed high-value lead is NOT left at the surface — the
engagement keeps going until the lead is VERIFIED or EXHAUSTED.

Run: python -m pytest tests/fleet/test_verification.py   (from syber-platform/)
"""
from __future__ import annotations

from syber.fleet.board import Board, InMemoryTaskStore
from syber.fleet.coordinator import Coordinator, WorkerResult
from syber.fleet.leads import (EvidenceRung, Lead, LeadClass, LeadRegistry, LeadState,
                               classify_node, severity_for_rung, verify_task_kinds_for)
from syber.fleet.persistence import PersistencePolicy
from syber.fleet.planner import Planner
from syber.fleet import verify_runners as VR
from syber.graph.store import KnowledgeGraph


def _fresh():
    import syber.graph.store as store
    g = KnowledgeGraph(); store._graph = g
    return g


# --------------------------------------------------------------------------- #
# evidence ladder
# --------------------------------------------------------------------------- #
def test_severity_ladder():
    assert severity_for_rung(EvidenceRung.INFORMATIONAL) == "INFO"
    assert severity_for_rung(EvidenceRung.HYPOTHESIS) == "LOW"
    assert severity_for_rung(EvidenceRung.PRECONDITION) == "MEDIUM"
    assert severity_for_rung(EvidenceRung.VERIFIED) == "HIGH"
    assert severity_for_rung(EvidenceRung.IMPACT) == "CRITICAL"


def test_add_evidence_only_climbs():
    lead = Lead(id="l", lead_class=LeadClass.EXPOSED_ADMIN, target="t")
    lead.add_evidence("e1", EvidenceRung.HYPOTHESIS)
    assert lead.rung == EvidenceRung.HYPOTHESIS
    lead.add_evidence("e2", EvidenceRung.IMPACT)
    assert lead.rung == EvidenceRung.IMPACT and lead.state == LeadState.VERIFIED
    lead.add_evidence("e3", EvidenceRung.INFORMATIONAL)   # never demotes
    assert lead.rung == EvidenceRung.IMPACT


# --------------------------------------------------------------------------- #
# classification
# --------------------------------------------------------------------------- #
def test_classify_keycloak_admin_and_secret():
    admin = classify_node("https://x/auth/admin/", {"label": "WebEndpoint", "url": "https://x/auth/admin/"})
    assert admin.lead_class == LeadClass.EXPOSED_ADMIN and admin.high_value
    secret = classify_node("https://x/.git/HEAD", {"label": "WebEndpoint", "url": "https://x/.git/HEAD"})
    assert secret.lead_class == LeadClass.EXPOSED_SECRET
    kc = classify_node("1.2.3.4:443", {"label": "Technology", "name": "Keycloak", "version": "24.0.1"})
    assert kc.lead_class == LeadClass.DEFAULT_CRED_SERVICE and kc.version == "24.0.1"


def test_classify_versioned_product_is_cve_lead():
    lead = classify_node("1.2.3.4:80", {"label": "Service", "product": "Apache httpd", "version": "2.4.49"})
    assert lead.lead_class == LeadClass.VERSION_CVE


def test_classify_datastore_by_port():
    lead = classify_node("1.2.3.4:6379", {"label": "Service", "product": "redis", "port": 6379})
    assert lead.lead_class == LeadClass.DATASTORE_UNAUTH


def test_classify_benign_returns_none():
    assert classify_node("https://x/about", {"label": "WebEndpoint", "url": "https://x/about"}) is None
    assert classify_node("t", {"label": "Service", "product": "nginx"}) is None   # no version


def test_verify_kinds_per_class():
    assert "service_probe" in verify_task_kinds_for(LeadClass.EXPOSED_ADMIN)
    assert "datastore_unauth_probe" in verify_task_kinds_for(LeadClass.DATASTORE_UNAUTH)
    assert verify_task_kinds_for(LeadClass.LOW_VALUE) == []


# --------------------------------------------------------------------------- #
# registry done-gate
# --------------------------------------------------------------------------- #
def test_registry_done_gate_blocks_until_resolved():
    reg = LeadRegistry()
    reg.add(Lead(id="l1", lead_class=LeadClass.EXPOSED_ADMIN, target="t"))
    assert reg.no_open_highvalue_lead() is False        # open high-value -> not done
    reg.record_attempt("l1", "service_probe", success=True, evidence_ref="e", rung=EvidenceRung.VERIFIED)
    assert reg.no_open_highvalue_lead() is True          # verified -> done-eligible


def test_record_attempt_exhausts_after_all_fail():
    reg = LeadRegistry()
    lead = Lead(id="l", lead_class=LeadClass.DEFAULT_CRED_SERVICE, target="t")
    reg.add(lead)   # 1 hypothesis: default_login_check
    reg.record_attempt("l", "default_login_check", success=False, note="creds rejected")
    assert lead.state == LeadState.EXHAUSTED
    assert reg.no_open_highvalue_lead() is True
    assert any("creds rejected" in r for r in lead.reflections)


def test_low_value_lead_does_not_block():
    reg = LeadRegistry()
    reg.add(Lead(id="l", lead_class=LeadClass.LOW_VALUE, target="t"))
    assert reg.no_open_highvalue_lead() is True


def test_registry_snapshot_roundtrip():
    reg = LeadRegistry()
    lead = Lead(id="l", lead_class=LeadClass.EXPOSED_ADMIN, target="t")
    reg.add(lead)
    reg.record_attempt("l", "service_probe", success=True, evidence_ref="e", rung=EvidenceRung.IMPACT)
    reg2 = LeadRegistry(); reg2.restore(reg.snapshot())
    l2 = reg2.get("l")
    assert l2 is not None and l2.state == LeadState.VERIFIED and l2.rung == EvidenceRung.IMPACT


# --------------------------------------------------------------------------- #
# command builders (pure)
# --------------------------------------------------------------------------- #
def test_command_builders():
    assert VR.build_cve_nuclei_id("https://t", "CVE-2024-3656")[:5] == ["nuclei", "-u", "https://t", "-id", "CVE-2024-3656"]
    kc = VR.build_keycloak_token_grant("https://auth.t")
    assert "grant_type=password" in kc and "client_id=admin-cli" in kc
    assert VR.build_datastore_probe("Redis", "h", 6379) == ["redis-cli", "-h", "h", "-p", "6379", "ping"]
    assert VR.build_datastore_probe("nginx", "h", 80) is None
    assert "--script" in VR.build_cve_vulners("t", ports="443")


def test_destructive_floor_default_off(monkeypatch):
    monkeypatch.delenv("SYBER_FLEET_DESTRUCTIVE", raising=False)
    assert VR.DESTRUCTIVE_ENABLED() is False
    monkeypatch.setenv("SYBER_FLEET_DESTRUCTIVE", "1")
    assert VR.DESTRUCTIVE_ENABLED() is True


# --------------------------------------------------------------------------- #
# board spawns verify tasks from leads
# --------------------------------------------------------------------------- #
def test_board_spawns_verify_tasks_for_high_value_leads():
    g = _fresh()
    from syber.graph import model as M
    M.upsert_host("auth.x.com", ip="1.2.3.4")
    M.upsert_service("auth.x.com", 443, service="https")
    M.upsert_web_endpoint("auth.x.com", "https://auth.x.com/auth/admin/", status=200)
    M.upsert_technology("1.2.3.4:443", "Keycloak", version="24.0.1")
    board = Board(store=InMemoryTaskStore(), graph=g)
    board.materialize_frontier()
    kinds = {t.kind for t in board.store.list()}
    assert "service_probe" in kinds            # admin-console lead spawned a probe
    assert "default_login_check" in kinds      # keycloak default-cred lead
    # the verify task carries its lead id + product
    probe = next(t for t in board.store.list() if t.kind == "service_probe")
    assert probe.lead_id.startswith("lead:") and probe.target_id.startswith("https://")


# --------------------------------------------------------------------------- #
# END-TO-END: the reported failure is fixed
# --------------------------------------------------------------------------- #
def test_engagement_does_not_stop_at_unverified_high_value_lead():
    """The Keycloak failure: a worker that only does mechanical scans (never verifies)
    must NOT let the engagement finish with the admin-console lead still OPEN — it gets
    EXHAUSTED with logged attempts, not silently dropped."""
    g = _fresh()
    from syber.graph import model as M
    M.upsert_host("auth.x.com", ip="1.2.3.4")
    M.upsert_service("auth.x.com", 443, service="https")
    M.upsert_web_endpoint("auth.x.com", "https://auth.x.com/auth/admin/", status=200)
    M.upsert_technology("1.2.3.4:443", "Keycloak", version="24.0.1")
    board = Board(store=InMemoryTaskStore(), graph=g)

    def worker(task, board, wid):
        return WorkerResult(status="done")   # mechanical only — never records lead success

    coord = Coordinator(board, Planner(board, graph=g), worker=worker, concurrency=1,
                        persistence=PersistencePolicy())
    out = coord.run()
    assert out["status"] == "complete"
    # every high-value lead reached a terminal state (verified/exhausted) — none left open
    assert board.leads.no_open_highvalue_lead()
    assert all(l.state in (LeadState.VERIFIED, LeadState.EXHAUSTED)
               for l in board.leads.all() if l.high_value)


def test_verified_lead_climbs_to_critical():
    """A worker that confirms default creds drives the admin lead to CRITICAL (rung 4),
    not MEDIUM-and-stop."""
    g = _fresh()
    from syber.graph import model as M
    M.upsert_host("auth.x.com", ip="1.2.3.4")
    M.upsert_service("auth.x.com", 443, service="https")
    M.upsert_web_endpoint("auth.x.com", "https://auth.x.com/auth/admin/", status=200)
    M.upsert_technology("1.2.3.4:443", "Keycloak", version="24.0.1")
    board = Board(store=InMemoryTaskStore(), graph=g)

    def worker(task, board, wid):
        if task.kind == "service_probe":
            board.leads.record_attempt(task.lead_id, "service_probe", success=True,
                                       evidence_ref="admin token via admin/admin",
                                       rung=EvidenceRung.IMPACT)
        return WorkerResult(status="done")

    coord = Coordinator(board, Planner(board, graph=g), worker=worker, concurrency=1,
                        persistence=PersistencePolicy())
    out = coord.run()
    assert out["status"] == "complete"
    verified = [l for l in board.leads.all() if l.state == LeadState.VERIFIED]
    assert any(l.severity == "CRITICAL" for l in verified)
