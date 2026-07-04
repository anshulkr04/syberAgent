"""Authenticated-replay runner + API-path/token harvesting + coverage auth-gate."""
from __future__ import annotations

import json

import networkx as nx

from syber.scanning import credentials as cred, exfil, webapp
from syber.fleet import verify_runners as VR
from syber.fleet.board import Task
from syber.fleet.leads import LeadRegistry, Lead, LeadClass
from syber.fleet.coverage import engagement_coverage


class _Board:
    def __init__(self):
        self.leads = LeadRegistry()


def _mk_lead(reg, url):
    return reg.add(Lead(id=f"lead:needauth:{url}", lead_class=LeadClass.AUTH_BYPASS, target=url))


def test_auth_retest_confirms_broken_auth(monkeypatch, tmp_path):
    url = "https://np.x.com/api/Profile/GetDetails"
    board = _Board(); lead = _mk_lead(board.leads, url)
    monkeypatch.setattr(VR, "_authorized", lambda t: True)
    monkeypatch.setattr(exfil, "save_sample", lambda *a, **k: "")
    # a fresh cred store with a harvested token
    store = cred.CredentialStore(path=str(tmp_path / "c.json"))
    store.add(cred.Credential(kind="jwt", value="LEAKEDTOKEN123", name="appIdKey"))
    monkeypatch.setattr(cred, "get_store", lambda: store)
    monkeypatch.setattr(VR, "_mark_auth_retested", lambda u: None)

    # the endpoint returns real data ONLY when the leaked token is presented
    def fake_http(u, method="GET", headers=None, timeout=20):
        if headers and ("LEAKEDTOKEN123" in json.dumps(headers)):
            return {"status": 200, "headers": {"content-type": "application/json"},
                    "body": '[{"pan":"ABCDE1234F","email":"a@b.com"}]'}
        return {"status": 401, "headers": {"content-type": "application/json"}, "body": '"No Auth Header"'}
    monkeypatch.setattr(webapp, "http_request", fake_http)

    task = Task(id="t", kind="auth_retest", target_id=url, lead_id=lead.id, url=url)
    res = VR.run_auth_retest(task, board, "w1")
    assert res.status == "done"
    assert "BROKEN AUTH" in res.note
    from syber.fleet.leads import EvidenceRung, LeadState
    assert lead.rung == EvidenceRung.IMPACT and lead.state == LeadState.VERIFIED


def test_auth_retest_holds_when_no_token_works(monkeypatch, tmp_path):
    url = "https://np.x.com/api/x"
    board = _Board(); lead = _mk_lead(board.leads, url)
    monkeypatch.setattr(VR, "_authorized", lambda t: True)
    monkeypatch.setattr(VR, "_mark_auth_retested", lambda u: None)
    store = cred.CredentialStore(path=str(tmp_path / "c.json"))
    store.add(cred.Credential(kind="jwt", value="WRONGTOKEN", name="jwt"))
    monkeypatch.setattr(cred, "get_store", lambda: store)
    monkeypatch.setattr(webapp, "http_request",
                        lambda u, **k: {"status": 401, "headers": {}, "body": "No Auth Header Found"})
    task = Task(id="t", kind="auth_retest", target_id=url, lead_id=lead.id, url=url)
    res = VR.run_auth_retest(task, board, "w1")
    assert res.status == "done" and "auth holds" in res.note


def test_auth_retest_registered():
    assert "auth_retest" in VR.verify_runners()


# --- API-path extraction from JS/docs --------------------------------------- #
def test_extract_api_paths_from_js():
    js = '''var base="https://np.x.com/mwapi/api/Profile/Get";
            fetch("/api/v1/orders/list"); const x="/services/trade/place";
            var cdn="https://cdn.other.com/lib.js";'''
    paths = webapp.extract_api_paths(js, "https://x.com/assets/app.js")
    assert any("np.x.com/mwapi/api/Profile/Get" in p for p in paths)
    assert any(p.endswith("/api/v1/orders/list") for p in paths)
    assert any(p.endswith("/services/trade/place") for p in paths)
    assert not any("cdn.other.com" in p for p in paths)     # third-party excluded


# --- coverage: auth-gated endpoint blocks completion ------------------------ #
def test_coverage_blocks_on_auth_gated_endpoint():
    g = type("G", (), {})(); g.g = nx.DiGraph()
    g.g.add_node("acme.com", label="Host", subdomains_enumerated=True)
    g.g.add_node("s", label="Service", port=443); g.g.add_edge("acme.com", "s", edge_type="RUNS", port=443)
    g.g.add_node("https://acme.com/api/x", label="WebEndpoint", status=401)
    g.g.add_edge("acme.com", "https://acme.com/api/x", edge_type="SERVES")
    cov = engagement_coverage(graph=g)
    kinds = {r["kind"] for r in cov["remaining"]}
    assert "auth_retest" in kinds          # 401 endpoint must be auth-retested, not "done"
    # once retested, it clears
    g.g.nodes["https://acme.com/api/x"]["auth_retested"] = True
    g.g.nodes["https://acme.com/api/x"]["probed"] = True
    cov2 = engagement_coverage(graph=g)
    assert "auth_retest" not in {r["kind"] for r in cov2["remaining"]}


def test_coverage_requires_login_attempt():
    g = type("G", (), {})(); g.g = nx.DiGraph()
    g.g.add_node("acme.com", label="Host", subdomains_enumerated=True)
    g.g.add_node("s", label="Service", port=443); g.g.add_edge("acme.com", "s", edge_type="RUNS", port=443)
    g.g.add_node("https://acme.com/login.aspx", label="WebEndpoint", status=200, probed=True)
    g.g.add_edge("acme.com", "https://acme.com/login.aspx", edge_type="SERVES")
    cov = engagement_coverage(graph=g)
    assert "login_attempt" in {r["kind"] for r in cov["remaining"]}   # login page → must attempt login
    # recording a login attempt (session captured or exhausted) clears it
    g.g.nodes["acme.com"]["login_attempted"] = True
    cov2 = engagement_coverage(graph=g)
    assert "login_attempt" not in {r["kind"] for r in cov2["remaining"]}
