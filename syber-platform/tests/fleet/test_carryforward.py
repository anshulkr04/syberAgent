"""Cross-pass carry-forward: persistent recall ledger + engagement digest."""
from __future__ import annotations

import networkx as nx

from syber.scanning.recall import CallLedger
from syber.fleet.coverage import engagement_digest


# --- persistent recall ledger (survives a fresh 'pass' = new object) --------- #
def test_recall_persists_across_instances(tmp_path):
    path = str(tmp_path / "recall.json")
    l1 = CallLedger(path=path)
    l1.record("syber_http_request", {"url": "https://x/api/a"}, summary="200", status="ok")
    l1.record("syber_crawl", {"target": "x"}, summary="endpoints=5", status="ok")

    # a NEW ledger (simulating the next --rm pass) loads the prior calls from disk
    l2 = CallLedger(path=path)
    assert l2.seen("syber_http_request", {"url": "https://x/api/a"}) is True
    assert l2.seen("syber_crawl", {"target": "x"}) is True
    assert l2.seen("syber_http_request", {"url": "https://x/api/NEVER"}) is False


def test_recall_dedup_count_carries(tmp_path):
    path = str(tmp_path / "recall.json")
    CallLedger(path=path).record("t", {"url": "u"})
    l2 = CallLedger(path=path)
    rec = l2.record("t", {"url": "u"})          # same call again, next pass
    assert rec.count == 2                        # count carried forward, not reset


def test_recall_persistence_disabled_with_empty_path(monkeypatch):
    monkeypatch.setenv("SYBER_RECALL_PATH", "")
    from syber.scanning import recall
    assert recall._default_path() is None


# --- engagement digest carries prior findings/leads/remaining --------------- #
class _G:
    def __init__(self):
        self.g = nx.DiGraph()


def test_digest_lists_findings_and_remaining():
    g = _G()
    g.g.add_node("acme.com", label="Host", subdomains_enumerated=True)
    g.g.add_node("acme.com:443", label="Service", port=443)
    g.g.add_edge("acme.com", "acme.com:443", edge_type="RUNS", port=443)
    g.g.add_node("uat.acme.com", label="Host")          # unscanned -> remaining
    g.g.add_node("F1", label="Finding", severity="CRITICAL", summary="Unauth data exposure")
    d = engagement_digest(graph=g)
    assert "Carry-forward" in d
    assert "Unauth data exposure" in d                   # prior finding carried
    assert "Remaining THIS pass" in d
    assert "service_scan" in d                           # uat host still to scan
    assert "uat.acme.com" in d


def test_digest_marks_exhausted_leads():
    from syber.fleet.leads import LeadRegistry, Lead, LeadClass, LeadState
    g = _G()
    g.g.add_node("acme.com", label="Host", subdomains_enumerated=True)
    g.g.add_node("s", label="Service", port=443)
    g.g.add_edge("acme.com", "s", edge_type="RUNS", port=443)
    g.g.add_node("https://acme.com/x", label="WebEndpoint", probed=True)
    g.g.add_edge("acme.com", "https://acme.com/x", edge_type="SERVES")
    reg = LeadRegistry()
    lead = reg.add(Lead(id="lead:cve:x", lead_class=LeadClass.VERSION_CVE, target="x"))
    lead.state = LeadState.EXHAUSTED
    lead.reflections = ["[cve_verify] template did not fire"]
    d = engagement_digest(graph=g, leads=reg)
    assert "EXHAUSTED" in d and "do not retry" in d
    assert "lead:cve:x" in d
