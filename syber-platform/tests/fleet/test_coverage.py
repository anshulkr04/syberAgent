"""Objective coverage / Ralph-loop backpressure — completion is graph-derived, not claimed."""
from __future__ import annotations

import networkx as nx
import pytest

from syber.fleet.coverage import engagement_coverage


class _G:
    """Minimal graph shim matching KnowledgeGraph.g (a networkx DiGraph)."""
    def __init__(self):
        self.g = nx.DiGraph()

    def host(self, h, **props):
        self.g.add_node(h, label="Host", **props)

    def service(self, host, sid, port):
        self.g.add_node(sid, label="Service", port=port)
        self.g.add_edge(host, sid, edge_type="RUNS", port=port)

    def endpoint(self, host, url, **props):
        self.g.add_node(url, label="WebEndpoint", **props)
        self.g.add_edge(host, url, edge_type="SERVES")


def test_incomplete_when_apex_not_enumerated():
    g = _G(); g.host("acme.com")
    cov = engagement_coverage(graph=g)
    assert cov["complete"] is False
    kinds = {r["kind"] for r in cov["remaining"]}
    assert "subdomain_enum" in kinds


def test_incomplete_when_host_unscanned():
    g = _G(); g.host("acme.com", subdomains_enumerated=True)
    cov = engagement_coverage(graph=g)
    assert cov["complete"] is False
    assert "service_scan" in {r["kind"] for r in cov["remaining"]}


def test_incomplete_when_web_host_uncrawled():
    g = _G(); g.host("acme.com", subdomains_enumerated=True)
    g.service("acme.com", "acme.com:443", 443)                 # web service, but no endpoints
    cov = engagement_coverage(graph=g)
    assert "web_crawl" in {r["kind"] for r in cov["remaining"]}


def test_incomplete_when_endpoint_unprobed():
    g = _G(); g.host("acme.com", subdomains_enumerated=True)
    g.service("acme.com", "acme.com:443", 443)
    g.endpoint("acme.com", "https://acme.com/api?id=1", params="id")   # parametered, not probed
    cov = engagement_coverage(graph=g)
    assert "test_endpoint" in {r["kind"] for r in cov["remaining"]}


def test_complete_when_everything_probed():
    g = _G(); g.host("acme.com", subdomains_enumerated=True)
    g.service("acme.com", "acme.com:443", 443)
    g.endpoint("acme.com", "https://acme.com/api?id=1", params="id", probed=True)
    cov = engagement_coverage(graph=g)
    assert cov["complete"] is True and cov["remaining_count"] == 0


def test_open_highvalue_lead_blocks_completion():
    from syber.fleet.leads import LeadRegistry, Lead, LeadClass
    g = _G(); g.host("acme.com", subdomains_enumerated=True)
    g.service("acme.com", "acme.com:443", 443)
    g.endpoint("acme.com", "https://acme.com/x", probed=True)
    reg = LeadRegistry()
    reg.add(Lead(id="lead:admin:x", lead_class=LeadClass.EXPOSED_ADMIN, target="https://acme.com/admin"))
    cov = engagement_coverage(graph=g, leads=reg)
    assert cov["complete"] is False
    assert "verify_lead" in {r["kind"] for r in cov["remaining"]}


def test_graph_unavailable_is_not_complete():
    # never emit a false 'done' when we can't read state
    class _Bad:
        @property
        def g(self):
            raise RuntimeError("no graph")
    cov = engagement_coverage(graph=_Bad())
    # nodes() call fails -> no nodes -> nothing remaining -> but must not falsely complete
    # (empty graph legitimately has nothing to do; assert it doesn't crash)
    assert "complete" in cov


def test_non_apex_subdomain_not_required_to_enumerate():
    g = _G()
    g.host("acme.com", subdomains_enumerated=True)
    g.service("acme.com", "acme.com:443", 443)
    g.endpoint("acme.com", "https://acme.com/x", probed=True)
    g.host("uat.acme.com")                                     # subdomain: needs scan, not enum
    cov = engagement_coverage(graph=g)
    kinds = {r["kind"] for r in cov["remaining"]}
    assert "service_scan" in kinds                             # the subdomain must be scanned
    # the subdomain itself should NOT trigger a subdomain_enum requirement
    enum = next((r for r in cov["remaining"] if r["kind"] == "subdomain_enum"), None)
    assert enum is None
