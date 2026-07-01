"""
Fleet Phase 6 — attack-graph reachability layer tests (no network).

Covers the MulVAL-style upgrade: CAN_REACH edges + host access-state, the
netAccess derivation (compromising a host makes its CAN_REACH neighbours
reachable), the store query helpers, and the fleet's lateral-movement frontier
rule (a foothold spawns lateral tasks that the planner/coordinator then work).

Run: python -m pytest tests/fleet/test_reachability.py   (from syber-platform/)
"""
from __future__ import annotations

from syber.fleet.board import Board, InMemoryTaskStore
from syber.fleet.coordinator import Coordinator, WorkerResult
from syber.fleet.planner import Planner
from syber.graph.store import KnowledgeGraph


def _fresh() -> KnowledgeGraph:
    import syber.graph.store as store
    g = KnowledgeGraph()
    store._graph = g
    return g


class _AllowAuth:
    """Fake auth store: authorises a fixed set of hosts (keeps the lateral rule's
    scope check deterministic + network-free)."""
    def __init__(self, allowed):
        self.allowed = set(allowed)

    def is_authorized(self, host):
        return (host in self.allowed, "ok" if host in self.allowed else "denied")


def _authorize(monkeypatch, *hosts):
    import syber.scanning.authorization as authz
    monkeypatch.setattr(authz, "get_auth_store", lambda: _AllowAuth(hosts))


# --------------------------------------------------------------------------- #
# model: state + reachability + derivation
# --------------------------------------------------------------------------- #
def test_set_host_state():
    g = _fresh()
    from syber.graph import model as M
    M.upsert_host("a.com")
    M.set_host_state("a.com", discovered=True, access="user", value=5.0)
    d = g.g.nodes["a.com"]
    assert d["discovered"] is True and d["access"] == "user" and d["value"] == 5.0


def test_invalid_access_level_ignored():
    g = _fresh()
    from syber.graph import model as M
    M.upsert_host("a.com")
    M.set_host_state("a.com", access="superuser")     # not a valid level
    assert "access" not in g.g.nodes["a.com"]


def test_upsert_reachability_marks_dst_reachable():
    g = _fresh()
    from syber.graph import model as M
    M.upsert_host("a.com")
    M.upsert_reachability("a.com", "b.com", port=445)
    assert g.reachable_from("a.com") == ["b.com"]
    assert g.g.nodes["b.com"]["reachable"] is True
    assert g.g.nodes["b.com"]["discovered"] is True


def test_mark_compromised_derives_netaccess():
    g = _fresh()
    from syber.graph import model as M
    M.upsert_host("a.com")
    M.upsert_reachability("a.com", "b.com")
    M.upsert_reachability("a.com", "c.com")
    derived = M.mark_compromised("a.com", access="root")
    assert set(derived) == {"b.com", "c.com"}
    assert g.g.nodes["a.com"]["compromised"] is True and g.g.nodes["a.com"]["access"] == "root"
    # b and c are now the lateral frontier (reachable, not compromised)
    assert set(g.lateral_frontier()) == {"b.com", "c.com"}
    assert g.compromised_hosts() == ["a.com"]


def test_already_compromised_neighbour_not_in_derived():
    g = _fresh()
    from syber.graph import model as M
    M.upsert_reachability("a.com", "b.com")
    M.mark_compromised("b.com")                       # b already owned
    derived = M.mark_compromised("a.com")
    assert "b.com" not in derived


# --------------------------------------------------------------------------- #
# fleet: lateral-movement frontier rule
# --------------------------------------------------------------------------- #
def test_lateral_rule_inert_without_foothold():
    g = _fresh()
    from syber.graph import model as M
    M.upsert_host("a.com")
    M.upsert_reachability("a.com", "b.com")           # reachable but no foothold yet
    board = Board(store=InMemoryTaskStore(), graph=g)
    board.materialize_frontier()
    assert not any(t.kind == "lateral" for t in board.store.list())


def test_lateral_rule_fires_after_compromise(monkeypatch):
    g = _fresh()
    from syber.graph import model as M
    M.upsert_host("a.com")
    M.upsert_reachability("a.com", "b.com")
    M.upsert_reachability("a.com", "c.com")
    M.mark_compromised("a.com")
    _authorize(monkeypatch, "a.com", "b.com", "c.com")     # neighbours in scope
    board = Board(store=InMemoryTaskStore(), graph=g)
    board.materialize_frontier()
    lateral = {t.id for t in board.store.list() if t.kind == "lateral"}
    assert "lateral:a.com->b.com" in lateral
    assert "lateral:a.com->c.com" in lateral


def test_lateral_rule_skips_out_of_scope_neighbour(monkeypatch):
    """A reachable neighbour that is NOT authorised gets NO lateral task — movement
    never expands scope (the CAN_REACH lead is still recorded in the graph)."""
    g = _fresh()
    from syber.graph import model as M
    M.upsert_host("a.com")
    M.upsert_reachability("a.com", "in-scope.com")
    M.upsert_reachability("a.com", "out-of-scope.com")
    M.mark_compromised("a.com")
    _authorize(monkeypatch, "a.com", "in-scope.com")       # out-of-scope.com NOT authorised
    board = Board(store=InMemoryTaskStore(), graph=g)
    board.materialize_frontier()
    lateral = {t.id for t in board.store.list() if t.kind == "lateral"}
    assert "lateral:a.com->in-scope.com" in lateral
    assert "lateral:a.com->out-of-scope.com" not in lateral
    # the reachability lead is still recorded for the analyst
    assert "out-of-scope.com" in g.reachable_from("a.com")


def test_compromise_during_run_opens_lateral_frontier(monkeypatch):
    """End-to-end: a worker that compromises a host mid-run should cause the fleet to
    discover and work the newly-reachable neighbour (the attack path extends live)."""
    g = _fresh()
    from syber.graph import model as M
    M.upsert_host("a.com", ip="10.0.0.1")
    M.upsert_reachability("a.com", "b.com")
    _authorize(monkeypatch, "a.com", "b.com")              # both in scope
    board = Board(store=InMemoryTaskStore(), graph=g)

    def worker(task, board, wid):
        if task.kind == "service_scan" and task.target_id == "a.com":
            M.mark_compromised("a.com")               # foothold -> b.com becomes reachable
        return WorkerResult(status="done")

    coord = Coordinator(board, Planner(board, graph=g), worker=worker, concurrency=2)
    out = coord.run()
    assert out["status"] == "complete"
    ids = {t.id for t in board.store.list()}
    # b.com got discovered, scanned, AND a lateral task was created and worked
    assert "service_scan:b.com" in ids
    assert "lateral:a.com->b.com" in ids
    assert board.is_quiescent()
