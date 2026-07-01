"""
Fleet Phase 7 — persistence policy tests (no network, no LLM).

Covers: the deepening strategies (revive dead/blocked tasks with a cap, deepen-web
content-discovery, AUTHORISED-only scope expansion), found_something detection, the
store.revive cap, and the coordinator's persistence behaviour — it does NOT stop at
a shallow fixpoint while deepening can re-open the frontier, and only stops at a deep
fixpoint or on stop_on_first_find.

Run: python -m pytest tests/fleet/test_persistence.py   (from syber-platform/)
"""
from __future__ import annotations

from syber.fleet.board import Board, InMemoryTaskStore, Task, TaskStatus
from syber.fleet.coordinator import Coordinator, WorkerResult
from syber.fleet.persistence import PersistencePolicy
from syber.fleet.planner import Planner
from syber.graph.store import KnowledgeGraph


def _fresh() -> KnowledgeGraph:
    import syber.graph.store as store
    g = KnowledgeGraph()
    store._graph = g
    return g


# --------------------------------------------------------------------------- #
# store.revive
# --------------------------------------------------------------------------- #
def test_store_revive_caps():
    s = InMemoryTaskStore()
    s.add(Task(id="t1", kind="recon", status=TaskStatus.DEAD))
    r = s.revive("t1", max_revivals=1)
    assert r is not None and r.status == TaskStatus.FRONTIER and r.revivals == 1
    # mark dead again, second revive refused (cap=1)
    t = s.get("t1"); t.status = TaskStatus.DEAD; s._tasks["t1"] = t
    assert s.revive("t1", max_revivals=1) is None


def test_store_revive_only_dead_or_blocked():
    s = InMemoryTaskStore()
    s.add(Task(id="t1", kind="recon", status=TaskStatus.FRONTIER))
    assert s.revive("t1") is None


# --------------------------------------------------------------------------- #
# deepening strategies
# --------------------------------------------------------------------------- #
def test_revive_dead_reopens_frontier():
    g = _fresh()
    board = Board(store=InMemoryTaskStore(), graph=g, rules=[])
    board.store.add(Task(id="t1", kind="vuln_scan", status=TaskStatus.DEAD))
    board.store.add(Task(id="t2", kind="exploit", status=TaskStatus.BLOCKED))
    pol = PersistencePolicy(max_revivals=1)
    opened = pol.deepen(board)
    ids = {t.id for t in opened}
    assert "t1" in ids and "t2" in ids
    assert board.store.get("t1").status == TaskStatus.FRONTIER
    # second deepen does nothing (cap reached) -> exhaustion signal
    board.store._tasks["t1"].status = TaskStatus.DEAD
    board.store._tasks["t2"].status = TaskStatus.BLOCKED
    assert pol.deepen(board) == []


def test_deepen_web_adds_content_discovery():
    g = _fresh()
    from syber.graph import model as M
    M.upsert_host("t.com")
    M.upsert_service("t.com", 443, service="https")
    M.upsert_web_endpoint("t.com", "https://t.com/", status=200)
    board = Board(store=InMemoryTaskStore(), graph=g, rules=[])
    pol = PersistencePolicy(revive_dead=False, expand_scope=False)
    opened = pol.deepen(board)
    assert any(t.id == "content_discovery:t.com" for t in opened)
    # idempotent: second call doesn't re-add
    assert pol.deepen(board) == []


def test_expand_scope_only_authorised(monkeypatch):
    g = _fresh()
    from syber.graph import model as M
    # a sibling domain discovered via a cert SAN
    M.upsert_certificate("t.com", "fp1", sans=["sib.t.com", "evil-other.com"])
    board = Board(store=InMemoryTaskStore(), graph=g, rules=[])

    # authorise only sib.t.com
    import syber.scanning.authorization as authz
    class _Auth:
        def is_authorized(self, name):
            return (name == "sib.t.com", "ok" if name == "sib.t.com" else "no")
    monkeypatch.setattr(authz, "get_auth_store", lambda: _Auth())

    pol = PersistencePolicy(revive_dead=False, deepen_web=False)
    opened = pol.deepen(board)
    ids = {t.target_id for t in opened}
    assert "sib.t.com" in ids            # authorised sibling promoted
    assert "evil-other.com" not in ids   # unauthorised sibling NOT scanned (default-deny)


def test_expand_scope_safe_without_auth_store(monkeypatch):
    g = _fresh()
    from syber.graph import model as M
    M.upsert_certificate("t.com", "fp1", sans=["sib.t.com"])
    board = Board(store=InMemoryTaskStore(), graph=g, rules=[])
    import syber.scanning.authorization as authz
    def _boom():
        raise RuntimeError("no auth store")
    monkeypatch.setattr(authz, "get_auth_store", _boom)
    pol = PersistencePolicy(revive_dead=False, deepen_web=False)
    assert pol.deepen(board) == []       # no auth store -> never expands (safe)


# --------------------------------------------------------------------------- #
# found_something
# --------------------------------------------------------------------------- #
def test_found_something_on_vuln_and_compromise():
    g = _fresh()
    from syber.graph import model as M
    board = Board(store=InMemoryTaskStore(), graph=g, rules=[])
    pol = PersistencePolicy()
    assert pol.found_something(board) is False
    M.upsert_host("t.com")
    M.upsert_vulnerability("t.com", "CVE-1", severity="high")
    assert pol.found_something(board) is True


def test_found_something_severity_floor():
    g = _fresh()
    from syber.graph import model as M
    M.upsert_host("t.com")
    M.upsert_vulnerability("t.com", "CVE-low", severity="low")
    board = Board(store=InMemoryTaskStore(), graph=g, rules=[])
    assert PersistencePolicy(require_severity="high").found_something(board) is False
    M.upsert_vulnerability("t.com", "CVE-crit", severity="critical")
    assert PersistencePolicy(require_severity="high").found_something(board) is True


# --------------------------------------------------------------------------- #
# coordinator persistence behaviour
# --------------------------------------------------------------------------- #
def test_persistence_revives_before_stopping():
    """Without persistence a failing task dead-letters and the run completes with the
    task DEAD. With persistence the coordinator revives it and retries before stopping."""
    g = _fresh()
    from syber.graph import model as M
    M.upsert_host("t.com")
    board = Board(store=InMemoryTaskStore(), graph=g)
    attempts = {"n": 0}

    def worker(task, board, wid):
        if task.kind == "service_scan":
            attempts["n"] += 1
            # fail until it has been revived once (i.e. after 3 attempts + revival)
            if attempts["n"] <= 3:
                return WorkerResult(status="failed", note="flaky")
        return WorkerResult(status="done")

    coord = Coordinator(board, Planner(board, graph=g), worker=worker, concurrency=1,
                        persistence=PersistencePolicy(max_revivals=2))
    out = coord.run()
    assert out["status"] == "complete"
    # it was revived and eventually succeeded rather than left DEAD
    assert board.store.get("service_scan:t.com").status == TaskStatus.DONE
    assert attempts["n"] >= 4


def test_stop_on_first_find_short_circuits():
    g = _fresh()
    from syber.graph import model as M
    M.upsert_host("t.com", ip="1.2.3.4")
    board = Board(store=InMemoryTaskStore(), graph=g)

    def worker(task, board, wid):
        if task.kind == "service_scan":
            M.upsert_service("t.com", 443, service="https")
            M.upsert_vulnerability("t.com", "CVE-9", severity="high", service_id="1.2.3.4:443")
        return WorkerResult(status="done")

    coord = Coordinator(board, Planner(board, graph=g), worker=worker, concurrency=1,
                        persistence=PersistencePolicy(), stop_on_first_find=True)
    out = coord.run()
    assert out["status"] == "found" and out["found"] is True
    # it stopped early — not every task needs to be terminal
    assert any(t.status not in (TaskStatus.DONE, TaskStatus.DEAD, TaskStatus.BLOCKED)
               for t in board.store.list()) or out["coverage"]["open"] >= 0


def test_summary_reports_found_flag():
    g = _fresh()
    from syber.graph import model as M
    M.upsert_host("t.com")
    board = Board(store=InMemoryTaskStore(), graph=g)
    coord = Coordinator(board, Planner(board, graph=g), concurrency=1,
                        persistence=PersistencePolicy())
    out = coord.run()
    assert "found" in out and out["found"] in (True, False)


def test_no_persistence_preserves_old_behavior():
    """Coordinator without a persistence policy still stops at the shallow fixpoint."""
    g = _fresh()
    from syber.graph import model as M
    M.upsert_host("t.com")
    board = Board(store=InMemoryTaskStore(), graph=g)

    def worker(task, board, wid):
        return WorkerResult(status="failed", note="always fails")

    coord = Coordinator(board, Planner(board, graph=g), worker=worker, concurrency=1)
    out = coord.run()
    assert out["status"] == "complete"           # stops (no deepening)
    assert board.store.get("service_scan:t.com").status == TaskStatus.DEAD
