"""
Fleet Phase 3 — coordinator tests (no network, no LLM; injected workers + clock).

Covers: the full wave loop to a coverage fixpoint, evidence pooling growing the
frontier (a recon worker discovers a service -> new tasks appear -> get worked),
budget stops (waves/time), stuck-worker dead-lettering + HITL escalation, the
StuckDetector, parallel dispatch, and durable checkpoint/resume.

Run: python -m pytest tests/fleet/test_coordinator.py   (from syber-platform/)
"""
from __future__ import annotations

from syber.fleet.board import Board, InMemoryTaskStore, Task, TaskStatus
from syber.fleet.coordinator import (Coordinator, EngagementBudget, StuckDetector,
                                     WorkerResult)
from syber.fleet.planner import Planner
from syber.graph.store import KnowledgeGraph


def _fresh_graph() -> KnowledgeGraph:
    import syber.graph.store as store
    g = KnowledgeGraph()
    store._graph = g
    return g


# --------------------------------------------------------------------------- #
# StuckDetector
# --------------------------------------------------------------------------- #
def test_stuck_detector_repeated_action():
    sd = StuckDetector(window=3)
    assert sd.record("a", True) is False
    assert sd.record("a", True) is False
    assert sd.record("a", True) is True          # 3 identical actions -> stuck


def test_stuck_detector_no_progress():
    sd = StuckDetector(window=3)
    sd.record("a", False); sd.record("b", False)
    assert sd.record("c", False) is True         # window all no-progress -> stuck


def test_stuck_detector_healthy_stream_not_flagged():
    sd = StuckDetector(window=3)
    assert sd.record("a", True) is False
    assert sd.record("b", False) is False
    assert sd.record("c", True) is False         # varied + some progress -> ok


# --------------------------------------------------------------------------- #
# the wave loop
# --------------------------------------------------------------------------- #
def test_run_reaches_fixpoint_with_noop_worker():
    g = _fresh_graph()
    from syber.graph import model as M
    M.upsert_host("t.com")
    board = Board(store=InMemoryTaskStore(), graph=g)
    coord = Coordinator(board, Planner(board, graph=g), concurrency=1)
    out = coord.run()
    assert out["status"] == "complete" and out["done"] is True
    assert board.is_quiescent()


def test_evidence_pooling_grows_frontier():
    """A recon worker that writes a web service into the graph should cause new
    web_crawl / vuln_scan / injection tasks to appear and be worked — the pool +
    re-divide loop end to end."""
    g = _fresh_graph()
    from syber.graph import model as M
    M.upsert_host("t.com", ip="1.2.3.4")
    board = Board(store=InMemoryTaskStore(), graph=g)

    discovered = {"done": False}

    def worker(task: Task, board: Board, wid: str) -> WorkerResult:
        if task.kind == "service_scan" and not discovered["done"]:
            # simulate finding a web service + a parametered endpoint + a vuln
            M.upsert_service("t.com", 443, service="https")
            M.upsert_web_endpoint("t.com", "https://t.com/i?id=5", status=200, params=["id"])
            M.upsert_vulnerability("t.com", "CVE-9", severity="high", service_id="1.2.3.4:443")
            discovered["done"] = True
        return WorkerResult(status="done")

    coord = Coordinator(board, Planner(board, graph=g), worker=worker, concurrency=1)
    out = coord.run()
    assert out["status"] == "complete"
    ids = {t.id for t in board.store.list()}
    # frontier expanded from the single host as evidence was pooled
    assert "web_crawl:t.com" in ids
    assert "vuln_scan:t.com" in ids
    assert "test_access_control:https://t.com/i?id=5" in ids
    assert "exploit:CVE-9" in ids
    # everything got worked to terminal
    assert all(t.status in (TaskStatus.DONE,) for t in board.store.list())


def test_parallel_dispatch_many_hosts():
    g = _fresh_graph()
    from syber.graph import model as M
    for i in range(10):
        M.upsert_host(f"h{i}.com", ip=f"10.0.0.{i}")
    board = Board(store=InMemoryTaskStore(), graph=g)
    ran: list[str] = []
    import threading
    lk = threading.Lock()

    def worker(task, board, wid):
        with lk:
            ran.append(task.id)
        return WorkerResult(status="done")

    coord = Coordinator(board, Planner(board, graph=g), worker=worker, concurrency=8)
    out = coord.run()
    assert out["status"] == "complete"
    assert len(set(ran)) == len(ran)             # each task ran exactly once
    assert any(r.startswith("service_scan:") for r in ran)


# --------------------------------------------------------------------------- #
# budgets + stuck recovery
# --------------------------------------------------------------------------- #
def test_budget_max_waves_stops():
    g = _fresh_graph()
    from syber.graph import model as M
    M.upsert_host("t.com")
    board = Board(store=InMemoryTaskStore(), graph=g)

    # a worker that always fails-loops so the frontier never closes
    def worker(task, board, wid):
        return WorkerResult(status="failed", note="never finishes")

    # but cap attempts low so it would dead-letter; use max_waves to force the stop
    coord = Coordinator(board, Planner(board, graph=g), worker=worker, concurrency=1,
                        budget=EngagementBudget(max_waves=2, max_stall_waves=99))
    out = coord.run()
    assert out["status"] == "max_waves" and out["waves"] == 2


def test_failed_task_deadletters_and_calls_hitl():
    g = _fresh_graph()
    from syber.graph import model as M
    M.upsert_host("t.com")
    board = Board(store=InMemoryTaskStore(), graph=g)
    escalated: list[str] = []

    def worker(task, board, wid):
        return WorkerResult(status="failed", note="boom")

    coord = Coordinator(board, Planner(board, graph=g), worker=worker, concurrency=1,
                        hitl=lambda t: escalated.append(t.id),
                        budget=EngagementBudget(max_waves=50))
    out = coord.run()
    # service_scan:t.com fails 3x (default max_attempts) -> dead -> HITL
    assert "service_scan:t.com" in out["dead_lettered"]
    assert "service_scan:t.com" in escalated
    assert board.store.get("service_scan:t.com").status == TaskStatus.DEAD


def test_blocked_task_is_terminal_not_retried():
    g = _fresh_graph()
    from syber.graph import model as M
    M.upsert_host("t.com")
    board = Board(store=InMemoryTaskStore(), graph=g)

    def worker(task, board, wid):
        return WorkerResult(status="blocked", note="cloudflare 1020")

    coord = Coordinator(board, Planner(board, graph=g), worker=worker, concurrency=1)
    out = coord.run()
    t = board.store.get("service_scan:t.com")
    assert t.status == TaskStatus.BLOCKED and t.attempts == 1   # not retried


def test_looped_result_requeues_with_reflexion_note():
    g = _fresh_graph()
    from syber.graph import model as M
    M.upsert_host("t.com")
    board = Board(store=InMemoryTaskStore(), graph=g)
    calls = {"n": 0}

    def worker(task, board, wid):
        calls["n"] += 1
        if calls["n"] == 1:
            return WorkerResult(status="done", looped=True)   # first attempt loops
        return WorkerResult(status="done")                    # retry succeeds

    coord = Coordinator(board, Planner(board, graph=g), worker=worker, concurrency=1)
    out = coord.run()
    assert out["status"] == "complete"
    assert calls["n"] >= 2                                     # it was retried


# --------------------------------------------------------------------------- #
# durable checkpoint / resume
# --------------------------------------------------------------------------- #
def test_checkpoint_and_resume(tmp_path):
    g = _fresh_graph()
    from syber.graph import model as M
    for i in range(4):
        M.upsert_host(f"h{i}.com")
    board = Board(store=InMemoryTaskStore(), graph=g)
    cp = str(tmp_path / "run.json")

    # run 1: stop early via budget so the engagement is left mid-flight
    coord = Coordinator(board, Planner(board, graph=g), concurrency=1,
                        checkpoint_path=cp, budget=EngagementBudget(max_waves=1,
                                                                    max_stall_waves=99))
    out1 = coord.run()
    assert out1["status"] == "max_waves"

    import os
    assert os.path.isfile(cp)

    # run 2: a brand-new coordinator + empty board restores from the checkpoint and finishes
    board2 = Board(store=InMemoryTaskStore(), graph=g)
    coord2 = Coordinator(board2, Planner(board2, graph=g), concurrency=1,
                         checkpoint_path=cp, budget=EngagementBudget(max_waves=50))
    out2 = coord2.run()
    assert out2["status"] == "complete"
    # the resumed run preserved the wave counter from before the crash
    assert out2["waves"] >= 1
    assert board2.is_quiescent()


def test_per_call_budget_resets_each_call_until_done():
    """A per-call time budget must NOT be cumulative: each run() call gets a fresh
    window, so resuming continues instead of instantly expiring. (If the budget were
    measured from the original started_at, the 2nd call would stop immediately and the
    engagement would never finish — this loop would hit the cap without done=True.)"""
    g = _fresh_graph()
    from syber.graph import model as M
    from syber.fleet.persistence import PersistencePolicy
    M.upsert_host("t.com", ip="1.2.3.4")
    board = Board(store=InMemoryTaskStore(), graph=g)
    tick = {"t": 0.0}

    def worker(task, board, wid):
        tick["t"] += 1.0                              # every unit of work advances the clock
        if task.kind == "service_scan":
            M.upsert_service("t.com", 443, service="https")
        return WorkerResult(status="done")

    statuses = []
    saw_resumable = False
    for _ in range(30):
        coord = Coordinator(board, Planner(board, graph=g), worker=worker, concurrency=1,
                            budget=EngagementBudget(max_seconds=1.0, max_waves=1000),
                            persistence=PersistencePolicy(), clock=lambda: tick["t"])
        out = coord.run()
        statuses.append(out["status"])
        if out.get("resumable"):
            saw_resumable = True
            assert out["done"] is False                 # resumable implies not done
        if out["done"]:
            break

    assert any(s == "max_seconds" for s in statuses)    # the per-call bound did trigger
    assert saw_resumable                                # and at least one stop was resumable
    assert statuses[-1] in ("complete", "found")         # and we still finished (resume works)
    assert board.is_quiescent()


def test_checkpoint_state_roundtrips():
    g = _fresh_graph()
    from syber.graph import model as M
    M.upsert_host("t.com")
    board = Board(store=InMemoryTaskStore(), graph=g)
    board.materialize_frontier()
    coord = Coordinator(board, Planner(board, graph=g))
    snap = coord.checkpoint_state()
    board2 = Board(store=InMemoryTaskStore(), graph=g)
    board2.store.restore(snap["tasks"])
    assert {t.id for t in board2.store.list()} == {t.id for t in board.store.list()}
