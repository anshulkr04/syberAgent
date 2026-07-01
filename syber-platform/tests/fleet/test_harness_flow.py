"""
Fleet Phase 5 — harness-driven flow tests (no network, no LLM, no fastmcp).

The MCP fleet tools (syber_fleet_plan_wave / next_task / complete) are thin wrappers
over the Board + specialists. fastmcp isn't importable on the host, so this test
replicates the EXACT call sequence those tools perform and proves the interactive,
multi-subagent flow works: plan a wave, have several "subagents" each claim a
distinct task (atomic — no double-claim), receive their specialist prompt, do work
that writes to the graph, complete, and watch the frontier grow to a fixpoint.

Run: python -m pytest tests/fleet/test_harness_flow.py   (from syber-platform/)
"""
from __future__ import annotations

import threading

from syber.fleet.board import Board, InMemoryTaskStore, TaskStatus
from syber.fleet.planner import Planner
from syber.fleet.specialists import specialist_for, specialist_system_prompt
from syber.graph.store import KnowledgeGraph


def _fresh():
    import syber.graph.store as store
    g = KnowledgeGraph()
    store._graph = g
    return g


# -- the exact logic the MCP tools run, factored so the test mirrors them ----- #
def _next_task(board: Board, worker_id: str, kinds=None):
    """Mirror of syber_fleet_next_task."""
    board.materialize_frontier()
    t = board.claim_next(worker_id, kinds=kinds)
    if t is None:
        return None
    board.start(t.id, worker_id)
    spec = specialist_for(t.kind)
    peers = [specialist_for(x.kind).name
             for x in board.store.list(status=TaskStatus.IN_PROGRESS)
             if x.id != t.id and specialist_for(x.kind)]
    prompt = specialist_system_prompt(spec, peer_names=peers) if spec else ""
    return {"task": t, "specialist": spec.name if spec else None, "prompt": prompt}


def _complete(board: Board, task_id: str, worker_id: str, status="done"):
    """Mirror of syber_fleet_complete."""
    if status == "done":
        ok = board.complete(task_id, worker_id)
    elif status == "blocked":
        ok = board.block(task_id, worker_id)
    else:
        ok = board.fail(task_id, worker_id) is not None
    board.materialize_frontier()
    return ok


# --------------------------------------------------------------------------- #
def test_plan_wave_returns_disjoint_batch():
    g = _fresh()
    from syber.graph import model as M
    for i in range(5):
        M.upsert_host(f"h{i}.com", ip=f"10.0.0.{i}")
    board = Board(store=InMemoryTaskStore(), graph=g)
    planner = Planner(board, graph=g)
    board.materialize_frontier()
    wave = planner.next_batch(max_size=6)
    hosts = [st.host for st in wave]
    assert len(hosts) == len(set(hosts)) and len(wave) >= 4


def test_next_task_returns_specialist_prompt_with_peers():
    g = _fresh()
    from syber.graph import model as M
    M.upsert_host("t.com", ip="1.2.3.4")
    M.upsert_service("t.com", 443, service="https")
    M.upsert_web_endpoint("t.com", "https://t.com/i?id=5", status=200, params=["id"])
    board = Board(store=InMemoryTaskStore(), graph=g)
    # one worker already on an injection task...
    board.materialize_frontier()
    board.store.claim("test_injection:https://t.com/i?id=5", "w0", ttl=100, now=1.0)
    board.store.start("test_injection:https://t.com/i?id=5", "w0")
    # ...a second worker claims the access-control task and should see the peer
    got = _next_task(board, "w1", kinds=["test_access_control"])
    assert got and got["specialist"] == "idor-bola"
    assert "do not duplicate" in got["prompt"].lower()


def test_two_subagents_never_get_the_same_task():
    g = _fresh()
    from syber.graph import model as M
    M.upsert_host("t.com")
    board = Board(store=InMemoryTaskStore(), graph=g)
    a = _next_task(board, "wA")
    b = _next_task(board, "wB")
    # only one service_scan task exists -> exactly one worker gets it
    assert a is not None
    if b is not None:
        assert a["task"].id != b["task"].id


def test_interactive_flow_reaches_fixpoint():
    """Simulate the lead repeatedly planning waves and N subagents working them, each
    writing discoveries to the graph — until the frontier drains."""
    g = _fresh()
    from syber.graph import model as M
    M.upsert_host("t.com", ip="1.2.3.4")
    board = Board(store=InMemoryTaskStore(), graph=g)

    def do_work(task):
        if task.kind == "service_scan":
            M.upsert_service("t.com", 443, service="https")
        elif task.kind == "web_crawl":
            M.upsert_web_endpoint("t.com", "https://t.com/i?id=5", status=200, params=["id"])
        elif task.kind == "vuln_scan":
            M.upsert_vulnerability("t.com", "CVE-3", severity="high", service_id="1.2.3.4:443")
        # injection / access_control / exploit: no graph growth

    board.materialize_frontier()        # the lead's first plan_wave/next_task seeds the frontier
    guard = 0
    while not board.is_quiescent() and guard < 100:
        guard += 1
        got = _next_task(board, f"w{guard}")
        if got is None:
            board.materialize_frontier()
            if board.is_quiescent():
                break
            continue
        task = got["task"]
        if task.kind in ("exploit", "priv_esc", "lateral"):
            _complete(board, task.id, f"w{guard}", status="blocked")   # park for real agent
        else:
            do_work(task)
            _complete(board, task.id, f"w{guard}", status="done")

    ids = {t.id for t in board.store.list()}
    assert "web_crawl:t.com" in ids and "vuln_scan:t.com" in ids
    assert "test_access_control:https://t.com/i?id=5" in ids
    assert board.is_quiescent()


def test_concurrent_subagents_claim_safely():
    g = _fresh()
    from syber.graph import model as M
    for i in range(50):
        M.upsert_host(f"h{i}.com", ip=f"10.0.0.{i}")
    board = Board(store=InMemoryTaskStore(), graph=g)
    board.materialize_frontier()
    claimed: dict[str, int] = {}
    lock = threading.Lock()

    def subagent(wid: str):
        while True:
            got = _next_task(board, wid)
            if got is None:
                return
            with lock:
                claimed[got["task"].id] = claimed.get(got["task"].id, 0) + 1
            _complete(board, got["task"].id, wid, status="done")

    threads = [threading.Thread(target=subagent, args=(f"w{k}",)) for k in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # every claimed task was handed out exactly once
    assert claimed and all(v == 1 for v in claimed.values())
