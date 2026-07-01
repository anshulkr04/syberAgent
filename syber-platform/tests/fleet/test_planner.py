"""
Fleet Phase 2 — planner tests (no network, no LLM).

Covers: owning-host resolution across task kinds, expected-value scoring (severity,
risk, info-gain, cost, attempts penalty), rank_frontier writing priorities back,
disjoint-by-host batching, phase-aware wave sizing (fan-out reads / serialize
writes), and the read-before-write phase inference.

Run: python -m pytest tests/fleet/test_planner.py   (from syber-platform/)
"""
from __future__ import annotations

from syber.fleet.board import Board, InMemoryTaskStore, Task, TaskStatus
from syber.fleet.planner import (READ_KINDS, WRITE_KINDS, Planner, PlannerWeights,
                                 _owning_host)
from syber.graph.store import KnowledgeGraph


def _graph() -> KnowledgeGraph:
    from syber.graph import model as M
    import syber.graph.store as store
    g = KnowledgeGraph()
    store._graph = g
    M.upsert_host("t.com", ip="1.2.3.4")
    M.upsert_service("t.com", 443, service="https")
    M.upsert_web_endpoint("t.com", "https://t.com/i?id=5", status=200, params=["id"])
    M.upsert_vulnerability("t.com", "CVE-1", severity="critical", service_id="1.2.3.4:443")
    return g


def _board(g) -> Board:
    return Board(store=InMemoryTaskStore(), graph=g)


# --------------------------------------------------------------------------- #
# owning-host resolution
# --------------------------------------------------------------------------- #
def test_owning_host_direct_and_indirect():
    g = _graph()
    assert _owning_host(g, "t.com") == "t.com"                       # host itself
    assert _owning_host(g, "https://t.com/i?id=5") == "t.com"        # via SERVES
    assert _owning_host(g, "CVE-1") == "t.com"                       # via service->host


# --------------------------------------------------------------------------- #
# scoring
# --------------------------------------------------------------------------- #
def test_scoring_includes_breakdown_and_costs():
    g = _graph()
    board = _board(g)
    board.materialize_frontier()
    planner = Planner(board, graph=g)
    ctx = planner._context()
    t = board.store.get("service_scan:t.com")
    st = planner.score_task(t, ctx)
    assert st.host == "t.com"
    assert st.breakdown["info_gain"] > 0      # scans carry info-gain
    assert st.breakdown["cost"] < 0           # cost is subtracted
    assert "risk" in st.breakdown


def test_attempts_penalty_lowers_score():
    g = _graph()
    board = _board(g)
    planner = Planner(board, graph=g)
    ctx = planner._context()
    fresh = Task(id="recon:a", kind="recon", target_id="t.com")
    tired = Task(id="recon:b", kind="recon", target_id="t.com", attempts=3)
    s_fresh = planner.score_task(fresh, ctx).score
    s_tired = planner.score_task(tired, ctx).score
    assert s_tired < s_fresh


def test_exploit_uses_severity_weight():
    g = _graph()
    board = _board(g)
    planner = Planner(board, graph=g)
    ctx = planner._context()
    crit = planner.score_task(Task(id="exploit:CVE-1", kind="exploit", target_id="CVE-1"), ctx)
    assert crit.breakdown["severity"] > 0     # critical vuln => severity term contributes


# --------------------------------------------------------------------------- #
# rank_frontier writes priorities back
# --------------------------------------------------------------------------- #
def test_rank_frontier_writes_priority_back():
    g = _graph()
    board = _board(g)
    board.materialize_frontier()
    planner = Planner(board, graph=g)
    ranked = planner.rank_frontier()
    assert ranked and ranked == sorted(ranked, key=lambda s: s.score, reverse=True)
    # the board task now carries the computed priority
    top = ranked[0]
    assert board.store.get(top.task.id).priority == top.score


# --------------------------------------------------------------------------- #
# batching: disjoint by host + phase-aware size
# --------------------------------------------------------------------------- #
def _multi_host_board() -> Board:
    from syber.graph import model as M
    import syber.graph.store as store
    g = KnowledgeGraph()
    store._graph = g
    for i in range(6):
        h = f"h{i}.com"
        M.upsert_host(h, ip=f"10.0.0.{i}")
        M.upsert_service(h, 443, service="https")
    return Board(store=InMemoryTaskStore(), graph=g)


def test_next_batch_disjoint_by_host():
    board = _multi_host_board()
    board.materialize_frontier()
    planner = Planner(board, graph=board.graph)
    batch = planner.next_batch(phase="read")
    hosts = [st.host for st in batch]
    assert len(hosts) == len(set(hosts))         # one task per host, no host twice


def test_read_phase_fans_out_write_phase_serializes():
    board = _multi_host_board()
    board.materialize_frontier()
    w = PlannerWeights(max_parallel_read=8, max_parallel_write=2)
    planner = Planner(board, graph=board.graph, weights=w)
    read_batch = planner.next_batch(phase="read")
    assert len(read_batch) >= 4                   # fans out across the 6 hosts
    assert all(st.task.kind in READ_KINDS for st in read_batch)

    # add exploit (write) tasks on distinct hosts
    for i in range(6):
        board.store.add(Task(id=f"exploit:h{i}", kind="exploit", target_id=f"h{i}.com"))
    write_batch = planner.next_batch(phase="write")
    assert len(write_batch) <= 2                  # serialize writes (capped)
    assert all(st.task.kind in WRITE_KINDS for st in write_batch)


def test_phase_inference_prefers_reads_first():
    board = _multi_host_board()
    board.materialize_frontier()
    board.store.add(Task(id="exploit:h0", kind="exploit", target_id="h0.com"))
    planner = Planner(board, graph=board.graph)
    batch = planner.next_batch()                  # phase=None -> infer
    # read tasks exist, so the inferred wave is read-phase
    assert all(st.task.kind in READ_KINDS for st in batch)


def test_max_size_caps_batch():
    board = _multi_host_board()
    board.materialize_frontier()
    planner = Planner(board, graph=board.graph)
    batch = planner.next_batch(phase="read", max_size=2)
    assert len(batch) == 2


def test_empty_frontier_empty_batch():
    g = KnowledgeGraph()
    board = Board(store=InMemoryTaskStore(), graph=g, rules=[])
    planner = Planner(board, graph=g)
    assert planner.next_batch() == []
