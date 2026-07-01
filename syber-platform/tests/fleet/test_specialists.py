"""
Fleet Phase 4 — specialist roster tests (no network, no LLM, no real tools).

Covers: roster integrity (every default task kind has a specialist), system-prompt
assembly (focus + doc-pack + counterfactual dedup), the deterministic tool worker's
dispatch + graceful handling of missing runners, and a FULL fleet run driven by the
tool worker against an injected fake-tool layer (proving board+planner+coordinator+
specialists compose end-to-end without an LLM).

Run: python -m pytest tests/fleet/test_specialists.py   (from syber-platform/)
"""
from __future__ import annotations

from syber.fleet.board import Board, InMemoryTaskStore, Task, TaskStatus
from syber.fleet.coordinator import Coordinator, WorkerResult
from syber.fleet.planner import Planner
from syber.fleet.specialists import (SPECIALISTS, counterfactual_directive,
                                     default_runners, make_tool_worker,
                                     specialist_for, specialist_system_prompt)
from syber.graph.store import KnowledgeGraph


# --------------------------------------------------------------------------- #
# roster integrity
# --------------------------------------------------------------------------- #
def test_every_frontier_kind_has_a_specialist():
    # the kinds the default frontier rules can emit
    kinds = {"service_scan", "web_crawl", "vuln_scan", "test_injection",
             "test_access_control", "exploit"}
    for k in kinds:
        assert specialist_for(k) is not None, f"no specialist for {k}"


def test_specialists_have_tools_and_docs():
    for s in SPECIALISTS:
        assert s.name and s.kinds and s.tools and s.docs
        assert len(s.docs) > 40            # a real doc-pack, not a stub


def test_no_duplicate_kind_ownership():
    seen: set[str] = set()
    for s in SPECIALISTS:
        for k in s.kinds:
            assert k not in seen, f"kind {k} owned by two specialists"
            seen.add(k)


# --------------------------------------------------------------------------- #
# prompt assembly
# --------------------------------------------------------------------------- #
def test_system_prompt_includes_focus_docs_and_tools():
    spec = specialist_for("idor-bola" and "test_access_control")
    p = specialist_system_prompt(spec)
    assert "idor-bola" in p
    assert "BOLA" in p or "Object Level Authorization" in p
    assert "syber_test_access_control" in p


def test_counterfactual_directive_present_with_peers():
    cf = counterfactual_directive(["injection", "vuln-triage"])
    assert "do not duplicate" in cf.lower()
    assert "injection" in cf and "vuln-triage" in cf


def test_counterfactual_empty_without_peers():
    assert counterfactual_directive([]) == ""


def test_system_prompt_embeds_counterfactual():
    spec = specialist_for("test_injection")
    p = specialist_system_prompt(spec, peer_names=["idor-bola"])
    assert "Assume the vulnerabilities THEY are pursuing do not exist" in p


# --------------------------------------------------------------------------- #
# deterministic tool worker dispatch
# --------------------------------------------------------------------------- #
def test_tool_worker_dispatches_by_kind():
    calls: list[str] = []

    def fake_runner(name):
        def r(task, board, wid):
            calls.append(f"{name}:{task.target_id}")
            return WorkerResult(status="done")
        return r

    runners = {"service_scan": fake_runner("svc"), "web_crawl": fake_runner("crawl")}
    worker = make_tool_worker(runners=runners)
    board = Board(store=InMemoryTaskStore(), graph=KnowledgeGraph(), rules=[])
    assert worker(Task(id="a", kind="service_scan", target_id="t.com"), board, "w1").status == "done"
    assert worker(Task(id="b", kind="web_crawl", target_id="t.com"), board, "w1").status == "done"
    assert calls == ["svc:t.com", "crawl:t.com"]


def test_tool_worker_blocks_unrunnable_kind():
    worker = make_tool_worker(runners={}, block_unrunnable=True)
    board = Board(store=InMemoryTaskStore(), graph=KnowledgeGraph(), rules=[])
    res = worker(Task(id="x", kind="exploit", target_id="CVE-1"), board, "w1")
    assert res.status == "blocked" and "agent specialist" in res.note


def test_tool_worker_fails_unrunnable_when_configured():
    worker = make_tool_worker(runners={}, block_unrunnable=False)
    board = Board(store=InMemoryTaskStore(), graph=KnowledgeGraph(), rules=[])
    res = worker(Task(id="x", kind="exploit", target_id="CVE-1"), board, "w1")
    assert res.status == "failed"


def test_default_runners_cover_mechanical_kinds():
    reg = default_runners()
    for k in ("service_scan", "vuln_scan", "web_crawl", "test_injection", "test_access_control"):
        assert k in reg


# --------------------------------------------------------------------------- #
# FULL fleet run via the tool worker against a fake tool layer
# --------------------------------------------------------------------------- #
def test_full_fleet_run_with_fake_tools():
    """board + planner + coordinator + tool worker, end to end, no LLM. Fake runners
    simulate real tools writing discoveries into the graph; the fleet should fan out,
    pool evidence, grow the frontier, and reach a fixpoint."""
    import syber.graph.store as store
    from syber.graph import model as M
    g = KnowledgeGraph()
    store._graph = g
    M.upsert_host("t.com", ip="1.2.3.4")
    board = Board(store=InMemoryTaskStore(), graph=g)

    def svc_runner(task, board, wid):
        M.upsert_service("t.com", 443, service="https")
        return WorkerResult(status="done", note="found 443")

    def crawl_runner(task, board, wid):
        M.upsert_web_endpoint("t.com", "https://t.com/i?id=5", status=200, params=["id"])
        return WorkerResult(status="done", note="1 endpoint")

    def vuln_runner(task, board, wid):
        M.upsert_vulnerability("t.com", "CVE-7", severity="high", service_id="1.2.3.4:443")
        return WorkerResult(status="done", note="1 vuln")

    def probe_runner(task, board, wid):
        return WorkerResult(status="done", note="probed")

    runners = {"service_scan": svc_runner, "web_crawl": crawl_runner,
               "vuln_scan": vuln_runner, "test_injection": probe_runner,
               "test_access_control": probe_runner}
    worker = make_tool_worker(runners=runners, block_unrunnable=True)
    coord = Coordinator(board, Planner(board, graph=g), worker=worker, concurrency=4)
    out = coord.run()

    assert out["status"] == "complete"
    ids = {t.id for t in board.store.list()}
    assert {"service_scan:t.com", "web_crawl:t.com", "vuln_scan:t.com",
            "test_access_control:https://t.com/i?id=5"} <= ids
    # mechanical scan kinds done; exploit + Phase-8 verify kinds are parked (no runner
    # supplied in this fixture) for the agent/verify worker.
    exploit = board.store.get("exploit:CVE-7")
    assert exploit is not None and exploit.status == TaskStatus.BLOCKED
    scan_kinds = {"service_scan", "web_crawl", "vuln_scan", "test_injection",
                  "test_access_control"}
    mechanical = [t for t in board.store.list() if t.kind in scan_kinds]
    assert all(t.status == TaskStatus.DONE for t in mechanical)
