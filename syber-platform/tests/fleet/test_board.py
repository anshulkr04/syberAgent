"""
Fleet Phase 1 — blackboard task layer tests (no network, no LLM).

Covers: the atomic claim/lease protocol (claim, claim_next priority order,
double-claim mutual exclusion, lease expiry reclaim), heartbeat (renew + lost-lease
detection), reaper, complete/fail/dead-letter/block, dependency gating, idempotent
frontier materialization from a real in-memory attack graph, and concurrent claim
safety under threads.

Run: python -m pytest tests/fleet/test_board.py   (from syber-platform/)
"""
from __future__ import annotations

import threading

from syber.fleet.board import (Board, InMemoryTaskStore, Task, TaskStatus,
                               default_frontier_rules, make_board)
from syber.graph.store import KnowledgeGraph


# --------------------------------------------------------------------------- #
# claim / lease
# --------------------------------------------------------------------------- #
def test_claim_marks_owned_and_increments_attempts():
    s = InMemoryTaskStore()
    s.add(Task(id="t1", kind="recon"))
    c = s.claim("t1", "w1", ttl=10, now=100.0)
    assert c is not None and c.status == TaskStatus.CLAIMED
    assert c.lease_owner == "w1" and c.lease_until == 110.0 and c.attempts == 1


def test_double_claim_is_mutually_exclusive():
    s = InMemoryTaskStore()
    s.add(Task(id="t1", kind="recon"))
    first = s.claim("t1", "w1", ttl=10, now=100.0)
    second = s.claim("t1", "w2", ttl=10, now=101.0)   # still leased, not expired
    assert first is not None and second is None


def test_expired_lease_is_reclaimable():
    s = InMemoryTaskStore()
    s.add(Task(id="t1", kind="recon"))
    s.claim("t1", "w1", ttl=10, now=100.0)
    # w2 claims after the lease expired
    reclaim = s.claim("t1", "w2", ttl=10, now=200.0)
    assert reclaim is not None and reclaim.lease_owner == "w2" and reclaim.attempts == 2


def test_claim_next_priority_order():
    s = InMemoryTaskStore()
    s.add(Task(id="lo", kind="recon", priority=0.1))
    s.add(Task(id="hi", kind="recon", priority=0.9))
    s.add(Task(id="mid", kind="recon", priority=0.5))
    got = s.claim_next("w1", ttl=10, now=1.0)
    assert got is not None and got.id == "hi"


def test_claim_next_filters_by_kind():
    s = InMemoryTaskStore()
    s.add(Task(id="a", kind="recon", priority=0.9))
    s.add(Task(id="b", kind="exploit", priority=0.1))
    got = s.claim_next("w1", ttl=10, kinds=["exploit"], now=1.0)
    assert got is not None and got.id == "b"


def test_claim_next_respects_dependencies():
    s = InMemoryTaskStore()
    s.add(Task(id="dep", kind="service_scan", priority=1.0))
    s.add(Task(id="child", kind="vuln_scan", priority=0.5, deps=["dep"]))
    # child blocked until dep is done -> claim_next returns dep first
    got = s.claim_next("w1", ttl=10, now=1.0)
    assert got is not None and got.id == "dep"
    # child still not claimable while dep is only claimed (not done)
    got2 = s.claim_next("w2", ttl=10, kinds=["vuln_scan"], now=2.0)
    assert got2 is None
    s.complete("dep", "w1")
    got3 = s.claim_next("w2", ttl=10, kinds=["vuln_scan"], now=3.0)
    assert got3 is not None and got3.id == "child"


# --------------------------------------------------------------------------- #
# heartbeat / complete / fail / reap
# --------------------------------------------------------------------------- #
def test_heartbeat_renews_and_detects_lost_lease():
    s = InMemoryTaskStore()
    s.add(Task(id="t1", kind="recon"))
    s.claim("t1", "w1", ttl=10, now=100.0)
    assert s.heartbeat("t1", "w1", ttl=10, now=105.0) is True
    assert s.get("t1").lease_until == 115.0
    # a different worker (or a reaped one) cannot heartbeat
    assert s.heartbeat("t1", "w2", ttl=10, now=106.0) is False


def test_complete_only_by_owner():
    s = InMemoryTaskStore()
    s.add(Task(id="t1", kind="recon"))
    s.claim("t1", "w1", ttl=10, now=1.0)
    assert s.complete("t1", "w2", "ref") is False
    assert s.complete("t1", "w1", "finding:1") is True
    t = s.get("t1")
    assert t.status == TaskStatus.DONE and t.result_ref == "finding:1" and t.lease_owner is None


def test_fail_requeues_then_deadletters():
    s = InMemoryTaskStore()
    s.add(Task(id="t1", kind="recon", max_attempts=2))
    s.claim("t1", "w1", ttl=10, now=1.0)            # attempt 1
    r1 = s.fail("t1", "w1", note="boom", now=2.0)
    assert r1.status == TaskStatus.FAILED           # retryable
    s.claim("t1", "w1", ttl=10, now=3.0)            # attempt 2
    r2 = s.fail("t1", "w1", note="boom again", now=4.0)
    assert r2.status == TaskStatus.DEAD             # attempts exhausted -> dead-letter


def test_reap_reclaims_expired_leases():
    s = InMemoryTaskStore()
    s.add(Task(id="t1", kind="recon"))
    s.add(Task(id="t2", kind="recon"))
    s.claim("t1", "w1", ttl=10, now=100.0)
    s.claim("t2", "w2", ttl=10, now=100.0)
    s.heartbeat("t2", "w2", ttl=1000, now=105.0)    # t2 keeps its lease alive
    reaped = s.reap(now=200.0)
    assert reaped == ["t1"]
    assert s.get("t1").status == TaskStatus.FAILED   # back to retryable
    assert s.get("t2").status == TaskStatus.CLAIMED


def test_reaped_worker_cannot_complete_after_reclaim():
    s = InMemoryTaskStore()
    s.add(Task(id="t1", kind="recon"))
    s.claim("t1", "w1", ttl=10, now=100.0)
    s.reap(now=200.0)                                 # w1's lease expires -> requeued
    # w1 wakes up late and tries to finish -> rejected (it lost the lease)
    assert s.complete("t1", "w1", "ref") is False
    assert s.heartbeat("t1", "w1", ttl=10, now=201.0) is False


def test_block_is_terminal():
    s = InMemoryTaskStore()
    s.add(Task(id="t1", kind="exploit"))
    s.claim("t1", "w1", ttl=10, now=1.0)
    assert s.block("t1", "w1", note="cloudflare 1020 hard block") is True
    assert s.get("t1").status == TaskStatus.BLOCKED


# --------------------------------------------------------------------------- #
# frontier materialization over a real graph
# --------------------------------------------------------------------------- #
def _graph_with_web_host() -> KnowledgeGraph:
    from syber.graph import model as M
    # point the model at a fresh graph
    import syber.graph.store as store
    g = KnowledgeGraph()
    store._graph = g
    M.upsert_host("t.com", ip="1.2.3.4")
    M.upsert_service("t.com", 443, service="https")
    M.upsert_web_endpoint("t.com", "https://t.com/item?id=5", status=200, params=["id"])
    M.upsert_vulnerability("t.com", "CVE-2024-9999", severity="high")
    return g


def test_materialize_frontier_from_graph():
    g = _graph_with_web_host()
    board = Board(store=InMemoryTaskStore(), graph=g)
    created = board.materialize_frontier()
    ids = {t.id for t in created}
    assert "service_scan:t.com" in ids
    assert "web_crawl:t.com" in ids                  # 443 is a web port
    assert "vuln_scan:t.com" in ids
    assert "test_injection:https://t.com/item?id=5" in ids
    assert "test_access_control:https://t.com/item?id=5" in ids
    assert "exploit:CVE-2024-9999" in ids


def test_materialize_frontier_is_idempotent():
    g = _graph_with_web_host()
    board = Board(store=InMemoryTaskStore(), graph=g)
    first = board.materialize_frontier()
    second = board.materialize_frontier()            # no graph change
    assert len(first) > 0 and second == []           # nothing new the 2nd time
    # totals didn't double
    assert len(board.store.list()) == len(first)


def test_materialize_does_not_resurrect_done_task():
    g = _graph_with_web_host()
    board = Board(store=InMemoryTaskStore(), graph=g)
    board.materialize_frontier()
    # satisfy the dependency (service_scan) before the dependent vuln_scan is claimable
    board.store.claim("service_scan:t.com", "w1", ttl=10, now=1.0)
    board.store.complete("service_scan:t.com", "w1")
    assert board.store.claim("vuln_scan:t.com", "w1", ttl=10, now=2.0) is not None
    board.store.complete("vuln_scan:t.com", "w1")
    board.materialize_frontier()                      # must NOT flip it back to frontier
    assert board.store.get("vuln_scan:t.com").status == TaskStatus.DONE


def test_weaponised_vuln_not_re_added_as_exploit():
    g = _graph_with_web_host()
    # mark the vuln edge weaponised
    for src, dst, ed in list(g.g.in_edges("CVE-2024-9999", data=True)):
        if ed.get("edge_type") == "VULNERABLE_TO":
            g.g[src][dst]["weaponised"] = True
    board = Board(store=InMemoryTaskStore(), graph=g)
    created = board.materialize_frontier()
    assert "exploit:CVE-2024-9999" not in {t.id for t in created}


# --------------------------------------------------------------------------- #
# coverage / quiescence
# --------------------------------------------------------------------------- #
def test_coverage_and_quiescence():
    s = InMemoryTaskStore()
    board = Board(store=s, graph=KnowledgeGraph(), rules=[])
    s.add(Task(id="t1", kind="recon"))
    s.add(Task(id="t2", kind="recon"))
    assert not board.is_quiescent()
    s.claim("t1", "w1", ttl=10, now=1.0); s.complete("t1", "w1")
    s.claim("t2", "w1", ttl=10, now=2.0); s.complete("t2", "w1")
    assert board.is_quiescent()
    cov = board.coverage()
    assert cov["total"] == 2 and cov["open"] == 0 and cov["fraction_done"] == 1.0


# --------------------------------------------------------------------------- #
# concurrency — only one worker may win a task
# --------------------------------------------------------------------------- #
def test_concurrent_claim_next_no_double_dispatch():
    s = InMemoryTaskStore()
    n = 200
    for i in range(n):
        s.add(Task(id=f"t{i}", kind="recon", priority=1.0))
    claimed_by: dict[str, list[str]] = {}
    lock = threading.Lock()

    def worker(wid: str):
        while True:
            t = s.claim_next(wid, ttl=1000)
            if t is None:
                return
            with lock:
                claimed_by.setdefault(t.id, []).append(wid)
            s.complete(t.id, wid)

    threads = [threading.Thread(target=worker, args=(f"w{k}",)) for k in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # every task claimed exactly once, by exactly one worker
    assert len(claimed_by) == n
    assert all(len(v) == 1 for v in claimed_by.values())
    assert all(t.status == TaskStatus.DONE for t in s.list())


def test_make_board_defaults_to_memory():
    board = make_board(graph=KnowledgeGraph())
    assert isinstance(board.store, InMemoryTaskStore)
    assert board.rules == default_frontier_rules() or len(board.rules) > 0
