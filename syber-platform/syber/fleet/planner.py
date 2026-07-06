"""
The planner (fleet Phase 2).

Reads the blackboard frontier and decides the *next parallel wave*: it scores each
claimable task by **expected value**, writes the priority back onto the task, then
hands the coordinator a **disjoint, phase-aware batch** to fan out.

Two ideas from the research drive the design:

  * **Expected-value ranking = NASim reward generalised** (research_graph.md §3.4):
    value(target) + risk + pivot(betweenness) + path-gain + severity + info-gain
    − action-cost − repeated-failure penalty. Crucially this is mostly *wiring
    Syber's existing graph analytics into a priority* — `risk_score`,
    `betweenness_top`, `yens_k_shortest`, `critical_targets` already exist.
  * **Fan out reads, serialize writes** (research_orchestration.md — Anthropic vs
    Cognition reconciliation): recon/enum/probe tasks are read-heavy and largely
    independent → batch many in parallel; exploit/write tasks carry implicit
    decisions → batch few. And **one task per host per wave** so parallel workers
    touch disjoint subgraphs, minimising lock/state contention by construction
    (research_graph.md §2.4 / §3.4 disjoint batching).

Pure over the board + graph; no network, no LLM. Returns recommendations — the
coordinator (Phase 3) does the actual claiming, so ranking never races a worker.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .board import Board, Task, TaskStatus

__all__ = ["PlannerWeights", "ScoredTask", "Planner", "READ_KINDS", "WRITE_KINDS"]

# Phase classification (research: fan-out reads, serialize writes).
READ_KINDS = {"subdomain_enum", "service_scan", "web_crawl", "vuln_scan", "recon", "tech_fingerprint",
              "cert_recon", "content_discovery", "test_injection", "test_access_control",
              # Phase 8 verification kinds (read-mostly probes that climb the ladder).
              "cve_lookup", "cve_verify", "tls_audit", "default_login_check",
              "exposed_artifact_check", "http_verb_tampering", "datastore_unauth_probe",
              "service_probe", "data_extraction", "auth_retest", "bypass_403"}
WRITE_KINDS = {"exploit", "priv_esc", "lateral"}

# Per-kind action cost (NASim: scans cheap, exploits expensive).
_ACTION_COST = {
    "subdomain_enum": 1.0,
    "service_scan": 1.0, "recon": 1.0, "tech_fingerprint": 1.0, "cert_recon": 1.0,
    "web_crawl": 1.5, "vuln_scan": 2.0, "content_discovery": 1.5,
    "test_injection": 2.5, "test_access_control": 2.5,
    "cve_lookup": 2.0, "cve_verify": 1.5, "tls_audit": 1.5, "default_login_check": 2.0,
    "exposed_artifact_check": 1.0, "http_verb_tampering": 1.5,
    "datastore_unauth_probe": 1.5, "service_probe": 2.0, "data_extraction": 1.5,
    "auth_retest": 1.8, "bypass_403": 2.0,
    "exploit": 5.0, "priv_esc": 4.0, "lateral": 4.0,
}
# Info-gain bonus: scans reduce uncertainty / open new frontier (POMDP value).
_INFO_GAIN = {
    "service_scan": 2.0, "web_crawl": 1.5, "vuln_scan": 1.0, "recon": 2.0,
    "cert_recon": 1.0, "tech_fingerprint": 0.5, "content_discovery": 1.5,
}
_SEV_WEIGHT = {"critical": 10.0, "high": 6.0, "medium": 3.0, "low": 1.0,
               "info": 0.2, "unknown": 0.5}


@dataclass
class PlannerWeights:
    value: float = 3.0          # crown-jewel / criticality of the owning host
    risk: float = 1.0           # graph.risk_score(host)
    pivot: float = 2.0          # betweenness centrality (lateral-movement hub)
    path_gain: float = 2.0      # proximity to a critical target (1/(1+cost))
    severity: float = 1.0       # vuln severity (for exploit tasks)
    info_gain: float = 1.0      # uncertainty reduced (scans)
    cost: float = 1.0           # action cost (subtracted)
    attempts: float = 1.5       # demote repeatedly-failing tasks (subtracted)

    # Concurrency caps (effort-scaling + serialize-writes).
    max_parallel_read: int = 8
    max_parallel_write: int = 3


@dataclass
class ScoredTask:
    task: Task
    host: str
    score: float
    breakdown: dict[str, float]

    def to_dict(self) -> dict[str, Any]:
        return {"task_id": self.task.id, "kind": self.task.kind, "host": self.host,
                "score": round(self.score, 3), "breakdown": {k: round(v, 3)
                for k, v in self.breakdown.items()}}


def _owning_host(graph, node_id: str, max_hops: int = 4) -> str:
    """Resolve the Host node that owns a task target by walking reverse edges.

    A task may target a Host directly (service_scan), a WebEndpoint (test_injection),
    or a Vulnerability (exploit). We BFS up the in-edges to the nearest ``Host``
    label so disjoint-by-host batching and host-level scoring work for every kind."""
    try:
        nodes = graph.g.nodes
        if node_id in nodes and nodes[node_id].get("label") == "Host":
            return node_id
        seen = {node_id}
        frontier = [node_id]
        for _ in range(max_hops):
            nxt: list[str] = []
            for n in frontier:
                for src, _, _ in graph.g.in_edges(n, data=True):
                    if src in seen:
                        continue
                    if nodes[src].get("label") == "Host":
                        return src
                    seen.add(src)
                    nxt.append(src)
            frontier = nxt
            if not frontier:
                break
    except Exception:  # noqa: BLE001 - tolerate any graph shape
        pass
    return node_id  # fall back to the target itself (still a valid disjointness key)


class Planner:
    """Scores the frontier and proposes the next disjoint parallel wave."""

    def __init__(self, board: Board, graph: Any = None,
                 weights: PlannerWeights | None = None):
        self.board = board
        self._graph = graph
        self.w = weights or PlannerWeights()

    @property
    def graph(self):
        if self._graph is None:
            self._graph = self.board.graph
        return self._graph

    # ------------------------------------------------------------------ #
    def _context(self) -> dict[str, Any]:
        """Precompute graph-wide analytics once per ranking call (betweenness is the
        expensive one — O(V·E) — so never per-task)."""
        g = self.graph
        bmap: dict[str, float] = {}
        try:
            for row in g.betweenness_top(limit=10_000):
                bmap[row["node"]] = row["score"]
        except Exception:  # noqa: BLE001
            pass
        try:
            criticals = list(g.critical_targets())
        except Exception:  # noqa: BLE001
            criticals = []
        return {"betweenness": bmap, "criticals": criticals}

    def _path_gain(self, host: str, criticals: list[str]) -> float:
        """1/(1+cost) of the cheapest path from host to any critical target.
        0 when there are no criticals or no path (so the term simply drops out)."""
        if not criticals:
            return 0.0
        best = None
        g = self.graph
        for tgt in criticals:
            if tgt == host:
                continue
            try:
                res = g.dijkstra(host, tgt)
            except Exception:  # noqa: BLE001
                res = None
            if res:
                c = res.get("total_cost", 0.0)
                best = c if best is None else min(best, c)
        return 0.0 if best is None else 1.0 / (1.0 + best)

    def _severity_weight(self, task: Task) -> float:
        if task.kind not in WRITE_KINDS:
            return 0.0
        try:
            d = self.graph.g.nodes.get(task.target_id, {})
            return _SEV_WEIGHT.get(str(d.get("severity", "unknown")).lower(), 0.5)
        except Exception:  # noqa: BLE001
            return 0.5

    def score_task(self, task: Task, ctx: dict[str, Any]) -> ScoredTask:
        g = self.graph
        host = _owning_host(g, task.target_id or task.id)
        try:
            risk = float(g.risk_score(host))
        except Exception:  # noqa: BLE001
            risk = 0.0
        value = 2.0 if host in ctx["criticals"] else 1.0
        pivot = ctx["betweenness"].get(host, 0.0)
        path_gain = self._path_gain(host, ctx["criticals"])
        sev = self._severity_weight(task)
        info = _INFO_GAIN.get(task.kind, 0.0)
        cost = _ACTION_COST.get(task.kind, 2.0)
        w = self.w
        breakdown = {
            "value": w.value * value,
            "risk": w.risk * risk,
            "pivot": w.pivot * pivot,
            "path_gain": w.path_gain * path_gain,
            "severity": w.severity * sev,
            "info_gain": w.info_gain * info,
            "cost": -w.cost * cost,
            "attempts": -w.attempts * task.attempts,
        }
        score = sum(breakdown.values())
        return ScoredTask(task=task, host=host, score=score, breakdown=breakdown)

    # ------------------------------------------------------------------ #
    def rank_frontier(self, kinds: set[str] | None = None) -> list[ScoredTask]:
        """Score every claimable frontier/failed task, write the score+priority back
        onto the board, and return them ranked high-to-low."""
        ctx = self._context()
        scored: list[ScoredTask] = []
        for t in self.board.store.list():
            if t.status not in (TaskStatus.FRONTIER, TaskStatus.FAILED):
                continue
            if kinds is not None and t.kind not in kinds:
                continue
            st = self.score_task(t, ctx)
            scored.append(st)
            self.board.store.set_priority(t.id, priority=st.score, score=st.score)
        scored.sort(key=lambda s: s.score, reverse=True)
        return scored

    def wave_size(self, scored: list[ScoredTask], phase: str) -> int:
        """Effort scaling (Anthropic) × phase (Cognition serialize-writes).

        Few candidates → small wave; many → up to the phase cap. Write phase
        (exploit/lateral) is capped low because those actions carry implicit
        decisions and shouldn't run wide in parallel."""
        n = len(scored)
        if n == 0:
            return 0
        cap = self.w.max_parallel_write if phase == "write" else self.w.max_parallel_read
        if n <= 2:
            return min(n, cap)
        return min(cap, max(2, n))

    def next_batch(self, max_size: int | None = None,
                   phase: str | None = None) -> list[ScoredTask]:
        """Propose the next parallel wave: ranked, **one task per host** (disjoint
        subgraphs ⇒ low contention), sized by effort + phase. Does NOT claim — the
        coordinator claims, so ranking never races a worker.

        If ``phase`` is None it is inferred: prefer a read-heavy wave when read tasks
        exist (fan out wide), otherwise a write wave (serialize)."""
        # Rank read and write pools; decide phase.
        read_ranked = self.rank_frontier(kinds=READ_KINDS)
        if phase is None:
            phase = "read" if read_ranked else "write"
        ranked = read_ranked if phase == "read" else self.rank_frontier(kinds=WRITE_KINDS)

        size = self.wave_size(ranked, phase)
        if max_size is not None:
            size = min(size, max_size)

        # Disjoint by host: keep only the top-scoring task per owning host.
        batch: list[ScoredTask] = []
        used_hosts: set[str] = set()
        for st in ranked:
            if st.host in used_hosts:
                continue
            used_hosts.add(st.host)
            batch.append(st)
            if len(batch) >= size:
                break
        return batch
