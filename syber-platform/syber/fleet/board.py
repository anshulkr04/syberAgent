"""
The blackboard task layer (fleet Phase 1).

This is the coordination substrate for the parallel fleet. Workers never talk to
each other; they coordinate *through shared state* (the HEARSAY-II / MetaGPT
blackboard principle, and the answer to Cognition's "parallel agents make
conflicting decisions" objection — everyone reads the same evolving board).

Two halves:
  * ``TaskStore`` — the durable-ish task ledger with an **atomic claim/lease**
    protocol (claim-with-TTL, heartbeat to renew, reaper to reclaim dead workers).
    ``InMemoryTaskStore`` is the default (thread-safe, single-process); the same
    interface fronts a Neo4j/Postgres store later (Postgres ``FOR UPDATE SKIP
    LOCKED`` / Neo4j compare-and-set), so cross-process scale-up needs no caller
    change. This mirrors SQS's visibility-timeout model: a claimed task is invisible
    to others until its lease lapses, then it is reclaimable.
  * ``Board`` — ties the store to the attack graph and **materializes the frontier**:
    as workers write discoveries into the graph (a new host, a web service, a vuln),
    deterministic rules spawn the next *frontier* tasks. Task ids are deterministic,
    so materialization is idempotent under concurrency — re-running never duplicates.

Pure Python + threading (+ the existing NetworkX graph); no network, unit-tested.
The "never hard-crash, degrade gracefully" contract applies: with no Neo4j/Postgres
this runs entirely in-process with thread workers sharing one graph.

Refs: research_persistence.md (SQS visibility timeout, Postgres SKIP LOCKED,
lease/heartbeat/reaper, idempotency), research_graph.md (graph-as-blackboard,
frontier materialization, claim/lease protocol), research_papers.md (VulnBot PTG +
Merge, AutoPT state machine).
"""
from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any

__all__ = ["TaskStatus", "Task", "TaskStore", "InMemoryTaskStore", "Board",
           "make_board", "FrontierRule", "default_frontier_rules"]


# --------------------------------------------------------------------------- #
# Task model
# --------------------------------------------------------------------------- #
class TaskStatus(str, Enum):
    FRONTIER = "frontier"      # unexplored — the planner's candidate pool
    CLAIMED = "claimed"        # a worker holds a lease, not yet started
    IN_PROGRESS = "in_progress"
    DONE = "done"
    FAILED = "failed"          # transient failure, requeued for retry
    DEAD = "dead"              # attempts exhausted — dead-letter / HITL
    BLOCKED = "blocked"        # cannot proceed (e.g. hard WAF block); terminal-ish

    def __str__(self) -> str:
        return self.value


# Statuses a worker currently owns (lease-bearing) — eligible for reaping.
_LEASED = {TaskStatus.CLAIMED, TaskStatus.IN_PROGRESS}
# Terminal statuses (never re-dispatched).
TERMINAL = {TaskStatus.DONE, TaskStatus.DEAD, TaskStatus.BLOCKED}


@dataclass
class Task:
    id: str
    kind: str                              # service_scan|web_crawl|vuln_scan|test_injection|...
    target_id: str = ""                    # the graph node this task acts on
    status: TaskStatus = TaskStatus.FRONTIER
    priority: float = 0.0                  # higher = sooner (set by the planner)
    score: float = 0.0                     # planner's expected-value score
    deps: list[str] = field(default_factory=list)   # task ids that must be DONE first
    lease_owner: str | None = None
    lease_until: float = 0.0
    attempts: int = 0
    max_attempts: int = 3
    result_ref: str | None = None          # pointer to produced finding / evidence
    note: str = ""                         # last failure reason / hint for retry
    revivals: int = 0                      # times a dead task was revived (persistence)
    # Verification-task context (Phase 8): the lead a verify task serves + probe inputs.
    lead_id: str = ""
    product: str = ""
    version: str = ""
    cve: str = ""
    url: str = ""
    created_seq: int = 0
    updated_seq: int = 0
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "kind": self.kind, "target_id": self.target_id,
                "status": str(self.status), "priority": self.priority, "score": self.score,
                "deps": list(self.deps), "lease_owner": self.lease_owner,
                "lease_until": self.lease_until, "attempts": self.attempts,
                "max_attempts": self.max_attempts, "result_ref": self.result_ref,
                "note": self.note, "revivals": self.revivals,
                "lead_id": self.lead_id, "product": self.product, "version": self.version,
                "cve": self.cve, "url": self.url,
                "created_seq": self.created_seq, "updated_seq": self.updated_seq}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Task":
        return cls(id=d["id"], kind=d["kind"], target_id=d.get("target_id", ""),
                   status=TaskStatus(d.get("status", "frontier")),
                   priority=d.get("priority", 0.0), score=d.get("score", 0.0),
                   deps=list(d.get("deps", [])), lease_owner=d.get("lease_owner"),
                   lease_until=d.get("lease_until", 0.0), attempts=d.get("attempts", 0),
                   max_attempts=d.get("max_attempts", 3), result_ref=d.get("result_ref"),
                   note=d.get("note", ""), revivals=d.get("revivals", 0),
                   lead_id=d.get("lead_id", ""), product=d.get("product", ""),
                   version=d.get("version", ""), cve=d.get("cve", ""), url=d.get("url", ""),
                   created_seq=d.get("created_seq", 0), updated_seq=d.get("updated_seq", 0))


# --------------------------------------------------------------------------- #
# Task store — atomic claim/lease ledger
# --------------------------------------------------------------------------- #
class TaskStore:
    """Interface for the task ledger. ``InMemoryTaskStore`` is the default; a
    Neo4j/Postgres-backed store implements the same contract for cross-process
    scale-up (Postgres SKIP LOCKED / Neo4j CAS), so the Board/Coordinator never
    change. All mutating methods MUST be atomic w.r.t. concurrent callers."""

    def add(self, task: Task) -> Task: raise NotImplementedError
    def get(self, task_id: str) -> Task | None: raise NotImplementedError
    def upsert_frontier(self, task: Task) -> Task: raise NotImplementedError
    def claim(self, task_id: str, worker_id: str, ttl: float, now: float | None = None) -> Task | None: raise NotImplementedError
    def claim_next(self, worker_id: str, ttl: float, kinds: Iterable[str] | None = None,
                   now: float | None = None) -> Task | None: raise NotImplementedError
    def heartbeat(self, task_id: str, worker_id: str, ttl: float, now: float | None = None) -> bool: raise NotImplementedError
    def start(self, task_id: str, worker_id: str) -> bool: raise NotImplementedError
    def complete(self, task_id: str, worker_id: str, result_ref: str | None = None) -> bool: raise NotImplementedError
    def fail(self, task_id: str, worker_id: str, note: str = "", now: float | None = None) -> Task | None: raise NotImplementedError
    def block(self, task_id: str, worker_id: str, note: str = "") -> bool: raise NotImplementedError
    def reap(self, now: float | None = None) -> list[str]: raise NotImplementedError
    def list(self, status: TaskStatus | None = None) -> list[Task]: raise NotImplementedError
    def counts(self) -> dict[str, int]: raise NotImplementedError
    def set_priority(self, task_id: str, priority: float, score: float | None = None) -> bool: raise NotImplementedError
    def revive(self, task_id: str, max_revivals: int = 1) -> Task | None: raise NotImplementedError


class InMemoryTaskStore(TaskStore):
    """Thread-safe in-process task ledger. A single ``RLock`` serialises all
    mutations so claim/lease is atomic (the in-memory analogue of Postgres SKIP
    LOCKED / Neo4j compare-and-set). Good for a single Kali process running thread
    workers — the default deployment."""

    def __init__(self) -> None:
        self._tasks: dict[str, Task] = {}
        self._lock = threading.RLock()
        self._seq = 0

    # -- internals ------------------------------------------------------------ #
    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def _deps_done(self, task: Task) -> bool:
        for d in task.deps:
            dep = self._tasks.get(d)
            if dep is None or dep.status != TaskStatus.DONE:
                return False
        return True

    def _claimable(self, t: Task, now: float) -> bool:
        if t.status == TaskStatus.FRONTIER or t.status == TaskStatus.FAILED:
            return self._deps_done(t)
        # an expired lease on a leased task makes it reclaimable
        if t.status in _LEASED and t.lease_until < now:
            return self._deps_done(t)
        return False

    def _do_claim(self, t: Task, worker_id: str, ttl: float, now: float) -> Task:
        t.status = TaskStatus.CLAIMED
        t.lease_owner = worker_id
        t.lease_until = now + ttl
        t.attempts += 1
        t.updated_seq = self._next_seq()
        t.updated_at = now
        return replace(t)        # hand back a copy so callers can't mutate store state

    # -- API ------------------------------------------------------------------ #
    def add(self, task: Task) -> Task:
        with self._lock:
            if task.created_seq == 0:
                task.created_seq = self._next_seq()
            task.updated_seq = task.created_seq
            self._tasks[task.id] = task
            return replace(task)

    def get(self, task_id: str) -> Task | None:
        with self._lock:
            t = self._tasks.get(task_id)
            return replace(t) if t else None

    def upsert_frontier(self, task: Task) -> Task:
        """Idempotent: create a frontier task if absent; if it already exists in any
        state, leave it untouched (never resurrect a done/claimed task). This is what
        makes frontier materialization safe to re-run under concurrency."""
        with self._lock:
            existing = self._tasks.get(task.id)
            if existing is not None:
                return replace(existing)
            return self.add(task)

    def claim(self, task_id: str, worker_id: str, ttl: float, now: float | None = None) -> Task | None:
        now = time.time() if now is None else now
        with self._lock:
            t = self._tasks.get(task_id)
            if t is None or not self._claimable(t, now):
                return None
            return self._do_claim(t, worker_id, ttl, now)

    def claim_next(self, worker_id: str, ttl: float, kinds: Iterable[str] | None = None,
                   now: float | None = None) -> Task | None:
        now = time.time() if now is None else now
        kindset = set(kinds) if kinds is not None else None
        with self._lock:
            # highest priority, then score, then oldest — among claimable tasks.
            cands = [t for t in self._tasks.values()
                     if (kindset is None or t.kind in kindset) and self._claimable(t, now)]
            if not cands:
                return None
            cands.sort(key=lambda t: (-t.priority, -t.score, t.created_seq))
            return self._do_claim(cands[0], worker_id, ttl, now)

    def heartbeat(self, task_id: str, worker_id: str, ttl: float, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        with self._lock:
            t = self._tasks.get(task_id)
            if t is None or t.lease_owner != worker_id or t.status not in _LEASED:
                return False           # lost the lease (reaped) -> worker must abort
            t.lease_until = now + ttl
            t.updated_seq = self._next_seq()
            t.updated_at = now
            return True

    def start(self, task_id: str, worker_id: str) -> bool:
        with self._lock:
            t = self._tasks.get(task_id)
            if t is None or t.lease_owner != worker_id or t.status != TaskStatus.CLAIMED:
                return False
            t.status = TaskStatus.IN_PROGRESS
            t.updated_seq = self._next_seq()
            return True

    def complete(self, task_id: str, worker_id: str, result_ref: str | None = None) -> bool:
        with self._lock:
            t = self._tasks.get(task_id)
            if t is None or t.lease_owner != worker_id or t.status not in _LEASED:
                return False
            t.status = TaskStatus.DONE
            t.result_ref = result_ref
            t.lease_owner = None
            t.lease_until = 0.0
            t.updated_seq = self._next_seq()
            t.updated_at = time.time()
            return True

    def fail(self, task_id: str, worker_id: str, note: str = "", now: float | None = None) -> Task | None:
        now = time.time() if now is None else now
        with self._lock:
            t = self._tasks.get(task_id)
            if t is None or t.lease_owner != worker_id or t.status not in _LEASED:
                return None
            t.note = note
            t.lease_owner = None
            t.lease_until = 0.0
            # exhausted retries -> dead-letter; otherwise requeue for another attempt.
            t.status = TaskStatus.DEAD if t.attempts >= t.max_attempts else TaskStatus.FAILED
            t.updated_seq = self._next_seq()
            t.updated_at = now
            return replace(t)

    def block(self, task_id: str, worker_id: str, note: str = "") -> bool:
        with self._lock:
            t = self._tasks.get(task_id)
            if t is None or t.lease_owner != worker_id or t.status not in _LEASED:
                return False
            t.status = TaskStatus.BLOCKED
            t.note = note
            t.lease_owner = None
            t.lease_until = 0.0
            t.updated_seq = self._next_seq()
            return True

    def reap(self, now: float | None = None) -> list[str]:
        """Reclaim tasks whose lease expired (crashed/hung workers). Returns the
        reclaimed task ids. Requeues to FAILED (retryable) or DEAD if exhausted."""
        now = time.time() if now is None else now
        reaped: list[str] = []
        with self._lock:
            for t in self._tasks.values():
                if t.status in _LEASED and t.lease_until < now:
                    t.lease_owner = None
                    t.lease_until = 0.0
                    t.status = TaskStatus.DEAD if t.attempts >= t.max_attempts else TaskStatus.FAILED
                    t.note = (t.note + "; " if t.note else "") + "lease expired (reaped)"
                    t.updated_seq = self._next_seq()
                    t.updated_at = now
                    reaped.append(t.id)
        return reaped

    def list(self, status: TaskStatus | None = None) -> list[Task]:
        with self._lock:
            out = [replace(t) for t in self._tasks.values()
                   if status is None or t.status == status]
        return sorted(out, key=lambda t: t.created_seq)

    def counts(self) -> dict[str, int]:
        with self._lock:
            c: dict[str, int] = {}
            for t in self._tasks.values():
                c[str(t.status)] = c.get(str(t.status), 0) + 1
            return c

    def set_priority(self, task_id: str, priority: float, score: float | None = None) -> bool:
        with self._lock:
            t = self._tasks.get(task_id)
            if t is None:
                return False
            t.priority = priority
            if score is not None:
                t.score = score
            t.updated_seq = self._next_seq()
            return True

    def revive(self, task_id: str, max_revivals: int = 1) -> Task | None:
        """Bring a DEAD/BLOCKED task back to the frontier for another attempt — the
        anti-premature-abandonment lever. Capped by ``max_revivals`` so a hopeless
        task can't loop forever. Returns the revived task, or None if not revivable."""
        with self._lock:
            t = self._tasks.get(task_id)
            if t is None or t.status not in (TaskStatus.DEAD, TaskStatus.BLOCKED):
                return None
            if t.revivals >= max_revivals:
                return None
            t.status = TaskStatus.FRONTIER
            t.attempts = 0
            t.revivals += 1
            t.lease_owner = None
            t.lease_until = 0.0
            t.note = (t.note + "; " if t.note else "") + f"revived (#{t.revivals})"
            t.updated_seq = self._next_seq()
            return replace(t)

    # -- durable snapshot / restore (coordinator checkpointing) --------------- #
    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {"seq": self._seq, "tasks": [t.to_dict() for t in self._tasks.values()]}

    def restore(self, data: dict[str, Any]) -> None:
        with self._lock:
            self._tasks = {d["id"]: Task.from_dict(d) for d in data.get("tasks", [])}
            self._seq = int(data.get("seq", len(self._tasks)))


# --------------------------------------------------------------------------- #
# Frontier materialization — graph state -> next tasks
# --------------------------------------------------------------------------- #
# A rule reads the graph and yields candidate frontier tasks. Task ids are
# deterministic so re-running is idempotent (upsert_frontier dedups).
FrontierRule = Callable[["Any"], "list[Task]"]

_WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}


def _nodes(graph, label: str) -> list[tuple[str, dict]]:
    """All (id, props) for a label, read straight off the NetworkX DiGraph."""
    try:
        return [(n, d) for n, d in graph.g.nodes(data=True) if d.get("label") == label]
    except Exception:  # noqa: BLE001 - tolerate any graph backend shape
        return []


def _out_labels(graph, node_id: str, label: str) -> list[tuple[str, dict]]:
    """Out-neighbours of node_id that carry the given label."""
    out: list[tuple[str, dict]] = []
    try:
        for _, dst, _ in graph.g.out_edges(node_id, data=True):
            d = graph.g.nodes[dst]
            if d.get("label") == label:
                out.append((dst, d))
    except Exception:  # noqa: BLE001
        pass
    return out


def _rule_subdomain_enum(graph) -> list[Task]:
    """Map the surface FIRST: each apex Host gets a one-time top-priority subdomain
    enumeration task (CT logs + prefix brute). Only the registrable apex enumerates
    (discovered subdomains are Hosts but not apexes → no fan-out explosion)."""
    from ..scanning.subdomains import registrable_apex
    out: list[Task] = []
    for h, d in _nodes(graph, "Host"):
        if d.get("subdomains_enumerated"):
            continue
        try:
            if registrable_apex(h) != h:
                continue
        except Exception:  # noqa: BLE001
            continue
        out.append(Task(id=f"subdomain_enum:{h}", kind="subdomain_enum", target_id=h,
                        priority=2.0))
    return out


def _rule_service_scan(graph) -> list[Task]:
    # Every Host gets a service_scan task (idempotent on host id).
    return [Task(id=f"service_scan:{h}", kind="service_scan", target_id=h,
                 priority=1.0) for h, _ in _nodes(graph, "Host")]


def _rule_web_crawl(graph) -> list[Task]:
    out: list[Task] = []
    for h, _ in _nodes(graph, "Host"):
        svcs = _out_labels(graph, h, "Service")
        if any((s[1].get("port") in _WEB_PORTS) for s in svcs):
            out.append(Task(id=f"web_crawl:{h}", kind="web_crawl", target_id=h,
                            priority=0.9, deps=[f"service_scan:{h}"]))
    return out


def _rule_vuln_scan(graph) -> list[Task]:
    out: list[Task] = []
    for h, _ in _nodes(graph, "Host"):
        if _out_labels(graph, h, "Service"):
            out.append(Task(id=f"vuln_scan:{h}", kind="vuln_scan", target_id=h,
                            priority=0.8, deps=[f"service_scan:{h}"]))
    return out


def _rule_injection(graph) -> list[Task]:
    # WebEndpoints that carry parameters are injection/IDOR surface.
    out: list[Task] = []
    for url, d in _nodes(graph, "WebEndpoint"):
        if d.get("params"):
            out.append(Task(id=f"test_injection:{url}", kind="test_injection",
                            target_id=url, priority=0.7))
            out.append(Task(id=f"test_access_control:{url}", kind="test_access_control",
                            target_id=url, priority=0.95))   # IDOR/BOLA = OWASP API #1
    return out


def _rule_exploit(graph) -> list[Task]:
    # Vulnerabilities not yet weaponised become exploit frontier tasks.
    out: list[Task] = []
    for vid, d in _nodes(graph, "Vulnerability"):
        weaponised = False
        try:
            for src, _, ed in graph.g.in_edges(vid, data=True):
                if ed.get("edge_type") == "VULNERABLE_TO" and ed.get("weaponised"):
                    weaponised = True
                    break
        except Exception:  # noqa: BLE001
            pass
        if not weaponised:
            sev = str(d.get("severity", "unknown")).lower()
            pr = {"critical": 1.5, "high": 1.2, "medium": 0.8}.get(sev, 0.5)
            out.append(Task(id=f"exploit:{vid}", kind="exploit", target_id=vid, priority=pr))
    return out


def _authorized(host: str) -> bool:
    """Default-deny scope check used by the lateral rule so a foothold only spawns
    lateral tasks to ALREADY-AUTHORISED reachable hosts — scope is never expanded by
    movement. If the auth store can't be loaded, fail safe (no lateral task); the
    execution-time _require_authorized gate is the backstop either way."""
    try:
        from ..scanning.authorization import get_auth_store
        allowed, _ = get_auth_store().is_authorized(host)
        return bool(allowed)
    except Exception:  # noqa: BLE001 - fail safe: no auth answer -> no lateral task
        return False


def _rule_lateral(graph) -> list[Task]:
    """For each compromised host, a lateral-movement task to each host it CAN_REACH
    that isn't compromised yet (MulVAL netAccess → the attack path continues), BUT
    only to hosts already inside authorised scope (default-deny). Fires only once a
    foothold exists, so it is inert on a fresh surface graph. An out-of-scope
    reachable neighbour stays recorded as a CAN_REACH lead in the graph but gets no
    task — movement records the lead, it does not expand scope."""
    out: list[Task] = []
    try:
        nodes = graph.g.nodes
        for h, d in _nodes(graph, "Host"):
            if not d.get("compromised"):
                continue
            for _, dst, ed in graph.g.out_edges(h, data=True):
                if ed.get("edge_type") != "CAN_REACH":
                    continue
                if not nodes.get(dst, {}).get("compromised") and _authorized(dst):
                    out.append(Task(id=f"lateral:{h}->{dst}", kind="lateral",
                                    target_id=dst, priority=1.1))
    except Exception:  # noqa: BLE001
        pass
    return out


def default_frontier_rules() -> list[FrontierRule]:
    """The standard recon->enum->test->exploit frontier expansion, plus lateral
    movement once a foothold is gained."""
    return [_rule_subdomain_enum, _rule_service_scan, _rule_web_crawl, _rule_vuln_scan,
            _rule_injection, _rule_exploit, _rule_lateral]


# --------------------------------------------------------------------------- #
# Board — store + graph + frontier rules
# --------------------------------------------------------------------------- #
class Board:
    """The blackboard: the task ledger plus the attack graph it derives work from.

    Workers claim tasks, run scoped tools, write discoveries into the graph, and
    complete; the Board re-materializes the frontier so new graph facts spawn the
    next wave of tasks. The graph is the single source of truth; the task ledger is
    the coordination overlay."""

    def __init__(self, store: TaskStore | None = None, graph: Any = None,
                 rules: list[FrontierRule] | None = None, default_ttl: float = 90.0,
                 leads: Any = None):
        self.store = store or InMemoryTaskStore()
        self._graph = graph
        self.rules = rules if rules is not None else default_frontier_rules()
        self.default_ttl = default_ttl
        # Lead registry (Phase 8): classifies discoveries into verifiable leads; the
        # done-condition requires every high-value lead VERIFIED or EXHAUSTED.
        if leads is None:
            from .leads import LeadRegistry
            leads = LeadRegistry()
        self.leads = leads

    @property
    def graph(self):
        if self._graph is None:
            from ..graph.store import get_graph
            self._graph = get_graph()
        return self._graph

    # -- frontier ------------------------------------------------------------- #
    def materialize_frontier(self) -> list[Task]:
        """Run every frontier rule over the current graph and upsert the candidate
        tasks. Returns the tasks that were NEWLY created this call. Idempotent.

        Also derives LEADS from the graph and spawns a verification task per open
        high-value lead (Phase 8) — so an exposed admin console / version-matched
        product doesn't just sit there, it gets verified up the evidence ladder."""
        created: list[Task] = []
        for rule in self.rules:
            try:
                candidates = rule(self.graph)
            except Exception:  # noqa: BLE001 - a bad rule must not break the board
                candidates = []
            for cand in candidates:
                before = self.store.get(cand.id)
                self.store.upsert_frontier(cand)
                if before is None:
                    created.append(cand)
        created += self._materialize_verify_tasks()
        return created

    def _materialize_verify_tasks(self) -> list[Task]:
        """Classify the graph into leads and spawn a verification task for each
        open high-value lead's untried hypotheses. Idempotent (deterministic ids)."""
        created: list[Task] = []
        try:
            self.leads.derive_from_graph(self.graph)
        except Exception:  # noqa: BLE001
            return created
        from .leads import LeadState
        for lead in self.leads.open_highvalue():
            for hyp in lead.hypotheses:
                if hyp.failed:
                    continue
                tid = f"{hyp.verify_kind}:{lead.id}"
                if self.store.get(tid) is not None:
                    continue
                t = Task(id=tid, kind=hyp.verify_kind, target_id=lead.target,
                         priority=1.3, lead_id=lead.id, product=lead.product,
                         version=lead.version,
                         url=lead.target if "://" in lead.target else "")
                self.store.upsert_frontier(t)
                created.append(t)
        return created

    # -- worker-facing pass-throughs (so workers depend only on Board) -------- #
    def claim_next(self, worker_id: str, kinds: Iterable[str] | None = None,
                   ttl: float | None = None) -> Task | None:
        return self.store.claim_next(worker_id, ttl or self.default_ttl, kinds=kinds)

    def heartbeat(self, task_id: str, worker_id: str, ttl: float | None = None) -> bool:
        return self.store.heartbeat(task_id, worker_id, ttl or self.default_ttl)

    def start(self, task_id: str, worker_id: str) -> bool:
        return self.store.start(task_id, worker_id)

    def complete(self, task_id: str, worker_id: str, result_ref: str | None = None) -> bool:
        return self.store.complete(task_id, worker_id, result_ref)

    def fail(self, task_id: str, worker_id: str, note: str = "") -> Task | None:
        return self.store.fail(task_id, worker_id, note=note)

    def block(self, task_id: str, worker_id: str, note: str = "") -> bool:
        return self.store.block(task_id, worker_id, note=note)

    def reap(self) -> list[str]:
        return self.store.reap()

    # -- coverage / done-detection ------------------------------------------- #
    def open_tasks(self) -> list[Task]:
        """Tasks still needing work: frontier / failed / leased (not terminal)."""
        return [t for t in self.store.list() if t.status not in TERMINAL]

    def coverage(self) -> dict[str, Any]:
        counts = self.store.counts()
        total = sum(counts.values())
        terminal = sum(counts.get(str(s), 0) for s in TERMINAL)
        return {"counts": counts, "total": total, "terminal": terminal,
                "open": total - terminal,
                "fraction_done": (counts.get("done", 0) / total) if total else 0.0}

    def is_quiescent(self) -> bool:
        """No open tasks remain (frontier drained, nothing leased/failed). One of the
        conditions the coordinator's done-fixpoint check uses (the others — no new
        frontier after re-materialization, findings consolidated — live in Phase 3)."""
        return not self.open_tasks()


def make_board(graph: Any = None, rules: list[FrontierRule] | None = None,
               default_ttl: float = 90.0) -> Board:
    """Construct a Board. In-memory store by default; a future backend env var
    (SYBER_FLEET_BACKEND=neo4j|postgres) selects a durable cross-process store here
    without changing any caller — matching the platform's graceful-scale-up pattern."""
    import os

    backend = os.environ.get("SYBER_FLEET_BACKEND", "memory").lower()
    store: TaskStore = InMemoryTaskStore()
    if backend in ("neo4j", "postgres"):
        # Durable stores land in a later phase; fall back to in-memory until then so
        # the fleet always runs rather than hard-failing on an unimplemented backend.
        pass
    return Board(store=store, graph=graph, rules=rules, default_ttl=default_ttl)
