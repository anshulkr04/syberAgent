"""
The coordinator (fleet Phase 3) — the persistent parallel loop.

This is the lead/orchestrator: it runs the engagement as a sequence of **waves**,
each wave a parallel fan-out of workers over a disjoint batch the planner chose,
pooling their evidence into the graph (the blackboard), then re-dividing — until a
coverage **fixpoint** or a budget stop. It is the piece no published pentest system
ships: every wave is concurrent (research_papers.md Part 3), not the sequential
specialist dispatch of HPTSA/VulnBot/AutoPT.

What it owns (research_persistence.md Part 2/3):
  * **Wave loop**: materialize frontier → plan disjoint batch → claim+dispatch in
    parallel → workers write to graph → re-materialize → checkpoint → repeat.
  * **Budgets**: per-engagement (waves / time / tasks) and per-worker (time), with a
    hard stop, not just an alert.
  * **Stuck/loop recovery**: a worker that loops or fails is requeued with a
    reflexion note; after ``max_attempts`` it dead-letters and (if wired) escalates
    to HITL. ``StuckDetector`` is the reusable action-hash + empty-coverage-delta
    monitor specialists feed their steps into.
  * **Durable checkpoint/resume**: the whole engagement is reconstructable from the
    task snapshot + the graph; on restart it resumes, never restarts (expired leases
    are reaped, done work is never re-run).
  * **Done = coverage fixpoint** (research §3.6): no open tasks AND re-materializing
    the frontier yields nothing new — not the agent "feeling" finished.

The worker is INJECTED (``WorkerFn``) so this phase is fully testable without an
LLM; the real specialist workers arrive in Phase 4. The default worker is a safe
no-op that marks tasks done, so the loop is runnable end-to-end immediately.
"""
from __future__ import annotations

import json
import os
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable

from .board import Board, Task, TaskStatus
from .persistence import PersistencePolicy
from .planner import Planner, ScoredTask

__all__ = ["WorkerResult", "WorkerFn", "EngagementBudget", "StuckDetector",
           "Coordinator", "PersistencePolicy"]


# --------------------------------------------------------------------------- #
# Worker contract
# --------------------------------------------------------------------------- #
@dataclass
class WorkerResult:
    """What a worker returns. Evidence is written to the GRAPH directly (pooling on
    the blackboard); this just reports the task outcome + telemetry."""
    status: str = "done"             # "done" | "failed" | "blocked"
    result_ref: str | None = None
    note: str = ""
    looped: bool = False             # the worker detected it was spinning
    steps: int = 0
    tokens: int = 0


# A worker claims nothing itself — the coordinator already claimed the task and
# passes it in with the worker_id whose lease it holds.
WorkerFn = Callable[[Task, Board, str], WorkerResult]


def _noop_worker(task: Task, board: Board, worker_id: str) -> WorkerResult:
    """Default safe worker: marks the task done with no side effects. Lets the loop
    run end-to-end before real specialists exist (Phase 4)."""
    return WorkerResult(status="done", result_ref=None, note="noop")


# --------------------------------------------------------------------------- #
# Budgets + stuck detection
# --------------------------------------------------------------------------- #
@dataclass
class EngagementBudget:
    max_waves: int = 50
    max_seconds: float = 3600.0
    max_tasks: int = 2000             # total task *dispatches* across the run
    worker_lease_s: float = 900.0     # lease length per dispatched task
    max_stall_waves: int = 3          # consecutive no-progress waves -> stop


class StuckDetector:
    """Action-hash + empty-coverage-delta loop detector (AutoPentester repetition
    identifier / research_persistence §3.3). A specialist feeds each step; ``record``
    returns True once the recent window is all-repeats or all-no-progress."""

    def __init__(self, window: int = 3):
        self.window = max(2, window)
        self._actions: deque[str] = deque(maxlen=self.window)
        self._progress: deque[bool] = deque(maxlen=self.window)

    def record(self, action_hash: str, made_progress: bool) -> bool:
        self._actions.append(action_hash)
        self._progress.append(bool(made_progress))
        if len(self._actions) < self.window:
            return False
        all_same = len(set(self._actions)) == 1
        no_progress = not any(self._progress)
        return all_same or no_progress

    def reset(self) -> None:
        self._actions.clear()
        self._progress.clear()


# --------------------------------------------------------------------------- #
# Coordinator
# --------------------------------------------------------------------------- #
class Coordinator:
    def __init__(self, board: Board, planner: Planner | None = None, *,
                 worker: WorkerFn | None = None, budget: EngagementBudget | None = None,
                 concurrency: int = 8, hitl: Callable[[Task], None] | None = None,
                 checkpoint_path: str | None = None, clock: Callable[[], float] = time.time,
                 engagement_id: str = "eng",
                 persistence: PersistencePolicy | None = None,
                 stop_on_first_find: bool = False):
        self.board = board
        self.planner = planner or Planner(board)
        self.worker = worker or _noop_worker
        self.budget = budget or EngagementBudget()
        self.concurrency = max(1, concurrency)
        self.hitl = hitl
        self.checkpoint_path = checkpoint_path
        self.clock = clock
        self.engagement_id = engagement_id
        # Persistence: when set, a would-be (shallow) fixpoint triggers deepening
        # strategies before the run is allowed to stop — so the fleet keeps exploring
        # the whole attack chain instead of giving up early.
        self.persistence = persistence
        self.stop_on_first_find = stop_on_first_find
        # run state (all reconstructable from a checkpoint)
        self.wave = 0
        self.dispatched = 0
        self.started_at = 0.0
        self.dead_lettered: list[str] = []
        self._stall = 0
        self._wid = 0
        self._wid_lock = threading.Lock()
        self._call_start = 0.0       # start of THIS run() call (per-call time budget)

    # ------------------------------------------------------------------ #
    def _worker_id(self) -> str:
        with self._wid_lock:
            self._wid += 1
            return f"w{self._wid}"

    def _budget_exhausted(self) -> str | None:
        if self.wave >= self.budget.max_waves:
            return "max_waves"
        if self.dispatched >= self.budget.max_tasks:
            return "max_tasks"
        # Time budget is PER-CALL (from this run() invocation), not cumulative — so a
        # resumed call gets a fresh window instead of expiring instantly because the
        # original started_at (restored from the checkpoint) is already old. (run()
        # always sets _call_start before the loop, so no truthiness guard — a clock
        # that legitimately reads 0.0 must still be honoured.)
        if (self.clock() - self._call_start) >= self.budget.max_seconds:
            return "max_seconds"
        return None

    # ------------------------------------------------------------------ #
    def _run_one(self, task: Task, worker_id: str) -> None:
        """Execute one claimed task: run the worker, translate its result into a
        board transition. Any exception fails (and possibly dead-letters) the task —
        a crashing worker never wedges the wave."""
        self.board.start(task.id, worker_id)
        try:
            res = self.worker(task, self.board, worker_id)
        except Exception as e:  # noqa: BLE001 - isolate worker crashes
            res = WorkerResult(status="failed", note=f"worker exception: {e}")

        if res.status == "done" and not res.looped:
            self.board.complete(task.id, worker_id, result_ref=res.result_ref)
            return
        if res.status == "blocked":
            self.board.block(task.id, worker_id, note=res.note or "blocked")
            return
        # failed or looped -> requeue with a reflexion note; may dead-letter.
        note = res.note or ("looping — change approach" if res.looped else "failed")
        outcome = self.board.fail(task.id, worker_id, note=note)
        if outcome is not None and outcome.status == TaskStatus.DEAD:
            self.dead_lettered.append(task.id)
            if self.hitl is not None:
                try:
                    self.hitl(outcome)
                except Exception:  # noqa: BLE001 - HITL hook must not break the loop
                    pass

    def _dispatch_wave(self, batch: list[ScoredTask]) -> int:
        """Claim each batch task and run the wave in parallel. Returns the number of
        tasks actually dispatched (claims can lose to dep-gating / expired state)."""
        claimed: list[tuple[Task, str]] = []
        for st in batch:
            wid = self._worker_id()
            t = self.board.store.claim(st.task.id, wid, ttl=self.budget.worker_lease_s)
            if t is not None:
                claimed.append((t, wid))
        if not claimed:
            return 0
        if self.concurrency == 1 or len(claimed) == 1:
            for t, wid in claimed:          # deterministic path (tests / serial mode)
                self._run_one(t, wid)
        else:
            with ThreadPoolExecutor(max_workers=min(self.concurrency, len(claimed))) as pool:
                futs = [pool.submit(self._run_one, t, wid) for t, wid in claimed]
                for f in futs:
                    f.result()
        self.dispatched += len(claimed)
        return len(claimed)

    # ------------------------------------------------------------------ #
    def run(self) -> dict[str, Any]:
        """Run the engagement to a coverage fixpoint or a budget stop."""
        if self.checkpoint_path:
            self._restore()
        self._call_start = self.clock()
        if not self.started_at:
            self.started_at = self.clock()

        status = "complete"
        self.board.materialize_frontier()
        while True:
            stop = self._budget_exhausted()
            if stop:
                status = stop
                break

            self.board.reap()                       # reclaim dead/expired leases
            batch = self.planner.next_batch()
            if not batch:
                # frontier empty: re-materialize; if still nothing, try to DEEPEN
                # before giving up (persistence) so we don't stop at a shallow fixpoint.
                if self.board.materialize_frontier():
                    continue
                if self.persistence is not None and self.persistence.deepen(self.board):
                    continue                         # deepening re-opened the frontier
                # THE verification gate: do not finish while a high-value lead is
                # unverified. An exposed admin console / version-matched product is a
                # lead that MUST be verified or exhausted first (research_verify §2.4).
                if not self._highvalue_leads_resolved():
                    if self.board.materialize_frontier():   # spawn their verify tasks
                        continue
                    # nothing left to spawn but leads still open -> exhaust them so the
                    # engagement can converge (they were genuinely un-runnable here).
                    self._exhaust_stuck_leads()
                    continue
                status = "complete"                  # deep fixpoint: chain exhausted
                break

            n = self._dispatch_wave(batch)
            new = self.board.materialize_frontier()  # pool: new facts -> new frontier
            self.wave += 1
            self._checkpoint()

            # optional early success: stop as soon as the chain yields a result.
            if self.stop_on_first_find and self.persistence is not None \
                    and self.persistence.found_something(self.board):
                status = "found"
                break

            # stall guard: a wave that dispatched nothing and opened no frontier.
            if n == 0 and not new:
                self._stall += 1
                if self._stall >= self.budget.max_stall_waves:
                    status = "stalled"
                    break
            else:
                self._stall = 0

        self._checkpoint()
        return self.summary(status)

    def _highvalue_leads_resolved(self) -> bool:
        try:
            return self.board.leads.no_open_highvalue_lead()
        except Exception:  # noqa: BLE001 - no registry -> don't block (back-compat)
            return True

    def _exhaust_stuck_leads(self) -> None:
        """Mark any still-open high-value lead EXHAUSTED with a logged reason — used
        only when no verify task can be spawned for it (e.g. an LLM-only lead the
        deterministic runners can't auto-verify). The lead survives in the registry
        for the LLM verify subagent / report; this just lets the loop converge."""
        try:
            from .board import TERMINAL
            for lead in self.board.leads.open_highvalue():
                # leave it OPEN if a verify task for it is still pending/active
                pending = False
                for h in lead.hypotheses:
                    t = self.board.store.get(f"{h.verify_kind}:{lead.id}")
                    if t is not None and t.status not in TERMINAL:
                        pending = True
                        break
                if pending:
                    continue
                self.board.leads.mark_exhausted(
                    lead.id, note="deterministic verification exhausted; hand to LLM verify subagent")
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------ #
    def summary(self, status: str) -> dict[str, Any]:
        cov = self.board.coverage()
        found = self.persistence.found_something(self.board) if self.persistence else None
        done = status in ("complete", "found") and cov["open"] == 0
        # A budget stop with work still open is RESUMABLE — call run() again (it
        # reloads the checkpoint and continues from the wave boundary).
        resumable = (not done) and cov["open"] > 0 and status in (
            "max_seconds", "max_waves", "max_tasks")
        return {"engagement_id": self.engagement_id, "status": status,
                "waves": self.wave, "dispatched": self.dispatched,
                "dead_lettered": list(self.dead_lettered),
                "elapsed_s": round((self.clock() - self.started_at), 2) if self.started_at else 0.0,
                "coverage": cov, "found": found,
                "done": done, "resumable": resumable}

    # -- durable checkpoint / resume ----------------------------------------- #
    def checkpoint_state(self) -> dict[str, Any]:
        leads = {}
        try:
            leads = self.board.leads.snapshot()
        except Exception:  # noqa: BLE001
            pass
        return {"engagement_id": self.engagement_id, "wave": self.wave,
                "dispatched": self.dispatched, "started_at": self.started_at,
                "dead_lettered": self.dead_lettered, "wid": self._wid,
                "tasks": self.board.store.snapshot(), "leads": leads}

    def _checkpoint(self) -> None:
        if not self.checkpoint_path:
            return
        try:
            os.makedirs(os.path.dirname(self.checkpoint_path) or ".", exist_ok=True)
            tmp = self.checkpoint_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.checkpoint_state(), fh)
            os.replace(tmp, self.checkpoint_path)    # atomic
        except Exception:  # noqa: BLE001 - a failed checkpoint must not stop the run
            pass

    def _restore(self) -> None:
        if not self.checkpoint_path or not os.path.isfile(self.checkpoint_path):
            return
        try:
            with open(self.checkpoint_path, encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:  # noqa: BLE001
            return
        self.wave = data.get("wave", 0)
        self.dispatched = data.get("dispatched", 0)
        self.started_at = data.get("started_at", 0.0)
        self.dead_lettered = list(data.get("dead_lettered", []))
        self._wid = data.get("wid", 0)
        snap = data.get("tasks")
        if snap and hasattr(self.board.store, "restore"):
            self.board.store.restore(snap)
        leadsnap = data.get("leads")
        if leadsnap:
            try:
                self.board.leads.restore(leadsnap)
            except Exception:  # noqa: BLE001
                pass
        # expired leases from before the crash are reclaimed on the next reap().
