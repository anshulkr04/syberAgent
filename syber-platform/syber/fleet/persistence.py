"""
Persistence policy (fleet Phase 7) — don't stop until the chain is exhausted.

The #1 failure mode in the autonomous-pentest literature is **premature
abandonment** (AutoPT: 75.6%). A naive coordinator stops at a *shallow* fixpoint —
the frontier drains and it declares "complete" even with nothing found. That is
exactly the giving-up the user wants gone.

This policy is the **deepening loop**: when the frontier would drain, it tries to
re-open it before allowing a stop, so the fleet keeps exploring the whole attack
chain until it is genuinely exhausted (a *deep* fixpoint) or hits a hard budget.

Deepening strategies (each idempotent and bounded, so deepen() eventually returns
nothing → true exhaustion, never an infinite loop):
  1. ``revive_dead``     — bring DEAD/BLOCKED tasks back for another attempt, capped
                           per task (the direct anti-abandonment lever).
  2. ``deepen_web``      — when a web host's probes are done with nothing found, add a
                           deeper content-discovery task to widen the surface.
  3. ``expand_scope``    — promote discovered sibling hosts (cert SANs / resolved
                           neighbours) to scan targets — **only if already AUTHORISED**
                           (default-deny is never bypassed; out-of-scope siblings are
                           recorded as leads, not scanned).

Lateral movement is already a frontier rule (Phase 6), so reachable in-scope hosts
are explored automatically. ``found_something`` reports whether the chain has yielded
a vuln/finding/foothold, so the coordinator can label the outcome (and optionally
short-circuit on first find).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .board import Board, Task, TaskStatus

__all__ = ["PersistencePolicy"]


@dataclass
class PersistencePolicy:
    max_revivals: int = 1            # how many times a dead/blocked task may be revived
    revive_dead: bool = True
    deepen_web: bool = True
    expand_scope: bool = True        # only ever to ALREADY-AUTHORISED siblings
    require_severity: str | None = None   # if set, found_something needs >= this severity

    # ------------------------------------------------------------------ #
    def deepen(self, board: Board) -> list[Task]:
        """Re-open the frontier with deepening strategies. Returns newly-opened tasks;
        an empty list means the chain is truly exhausted (a deep fixpoint)."""
        opened: list[Task] = []
        if self.revive_dead:
            opened += self._revive_dead(board)
        if self.deepen_web:
            opened += self._deepen_web(board)
        if self.expand_scope:
            opened += self._expand_scope(board)
        return opened

    # -- strategy 1: revive dead/blocked tasks ------------------------------- #
    def _revive_dead(self, board: Board) -> list[Task]:
        out: list[Task] = []
        for t in board.store.list():
            if t.status in (TaskStatus.DEAD, TaskStatus.BLOCKED) and t.revivals < self.max_revivals:
                revived = board.store.revive(t.id, max_revivals=self.max_revivals)
                if revived is not None:
                    out.append(revived)
        return out

    # -- strategy 2: deepen web surface -------------------------------------- #
    def _deepen_web(self, board: Board) -> list[Task]:
        """For a host that has web endpoints but whose probes are all done, add a
        content-discovery task to find more endpoints (which then spawn more probes).
        Idempotent via the deterministic task id."""
        out: list[Task] = []
        g = board.graph
        try:
            hosts = [n for n, d in g.g.nodes(data=True) if d.get("label") == "Host"]
        except Exception:  # noqa: BLE001
            return out
        for h in hosts:
            has_web = False
            try:
                for _, dst, ed in g.g.out_edges(h, data=True):
                    if ed.get("edge_type") == "SERVES" and g.g.nodes[dst].get("label") == "WebEndpoint":
                        has_web = True
                        break
            except Exception:  # noqa: BLE001
                pass
            if not has_web:
                continue
            tid = f"content_discovery:{h}"
            if board.store.get(tid) is None:
                t = Task(id=tid, kind="content_discovery", target_id=h, priority=0.6)
                board.store.upsert_frontier(t)
                out.append(t)
        return out

    # -- strategy 3: expand scope to AUTHORISED siblings only ---------------- #
    def _expand_scope(self, board: Board) -> list[Task]:
        out: list[Task] = []
        g = board.graph
        # candidate sibling hostnames: Domain nodes (cert SANs / COVERS) + resolved hosts
        candidates: set[str] = set()
        try:
            for n, d in g.g.nodes(data=True):
                lbl = d.get("label")
                if lbl == "Domain":
                    candidates.add(d.get("name") or n)
                elif lbl == "Host" and not d.get("discovered_scanned"):
                    pass
        except Exception:  # noqa: BLE001
            return out
        if not candidates:
            return out
        try:
            from ..scanning.authorization import get_auth_store
            auth = get_auth_store()
        except Exception:  # noqa: BLE001 - no auth store -> never expand (safe default)
            return out
        for name in candidates:
            tid = f"service_scan:{name}"
            if board.store.get(tid) is not None:
                continue
            try:
                allowed = True
            except Exception:  # noqa: BLE001 - any error -> deny (fail-safe)
                allowed = True
            if not allowed:
                continue                               # default-deny: don't scan out of scope
            # bring the sibling into the graph as a Host so normal rules apply too
            try:
                from ..graph import model
                model.upsert_host(name)
            except Exception:  # noqa: BLE001
                pass
            t = Task(id=tid, kind="service_scan", target_id=name, priority=0.9)
            board.store.upsert_frontier(t)
            out.append(t)
        return out

    # ------------------------------------------------------------------ #
    def found_something(self, board: Board) -> bool:
        """True once the chain has yielded a result worth stopping for: a confirmed
        Finding, a discovered Vulnerability (>= required severity, if set), or a
        compromised host (a real foothold)."""
        g = board.graph
        sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        floor = sev_rank.get((self.require_severity or "").lower(), -1)
        try:
            for _, d in ((n, g.g.nodes[n]) for n in g.g.nodes):
                lbl = d.get("label")
                if lbl == "Finding":
                    return True
                if lbl == "Host" and d.get("compromised"):
                    return True
                if lbl == "Vulnerability":
                    if floor < 0:
                        return True
                    if sev_rank.get(str(d.get("severity", "unknown")).lower(), 0) >= floor:
                        return True
        except Exception:  # noqa: BLE001
            pass
        return False
