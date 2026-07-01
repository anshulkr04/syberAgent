"""
Tool-call recall ledger — "you already ran this; don't repeat it."

The single biggest source of wasted agent loops is re-issuing a call that was
already made (same tool, same args) and getting the same answer. VulnClaw fixes
this with a blackboard tool-call ledger surfaced back into the prompt; this is the
same idea as a small, thread-safe, process-lifetime store the MCP layer writes to
on every call and the agent can query.

  * ``record`` — log a (tool, args) call with a one-line outcome summary.
  * ``lookup`` — return the prior record for an identical (tool, args), or None.
  * ``recent`` / ``summarize`` — a compact dedup view for the agent's context.

Keyed by a stable hash of tool name + normalised args (order-independent), capped
LRU so it can't grow unbounded. Pure in-memory; no persistence (a single
engagement's lifetime is the useful scope, and it must never become a stale cache
across targets). Best-effort: recording never raises into a tool call.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

__all__ = ["CallRecord", "CallLedger", "get_ledger", "record", "lookup",
           "recent", "summarize"]


def _key(tool: str, args: dict[str, Any] | None) -> str:
    try:
        norm = json.dumps(args or {}, sort_keys=True, default=str)
    except (TypeError, ValueError):
        norm = str(sorted((args or {}).items()))
    return hashlib.sha1(f"{tool}\x00{norm}".encode()).hexdigest()[:16]


@dataclass
class CallRecord:
    tool: str
    args: dict[str, Any]
    summary: str = ""
    status: str = ""                 # e.g. "ok" | "error" | a status code
    count: int = 1                   # how many times this exact call was made
    first_ts: float = field(default_factory=time.time)
    last_ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {"tool": self.tool, "args": self.args, "summary": self.summary,
                "status": self.status, "count": self.count,
                "age_s": round(time.time() - self.first_ts, 1)}


class CallLedger:
    def __init__(self, capacity: int = 500):
        self.capacity = capacity
        self._store: "OrderedDict[str, CallRecord]" = OrderedDict()
        self._lock = threading.Lock()

    def record(self, tool: str, args: dict[str, Any] | None = None,
               summary: str = "", status: str = "") -> CallRecord:
        k = _key(tool, args)
        with self._lock:
            rec = self._store.get(k)
            if rec is not None:
                rec.count += 1
                rec.last_ts = time.time()
                if summary:
                    rec.summary = summary
                if status:
                    rec.status = status
                self._store.move_to_end(k)
                return rec
            rec = CallRecord(tool=tool, args=dict(args or {}), summary=summary, status=status)
            self._store[k] = rec
            self._store.move_to_end(k)
            while len(self._store) > self.capacity:
                self._store.popitem(last=False)
            return rec

    def lookup(self, tool: str, args: dict[str, Any] | None = None) -> CallRecord | None:
        with self._lock:
            return self._store.get(_key(tool, args))

    def seen(self, tool: str, args: dict[str, Any] | None = None) -> bool:
        return self.lookup(tool, args) is not None

    def recent(self, limit: int = 30) -> list[CallRecord]:
        with self._lock:
            return list(reversed(list(self._store.values())))[:limit]

    def summarize(self, limit: int = 30) -> str:
        recs = self.recent(limit)
        if not recs:
            return "no tool calls recorded yet"
        lines = ["already executed (do not repeat without a reason):"]
        for r in recs:
            arg = ""
            for kk in ("url", "target", "host", "domain"):
                if r.args.get(kk):
                    arg = str(r.args[kk])
                    break
            tag = f"×{r.count}" if r.count > 1 else ""
            lines.append(f"  - {r.tool}({arg}) {tag} -> {r.status or '?'} {r.summary}".rstrip())
        return "\n".join(lines)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()


_ledger: CallLedger | None = None


def get_ledger() -> CallLedger:
    global _ledger
    if _ledger is None:
        _ledger = CallLedger()
    return _ledger


def record(tool: str, args: dict[str, Any] | None = None, summary: str = "",
           status: str = "") -> CallRecord | None:
    try:
        return get_ledger().record(tool, args, summary=summary, status=status)
    except Exception:  # noqa: BLE001 - recall must never break a tool call
        return None


def lookup(tool: str, args: dict[str, Any] | None = None) -> CallRecord | None:
    return get_ledger().lookup(tool, args)


def recent(limit: int = 30) -> list[CallRecord]:
    return get_ledger().recent(limit)


def summarize(limit: int = 30) -> str:
    return get_ledger().summarize(limit)
