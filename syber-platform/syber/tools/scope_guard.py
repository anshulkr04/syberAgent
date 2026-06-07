"""
Investigation scope enforcement (spec section 3.4 / 6.3).

Every tool consults the active InvestigationScope before returning data. The
scope bounds an investigation to a fixed set of entities and a time window so a
prompt-injected instruction cannot pivot the agent onto out-of-scope data
(spec 15.1 scope_violation test case).
"""
from __future__ import annotations

import contextvars
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable


@dataclass
class InvestigationScope:
    investigation_id: str
    allowed_entities: set[str] = field(default_factory=set)
    allowed_node_ids: set[str] = field(default_factory=set)
    time_start_utc: str = ""
    time_end_utc: str = ""

    def allows_entity(self, entity_id: str) -> bool:
        # Empty allow-list means "scope not yet narrowed" -> permit (demo-friendly),
        # but a populated list is strictly enforced.
        return not self.allowed_entities or entity_id in self.allowed_entities

    def allows_time(self, ts_iso: str) -> bool:
        if not (self.time_start_utc and self.time_end_utc):
            return True
        try:
            t = _parse(ts_iso)
            return _parse(self.time_start_utc) <= t <= _parse(self.time_end_utc)
        except ValueError:
            return True

    def add_entities(self, entities: Iterable[str]) -> None:
        self.allowed_entities.update(entities)


def _parse(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


# Scope travels with the in-process tool call via a context variable, mirroring
# the spec's get_current_scope() / set_current_scope().
_current: contextvars.ContextVar[InvestigationScope | None] = contextvars.ContextVar(
    "syber_current_scope", default=None
)


def set_current_scope(scope: InvestigationScope) -> None:
    _current.set(scope)


def get_current_scope() -> InvestigationScope:
    scope = _current.get()
    if scope is None:
        raise RuntimeError("No active investigation scope set (call set_current_scope).")
    return scope
