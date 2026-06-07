"""
Security Data Lake (spec section 5).

The spec stores CSIM-normalised events as Apache Parquet (Arrow hot tier,
DuckDB warm tier) partitioned by (date, entity_bucket=murmur3(entity)%256).
To stay dependency-light and runnable, this is an in-memory column-light store
with the SAME query contract: "all events for entity X in [T1,T2], optionally
filtered by event_class". The partition key is computed exactly as specified.
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any


def entity_bucket(entity_id: str) -> int:
    """Spec 5.3: entity_bucket = hash(entity_id) % 256 (murmur3 -> sha256 here)."""
    h = hashlib.sha256(entity_id.encode()).digest()
    return int.from_bytes(h[:4], "big") % 256


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


class SecurityDataLake:
    def __init__(self) -> None:
        self._events: list[dict[str, Any]] = []

    def ingest(self, csim_event: dict[str, Any]) -> None:
        ev = dict(csim_event)
        ev.setdefault("raw_ref", "sha256:" + hashlib.sha256(
            repr(sorted(ev.items())).encode()).hexdigest()[:16])
        ev["_bucket"] = entity_bucket(ev.get("entity", {}).get("id", ""))
        self._events.append(ev)

    def bulk_ingest(self, events: list[dict[str, Any]]) -> None:
        for e in events:
            self.ingest(e)

    def query(
        self,
        entity_id: str,
        time_window_start_utc: str | None = None,
        time_window_end_utc: str | None = None,
        event_classes: list[str] | None = None,
        max_results: int = 500,
        scope: Any = None,
        **_: Any,
    ) -> list[dict[str, Any]]:
        """Return CSIM events for an entity in a window (spec 3.4 contract)."""
        start = _parse(time_window_start_utc) if time_window_start_utc else None
        end = _parse(time_window_end_utc) if time_window_end_utc else None
        classes = set(event_classes) if event_classes else None

        out: list[dict[str, Any]] = []
        for ev in self._events:
            ent = ev.get("entity", {})
            target = ev.get("target_resource", {})
            # Match if the entity is the actor OR the target of the event.
            if entity_id not in {ent.get("id"), target.get("id")}:
                continue
            if classes and ev.get("event_class") not in classes:
                continue
            ts = ev.get("timestamp_utc")
            if ts and (start or end):
                t = _parse(ts)
                if start and t < start:
                    continue
                if end and t > end:
                    continue
            out.append(ev)
            if len(out) >= max_results:
                break

        out.sort(key=lambda e: e.get("timestamp_utc", ""))
        # Each row is returned with a content rendering for the injection filter
        # to scan (spec 3.4 data_lake.query -> r["content"]).
        for ev in out:
            ev["content"] = _render(ev)
        return out

    def count(self) -> int:
        return len(self._events)


def _render(ev: dict[str, Any]) -> str:
    ent = ev.get("entity", {})
    tgt = ev.get("target_resource", {})
    return (
        f"[{ev.get('timestamp_utc')}] {ev.get('event_class')}/{ev.get('event_subclass')} "
        f"actor={ent.get('id')} target={tgt.get('id')}({tgt.get('hostname','')}) "
        f"src_ip={ev.get('source_ip')} outcome={ev.get('outcome')} "
        f"risk={','.join(ev.get('risk_indicators', []))} ref={ev.get('raw_ref')}"
        + (f" :: {ev.get('note')}" if ev.get("note") else "")
    )


_singleton: SecurityDataLake | None = None


def get_data_lake() -> SecurityDataLake:
    global _singleton
    if _singleton is None:
        _singleton = SecurityDataLake()
    return _singleton
