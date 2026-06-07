"""
Memory poisoning defence (spec section 11) — MINJA mitigation.

MINJA (Dong et al., NeurIPS 2025, https://arxiv.org/abs/2503.03704) poisons an
agent's memory through query-only interaction. The defence is an append-only,
hash-chained memory store plus a nightly integrity scanner, combined with a
hard write-access restriction: only the orchestrator and response orchestrator
hold `memory_write`. No retrieved-evidence / TI / user-query path can write.

The spec uses Postgres + pgvector. To stay runnable we use SQLite with the
identical chain semantics; the schema and verify_chain logic match spec 11.2.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..config import PATHS

WRITE_PRIVILEGED_AGENTS = {"orchestrator", "response_orchestrator"}


class MemoryWriteDenied(Exception):
    pass


class MemoryStore:
    def __init__(self, db_path: Path | None = None):
        self.path = db_path or PATHS.memory_db
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS memory_store (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_id TEXT, agent_id TEXT, investigation_id TEXT,
                content TEXT, entry_hash TEXT, prev_hash TEXT,
                timestamp_utc TEXT, source_provenance TEXT
            )
            """
        )
        self._conn.commit()

    def _last_hash(self) -> str:
        row = self._conn.execute("SELECT entry_hash FROM memory_store ORDER BY id DESC LIMIT 1").fetchone()
        return row[0] if row else hashlib.sha256(b"SYBER_MEMORY_GENESIS").hexdigest()

    def write(self, entry: dict[str, Any], agent_id: str, investigation_id: str) -> str:
        # Write-access restriction (spec 11.2): only privileged agents may write.
        if agent_id not in WRITE_PRIVILEGED_AGENTS:
            raise MemoryWriteDenied(
                f"agent '{agent_id}' lacks memory_write; only {sorted(WRITE_PRIVILEGED_AGENTS)} may write"
            )
        with self._lock:
            prev_hash = self._last_hash()
            entry_json = json.dumps(entry, sort_keys=True)
            entry_hash = hashlib.sha256((prev_hash + entry_json).encode()).hexdigest()
            self._conn.execute(
                """
                INSERT INTO memory_store
                    (entry_id, agent_id, investigation_id, content,
                     entry_hash, prev_hash, timestamp_utc, source_provenance)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()), agent_id, investigation_id, entry_json,
                    entry_hash, prev_hash, datetime.now(timezone.utc).isoformat(),
                    json.dumps({"agent_id": agent_id, "investigation_id": investigation_id}),
                ),
            )
            self._conn.commit()
            return entry_hash

    def verify_chain(self) -> bool:
        """Nightly integrity scan (spec 11.2). Re-derives each link's hash."""
        rows = self._conn.execute(
            "SELECT entry_hash, prev_hash, content FROM memory_store ORDER BY id ASC"
        ).fetchall()
        for entry_hash, prev_hash, content in rows:
            expected = hashlib.sha256((prev_hash + content).encode()).hexdigest()
            if entry_hash != expected:
                from ..audit.log import get_audit_log
                get_audit_log().write("memory_chain_broken", {"entry_hash": entry_hash}, "memory_integrity")
                return False
        return True

    def all_entries(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT investigation_id, content, timestamp_utc FROM memory_store ORDER BY id ASC"
        ).fetchall()
        return [{"investigation_id": r[0], "content": json.loads(r[1]), "timestamp_utc": r[2]} for r in rows]


class PostgresMemoryStore:
    """Postgres + pgvector memory store (spec §11) — same append-only hash chain
    as the SQLite store, activated by DATABASE_URL. Used so the memory provenance
    chain lives in the production datastore the spec specifies."""

    def __init__(self, dsn: str):
        import psycopg

        self._lock = threading.Lock()
        self._conn = psycopg.connect(dsn, autocommit=True)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS memory_store (
                id BIGSERIAL PRIMARY KEY,
                entry_id TEXT, agent_id TEXT, investigation_id TEXT,
                content TEXT, entry_hash TEXT, prev_hash TEXT,
                timestamp_utc TEXT, source_provenance TEXT
            )
            """
        )

    def _last_hash(self) -> str:
        row = self._conn.execute("SELECT entry_hash FROM memory_store ORDER BY id DESC LIMIT 1").fetchone()
        return row[0] if row else hashlib.sha256(b"SYBER_MEMORY_GENESIS").hexdigest()

    def write(self, entry: dict[str, Any], agent_id: str, investigation_id: str) -> str:
        if agent_id not in WRITE_PRIVILEGED_AGENTS:
            raise MemoryWriteDenied(
                f"agent '{agent_id}' lacks memory_write; only {sorted(WRITE_PRIVILEGED_AGENTS)} may write"
            )
        with self._lock:
            prev_hash = self._last_hash()
            entry_json = json.dumps(entry, sort_keys=True)
            entry_hash = hashlib.sha256((prev_hash + entry_json).encode()).hexdigest()
            self._conn.execute(
                "INSERT INTO memory_store (entry_id, agent_id, investigation_id, content, "
                "entry_hash, prev_hash, timestamp_utc, source_provenance) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (str(uuid.uuid4()), agent_id, investigation_id, entry_json, entry_hash, prev_hash,
                 datetime.now(timezone.utc).isoformat(),
                 json.dumps({"agent_id": agent_id, "investigation_id": investigation_id})),
            )
            return entry_hash

    def verify_chain(self) -> bool:
        rows = self._conn.execute(
            "SELECT entry_hash, prev_hash, content FROM memory_store ORDER BY id ASC"
        ).fetchall()
        for entry_hash, prev_hash, content in rows:
            if entry_hash != hashlib.sha256((prev_hash + content).encode()).hexdigest():
                from ..audit.log import get_audit_log
                get_audit_log().write("memory_chain_broken", {"entry_hash": entry_hash}, "memory_integrity")
                return False
        return True

    def all_entries(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT investigation_id, content, timestamp_utc FROM memory_store ORDER BY id ASC"
        ).fetchall()
        return [{"investigation_id": r[0], "content": json.loads(r[1]), "timestamp_utc": r[2]} for r in rows]


_singleton: "MemoryStore | PostgresMemoryStore | None" = None


def get_memory_store() -> "MemoryStore | PostgresMemoryStore":
    """Postgres when DATABASE_URL is set and reachable (spec §11), else SQLite."""
    global _singleton
    if _singleton is None:
        dsn = os.environ.get("DATABASE_URL")
        if dsn:
            try:
                _singleton = PostgresMemoryStore(dsn)
            except Exception as exc:  # noqa: BLE001 - fall back to SQLite
                import sys
                print(f"[memory] DATABASE_URL set but connection failed ({exc}); using SQLite", file=sys.stderr)
                _singleton = MemoryStore()
        else:
            _singleton = MemoryStore()
    return _singleton
