"""
Immutable audit log (spec section 14).

Append-only, hash-chained, HMAC-signed. Each entry commits to the previous
entry's signature, so any tampering with history is detectable by re-walking
the chain. The spec writes entries to object-locked storage (WORM); here we use
an append-only JSONL file plus an in-memory mirror, with the same chain logic.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any

try:
    import fcntl  # POSIX file locking for multi-process safety
except ImportError:  # pragma: no cover - non-POSIX
    fcntl = None  # type: ignore

from ..config import PATHS


class AuditLog:
    def __init__(self, storage_dir: Path | None = None, signing_key: bytes | None = None):
        self.dir = storage_dir or PATHS.audit
        self.dir.mkdir(parents=True, exist_ok=True)
        # In a real deployment the signing key is retrieved from an HSM at
        # startup (spec 4.2). Here it is derived deterministically for the demo.
        self.signing_key = signing_key or hashlib.sha256(b"syber-audit-signing-key").digest()
        self._lock = threading.Lock()
        self._path = self.dir / "audit.jsonl"
        self._last_hash = self._genesis_hash()

    def _genesis_hash(self) -> str:
        if self._path.exists():
            last = None
            for line in self._path.read_text().splitlines():
                if line.strip():
                    last = line
            if last:
                try:
                    return json.loads(last)["signature"]
                except (json.JSONDecodeError, KeyError):
                    pass
        return hashlib.sha256(b"SYBER_GENESIS").hexdigest()

    def _last_hash_on_disk(self) -> str:
        """Read the most recent entry's signature directly from the file, so the
        chain stays valid even when another process appended since we last wrote
        (the orchestrator and the MCP-server subprocess share this file)."""
        try:
            with open(self._path, "rb") as fh:
                last = None
                for raw in fh:
                    if raw.strip():
                        last = raw
                if last:
                    return json.loads(last)["signature"]
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            pass
        return hashlib.sha256(b"SYBER_GENESIS").hexdigest()

    def write(self, event_type: str, data: dict[str, Any], agent_id: str = "orchestrator") -> str:
        with self._lock:
            # Open for append and take an exclusive OS lock so concurrent writers
            # (separate processes) cannot interleave and fork the hash chain.
            with open(self._path, "a") as fh:
                if fcntl is not None:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
                try:
                    prev_hash = self._last_hash_on_disk()
                    entry = {
                        "log_id": str(uuid.uuid4()),
                        "event_type": event_type,
                        "agent_id": agent_id,
                        "timestamp_us": int(time.time() * 1e6),
                        "data": data,
                        "prev_hash": prev_hash,
                    }
                    entry_bytes = json.dumps(entry, sort_keys=True, default=str).encode()
                    entry["signature"] = hmac.new(self.signing_key, entry_bytes, "sha256").hexdigest()
                    fh.write(json.dumps(entry, default=str) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                    self._last_hash = entry["signature"]
                finally:
                    if fcntl is not None:
                        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            return entry["log_id"]

    # -- convenience writers referenced across the spec --------------------- #
    def write_tool_call(self, tool: str, args: dict, scope: Any = None) -> str:
        return self.write("tool_call", {"tool": tool, "args": args, "scope": getattr(scope, "investigation_id", None)})

    def write_scope_violation(self, tool: str, args: dict) -> str:
        return self.write("scope_violation", {"tool": tool, "args": args}, agent_id="scope_guard")

    def write_injection_probe(self, chunk: str, score: float) -> str:
        return self.write("injection_probe_detected", {"chunk": chunk[:500], "score": score}, agent_id="injection_guard")

    def write_injection_probe_detected(self, quarantined: list[str], args: dict) -> str:
        return self.write("injection_quarantine", {"count": len(quarantined), "args": args}, agent_id="injection_guard")

    def write_ti_rejection(self, doc: dict, reason: str, detail: str) -> str:
        return self.write("ti_rejection", {"reason": reason, "detail": detail}, agent_id="ti_integrity")

    def write_step_execution(self, step: dict, result: dict) -> str:
        return self.write("response_step", {"step_id": step.get("step_id"), "result": result}, agent_id="response_orchestrator")

    def write_rollback(self, step: dict) -> str:
        return self.write("rollback", {"step_id": step.get("step_id")}, agent_id="response_orchestrator")

    def write_rollback_failure(self, step: dict, err: Exception) -> str:
        return self.write("rollback_failure", {"step_id": step.get("step_id"), "error": str(err)}, agent_id="response_orchestrator")

    # -- integrity verification -------------------------------------------- #
    def verify_chain(self) -> bool:
        if not self._path.exists():
            return True
        prev = hashlib.sha256(b"SYBER_GENESIS").hexdigest()
        for line in self._path.read_text().splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            sig = entry.pop("signature")
            if entry["prev_hash"] != prev:
                return False
            recomputed = hmac.new(self.signing_key, json.dumps(entry, sort_keys=True, default=str).encode(), "sha256").hexdigest()
            if recomputed != sig:
                return False
            prev = sig
        return True


_singleton: AuditLog | None = None


def get_audit_log() -> AuditLog:
    global _singleton
    if _singleton is None:
        _singleton = AuditLog()
    return _singleton
