"""
cf_clearance cookie store (waf-spec §4.4) — keyed by (domain, IP, User-Agent).

Once a Cloudflare challenge is solved, the resulting ``cf_clearance`` cookie is
the single most valuable artefact: replaying it (L2 session reuse) avoids 80–90%
of subsequent challenges (waf-spec §3.6). But Cloudflare binds the cookie to the
*exact* IP and User-Agent that solved the challenge — present it from a different
IP/UA and it is rejected and a fresh challenge is triggered. The store therefore
keys on the (domain, ip, ua) triple and never returns a cookie under a mismatch.

Three backends behind one interface (waf-spec §4.4):
  * InMemoryCookieStore — LRU + TTL, for ephemeral sessions (the default; matches
    the platform's "works with zero external services" posture).
  * SQLiteCookieStore   — single-node persistence across runs.
  * RedisCookieStore    — distributed setups (import-guarded; optional).

All share: get(domain, ip, ua) · set(record) · delete(domain, ip, ua) ·
cleanup_expired(). Expiry is checked on every get so a stale cookie is never
handed back even if cleanup hasn't run yet.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

__all__ = ["CookieRecord", "CookieStore", "InMemoryCookieStore",
           "SQLiteCookieStore", "RedisCookieStore", "make_cookie_store"]


@dataclass
class CookieRecord:
    """One solved-challenge cookie and the identity it is bound to (waf-spec §4.4)."""

    domain: str
    cookie_value: str
    ip_address: str = ""
    user_agent: str = ""
    cookie_name: str = "cf_clearance"
    expires_at: float = 0.0          # epoch seconds; 0 == unknown -> use default TTL
    created_at: float = field(default_factory=time.time)
    challenge_type: str = "js_challenge"

    def key(self) -> tuple[str, str, str]:
        return (self.domain.lower(), self.ip_address, self.user_agent)

    def is_expired(self, now: float | None = None, default_ttl: float = 1800.0) -> bool:
        now = time.time() if now is None else now
        exp = self.expires_at or (self.created_at + default_ttl)
        return now >= exp

    def cookie_header(self) -> str:
        """The value to send as a ``Cookie:`` header (just the cf_clearance pair)."""
        return f"{self.cookie_name}={self.cookie_value}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain, "cookie_name": self.cookie_name,
            "cookie_value": self.cookie_value, "ip_address": self.ip_address,
            "user_agent": self.user_agent, "expires_at": self.expires_at,
            "created_at": self.created_at, "challenge_type": self.challenge_type,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CookieRecord":
        return cls(**{k: d[k] for k in d if k in cls.__dataclass_fields__})


class CookieStore:
    """Backend interface. All methods are thread-safe in the implementations."""

    default_ttl: float = 1800.0

    def get(self, domain: str, ip: str = "", ua: str = "") -> CookieRecord | None:
        raise NotImplementedError

    def set(self, record: CookieRecord) -> None:
        raise NotImplementedError

    def delete(self, domain: str, ip: str = "", ua: str = "") -> None:
        raise NotImplementedError

    def cleanup_expired(self, now: float | None = None) -> int:
        raise NotImplementedError

    # Convenience: the cookie header to attach, or None if nothing valid is stored.
    def cookie_header(self, domain: str, ip: str = "", ua: str = "") -> str | None:
        rec = self.get(domain, ip, ua)
        return rec.cookie_header() if rec else None


class InMemoryCookieStore(CookieStore):
    """LRU + TTL in-memory store (waf-spec §4.4 "in-memory LRU cache")."""

    def __init__(self, max_size: int = 512, default_ttl: float = 1800.0):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._data: "OrderedDict[tuple[str, str, str], CookieRecord]" = OrderedDict()
        self._lock = threading.RLock()

    def get(self, domain: str, ip: str = "", ua: str = "") -> CookieRecord | None:
        key = (domain.lower(), ip, ua)
        with self._lock:
            rec = self._data.get(key)
            if rec is None:
                return None
            if rec.is_expired(default_ttl=self.default_ttl):
                self._data.pop(key, None)
                return None
            self._data.move_to_end(key)        # LRU touch
            return rec

    def set(self, record: CookieRecord) -> None:
        with self._lock:
            self._data[record.key()] = record
            self._data.move_to_end(record.key())
            while len(self._data) > self.max_size:
                self._data.popitem(last=False)  # evict least-recently-used

    def delete(self, domain: str, ip: str = "", ua: str = "") -> None:
        with self._lock:
            self._data.pop((domain.lower(), ip, ua), None)

    def cleanup_expired(self, now: float | None = None) -> int:
        now = time.time() if now is None else now
        with self._lock:
            stale = [k for k, r in self._data.items()
                     if r.is_expired(now, default_ttl=self.default_ttl)]
            for k in stale:
                self._data.pop(k, None)
            return len(stale)


class SQLiteCookieStore(CookieStore):
    """Single-node persistent store (waf-spec §4.4 "SQLite for single-node")."""

    def __init__(self, path: str = ".waf_cookies.sqlite", default_ttl: float = 1800.0):
        self.path = path
        self.default_ttl = default_ttl
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS cf_cookies ("
            " domain TEXT, ip_address TEXT, user_agent TEXT, cookie_name TEXT,"
            " cookie_value TEXT, expires_at REAL, created_at REAL, challenge_type TEXT,"
            " PRIMARY KEY (domain, ip_address, user_agent))")
        self._conn.commit()

    def get(self, domain: str, ip: str = "", ua: str = "") -> CookieRecord | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT domain, ip_address, user_agent, cookie_name, cookie_value,"
                " expires_at, created_at, challenge_type FROM cf_cookies"
                " WHERE domain=? AND ip_address=? AND user_agent=?",
                (domain.lower(), ip, ua))
            row = cur.fetchone()
        if not row:
            return None
        rec = CookieRecord(domain=row[0], ip_address=row[1], user_agent=row[2],
                           cookie_name=row[3], cookie_value=row[4], expires_at=row[5],
                           created_at=row[6], challenge_type=row[7])
        if rec.is_expired(default_ttl=self.default_ttl):
            self.delete(domain, ip, ua)
            return None
        return rec

    def set(self, record: CookieRecord) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO cf_cookies VALUES (?,?,?,?,?,?,?,?)",
                (record.domain.lower(), record.ip_address, record.user_agent,
                 record.cookie_name, record.cookie_value, record.expires_at,
                 record.created_at, record.challenge_type))
            self._conn.commit()

    def delete(self, domain: str, ip: str = "", ua: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM cf_cookies WHERE domain=? AND ip_address=? AND user_agent=?",
                (domain.lower(), ip, ua))
            self._conn.commit()

    def cleanup_expired(self, now: float | None = None) -> int:
        now = time.time() if now is None else now
        with self._lock:
            # expires_at==0 means "unknown" -> expire created_at + default_ttl.
            cur = self._conn.execute(
                "DELETE FROM cf_cookies WHERE (expires_at > 0 AND expires_at <= ?)"
                " OR (expires_at = 0 AND created_at + ? <= ?)",
                (now, self.default_ttl, now))
            self._conn.commit()
            return cur.rowcount


class RedisCookieStore(CookieStore):
    """Distributed store (waf-spec §4.4 "Redis for high-performance distributed").

    Import-guarded: redis is optional. Redis TTL handles expiry natively, so
    cleanup_expired is a no-op. The triple is encoded into the key.
    """

    def __init__(self, redis_url: str = "redis://localhost:6379/0",
                 default_ttl: float = 1800.0, prefix: str = "waf:cf:"):
        import redis  # optional dependency — raises if absent

        self.default_ttl = default_ttl
        self.prefix = prefix
        self._r = redis.Redis.from_url(redis_url, decode_responses=True)

    def _key(self, domain: str, ip: str, ua: str) -> str:
        import hashlib

        ident = hashlib.sha256(f"{domain.lower()}|{ip}|{ua}".encode()).hexdigest()[:24]
        return f"{self.prefix}{ident}"

    def get(self, domain: str, ip: str = "", ua: str = "") -> CookieRecord | None:
        raw = self._r.get(self._key(domain, ip, ua))
        if not raw:
            return None
        rec = CookieRecord.from_dict(json.loads(raw))
        return None if rec.is_expired(default_ttl=self.default_ttl) else rec

    def set(self, record: CookieRecord) -> None:
        ttl = int(max(1.0, (record.expires_at or record.created_at + self.default_ttl) - time.time()))
        self._r.set(self._key(record.domain, record.ip_address, record.user_agent),
                    json.dumps(record.to_dict()), ex=ttl)

    def delete(self, domain: str, ip: str = "", ua: str = "") -> None:
        self._r.delete(self._key(domain, ip, ua))

    def cleanup_expired(self, now: float | None = None) -> int:
        return 0  # Redis TTL handles this natively.


def make_cookie_store(backend: str = "memory", *, redis_url: str = "redis://localhost:6379/0",
                      sqlite_path: str = ".waf_cookies.sqlite",
                      default_ttl: float = 1800.0) -> CookieStore:
    """Build a cookie store from a backend name (waf-spec §5 ``cookie_store.backend``).

    Falls back to the in-memory store on any backend-init failure, mirroring the
    platform's "never hard-crash on a backend outage" contract.
    """
    backend = (backend or "memory").lower()
    try:
        if backend == "redis":
            return RedisCookieStore(redis_url=redis_url, default_ttl=default_ttl)
        if backend in ("sqlite", "sqlite3"):
            return SQLiteCookieStore(path=sqlite_path, default_ttl=default_ttl)
    except Exception:  # noqa: BLE001 - optional backend missing/unreachable
        pass
    return InMemoryCookieStore(default_ttl=default_ttl)
