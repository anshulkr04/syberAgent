"""
Credential / auth-token harvesting + replay store — "use the tokens that are lying around."

The failure this fixes: engagements found publicly-exposed auth material (JWTs in JS
bundles, API keys, documented vendor creds, sample-payload tokens in API docs) and 30+
endpoints returning 401 "No Auth Header" — then concluded "auth properly enforced,
secure." That is backwards: the job is to COLLECT every credential the target leaks and
REPLAY it against the auth-gated endpoints. A token that unlocks another user's data, or
an endpoint that accepts a stale/low-priv token for a privileged action, is the finding.

This module:
  * ``harvest`` — pull replayable auth material out of any text (JS, API docs, responses):
    JWTs, ``Bearer``/``Basic`` tokens, AWS keys, ``apiKey``/``token``/``x-api-key`` fields,
    and documented ``username``/``password`` pairs.
  * ``CredentialStore`` — an engagement-wide, PERSISTED store (survives Ralph passes via the
    state volume, like the recall ledger) so a token found on host A is replayed on host B.
  * ``auth_headers`` — turn each stored credential into the concrete request-header variants
    to try (Authorization: Bearer / Basic / raw, X-API-Key, cookie, appIdKey, jwt, …).

Pure harvesting + store; the replay itself lives in the auth-retest runner. Unit-tested.
Scope: only the AUTHORISED engagement's own leaked material; the store is wiped at teardown.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any

__all__ = ["Credential", "CredentialStore", "get_store", "harvest", "auth_headers"]

# --- patterns for replayable auth material --------------------------------- #
_JWT_RX = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\b")
_BEARER_RX = re.compile(r"\bBearer\s+([A-Za-z0-9._~+/=-]{12,})", re.IGNORECASE)
_BASIC_RX = re.compile(r"\bBasic\s+([A-Za-z0-9+/=]{12,})", re.IGNORECASE)
_AWS_RX = re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")
# keyed auth fields: "apiKey":"...", api_key=..., x-api-key: ..., appIdKey, ewjwt, mwAuth
_FIELD_RX = re.compile(
    r"[\"']?((?:x-)?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|"
    r"app[_-]?id[_-]?key|client[_-]?secret|session[_-]?id|jwt|ewjwt|mwauth|gauth|"
    r"authorization|bearer|token|secret|apikey))[\"']?\s*[:=]\s*[\"']([^\"'\s,;}<>&]{8,})",
    re.IGNORECASE)
# documented credential pairs: username/user/login + password/pass/pwd near each other
_CREDPAIR_RX = re.compile(
    r"(?:user(?:name)?|login|email)[\"']?\s*[:=]\s*[\"']?([^\"'\s,;}<>&]{3,})[\s\S]{0,80}?"
    r"(?:pass(?:word|wd)?|pwd)[\"']?\s*[:=]\s*[\"']?([^\"'\s,;}<>&]{3,})",
    re.IGNORECASE)

# header names to try a bearer-ish token in (targets often use custom names)
_TOKEN_HEADER_NAMES = ["Authorization", "X-API-Key", "x-api-key", "AppIdKey", "appIdKey",
                       "jwt", "ewjwt", "mwAuth", "GAuth", "token", "X-Auth-Token"]


@dataclass
class Credential:
    kind: str                 # jwt | bearer | basic | aws | field | cred_pair
    value: str = ""
    name: str = ""            # the field/header name it was found under (if any)
    username: str = ""        # for cred_pair
    password: str = ""        # for cred_pair
    source: str = ""          # where harvested (url / "docs" / "js")
    first_ts: float = field(default_factory=time.time)

    def key(self) -> str:
        return f"{self.kind}:{self.name}:{self.value or self.username}"[:200]

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "value": self.value, "name": self.name,
                "username": self.username, "password": self.password, "source": self.source}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Credential":
        return cls(kind=d.get("kind", "field"), value=d.get("value", ""), name=d.get("name", ""),
                   username=d.get("username", ""), password=d.get("password", ""),
                   source=d.get("source", ""))


def _looks_like_token(v: str) -> bool:
    # avoid junk: needs some length + entropy-ish (not a plain english word / url / bool)
    if len(v) < 8 or v.lower() in ("password", "changeme", "true", "false", "null", "undefined"):
        return False
    if v.startswith(("http://", "https://", "/", "function", "{{", "${")):
        return False
    return bool(re.search(r"[A-Za-z0-9]", v))


def harvest(text: str | None, source: str = "") -> list[Credential]:
    """Extract replayable auth material from arbitrary text (JS/doc/response body)."""
    out: list[Credential] = []
    if not text:
        return out
    seen: set[str] = set()

    def add(c: Credential) -> None:
        k = c.key()
        if k not in seen:
            seen.add(k)
            out.append(c)

    for m in _JWT_RX.findall(text):
        add(Credential(kind="jwt", value=m, source=source))
    for m in _BEARER_RX.findall(text):
        add(Credential(kind="bearer", value=m, source=source))
    for m in _BASIC_RX.findall(text):
        add(Credential(kind="basic", value=m, source=source))
    for m in _AWS_RX.findall(text):
        add(Credential(kind="aws", value=m, name="aws_access_key_id", source=source))
    for name, val in _FIELD_RX.findall(text):
        if _looks_like_token(val):
            add(Credential(kind="field", name=name, value=val, source=source))
    for user, pwd in _CREDPAIR_RX.findall(text):
        if user and pwd and pwd.lower() not in ("password", "yourpassword", "xxxx"):
            add(Credential(kind="cred_pair", username=user, password=pwd, source=source))
    return out


def auth_headers(cred: Credential) -> list[dict[str, str]]:
    """Concrete request-header variants to try for one credential. Custom header names
    matter — targets often read the token from AppIdKey/jwt/mwAuth, not Authorization."""
    variants: list[dict[str, str]] = []
    v = cred.value
    if cred.kind in ("jwt", "bearer", "field") and v:
        variants.append({"Authorization": f"Bearer {v}"})
        # try the token under its own field name and common custom header names
        names = [cred.name] if cred.name else []
        for hn in names + _TOKEN_HEADER_NAMES:
            if hn:
                variants.append({hn: v})
    elif cred.kind == "basic" and v:
        variants.append({"Authorization": f"Basic {v}"})
    elif cred.kind == "cred_pair" and cred.username:
        import base64
        b = base64.b64encode(f"{cred.username}:{cred.password}".encode()).decode()
        variants.append({"Authorization": f"Basic {b}"})
    # dedupe preserving order
    uniq, seen = [], set()
    for hv in variants:
        k = json.dumps(hv, sort_keys=True)
        if k not in seen:
            seen.add(k)
            uniq.append(hv)
    return uniq


# --------------------------------------------------------------------------- #
# Persistent engagement-wide store
# --------------------------------------------------------------------------- #
class CredentialStore:
    def __init__(self, path: str | None = None, capacity: int = 500):
        self.capacity = capacity
        self._creds: dict[str, Credential] = {}
        self._lock = threading.Lock()
        self._path = path if path is not None else _default_path()
        self._load()

    def _load(self) -> None:
        if not self._path or not os.path.isfile(self._path):
            return
        try:
            with open(self._path) as f:
                for d in json.load(f).get("creds", []):
                    c = Credential.from_dict(d)
                    self._creds[c.key()] = c
        except Exception:  # noqa: BLE001
            pass

    def _save(self) -> None:
        if not self._path:
            return
        try:
            os.makedirs(os.path.dirname(self._path), exist_ok=True)
            tmp = f"{self._path}.tmp.{os.getpid()}"
            with open(tmp, "w") as f:
                json.dump({"creds": [c.to_dict() for c in self._creds.values()]}, f)
            os.replace(tmp, self._path)
        except Exception:  # noqa: BLE001
            pass

    def add(self, cred: Credential) -> None:
        with self._lock:
            self._creds.setdefault(cred.key(), cred)
            while len(self._creds) > self.capacity:
                self._creds.pop(next(iter(self._creds)))
            self._save()

    def add_from_text(self, text: str | None, source: str = "") -> int:
        found = harvest(text, source=source)
        for c in found:
            self.add(c)
        return len(found)

    def add_cookie(self, host: str, cookie: str) -> None:
        """Store a session cookie captured from a login (replayable on that host)."""
        if cookie:
            self.add(Credential(kind="field", name="Cookie", value=cookie, source=f"login:{host}"))

    def all(self) -> list[Credential]:
        with self._lock:
            return list(self._creds.values())

    def summary(self) -> dict[str, Any]:
        by_kind: dict[str, int] = {}
        for c in self._creds.values():
            by_kind[c.kind] = by_kind.get(c.kind, 0) + 1
        return {"total": len(self._creds), "by_kind": by_kind,
                "sources": sorted({c.source for c in self._creds.values() if c.source})[:20]}


def _default_path() -> str | None:
    override = os.environ.get("SYBER_CREDS_PATH")
    if override is not None:
        return override or None
    try:
        from ..config import PATHS
        return str(PATHS.state / "credentials.json")
    except Exception:  # noqa: BLE001
        return None


_store: CredentialStore | None = None


def get_store() -> CredentialStore:
    global _store
    if _store is None:
        _store = CredentialStore()
    return _store
