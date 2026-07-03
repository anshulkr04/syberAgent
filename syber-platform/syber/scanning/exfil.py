"""
Data-exposure verification (the IMPACT rung) — "is there REAL data behind it?"

The failure this fixes: the fleet/agent confirms an unauthenticated endpoint *responds*
(HTTP 200, or returns ``true``, or "structured data present") and then claims
CRITICAL/IMPACT — without ever proving that real, sensitive data is actually exposed.
A reachable endpoint is rung 2/3; *demonstrated material harm — pulled real data* is
rung 4 (IMPACT). This module earns that rung by **sampling the response body and
classifying what is actually in it**.

Design (same posture as the rest of the platform):
  * ``scan_sensitive(body, content_type)`` is **pure** and unit-tested with no network:
    it detects PII (email/phone/PAN/Aadhaar/SSN/credit-card-Luhn/IFSC), secrets/tokens
    (JWT/AWS/private-key/credential JSON fields), and **structured records** (a JSON
    array of objects, or many keyed rows), and returns a verdict + a **redacted** sample.
  * Verdict ladder: ``REAL_DATA`` (PII / secret / financial) → IMPACT / CRITICAL;
    ``STRUCTURED`` (real records, no classified-sensitive field) → VERIFIED / HIGH
    (an unauthenticated data API IS an exposure); ``EMPTY`` / ``BOILERPLATE`` /
    ``ERROR`` → not a finding (failed hypothesis).
  * ``save_sample`` writes a capped raw body + a redacted JSON summary to the
    engagement evidence dir, so the operator gets a real *downloaded* artefact to
    review — while what is surfaced to the model/lead is always redacted.

Nothing here decides severity by itself; it feeds the lead ladder (leads.py) and the
``data_extraction`` runner (verify_runners.py) which records the rung.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from hashlib import blake2b
from pathlib import Path
from typing import Any

__all__ = ["DataEvidence", "scan_sensitive", "redact", "save_sample", "luhn_valid",
           "is_confirmed", "is_gated_page"]

# A page that PROVES nothing: a login/auth wall, an access-denied/WAF block, or an error.
# A screenshot/capture of one of these is NOT evidence of a vulnerability.
_GATED_RX = re.compile(
    r"access denied|forbidden|not authorized|unauthorized|401 |403 |"
    r"sign in|log ?in to (?:your|continue)|please (?:log ?in|sign in|authenticate)|"
    r"session (?:expired|timed out)|enter your (?:password|credentials|user)|"
    r"authentication required|just a moment|attention required|cloudflare|"
    r"captcha|are you (?:a )?human|verify you are|request blocked|"
    r"page not found|404 not found|error 40[0-9]", re.IGNORECASE)
# Signals a real logged-in / data-bearing view.
_LOGGED_IN_RX = re.compile(
    r"log ?out|sign ?out|my account|dashboard|welcome,? |account number|"
    r"balance|portfolio|profile|settings|holdings|transactions", re.IGNORECASE)


def is_gated_page(body: str | None, status: int | None = None) -> bool:
    """True if the page is a login/auth wall, access-denied/WAF block, or error — i.e.
    it does NOT show accessible data and must not be used as proof of a finding."""
    try:
        if status is not None and not (200 <= int(status) < 300):
            return True
    except (TypeError, ValueError):
        pass
    text = (body or "")[:20000]
    if not text.strip():
        return True
    # a login/denied marker with no logged-in/data marker ⇒ gated
    if _GATED_RX.search(text) and not _LOGGED_IN_RX.search(text):
        return True
    return False

# Bodies larger than this are not scanned in full (head sample) — keeps it cheap.
_SCAN_CAP = 200_000
# Raw artefact saved to disk is capped so a huge dump never fills the volume.
_SAVE_CAP = 262_144  # 256 KiB

# --------------------------------------------------------------------------- #
# Sensitive-data detectors (high-precision; each maps to a category)
# --------------------------------------------------------------------------- #
_EMAIL_RX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_JWT_RX = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_AWS_KEY_RX = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_PRIVKEY_RX = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")
_PAN_RX = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")          # Indian PAN
_IFSC_RX = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")          # Indian bank IFSC
_AADHAAR_RX = re.compile(r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b")  # Indian Aadhaar (12 digit)
_SSN_RX = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")              # US SSN
_INDIAN_MOBILE_RX = re.compile(r"(?<!\d)[6-9]\d{9}(?!\d)")
_CC_CANDIDATE_RX = re.compile(r"\b(?:\d[ -]?){13,19}\b")
# credential-bearing JSON / config fields ("password": "...", api_key=..., etc.)
_SECRET_FIELD_RX = re.compile(
    r"\"?(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|private[_-]?key|authorization|auth[_-]?token|session[_-]?id|"
    r"bearer|x-api-key)\"?\s*[:=]\s*\"?([^\"&,\s}]{6,})",
    re.IGNORECASE)
_BEARER_RX = re.compile(r"\bBearer\s+[A-Za-z0-9._-]{12,}")

# Values that are NOT real data (so an empty/boolean/health endpoint isn't "impact").
_EMPTY_BODIES = {"", "true", "false", "null", "ok", "{}", "[]", "0", "1",
                 "pong", "success", "healthy", "alive", "up"}


def luhn_valid(number: str) -> bool:
    """Luhn checksum — keeps credit-card detection high-precision (avoids matching
    arbitrary 16-digit ids)."""
    digits = [int(c) for c in re.sub(r"\D", "", number)]
    if not 13 <= len(digits) <= 19:
        return False
    checksum, parity = 0, len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def redact(value: str, keep: int = 2) -> str:
    """Mask the middle of a sensitive value: ``john@x.com`` -> ``jo***om``. Short
    values are fully masked. Never surfaces a usable secret to the model/report."""
    v = str(value)
    if len(v) <= keep * 2:
        return "*" * len(v)
    return f"{v[:keep]}***{v[-keep:]}"


@dataclass
class DataEvidence:
    """Result of scanning a response body for real, sensitive data."""
    verdict: str = "EMPTY"                       # REAL_DATA | STRUCTURED | BOILERPLATE | ERROR | EMPTY
    categories: dict[str, int] = field(default_factory=dict)  # category -> count
    record_count: int = 0                        # structured records detected
    redacted_samples: list[str] = field(default_factory=list)  # masked example hits
    length: int = 0
    content_type: str = ""

    @property
    def has_sensitive(self) -> bool:
        return self.verdict == "REAL_DATA"

    @property
    def severity(self) -> str:
        return {"REAL_DATA": "CRITICAL", "STRUCTURED": "HIGH"}.get(self.verdict, "INFO")

    def summary(self) -> str:
        if self.verdict == "REAL_DATA":
            cats = ", ".join(f"{k}×{v}" for k, v in sorted(self.categories.items()))
            return f"REAL sensitive data exposed ({cats})"
        if self.verdict == "STRUCTURED":
            return f"structured data exposed ({self.record_count} records, no classified PII)"
        return {"BOILERPLATE": "HTML/boilerplate page, no data",
                "ERROR": "error/empty response", "EMPTY": "no data (empty/boolean/health)"}.get(
            self.verdict, "no data")

    def to_dict(self) -> dict[str, Any]:
        return {"verdict": self.verdict, "categories": self.categories,
                "record_count": self.record_count, "redacted_samples": self.redacted_samples,
                "length": self.length, "content_type": self.content_type,
                "severity": self.severity, "summary": self.summary(),
                "has_sensitive": self.has_sensitive}


def _count_records(body: str, content_type: str) -> int:
    """How many structured records does the body carry? Tries JSON first (array of
    objects, or the largest list inside an object); falls back to NDJSON / CSV rows."""
    stripped = body.strip()
    if stripped[:1] in ("{", "["):
        try:
            doc = json.loads(stripped)
        except Exception:  # noqa: BLE001 - truncated/invalid JSON falls through
            doc = None
        if isinstance(doc, list):
            return sum(1 for x in doc if isinstance(x, (dict, list))) or (len(doc) if doc else 0)
        if isinstance(doc, dict):
            best = 0
            for v in doc.values():
                if isinstance(v, list):
                    best = max(best, len(v))
            # a single object with several fields is one record
            return best or (1 if len(doc) >= 2 else 0)
    if "csv" in content_type or ("," in stripped and "\n" in stripped):
        rows = [r for r in stripped.splitlines() if r.strip()]
        if len(rows) >= 2 and rows[0].count(",") >= 1:
            return len(rows) - 1  # minus header
    # NDJSON
    lines = [l for l in stripped.splitlines() if l.strip().startswith("{")]
    return len(lines)


def scan_sensitive(body: str | None, content_type: str = "") -> DataEvidence:
    """Classify a response body. PURE — no network, no disk. The single source of
    truth for "is there real data here?"."""
    ct = (content_type or "").lower()
    raw = body or ""
    ev = DataEvidence(length=len(raw), content_type=ct)
    sample = raw[:_SCAN_CAP]
    norm = sample.strip().lower()

    if not raw or norm in _EMPTY_BODIES or len(sample.strip()) < 3:
        ev.verdict = "EMPTY"
        return ev

    cats: dict[str, int] = {}
    samples: list[str] = []

    def hit(cat: str, values: list[str]) -> None:
        if not values:
            return
        cats[cat] = cats.get(cat, 0) + len(values)
        if len(samples) < 8:
            samples.append(f"{cat}: {redact(values[0])}")

    hit("private_key", _PRIVKEY_RX.findall(sample))
    hit("jwt", _JWT_RX.findall(sample))
    hit("aws_key", _AWS_KEY_RX.findall(sample))
    hit("bearer_token", _BEARER_RX.findall(sample))
    hit("credential_field", [m.group(1) for m in _SECRET_FIELD_RX.finditer(sample)])
    hit("email", _EMAIL_RX.findall(sample))
    hit("pan", _PAN_RX.findall(sample))
    hit("ifsc", _IFSC_RX.findall(sample))
    hit("aadhaar", _AADHAAR_RX.findall(sample))
    hit("ssn", _SSN_RX.findall(sample))
    hit("phone", _INDIAN_MOBILE_RX.findall(sample))
    cc = [c for c in _CC_CANDIDATE_RX.findall(sample) if luhn_valid(c)]
    hit("credit_card", cc)

    ev.categories = cats
    ev.redacted_samples = samples
    ev.record_count = _count_records(sample, ct)

    if cats:
        ev.verdict = "REAL_DATA"
    elif "html" in ct or sample.lstrip()[:1] == "<" or "<!doctype" in norm[:64] or "<html" in norm[:256]:
        ev.verdict = "BOILERPLATE"
    elif ev.record_count >= 1 and (sample.strip()[:1] in ("{", "[") or "csv" in ct):
        ev.verdict = "STRUCTURED"
    else:
        ev.verdict = "BOILERPLATE"
    return ev


def is_confirmed(status: int | None, evidence: DataEvidence) -> bool:
    """A capture CONFIRMS an exposure only when the endpoint actually served data: a
    2xx status AND real/structured content. A 401/403/blocked/challenge/empty page is
    NOT proof of anything — it is an inaccessible attempt, never presented as a finding."""
    try:
        ok = status is not None and 200 <= int(status) < 300
    except (TypeError, ValueError):
        ok = False
    return ok and evidence.verdict in ("REAL_DATA", "STRUCTURED")


def save_sample(url: str, status: int | None, body: str | None, evidence: DataEvidence,
                root: Path | None = None, *, method: str = "GET",
                request_headers: dict[str, str] | None = None,
                response_headers: dict[str, str] | None = None,
                transport: str = "", screenshot: str | None = None) -> str:
    """Persist a *downloaded* sample for operator review: a capped raw body plus a
    redacted JSON summary that also records the EXACT request (method/url/headers) so a
    faithful curl reproduction can be generated, and a ``confirmed`` flag (2xx + real
    data) so inaccessible attempts are never mistaken for proof. Returns the evidence
    base path (best-effort — "" on IO error). Raw body is operator-only on disk."""
    try:
        if root is None:
            from ..config import config
            root = config.state / "evidence"
        host = re.sub(r"[^A-Za-z0-9._-]", "_", url.split("://")[-1].split("/")[0]) or "target"
        digest = blake2b(f"{method} {url}".encode(), digest_size=6).hexdigest()
        d = Path(root) / host
        d.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%dT%H%M%S")
        base = d / f"{stamp}-{digest}"
        (base.with_suffix(".body")).write_text((body or "")[:_SAVE_CAP], encoding="utf-8", errors="replace")
        # Store the REAL request headers so the operator can reproduce exactly. The report
        # is operator-locked (SYBER_REPORT_TO), and a faithful PoC needs the working
        # request verbatim — including any auth/token the agent used to reach the data.
        summary = {
            "url": url, "method": method.upper(), "status": status, "saved_at": stamp,
            "transport": transport,
            "request_headers": dict(request_headers or {}),
            "response_content_type": (response_headers or {}).get("content-type", ""),
            "response_server": (response_headers or {}).get("server", ""),
            "confirmed": is_confirmed(status, evidence),
            "screenshot": screenshot or "",
            **evidence.to_dict(),
        }
        (base.with_suffix(".json")).write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return str(base)
    except Exception:  # noqa: BLE001 - evidence-saving must never break a probe
        return ""
