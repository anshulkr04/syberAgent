"""
Tool-output hygiene — keep verbose tool results from blowing the brain's window.

A single noisy command (a `curl` of a minified bundle, a full nuclei dump, a
crawl of a large app) can return hundreds of KB. Handed verbatim to the model,
that evicts the actual engagement context and triggers re-calls. Two cheap,
deterministic defences, applied at the tool boundary (before the result reaches
the harness), mirroring the strongest idea from CAI's auto-compactor Phase 1 and
VulnClaw's lead-first output ordering:

  * ``truncate`` — content-type-aware head+tail truncation with an explicit
    ``[... N characters truncated ...]`` marker. Minified/binary content is
    capped harder than prose because it carries less per-character signal.
  * ``lead_first`` — move high-value lines (secrets, confirmed leads, admin/auth
    surfaces) to the front so that if anything IS dropped by a downstream cap, it
    is the low-value bulk, never the finding.

Pure functions over strings/lists — no I/O, unit-tested without a network. This
is the "never hard-crash, degrade gracefully" contract the rest of the platform
uses, applied to context pressure instead of missing backends.
"""
from __future__ import annotations

import re
from typing import Any

__all__ = ["detect_content_kind", "cap_for", "truncate", "lead_first",
           "hygienic", "DEFAULT_CAP", "MINIFIED_CAP", "BINARY_CAP"]

# Per-kind character caps. Prose gets the most room; minified/binary the least
# because a head+tail sample is all the signal the model can use anyway.
DEFAULT_CAP = 50_000
MINIFIED_CAP = 10_000
BINARY_CAP = 2_000

# High-value markers — lines containing these float to the top under lead_first.
# Ordered roughly by interest; secrets and confirmed findings first.
_LEAD_MARKERS = [
    r"\bCONFIRMED\b", r"🔴", r"\[\+\]", r"⚠",
    r"(?:api[_-]?key|secret|token|password|passwd|bearer|authorization)\s*[:=]",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    r"\bAKIA[0-9A-Z]{16}\b",                 # AWS access key id
    r"\bAIza[0-9A-Za-z_\-]{35}\b",           # Google API key
    r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.", # JWT
    r"\b(?:admin|login|auth|token|debug|internal|config|backup|\.git|\.env)\b",
    r"\b[1-5]\d{2}\b\s+(?:GET|POST|PUT|PATCH|DELETE)",  # status+method lines
]
_LEAD_RX = re.compile("|".join(_LEAD_MARKERS), re.IGNORECASE)

# Binary sniff: a NUL byte or a high ratio of non-printable characters.
_PRINTABLE = re.compile(r"[^\x09\x0a\x0d\x20-\x7e]")


def detect_content_kind(text: str, content_type: str = "") -> str:
    """Classify a payload as ``binary`` | ``minified`` | ``structured`` | ``text``.

    ``content_type`` (an HTTP header value, if known) is a strong hint; otherwise
    we sniff the body. Used only to pick a truncation cap — never to alter content.
    """
    ct = (content_type or "").lower()
    sample = text[:4096]
    if "\x00" in sample or (sample and len(_PRINTABLE.findall(sample)) / len(sample) > 0.30):
        return "binary"
    if any(b in ct for b in ("octet-stream", "image/", "font/", "application/pdf", "/zip")):
        return "binary"
    if any(s in ct for s in ("json", "xml", "javascript", "css")):
        # Treat as minified when lines are very long (little newline structure).
        return "minified" if _is_minified(text) else "structured"
    if _is_minified(text):
        return "minified"
    return "text"


def _is_minified(text: str) -> bool:
    if not text:
        return False
    nl = text.count("\n")
    # Long content with almost no newlines = minified/one-liner.
    return len(text) > 2_000 and (nl == 0 or len(text) / (nl + 1) > 400)


def cap_for(kind: str) -> int:
    return {"binary": BINARY_CAP, "minified": MINIFIED_CAP}.get(kind, DEFAULT_CAP)


def truncate(text: str, cap: int | None = None, content_type: str = "") -> str:
    """Head+tail truncate ``text`` to ``cap`` chars with an explicit marker.

    Keeps ~70% from the head (where status/structure live) and ~30% from the tail
    (where errors/summaries often live). A ``cap`` of None is derived from the
    detected content kind. Content at or under the cap is returned unchanged.
    """
    text = text or ""
    if cap is None:
        cap = cap_for(detect_content_kind(text, content_type))
    if len(text) <= cap:
        return text
    dropped = len(text) - cap
    head = int(cap * 0.70)
    tail = cap - head
    marker = f"\n\n[... {dropped} characters truncated ({len(text)} total) ...]\n\n"
    return text[:head] + marker + (text[-tail:] if tail > 0 else "")


def lead_first(text: str, max_leads: int = 40) -> str:
    """Reorder lines so high-value (secret/lead/auth) lines come first.

    A ``=== high-value leads ===`` banner precedes the promoted lines; the full
    body follows unchanged underneath, so nothing is lost — only re-ordered, so a
    later truncation drops bulk rather than findings. No-op when nothing scores.
    """
    text = text or ""
    if not text:
        return text
    leads: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        if _LEAD_RX.search(line):
            key = line.strip()
            if key and key not in seen:
                seen.add(key)
                leads.append(line.rstrip())
                if len(leads) >= max_leads:
                    break
    if not leads:
        return text
    banner = "=== high-value leads (promoted; full output below) ===\n"
    return banner + "\n".join(leads) + "\n\n=== full output ===\n" + text


def hygienic(text: str, *, content_type: str = "", cap: int | None = None,
             promote_leads: bool = True, max_leads: int = 40) -> str:
    """Lead-first ordering THEN truncation — the order matters so promoted leads
    survive the cap. The one call a tool wrapper should make on a big text blob."""
    if promote_leads:
        text = lead_first(text, max_leads=max_leads)
    return truncate(text, cap=cap, content_type=content_type)


def hygienic_response(resp: dict[str, Any], *, body_key: str = "body",
                      max_leads: int = 40) -> dict[str, Any]:
    """Apply ``hygienic`` to an http_request-shaped result dict in place-ish.

    Reads the response's own ``content-type`` header to pick the cap, records the
    pre-truncation length under ``length`` if absent, and returns the same dict
    with a hygiene-trimmed body. Safe on dicts without a body."""
    body = resp.get(body_key)
    if not isinstance(body, str) or not body:
        return resp
    ct = ""
    headers = resp.get("headers")
    if isinstance(headers, dict):
        ct = str(headers.get("content-type", ""))
    resp.setdefault("length", len(body))
    resp[body_key] = hygienic(body, content_type=ct, max_leads=max_leads)
    return resp
