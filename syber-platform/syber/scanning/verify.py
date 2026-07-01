"""
Evidence-grounded verification — the anti-hallucination floor (CES complement).

Syber's CES gate scores a finished finding (consistency × calibration × self-check).
This module guards the layer beneath it: it answers two cheaper, binary questions
the LLM is prone to getting wrong on its own —

  1. ``classify_verdict`` — did a probe actually CONFIRM the bug, or is it only
     POSSIBLE, or REJECTED? A probe ships a verdict, not a vibe. Anything not
     explicitly CONFIRMED is, by default, NOT a finding (the discipline behind
     VulnClaw's "未经验证的漏洞 = 误报" verified-only report pipeline).

  2. ``evidence_grounded`` — does a claimed result (a flag, a leaked value, a
     "confirmed" string) actually appear in captured tool output? If the model
     says it found X but X is nowhere in any real tool result, X is a
     hallucination and the claim is rejected (VulnClaw solver's
     ``_completion_is_grounded``).

Pure functions over strings/dicts — no network, no LLM. The probe modules
(``webapp.test_injection`` / ``test_access_control``) attach a ``verdict`` to
each finding via ``classify_verdict``; a coverage/stop-condition check can call
``evidence_grounded`` before declaring a task-tree node "done".
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

__all__ = ["Verdict", "classify_verdict", "evidence_grounded", "GroundingResult",
           "unverified_claims", "is_reportable"]


class Verdict(str, Enum):
    CONFIRMED = "CONFIRMED"   # a probe self-confirmed (canary echoed, DB error, diff proven)
    POSSIBLE = "POSSIBLE"     # a weak/ambiguous signal — needs corroboration, NOT a finding
    REJECTED = "REJECTED"     # actively disproven (encoded/handled/equal baseline)

    def __str__(self) -> str:        # so it serialises as the bare string
        return self.value


def classify_verdict(*, confirmed: bool, possible: bool = False,
                     rejected: bool = False) -> Verdict:
    """Collapse a probe's boolean signals into a single verdict. Precedence:
    an explicit CONFIRMED wins; else an explicit REJECTED; else POSSIBLE if there
    was any weak signal; else REJECTED (default-reject — silence is not a bug)."""
    if confirmed:
        return Verdict.CONFIRMED
    if rejected:
        return Verdict.REJECTED
    return Verdict.POSSIBLE if possible else Verdict.REJECTED


def is_reportable(verdict: Verdict | str) -> bool:
    """Only CONFIRMED findings are reportable. POSSIBLE/REJECTED are not."""
    return str(verdict) == Verdict.CONFIRMED.value


# --------------------------------------------------------------------------- #
# Grounding: a claimed value must appear in real captured tool output
# --------------------------------------------------------------------------- #
@dataclass
class GroundingResult:
    grounded: bool
    found: list[str]          # claims located verbatim in the evidence
    missing: list[str]        # claims absent from all evidence (hallucinations)

    def to_dict(self) -> dict[str, Any]:
        return {"grounded": self.grounded, "found": self.found, "missing": self.missing}


def _haystack(evidence: Any) -> str:
    """Flatten arbitrary captured tool output (str / list / dict of responses)
    into one lowercased searchable blob."""
    parts: list[str] = []

    def walk(x: Any) -> None:
        if x is None:
            return
        if isinstance(x, str):
            parts.append(x)
        elif isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, (list, tuple, set)):
            for v in x:
                walk(v)
        else:
            parts.append(str(x))

    walk(evidence)
    return "\n".join(parts).lower()


def _norm_claim(claim: str) -> str:
    return re.sub(r"\s+", " ", (claim or "").strip()).lower()


def evidence_grounded(claims: str | list[str], captured: Any,
                      *, min_len: int = 4) -> GroundingResult:
    """Are the claimed string(s) present in the captured tool output?

    ``claims`` is one value or a list (a flag, a leaked field, a password, an id).
    ``captured`` is whatever real output was collected (response dicts, tool
    stdout, a list of bodies). A claim shorter than ``min_len`` is ignored (too
    generic to verify). ``grounded`` is True only if EVERY checkable claim is
    found verbatim — so a single fabricated value fails the gate.
    """
    if isinstance(claims, str):
        claims = [claims]
    hay = _haystack(captured)
    found, missing = [], []
    checkable = 0
    for raw in claims:
        c = _norm_claim(raw)
        if len(c) < min_len:
            continue
        checkable += 1
        if c in hay:
            found.append(raw)
        else:
            missing.append(raw)
    grounded = checkable > 0 and not missing
    return GroundingResult(grounded=grounded, found=found, missing=missing)


# Flag/secret shapes worth extracting from a model's prose claim to verify.
_FLAG_RX = re.compile(r"\b[A-Za-z0-9_]{2,}\{[^}\n]{1,120}\}")  # CTF flag{...}, FLAG{...}


def unverified_claims(text: str, captured: Any) -> list[str]:
    """Pull flag-shaped tokens out of a model's text and return those NOT present
    in captured output — i.e. likely hallucinated flags. Empty list == all good."""
    candidates = sorted(set(_FLAG_RX.findall(text or "")))
    if not candidates:
        return []
    res = evidence_grounded(candidates, captured)
    return res.missing
