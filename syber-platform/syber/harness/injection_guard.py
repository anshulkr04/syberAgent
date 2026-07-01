"""
Prompt-injection defence (spec section 9.1) — StruQ + classifier.

Two layers:

  1. StruQ dual-channel structured queries: trusted system instructions and
     untrusted retrieved evidence are placed in separate, explicitly delimited
     channels so the model is told which span it may take instructions from.
     Reference: StruQ, Chen et al., USENIX Security 2025
     (https://arxiv.org/abs/2402.06363, https://github.com/Sizhe-Chen/StruQ).

  2. A classifier that scores each retrieved chunk for injection content. The
     spec uses a DeBERTa-v3-small fine-tuned on InjectBench. transformers/torch
     have no Python 3.14 wheels, so the default scorer is a high-precision
     heuristic exposing the SAME interface (scan_for_injection -> (bool, prob)).
     Set SYBER_INJECTION_MODEL to a HF checkpoint to swap in the real DeBERTa
     model once a compatible runtime is available.
"""
from __future__ import annotations

import base64
import binascii
import os
import re
import unicodedata
from typing import Callable

from ..config import THRESHOLDS

PROMPT_DELIMITER_START = "<<<SYSTEM_INSTRUCTIONS>>>"
PROMPT_DELIMITER_END = "<<<END_SYSTEM_INSTRUCTIONS>>>"
DATA_DELIMITER_START = "<<<RETRIEVED_EVIDENCE>>>"
DATA_DELIMITER_END = "<<<END_RETRIEVED_EVIDENCE>>>"


def build_structured_query(system_instructions: str, retrieved_evidence: list[str]) -> str:
    """StruQ dual-channel framing (spec 9.1)."""
    evidence_block = "\n---\n".join(retrieved_evidence)
    return (
        f"{PROMPT_DELIMITER_START}\n"
        f"{system_instructions}\n"
        f"{PROMPT_DELIMITER_END}\n\n"
        f"{DATA_DELIMITER_START}\n"
        f"{evidence_block}\n"
        f"{DATA_DELIMITER_END}"
    )


# --------------------------------------------------------------------------- #
# Classifier interface
# --------------------------------------------------------------------------- #

# Phrases that, embedded in *retrieved data*, indicate an injection attempt.
_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"disregard\s+(your|all|the)\s+(instructions|rules|system\s+prompt)",
    r"\bsystem\s*:\s",                       # fake system turn inside data
    r"<<<\s*system",                          # forged StruQ delimiter
    r"new\s+instructions?\s*:",
    r"you\s+are\s+now\s+",
    r"reveal\s+(all|the)\s+(investigation|system|secret|prompt)",
    r"print\s+['\"]?compromised",
    r"email\s+(all\s+)?(findings|data|results)\s+to\s+\S+@",
    r"send\s+(all\s+)?(findings|data)\s+to\b",
    r"exfiltrat",
    r"override\s+(the\s+)?(scope|policy|guard)",
    r"do\s+not\s+(tell|inform|alert)\s+the\s+(analyst|user)",
]
_COMPILED = [re.compile(p, re.IGNORECASE) for p in _INJECTION_PATTERNS]

# --------------------------------------------------------------------------- #
# Detective pre-processing (defeats evasion that plain regex misses)
# --------------------------------------------------------------------------- #
# Confusable lookalikes -> their ASCII counterpart, so "іgnore previous" (Cyrillic
# і) is normalised to "ignore previous" before the pattern bank runs. Cheap,
# high-value: attackers swap a few homoglyphs to slip past keyword filters.
# (Adapted from CAI's normalize_unicode_homographs, agents/guardrails.py.)
_HOMOGLYPHS = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "А": "A", "В": "B", "Е": "E", "К": "K",
    "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
    # Greek
    "α": "a", "ο": "o", "ι": "i", "ρ": "p", "ν": "v", "Α": "A", "Β": "B",
    "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N",
    "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    # Fullwidth latin (common in obfuscation)
    "ａ": "a", "ｅ": "e", "ｉ": "i", "ｏ": "o", "ｓ": "s", "ｇ": "g", "ｎ": "n",
}
_HOMOGLYPH_TABLE = {ord(k): v for k, v in _HOMOGLYPHS.items()}

# A run of base64/base32 long enough to hide a command/instruction.
_B64_RX = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_B32_RX = re.compile(r"[A-Z2-7]{24,}={0,6}")


def normalize_homographs(text: str) -> str:
    """NFKC-normalise and fold confusable Unicode lookalikes to ASCII so keyword
    detection can't be bypassed with homoglyph substitution."""
    if not text:
        return text
    return unicodedata.normalize("NFKC", text).translate(_HOMOGLYPH_TABLE)


def _decoded_candidates(text: str) -> list[str]:
    """Decode long base64/base32 runs and return any that look like text — so an
    injection or reverse-shell hidden inside an encoded blob can be inspected."""
    out: list[str] = []
    for rx, decoder in ((_B64_RX, _b64), (_B32_RX, _b32)):
        for m in rx.finditer(text):
            dec = decoder(m.group(0))
            if dec and _looks_textual(dec):
                out.append(dec)
    return out


def _b64(s: str) -> str:
    try:
        pad = "=" * (-len(s) % 4)
        return base64.b64decode(s + pad, validate=False).decode("utf-8", "ignore")
    except (binascii.Error, ValueError):
        return ""


def _b32(s: str) -> str:
    try:
        pad = "=" * (-len(s) % 8)
        return base64.b32decode(s + pad, casefold=True).decode("utf-8", "ignore")
    except (binascii.Error, ValueError):
        return ""


def _looks_textual(s: str) -> bool:
    if len(s) < 6:
        return False
    printable = sum(1 for c in s if c.isprintable() or c in "\t\n\r")
    return printable / len(s) > 0.85


# Dangerous content that is only interesting once DECODED (reverse shells,
# pipe-to-shell, exfil) — applied to decoded candidates, not the raw text.
_DECODED_DANGER = re.compile(
    r"(?:bash\s+-i|/dev/tcp/|nc\s+-e|sh\s+-i|curl\s+[^|]+\|\s*(?:ba)?sh|"
    r"powershell|/bin/sh|reverse\s+shell|rm\s+-rf\s+/)", re.IGNORECASE)


def _heuristic_scan(text: str) -> tuple[bool, float]:
    norm = normalize_homographs(text)
    hits = sum(1 for rx in _COMPILED if rx.search(norm))
    # Inspect anything hidden inside encoded blobs.
    for dec in _decoded_candidates(norm):
        dnorm = normalize_homographs(dec)
        if _DECODED_DANGER.search(dnorm) or any(rx.search(dnorm) for rx in _COMPILED):
            hits += 2  # an encoded payload is a strong, deliberate signal
    if hits == 0:
        return False, 0.04
    # Each independent signature pushes probability toward 1.0.
    prob = min(0.99, 0.6 + 0.18 * hits)
    return prob > THRESHOLDS.injection_prob, prob


# Pluggable scorer. Swap to a DeBERTa-backed implementation by setting the env
# var and providing a compatible runtime (see module docstring).
_scanner: Callable[[str], tuple[bool, float]] = _heuristic_scan


def _try_load_transformer_scanner() -> None:
    model_id = os.environ.get("SYBER_INJECTION_MODEL")
    if not model_id:
        return
    try:  # pragma: no cover - only when a real model + runtime is present
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        tok = AutoTokenizer.from_pretrained(model_id)
        model = AutoModelForSequenceClassification.from_pretrained(model_id)
        model.eval()

        def _transformer_scan(text: str) -> tuple[bool, float]:
            inputs = tok(text, return_tensors="pt", truncation=True, max_length=512)
            with torch.no_grad():
                logits = model(**inputs).logits
            prob = torch.softmax(logits, dim=-1)[0][1].item()
            return prob > THRESHOLDS.injection_prob, prob

        global _scanner
        _scanner = _transformer_scan
    except Exception:  # noqa: BLE001 - fall back to heuristic silently
        pass


_try_load_transformer_scanner()


def scan_for_injection(text: str) -> tuple[bool, float]:
    """Return (is_injection, injection_probability) for one text span."""
    return _scanner(text)


def filter_evidence_chunks(chunks: list[str]) -> tuple[list[str], list[str]]:
    """Partition retrieved chunks into clean and quarantined (spec 3.4/9.1)."""
    from ..audit.log import get_audit_log

    audit = get_audit_log()
    clean: list[str] = []
    quarantined: list[str] = []
    for chunk in chunks:
        is_injection, score = scan_for_injection(chunk)
        if is_injection:
            audit.write_injection_probe(chunk, score)
            quarantined.append(chunk)
        else:
            clean.append(chunk)
    return clean, quarantined
