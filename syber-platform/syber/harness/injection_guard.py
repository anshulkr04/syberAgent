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

import os
import re
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


def _heuristic_scan(text: str) -> tuple[bool, float]:
    hits = sum(1 for rx in _COMPILED if rx.search(text))
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
