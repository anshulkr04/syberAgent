"""
Answer extraction + metrics for CTIBench tasks (pure — unit-tested, no network/LLM).

  * CTI-RCM: extract a single CWE id; accuracy = exact match (the paper normalises a
    few CWE aliases; we do exact normalised match and note the small possible delta).
  * CTI-ATE: extract a set of ATT&CK technique ids; metric = micro-F1 over all
    instances (multi-label), matching the paper.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

_CWE_RX = re.compile(r"CWE[-\s]?(\d+)", re.IGNORECASE)
_TECH_RX = re.compile(r"\bT(\d{4})(?:\.(\d{3}))?\b", re.IGNORECASE)


# --------------------------------------------------------------------------- #
# CTI-RCM (CVE -> CWE)
# --------------------------------------------------------------------------- #
def extract_cwe(text: str) -> str:
    """Pull the predicted CWE id. The prompt asks for the id alone on the last line,
    so prefer the last line; fall back to the last CWE mention anywhere."""
    if not text:
        return ""
    for line in reversed([l for l in text.splitlines() if l.strip()]):
        found = _CWE_RX.findall(line)
        if found:
            return f"CWE-{int(found[-1])}"   # last id on the line (e.g. "CWE-20 or CWE-787")
    return ""


def norm_cwe(s: str) -> str:
    m = _CWE_RX.search(s or "")
    return f"CWE-{int(m.group(1))}" if m else (s or "").strip().upper()


def score_rcm(pred: str, gt: str) -> bool:
    return bool(pred) and norm_cwe(pred) == norm_cwe(gt)


# --------------------------------------------------------------------------- #
# CTI-ATE (report -> set of ATT&CK techniques)
# --------------------------------------------------------------------------- #
def extract_techniques(text: str, *, base_only: bool = True) -> set[str]:
    """Extract ATT&CK technique ids. ``base_only`` collapses sub-techniques
    (T1059.001 -> T1059) since CTIBench ground truth uses base technique ids."""
    out: set[str] = set()
    for base, sub in _TECH_RX.findall(text or ""):
        out.add(f"T{base}" if base_only or not sub else f"T{base}.{sub}")
    return out


def parse_technique_gt(gt: str, *, base_only: bool = True) -> set[str]:
    return extract_techniques(gt, base_only=base_only)


@dataclass
class MicroF1:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    def add(self, pred: set[str], gt: set[str]) -> None:
        self.tp += len(pred & gt)
        self.fp += len(pred - gt)
        self.fn += len(gt - pred)

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def to_dict(self) -> dict:
        return {"precision": round(self.precision, 4), "recall": round(self.recall, 4),
                "f1": round(self.f1, 4), "tp": self.tp, "fp": self.fp, "fn": self.fn}


def micro_f1(pairs: Iterable[tuple[set[str], set[str]]]) -> MicroF1:
    m = MicroF1()
    for pred, gt in pairs:
        m.add(pred, gt)
    return m


@dataclass
class RcmResult:
    total: int = 0
    correct: int = 0
    details: list[dict] = field(default_factory=list)

    @property
    def accuracy(self) -> float:
        return self.correct / self.total if self.total else 0.0
