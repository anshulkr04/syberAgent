"""Fetch + cache CTIBench TSV datasets (CC-BY-NC-SA-4.0; not committed)."""
from __future__ import annotations

import csv
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from ..config import PATHS

_HF_BASE = "https://huggingface.co/datasets/AI4Sec/cti-bench/resolve/main"
_CACHE = PATHS.root / ".bench_cache"

# task -> (tsv filename, input column, ground-truth column)
TASK_FILES = {
    "cti_rcm": ("cti-rcm.tsv", "Prompt", "GT"),
    "cti_ate": ("cti-ate.tsv", "Prompt", "GT"),
}


@dataclass
class Example:
    idx: int
    prompt: str          # the benchmark's verbatim task prompt (input column)
    gt: str              # ground-truth answer (raw string)
    description: str = ""  # raw description (for subagent-prompt variants)
    meta: dict | None = None


def _download(filename: str) -> Path:
    _CACHE.mkdir(parents=True, exist_ok=True)
    dst = _CACHE / filename
    if dst.exists() and dst.stat().st_size > 0:
        return dst
    url = f"{_HF_BASE}/{filename}"
    req = urllib.request.Request(url, headers={"User-Agent": "syber-bench/1.0"})
    with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310 - trusted HF host
        data = r.read()
    dst.write_bytes(data)
    return dst


def load(task: str, limit: int | None = None) -> list[Example]:
    """Load a CTIBench task as a list of Examples (downloading + caching on first use)."""
    if task not in TASK_FILES:
        raise ValueError(f"unknown task {task!r}; known: {sorted(TASK_FILES)}")
    filename, in_col, gt_col = TASK_FILES[task]
    path = _download(filename)
    rows: list[Example] = []
    with path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        for i, row in enumerate(reader):
            rows.append(Example(
                idx=i,
                prompt=(row.get(in_col) or "").strip(),
                gt=(row.get(gt_col) or "").strip(),
                description=(row.get("Description") or "").strip(),
                meta={k: v for k, v in row.items() if k not in (in_col, gt_col)},
            ))
    if limit is not None:
        rows = rows[:limit]
    return rows
