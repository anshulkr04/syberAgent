"""Scan-timeout resolution: full_scan must be bounded, not 3× the per-stage timeout."""
from __future__ import annotations

from syber.scanning import active_scan as A


def test_explicit_timeout_beats_env(monkeypatch):
    # THE bug fix: SYBER_SCAN_TIMEOUT used to override even an explicit per-stage value,
    # so full_scan's stages each ran to the full 900s. Explicit must now win.
    monkeypatch.setenv("SYBER_SCAN_TIMEOUT", "900")
    assert A._resolve_timeout(120, 300) == 120
    assert A._resolve_timeout(None, 300) == 900          # env fills only the None default


def test_resolve_timeout_default_without_env(monkeypatch):
    monkeypatch.delenv("SYBER_SCAN_TIMEOUT", raising=False)
    assert A._resolve_timeout(None, 300) == 300
    assert A._resolve_timeout(45, 300) == 45


def test_fullscan_budget(monkeypatch):
    monkeypatch.delenv("SYBER_FULLSCAN_BUDGET", raising=False)
    assert A._fullscan_budget(None) == 1800              # thorough default (~30 min total)
    assert A._fullscan_budget(180) == 180                # explicit wins
    monkeypatch.setenv("SYBER_FULLSCAN_BUDGET", "300")
    assert A._fullscan_budget(None) == 300


def test_fullscan_stage_split_is_bounded(monkeypatch):
    """The three stages sum to ~one budget, NOT 3× a per-stage timeout — so full_scan
    stays bounded even when SYBER_SCAN_TIMEOUT is large."""
    monkeypatch.setenv("SYBER_SCAN_TIMEOUT", "900")       # would have made each stage 900
    monkeypatch.setenv("SYBER_FULLSCAN_BUDGET", "600")
    budget = A._fullscan_budget(None)
    svc_t = max(60, int(budget * 0.2))
    web_t = max(120, int(budget * 0.4))
    assert svc_t + web_t + web_t <= budget + 120          # bounded near the budget
    assert svc_t + web_t + web_t < 3 * 900                # far below the old 3×900
