"""WAF-block detection for the browser navigate+render fallback (Bug 2 regression)."""
from __future__ import annotations

from syber.scanning.webapp import _looks_blocked


def test_looks_blocked_status():
    assert _looks_blocked(403, "x") is True
    assert _looks_blocked(429, "x") is True
    assert _looks_blocked(503, "x") is True
    assert _looks_blocked(200, '{"data":1}') is False
    assert _looks_blocked(None, '{"data":1}') is False


def test_looks_blocked_challenge_body():
    assert _looks_blocked(200, "<title>Just a moment...</title>") is True
    assert _looks_blocked(200, "Attention Required! | Cloudflare") is True
    assert _looks_blocked(200, "/cdn-cgi/challenge-platform/") is True
    assert _looks_blocked(200, "Access Denied ... Reference #18.abc  (akamai)") is True


def test_real_content_not_blocked():
    assert _looks_blocked(200, '<html><body>Dashboard: welcome Asha, balance 9000</body></html>') is False
