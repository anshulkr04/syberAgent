"""
Web-application testing — deterministic tests (no network, no LLM spend).

Covers the BOLA/IDOR + injection detection logic, attack-surface parsing, and the
default-deny authorisation gate on every active web-app tool.

Run: python -m pytest tests/integration/test_webapp.py   (from syber-platform/)
"""
from __future__ import annotations

import pytest

from syber.scanning import webapp
from syber.scanning.active_scan import NotAuthorized


# --- injection detection ---------------------------------------------------- #
def test_sqli_error_signatures_detected():
    body = "Warning: mysqli_query(): You have an error in your SQL syntax near '''"
    assert webapp.sqli_errors(body)
    assert webapp.sqli_errors("ORA-01756: quoted string not properly terminated")
    assert webapp.sqli_errors("normal page, nothing wrong here") == []


def test_reflected_xss_requires_unencoded_marker():
    canary = "sybxssabc123"
    assert webapp.xss_reflected(f"<p><{canary}></p>", canary) is True
    assert webapp.xss_reflected(f"&lt;{canary}&gt;", canary) is False  # escaped -> safe
    assert webapp.xss_reflected("unrelated body", canary) is False


# --- IDOR/BOLA response comparison ------------------------------------------ #
def test_responses_differ_distinguishes_objects():
    alice = webapp.response_signature(200, "alice confidential invoice 1041 total 500 secret")
    bob = webapp.response_signature(200, "bob different invoice 9999 total 12 unrelated content here")
    alice2 = webapp.response_signature(200, "alice confidential invoice 1041 total 500 secret")
    assert webapp.responses_differ(alice, bob) is True       # other user's object
    assert webapp.responses_differ(alice, alice2) is False   # same content


def test_unauthorized_leak_detection():
    base = {"status": 200, "body": "alice private data here and more text to compare", "length": 47}
    leak = {"status": 200, "body": "alice private data here and more text to compare", "length": 47}
    denied = {"status": 403, "body": "forbidden", "length": 9}
    assert webapp._is_unauthorized_leak(base, leak) is True    # B saw A's object
    assert webapp._is_unauthorized_leak(base, denied) is False  # B correctly blocked


def test_other_object_needs_2xx_and_difference():
    base_sig = webapp.response_signature(200, "my own object alpha beta gamma delta epsilon")
    other_2xx = {"status": 200, "body": "someone elses object zeta eta theta iota kappa lambda", "length": 52}
    other_404 = {"status": 404, "body": "not found", "length": 9}
    assert webapp._looks_like_other_object(
        other_2xx, base_sig, webapp.response_signature(200, other_2xx["body"])) is True
    assert webapp._looks_like_other_object(
        other_404, base_sig, webapp.response_signature(404, other_404["body"])) is False


# --- attack-surface parsing + id manipulation ------------------------------- #
def test_extract_surface_links_forms_params():
    html = ('<a href="/users?id=7">u</a><a href="https://other.test/x">ext</a>'
            '<form action="/login" method="post"><input name="email"><input name="pw"></form>')
    surf = webapp.extract_surface(html, "https://app.test/home")
    assert "https://app.test/users?id=7" in surf["links"]
    assert all("other.test" not in l for l in surf["links"])  # off-host link dropped
    assert surf["params"] == ["email", "id", "pw"]
    assert surf["forms"][0]["method"] == "POST"


def test_locate_and_swap_id_path_and_query():
    assert webapp._locate_id("https://t/invoices/1041", None) == ("1041", "path")
    assert webapp._locate_id("https://t/api?doc_id=5&x=1", None) == ("5", "query:doc_id")
    assert webapp._swap_id("https://t/invoices/1041", "path", "1042") == "https://t/invoices/1042"
    assert webapp._swap_id("https://t/api?doc_id=5", "query:doc_id", "6") == "https://t/api?doc_id=6"


# --- PTT plan --------------------------------------------------------------- #
def test_pentest_plan_has_ordered_phases():
    plan = webapp.pentest_plan("scanme.nmap.org")
    phases = [p["phase"] for p in plan["phases"]]
    assert len(phases) == 5
    assert any("access_control" == t["id"] for p in plan["phases"] for t in p["tasks"])
    assert any("crawl" == t["id"] for p in plan["phases"] for t in p["tasks"])


# --- default-deny authorisation gate ---------------------------------------- #
@pytest.mark.parametrize("call", [
    lambda: webapp.http_request("http://unauthorised.example/x"),
    lambda: webapp.crawl("unauthorised.example"),
    lambda: webapp.test_access_control("http://unauthorised.example/invoices/1"),
    lambda: webapp.test_injection("http://unauthorised.example/s?q=1"),
])
def test_active_webapp_tools_are_authorisation_gated(call):
    with pytest.raises(NotAuthorized):
        call()
