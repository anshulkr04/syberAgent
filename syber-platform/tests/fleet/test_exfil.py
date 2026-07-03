"""Tests for the data-exposure verification layer (exfil.py + data_extraction runner
+ lead classification) — proving REAL data is exposed earns the IMPACT rung; a bare
200 / 'true' / structured-but-empty does not."""
from __future__ import annotations

import json

import pytest

from syber.scanning import exfil
from syber.scanning.exfil import scan_sensitive, redact, luhn_valid
from syber.fleet import leads, verify_runners
from syber.fleet.board import Board, Task
from syber.fleet.leads import LeadClass, LeadRegistry, EvidenceRung, LeadState


# --------------------------------------------------------------------------- #
# Pure scanner
# --------------------------------------------------------------------------- #
def test_empty_and_boolean_bodies_are_not_data():
    for b in ("", "true", "false", "null", "{}", "[]", "OK", "pong"):
        ev = scan_sensitive(b)
        assert ev.verdict == "EMPTY", b
        assert not ev.has_sensitive


def test_html_is_boilerplate():
    ev = scan_sensitive("<!DOCTYPE html><html><body>welcome</body></html>", "text/html")
    assert ev.verdict == "BOILERPLATE"
    assert not ev.has_sensitive


def test_real_pii_is_critical_impact():
    body = json.dumps([
        {"name": "Asha Rao", "email": "asha.rao@example.com", "pan": "ABCDE1234F"},
        {"name": "Vik Sen", "email": "vik@example.in", "mobile": "9876543210"},
    ])
    ev = scan_sensitive(body, "application/json")
    assert ev.verdict == "REAL_DATA"
    assert ev.has_sensitive and ev.severity == "CRITICAL"
    assert "email" in ev.categories and "pan" in ev.categories
    assert ev.record_count == 2
    # samples are redacted — the raw value never leaks
    assert not any("asha.rao@example.com" in s for s in ev.redacted_samples)
    assert any("***" in s for s in ev.redacted_samples)


def test_secrets_and_tokens_detected():
    body = ('{"jwt":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.'
            'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c","password":"hunter2secret"}')
    ev = scan_sensitive(body, "application/json")
    assert ev.verdict == "REAL_DATA"
    assert "jwt" in ev.categories
    assert "credential_field" in ev.categories


def test_structured_without_pii_is_verified_not_critical():
    body = json.dumps([{"id": 1, "qty": 5}, {"id": 2, "qty": 9}, {"id": 3, "qty": 1}])
    ev = scan_sensitive(body, "application/json")
    assert ev.verdict == "STRUCTURED"
    assert ev.severity == "HIGH"
    assert not ev.has_sensitive
    assert ev.record_count == 3


def test_credit_card_requires_luhn():
    assert luhn_valid("4242424242424242")
    assert not luhn_valid("4242424242424241")
    good = scan_sensitive('{"card":"4242424242424242"}')
    assert "credit_card" in good.categories
    bad = scan_sensitive('{"ref":"1234567890123456"}')   # fails Luhn
    assert "credit_card" not in bad.categories


def test_redact_masks_middle():
    assert redact("supersecretvalue") == "su***ue"
    assert redact("ab") == "**"


# --------------------------------------------------------------------------- #
# Lead classification
# --------------------------------------------------------------------------- #
def test_reachable_api_endpoint_classified_as_unauth_api_data():
    lead = leads.classify_node("https://x/api/Account/GetUserDetails",
                               {"label": "WebEndpoint",
                                "url": "https://x/api/Account/GetUserDetails", "status": 200})
    assert lead is not None and lead.lead_class == LeadClass.UNAUTH_API_DATA
    assert lead.high_value
    assert "data_extraction" in leads.verify_task_kinds_for(lead.lead_class)


def test_auth_gated_api_endpoint_is_needauth_lead():
    # a 401/403 API endpoint is NOT "secure" — it's a needs-auth lead to token-replay
    lead = leads.classify_node("https://x/api/foo",
                               {"label": "WebEndpoint", "url": "https://x/api/foo", "status": 403})
    assert lead is not None and lead.lead_class == leads.LeadClass.AUTH_BYPASS
    assert "auth_retest" in leads.verify_task_kinds_for(lead.lead_class)


def test_swagger_spec_classified_as_exposed_secret():
    lead = leads.classify_node("https://x/EWMTrade/swagger/docs/v1",
                               {"label": "WebEndpoint", "url": "https://x/EWMTrade/swagger/docs/v1",
                                "status": 200})
    assert lead is not None and lead.lead_class == LeadClass.EXPOSED_SECRET
    assert "data_extraction" in leads.verify_task_kinds_for(lead.lead_class)


# --------------------------------------------------------------------------- #
# data_extraction runner (network monkeypatched)
# --------------------------------------------------------------------------- #
class _StubBoard:
    def __init__(self):
        self.leads = LeadRegistry()


def _make_lead(reg: LeadRegistry, url: str):
    from syber.fleet.leads import Lead
    return reg.add(Lead(id=f"lead:apidata:{url}", lead_class=LeadClass.UNAUTH_API_DATA, target=url))


def _patch(monkeypatch, body, ctype="application/json", status=200):
    monkeypatch.setattr(verify_runners, "_authorized", lambda t: True)
    monkeypatch.setattr(exfil, "save_sample", lambda *a, **k: "")
    def fake_http(url, **kw):
        return {"status": status, "headers": {"content-type": ctype}, "body": body,
                "length": len(body), "transport": "stub"}
    import syber.scanning.webapp as webapp
    monkeypatch.setattr(webapp, "http_request", fake_http)


def test_runner_real_data_reaches_impact(monkeypatch):
    board = _StubBoard()
    url = "https://x/api/GetUserDetails"
    lead = _make_lead(board.leads, url)
    _patch(monkeypatch, json.dumps([{"email": "a@b.com", "pan": "ABCDE1234F"}]))
    task = Task(id=f"data_extraction:{lead.id}", kind="data_extraction", target_id=url,
                lead_id=lead.id, url=url)
    res = verify_runners.run_data_extraction(task, board, "w1")
    assert res.status == "done"
    assert lead.rung == EvidenceRung.IMPACT
    assert lead.state == LeadState.VERIFIED
    assert lead.severity == "CRITICAL"


def test_runner_empty_body_logs_failure(monkeypatch):
    board = _StubBoard()
    url = "https://x/api/MonitorDB"
    lead = _make_lead(board.leads, url)
    _patch(monkeypatch, "true", ctype="application/json")
    task = Task(id=f"data_extraction:{lead.id}", kind="data_extraction", target_id=url,
                lead_id=lead.id, url=url)
    res = verify_runners.run_data_extraction(task, board, "w1")
    assert res.status == "done"
    assert lead.rung == EvidenceRung.INFORMATIONAL          # never climbed
    assert lead.state == LeadState.EXHAUSTED                # the one hypothesis logged-failed


def test_runner_unauthorized_fails(monkeypatch):
    board = _StubBoard()
    url = "https://x/api/foo"
    lead = _make_lead(board.leads, url)
    monkeypatch.setattr(verify_runners, "_authorized", lambda t: False)
    task = Task(id="t", kind="data_extraction", target_id=url, lead_id=lead.id, url=url)
    res = verify_runners.run_data_extraction(task, board, "w1")
    assert res.status == "failed"


def test_data_extraction_registered():
    assert "data_extraction" in verify_runners.verify_runners()
