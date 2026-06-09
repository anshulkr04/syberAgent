"""Identity-provisioning integrations — deterministic tests (no network).

Covers the pure parsing/guard logic of the AgentMail / AgentPhone clients:
verification-link + OTP extraction, address resolution, the not-configured error
path, and the operator-only outbound guard. The live API calls are exercised
separately (they need a real key); here we only test logic that must be correct.

Run: python -m pytest tests/integration/test_integrations.py   (from syber-platform/)
"""
from __future__ import annotations

import pytest

from syber.integrations import (IntegrationError, IntegrationNotConfigured,
                                agentmail, agentphone)


# --- AgentMail: address resolution ----------------------------------------- #
def test_address_of_prefers_inbox_id():
    assert agentmail.address_of({"inbox_id": "a@agentmail.to"}) == "a@agentmail.to"
    assert agentmail.address_of({"address": "b@agentmail.to"}) == "b@agentmail.to"
    assert agentmail.address_of({}) == ""


# --- AgentMail: OTP + link extraction from confirmation mail ---------------- #
def test_extract_otp_prefers_keyword_adjacent_code():
    msg = {"text": "Your order 12345 shipped. Verification code: 778201. Thanks."}
    assert agentmail.extract_otp(msg) == "778201"


def test_extract_otp_falls_back_to_any_code():
    assert agentmail.extract_otp({"text": "Use 4821 to continue"}) == "4821"
    assert agentmail.extract_otp({"text": "no codes here"}) is None


def test_extract_links_puts_verification_first():
    msg = {"text": "Welcome! Click https://app.example.com/confirm?token=abc to verify. "
                   "Or visit https://example.com/home later."}
    links = agentmail.extract_links(msg)
    assert links[0] == "https://app.example.com/confirm?token=abc"
    assert "https://example.com/home" in links


def test_extract_links_strips_trailing_punctuation():
    msg = {"text": "Go to https://example.com/verify?x=1)."}
    assert "https://example.com/verify?x=1" in agentmail.extract_links(msg)


# --- not-configured surfaces an actionable error, not a crash --------------- #
def test_agentmail_requires_key(monkeypatch):
    monkeypatch.delenv("AGENTMAIL_API_KEY", raising=False)
    assert agentmail.configured() is False
    with pytest.raises(IntegrationNotConfigured):
        agentmail.create_inbox()


def test_agentphone_requires_key(monkeypatch):
    monkeypatch.delenv("AGENTPHONE_API_KEY", raising=False)
    monkeypatch.delenv("AGENTPHONE_NUMBER_ID", raising=False)
    assert agentphone.configured() is False
    with pytest.raises(IntegrationNotConfigured):
        agentphone.read_sms()


# --- AgentPhone: SMS OTP extraction ----------------------------------------- #
def test_phone_extract_otp():
    assert agentphone.extract_otp({"body": "Your code is 901234"}) == "901234"
    assert agentphone.extract_otp({"text": "847291 is your PIN"}) == "847291"


# --- AgentPhone: outbound is operator-only (no third-party calling) ---------- #
def test_outbound_refused_without_operator(monkeypatch):
    monkeypatch.setenv("AGENTPHONE_API_KEY", "x")
    monkeypatch.delenv("SYBER_OPERATOR_PHONE", raising=False)
    with pytest.raises(IntegrationNotConfigured):
        agentphone.notify_operator_sms("hi")


def test_outbound_only_to_operator_number(monkeypatch):
    monkeypatch.setenv("SYBER_OPERATOR_PHONE", "+15551230000")
    # The guard returns the operator number for the allowed (empty -> operator) case…
    assert agentphone._assert_operator("") == "+15551230000"
    assert agentphone._assert_operator("+15551230000") == "+15551230000"
    # …and refuses any other destination outright.
    with pytest.raises(IntegrationError):
        agentphone._assert_operator("+19998887777")
