"""AgentPhone client — a real US/CA number so the agent can RECEIVE SMS OTP while
registering test accounts that gate signup behind phone verification.

REST API: https://api.agentphone.ai   Auth: Bearer $AGENTPHONE_API_KEY
Docs: https://agentphone.ai/skills.md

SCOPE — inbound only by policy:
  * read_sms / wait_for_sms / call transcripts / status: enabled (our own number).
  * Outbound call/SMS: restricted to the operator's own number (SYBER_OPERATOR_PHONE)
    for the consensual "call me" notification. There is intentionally NO tool to
    place calls/SMS to arbitrary numbers — that is social engineering (vishing/
    smishing), out of scope for this platform.

Signup is a one-time interactive bootstrap (see `signup` / `verify`); it mints the
api_key + agent_id + number_id + phone_number that go into syberAgent/.env.
"""
from __future__ import annotations

import re
import time
from typing import Any

from . import IntegrationError, IntegrationNotConfigured, env, http_json

BASE = "https://api.agentphone.ai"
_OTP_RE = re.compile(r"\b(\d{4,8})\b")


def _token() -> str:
    key = env("AGENTPHONE_API_KEY")
    if not key:
        raise IntegrationNotConfigured(
            "AGENTPHONE_API_KEY is not set. Run a one-time signup "
            "(scripts/syber_phone_signup.sh) and put the returned api_key / agent_id / "
            "number_id into syberAgent/.env, then restart the agent."
        )
    return key


def _number_id() -> str:
    nid = env("AGENTPHONE_NUMBER_ID")
    if not nid:
        raise IntegrationNotConfigured(
            "AGENTPHONE_NUMBER_ID is not set (the id of your provisioned number)."
        )
    return nid


def configured() -> bool:
    return bool(env("AGENTPHONE_API_KEY") and env("AGENTPHONE_NUMBER_ID"))


# --------------------------------------------------------------------------- #
# One-time signup / provisioning (interactive bootstrap)
# --------------------------------------------------------------------------- #
def signup(human_email: str, agent_name: str = "syber-agent") -> dict[str, Any]:
    """Step 1: request signup. A 6-digit code is emailed to `human_email`.
    Returns {verification_id}. (No auth required.)"""
    return http_json("POST", f"{BASE}/v0/agent/sign-up", token="",
                     body={"human_email": human_email, "agent_name": agent_name},
                     auth_scheme="")


def verify(verification_id: str, otp_code: str) -> dict[str, Any]:
    """Step 2: confirm signup with the emailed OTP. Returns
    {api_key, agent_id, number_id, phone_number} — store these in .env. Shown once."""
    return http_json("POST", f"{BASE}/v0/agent/verify", token="",
                     body={"verification_id": verification_id, "otp_code": otp_code},
                     auth_scheme="")


def status() -> dict[str, Any]:
    """Account/usage status (also confirms the number works)."""
    return http_json("GET", f"{BASE}/v1/usage", token=_token())


# --------------------------------------------------------------------------- #
# Inbound SMS (OTP capture)
# --------------------------------------------------------------------------- #
def _sms_body(m: dict[str, Any]) -> str:
    for k in ("body", "text", "message", "content"):
        if m.get(k):
            return str(m[k])
    return ""


def _sms_id(m: dict[str, Any]) -> str:
    for k in ("message_id", "id", "sid"):
        if m.get(k):
            return str(m[k])
    return _sms_body(m)[:40]


def read_sms(limit: int = 10, number_id: str | None = None) -> list[dict[str, Any]]:
    nid = number_id or _number_id()
    out = http_json("GET", f"{BASE}/v1/numbers/{nid}/messages?limit={int(limit)}", token=_token())
    if isinstance(out, dict):
        for k in ("data", "messages", "items"):
            if isinstance(out.get(k), list):
                return out[k]
        return []
    return out


def wait_for_sms(match: str | None = None, timeout: int = 120, poll: int = 5,
                 number_id: str | None = None) -> dict[str, Any] | None:
    """Poll inbound SMS until a (optionally matching) message arrives. Returns the
    message dict or None on timeout."""
    deadline = time.time() + max(1, timeout)
    needle = (match or "").lower()
    seen: set[str] = set()
    while time.time() < deadline:
        for m in read_sms(limit=10, number_id=number_id):
            sid = _sms_id(m)
            if sid in seen:
                continue
            seen.add(sid)
            if not needle or needle in _sms_body(m).lower():
                return m
        time.sleep(max(1, poll))
    return None


def extract_otp(msg: dict[str, Any]) -> str | None:
    body = _sms_body(msg)
    near = re.search(r"(?:code|otp|verif\w*|pin)\D{0,20}(\d{4,8})", body, re.I)
    if near:
        return near.group(1)
    m = _OTP_RE.search(body)
    return m.group(1) if m else None


# --------------------------------------------------------------------------- #
# Outbound — operator-only (consensual notification), NOT a generic capability
# --------------------------------------------------------------------------- #
def _assert_operator(to_number: str) -> str:
    operator = env("SYBER_OPERATOR_PHONE")
    if not operator:
        raise IntegrationNotConfigured(
            "SYBER_OPERATOR_PHONE is not set. Outbound is restricted to the operator's "
            "own number; set it in .env to receive notifications."
        )
    if to_number not in ("", operator):
        raise IntegrationError(
            "Refused: outbound calls/SMS are restricted to the operator number "
            f"({operator}). Calling arbitrary numbers is out of scope for this platform."
        )
    return operator


def notify_operator_sms(body: str) -> dict[str, Any]:
    """Send an SMS to the OPERATOR's own number only (e.g. 'engagement complete')."""
    to = _assert_operator("")
    agent_id = env("AGENTPHONE_AGENT_ID") or ""
    return http_json("POST", f"{BASE}/v1/messages", token=_token(),
                     body={"agent_id": agent_id, "to_number": to, "body": body})


def call_operator(message: str, greeting: str = "Hi, this is your Syber agent.") -> dict[str, Any]:
    """Place a call to the OPERATOR's own number only (the consensual 'call me'
    demo). Refuses any other number."""
    to = _assert_operator("")
    agent_id = env("AGENTPHONE_AGENT_ID") or ""
    return http_json("POST", f"{BASE}/v1/calls", token=_token(),
                     body={"agentId": agent_id, "toNumber": to,
                           "systemPrompt": message, "initialGreeting": greeting})
