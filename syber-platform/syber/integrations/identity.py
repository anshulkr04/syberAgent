"""Test-identity provisioning — the bridge between the comms integrations and the
IDOR/BOLA engine.

The agent calls `provision_identity()` once per account it needs to register on the
target (typically two: account A and account B). It then drives the target's own
signup form with that email/phone, and calls `harvest_verification()` to pull the
confirmation link or OTP back out of the inbox / SMS so it can complete signup and
capture a real authenticated session. Two such sessions are exactly what
`webapp.test_access_control(cookies_a, cookies_b)` needs to prove broken object
authorisation.

Nothing here touches the target — see SCOPE BOUNDARY in syber.integrations.__init__.
"""
from __future__ import annotations

import time
from typing import Any

from . import IntegrationError
from . import agentmail, agentphone


def provision_identity(label: str = "acct", want_phone: bool = False) -> dict[str, Any]:
    """Stand up a fresh test identity: a real inbox (always) and, if `want_phone`,
    the shared provisioned phone number for SMS-OTP signups.

    Returns {email, inbox_id, phone, number_id, label, ts}. `inbox_id` is the
    handle for harvest_verification(); `email`/`phone` go into the target's signup
    form."""
    client_id = f"syber-{label}-{int(time.time())}"
    inbox = agentmail.create_inbox(client_id=client_id)
    addr = agentmail.address_of(inbox)
    if not addr:
        raise IntegrationError(f"AgentMail returned no address for inbox: {inbox}")

    out: dict[str, Any] = {
        "label": label,
        "email": addr,
        "inbox_id": addr,
        "phone": None,
        "number_id": None,
        "ts": int(time.time()),
    }
    if want_phone:
        if not agentphone.configured():
            out["phone_error"] = (
                "phone requested but AgentPhone is not configured (run the one-time "
                "signup). Email identity still provisioned."
            )
        else:
            from . import env
            out["phone"] = env("AGENTPHONE_NUMBER")
            out["number_id"] = env("AGENTPHONE_NUMBER_ID")
    return out


def harvest_verification(inbox_id: str, timeout: int = 120, want_sms: bool = False,
                         sms_match: str | None = None) -> dict[str, Any]:
    """After triggering signup on the target, pull the confirmation back out:
    the verification link(s) and any OTP from email, plus SMS OTP if `want_sms`.
    Returns {email_links, email_otp, sms_otp, raw_subject}. Empty fields mean
    nothing matching arrived before `timeout`."""
    result: dict[str, Any] = {"email_links": [], "email_otp": None,
                              "sms_otp": None, "raw_subject": None}

    msg = agentmail.wait_for_message(inbox_id, timeout=timeout)
    if msg:
        result["raw_subject"] = msg.get("subject")
        result["email_links"] = agentmail.extract_links(msg)
        result["email_otp"] = agentmail.extract_otp(msg)

    if want_sms and agentphone.configured():
        sms = agentphone.wait_for_sms(match=sms_match, timeout=timeout)
        if sms:
            result["sms_otp"] = agentphone.extract_otp(sms)

    return result
