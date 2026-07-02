"""
Resend email client — deliver the engagement report + proofs to the operator.

Used by ``syber.reporting`` to email a verifiable report (gated findings + attached
evidence: downloaded data samples, screenshots, HTTP request/response captures) so the
operator can confirm each finding is real before forwarding it to the target org.

Same posture as the other integrations: stdlib urllib via the shared ``http_json``
helper, actionable error on a missing key (never a stack trace). Resend REST API:
POST https://api.resend.com/emails  (Bearer RESEND_API_KEY).
"""
from __future__ import annotations

from typing import Any

from . import IntegrationNotConfigured, env, http_json

_API = "https://api.resend.com"
# Resend's shared sandbox sender works with NO domain verification, but only delivers
# to the Resend account owner's own address — perfect for the operator-verify loop.
# Set SYBER_REPORT_FROM to a verified-domain sender to email the target org directly.
_DEFAULT_FROM = "Syber Security <onboarding@resend.dev>"


def configured() -> bool:
    return bool(env("RESEND_API_KEY"))


def _key() -> str:
    key = env("RESEND_API_KEY")
    if not key:
        raise IntegrationNotConfigured(
            "RESEND_API_KEY not set. Add it to syberAgent/.env (and to the .mcp.json env block) "
            "to enable emailed reports.")
    return key


def send_email(to: str | list[str], subject: str, html: str, *,
               text: str | None = None, from_addr: str | None = None,
               attachments: list[dict[str, str]] | None = None,
               reply_to: str | None = None) -> dict[str, Any]:
    """Send one email. ``attachments`` = list of {filename, content} where content is
    base64-encoded file bytes (Resend's REST attachment format). Returns the Resend
    response ({"id": ...} on success)."""
    key = _key()
    to_list = [to] if isinstance(to, str) else list(to)
    body: dict[str, Any] = {
        "from": from_addr or env("SYBER_REPORT_FROM", _DEFAULT_FROM),
        "to": to_list,
        "subject": subject,
        "html": html,
    }
    if text:
        body["text"] = text
    if reply_to:
        body["reply_to"] = reply_to
    if attachments:
        body["attachments"] = attachments
    return http_json("POST", f"{_API}/emails", token=key, body=body, timeout=60)
