"""AgentMail client — programmatic email inboxes for the agent's own test accounts.

REST API: https://api.agentmail.to   Auth: Bearer $AGENTMAIL_API_KEY
Docs: https://docs.agentmail.to

`inbox_id` IS the email address (e.g. "abc123@agentmail.to"); use it both as the
signup address on the target and as the handle to read confirmation mail.

Only the agent's own AgentMail account is touched here — see SCOPE BOUNDARY in
syber.integrations.__init__.
"""
from __future__ import annotations

import re
import time
import urllib.parse
from typing import Any

from . import IntegrationNotConfigured, env, http_json

BASE = "https://api.agentmail.to"

# Verification artefacts to lift out of confirmation mail.
_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+")
_OTP_RE = re.compile(r"\b(\d{4,8})\b")


def _token() -> str:
    key = env("AGENTMAIL_API_KEY")
    if not key:
        raise IntegrationNotConfigured(
            "AGENTMAIL_API_KEY is not set. Add it to syberAgent/.env "
            "(get a key at https://console.agentmail.to) and restart the agent."
        )
    return key


def configured() -> bool:
    return bool(env("AGENTMAIL_API_KEY"))


# --------------------------------------------------------------------------- #
# Inboxes
# --------------------------------------------------------------------------- #
def create_inbox(client_id: str | None = None, username: str | None = None,
                 domain: str | None = None) -> dict[str, Any]:
    """Create an inbox. `client_id` makes the create idempotent across retries.
    Returns the inbox dict; `inbox_id` is the email address."""
    body: dict[str, Any] = {}
    if client_id:
        body["client_id"] = client_id
    if username:
        body["username"] = username
    if domain:
        body["domain"] = domain
    return http_json("POST", f"{BASE}/inboxes", token=_token(), body=body or None)


def list_inboxes() -> list[dict[str, Any]]:
    out = http_json("GET", f"{BASE}/inboxes", token=_token())
    return out.get("inboxes", out) if isinstance(out, dict) else out


def delete_inbox(inbox_id: str) -> dict[str, Any]:
    """Delete an inbox (free-tier accounts have a small inbox cap; clean up test
    identities after an engagement)."""
    return http_json("DELETE", f"{BASE}/inboxes/{urllib.parse.quote(inbox_id, safe='')}",
                      token=_token())


def address_of(inbox: dict[str, Any]) -> str:
    """The email address from a create_inbox response (the API uses inbox_id as
    the address, but tolerate a few field spellings)."""
    for k in ("inbox_id", "address", "email", "inbox"):
        if inbox.get(k):
            return str(inbox[k])
    return ""


# --------------------------------------------------------------------------- #
# Messages
# --------------------------------------------------------------------------- #
def list_messages(inbox_id: str, limit: int = 10, labels: str | None = None) -> list[dict[str, Any]]:
    url = f"{BASE}/inboxes/{inbox_id}/messages?limit={int(limit)}"
    if labels:
        url += f"&labels={labels}"
    out = http_json("GET", url, token=_token())
    return out.get("messages", out) if isinstance(out, dict) else out


def get_message(inbox_id: str, message_id: str) -> dict[str, Any]:
    # message_id can contain '<', '>', '@' (RFC822 Message-ID) — encode the path segment.
    mid = urllib.parse.quote(message_id, safe="")
    return http_json("GET", f"{BASE}/inboxes/{inbox_id}/messages/{mid}", token=_token())


def _message_text(msg: dict[str, Any]) -> str:
    """Best available body text from a message summary or full message."""
    for k in ("extracted_text", "text", "preview", "snippet"):
        if msg.get(k):
            return str(msg[k])
    return str(msg.get("extracted_html") or msg.get("html") or "")


def _message_id(msg: dict[str, Any]) -> str:
    for k in ("message_id", "id", "messageId"):
        if msg.get(k):
            return str(msg[k])
    return ""


def wait_for_message(inbox_id: str, match: str | None = None, timeout: int = 120,
                     poll: int = 5) -> dict[str, Any] | None:
    """Poll the inbox until a (optionally matching) message arrives. `match` is a
    case-insensitive substring tested against subject + sender + body. Returns the
    full message dict, or None on timeout. Signup mail can take 10–60s."""
    deadline = time.time() + max(1, timeout)
    needle = (match or "").lower()
    seen: set[str] = set()
    while time.time() < deadline:
        for m in list_messages(inbox_id, limit=10):
            mid = _message_id(m)
            if mid in seen:
                continue
            seen.add(mid)
            try:
                full = get_message(inbox_id, mid) if mid else m
            except Exception:  # noqa: BLE001 — fall back to the list summary (still has text/preview)
                full = m
            blob = " ".join(str(full.get(k, "")) for k in ("subject", "from", "sender")) \
                + " " + _message_text(full)
            if not needle or needle in blob.lower():
                return full
        time.sleep(max(1, poll))
    return None


# --------------------------------------------------------------------------- #
# Verification extraction (links + OTP) from confirmation mail
# --------------------------------------------------------------------------- #
def extract_links(msg: dict[str, Any]) -> list[str]:
    body = _message_text(msg) + " " + str(msg.get("html") or msg.get("extracted_html") or "")
    # De-dupe, preserve order, prefer ones that look like verify/confirm links first.
    seen, links = set(), []
    for u in _URL_RE.findall(body):
        u = u.rstrip(".,);")
        if u not in seen:
            seen.add(u)
            links.append(u)
    verify_first = [u for u in links if re.search(r"verif|confirm|activat|token|magic", u, re.I)]
    rest = [u for u in links if u not in verify_first]
    return verify_first + rest


def extract_otp(msg: dict[str, Any]) -> str | None:
    """Lift a 4–8 digit OTP from a confirmation message, preferring a code that
    appears next to a keyword like 'code' / 'OTP' / 'verification'."""
    body = _message_text(msg)
    near = re.search(r"(?:code|otp|verif\w*|pin)\D{0,20}(\d{4,8})", body, re.I)
    if near:
        return near.group(1)
    m = _OTP_RE.search(body)
    return m.group(1) if m else None
