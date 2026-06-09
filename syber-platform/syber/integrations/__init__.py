"""External communication integrations for identity provisioning.

These modules let the Syber agent stand up its OWN test identities — real email
inboxes (AgentMail) and a real phone number (AgentPhone) — so that authenticated
attacks that require *multiple verified accounts* become possible. The flagship
use case is IDOR / BOLA (OWASP API #1): to prove that account A's objects can be
read by account B you first need two real, signup-confirmed sessions, and signup
confirmation arrives by email (verification link) or SMS (OTP).

SCOPE BOUNDARY — read before extending:
  * These tools touch only the agent's *own* AgentMail / AgentPhone account.
    They never touch the engagement target, so they are NOT behind the
    target-authorisation gate (`syber.scanning.active_scan._require_authorized`).
    That gate still governs every action against the target itself.
  * Inbound is fully enabled (receive signup emails / OTP SMS). Outbound calling
    and SMS to arbitrary numbers is deliberately NOT exposed — pointed at third
    parties that is vishing/smishing, a separate consent domain. Outbound is
    library-only and restricted to the configured operator number
    (`SYBER_OPERATOR_PHONE`) for consensual notifications.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


class IntegrationError(RuntimeError):
    """An integration call failed (HTTP error, bad response)."""


class IntegrationNotConfigured(IntegrationError):
    """A required API key / env var is missing. Raised instead of crashing so the
    agent gets an actionable message (set the key) rather than a stack trace."""


def http_json(
    method: str,
    url: str,
    *,
    token: str,
    body: dict[str, Any] | None = None,
    timeout: int = 30,
    auth_scheme: str = "Bearer",
) -> Any:
    """Minimal JSON-over-HTTP helper (stdlib only, no new deps) shared by the
    AgentMail / AgentPhone clients. Raises IntegrationError on transport or
    non-2xx responses with the server's message attached."""
    # A real browser User-Agent: some API edges (AgentPhone is behind Cloudflare)
    # ban the default "Python-urllib/x" signature with a 1010 error.
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
    }
    if auth_scheme and token:
        headers["Authorization"] = f"{auth_scheme} {token}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method.upper(), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (trusted API host)
            raw = r.read().decode("utf-8", "replace")
            return json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            pass
        raise IntegrationError(f"{method} {url} -> HTTP {e.code}: {detail[:500]}") from e
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise IntegrationError(f"{method} {url} failed: {e}") from e


def env(name: str, default: str | None = None) -> str | None:
    v = os.getenv(name)
    return v if v not in (None, "") else default
