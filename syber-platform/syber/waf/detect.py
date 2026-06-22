"""
Cloudflare challenge detection (waf-spec §2) — pure, network-free signatures.

Cloudflare fuses many signals into a composite risk score; when it trips, the
*origin response itself* carries tell-tale markers (status, headers, body) that
let us classify what kind of obstacle we hit and decide which layer (L2 session
reuse, L3 challenge solver, L4 CAPTCHA) should handle it.

Everything here is pure data + functions over (status, headers, body) so it is
unit-tested without any network — the same discipline the web-app testing layer
uses for its SQLi/XSS signatures (see scanning/webapp.py).

Challenge taxonomy (waf-spec §2.3–2.4, §4.4 `challenge_type`):
  * ``js_challenge``          — the classic "Just a moment…" interstitial that
                                runs an obfuscated JS computation to set
                                ``cf_clearance`` (solvable headlessly).
  * ``turnstile_managed``     — a Turnstile widget on a managed-challenge page
                                (mostly invisible proof-of-work; solvable
                                headlessly in managed/non-interactive mode).
  * ``turnstile_interactive`` — Turnstile demanding a user action (needs a
                                CAPTCHA-solving service, L4).
  * ``managed_challenge``     — a generic Cloudflare managed challenge with no
                                Turnstile widget surfaced in the HTML.
  * ``rate_limited``          — HTTP 429; honour ``Retry-After`` (waf-spec §4.6).
  * ``blocked``               — a hard block (error 1020/1010/1006…); not a
                                challenge — no amount of solving helps.

References: waf-spec §2; Cloudflare challenge-platform markers as documented in
the public bypass research (FlareSolverr, curl_cffi, scrapfly/bright-data write-ups).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

__all__ = ["ChallengeInfo", "detect_challenge", "is_cloudflare",
           "extract_turnstile_sitekey", "parse_retry_after", "extract_cf_clearance"]

# Body markers that the Cloudflare challenge-platform injects into interstitials.
_JS_CHALLENGE_MARKERS = [
    r"/cdn-cgi/challenge-platform/",
    r"challenge-platform",
    r"cf[-_]chl[-_]?opt",
    r"__cf_chl_",
    r"cf_chl_",
    r"jschl[-_]?vc",
    r"jschl[-_]?answer",
    r"cf-browser-verification",
    r"cf_im_under_attack",
    r"just a moment\s*\.\.\.|just a moment&hellip;",
    r"checking (your|if the site connection is) (browser|secure)",
    r"please (stand by|wait)[^<]{0,40}(while )?we (check|are checking)",
    r"enable javascript and cookies to continue",
]
_JS_CHALLENGE_RX = re.compile("|".join(_JS_CHALLENGE_MARKERS), re.IGNORECASE)

# A Turnstile widget. Managed/interactive can't be told apart purely from the
# server response; we surface the widget + sitekey and let the solver attempt the
# (cheaper) managed path first, escalating to L4 only if that proof-of-work fails.
_TURNSTILE_MARKERS = [
    r"cf-turnstile",
    r"challenges\.cloudflare\.com/turnstile",
    r"turnstile/v0/api\.js",
]
_TURNSTILE_RX = re.compile("|".join(_TURNSTILE_MARKERS), re.IGNORECASE)
# Turnstile/Cloudflare sitekeys look like ``0x4AAAAAAA...`` (0x + base62).
_SITEKEY_RX = re.compile(r"""(?:data-sitekey|['"]?sitekey['"]?)\s*[:=]\s*['"]?(0x[A-Za-z0-9_-]{8,})""",
                         re.IGNORECASE)

# Hard-block markers. These are NOT challenges — solving cannot help; the agent
# must back off / rotate IP (waf-spec §2.5) or stop.
_BLOCK_MARKERS = [
    r"error code:?\s*1020",            # access denied (firewall rule)
    r"error code:?\s*1010",            # browser signature banned
    r"error code:?\s*1006|1007|1008",  # IP banned
    r"sorry, you have been blocked",
    r"you (have been|are) blocked",
    r"this website is using a security service to protect itself",
    r"attention required!\s*\|\s*cloudflare",
]
_BLOCK_RX = re.compile("|".join(_BLOCK_MARKERS), re.IGNORECASE)

_CF_RAY_RX = re.compile(r"\b([0-9a-f]{16})-([A-Z]{3})\b")  # cf-ray value shape


@dataclass
class ChallengeInfo:
    """The verdict for one response. ``detected`` False == a clean pass-through."""

    detected: bool
    kind: str                       # one of the taxonomy strings, or "" when clean
    cloudflare: bool                # did this response come from Cloudflare at all?
    status: int | None = None
    sitekey: str | None = None      # Turnstile sitekey, when present
    ray_id: str | None = None       # cf-ray, for correlating with CF logs
    retry_after: float | None = None  # seconds, from a 429
    reason: str = ""

    # Which traversal layer should handle this verdict (waf-spec §4.1 L2–L4).
    @property
    def solvable_headless(self) -> bool:
        """True when an automated browser (L3) can plausibly clear it."""
        return self.kind in {"js_challenge", "turnstile_managed", "managed_challenge"}

    @property
    def needs_captcha_service(self) -> bool:
        """True when L3 won't suffice and L4 (a solving service) is required."""
        return self.kind == "turnstile_interactive"

    @property
    def is_block(self) -> bool:
        return self.kind == "blocked"

    def to_dict(self) -> dict[str, Any]:
        return {
            "detected": self.detected, "kind": self.kind, "cloudflare": self.cloudflare,
            "status": self.status, "sitekey": self.sitekey, "ray_id": self.ray_id,
            "retry_after": self.retry_after, "reason": self.reason,
            "solvable_headless": self.solvable_headless,
            "needs_captcha_service": self.needs_captcha_service,
        }


def _norm_headers(headers: dict[str, str] | None) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in (headers or {}).items()}


def is_cloudflare(headers: dict[str, str] | None, body: str | None = None) -> bool:
    """True if the response was served by Cloudflare (so a 403/503 is a CF verdict
    rather than the origin's own). Looks for ``server: cloudflare``, the ``cf-ray``
    /``cf-mitigated``/``cf-cache-status`` headers, or a cdn-cgi body marker."""
    h = _norm_headers(headers)
    if "cf-ray" in h or "cf-mitigated" in h or "cf-cache-status" in h:
        return True
    if "cloudflare" in h.get("server", "").lower():
        return True
    b = body or ""
    return "/cdn-cgi/" in b or "cloudflare" in b.lower() and "ray id" in b.lower()


def extract_turnstile_sitekey(body: str | None) -> str | None:
    """Pull the Turnstile sitekey out of a challenge page so L4 can request a token."""
    m = _SITEKEY_RX.search(body or "")
    return m.group(1) if m else None


def parse_retry_after(headers: dict[str, str] | None) -> float | None:
    """Parse a ``Retry-After`` header (delta-seconds form) to a float, else None.

    Cloudflare's rate-limit 429s use the numeric form; the HTTP-date form is rare
    here and we fall back to None (the caller then uses exponential backoff)."""
    raw = _norm_headers(headers).get("retry-after")
    if not raw:
        return None
    try:
        return max(0.0, float(raw.strip()))
    except (ValueError, TypeError):
        return None


def extract_cf_clearance(set_cookie_values: list[str] | dict[str, str] | None) -> str | None:
    """Return the ``cf_clearance`` value from Set-Cookie data (a list of raw
    Set-Cookie strings, or an already-parsed name->value mapping)."""
    if not set_cookie_values:
        return None
    if isinstance(set_cookie_values, dict):
        return set_cookie_values.get("cf_clearance")
    for raw in set_cookie_values:
        m = re.search(r"\bcf_clearance=([^;]+)", raw or "")
        if m:
            return m.group(1)
    return None


def detect_challenge(status: int | None, headers: dict[str, str] | None,
                     body: str | None = None) -> ChallengeInfo:
    """Classify a response. Returns a ChallengeInfo whose ``kind`` drives the
    layer-escalation decision in WAFIntegration (waf-spec §4.3).

    Decision order (cheapest signal first):
      1. 429 -> rate_limited (honour Retry-After).
      2. Not Cloudflare, or 2xx/3xx with no markers -> clean pass-through.
      3. Hard-block markers -> blocked (don't try to solve).
      4. Turnstile widget present -> turnstile_managed (sitekey captured).
      5. JS-challenge markers -> js_challenge.
      6. 403/503 from Cloudflare with no specific marker -> managed_challenge.
    """
    h = _norm_headers(headers)
    b = body or ""
    cf = is_cloudflare(headers, body)
    ray = None
    if h.get("cf-ray"):
        ray = h["cf-ray"].split("-")[0]
    else:
        m = _CF_RAY_RX.search(b)
        ray = m.group(1) if m else None

    # 1. Rate limiting is independent of Cloudflare-ness (origin or CF may 429).
    if status == 429:
        return ChallengeInfo(detected=True, kind="rate_limited", cloudflare=cf,
                             status=status, ray_id=ray,
                             retry_after=parse_retry_after(headers),
                             reason="HTTP 429 rate limited")

    # 2. Clean response: a success/redirect with no challenge body markers.
    cf_mitigated = "challenge" in h.get("cf-mitigated", "").lower()
    looks_challenged = bool(_JS_CHALLENGE_RX.search(b) or _TURNSTILE_RX.search(b)
                            or _BLOCK_RX.search(b) or cf_mitigated)
    if status is not None and status < 400 and not looks_challenged:
        return ChallengeInfo(detected=False, kind="", cloudflare=cf, status=status,
                             ray_id=ray, reason="clean response")

    # 3. Hard block — solving cannot help (waf-spec §2.5).
    if _BLOCK_RX.search(b):
        return ChallengeInfo(detected=True, kind="blocked", cloudflare=cf, status=status,
                             ray_id=ray, reason="Cloudflare hard block (firewall/IP ban)")

    # 4. Turnstile widget — managed proof-of-work first (L3), escalate to L4 if it fails.
    if _TURNSTILE_RX.search(b):
        return ChallengeInfo(detected=True, kind="turnstile_managed", cloudflare=cf,
                             status=status, ray_id=ray,
                             sitekey=extract_turnstile_sitekey(b),
                             reason="Cloudflare Turnstile widget present")

    # 5. Classic JS interstitial.
    if _JS_CHALLENGE_RX.search(b):
        return ChallengeInfo(detected=True, kind="js_challenge", cloudflare=cf,
                             status=status, ray_id=ray,
                             reason="Cloudflare JS challenge interstitial")

    # 6. A 403/503 from Cloudflare with no surfaced marker — treat as a managed
    #    challenge (try the headless solver; it will report if it can't clear it).
    if cf and status in (403, 503) or cf_mitigated:
        return ChallengeInfo(detected=True, kind="managed_challenge", cloudflare=cf,
                             status=status, ray_id=ray,
                             reason="Cloudflare managed challenge (no specific marker)")

    # Non-Cloudflare 4xx/5xx: not our concern — pass the verdict back as undetected.
    return ChallengeInfo(detected=False, kind="", cloudflare=cf, status=status,
                         ray_id=ray, reason="non-Cloudflare response")
