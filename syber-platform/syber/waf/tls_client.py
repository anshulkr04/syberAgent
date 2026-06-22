"""
L1 — TLS / HTTP-2 fingerprint impersonation (waf-spec §3.1, §4.1).

Cloudflare's *first* filter is the TLS/HTTP-2 fingerprint (JA3/JA4/JA4H): Python's
``requests``/``urllib`` produce a non-browser ClientHello that is flagged before a
single header is read (waf-spec §2.1–2.2). ``curl_cffi`` wraps curl-impersonate to
emit a real Chrome/Firefox/Safari fingerprint — the single most impactful technique
(waf-spec §3.1). We use it when present.

curl_cffi has no Python-3.14 wheel yet (this machine runs 3.14), so — exactly like
the platform's torch / transformers / SBERT fallbacks — this module degrades to a
stdlib ``urllib`` transport that still carries a browser User-Agent, proxy, and
cookies. The fingerprint is then non-browser, so L1 alone won't clear a strict
site; the request flow escalates to L3 (a real browser) which IS fingerprint-clean.
Install ``curl_cffi`` on Python ≤3.12 and it is auto-detected, no code change.

Returns a normalised ``FetchResult`` regardless of backend.
"""
from __future__ import annotations

import http.cookies
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

__all__ = ["FetchResult", "TLSClient", "curl_cffi_available"]


@dataclass
class FetchResult:
    status: int | None
    headers: dict[str, str]
    body: str
    set_cookies: dict[str, str] = field(default_factory=dict)  # name -> value
    transport: str = "urllib"        # curl_cffi | urllib
    error: str | None = None

    @property
    def length(self) -> int:
        return len(self.body or "")

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status, "headers": self.headers,
                "body": self.body, "length": self.length,
                "transport": self.transport, "error": self.error}


def curl_cffi_available() -> bool:
    try:
        import curl_cffi  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def _parse_set_cookies(raw_values: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in raw_values:
        try:
            jar = http.cookies.SimpleCookie()
            jar.load(raw)
            for name, morsel in jar.items():
                out[name] = morsel.value
        except Exception:  # noqa: BLE001 - malformed Set-Cookie, skip
            continue
    return out


class TLSClient:
    """Browser-fingerprint HTTP client (curl_cffi) with a urllib fallback."""

    def __init__(self, impersonate: str = "chrome120", user_agent: str = "",
                 timeout: int = 30):
        self.impersonate = impersonate
        self.user_agent = user_agent
        self.timeout = timeout
        self._use_curl = curl_cffi_available()

    @property
    def transport_name(self) -> str:
        return "curl_cffi" if self._use_curl else "urllib"

    def fetch(self, url: str, method: str = "GET",
              headers: dict[str, str] | None = None, body: str | None = None,
              cookies: str | None = None, proxy: str | None = None,
              timeout: int | None = None) -> FetchResult:
        headers = dict(headers or {})
        if self.user_agent and not any(k.lower() == "user-agent" for k in headers):
            headers["User-Agent"] = self.user_agent
        if cookies:
            headers["Cookie"] = cookies
        timeout = timeout or self.timeout
        if self._use_curl:
            return self._fetch_curl(url, method, headers, body, proxy, timeout)
        return self._fetch_urllib(url, method, headers, body, proxy, timeout)

    # ------------------------------------------------------------------ #
    def _fetch_curl(self, url, method, headers, body, proxy, timeout) -> FetchResult:
        try:  # pragma: no cover - only runs where curl_cffi is installed
            from curl_cffi import requests as cffi_requests

            proxies = {"http": proxy, "https": proxy} if proxy else None
            r = cffi_requests.request(
                method, url, headers=headers, data=body, proxies=proxies,
                impersonate=self.impersonate, timeout=timeout, allow_redirects=True)
            set_cookies = {c.name: c.value for c in r.cookies.jar} if hasattr(r, "cookies") else {}
            return FetchResult(status=r.status_code,
                               headers={k.lower(): v for k, v in r.headers.items()},
                               body=r.text or "", set_cookies=set_cookies,
                               transport="curl_cffi")
        except Exception as e:  # noqa: BLE001 - fall back to urllib on any curl error
            return self._fetch_urllib(url, method, headers, body, proxy, timeout,
                                      note=f"curl_cffi error: {e}")

    def _fetch_urllib(self, url, method, headers, body, proxy, timeout,
                      note: str | None = None) -> FetchResult:
        handlers: list[urllib.request.BaseHandler] = []
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        opener = urllib.request.build_opener(*handlers)
        data = body.encode("utf-8", "replace") if isinstance(body, str) else body
        req = urllib.request.Request(url, data=data, method=method.upper(), headers=headers)
        try:
            with opener.open(req, timeout=timeout) as resp:
                raw = resp.read()
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                set_cookies = _parse_set_cookies(resp.headers.get_all("Set-Cookie") or [])
                return FetchResult(status=resp.status,
                                   headers=hdrs,
                                   body=raw.decode("utf-8", "replace"),
                                   set_cookies=set_cookies, transport="urllib",
                                   error=note)
        except urllib.error.HTTPError as e:
            raw = e.read() if hasattr(e, "read") else b""
            hdrs = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
            set_cookies = _parse_set_cookies(
                e.headers.get_all("Set-Cookie") if e.headers else [] or [])
            # An HTTPError IS the response (403 challenge, 429, etc.) — return it.
            return FetchResult(status=e.code, headers=hdrs,
                               body=raw.decode("utf-8", "replace"),
                               set_cookies=set_cookies, transport="urllib", error=note)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            return FetchResult(status=None, headers={}, body="", transport="urllib",
                               error=note or f"transport error: {e}")
