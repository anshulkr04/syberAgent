"""
L3 — challenge solvers (waf-spec §3.2–3.3, §4.1).

When L1 (TLS impersonation) isn't enough — a JS challenge or a Turnstile widget
must actually be *executed* — a real browser solves it and yields the
``cf_clearance`` cookie, which L2 then replays cheaply (waf-spec §3.6).

Three engines behind one interface:

  * AgentBrowserSolver — drives the platform's own ``agent-browser`` + Chromium
    (the same real browser used for recon/web-app testing). It opens the URL,
    waits for the interstitial to clear, then reads cookies via CDP
    (``cookies get`` — which, unlike ``document.cookie``, returns the HttpOnly
    ``cf_clearance``). This is the default: no new dependency, and the browser is
    fingerprint-clean where a patched HTTP client is not. (waf-spec §3.2 lists
    PyDoll; we reuse the browser the platform already ships.)
  * FlareSolverrSolver — POSTs to a FlareSolverr proxy (waf-spec §3.3) and lifts
    ``cf_clearance`` from its returned cookie jar. A drop-in fallback engine.
  * PyDollSolver — import-guarded adapter for PyDoll (waf-spec §3.2) when it is
    installed; otherwise reports unavailable.

Every engine returns a SolveResult; failures are reported, never raised, so the
request flow can escalate (to L4 / WAFBlockError) rather than crash.
"""
from __future__ import annotations

import json
import time
import urllib.request
from dataclasses import dataclass
from typing import Any

from .cookie_store import CookieRecord
from .detect import detect_challenge

__all__ = ["SolveResult", "ChallengeSolver", "AgentBrowserSolver",
           "FlareSolverrSolver", "PyDollSolver", "make_solver"]


@dataclass
class SolveResult:
    ok: bool
    cookie: CookieRecord | None = None
    user_agent: str = ""
    final_url: str = ""
    body: str = ""
    engine: str = ""
    error: str | None = None


class ChallengeSolver:
    name = "base"

    def available(self) -> bool:
        raise NotImplementedError

    def solve(self, url: str, domain: str, *, ip: str = "",
              timeout: int = 60) -> SolveResult:
        raise NotImplementedError


# --------------------------------------------------------------------------- #
# Agent-browser engine (default) — reuses the platform's real Chrome driver.
# --------------------------------------------------------------------------- #
class AgentBrowserSolver(ChallengeSolver):
    name = "agent-browser"

    def __init__(self, headless: bool = True, poll_interval: float = 1.5):
        self.headless = headless
        self.poll_interval = poll_interval

    def available(self) -> bool:
        # Reuse the recon module's detection so we share one source of truth.
        from ..recon.browser_recon import browser_available
        return browser_available()

    def _ab(self, args: list[str], timeout: int = 45):
        from ..recon.browser_recon import _ab
        return _ab(args, timeout=timeout)

    def solve(self, url: str, domain: str, *, ip: str = "",
              timeout: int = 60) -> SolveResult:
        if not self.available():
            return SolveResult(ok=False, engine=self.name,
                               error="agent-browser not installed")
        import uuid
        sess = f"waf-{uuid.uuid4().hex[:8]}"
        try:
            self._ab(["--session", sess, "open", url], timeout=min(timeout, 60))
            ua = self._read_ua(sess)
            deadline = time.time() + timeout
            cleared = False
            html = ""
            # Poll the rendered page until the challenge interstitial disappears.
            while time.time() < deadline:
                self._ab(["--session", sess, "wait", str(int(self.poll_interval * 1000))])
                html = self._page_html(sess)
                # An empty/parse-failed read is NOT a clear — keep waiting for Chrome
                # to finish solving (the challenge takes a few seconds).
                if len(html) < 256:
                    continue
                verdict = detect_challenge(200, {}, html)
                if not verdict.detected or verdict.kind == "blocked":
                    cleared = not verdict.detected
                    if verdict.kind == "blocked":
                        return SolveResult(ok=False, engine=self.name, user_agent=ua,
                                           body=html[:4000],
                                           error="hard block — cannot solve")
                    break
            cookies = self._read_cookies(sess)
            clearance = cookies.get("cf_clearance")
            final_url = self._read_url(sess)
            if clearance:
                rec = CookieRecord(domain=domain, cookie_value=clearance, ip_address=ip,
                                   user_agent=ua, challenge_type="js_challenge")
                return SolveResult(ok=True, cookie=rec, user_agent=ua, body=html,
                                   final_url=final_url, engine=self.name)
            # Challenge cleared in the browser but Cloudflare issued no cf_clearance
            # (it can bind to the live browser session, or skip the cookie). Hand back
            # the *rendered* page so the caller still gets real content (not the
            # interstitial), even on Python 3.14 without curl_cffi.
            return SolveResult(ok=cleared, engine=self.name, user_agent=ua, body=html,
                               final_url=final_url,
                               error=None if cleared else "challenge not cleared "
                                     "(headless may be detected — try headless:false / curl_cffi)")
        finally:
            self._ab(["--session", sess, "close", "--all"], timeout=15)

    # ---- agent-browser output parsing ---------------------------------- #
    def _read_ua(self, sess: str) -> str:
        rc, out, _ = self._ab(["--session", sess, "eval", "navigator.userAgent"])
        return _unjson_str(out)

    def _read_url(self, sess: str) -> str:
        rc, out, _ = self._ab(["--session", sess, "get", "url"])
        return out.strip()

    def _page_html(self, sess: str) -> str:
        # `get html` is truncated; eval the live DOM for the full rendered page.
        rc, out, _ = self._ab(["--session", sess, "eval", "document.documentElement.outerHTML"])
        return _unjson_str(out)

    def _read_cookies(self, sess: str) -> dict[str, str]:
        rc, out, _ = self._ab(["--session", sess, "cookies", "get"])
        return parse_ab_cookies(out)


def parse_ab_cookies(raw: str) -> dict[str, str]:
    """Parse ``agent-browser cookies get`` output into name->value.

    The CLI may emit either a JSON array of cookie objects
    ({name,value,domain,...}) or a cookie-header / ``name=value`` listing (one per
    line or ``;``-separated). Handle both, defensively."""
    raw = (raw or "").strip()
    if not raw:
        return {}
    # JSON form first (possibly double-encoded).
    val: Any = raw
    if raw[0] in "[{" or (raw[0] == '"' and raw.lstrip('"')[:1] in "[{"):
        for _ in range(2):
            if isinstance(val, (dict, list)):
                break
            try:
                val = json.loads(val)
            except (json.JSONDecodeError, ValueError):
                val = None
                break
        if isinstance(val, (dict, list)):
            items = val if isinstance(val, list) else val.get("cookies", [])
            out: dict[str, str] = {}
            for c in items:
                if isinstance(c, dict) and "name" in c:
                    out[str(c["name"])] = str(c.get("value", ""))
            return out
    # Cookie-header / key=value form: split on newlines and ';'.
    out = {}
    for chunk in raw.replace(";", "\n").splitlines():
        chunk = chunk.strip()
        if "=" in chunk:
            name, _, value = chunk.partition("=")
            name = name.strip()
            # Skip cookie attributes (Path, Domain, HttpOnly…), keep real pairs.
            if name and name.lower() not in {
                    "path", "domain", "expires", "max-age", "samesite",
                    "secure", "httponly", "priority"}:
                out[name] = value.strip()
    return out


def _unjson_str(raw: str) -> str:
    raw = (raw or "").strip()
    try:
        v = json.loads(raw)
        return v if isinstance(v, str) else raw
    except (json.JSONDecodeError, ValueError):
        return raw


# --------------------------------------------------------------------------- #
# FlareSolverr engine — challenge-solving proxy (waf-spec §3.3).
# --------------------------------------------------------------------------- #
class FlareSolverrSolver(ChallengeSolver):
    name = "flaresolverr"

    def __init__(self, endpoint: str = "http://localhost:8191"):
        self.endpoint = endpoint.rstrip("/")

    def available(self) -> bool:
        try:
            req = urllib.request.Request(self.endpoint + "/", method="GET")
            with urllib.request.urlopen(req, timeout=3):
                return True
        except Exception:  # noqa: BLE001
            return False

    def solve(self, url: str, domain: str, *, ip: str = "",
              timeout: int = 60) -> SolveResult:
        payload = json.dumps({"cmd": "request.get", "url": url,
                              "maxTimeout": int(timeout * 1000)}).encode()
        try:
            req = urllib.request.Request(self.endpoint + "/v1", data=payload,
                                         headers={"Content-Type": "application/json"},
                                         method="POST")
            with urllib.request.urlopen(req, timeout=timeout + 5) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
        except Exception as e:  # noqa: BLE001
            return SolveResult(ok=False, engine=self.name, error=f"flaresolverr error: {e}")
        sol = data.get("solution", {}) if isinstance(data, dict) else {}
        ua = sol.get("userAgent", "")
        clearance = None
        for c in sol.get("cookies", []) or []:
            if c.get("name") == "cf_clearance":
                clearance = c.get("value")
                break
        if clearance:
            rec = CookieRecord(domain=domain, cookie_value=clearance, ip_address=ip,
                               user_agent=ua, challenge_type="js_challenge")
            return SolveResult(ok=True, cookie=rec, user_agent=ua,
                               final_url=sol.get("url", url),
                               body=sol.get("response", ""), engine=self.name)
        return SolveResult(ok=False, engine=self.name, user_agent=ua,
                           error="flaresolverr returned no cf_clearance")


# --------------------------------------------------------------------------- #
# PyDoll engine — import-guarded (waf-spec §3.2).
# --------------------------------------------------------------------------- #
class PyDollSolver(ChallengeSolver):
    name = "pydoll"

    def available(self) -> bool:
        try:
            import pydoll  # noqa: F401
            return True
        except Exception:  # noqa: BLE001
            return False

    def solve(self, url: str, domain: str, *, ip: str = "",
              timeout: int = 60) -> SolveResult:  # pragma: no cover - optional dep
        if not self.available():
            return SolveResult(ok=False, engine=self.name,
                               error="pydoll not installed (pip install pydoll-python)")
        # PyDoll's API is async + version-volatile; we expose the seam and defer to
        # the agent-browser engine in this build. Wire the concrete calls here when
        # pydoll is pinned in the target environment.
        return SolveResult(ok=False, engine=self.name,
                           error="pydoll engine present but not wired in this build; "
                                 "use engine='agent-browser' or 'flaresolverr'")


def make_solver(engine: str = "agent-browser", *, headless: bool = True,
                flaresolverr_url: str = "http://localhost:8191") -> ChallengeSolver | None:
    """Build the configured solver, or None for engine 'none' (waf-spec §5)."""
    engine = (engine or "agent-browser").lower()
    if engine in ("none", "off", ""):
        return None
    if engine == "flaresolverr":
        return FlareSolverrSolver(endpoint=flaresolverr_url)
    if engine == "pydoll":
        return PyDollSolver()
    return AgentBrowserSolver(headless=headless)
