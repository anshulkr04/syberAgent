"""
WAFIntegration — the layered orchestrator (waf-spec §4.1–4.3).

A single ``request()`` entry point runs the deterministic layer-escalation flow,
trying the cheapest method first and escalating only on need (waf-spec §4.3):

    L0 API-first  ->  L2 session reuse  ->  L1 TLS impersonation
                  ->  L3 challenge solver  ->  L4 CAPTCHA service  ->  WAFBlockError

The spec's interface (§4.2) is async; this implementation is synchronous to match
the rest of the platform (urllib, subprocess-driven agent-browser, no event loop).
``batch_request`` uses a thread pool for concurrency, and the per-domain rate
limiter + jitter serialise pacing across threads. A trivial async wrapper can be
layered on top if an asyncio host ever needs one.

Everything degrades gracefully: no proxies -> direct; no solver -> L1 only; no
CAPTCHA key -> L4 reports a block with the sitekey so the agent can solve it via
its own browser session. A genuine dead-end raises ``WAFBlockError`` with full
context (challenge type, status, ray id, body) rather than a bare failure.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlparse

from .config import WAFIntegrationConfig
from .cookie_store import CookieRecord, CookieStore, make_cookie_store
from .detect import ChallengeInfo, detect_challenge, extract_cf_clearance
from .proxy_pool import ProxyEndpoint, ProxyPool, ProxyProvider
from .rate_limiter import JitterEngine, RateLimiter
from .solver import ChallengeSolver, make_solver
from .captcha import CaptchaSolver
from .tls_client import TLSClient

__all__ = ["WAFResponse", "WAFBlockError", "WAFIntegration", "build_waf_integration"]

# Optional L0 hook: (domain, url) -> dict|None. Return a response dict to short-
# circuit through an official API (waf-spec §3.8/§4.1 L0), or None to continue.
APIRouter = Callable[[str, str], "dict | None"]


@dataclass
class WAFResponse:
    status: int | None
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    transport: str = ""
    layer: str = ""                 # which layer produced this (L0..L4)
    domain: str = ""
    cookie_used: bool = False
    attempts: int = 0
    challenge: dict[str, Any] | None = None
    error: str | None = None

    @property
    def length(self) -> int:
        return len(self.body or "")

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 400

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status, "headers": self.headers, "body": self.body,
                "length": self.length, "transport": self.transport, "layer": self.layer,
                "domain": self.domain, "cookie_used": self.cookie_used,
                "attempts": self.attempts, "challenge": self.challenge, "error": self.error}


class WAFBlockError(Exception):
    """Raised when every layer fails (waf-spec §4.3 step 8)."""

    def __init__(self, message: str, *, challenge_type: str = "", status: int | None = None,
                 ray_id: str | None = None, sitekey: str | None = None,
                 captcha_token: str | None = None, body: str = ""):
        super().__init__(message)
        self.challenge_type = challenge_type
        self.status = status
        self.ray_id = ray_id
        self.sitekey = sitekey
        self.captcha_token = captcha_token
        self.body = body

    def to_dict(self) -> dict[str, Any]:
        return {"error": "waf_block", "message": str(self), "challenge_type": self.challenge_type,
                "status": self.status, "ray_id": self.ray_id, "sitekey": self.sitekey,
                "captcha_token": self.captcha_token, "body": (self.body or "")[:2000]}


def _domain_of(url: str) -> str:
    return (urlparse(url).netloc.split("@")[-1].split(":")[0] or "").lower()


def _proxy_id(proxy: ProxyEndpoint | None) -> str:
    """A stable id for the egress path, used as the cookie's ``ip`` key. We can't
    see the real egress IP without a round-trip, so the proxy host is the binding
    key (and "" for a direct connection) — consistent reuse is what matters."""
    if proxy is None:
        return ""
    return _domain_of(proxy.url) or proxy.url


class WAFIntegration:
    """Unified WAF-traversal client (waf-spec §4.2)."""

    def __init__(self, config: WAFIntegrationConfig | None = None, *,
                 cookie_store: CookieStore | None = None,
                 solver: ChallengeSolver | None = None,
                 captcha: CaptchaSolver | None = None,
                 proxy_pool: ProxyPool | None = None,
                 rate_limiter: RateLimiter | None = None,
                 api_router: APIRouter | None = None):
        self.config = config or WAFIntegrationConfig()
        cs = self.config.cookie_store
        self.cookies = cookie_store or make_cookie_store(
            cs.backend, redis_url=cs.redis_url, sqlite_path=cs.sqlite_path,
            default_ttl=cs.default_ttl_s)
        sv = self.config.challenge_solver
        self.solver = solver if solver is not None else make_solver(
            sv.engine, headless=sv.headless, flaresolverr_url=sv.flaresolverr_url)
        cap = self.config.captcha_service
        self.captcha = captcha or CaptchaSolver(provider=cap.provider, api_key=cap.api_key,
                                                poll_interval=cap.poll_interval_s,
                                                max_wait=cap.max_wait_s)
        self.proxies = proxy_pool or _build_proxy_pool(self.config)
        lo, hi = self.config.jitter_range_ms
        self.rate_limiter = rate_limiter or RateLimiter(
            rps=self.config.rate_limit_rps,
            jitter=JitterEngine(lo, hi, self.config.jitter_distribution))
        self.api_router = api_router
        self._client = TLSClient(impersonate=self.config.tls_impersonation,
                                 user_agent=self.config.user_agent)
        # Per-domain effective User-Agent. A cf_clearance is bound to the UA that
        # solved it, so once the L3 browser solves a domain we must replay with that
        # browser's exact UA (same machine -> same IP) or Cloudflare rejects it.
        self._domain_ua: dict[str, str] = {}

    # ------------------------------------------------------------------ #
    # Public interface (waf-spec §4.2)
    # ------------------------------------------------------------------ #
    def request(self, url: str, method: str = "GET",
                headers: dict[str, str] | None = None, body: str | None = None,
                max_retries: int | None = None) -> WAFResponse:
        """Single request with automatic WAF handling (waf-spec §4.3)."""
        domain = _domain_of(url)
        cfg = self.config.for_target(domain)
        max_retries = cfg.max_retries if max_retries is None else max_retries
        headers = dict(headers or {})

        # Step 1 — L0 API-first.
        if self.api_router is not None:
            api = self.api_router(domain, url)
            if api is not None:
                return WAFResponse(status=api.get("status", 200), headers=api.get("headers", {}),
                                   body=api.get("body", ""), transport="api", layer="L0",
                                   domain=domain)

        attempts = 0
        last: WAFResponse | None = None
        while attempts < max(1, max_retries):
            attempts += 1
            ua = self._domain_ua.get(domain, cfg.user_agent)
            proxy = self.proxies.get(domain, sticky=self._has_cookie(domain, cfg))
            proxy_id = _proxy_id(proxy)
            cookie_rec = self.cookies.get(domain, proxy_id, ua)

            # Steps 3–4 — L1 TLS impersonation (carrying the L2 cookie if present).
            # Send the effective UA explicitly so it matches the cf_clearance binding.
            req_headers = dict(headers)
            req_headers["User-Agent"] = ua
            self.rate_limiter.acquire(domain)
            fr = self._client.fetch(
                url, method=method, headers=req_headers, body=body,
                cookies=cookie_rec.cookie_header() if cookie_rec else None,
                proxy=(proxy.url if proxy else None), timeout=cfg.challenge_timeout_s)

            if fr.status is None:
                self.proxies.report_failure(proxy, domain)
                last = WAFResponse(status=None, transport=fr.transport, layer="L1",
                                   domain=domain, attempts=attempts, error=fr.error)
                self.rate_limiter.backoff_and_wait(domain, attempts)
                continue

            verdict = detect_challenge(fr.status, fr.headers, fr.body)
            self._store_new_cookie(domain, proxy_id, ua, fr.set_cookies, verdict)

            # Step 4 — clean pass-through.
            if not verdict.detected:
                self.proxies.report_success(proxy)
                self.rate_limiter.note_success(domain)
                return WAFResponse(status=fr.status, headers=fr.headers, body=fr.body,
                                   transport=fr.transport, layer="L1", domain=domain,
                                   cookie_used=cookie_rec is not None, attempts=attempts)

            # Step 5 — rate limited.
            if verdict.kind == "rate_limited":
                wait = self.rate_limiter.note_rate_limited(domain, verdict.retry_after)
                last = WAFResponse(status=429, headers=fr.headers, body=fr.body,
                                   transport=fr.transport, layer="L1", domain=domain,
                                   attempts=attempts, challenge=verdict.to_dict())
                self.rate_limiter._sleep(min(wait, 60.0))
                continue

            # Hard block — no layer can clear it.
            if verdict.is_block:
                raise WAFBlockError("Cloudflare hard block (firewall/IP ban)",
                                    challenge_type=verdict.kind, status=fr.status,
                                    ray_id=verdict.ray_id, body=fr.body)

            # Steps 6–7 — solve the challenge, then retry the original request.
            solved = self._solve(url, domain, proxy_id, verdict, cfg)
            if solved is not None and solved.ok:
                # Stash the browser-rendered page as a fallback: if cookie replay
                # then fails (CF won't honour cf_clearance off the live browser
                # session), we still return real content instead of "blocked".
                if solved.body:
                    last = WAFResponse(status=200, headers={}, body=solved.body,
                                       transport=f"agent-browser:{solved.engine}", layer="L3",
                                       domain=domain, attempts=attempts,
                                       challenge=verdict.to_dict())
                if solved.cookie is not None:
                    continue  # cf_clearance stored; loop re-fetches with L2 in play
                if solved.body:
                    return last  # cleared, no cookie — hand back the rendered page
                continue
            # Solver couldn't clear it -> fall through to escalation / block.
            last = WAFResponse(status=fr.status, headers=fr.headers, body=fr.body,
                               transport=fr.transport, layer="L3", domain=domain,
                               attempts=attempts, challenge=verdict.to_dict(),
                               error=(solved.error if solved else None) or "challenge unsolved")
            if verdict.needs_captcha_service and not self.captcha.configured:
                raise WAFBlockError(
                    "Interactive Turnstile — no CAPTCHA service configured. Solve via the "
                    "agent's own browser (agent-browser) or set captcha_service.api_key.",
                    challenge_type=verdict.kind, status=fr.status, ray_id=verdict.ray_id,
                    sitekey=verdict.sitekey, body=fr.body)
            self.rate_limiter.backoff_and_wait(domain, attempts)

        # Cookie replay never produced a clean L1 pass, but if the browser rendered
        # the real page, return that content rather than failing the request.
        if last is not None and last.ok and last.body:
            return last
        if last is not None:
            raise WAFBlockError(
                f"WAF traversal exhausted after {attempts} attempts ({last.error or 'challenged'})",
                challenge_type=(last.challenge or {}).get("kind", ""), status=last.status,
                ray_id=(last.challenge or {}).get("ray_id"), body=last.body)
        raise WAFBlockError("WAF traversal failed with no response", status=None)

    def batch_request(self, urls: list[str], concurrency: int = 5,
                      method: str = "GET") -> list[WAFResponse | WAFBlockError]:
        """Batch requests with a shared session + rate limiting (waf-spec §4.2)."""
        out: list[WAFResponse | WAFBlockError] = [None] * len(urls)  # type: ignore

        def _one(i: int, u: str):
            try:
                out[i] = self.request(u, method=method)
            except WAFBlockError as e:
                out[i] = e

        with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
            for i, u in enumerate(urls):
                pool.submit(_one, i, u)
        return out

    def refresh_session(self, domain: str, scheme: str = "https") -> bool:
        """Proactively solve a challenge and cache the cookie before expiry
        (waf-spec §4.2 / §3.6 cookie-refresh pipeline)."""
        cfg = self.config.for_target(domain)
        proxy = self.proxies.get(domain, sticky=True)
        proxy_id = _proxy_id(proxy)
        res = self._solve(f"{scheme}://{domain}/", domain, proxy_id,
                          detect_challenge(403, {}, ""), cfg, force=True)
        return bool(res and res.ok)

    def get_cookie(self, domain: str) -> str | None:
        """Stored cf_clearance header for ``domain`` (any matching identity)."""
        cfg = self.config.for_target(domain)
        ua = self._domain_ua.get(domain, cfg.user_agent)
        for proxy_sticky in (True, False):
            proxy = self.proxies.get(domain, sticky=proxy_sticky)
            rec = self.cookies.get(domain, _proxy_id(proxy), ua)
            if rec:
                return rec.cookie_header()
        return None

    def cleanup(self) -> int:
        return self.cookies.cleanup_expired()

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #
    def _has_cookie(self, domain: str, cfg: WAFIntegrationConfig) -> bool:
        # Sticky-proxy decision: do we already hold a cookie for any path? Cheap
        # check against the direct-path key (the common case).
        ua = self._domain_ua.get(domain, cfg.user_agent)
        return self.cookies.get(domain, "", ua) is not None

    def _store_new_cookie(self, domain: str, proxy_id: str, ua: str,
                          set_cookies: dict[str, str], verdict: ChallengeInfo) -> None:
        clearance = extract_cf_clearance(set_cookies)
        if clearance:
            self.cookies.set(CookieRecord(
                domain=domain, cookie_value=clearance, ip_address=proxy_id, user_agent=ua,
                challenge_type=verdict.kind or "js_challenge"))

    def _solve(self, url: str, domain: str, proxy_id: str, verdict: ChallengeInfo,
               cfg: WAFIntegrationConfig, force: bool = False):
        """Run L3 (and L4 if needed). On a cf_clearance, store it. Returns the
        SolveResult (or None when no solver is configured)."""
        if self.solver is None:
            return None
        if not force and verdict.needs_captcha_service and self.captcha.configured:
            # L4 token retrieval first; the browser solver then completes the flow.
            self.captcha.solve_turnstile(verdict.sitekey or "", url)
        res = self.solver.solve(url, domain, ip=proxy_id, timeout=cfg.challenge_timeout_s)
        if res.ok and res.cookie:
            # Bind the cookie to the UA the solver actually used (cookie<->UA<->IP),
            # and adopt that UA for this domain so L1 replay matches the binding.
            res.cookie.ip_address = proxy_id
            self.cookies.set(res.cookie)
            if res.cookie.user_agent:
                self._domain_ua[domain] = res.cookie.user_agent
        return res


# --------------------------------------------------------------------------- #
def _build_proxy_pool(config: WAFIntegrationConfig) -> ProxyPool:
    import os

    pp = config.proxy_pool
    raw = list(pp.endpoints)
    env_val = os.environ.get(pp.endpoints_env, "")
    if env_val:
        raw += [u.strip() for u in env_val.split(",") if u.strip()]
    endpoints = [ProxyEndpoint(url=u, provider="env", proxy_type=pp.type, geo=pp.geo_target)
                 for u in raw]
    providers = [ProxyProvider(name="default", endpoints=endpoints)] if endpoints else []
    return ProxyPool(providers=providers, sticky_ttl=pp.sticky_session_ttl,
                     max_failures_before_rotate=pp.max_failures_before_rotate,
                     geo_target=pp.geo_target)


def build_waf_integration(config_path: str | None = None,
                          api_router: APIRouter | None = None) -> WAFIntegration:
    """Construct a WAFIntegration from a config file path (or all-defaults), with
    env overrides so an operator can configure it purely via .env (the project's
    convention): SYBER_WAF_CONFIG, SYBER_WAF_PROXIES (read by the proxy pool),
    SYBER_WAF_CAPTCHA_PROVIDER / SYBER_WAF_CAPTCHA_KEY."""
    import os

    from .config import load_waf_config

    cfg = load_waf_config(config_path)
    provider = os.environ.get("SYBER_WAF_CAPTCHA_PROVIDER")
    key = os.environ.get("SYBER_WAF_CAPTCHA_KEY")
    if provider:
        cfg.captcha_service.provider = provider
    if key:
        cfg.captcha_service.api_key = key
    return WAFIntegration(cfg, api_router=api_router)
