"""
WAF traversal module — deterministic tests (no network, no LLM spend).

Covers the pure pieces (waf-spec §2–§5): challenge detection signatures, the
cf_clearance cookie store's domain/IP/UA keying + TTL, the rate-limiter token
bucket + jitter + 429 cool-down, proxy sticky sessions, config target-merge, and
the layered request-flow escalation with a fully faked transport + solver (so the
L1->L2->L3 logic is exercised offline).

Run: python -m pytest tests/waf/test_waf.py   (from syber-platform/)
"""
from __future__ import annotations

import random

import pytest

from syber.waf import detect_challenge
from syber.waf.config import WAFIntegrationConfig, load_waf_config
from syber.waf.cookie_store import (CookieRecord, InMemoryCookieStore,
                                    SQLiteCookieStore, make_cookie_store)
from syber.waf.detect import (extract_cf_clearance, extract_turnstile_sitekey,
                              is_cloudflare, parse_retry_after)
from syber.waf.integration import WAFBlockError, WAFIntegration, WAFResponse
from syber.waf.proxy_pool import ProxyEndpoint, ProxyPool, ProxyProvider
from syber.waf.rate_limiter import JitterEngine, RateLimiter, backoff_delay
from syber.waf.solver import SolveResult, parse_ab_cookies
from syber.waf.tls_client import FetchResult


# --------------------------------------------------------------------------- #
# §2 — challenge detection
# --------------------------------------------------------------------------- #
def test_js_challenge_detected_and_solvable():
    v = detect_challenge(403, {"server": "cloudflare", "cf-ray": "8aabbccddeeff011-LHR"},
                         "Just a moment... /cdn-cgi/challenge-platform/ cf_chl_opt")
    assert v.detected and v.kind == "js_challenge"
    assert v.solvable_headless and not v.needs_captcha_service
    assert v.ray_id == "8aabbccddeeff011"


def test_turnstile_widget_yields_sitekey():
    body = '<div class="cf-turnstile" data-sitekey="0x4AAAAAAABkMYinukE8nzY"></div>'
    v = detect_challenge(403, {"server": "cloudflare"}, body)
    assert v.kind == "turnstile_managed"
    assert v.sitekey == "0x4AAAAAAABkMYinukE8nzY"


def test_clean_response_not_flagged():
    v = detect_challenge(200, {"server": "cloudflare"}, "<html>real content</html>")
    assert not v.detected and v.kind == ""


def test_rate_limit_and_retry_after():
    v = detect_challenge(429, {"retry-after": "12"}, "")
    assert v.kind == "rate_limited" and v.retry_after == 12.0
    assert parse_retry_after({"Retry-After": "5"}) == 5.0
    assert parse_retry_after({}) is None


def test_hard_block_is_not_solvable():
    v = detect_challenge(403, {"server": "cloudflare"},
                         "Sorry, you have been blocked error code: 1020")
    assert v.kind == "blocked" and v.is_block and not v.solvable_headless


def test_managed_challenge_fallback_on_cf_403_no_marker():
    v = detect_challenge(403, {"server": "cloudflare", "cf-ray": "abc-LHR"}, "denied")
    assert v.kind == "managed_challenge" and v.solvable_headless


def test_non_cloudflare_403_passes_through():
    v = detect_challenge(403, {"server": "nginx"}, "Forbidden")
    assert not v.detected


def test_is_cloudflare_and_cf_clearance_extraction():
    assert is_cloudflare({"cf-ray": "x"}, "")
    assert not is_cloudflare({"server": "nginx"}, "plain")
    cookies = ["other=1; Path=/", "cf_clearance=abc123xyz; Path=/; HttpOnly"]
    assert extract_cf_clearance(cookies) == "abc123xyz"
    assert extract_cf_clearance({"cf_clearance": "zzz"}) == "zzz"
    assert extract_cf_clearance([]) is None


def test_sitekey_both_html_and_js_forms():
    assert extract_turnstile_sitekey('data-sitekey="0xABCDEF123456"') == "0xABCDEF123456"
    assert extract_turnstile_sitekey('render({sitekey: "0x999888777666"})') == "0x999888777666"


# --------------------------------------------------------------------------- #
# §4.4 — cookie store: domain/IP/UA keying + TTL
# --------------------------------------------------------------------------- #
def test_cookie_store_keying():
    store = InMemoryCookieStore(default_ttl=1800)
    rec = CookieRecord(domain="ex.com", cookie_value="CLR", ip_address="1.2.3.4",
                       user_agent="UA-A")
    store.set(rec)
    # Exact triple matches; any mismatch on ip or ua does NOT (waf-spec §4.4).
    assert store.get("ex.com", "1.2.3.4", "UA-A").cookie_value == "CLR"
    assert store.get("ex.com", "9.9.9.9", "UA-A") is None
    assert store.get("ex.com", "1.2.3.4", "UA-B") is None
    assert store.cookie_header("ex.com", "1.2.3.4", "UA-A") == "cf_clearance=CLR"


def test_cookie_store_expiry():
    store = InMemoryCookieStore(default_ttl=1800)
    rec = CookieRecord(domain="ex.com", cookie_value="CLR", expires_at=1000.0,
                       created_at=500.0)
    store.set(rec)
    assert rec.is_expired(now=1001.0)
    # get() must drop an expired record even before cleanup runs.
    assert store.get("ex.com") is None


def test_cookie_store_cleanup_and_lru():
    store = InMemoryCookieStore(max_size=2, default_ttl=1800)
    store.set(CookieRecord(domain="a.com", cookie_value="1"))
    store.set(CookieRecord(domain="b.com", cookie_value="2"))
    store.set(CookieRecord(domain="c.com", cookie_value="3"))  # evicts LRU (a.com)
    assert store.get("a.com") is None
    assert store.get("c.com") is not None


def test_sqlite_cookie_store_roundtrip(tmp_path):
    path = str(tmp_path / "cookies.sqlite")
    store = SQLiteCookieStore(path=path, default_ttl=1800)
    store.set(CookieRecord(domain="ex.com", cookie_value="CLR", ip_address="ip",
                           user_agent="ua"))
    # A fresh handle on the same file still sees it (persistence).
    again = SQLiteCookieStore(path=path, default_ttl=1800)
    assert again.get("ex.com", "ip", "ua").cookie_value == "CLR"
    again.delete("ex.com", "ip", "ua")
    assert again.get("ex.com", "ip", "ua") is None


def test_make_cookie_store_falls_back_to_memory():
    # An unreachable redis backend degrades to in-memory, never raises.
    store = make_cookie_store("redis", redis_url="redis://127.0.0.1:1/0")
    assert isinstance(store, InMemoryCookieStore)


# --------------------------------------------------------------------------- #
# §4.6 — rate limiter + jitter (deterministic via injected sleep/clock/rng)
# --------------------------------------------------------------------------- #
def test_backoff_is_exponential_and_capped():
    assert backoff_delay(1) == 0.5
    assert backoff_delay(2) == 1.0
    assert backoff_delay(3) == 2.0
    assert backoff_delay(50) == 60.0  # capped


def test_jitter_within_range():
    j = JitterEngine(500, 3000, "uniform", rng=random.Random(7))
    for _ in range(50):
        d = j.next_delay()
        assert 0.5 <= d <= 3.0


def test_rate_limiter_token_bucket_paces_requests():
    waits: list[float] = []
    t = {"now": 0.0}
    rl = RateLimiter(rps=2.0, jitter=JitterEngine(0, 0, rng=random.Random(1)),
                     sleep=lambda s: waits.append(s),
                     clock=lambda: t["now"])
    rl.acquire("ex.com")          # bucket starts full -> immediate
    rl.acquire("ex.com")          # second token still available
    rl.acquire("ex.com")          # third must wait ~1/rps = 0.5s
    assert waits[-1] == pytest.approx(0.5, abs=1e-6)


def test_rate_limiter_429_cooldown_ratchets():
    rl = RateLimiter(rps=2.0, sleep=lambda s: None, clock=lambda: 0.0)
    w1 = rl.note_rate_limited("ex.com")              # streak 1 -> backoff_delay(1)=0.5
    w2 = rl.note_rate_limited("ex.com", retry_after=7.0)  # honour Retry-After
    assert w1 == 0.5 and w2 == 7.0
    rl.note_success("ex.com")                        # relaxes the cooldown


# --------------------------------------------------------------------------- #
# §4.5 — proxy pool sticky sessions
# --------------------------------------------------------------------------- #
def test_proxy_pool_sticky_and_rotation():
    eps = [ProxyEndpoint(url=f"http://h{i}:8080") for i in range(3)]
    pool = ProxyPool([ProxyProvider("p", eps)], rng=random.Random(3),
                     clock=lambda: 0.0)
    assert pool.configured
    sticky1 = pool.get("ex.com", sticky=True)
    sticky2 = pool.get("ex.com", sticky=True)
    assert sticky1 is sticky2                        # same IP held for the domain
    # A failure past threshold drops the sticky assignment.
    for _ in range(3):
        pool.report_failure(sticky1, "ex.com")
    assert not sticky1.healthy
    assert pool.get("ex.com", sticky=True) is not sticky1


def test_proxy_pool_empty_is_direct():
    pool = ProxyPool([])
    assert not pool.configured
    assert pool.get("ex.com", sticky=True) is None   # direct connection


def test_proxy_geo_targeting():
    eps = [ProxyEndpoint(url="http://us:1", geo="US"),
           ProxyEndpoint(url="http://de:1", geo="DE")]
    pool = ProxyPool([ProxyProvider("p", eps)], geo_target="US", rng=random.Random(1))
    for _ in range(10):
        assert pool.get("ex.com").geo == "US"


# --------------------------------------------------------------------------- #
# §5 — config load + per-target override merge
# --------------------------------------------------------------------------- #
def test_config_defaults_when_no_file():
    cfg = load_waf_config(None)
    assert isinstance(cfg, WAFIntegrationConfig)
    assert cfg.tls_impersonation == "chrome120"


def test_config_target_merge_from_mapping():
    from syber.waf.config import _from_mapping
    cfg = _from_mapping({"waf_integration": {
        "default": {"rate_limit_rps": 2.0, "cookie_store": {"backend": "sqlite"}},
        "targets": {"slow.com": {"rate_limit_rps": 0.25,
                                 "proxy_pool": {"geo_target": "GB"}}}}})
    assert cfg.cookie_store.backend == "sqlite"
    eff = cfg.for_target("slow.com")
    assert eff.rate_limit_rps == 0.25
    assert eff.proxy_pool.geo_target == "GB"
    # Untargeted domain keeps the default rate.
    assert cfg.for_target("fast.com").rate_limit_rps == 2.0


# --------------------------------------------------------------------------- #
# parsing helpers used by the L3 solver
# --------------------------------------------------------------------------- #
def test_parse_agent_browser_cookies():
    raw = '[{"name":"cf_clearance","value":"TOKEN","domain":".ex.com"},' \
          '{"name":"other","value":"x"}]'
    out = parse_ab_cookies(raw)
    assert out["cf_clearance"] == "TOKEN" and out["other"] == "x"
    assert parse_ab_cookies("") == {}
    assert parse_ab_cookies("not json") == {}


# --------------------------------------------------------------------------- #
# §4.3 — the layered request flow, with a faked transport + solver
# --------------------------------------------------------------------------- #
class _FakeClient:
    """Scripts a sequence of FetchResults so the flow is exercised offline."""

    def __init__(self, results):
        self._results = list(results)
        self.calls = []

    def fetch(self, url, method="GET", headers=None, body=None, cookies=None,
              proxy=None, timeout=None):
        self.calls.append({"cookies": cookies})
        return self._results.pop(0) if self._results else self._results_default()

    def _results_default(self):
        return FetchResult(status=200, headers={}, body="ok")


class _FakeSolver:
    name = "fake"

    def __init__(self, cookie_value="SOLVED"):
        self.cookie_value = cookie_value
        self.solved = 0

    def available(self):
        return True

    def solve(self, url, domain, ip="", timeout=60):
        self.solved += 1
        return SolveResult(ok=True, engine="fake", user_agent="UA",
                           cookie=CookieRecord(domain=domain, cookie_value=self.cookie_value,
                                               ip_address=ip, user_agent="UA"))


def _waf(client, solver=None):
    cfg = WAFIntegrationConfig()
    cfg.user_agent = "UA"
    rl = RateLimiter(rps=1000.0, jitter=JitterEngine(0, 0, rng=random.Random(0)),
                     sleep=lambda s: None, clock=lambda: 0.0)
    w = WAFIntegration(cfg, solver=solver or _FakeSolver(), rate_limiter=rl)
    w._client = client
    return w


def test_flow_clean_pass_through():
    client = _FakeClient([FetchResult(status=200, headers={}, body="<html>hi</html>")])
    resp = _waf(client).request("https://ex.com/")
    assert resp.ok and resp.layer == "L1" and not resp.cookie_used


def test_flow_solves_challenge_then_reuses_cookie():
    # 1st fetch: JS challenge. After solve, 2nd fetch: clean (and must carry cookie).
    client = _FakeClient([
        FetchResult(status=403, headers={"server": "cloudflare", "cf-ray": "r-LHR"},
                    body="Just a moment... /cdn-cgi/challenge-platform/ cf_chl_opt"),
        FetchResult(status=200, headers={}, body="<html>authed</html>"),
    ])
    solver = _FakeSolver(cookie_value="SOLVED")
    waf = _waf(client, solver)
    resp = waf.request("https://ex.com/")
    assert resp.ok and solver.solved == 1
    assert resp.cookie_used is True                 # L2 reuse on the retry
    # The retry fetch carried the solved cf_clearance cookie.
    assert client.calls[-1]["cookies"] == "cf_clearance=SOLVED"


def test_flow_hard_block_raises():
    client = _FakeClient([FetchResult(
        status=403, headers={"server": "cloudflare"},
        body="Sorry, you have been blocked error code: 1020")])
    with pytest.raises(WAFBlockError) as ei:
        _waf(client).request("https://ex.com/")
    assert ei.value.challenge_type == "blocked"


def test_flow_l0_api_router_short_circuits():
    client = _FakeClient([])  # must never be called
    waf = _waf(client)
    waf.api_router = lambda domain, url: {"status": 200, "body": "from-api", "headers": {}}
    resp = waf.request("https://ex.com/data")
    assert resp.layer == "L0" and resp.body == "from-api"
    assert client.calls == []


def test_flow_get_cookie_after_solve():
    client = _FakeClient([
        FetchResult(status=403, headers={"server": "cloudflare", "cf-ray": "r-LHR"},
                    body="/cdn-cgi/challenge-platform/ cf_chl_opt"),
        FetchResult(status=200, headers={}, body="ok"),
    ])
    waf = _waf(client)
    waf.request("https://ex.com/")
    assert waf.get_cookie("ex.com") == "cf_clearance=SOLVED"
