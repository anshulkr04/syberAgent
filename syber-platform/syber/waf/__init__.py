"""
syber.waf — Cloudflare WAF traversal & hardening module (waf-spec v1.0.0).

A layered, graceful-degrading client the agent harness uses to reach
Cloudflare-protected targets without being blocked, and to recognise/handle the
challenges it meets (waf-spec §4):

    L0 API-first  ->  L1 TLS impersonation  ->  L2 session reuse
                  ->  L3 challenge solver  ->  L4 CAPTCHA service

Quick use:

    from syber.waf import build_waf_integration
    waf = build_waf_integration()                 # all-defaults, zero external deps
    resp = waf.request("https://example.com/")     # WAFResponse (raises WAFBlockError if blocked)

Every layer is optional and falls back: no curl_cffi -> urllib (L1); no proxies ->
direct; no solver/CAPTCHA -> reports a block with the sitekey so the agent can
finish in its own browser. Same "never hard-crash on a missing backend" contract
as the rest of the platform.
"""
from __future__ import annotations

from .config import (CaptchaServiceConfig, CookieStoreConfig, ProxyPoolConfig,
                     SolverConfig, WAFIntegrationConfig, load_waf_config)
from .cookie_store import CookieRecord, CookieStore, make_cookie_store
from .detect import ChallengeInfo, detect_challenge, is_cloudflare
from .fallback import (FallbackResult, OriginCandidate, explore_alternate_vectors,
                       find_origin_candidates, is_cloudflare_ip, probe_origin)
from .integration import (WAFBlockError, WAFIntegration, WAFResponse,
                          build_waf_integration)

__all__ = [
    "WAFIntegration", "WAFResponse", "WAFBlockError", "build_waf_integration",
    "WAFIntegrationConfig", "CookieStoreConfig", "ProxyPoolConfig", "SolverConfig",
    "CaptchaServiceConfig", "load_waf_config",
    "ChallengeInfo", "detect_challenge", "is_cloudflare",
    "CookieRecord", "CookieStore", "make_cookie_store",
    "FallbackResult", "OriginCandidate", "explore_alternate_vectors",
    "find_origin_candidates", "probe_origin", "is_cloudflare_ip",
]
