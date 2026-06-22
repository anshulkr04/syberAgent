"""
Proxy pool with sticky sessions (waf-spec §4.5, §3.5).

IP reputation is a major Cloudflare signal: datacenter ranges score worse than
residential/mobile (waf-spec §2.5). For agents making many requests the pool:

  1. **Random-rotates** IPs for initial requests,
  2. keeps a **sticky** IP per domain while a ``cf_clearance`` cookie is valid
     (the cookie is bound to the IP that solved the challenge — waf-spec §4.4),
  3. **health-checks** out non-responsive proxies,
  4. supports **geo targeting**, and
  5. **falls back** across providers (ordered by priority) when one is exhausted.

The pool degrades to *direct connection* (proxy=None) when no providers are
configured — so the WAF module runs with zero proxy setup, consistent with the
platform's "works with nothing external" default.
"""
from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

__all__ = ["ProxyEndpoint", "ProxyProvider", "ProxyPool"]


@dataclass
class ProxyEndpoint:
    """A single usable proxy URL plus its health bookkeeping."""

    url: str                         # e.g. http://user:pass@host:port
    provider: str = ""
    proxy_type: str = "residential"  # residential | datacenter | mobile
    geo: str | None = None           # ISO country code
    failures: int = 0
    healthy: bool = True

    def as_requests_proxies(self) -> dict[str, str]:
        return {"http": self.url, "https": self.url}


@dataclass
class ProxyProvider:
    """An ordered provider with a static list of endpoints (waf-spec §4.5)."""

    name: str
    endpoints: list[ProxyEndpoint] = field(default_factory=list)
    priority: int = 0                # lower == tried first


class ProxyPool:
    """Rotation + sticky-session manager over one or more providers."""

    def __init__(self, providers: list[ProxyProvider] | None = None,
                 sticky_ttl: float = 1800.0,
                 max_failures_before_rotate: int = 3,
                 geo_target: str | None = None,
                 rng: random.Random | None = None,
                 clock: Callable[[], float] | None = None):
        self.providers = sorted(providers or [], key=lambda p: p.priority)
        self.sticky_ttl = sticky_ttl
        self.max_failures = max_failures_before_rotate
        self.geo_target = geo_target
        self._rng = rng or random.Random()
        self._clock = clock or time.monotonic
        self._sticky: dict[str, tuple[ProxyEndpoint, float]] = {}  # domain -> (ep, assigned_at)
        self._lock = threading.RLock()

    @property
    def configured(self) -> bool:
        return any(p.endpoints for p in self.providers)

    def _candidates(self) -> list[ProxyEndpoint]:
        out: list[ProxyEndpoint] = []
        for prov in self.providers:                      # already priority-ordered
            for ep in prov.endpoints:
                if not ep.healthy:
                    continue
                if self.geo_target and ep.geo and ep.geo.upper() != self.geo_target.upper():
                    continue
                out.append(ep)
        return out

    def get(self, domain: str, sticky: bool = False) -> ProxyEndpoint | None:
        """Return a proxy for ``domain``. When ``sticky`` (a cf_clearance cookie
        exists for it), reuse the same IP until the sticky TTL expires; otherwise
        random-rotate. Returns None when no proxies are configured (direct)."""
        domain = (domain or "").lower()
        if not self.configured:
            return None
        with self._lock:
            if sticky:
                held = self._sticky.get(domain)
                if held:
                    ep, assigned = held
                    if ep.healthy and (self._clock() - assigned) < self.sticky_ttl:
                        return ep
                    self._sticky.pop(domain, None)      # expired/unhealthy -> reassign
            pool = self._candidates()
            if not pool:
                return None
            ep = self._rng.choice(pool)
            if sticky:
                self._sticky[domain] = (ep, self._clock())
            return ep

    def report_failure(self, endpoint: ProxyEndpoint | None, domain: str = "") -> None:
        """Record a failure; mark the proxy unhealthy past the threshold and drop
        any sticky assignment so the next call rotates to a fresh IP (waf-spec §4.5)."""
        if endpoint is None:
            return
        with self._lock:
            endpoint.failures += 1
            if endpoint.failures >= self.max_failures:
                endpoint.healthy = False
            if domain:
                held = self._sticky.get(domain.lower())
                if held and held[0] is endpoint:
                    self._sticky.pop(domain.lower(), None)

    def report_success(self, endpoint: ProxyEndpoint | None) -> None:
        if endpoint is not None:
            endpoint.failures = 0
            endpoint.healthy = True

    def health_check(self, probe: Callable[[ProxyEndpoint], bool]) -> int:
        """Run ``probe`` against each endpoint; flip health accordingly. Returns the
        count now healthy. ``probe`` is injected so this is testable offline."""
        healthy = 0
        with self._lock:
            for prov in self.providers:
                for ep in prov.endpoints:
                    ok = False
                    try:
                        ok = bool(probe(ep))
                    except Exception:  # noqa: BLE001 - a probe error == unhealthy
                        ok = False
                    ep.healthy = ok
                    if ok:
                        ep.failures = 0
                        healthy += 1
        return healthy
