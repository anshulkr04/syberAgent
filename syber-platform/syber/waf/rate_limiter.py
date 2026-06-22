"""
Rate limiter + jitter engine (waf-spec §4.6).

Cloudflare scores request *timing and pattern*: precise intervals, predictable
crawl order, and bursts all read as automation (waf-spec §2.6). This module makes
the harness pace itself like a human:

  * RateLimiter — a token-bucket cap on requests/second, enforced per-domain and
    globally, plus respect for ``Retry-After`` on 429s, exponential backoff
    (capped at 60s), and a cool-down that *progressively slows* the rate after
    consecutive rate-limit responses (waf-spec §4.6).
  * JitterEngine — a randomised inter-request delay (uniform / Gaussian) so timing
    is irregular (waf-spec §4.6 default uniform 500–3000ms).

Both take injectable ``sleep`` and ``rng`` callables so the escalation/backoff
maths is unit-tested deterministically without real waits.
"""
from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

__all__ = ["JitterEngine", "RateLimiter", "backoff_delay"]

SleepFn = Callable[[float], None]


def backoff_delay(attempt: int, base: float = 0.5, cap: float = 60.0) -> float:
    """Exponential backoff for retry ``attempt`` (1-based), capped (waf-spec §4.6)."""
    if attempt < 1:
        attempt = 1
    return min(cap, base * (2 ** (attempt - 1)))


class JitterEngine:
    """Random inter-request delay (waf-spec §4.6). Distribution: uniform | gaussian."""

    def __init__(self, low_ms: float = 500.0, high_ms: float = 3000.0,
                 distribution: str = "uniform",
                 rng: random.Random | None = None):
        if high_ms < low_ms:
            low_ms, high_ms = high_ms, low_ms
        self.low = low_ms / 1000.0
        self.high = high_ms / 1000.0
        self.distribution = distribution
        self._rng = rng or random.Random()

    def next_delay(self) -> float:
        """Seconds to wait before the next request."""
        if self.distribution == "gaussian":
            mid = (self.low + self.high) / 2.0
            sigma = (self.high - self.low) / 6.0  # ~99.7% inside [low, high]
            return min(self.high, max(self.low, self._rng.gauss(mid, sigma)))
        return self._rng.uniform(self.low, self.high)


@dataclass
class _DomainState:
    tokens: float = 0.0
    last_refill: float = 0.0
    initialized: bool = False
    consecutive_429: int = 0
    cooldown_factor: float = 1.0       # >1 slows the effective rate after 429s


class RateLimiter:
    """Token-bucket RPS limiter, per-domain + global, with jitter and 429 cool-down.

    The bucket refills at ``rps`` tokens/second (divided by the current cooldown
    factor for a domain). ``acquire(domain)`` blocks until a token is available,
    then adds a jitter delay. ``note_rate_limited`` ratchets that domain's cooldown
    so a site that keeps 429-ing is hit progressively more gently (waf-spec §4.6).
    """

    def __init__(self, rps: float = 2.0, jitter: JitterEngine | None = None,
                 global_rps: float | None = None,
                 sleep: SleepFn | None = None,
                 clock: Callable[[], float] | None = None,
                 max_cooldown_factor: float = 8.0):
        self.rps = max(0.01, rps)
        self.global_rps = global_rps
        self.jitter = jitter or JitterEngine()
        self._sleep = sleep or time.sleep
        self._clock = clock or time.monotonic
        self.max_cooldown_factor = max_cooldown_factor
        self._domains: dict[str, _DomainState] = {}
        self._global = _DomainState()
        self._lock = threading.RLock()

    # ---- token bucket --------------------------------------------------- #
    def _wait_for_token(self, state: _DomainState, rps: float) -> float:
        """Compute the wait (seconds) until a token frees up for ``state`` and
        consume it. Returns the wait without sleeping (caller sleeps once)."""
        now = self._clock()
        if not state.initialized:
            state.initialized = True
            state.last_refill = now
            state.tokens = rps  # start full so the first request is immediate
        elapsed = now - state.last_refill
        state.tokens = min(rps, state.tokens + elapsed * rps)
        state.last_refill = now
        if state.tokens >= 1.0:
            state.tokens -= 1.0
            return 0.0
        wait = (1.0 - state.tokens) / rps
        state.tokens = 0.0
        state.last_refill = now + wait
        return wait

    def acquire(self, domain: str) -> float:
        """Block until a request to ``domain`` is permitted; return the total wait."""
        domain = (domain or "").lower()
        with self._lock:
            st = self._domains.setdefault(domain, _DomainState())
            eff_rps = self.rps / max(1.0, st.cooldown_factor)
            wait = self._wait_for_token(st, eff_rps)
            if self.global_rps:
                wait = max(wait, self._wait_for_token(self._global, self.global_rps))
        jitter = self.jitter.next_delay()
        total = wait + jitter
        if total > 0:
            self._sleep(total)
        return total

    # ---- 429 handling --------------------------------------------------- #
    def note_rate_limited(self, domain: str, retry_after: float | None = None) -> float:
        """Record a 429 for ``domain`` and return how long to wait before retrying.

        Ratchets the cooldown factor (slower effective RPS) and returns
        ``retry_after`` when provided, else exponential backoff on the streak."""
        domain = (domain or "").lower()
        with self._lock:
            st = self._domains.setdefault(domain, _DomainState())
            st.consecutive_429 += 1
            st.cooldown_factor = min(self.max_cooldown_factor, st.cooldown_factor * 2.0)
            streak = st.consecutive_429
        return retry_after if retry_after is not None else backoff_delay(streak)

    def note_success(self, domain: str) -> None:
        """A clean response relaxes the cool-down (gradually restores the rate)."""
        domain = (domain or "").lower()
        with self._lock:
            st = self._domains.setdefault(domain, _DomainState())
            st.consecutive_429 = 0
            st.cooldown_factor = max(1.0, st.cooldown_factor / 2.0)

    def backoff_and_wait(self, domain: str, attempt: int) -> float:
        """Sleep for the exponential backoff of ``attempt`` and return the delay."""
        delay = backoff_delay(attempt)
        if delay > 0:
            self._sleep(delay)
        return delay
