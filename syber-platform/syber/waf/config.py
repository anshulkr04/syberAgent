"""
WAF integration configuration (waf-spec §5).

A single schema with sensible defaults, loadable from YAML/JSON, with a
``default`` block plus a ``targets`` map for per-domain overrides (e.g. a slower
rate and US geo for one site). ``WAFIntegrationConfig.for_target(domain)`` returns
the effective config for a domain by deep-merging its override onto the default.

No hard dependency on PyYAML: ``pyyaml`` is in requirements (used by the Kafka
topic loader) but if a JSON file is given we parse it with the stdlib, and if a
YAML file is given without PyYAML present we raise a clear, actionable error.
"""
from __future__ import annotations

import copy
import json
import os
from dataclasses import dataclass, field, replace
from typing import Any

__all__ = ["CookieStoreConfig", "ProxyPoolConfig", "SolverConfig",
           "CaptchaServiceConfig", "WAFIntegrationConfig", "load_waf_config"]


@dataclass
class CookieStoreConfig:
    backend: str = "memory"          # memory | sqlite | redis (waf-spec §4.4)
    redis_url: str = "redis://localhost:6379/0"
    sqlite_path: str = ".waf_cookies.sqlite"
    cleanup_interval_s: int = 300
    default_ttl_s: float = 1800.0    # cf_clearance TTL assumption when unknown


@dataclass
class ProxyPoolConfig:
    type: str = "residential"        # residential | datacenter | mobile (waf-spec §4.5)
    sticky_session_ttl: int = 1800   # match cf_clearance TTL
    health_check_interval: int = 300
    geo_target: str | None = None
    max_failures_before_rotate: int = 3
    # Endpoints come from the environment (secrets), not the YAML, by default:
    # SYBER_WAF_PROXIES = "http://u:p@h1:p1,http://u:p@h2:p2"
    endpoints_env: str = "SYBER_WAF_PROXIES"
    endpoints: list[str] = field(default_factory=list)


@dataclass
class SolverConfig:
    engine: str = "agent-browser"    # agent-browser | flaresolverr | pydoll | none
    headless: bool = True
    flaresolverr_url: str = "http://localhost:8191"
    max_timeout_s: int = 60


@dataclass
class CaptchaServiceConfig:
    provider: str | None = None      # 2captcha | capsolver | None (waf-spec §4.4)
    api_key: str | None = None
    poll_interval_s: float = 5.0
    max_wait_s: float = 120.0


@dataclass
class WAFIntegrationConfig:
    """The unified config the WAFIntegration module consumes (waf-spec §4.2)."""

    tls_impersonation: str = "chrome120"
    rate_limit_rps: float = 2.0
    jitter_range_ms: tuple[float, float] = (500.0, 3000.0)
    jitter_distribution: str = "uniform"
    max_retries: int = 3
    challenge_timeout_s: int = 60
    user_agent: str = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/120.0.0.0 Safari/537.36")
    cookie_store: CookieStoreConfig = field(default_factory=CookieStoreConfig)
    proxy_pool: ProxyPoolConfig = field(default_factory=ProxyPoolConfig)
    challenge_solver: SolverConfig = field(default_factory=SolverConfig)
    captcha_service: CaptchaServiceConfig = field(default_factory=CaptchaServiceConfig)
    # Per-target overrides keyed by domain (populated by load_waf_config).
    targets: dict[str, dict[str, Any]] = field(default_factory=dict)

    # ----------------------------------------------------------------- #
    def for_target(self, domain: str) -> "WAFIntegrationConfig":
        """Effective config for ``domain`` = default deep-merged with its override."""
        override = self.targets.get((domain or "").lower())
        if not override:
            return self
        merged = copy.deepcopy(self)
        merged.targets = {}
        _apply_overrides(merged, override)
        return merged


# --------------------------------------------------------------------------- #
# Loading + merging
# --------------------------------------------------------------------------- #
_SUBCONFIGS = {
    "cookie_store": CookieStoreConfig,
    "proxy_pool": ProxyPoolConfig,
    "challenge_solver": SolverConfig,
    "captcha_service": CaptchaServiceConfig,
}


def _apply_overrides(cfg: WAFIntegrationConfig, data: dict[str, Any]) -> None:
    """Mutate ``cfg`` in place with the (possibly partial) mapping ``data``."""
    for key, value in (data or {}).items():
        if key == "targets":
            cfg.targets = {str(k).lower(): v for k, v in (value or {}).items()}
            continue
        if key in _SUBCONFIGS and isinstance(value, dict):
            sub = getattr(cfg, key)
            for sk, sv in value.items():
                if hasattr(sub, sk):
                    setattr(sub, sk, sv)
            continue
        if key == "jitter_range_ms" and isinstance(value, (list, tuple)) and len(value) == 2:
            cfg.jitter_range_ms = (float(value[0]), float(value[1]))
            continue
        if hasattr(cfg, key):
            setattr(cfg, key, value)


def _from_mapping(data: dict[str, Any]) -> WAFIntegrationConfig:
    # Accept either the bare default block or the spec's nested
    # {"waf_integration": {"default": {...}, "targets": {...}}} shape.
    root = data.get("waf_integration", data)
    default_block = root.get("default", root) if isinstance(root, dict) else {}
    cfg = WAFIntegrationConfig()
    _apply_overrides(cfg, default_block)
    if isinstance(root, dict) and "targets" in root:
        cfg.targets = {str(k).lower(): v for k, v in (root["targets"] or {}).items()}
    return cfg


def load_waf_config(path: str | None = None) -> WAFIntegrationConfig:
    """Load config from a YAML/JSON file (waf-spec §5). With no path (or a missing
    file) returns the all-defaults config so the module always has something to run.
    """
    path = path or os.environ.get("SYBER_WAF_CONFIG")
    if not path or not os.path.isfile(path):
        return WAFIntegrationConfig()
    text = open(path, encoding="utf-8").read()
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml
        except ImportError as e:  # pragma: no cover - pyyaml ships in requirements
            raise RuntimeError("PyYAML required to load a YAML WAF config; "
                               "use JSON or `pip install pyyaml`") from e
        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text)
    return _from_mapping(data)
