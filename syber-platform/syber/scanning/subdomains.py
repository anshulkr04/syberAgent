"""
Deterministic subdomain enumeration — "map the whole surface FIRST".

The consistency failure this fixes: the winning engagements found the catastrophic
exposure only because the agent *happened* to read a JS file that named the non-prod
subdomains (vamauat / nwmwuat / …). On an unlucky run it never found them and declared
the target "secure". Subdomain discovery must not depend on the model's mood — so this
module enumerates the surface deterministically at engagement start, every time.

Sources (best-effort, dependency-light — stdlib + urllib):
  * **Certificate Transparency** (crt.sh) — every host that ever served an HTTPS cert,
    including staging/UAT/CUG, which is exactly where the soft targets live.
  * **Prefix wordlist** — generic + non-prod-heavy names brute-resolved against the apex.
  * **DNS** resolution confirms which candidates exist; an optional lightweight HTTP
    probe records liveness/status.

Every discovered live host is ingested as a graph Host node, so the fleet's existing
service_scan / web_crawl / vuln_scan rules pick it up automatically. Non-prod hosts are
flagged (they are prioritised — that is where exposure usually is).

Pure helpers (``parse_crtsh``, ``candidate_hosts``, ``classify_env``, ``registrable_apex``)
are unit-tested without network.
"""
from __future__ import annotations

import json
import re
import socket
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

__all__ = ["enumerate_subdomains", "ingest_subdomains", "parse_crtsh",
           "candidate_hosts", "classify_env", "registrable_apex", "Subdomain",
           "NONPROD_PREFIXES", "GENERIC_PREFIXES"]

# Non-prod / soft-target prefixes — the priority hunt (staging leaks prod's secrets).
NONPROD_PREFIXES = [
    "uat", "cug", "qa", "sit", "dev", "test", "tst", "stg", "stage", "staging",
    "preprod", "pre-prod", "nonprod", "demo", "sandbox", "sbx", "beta", "internal",
    "int", "corp", "old", "legacy", "uat1", "uat2", "dev1", "qa1", "devtest",
]
# Generic service prefixes worth resolving on any target.
GENERIC_PREFIXES = [
    "www", "api", "apis", "app", "admin", "portal", "gateway", "gw", "auth", "login",
    "sso", "account", "accounts", "mobile", "m", "static", "cdn", "assets", "img",
    "mail", "webmail", "smtp", "ftp", "vpn", "remote", "git", "gitlab", "jenkins",
    "grafana", "kibana", "console", "dashboard", "mgmt", "ws", "socket", "onboarding",
]

# Strong env tokens: a label containing one of these (as substring) is non-prod
# (covers concatenated names like "vamauat", "nwmwuat", "onboardinguat").
_STRONG_ENV = ("uat", "cug", "staging", "preprod", "nonprod", "sandbox", "sbx")
# Weak env tokens: matched only as a bounded component (avoid "sit" in "website").
_WEAK_ENV = ("dev", "qa", "sit", "stg", "stage", "test", "tst", "demo", "beta",
             "int", "old", "legacy", "sbox")
_WEAK_RX = re.compile(r"(?:^|[.\-_])(" + "|".join(_WEAK_ENV) + r")(?:[.\-_]|\d*$)")

_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"


@dataclass
class Subdomain:
    host: str
    ips: list[str] = field(default_factory=list)
    alive: bool = False
    status: int | None = None
    env: str = "prod"          # "prod" | "non-prod"
    sources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"host": self.host, "ips": self.ips, "alive": self.alive,
                "status": self.status, "env": self.env, "sources": sorted(set(self.sources))}


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #
def registrable_apex(domain: str) -> str:
    """Best-effort registrable apex (handles the common two-level public suffixes)."""
    host = domain.strip().lower().split("//")[-1].split("/")[0].split(":")[0].rstrip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    two_level = {"co", "com", "org", "net", "gov", "edu", "ac"}
    if parts[-2] in two_level and len(parts[-1]) == 2:   # e.g. co.uk, com.au
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def classify_env(host: str) -> str:
    """'non-prod' if any label signals a non-production environment, else 'prod'."""
    labels = host.lower().split(".")
    for lab in labels:
        if any(tok in lab for tok in _STRONG_ENV):
            return "non-prod"
    if _WEAK_RX.search(host.lower()):
        return "non-prod"
    return "prod"


def parse_crtsh(json_text: str, domain: str) -> set[str]:
    """Extract unique hostnames under `domain` from a crt.sh JSON response."""
    out: set[str] = set()
    apex = domain.lower().lstrip("*.")
    try:
        rows = json.loads(json_text)
    except Exception:  # noqa: BLE001
        return out
    for row in rows if isinstance(rows, list) else []:
        for field_name in ("name_value", "common_name"):
            val = row.get(field_name) if isinstance(row, dict) else None
            if not val:
                continue
            for name in re.split(r"[\s,;]+", str(val)):
                name = name.strip().lower().lstrip("*.").rstrip(".")
                if name and (name == apex or name.endswith("." + apex)) and "*" not in name:
                    out.add(name)
    return out


def candidate_hosts(domain: str, prefixes: list[str] | None = None) -> list[str]:
    apex = registrable_apex(domain)
    prefixes = prefixes if prefixes is not None else (NONPROD_PREFIXES + GENERIC_PREFIXES)
    return [f"{p}.{apex}" for p in prefixes]


# Env tokens appended to a KNOWN base label to catch concatenated non-prod twins
# (the common pattern: nwmw -> nwmwuat, onboarding -> onboardinguat, vama -> vamauat).
_ENV_SUFFIXES = ["uat", "cug", "dev", "qa", "sit", "stg", "uat1", "test", "staging"]


def env_variants(base_labels: set[str], apex: str) -> set[str]:
    """For each known base label, generate its non-prod twins ({label}{env} and
    {label}-{env}) — the concatenated-env naming that CT alone may miss when crt.sh
    is down."""
    out: set[str] = set()
    for lab in base_labels:
        lab = lab.strip().lower()
        if not lab or classify_env(lab) == "non-prod":
            continue                              # already a non-prod label
        for env in _ENV_SUFFIXES:
            out.add(f"{lab}{env}.{apex}")
            out.add(f"{lab}-{env}.{apex}")
    return out


# --------------------------------------------------------------------------- #
# Network steps (best-effort)
# --------------------------------------------------------------------------- #
def _get(url: str, timeout: int) -> str | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
            return r.read().decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return None


def _fetch_crtsh(domain: str, timeout: int = 25, retries: int = 3) -> set[str]:
    """crt.sh CT search — retried because it frequently 502s / times out."""
    apex = registrable_apex(domain)
    url = f"https://crt.sh/?q=%25.{apex}&output=json"
    import time as _t
    for attempt in range(retries):
        body = _get(url, timeout)
        if body:
            hosts = parse_crtsh(body, apex)
            if hosts:
                return hosts
        if attempt < retries - 1:
            _t.sleep(1.5 * (attempt + 1))
    return set()


def _fetch_certspotter(domain: str, timeout: int = 25) -> set[str]:
    """certspotter CT issuances — the fallback source when crt.sh is down."""
    apex = registrable_apex(domain)
    url = (f"https://api.certspotter.com/v1/issuances?domain={apex}"
           f"&include_subdomains=true&expand=dns_names")
    body = _get(url, timeout)
    if not body:
        return set()
    out: set[str] = set()
    try:
        for row in json.loads(body):
            for name in row.get("dns_names", []) if isinstance(row, dict) else []:
                name = str(name).strip().lower().lstrip("*.").rstrip(".")
                if name and (name == apex or name.endswith("." + apex)) and "*" not in name:
                    out.add(name)
    except Exception:  # noqa: BLE001
        pass
    return out


def _fetch_ct(domain: str) -> set[str]:
    """Union of all Certificate-Transparency sources (robust to any single one failing)."""
    return _fetch_crtsh(domain) | _fetch_certspotter(domain)


def _resolve(host: str) -> list[str]:
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(host, None)})
    except Exception:  # noqa: BLE001
        return []


def _http_status(host: str, timeout: int = 6) -> int | None:
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(f"{scheme}://{host}/", method="GET",
                                         headers={"User-Agent": _UA})
            with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
                return r.status
        except urllib.error.HTTPError as e:
            return e.code
        except Exception:  # noqa: BLE001
            continue
    return None


def enumerate_subdomains(domain: str, *, deep: bool = True, probe: bool = True,
                         workers: int = 30, max_hosts: int = 1500) -> dict[str, Any]:
    """Enumerate subdomains of `domain` (CT logs + prefix brute), resolve, optionally
    probe liveness, and return a structured result. Ingest with ``ingest_subdomains``."""
    apex = registrable_apex(domain)
    names: set[str] = {apex}
    names |= set(candidate_hosts(apex))
    ct_hosts: set[str] = set()
    if deep:
        ct_hosts = _fetch_ct(apex)
        names |= ct_hosts
        # brute the non-prod twins of every known base label (CT leftmost labels + generics)
        base_labels = {h.split(".")[0] for h in ct_hosts} | set(GENERIC_PREFIXES)
        names |= env_variants(base_labels, apex)
    names = set(list(names)[:max_hosts])

    results: dict[str, Subdomain] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for host, ips in zip(names, pool.map(_resolve, names)):
            if not ips:
                continue
            sd = Subdomain(host=host, ips=ips, env=classify_env(host))
            sd.sources.append("ct" if host in ct_hosts else "dns")
            results[host] = sd

    if probe and results:
        live = list(results)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for host, status in zip(live, pool.map(_http_status, live)):
                results[host].status = status
                results[host].alive = status is not None

    subs = sorted(results.values(), key=lambda s: (s.env != "non-prod", s.host))
    return {
        "domain": apex,
        "total": len(subs),
        "nonprod": [s.to_dict() for s in subs if s.env == "non-prod"],
        "prod": [s.to_dict() for s in subs if s.env == "prod"],
        "subdomains": [s.to_dict() for s in subs],
        "ct_count": len(ct_hosts),
    }


def ingest_subdomains(result: dict[str, Any]) -> int:
    """Ingest discovered live hosts into the attack graph as Host nodes so the fleet's
    scan/crawl/vuln rules pick them up. Returns the count ingested."""
    n = 0
    try:
        from ..graph import model
    except Exception:  # noqa: BLE001
        return 0
    for sd in result.get("subdomains", []):
        try:
            ip = (sd.get("ips") or [None])[0]
            model.upsert_host(sd["host"], ip=ip)
            try:
                model.set_host_state(sd["host"], discovered=True)
            except Exception:  # noqa: BLE001 - set_host_state optional
                pass
            n += 1
        except Exception:  # noqa: BLE001
            continue
    return n
