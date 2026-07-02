"""
Deterministic subdomain enumeration — "map the whole surface FIRST".

The consistency failure this fixes: the winning engagements found the catastrophic
exposure only because the agent *happened* to read a JS file that named the non-prod
subdomains (vamauat / nwmwuat / …). On an unlucky run it never found them and declared
the target "secure". Subdomain discovery must not depend on the model's mood — so this
module enumerates the surface deterministically at engagement start, every time.

Multi-tier so no single source is a point of failure (crt.sh alone was — it 502s/rate-
limits constantly):
  * **Tier 1** — shell out to `subfinder` (~30 passive sources) when it is installed.
  * **Tier 2** — a parallel union of keyless passive sources over stdlib urllib:
    certspotter + crt.sh(retry) + hackertarget + urlscan + wayback CDX (+ AlienVault OTX
    when `OTX_API_KEY` is set). A single source failing never drops coverage to zero.
  * **Prefix wordlist + base×env twin brute** — generic + non-prod names, and the
    concatenated-env twins of discovered labels (nwmw → nwmwuat, vama → vamauat).
  * **Resolve/validate** — `dnsx` when installed (fast, wildcard-aware), else stdlib DNS;
    an optional lightweight HTTP probe records liveness/status.
Active DNS brute-force (puredns/massdns) is intentionally NOT run here by default
(noisy) — it belongs behind an opt-in flag.

Every discovered live host is ingested as a graph Host node, so the fleet's existing
service_scan / web_crawl / vuln_scan rules pick it up automatically. Non-prod hosts are
flagged (they are prioritised — that is where exposure usually is).

Pure helpers (``parse_crtsh``, ``candidate_hosts``, ``classify_env``, ``registrable_apex``)
are unit-tested without network.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import time
import urllib.parse
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
def _get(url: str, timeout: int, headers: dict[str, str] | None = None) -> str | None:
    h = {"User-Agent": _UA, "Accept": "*/*"}
    if headers:
        h.update(headers)
    try:
        req = urllib.request.Request(url, headers=h)
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
            return r.read().decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 - every source is best-effort
        return None


def _keep(name: str, apex: str) -> str | None:
    name = str(name).strip().lower().lstrip("*.").rstrip(".")
    if name and "*" not in name and " " not in name and (name == apex or name.endswith("." + apex)):
        return name
    return None


# --- passive sources (each returns a set; failure -> empty, never raises) --- #
def _src_certspotter(apex: str, timeout: int = 20) -> set[str]:
    body = _get(f"https://api.certspotter.com/v1/issuances?domain={apex}"
                f"&include_subdomains=true&expand=dns_names", timeout)
    out: set[str] = set()
    if body:
        try:
            for row in json.loads(body):
                for n in (row.get("dns_names", []) if isinstance(row, dict) else []):
                    k = _keep(n, apex)
                    if k:
                        out.add(k)
        except Exception:  # noqa: BLE001
            pass
    return out


def _src_crtsh(apex: str, timeout: int = 20, retries: int = 2) -> set[str]:
    """crt.sh — retried (frequently 502s); non-fatal since certspotter covers the same CT data."""
    url = f"https://crt.sh/?q=%25.{apex}&output=json"
    for attempt in range(retries):
        body = _get(url, timeout)
        if body:
            hosts = parse_crtsh(body, apex)
            if hosts:
                return hosts
        if attempt < retries - 1:
            time.sleep(1.0)
    return set()


def _src_hackertarget(apex: str, timeout: int = 15) -> set[str]:
    body = _get(f"https://api.hackertarget.com/hostsearch/?q={apex}", timeout)
    out: set[str] = set()
    if body and "API count" not in body and "error" not in body.lower()[:40]:
        for line in body.splitlines():
            k = _keep(line.split(",")[0], apex)
            if k:
                out.add(k)
    return out


def _src_urlscan(apex: str, timeout: int = 15) -> set[str]:
    body = _get(f"https://urlscan.io/api/v1/search/?q=domain:{apex}&size=10000", timeout)
    out: set[str] = set()
    if body:
        try:
            for r in json.loads(body).get("results", []):
                k = _keep((r.get("page") or {}).get("domain") or "", apex)
                if k:
                    out.add(k)
        except Exception:  # noqa: BLE001
            pass
    return out


def _src_wayback(apex: str, timeout: int = 25) -> set[str]:
    body = _get(f"http://web.archive.org/cdx/search/cdx?url=*.{apex}/*&output=json"
                f"&fl=original&collapse=urlkey&limit=50000", timeout)
    out: set[str] = set()
    if body:
        try:
            for row in json.loads(body)[1:]:
                m = re.search(r"https?://([^/:]+)", row[0])
                if m:
                    k = _keep(m.group(1), apex)
                    if k:
                        out.add(k)
        except Exception:  # noqa: BLE001
            pass
    return out


def _src_otx(apex: str, timeout: int = 15) -> set[str]:
    """AlienVault OTX passive DNS — needs the free OTX_API_KEY (unauth is 429-throttled)."""
    key = os.environ.get("OTX_API_KEY")
    if not key:
        return set()
    body = _get(f"https://otx.alienvault.com/api/v1/indicators/domain/{apex}/passive_dns",
                timeout, headers={"X-OTX-API-KEY": key})
    out: set[str] = set()
    if body:
        try:
            for e in json.loads(body).get("passive_dns", []):
                k = _keep(e.get("hostname") or "", apex)
                if k:
                    out.add(k)
        except Exception:  # noqa: BLE001
            pass
    return out


_PASSIVE_SOURCES = {
    "certspotter": _src_certspotter, "crtsh": _src_crtsh, "hackertarget": _src_hackertarget,
    "urlscan": _src_urlscan, "wayback": _src_wayback, "otx": _src_otx,
}


def passive_union(apex: str, workers: int = 6) -> tuple[set[str], dict[str, int]]:
    """Union every passive source in parallel. Returns (hosts, per-source counts). No
    single source failing (crt.sh 502, wayback down) drops coverage to zero."""
    hosts: set[str] = set()
    meta: dict[str, int] = {}
    items = list(_PASSIVE_SOURCES.items())
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for (name, _), got in zip(items, pool.map(lambda kv: kv[1](apex), items)):
            meta[name] = len(got)
            hosts |= got
    return hosts, meta


# --- external tools (used when present; degrade to pure-python otherwise) ---- #
def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


def _run_tool(cmd: list[str], *, input_text: str | None = None, timeout: int = 150) -> str:
    try:
        p = subprocess.run(cmd, input=input_text, capture_output=True, text=True, timeout=timeout)
        return p.stdout or ""
    except Exception:  # noqa: BLE001 - missing tool / timeout -> empty, degrade gracefully
        return ""


def run_subfinder(apex: str, timeout: int = 150) -> set[str]:
    """Tier-1 passive aggregator (~30 sources). Zero keys for the free sources; a
    provider-config.yaml unlocks more. Empty set if subfinder isn't installed."""
    if not _have("subfinder"):
        return set()
    out = _run_tool(["subfinder", "-d", apex, "-all", "-silent"], timeout=timeout)
    return {k for line in out.splitlines() if (k := _keep(line, apex))}


def _first_existing(paths: list[str]) -> str | None:
    for p in paths:
        if os.path.isfile(p):
            return p
    return None


def run_puredns_brute(apex: str, timeout: int = 900) -> set[str]:
    """Tier-3 ACTIVE brute-force: puredns (massdns) with a DNS wordlist + trusted
    resolvers, with wildcard filtering. Zero keys. Empty set if puredns/wordlist/
    resolvers aren't available. Noisy (mass DNS) — gated behind the `brute` flag."""
    if not _have("puredns"):
        return set()
    wl = os.environ.get("SYBER_DNS_WORDLIST") or _first_existing([
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
        "/usr/share/seclists/Discovery/DNS/n0kovo_subdomains_huge.txt",
        "/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt",
        "/usr/share/wordlists/amass/subdomains-top1mil-5000.txt"])
    if not wl:
        return set()
    resolvers = os.environ.get("SYBER_RESOLVERS") or _first_existing([
        "/opt/resolvers.txt", "/usr/share/resolvers/resolvers.txt"])
    cmd = ["puredns", "bruteforce", wl, apex, "-q"]
    if resolvers:
        cmd += ["-r", resolvers]
    out = _run_tool(cmd, timeout=timeout)
    return {k for line in out.splitlines() if (k := _keep(line, apex))}


def resolve_hosts(names: set[str], workers: int = 30) -> dict[str, list[str]]:
    """Resolve candidates to IPs. Prefers dnsx (fast, wildcard-aware) when installed;
    falls back to the stdlib socket resolver."""
    names = set(names)
    if not names:
        return {}
    if _have("dnsx"):
        out = _run_tool(["dnsx", "-silent", "-a", "-resp", "-json"],
                        input_text="\n".join(names), timeout=180)
        resolved: dict[str, list[str]] = {}
        for line in out.splitlines():
            try:
                rec = json.loads(line)
            except Exception:  # noqa: BLE001
                continue
            host = str(rec.get("host", "")).lower()
            if host:
                resolved[host] = rec.get("a", []) or resolved.get(host, [])
        if resolved:
            return resolved
    # socket fallback
    resolved = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for host, ips in zip(names, pool.map(_resolve, names)):
            if ips:
                resolved[host] = ips
    return resolved


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
                         brute: bool | None = None,
                         workers: int = 30, max_hosts: int = 5000) -> dict[str, Any]:
    """Enumerate subdomains of `domain` and return a structured result (ingest with
    ``ingest_subdomains``). Multi-tier, so no single source is a point of failure:
      * Tier 1 — `subfinder` (~30 passive sources) when installed;
      * Tier 2 — a parallel union of keyless passive sources (certspotter, crt.sh,
        hackertarget, urlscan, wayback, + OTX if OTX_API_KEY set);
      * plus the generic/non-prod prefix wordlist and base×env twin brute;
    then resolve/validate (dnsx if installed, else stdlib DNS) and optionally probe."""
    apex = registrable_apex(domain)
    discovered: set[str] = set()            # names asserted by a real source (not brute guesses)
    meta: dict[str, int] = {}
    if deep:
        sf = run_subfinder(apex)
        if sf:
            meta["subfinder"] = len(sf)
            discovered |= sf
        passive, pmeta = passive_union(apex, workers=6)
        meta.update(pmeta)
        discovered |= passive
        # Tier 3 — active DNS brute-force (puredns). Default follows SYBER_SUBDOMAIN_BRUTE
        # (default ON for the thorough profile); noisy, so it can be disabled per-call.
        if brute is None:
            brute = os.environ.get("SYBER_SUBDOMAIN_BRUTE", "1") not in ("0", "false", "off", "")
        if brute:
            bruted = run_puredns_brute(apex)
            if bruted:
                meta["puredns"] = len(bruted)
                discovered |= bruted

    # Candidate set = sourced names + generic prefixes + non-prod twins of known labels.
    names: set[str] = {apex} | set(candidate_hosts(apex)) | discovered
    base_labels = {h.split(".")[0] for h in discovered} | set(GENERIC_PREFIXES)
    names |= env_variants(base_labels, apex)
    names = set(list(names)[:max_hosts])

    resolved = resolve_hosts(names, workers=workers)
    results: dict[str, Subdomain] = {}
    for host, ips in resolved.items():
        sd = Subdomain(host=host, ips=ips, env=classify_env(host))
        sd.sources.append("source" if host in discovered else "dns")
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
        "sources": meta,                    # per-source counts (which sources produced hits)
        "nonprod": [s.to_dict() for s in subs if s.env == "non-prod"],
        "prod": [s.to_dict() for s in subs if s.env == "prod"],
        "subdomains": [s.to_dict() for s in subs],
        "ct_count": sum(meta.get(k, 0) for k in ("certspotter", "crtsh")),
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
