"""
WAF fallback / pivot (waf-spec §4.3 dead-end handling, extended).

When the layered traversal cannot clear a Cloudflare obstacle — a hard block
(error 1020/1010), an interactive Turnstile with no solving service, or plain
exhaustion — the engagement must NOT dead-end. Cloudflare only protects the
*proxied edge*; the origin server, sibling subdomains, and non-HTTP services
routinely sit outside the WAF. This module pivots the agent to those vectors:

  * origin discovery    — resolve common non-proxied subdomains and harvest
                          certificate-transparency SANs, then classify every
                          resolved IP as a Cloudflare edge vs a candidate origin.
  * direct-origin probe — connect to a candidate IP directly with the original
                          ``Host`` header; a real (non-challenge) response means
                          the WAF has been bypassed at the origin (the canonical
                          authorised-pentest Cloudflare bypass).
  * vector plan         — a ranked list of alternate attack surfaces to work when
                          no direct origin is found: non-edge subdomains, ports
                          Cloudflare doesn't proxy, DNS/mail, and API hosts.

Design rules (same posture as the rest of syber.waf):
  * Dependency-light — stdlib ``socket`` / ``ssl`` / ``ipaddress`` / ``urllib``.
  * Best-effort and graceful — every probe is guarded; a failure narrows the
    result, it never raises into the caller.
  * OSINT only against the *certificate*, never the target — the crt.sh lookup
    queries the public CT logs, not the protected host. Direct-origin probes only
    touch the SAME apex the caller already authorised.

References: Cloudflare published IP ranges (cloudflare.com/ips); origin-exposure
research (CloudFlair, crt.sh CT mining); waf-spec §2.5 (hard-block back-off) and
§3.8 (find an unprotected path before grinding the edge).
"""
from __future__ import annotations

import ipaddress
import json
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from .detect import detect_challenge

__all__ = ["FallbackResult", "OriginCandidate", "is_cloudflare_ip",
           "resolve_host", "candidate_subdomains", "harvest_ct_subdomains",
           "find_origin_candidates", "probe_origin", "explore_alternate_vectors"]

# Cloudflare's published IPv4 edge ranges (cloudflare.com/ips-v4). An IP inside
# these is the WAF edge; an IP OUTSIDE them — resolved for a sibling host or an
# old CT-log SAN — is a candidate origin that may not be fronted by the WAF.
_CF_RANGES_V4 = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]
_CF_RANGES_V6 = [
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]
_CF_NETS = [ipaddress.ip_network(c) for c in (_CF_RANGES_V4 + _CF_RANGES_V6)]

# Subdomain labels that frequently point straight at the origin (operators forget
# to proxy them, or they MUST resolve to the real host: mail, ftp, cpanel, etc.).
_ORIGIN_LABELS = [
    "direct", "origin", "origin-www", "www-origin", "direct-connect",
    "cpanel", "whm", "webmail", "mail", "email", "smtp", "imap", "pop",
    "mx", "mx1", "mx2", "ftp", "sftp", "ssh", "vpn", "remote", "gateway",
    "dev", "staging", "stage", "test", "testing", "beta", "qa", "uat",
    "api", "api-dev", "admin", "portal", "secure", "internal", "intranet",
    "server", "server1", "host", "web", "web1", "ns1", "ns2", "db", "mysql",
    "cdn-origin", "old", "legacy", "backup", "static", "assets",
]

# Ports Cloudflare's HTTP proxy does NOT cover by default — reaching them touches
# the origin directly even on a proxied host (a vector worth probing/scanning).
_NON_PROXIED_PORTS = [22, 21, 25, 110, 143, 3306, 5432, 6379, 8080, 8443, 9200, 3389]

_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")


# --------------------------------------------------------------------------- #
# IP classification + DNS
# --------------------------------------------------------------------------- #
def is_cloudflare_ip(ip: str) -> bool:
    """True if ``ip`` is inside a published Cloudflare edge range (so it is the
    WAF, not the origin). Malformed input is treated as non-Cloudflare."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _CF_NETS)


def resolve_host(host: str, timeout: float = 3.0) -> list[str]:
    """Resolve ``host`` to its A/AAAA addresses (deduped). Empty on any failure —
    a non-resolving sibling is simply not a vector, not an error."""
    prev = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, OSError, UnicodeError):
        return []
    finally:
        socket.setdefaulttimeout(prev)
    out: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in out:
            out.append(ip)
    return out


def _apex(domain: str) -> str:
    """Best-effort registrable apex (last two labels). Good enough for sibling
    enumeration; multi-part TLDs (co.uk) over-include slightly, which is harmless."""
    parts = (domain or "").strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def candidate_subdomains(domain: str) -> list[str]:
    """Common origin-revealing hostnames under the domain's apex (deduped, the
    bare apex first)."""
    apex = _apex(domain)
    hosts = [apex] + [f"{label}.{apex}" for label in _ORIGIN_LABELS]
    # keep insertion order, drop dups + the proxied host we already know is edge
    seen: set[str] = set()
    out: list[str] = []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def harvest_ct_subdomains(domain: str, timeout: float = 6.0, limit: int = 60) -> list[str]:
    """Mine certificate-transparency logs (crt.sh) for subdomains of the apex.

    This is OSINT against the public CT record, not a probe of the target. It
    surfaces hosts (incl. retired ones whose DNS may still point at the origin)
    that pure guessing misses. Network/parse failures yield an empty list."""
    apex = _apex(domain)
    url = f"https://crt.sh/?q=%25.{apex}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (public OSINT)
            raw = r.read(2_000_000).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ValueError):
        return []
    try:
        rows = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return []
    names: set[str] = set()
    for row in rows if isinstance(rows, list) else []:
        for field_ in ("common_name", "name_value"):
            val = row.get(field_) if isinstance(row, dict) else None
            for name in str(val or "").split("\n"):
                name = name.strip().lstrip("*.").lower()
                if name.endswith(apex) and "@" not in name and " " not in name:
                    names.add(name)
    return sorted(names)[:limit]


# --------------------------------------------------------------------------- #
# Origin discovery
# --------------------------------------------------------------------------- #
@dataclass
class OriginCandidate:
    host: str
    ip: str
    cloudflare: bool                # is this IP a Cloudflare edge?
    source: str = ""                # "guess" | "ct" | "apex"

    def to_dict(self) -> dict[str, Any]:
        return {"host": self.host, "ip": self.ip, "cloudflare": self.cloudflare,
                "source": self.source}


def find_origin_candidates(domain: str, use_ct: bool = True,
                           max_hosts: int = 80) -> list[OriginCandidate]:
    """Resolve sibling/CT hosts and classify each IP as a Cloudflare edge or a
    candidate origin. Non-Cloudflare IPs (``cloudflare=False``) are the prize."""
    apex = _apex(domain)
    sources: dict[str, str] = {}
    for h in candidate_subdomains(domain):
        sources[h] = "apex" if h == apex else "guess"
    if use_ct:
        for h in harvest_ct_subdomains(domain):
            sources.setdefault(h, "ct")
    hosts = list(sources)[:max_hosts]
    out: list[OriginCandidate] = []
    seen_ips: set[str] = set()
    for h in hosts:
        source = sources[h]
        for ip in resolve_host(h):
            key = f"{h}|{ip}"
            if key in seen_ips:
                continue
            seen_ips.add(key)
            out.append(OriginCandidate(host=h, ip=ip, cloudflare=is_cloudflare_ip(ip),
                                       source=source))
    # candidate origins (non-CF) first, then edges, for the caller's convenience
    out.sort(key=lambda c: (c.cloudflare, c.host))
    return out


def probe_origin(ip: str, domain: str, scheme: str = "https", path: str = "/",
                 timeout: float = 8.0) -> dict[str, Any] | None:
    """Hit ``ip`` directly with ``Host: domain`` — if the origin answers without a
    Cloudflare challenge, the WAF is bypassed. Returns a response dict on a real
    answer, ``None`` if it still looks like Cloudflare or the probe failed.

    TLS is attempted with SNI = the real domain but the connection is pinned to
    ``ip``; cert verification is disabled because we are deliberately connecting to
    a non-canonical address (an origin pull), exactly as a CDN does."""
    is_https = scheme == "https"
    port = 443 if is_https else 80
    host_header = domain
    request = (
        f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\n"
        f"User-Agent: {_UA}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    ).encode()
    try:
        raw_sock = socket.create_connection((ip, port), timeout=timeout)
    except (OSError, socket.timeout):
        return None
    try:
        sock: socket.socket = raw_sock
        if is_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw_sock, server_hostname=domain)
        sock.sendall(request)
        chunks: list[bytes] = []
        sock.settimeout(timeout)
        total = 0
        while total < 200_000:
            try:
                buf = sock.recv(16384)
            except (socket.timeout, ssl.SSLError, OSError):
                break
            if not buf:
                break
            chunks.append(buf)
            total += len(buf)
    except (OSError, ssl.SSLError, socket.timeout):
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return _parse_http_response(b"".join(chunks), ip, domain)


def _parse_http_response(raw: bytes, ip: str, domain: str) -> dict[str, Any] | None:
    if not raw:
        return None
    head, _, body_bytes = raw.partition(b"\r\n\r\n")
    text_head = head.decode("iso-8859-1", "replace")
    lines = text_head.split("\r\n")
    if not lines or not lines[0].startswith("HTTP/"):
        return None
    try:
        status = int(lines[0].split()[1])
    except (IndexError, ValueError):
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    body = body_bytes.decode("utf-8", "replace")
    # If the direct hit STILL looks like Cloudflare, this IP is just another edge.
    verdict = detect_challenge(status, headers, body)
    if verdict.cloudflare or verdict.detected:
        return None
    return {"status": status, "headers": headers, "body": body[:200_000],
            "length": len(body), "transport": f"origin-direct:{ip}",
            "origin_ip": ip, "host": domain}


# --------------------------------------------------------------------------- #
# Top-level pivot
# --------------------------------------------------------------------------- #
@dataclass
class FallbackResult:
    """The outcome of a WAF pivot: a direct origin hit (best case) plus the full
    alternate-vector plan for the agent to keep working the target."""

    domain: str
    direct_hit: dict[str, Any] | None = None          # bypassed response, if any
    origin_ip: str | None = None
    candidates: list[OriginCandidate] = field(default_factory=list)
    non_cf_hosts: list[dict[str, str]] = field(default_factory=list)
    cf_hosts: list[dict[str, str]] = field(default_factory=list)
    vectors: list[dict[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def bypassed(self) -> bool:
        return self.direct_hit is not None

    def to_dict(self) -> dict[str, Any]:
        return {"domain": self.domain, "bypassed": self.bypassed,
                "origin_ip": self.origin_ip, "direct_hit": self.direct_hit,
                "candidates": [c.to_dict() for c in self.candidates],
                "non_cf_hosts": self.non_cf_hosts, "cf_hosts": self.cf_hosts,
                "vectors": self.vectors, "notes": self.notes}


def explore_alternate_vectors(url_or_domain: str, *, use_ct: bool = True,
                              probe: bool = True, scheme: str | None = None,
                              max_probes: int = 8) -> FallbackResult:
    """The WAF dead-end pivot. Discover and (optionally) probe an unprotected path
    to the target, and return a ranked alternate-vector plan for the agent.

    1. Resolve sibling + CT-log hosts; classify each IP CF-edge vs candidate origin.
    2. For each NON-Cloudflare candidate, try a direct-origin probe (Host header).
       The first real answer is returned as ``direct_hit`` — the WAF is bypassed.
    3. Whether or not a direct hit lands, return the alternate-vector plan
       (non-edge subdomains, non-proxied ports, DNS/mail, API hosts) so the agent
       widens the search instead of grinding the protected edge.
    """
    parsed = urlparse(url_or_domain if "://" in url_or_domain else f"//{url_or_domain}")
    domain = (parsed.netloc or parsed.path).split("@")[-1].split(":")[0].lower()
    scheme = scheme or (parsed.scheme if parsed.scheme in ("http", "https") else "https")
    res = FallbackResult(domain=domain)

    res.candidates = find_origin_candidates(domain, use_ct=use_ct)
    res.non_cf_hosts = [{"host": c.host, "ip": c.ip} for c in res.candidates if not c.cloudflare]
    res.cf_hosts = [{"host": c.host, "ip": c.ip} for c in res.candidates if c.cloudflare]

    if not res.candidates:
        res.notes.append("No sibling/CT hosts resolved — DNS may be locked down or "
                         "the dev sandbox cannot resolve. Pivot to OSINT and the "
                         "network-layer surface (ports, mail, DNS) instead.")
    elif not res.non_cf_hosts:
        res.notes.append("Every resolved host is a Cloudflare edge — no exposed "
                         "origin found via DNS/CT. The origin IP is well hidden; "
                         "favour the non-proxied-port and OSINT vectors below.")

    # 2. Try to bypass at the origin.
    if probe and res.non_cf_hosts:
        tried = 0
        for cand in res.candidates:
            if cand.cloudflare or tried >= max_probes:
                continue
            tried += 1
            hit = probe_origin(cand.ip, domain, scheme=scheme)
            if hit is not None:
                res.direct_hit = hit
                res.origin_ip = cand.ip
                res.notes.append(
                    f"WAF BYPASSED — origin {cand.ip} (via {cand.host}) answered "
                    f"directly with HTTP {hit.get('status')} and no Cloudflare "
                    f"challenge. Drive further requests at this IP with "
                    f"Host: {domain} to skip the edge entirely.")
                break

    res.vectors = _build_vector_plan(res)
    return res


def _build_vector_plan(res: FallbackResult) -> list[dict[str, str]]:
    """Rank the alternate attack surfaces for the agent to pursue."""
    domain = res.domain
    vectors: list[dict[str, str]] = []

    if res.direct_hit:
        vectors.append({
            "vector": "direct-origin",
            "priority": "high",
            "action": f"Origin {res.origin_ip} is reachable behind the WAF. Re-run "
                      f"crawl / IDOR / injection against it with Host: {domain}.",
        })
    if res.non_cf_hosts:
        sample = ", ".join(h["host"] for h in res.non_cf_hosts[:5])
        vectors.append({
            "vector": "non-edge-subdomains",
            "priority": "high",
            "action": f"These siblings resolve OFF Cloudflare and are likely "
                      f"un-WAF'd: {sample}. Scan and app-test each one.",
        })
    vectors.append({
        "vector": "non-proxied-ports",
        "priority": "medium",
        "action": f"Cloudflare only proxies HTTP(S) on standard ports. Port-scan "
                  f"{domain} for {', '.join(map(str, _NON_PROXIED_PORTS))} — SSH, "
                  f"mail, DB and 8080/8443 admin panels often hit the origin direct.",
    })
    vectors.append({
        "vector": "subdomain-enumeration",
        "priority": "medium",
        "action": f"Enumerate more subdomains of {_apex(domain)} (CT logs, brute, "
                  f"DNS) — dev/staging/api hosts are commonly forgotten behind the WAF.",
    })
    vectors.append({
        "vector": "dns-and-mail",
        "priority": "low",
        "action": f"Review DNS/MX/SPF/DMARC for {_apex(domain)}; MX hosts point at "
                  f"real mail servers (origin-adjacent) and email auth gaps are "
                  f"in-scope findings of their own.",
    })
    vectors.append({
        "vector": "api-and-mobile",
        "priority": "low",
        "action": "Look for api.* / m.* / app.* hosts and documented API endpoints — "
                  "API origins are frequently provisioned with weaker edge rules.",
    })
    return vectors
