"""
Passive web reconnaissance engine.

Given a site (URL or domain) this gathers a security attack-surface picture using
only safe, passive/light techniques over standard HTTP(S):

  * DNS resolution (A/AAAA) + reverse DNS
  * HTTP(S) fetch: status, redirect chain, response headers
  * Security-header posture (HSTS, CSP, X-Frame-Options, ...)
  * TLS certificate (issuer, subject, validity window, SANs)
  * Server / technology fingerprint (headers + HTML signatures)
  * Page title + meta description
  * robots.txt, sitemap, /.well-known/security.txt presence
  * Light exposed-path probe (.git/, .env, /admin, ...) via HEAD only

No exploitation, no auth bypass, no active scanning — just what a defender or an
authorised analyst would collect to assess a site's exposure. The DeepSeek agent
reasons over this to produce a finding.
"""
from __future__ import annotations

import socket
import ssl
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

USER_AGENT = "SyberRecon/3.0 (+security-intelligence-platform; passive)"
TIMEOUT = 6.0

# Response headers that materially reduce attack surface when present.
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS (forces HTTPS)",
    "content-security-policy": "CSP (mitigates XSS/injection)",
    "x-frame-options": "clickjacking protection",
    "x-content-type-options": "MIME-sniffing protection",
    "referrer-policy": "referrer leakage control",
    "permissions-policy": "browser feature restriction",
}

# Light, non-destructive probes for commonly-exposed sensitive paths.
SENSITIVE_PATHS = ["/.git/HEAD", "/.env", "/.well-known/security.txt",
                   "/robots.txt", "/sitemap.xml", "/admin", "/server-status"]

# Header/HTML signatures -> technology.
TECH_SIGNATURES = {
    "x-powered-by": "powered-by header",
    "server": "server banner",
    "x-aspnet-version": "ASP.NET",
    "x-drupal-cache": "Drupal",
    "x-generator": "generator header",
}


def _normalise(site: str) -> tuple[str, str]:
    site = site.strip()
    if not site.startswith(("http://", "https://")):
        site = "https://" + site
    host = urlparse(site).hostname or site
    return site, host


def _dns(host: str) -> dict[str, Any]:
    out: dict[str, Any] = {"host": host, "addresses": [], "reverse_dns": None}
    try:
        infos = socket.getaddrinfo(host, None)
        out["addresses"] = sorted({i[4][0] for i in infos})
    except socket.gaierror as e:
        out["error"] = f"DNS resolution failed: {e}"
        return out
    try:
        if out["addresses"]:
            out["reverse_dns"] = socket.gethostbyaddr(out["addresses"][0])[0]
    except (socket.herror, socket.gaierror, OSError):
        pass
    return out


def _tls_cert(host: str, port: int = 443) -> dict[str, Any]:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
        subject = {k: v for t in cert.get("subject", []) for k, v in t}
        issuer = {k: v for t in cert.get("issuer", []) for k, v in t}
        sans = [v for typ, v in cert.get("subjectAltName", []) if typ == "DNS"]
        return {
            "subject_cn": subject.get("commonName"),
            "issuer": issuer.get("organizationName") or issuer.get("commonName"),
            "valid_from": cert.get("notBefore"),
            "valid_to": cert.get("notAfter"),
            "subject_alt_names": sans[:25],
            "tls_version": cipher[1] if cipher else None,
            "cipher": cipher[0] if cipher else None,
        }
    except (ssl.SSLError, socket.timeout, ConnectionError, OSError) as e:
        return {"error": f"TLS handshake failed: {e}"}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # noqa: D401
        return None


def _http(url: str) -> dict[str, Any]:
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    info: dict[str, Any] = {"requested": url}
    try:
        resp = opener.open(req, timeout=TIMEOUT)
        status, headers = resp.status, dict(resp.headers)
        body = resp.read(200_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        status, headers, body = e.code, dict(e.headers or {}), ""
        if 300 <= status < 400:
            info["redirect_to"] = headers.get("Location")
    except (urllib.error.URLError, socket.timeout, ConnectionError, OSError) as e:
        return {"requested": url, "error": f"HTTP request failed: {e}"}

    lower = {k.lower(): v for k, v in headers.items()}
    if 300 <= status < 400:
        info["redirect_to"] = lower.get("location")

    present = {h: lower[h] for h in SECURITY_HEADERS if h in lower}
    missing = [SECURITY_HEADERS[h] for h in SECURITY_HEADERS if h not in lower]

    tech = []
    for h, label in TECH_SIGNATURES.items():
        if h in lower:
            tech.append(f"{label}: {lower[h]}")
    title = (re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S) or [None, None])[1]
    desc = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']', body, re.I)
    for gen in re.findall(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'](.*?)["\']', body, re.I):
        tech.append(f"generator: {gen}")

    info.update({
        "status": status,
        "server": lower.get("server"),
        "security_headers_present": present,
        "security_headers_missing": missing,
        "technology": tech,
        "title": (title or "").strip()[:200] if title else None,
        "meta_description": (desc.group(1).strip()[:300] if desc else None),
        "sets_cookie": "set-cookie" in lower,
        "cookie_flags": _cookie_flags(headers),
    })
    return info


def _cookie_flags(headers: dict[str, str]) -> dict[str, bool] | None:
    cookie = next((v for k, v in headers.items() if k.lower() == "set-cookie"), None)
    if not cookie:
        return None
    low = cookie.lower()
    return {"secure": "secure" in low, "httponly": "httponly" in low, "samesite": "samesite" in low}


def _probe_paths(base: str) -> list[dict[str, Any]]:
    root = f"{urlparse(base).scheme}://{urlparse(base).hostname}"
    results = []
    for path in SENSITIVE_PATHS:
        url = root + path
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
        try:
            resp = urllib.request.urlopen(req, timeout=TIMEOUT)
            code = resp.status
        except urllib.error.HTTPError as e:
            code = e.code
        except (urllib.error.URLError, socket.timeout, ConnectionError, OSError):
            code = None
        # 200/403 on a sensitive path is noteworthy; 404 is fine.
        if code in (200, 401, 403):
            results.append({"path": path, "status": code,
                            "note": "exposed/restricted resource present"})
    return results


def recon_site(site: str) -> dict[str, Any]:
    """Run the full passive recon sweep and return a structured report."""
    url, host = _normalise(site)
    report: dict[str, Any] = {
        "input": site,
        "url": url,
        "host": host,
        "collected_at_utc": datetime.now(timezone.utc).isoformat(),
        "method": "passive (DNS + HTTP headers + TLS + light HEAD probes)",
    }
    report["dns"] = _dns(host)
    report["http"] = _http(url)
    if url.startswith("https://"):
        report["tls"] = _tls_cert(host)
    report["exposed_paths"] = _probe_paths(url)
    report["risk_indicators"] = _risk_indicators(report)
    return report


def _risk_indicators(r: dict[str, Any]) -> list[str]:
    risks: list[str] = []
    http = r.get("http", {})
    if isinstance(http, dict):
        missing = http.get("security_headers_missing", [])
        if "HSTS (forces HTTPS)" in missing:
            risks.append("missing_hsts")
        if "CSP (mitigates XSS/injection)" in missing:
            risks.append("missing_csp")
        if "clickjacking protection" in missing:
            risks.append("missing_x_frame_options")
        flags = http.get("cookie_flags")
        if flags and not flags.get("secure"):
            risks.append("cookie_without_secure_flag")
        if http.get("server"):
            risks.append("server_banner_disclosed")
    tls = r.get("tls", {})
    if isinstance(tls, dict) and tls.get("valid_to"):
        try:
            exp = datetime.strptime(tls["valid_to"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            if (exp - datetime.now(timezone.utc)).days < 21:
                risks.append("tls_cert_expiring_soon")
        except ValueError:
            pass
    for p in r.get("exposed_paths", []):
        if p["path"] in ("/.git/HEAD", "/.env") and p["status"] in (200, 403):
            risks.append(f"sensitive_path_exposed:{p['path']}")
    return risks
