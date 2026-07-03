"""
Browser-first web reconnaissance — drives a REAL Chrome via agent-browser.

Why not curl/urllib: a python HTTP client has a non-browser TLS (JA3) fingerprint
and User-Agent, runs no JavaScript, and is trivially flagged as a bot (and blocked
by Cloudflare/WAFs). This module navigates with real Chrome, so the target sees a
genuine browser, and we still extract everything recon needs:

  * status + response headers + redirect chain   -> via agent-browser HAR capture
  * rendered title, final URL, technologies        -> via eval on the live DOM
  * page structure (forms/inputs/links)            -> via eval + snapshot
  * evidence screenshot                            -> via screenshot

DNS resolution and the TLS certificate are still read at the socket level (not
bot-detectable, and they expose SANs / issuer the browser hides). Results feed
the rich attack-surface graph (graph/model.py).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import uuid
from typing import Any

from .site_recon import SECURITY_HEADERS, _dns, _normalise, _tls_cert

AB = "agent-browser"
_DOM_PROBE = (
    "JSON.stringify({"
    "title:document.title,"
    "finalUrl:location.href,"
    "generator:(document.querySelector('meta[name=generator]')||{}).content||null,"
    "forms:document.forms.length,"
    "inputs:document.querySelectorAll('input,textarea,select').length,"
    "links:document.querySelectorAll('a[href]').length,"
    "cookies:(document.cookie?document.cookie.split(';').length:0),"
    "tech:{"
    "jquery:!!window.jQuery,"
    "react:!!(window.React||document.querySelector('[data-reactroot],#__next,#root')),"
    "vue:!!(window.Vue||document.querySelector('[data-v-app]')),"
    "angular:!!(window.angular||document.querySelector('[ng-version]')),"
    "next:!!window.__NEXT_DATA__,"
    "wordpress:/wp-content|wp-includes/.test(document.documentElement.innerHTML.slice(0,8000)),"
    "bootstrap:!!document.querySelector('[class*=col-],[class*=navbar]')"
    "}})"
)


def browser_available() -> bool:
    return shutil.which(AB) is not None


def capture_screenshot(url: str, out_path: str, *, wait_ms: int = 2500,
                       cookies: str | None = None, require_data: bool = True) -> str | None:
    """Open `url` in real Chrome and screenshot it to `out_path` — a proof of a CONFIRMED
    exposure. Returns the path on success, else None.

    Two guards so the image actually PROVES something (not a login/403 page):
      * `cookies` (a "k=v; k2=v2" header) sets the authenticated session BEFORE navigating,
        so an auth-required finding is captured logged-in (showing the gated data) — the
        thing the operator asked for: "logging in and showing the data is the vulnerability."
      * `require_data`: after load, read the DOM and REFUSE to save the screenshot if it is
        a login wall / access-denied / error page (is_gated_page). No proof beats false proof.
    """
    if not browser_available():
        return None
    sess = f"proof-{uuid.uuid4().hex[:8]}"
    try:
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        # Set cookies for the target origin first (so the page renders authenticated).
        if cookies:
            for pair in cookies.split(";"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    _ab(["--session", sess, "cookies", "set", k.strip(), v.strip(), "--url", url], timeout=20)
        _ab(["--session", sess, "open", url], timeout=60)
        _ab(["--session", sess, "wait", str(wait_ms)])
        if require_data:
            _rc, dom, _ = _ab(["--session", sess, "eval",
                               "document.documentElement.innerText.slice(0,20000)"], timeout=30)
            body = _parse_eval(dom) if dom.strip().startswith('"') else dom
            body_text = body if isinstance(body, str) else str(body)
            try:
                from ..scanning.exfil import is_gated_page
                if is_gated_page(body_text):
                    _ab(["--session", sess, "close", "--all"])
                    return None            # login / denied / error page — not proof
            except Exception:  # noqa: BLE001
                pass
        _ab(["--session", sess, "screenshot", out_path])
        _ab(["--session", sess, "close", "--all"])
        return out_path if os.path.exists(out_path) else None
    except Exception:  # noqa: BLE001 - proof capture must never break the probe
        return None


def _ab(args: list[str], timeout: int = 45) -> tuple[int, str, str]:
    try:
        p = subprocess.run([AB, *args], capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError:
        return 127, "", "agent-browser not found"


def _parse_eval(raw: str) -> dict[str, Any]:
    raw = raw.strip()
    # agent-browser returns the JS result JSON-encoded (a quoted string).
    for _ in range(2):
        try:
            val = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            break
        if isinstance(val, dict):
            return val
        raw = val  # was a JSON string of our JSON; decode again
    return {}


def _parse_har(path: str) -> dict[str, Any]:
    try:
        har = json.load(open(path))
    except (json.JSONDecodeError, FileNotFoundError, OSError):
        return {}
    entries = har.get("log", {}).get("entries", [])
    if not entries:
        return {}
    doc = next((e for e in entries
                if e.get("response", {}).get("content", {}).get("mimeType", "").startswith("text/html")),
               entries[0])
    headers = {h["name"].lower(): h["value"] for h in doc.get("response", {}).get("headers", [])}
    redirects = [e["response"].get("redirectURL") or e["request"]["url"]
                 for e in entries if 300 <= e.get("response", {}).get("status", 0) < 400]
    req_headers = {h["name"].lower(): h["value"] for h in doc.get("request", {}).get("headers", [])}
    return {
        "status": doc.get("response", {}).get("status"),
        "headers": headers,
        "redirect_chain": redirects,
        "request_user_agent": req_headers.get("user-agent"),
        "url": doc.get("request", {}).get("url"),
    }


def _har_network_urls(path: str, host: str) -> list[dict[str, Any]]:
    """Harvest EVERY request the page made (the browser 'network tab') — XHR/fetch/API
    calls, not just the main document. These same-site URLs are the real API surface and
    must be ingested so they get probed. Returns [{url, method, status, params}]."""
    try:
        har = json.load(open(path))
    except (json.JSONDecodeError, FileNotFoundError, OSError):
        return []
    from urllib.parse import urlparse, parse_qsl
    apex = host.split(":")[0]
    out: dict[str, dict[str, Any]] = {}
    for e in har.get("log", {}).get("entries", []):
        req = e.get("request", {})
        url = req.get("url", "")
        if not url:
            continue
        netloc = urlparse(url).netloc.split(":")[0]
        # same registrable domain only (don't ingest third-party analytics/CDNs)
        if not (netloc == apex or netloc.endswith("." + _apex(apex))):
            continue
        key = url.split("#")[0]
        params = sorted({k for k, _ in parse_qsl(urlparse(url).query)})
        prev = out.get(key)
        if prev:
            prev["params"] = sorted(set(prev["params"]) | set(params))
        else:
            out[key] = {"url": key, "method": req.get("method", "GET"),
                        "status": e.get("response", {}).get("status"), "params": params}
    return list(out.values())


def _apex(host: str) -> str:
    try:
        from ..scanning.subdomains import registrable_apex
        return registrable_apex(host)
    except Exception:  # noqa: BLE001
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host


def recon_site(site: str, screenshot_dir: str | None = None) -> dict[str, Any]:
    """Browser-based passive recon. Same return shape as the old curl recon, but
    every HTTP byte goes through real Chrome (method = browser, not curl)."""
    url, host = _normalise(site)
    report: dict[str, Any] = {
        "input": site, "url": url, "host": host,
        "method": "real-browser (agent-browser + chromium) — not curl",
        "dns": _dns(host),
    }
    if url.startswith("https://"):
        report["tls"] = _tls_cert(host)

    if not browser_available():
        report["http"] = {"error": "agent-browser not installed — browser recon unavailable. "
                                    "Do NOT fall back to curl; install agent-browser."}
        report["risk_indicators"] = []
        return report

    sess = f"recon-{uuid.uuid4().hex[:8]}"
    har_path = os.path.join(tempfile.gettempdir(), f"{sess}.har")
    shot_dir = screenshot_dir or tempfile.gettempdir()
    shot_path = os.path.join(shot_dir, f"{sess}.png")

    _ab(["--session", sess, "network", "har", "start"])
    _ab(["--session", sess, "open", url], timeout=60)
    _ab(["--session", sess, "wait", "2000"])
    rc, dom_raw, _ = _ab(["--session", sess, "eval", _DOM_PROBE])
    _ab(["--session", sess, "network", "har", "stop", har_path])
    _ab(["--session", sess, "screenshot", shot_path])
    _ab(["--session", sess, "close", "--all"])

    dom = _parse_eval(dom_raw)
    har = _parse_har(har_path)
    headers = har.get("headers", {})

    present = {h: headers[h] for h in SECURITY_HEADERS if h in headers}
    missing = [SECURITY_HEADERS[h] for h in SECURITY_HEADERS if h not in headers]
    tech = _detect_tech(headers, dom)

    report["http"] = {
        "status": har.get("status"),
        "final_url": dom.get("finalUrl") or har.get("url"),
        "redirect_chain": har.get("redirect_chain", []),
        "server": headers.get("server"),
        "title": dom.get("title"),
        "security_headers_present": present,
        "security_headers_missing": missing,
        "technology": tech,
        "forms": dom.get("forms"),
        "inputs": dom.get("inputs"),
        "links": dom.get("links"),
        "cookies": dom.get("cookies"),
        "rendered_by_real_browser": True,
        "request_user_agent": har.get("request_user_agent"),
        "screenshot": shot_path if os.path.exists(shot_path) else None,
    }
    # The network tab: every same-site API/XHR/fetch the page fired — the real API surface.
    report["network_endpoints"] = _har_network_urls(har_path, host)
    report["risk_indicators"] = _risk_indicators(report)
    try:
        os.remove(har_path)
    except OSError:
        pass
    return report


def ingest_recon_to_graph(report: dict[str, Any]) -> dict[str, Any]:
    """Ingest a browser-recon report into the rich attack-surface graph (§6)."""
    from ..graph import model
    from ..graph.store import get_graph

    host = report["host"]
    ip = (report.get("dns", {}) or {}).get("addresses", [None])[0]
    model.upsert_host(host, ip=ip, source="browser_recon")

    http = report.get("http", {})
    if http.get("status") is not None:
        model.upsert_web_endpoint(host, report.get("url"), status=http.get("status"),
                                  title=http.get("title"))
    # Ingest every network-tab (API/XHR) URL as a WebEndpoint so coverage tracks it and
    # the probes test it — this is how "all URLs on the network tab" get covered.
    from urllib.parse import urlparse as _up
    for ne in report.get("network_endpoints", []):
        try:
            u = ne.get("url")
            if not u:
                continue
            ne_host = _up(u).netloc.split(":")[0] or host
            model.upsert_host(ne_host, source="network_tab")
            model.upsert_web_endpoint(ne_host, u, status=ne.get("status"),
                                      method=ne.get("method", "GET"), params=ne.get("params", []))
        except Exception:  # noqa: BLE001
            continue
    for t in http.get("technology", []):
        # "server: cloudflare" / "x-powered-by: PHP/8.1" -> the VALUE is the tech;
        # bare signals ("react", "wordpress") are the tech name themselves.
        name = t.split(":", 1)[1].strip() if ":" in t else t.strip()
        if name:
            model.upsert_technology(host, name, category="web")

    tls = report.get("tls", {})
    if isinstance(tls, dict) and not tls.get("error"):
        model.upsert_certificate(host, fingerprint=tls.get("subject_cn") or host,
                                 subject_cn=tls.get("subject_cn"), issuer=tls.get("issuer"),
                                 not_after=tls.get("valid_to"), sans=tls.get("subject_alt_names"))
    g = get_graph()
    return {"host": host, "risk_score": g.risk_score(host), "backend": type(g).__name__}


def _detect_tech(headers: dict[str, str], dom: dict[str, Any]) -> list[str]:
    tech: list[str] = []
    if headers.get("server"):
        tech.append(f"server: {headers['server']}")
    if headers.get("x-powered-by"):
        tech.append(f"x-powered-by: {headers['x-powered-by']}")
    if dom.get("generator"):
        tech.append(f"generator: {dom['generator']}")
    for name, on in (dom.get("tech") or {}).items():
        if on:
            tech.append(name)
    return tech


def _risk_indicators(r: dict[str, Any]) -> list[str]:
    risks: list[str] = []
    http = r.get("http", {})
    missing = http.get("security_headers_missing", [])
    if "HSTS (forces HTTPS)" in missing:
        risks.append("missing_hsts")
    if "CSP (mitigates XSS/injection)" in missing:
        risks.append("missing_csp")
    if "clickjacking protection" in missing:
        risks.append("missing_x_frame_options")
    if http.get("server"):
        risks.append("server_banner_disclosed")
    if http.get("forms"):
        risks.append("forms_present_review_for_authn_and_csrf")
    return risks
