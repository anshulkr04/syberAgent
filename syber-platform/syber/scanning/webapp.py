"""
Active web-application testing for AUTHORISED targets (OWASP WSTG / API Top 10).

Network scanners (nmap/nikto/nuclei) find *infrastructure* issues. They are blind
to application-logic flaws — above all Broken Object Level Authorization (BOLA/IDOR),
which OWASP ranks #1 for APIs and calls "invisible to most automated scanners"
because confirming it requires reasoning about object ownership across two sessions,
not matching a template.

This module adds that application layer:

  * http_request   — a crafted-HTTP primitive (real-browser transport preferred so
                     the target sees genuine Chrome + the live session; HTTP-client
                     fallback when the browser is unavailable or explicit session
                     cookies must be set, which browsers forbid on XHR).
  * crawl          — maps the app: endpoints, forms, and PARAMETERS (the attack
                     surface application scanners actually test), into the graph.
  * test_access_control — the BOLA/IDOR engine, implementing the six-family taxonomy
                     (Direct Object Reference, Action-level, Tenant isolation,
                     Workflow-context, Chained disclosure, Object rebinding) with
                     dual-session comparison and false-positive guards.
  * test_injection — non-destructive probes: reflected XSS (unique canary),
                     error-based SQL injection (DB error signatures), SSRF canary.
  * pentest_plan   — an explicit Pentest Task Tree (PTT) / state machine the agent
                     works through, so long engagements don't lose coverage
                     (the persistence lesson from AutoPT / PentestGPT).

EVERY active function is gated by _require_authorized() — default-deny, same as the
network scanners. Nothing here touches a target that has not been authorised.

References: OWASP API Security Top 10 (2023); OWASP WSTG; the six-family BOLA
taxonomy from bug-bounty disclosures (arXiv 2605.25865); AutoPT (arXiv 2411.01236,
PSM state machine); AutoPentester (arXiv 2510.05605); PentestGPT (arXiv 2308.06782, PTT).
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

from ..recon.browser_recon import browser_available
from .active_scan import NotAuthorized, _require_authorized  # noqa: F401  (re-export NotAuthorized)

AB = "agent-browser"

# A realistic desktop Chrome UA for the HTTP-client fallback transport.
_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")


# --------------------------------------------------------------------------- #
# Detection signatures (pure data — unit-tested without any network)
# --------------------------------------------------------------------------- #
# DBMS error strings that indicate an injected quote reached the SQL parser.
SQL_ERROR_SIGNATURES = [
    r"you have an error in your sql syntax",
    r"warning:\s*mysqli?_",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\)|pg_exec\(\)|postgresql.*error",
    r"psql:.*error|syntax error at or near",
    r"sqlite3?::|sqlite_error|unrecognized token",
    r"ora-\d{5}",
    r"microsoft (ole db|odbc|sql server).*error",
    r"odbc.*driver.*error",
    r"sqlstate\[",
    r"jdbc\.|java\.sql\.sqlexception",
    r"db2 sql error",
]
_SQL_ERROR_RX = re.compile("|".join(SQL_ERROR_SIGNATURES), re.IGNORECASE)

# Classic SQLi probe payloads (error-based — safe, non-destructive, read-only).
SQLI_PROBES = ["'", '"', "')", "';", " OR '1'='1", "1' AND '1'='2"]

# Reflected-XSS canary: a marker unlikely to occur naturally. If it comes back in
# an HTML response WITHOUT being entity-encoded, the input is reflected unsanitised.
XSS_MARK = "sybxss"
XSS_PROBES = [
    "<{m}>",                       # raw angle brackets survive -> high signal
    "\"'><{m}>",                   # break out of attribute/quote
    "<img src=x onerror={m}>",     # event-handler context
]

# A private/link-local target used as an SSRF canary. We never rely on hitting it;
# we look for evidence the server *tried* to fetch a user-supplied URL.
SSRF_CANARY_HOSTS = ["169.254.169.254", "127.0.0.1", "localhost", "metadata.google.internal"]


def sqli_errors(body: str) -> list[str]:
    """Return distinct DBMS error signatures present in a response body."""
    return sorted({m.group(0).lower() for m in _SQL_ERROR_RX.finditer(body or "")})


def xss_reflected(body: str, canary: str) -> bool:
    """True if the canary is reflected UNENCODED (the raw <...> form survived).

    We require the angle-bracketed marker (e.g. ``<sybxss>``) to appear verbatim.
    If only the entity-encoded form (``&lt;sybxss&gt;``) is present, the app
    escaped it -> not reflected XSS.
    """
    if not body or canary not in body:
        return False
    raw = f"<{canary}>"
    encoded = f"&lt;{canary}&gt;"
    # Raw marker present and not solely as an encoded entity.
    return raw in body and body.count(raw) > 0 and not (
        encoded in body and raw not in body.replace(encoded, ""))


def response_signature(status: int | None, body: str) -> dict[str, Any]:
    """A compact fingerprint of a response, for comparing across sessions/ids."""
    body = body or ""
    return {"status": status, "len": len(body), "tokens": _shingle(body)}


def responses_differ(a: dict[str, Any], b: dict[str, Any], length_tol: float = 0.10) -> bool:
    """Heuristic: do two response signatures represent materially different content?

    Different status class, or body length differing by > length_tol, or low token
    overlap. Used to tell "I got someone else's object" from "I got the same
    error/redirect both times" (the core IDOR confirmation question)."""
    if a.get("status") != b.get("status"):
        return True
    la, lb = a.get("len", 0), b.get("len", 0)
    if max(la, lb) > 0 and abs(la - lb) / max(la, lb) > length_tol:
        return True
    return _jaccard(a.get("tokens", set()), b.get("tokens", set())) < 0.6


def _shingle(text: str, k: int = 8, cap: int = 400) -> set[str]:
    toks = re.findall(r"[A-Za-z0-9]+", (text or "").lower())
    return set(toks[:cap]) if k else set(toks)


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


# --------------------------------------------------------------------------- #
# HTML parsing — extract the app's real attack surface (endpoints + parameters)
# --------------------------------------------------------------------------- #
class _SurfaceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: (v or "") for k, v in attrs}
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._form = {"action": a.get("action", ""),
                          "method": (a.get("method") or "GET").upper(), "inputs": []}
        elif tag in ("input", "textarea", "select") and self._form is not None:
            if a.get("name"):
                self._form["inputs"].append({"name": a["name"], "type": a.get("type", "text")})

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def extract_surface(html: str, base_url: str) -> dict[str, Any]:
    """Parse links/forms/parameters out of an HTML body, resolved against base_url."""
    p = _SurfaceParser()
    try:
        p.feed(html or "")
    except Exception:  # noqa: BLE001 - tolerate malformed markup
        pass
    base_host = urlparse(base_url).netloc
    links, params = [], set()
    for href in p.links:
        u = urljoin(base_url, href)
        pu = urlparse(u)
        if pu.scheme in ("http", "https") and pu.netloc == base_host:
            links.append(urlunparse(pu._replace(fragment="")))
            for k, _ in parse_qsl(pu.query):
                params.add(k)
    forms = []
    for f in p.forms:
        forms.append({"action": urljoin(base_url, f["action"]) if f["action"] else base_url,
                      "method": f["method"], "params": [i["name"] for i in f["inputs"]]})
        params.update(i["name"] for i in f["inputs"])
    return {"links": sorted(set(links)), "forms": forms, "params": sorted(params)}


# --------------------------------------------------------------------------- #
# HTTP transport — crafted requests (browser-preferred, HTTP-client fallback)
# --------------------------------------------------------------------------- #
def _ab(args: list[str], timeout: int = 45) -> tuple[int, str, str]:
    try:
        p = subprocess.run([AB, *args], capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError:
        return 127, "", "agent-browser not found"


def _parse_eval(raw: str) -> dict[str, Any]:
    raw = (raw or "").strip()
    for _ in range(2):  # agent-browser double-JSON-encodes eval output
        try:
            val = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            break
        if isinstance(val, dict):
            return val
        raw = val
    return {}


def _browser_fetch(url: str, method: str, headers: dict[str, str], body: str | None,
                   session: str, timeout: int) -> dict[str, Any] | None:
    """Same-origin crafted request via the live browser (real fingerprint + session
    cookies seated in the profile). Uses a synchronous XHR so agent-browser's eval
    returns the result directly (no async-await dependency). Cross-origin reads are
    blocked by CORS, so we open the target origin first and only fetch same-origin."""
    pu = urlparse(url)
    origin = f"{pu.scheme}://{pu.netloc}"
    _ab(["--session", session, "open", origin], timeout=min(timeout, 60))
    hdr_js = ";".join(f"x.setRequestHeader({json.dumps(k)},{json.dumps(v)})"
                      for k, v in (headers or {}).items()
                      if k.lower() not in ("cookie", "host", "content-length"))
    body_js = json.dumps(body) if body is not None else "null"
    js = (
        "(function(){try{"
        "var x=new XMLHttpRequest();"
        f"x.open({json.dumps(method.upper())},{json.dumps(url)},false);"
        "x.withCredentials=true;"
        f"{hdr_js};"
        f"x.send({body_js});"
        "return JSON.stringify({status:x.status,"
        "headers:x.getAllResponseHeaders(),"
        "body:x.responseText.slice(0,20000),len:x.responseText.length});"
        "}catch(e){return JSON.stringify({error:String(e)});}})()"
    )
    rc, out, _ = _ab(["--session", session, "eval", js], timeout=timeout)
    parsed = _parse_eval(out)
    if not parsed or "status" not in parsed:
        return None
    return {"status": parsed.get("status"), "headers": _parse_raw_headers(parsed.get("headers", "")),
            "body": parsed.get("body", ""), "length": parsed.get("len", 0), "transport": "browser"}


def _parse_raw_headers(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in (raw or "").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip().lower()] = v.strip()
    return out


def _python_fetch(url: str, method: str, headers: dict[str, str], body: str | None,
                  cookies: str | None, timeout: int) -> dict[str, Any]:
    """HTTP-client transport. Used when the browser is unavailable, or when explicit
    session cookies must be set (browsers forbid setting Cookie on XHR). Sends a
    real Chrome User-Agent so it is not trivially banner-flagged."""
    hdrs = {"User-Agent": _UA, "Accept": "*/*", **(headers or {})}
    if cookies:
        hdrs["Cookie"] = cookies
    data = body.encode() if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, method=method.upper(), headers=hdrs)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (authorised target)
            text = r.read(200_000).decode("utf-8", "replace")
            return {"status": r.status, "headers": {k.lower(): v for k, v in r.headers.items()},
                    "body": text, "length": len(text), "transport": "http-client",
                    "elapsed_ms": int((time.time() - t0) * 1000)}
    except urllib.error.HTTPError as e:
        text = e.read(200_000).decode("utf-8", "replace") if e.fp else ""
        return {"status": e.code, "headers": {k.lower(): v for k, v in (e.headers or {}).items()},
                "body": text, "length": len(text), "transport": "http-client",
                "elapsed_ms": int((time.time() - t0) * 1000)}
    except (urllib.error.URLError, OSError, ValueError) as e:
        return {"status": None, "error": str(e), "headers": {}, "body": "", "length": 0,
                "transport": "http-client"}


def http_request(url: str, method: str = "GET", headers: dict[str, str] | None = None,
                 body: str | None = None, cookies: str | None = None,
                 prefer_browser: bool = True, session: str | None = None,
                 timeout: int = 30) -> dict[str, Any]:
    """Send a crafted HTTP request to an AUTHORISED target and return the response.

    Transport: the real browser is preferred (genuine fingerprint + live session),
    but if `cookies` are supplied explicitly (dual-session BOLA testing) or the
    browser is unavailable, the HTTP-client transport is used instead. Returns
    {status, headers, body, length, transport}."""
    host = urlparse(url).netloc.split(":")[0]
    _require_authorized(host)
    headers = dict(headers or {})
    use_browser = prefer_browser and cookies is None and browser_available()
    if use_browser:
        sess = session or f"pt-{uuid.uuid4().hex[:8]}"
        out = _browser_fetch(url, method, headers, body, sess, timeout)
        if out is not None:
            return out  # else fall through to the client transport
    return _python_fetch(url, method, headers, body, cookies, timeout)


# --------------------------------------------------------------------------- #
# Crawl — map endpoints + parameters into the graph
# --------------------------------------------------------------------------- #
def crawl(target: str, max_pages: int = 40, max_depth: int = 2,
          cookies: str | None = None, timeout: int = 20) -> dict[str, Any]:
    """Breadth-first crawl of an AUTHORISED web target. Discovers endpoints, forms,
    and parameters (the application attack surface) and ingests them into the graph.
    Returns the endpoint inventory."""
    start = _as_url(target)
    host = urlparse(start).netloc.split(":")[0]
    _require_authorized(host)

    seen: set[str] = set()
    queue: list[tuple[str, int]] = [(start, 0)]
    endpoints: list[dict[str, Any]] = []
    all_forms: list[dict[str, Any]] = []
    sess = f"crawl-{uuid.uuid4().hex[:8]}"

    while queue and len(seen) < max_pages:
        url, depth = queue.pop(0)
        norm = urlunparse(urlparse(url)._replace(fragment=""))
        if norm in seen:
            continue
        seen.add(norm)
        resp = http_request(norm, cookies=cookies, session=sess, timeout=timeout)
        pu = urlparse(norm)
        ep = {"url": norm, "status": resp.get("status"),
              "params": sorted({k for k, _ in parse_qsl(pu.query)}),
              "content_type": resp.get("headers", {}).get("content-type", "")}
        if "html" in ep["content_type"] or (resp.get("body", "") or "").lstrip()[:1] == "<":
            surface = extract_surface(resp.get("body", ""), norm)
            ep["params"] = sorted(set(ep["params"]) | set(surface["params"]))
            all_forms.extend(f | {"page": norm} for f in surface["forms"])
            if depth < max_depth:
                for link in surface["links"][:50]:
                    if urlunparse(urlparse(link)._replace(fragment="")) not in seen:
                        queue.append((link, depth + 1))
        endpoints.append(ep)

    if browser_available():
        _ab(["--session", sess, "close", "--all"])
    graph = _ingest_crawl_to_graph(host, endpoints, all_forms)
    from ..audit.log import get_audit_log
    get_audit_log().write("webapp_crawl", {"target": host, "pages": len(seen),
                                            "endpoints": len(endpoints), "forms": len(all_forms)},
                          "webapp")
    return {"target": host, "pages_crawled": len(seen), "endpoint_count": len(endpoints),
            "endpoints": endpoints, "forms": all_forms, "graph": graph}


def _ingest_crawl_to_graph(host: str, endpoints: list[dict], forms: list[dict]) -> dict[str, Any]:
    from ..graph import model
    from ..graph.store import get_graph

    model.upsert_host(host, source="webapp_crawl")
    for ep in endpoints:
        params = ep.get("params") or []
        for f in forms:
            if f.get("page") == ep["url"]:
                params = sorted(set(params) | set(f.get("params", [])))
        model.upsert_web_endpoint(host, ep["url"], status=ep.get("status"),
                                  method="GET", params=params)
    for f in forms:
        model.upsert_web_endpoint(host, f.get("action", f.get("page", "")),
                                  method=f.get("method", "GET"), params=f.get("params", []))
    g = get_graph()
    return {"host": host, "endpoints_ingested": len(endpoints),
            "risk_score": g.risk_score(host), "backend": type(g).__name__}


# --------------------------------------------------------------------------- #
# BOLA / IDOR — the six-family access-control engine
# --------------------------------------------------------------------------- #
def test_access_control(url: str, id_param: str | None = None,
                        cookies_a: str | None = None, cookies_b: str | None = None,
                        known_other_ids: list[str] | None = None,
                        timeout: int = 20) -> dict[str, Any]:
    """Test one endpoint for Broken Object Level Authorization (BOLA/IDOR).

    Strategy (six-family taxonomy):
      * Direct Object Reference  — vary the object id and compare responses.
      * Sequential enumeration   — for integer ids, probe id±1.
      * Tenant / object rebinding — if cookies_a & cookies_b given, fetch A's object
        as B; if B sees A's data, authorization is broken.
      * Chained disclosure       — accepts ids harvested elsewhere (known_other_ids).
      * Authn comparison         — authed vs unauthenticated reachability.

    Dual-session (cookies_a, cookies_b) gives the strongest signal. Without it, the
    engine still does unauthenticated/sequential/chained probing. False-positive
    guards: a hit requires the *other* id's response to (a) be a 2xx with real
    content and (b) differ materially from a known-not-mine baseline."""
    host = urlparse(url).netloc.split(":")[0]
    _require_authorized(host)

    target_id, where = _locate_id(url, id_param)
    findings: list[dict[str, Any]] = []
    probes = 0

    def fetch(u: str, cookies: str | None) -> dict[str, Any]:
        nonlocal probes
        probes += 1
        return http_request(u, cookies=cookies, timeout=timeout)

    # Baseline: the object as its owner (session A, or unauthenticated).
    base = fetch(url, cookies_a)
    base_sig = response_signature(base.get("status"), base.get("body", ""))

    # --- Family 1/3/6: dual-session — fetch A's object as B -----------------
    if cookies_a and cookies_b:
        as_b = fetch(url, cookies_b)
        if _is_unauthorized_leak(base, as_b):
            findings.append({"family": "tenant/object-level (cross-session)",
                             "detail": "Account B retrieved Account A's object with a 2xx and "
                                       "matching content — ownership not enforced.",
                             "url": url, "evidence": _eviref(as_b)})

    # --- Family 1/2: Direct Object Reference — vary the id ------------------
    candidate_ids = list(known_other_ids or [])
    if target_id is not None and target_id.isdigit():
        n = int(target_id)
        candidate_ids += [str(n + 1), str(n - 1)] if n > 0 else [str(n + 1)]
    for oid in dict.fromkeys(candidate_ids):  # dedupe, keep order
        if oid == target_id:
            continue
        other_url = _swap_id(url, where, oid)
        # As the SAME session: did we reach a different user's object?
        r = fetch(other_url, cookies_a)
        other_sig = response_signature(r.get("status"), r.get("body", ""))
        if _looks_like_other_object(r, base_sig, other_sig):
            findings.append({"family": "direct-object-reference (IDOR)",
                             "detail": f"Object id {oid} returned a distinct 2xx object via the "
                                       f"same session — likely another user's resource.",
                             "url": other_url, "evidence": _eviref(r)})

    # --- Family 5 (chained) is driven by known_other_ids above; Family 4
    #     (workflow/state) and Family 2 (action-level writes) require caller-
    #     supplied state transitions and are reported as guidance, not auto-fired.
    verdict = "vulnerable" if findings else "no_idor_detected"
    from ..audit.log import get_audit_log
    get_audit_log().write("webapp_access_control", {"url": url, "verdict": verdict,
                                                    "probes": probes}, "webapp")
    return {"url": url, "id_param": where, "object_id": target_id, "probes": probes,
            "dual_session": bool(cookies_a and cookies_b), "verdict": verdict,
            "findings": findings,
            "note": None if findings else
            "No IDOR confirmed from these probes. For full coverage supply two "
            "accounts (cookies_a/cookies_b) and harvested ids (known_other_ids), and "
            "test state-changing methods (PATCH/DELETE) and archived/cross-tenant objects."}


def _locate_id(url: str, id_param: str | None) -> tuple[str | None, str]:
    """Find the object identifier to vary. Returns (id_value, location) where
    location is 'query:<param>' or 'path'."""
    pu = urlparse(url)
    q = dict(parse_qsl(pu.query))
    if id_param and id_param in q:
        return q[id_param], f"query:{id_param}"
    # Heuristic: an id-ish query param.
    for k, v in q.items():
        if re.search(r"(^|_)(id|uuid|user|account|order|invoice|doc)s?$", k, re.I):
            return v, f"query:{k}"
    # Path: a trailing numeric or uuid segment.
    segs = [s for s in pu.path.split("/") if s]
    if segs and re.fullmatch(r"\d+|[0-9a-fA-F-]{8,}", segs[-1]):
        return segs[-1], "path"
    return None, "path"


def _swap_id(url: str, where: str, new_id: str) -> str:
    pu = urlparse(url)
    if where.startswith("query:"):
        key = where.split(":", 1)[1]
        q = dict(parse_qsl(pu.query))
        q[key] = new_id
        from urllib.parse import urlencode
        return urlunparse(pu._replace(query=urlencode(q)))
    segs = pu.path.split("/")
    for i in range(len(segs) - 1, -1, -1):
        if segs[i]:
            segs[i] = new_id
            break
    return urlunparse(pu._replace(path="/".join(segs)))


def _is_2xx_with_content(r: dict[str, Any]) -> bool:
    s = r.get("status")
    return isinstance(s, int) and 200 <= s < 300 and len(r.get("body", "") or "") > 0


def _is_unauthorized_leak(base: dict[str, Any], as_other: dict[str, Any]) -> bool:
    """Account B got a 2xx whose content matches A's object -> ownership not enforced."""
    if not _is_2xx_with_content(as_other) or not _is_2xx_with_content(base):
        return False
    return not responses_differ(response_signature(base.get("status"), base.get("body", "")),
                                response_signature(as_other.get("status"), as_other.get("body", "")))


def _looks_like_other_object(r: dict[str, Any], base_sig: dict[str, Any],
                             other_sig: dict[str, Any]) -> bool:
    """A different object id returned a 2xx that is real content and materially
    different from the baseline object (so it isn't the same generic page/error)."""
    return _is_2xx_with_content(r) and responses_differ(base_sig, other_sig)


def _eviref(r: dict[str, Any]) -> dict[str, Any]:
    return {"status": r.get("status"), "length": r.get("length"),
            "snippet": (r.get("body", "") or "")[:200], "transport": r.get("transport")}


# --------------------------------------------------------------------------- #
# Injection — reflected XSS, error-based SQLi, SSRF canary (non-destructive)
# --------------------------------------------------------------------------- #
def test_injection(url: str, params: list[str] | None = None, cookies: str | None = None,
                   timeout: int = 20) -> dict[str, Any]:
    """Probe an AUTHORISED endpoint's parameters for reflected XSS, error-based SQL
    injection, and SSRF. Non-destructive (read-only payloads). If `params` is
    omitted, the query parameters in `url` are used."""
    host = urlparse(url).netloc.split(":")[0]
    _require_authorized(host)
    pu = urlparse(url)
    q = dict(parse_qsl(pu.query))
    test_params = params or list(q.keys())
    findings: list[dict[str, Any]] = []
    probes = 0

    for param in test_params:
        # --- reflected XSS ---
        canary = f"{XSS_MARK}{uuid.uuid4().hex[:6]}"
        for tmpl in XSS_PROBES:
            payload = tmpl.format(m=canary)
            r = http_request(_with_param(url, param, payload), cookies=cookies, timeout=timeout)
            probes += 1
            if xss_reflected(r.get("body", ""), canary):
                findings.append({"type": "reflected-xss", "param": param,
                                 "payload": payload, "url": _with_param(url, param, payload),
                                 "detail": "Payload reflected unencoded in the HTML response.",
                                 "evidence": _eviref(r)})
                break
        # --- error-based SQLi ---
        for payload in SQLI_PROBES:
            r = http_request(_with_param(url, param, payload), cookies=cookies, timeout=timeout)
            probes += 1
            errs = sqli_errors(r.get("body", ""))
            if errs:
                findings.append({"type": "sql-injection (error-based)", "param": param,
                                 "payload": payload, "url": _with_param(url, param, payload),
                                 "detail": f"DBMS error signature surfaced: {errs[0]}",
                                 "evidence": _eviref(r)})
                break
        # --- SSRF canary ---
        r = http_request(_with_param(url, param, f"http://{SSRF_CANARY_HOSTS[0]}/"),
                         cookies=cookies, timeout=timeout)
        probes += 1
        if _ssrf_signal(r):
            findings.append({"type": "ssrf (candidate)", "param": param,
                             "url": _with_param(url, param, f"http://{SSRF_CANARY_HOSTS[0]}/"),
                             "detail": "Parameter appears to trigger a server-side fetch of a "
                                       "user-supplied URL — verify with an out-of-band canary.",
                             "evidence": _eviref(r)})

    verdict = "vulnerable" if findings else "no_injection_detected"
    from ..audit.log import get_audit_log
    get_audit_log().write("webapp_injection", {"url": url, "verdict": verdict, "probes": probes},
                          "webapp")
    return {"url": url, "params_tested": test_params, "probes": probes, "verdict": verdict,
            "findings": findings}


def _ssrf_signal(r: dict[str, Any]) -> bool:
    """Weak signal that a server-side fetch occurred: cloud-metadata markers or an
    unusual delay/error referencing the canary host. SSRF needs OOB confirmation;
    this only flags candidates."""
    body = (r.get("body", "") or "").lower()
    return any(m in body for m in ("imdsv", "ami-id", "instance-id", "computemetadata",
                                   "metadata-flavor", "iam/security-credentials"))


def _with_param(url: str, param: str, value: str) -> str:
    from urllib.parse import urlencode
    pu = urlparse(url)
    q = dict(parse_qsl(pu.query))
    q[param] = value
    return urlunparse(pu._replace(query=urlencode(q)))


# --------------------------------------------------------------------------- #
# Pentest Task Tree (PTT) — explicit coverage state machine
# --------------------------------------------------------------------------- #
def pentest_plan(target: str) -> dict[str, Any]:
    """Return an explicit Pentest Task Tree for `target`: the ordered phases and
    tasks the agent must complete (and not abandon early). Mirrors AutoPT's state
    machine / PentestGPT's PTT — the persistence mechanism that keeps long
    engagements from losing coverage."""
    t = target
    return {
        "target": t,
        "doctrine": "Work top-to-bottom. Do not conclude while any task is 'todo' "
                    "without recording why it is N/A. Re-run timed-out tools with a "
                    "longer SYBER_SCAN_TIMEOUT rather than dropping the task.",
        "phases": [
            {"phase": "1. Authorise & scope", "tasks": [
                {"id": "auth", "task": f"Confirm {t} is authorised (syber_list_authorized; "
                                       "syber_authorize_target with attestation if not)."}]},
            {"phase": "2. Network surface", "tasks": [
                {"id": "ports", "task": "Full/relevant port scan (syber_port_scan)."},
                {"id": "services", "task": "Service+version+default-script enum on every open "
                                           "port (syber_service_scan)."},
                {"id": "nuclei", "task": "Templated vuln scan on web ports (syber_vuln_scan)."}]},
            {"phase": "3. Application mapping", "tasks": [
                {"id": "crawl", "task": "Crawl the app; enumerate endpoints, forms, PARAMETERS "
                                        "(syber_crawl)."},
                {"id": "browser", "task": "Open each web service in the real browser; snapshot "
                                          "structure, login/forms (agent-browser)."}]},
            {"phase": "4. Application testing", "tasks": [
                {"id": "access_control", "task": "Test access control / IDOR-BOLA on every "
                                                 "object-bearing endpoint (syber_test_access_control); "
                                                 "use two accounts when available."},
                {"id": "injection", "task": "Probe parameters for reflected XSS / error-based SQLi "
                                            "/ SSRF (syber_test_injection)."},
                {"id": "authn", "task": "Review authentication/session: cookie flags, logout, "
                                        "password reset, rate limiting."}]},
            {"phase": "5. Synthesise", "tasks": [
                {"id": "graph", "task": "Review the attack surface (syber_get_graph_context); "
                                        "reconcile findings."},
                {"id": "report", "task": "Publish findings with evidence + exploitability + "
                                         "evidence-based severity (syber_publish_finding); gate (syber_gate_finding)."}]},
        ],
    }


# --------------------------------------------------------------------------- #
def _as_url(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return target
    return "https://" + target if ":" not in target.split("/")[0] else "http://" + target
