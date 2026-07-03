"""
Syber Tools — in-process MCP server (spec §3.4) for the Claude Code plugin.

This is the integration seam between Claude Code (the agent harness, spec §3.1)
and the Syber platform. Every Syber component is exposed here as an MCP tool:

    graph (§6)      -> syber_get_graph_context
    data lake (§5)  -> syber_query_data_lake
    analytics (§7)  -> syber_score_behaviour
    findings (§3.4) -> syber_publish_finding, syber_request_hitl
    CES gate (§12)  -> syber_gate_finding
    response (§13)  -> syber_run_response_playbook
    audit/memory    -> syber_verify_integrity
    ops             -> syber_start_investigation, syber_backend_status,
                       syber_run_full_investigation

Each granular tool runs the same scope guard + StruQ injection filter + audit
log as the standalone platform (it reuses the exact tool handlers). Claude Code
drives the loop and dispatches the Syber subagents (agents/*.md), which call
these tools — Claude Code IS the orchestration harness.

Run (stdio): python -m server.syber_mcp   (wired via the plugin .mcp.json)
"""
from __future__ import annotations

import json
import os
from typing import Any

from mcp.server.fastmcp import FastMCP

# --- Syber platform imports (installed editable; importable from any cwd) ---
from syber.agents.orchestrator import run_investigation
from syber.analytics.service import score_entity
from syber.audit.log import get_audit_log
from syber.config import LLM
from syber.data_lake import get_data_lake  # noqa: F401  (ensures singleton init)
from syber.graph.store import get_graph
from syber.harness.memory_integrity import get_memory_store
from syber.llm.exceptions import HumanApprovalRequired
from syber.recon.browser_recon import browser_available, ingest_recon_to_graph
from syber.recon.browser_recon import recon_site as browser_recon_site
from syber.response.executor import execute_playbook, mock_integration
from syber.response.playbooks import CRED_REVOKE_PLAYBOOK, matches_trigger
from syber.integrations import IntegrationError
from syber.integrations import agentmail as _agentmail
from syber.integrations import agentphone as _agentphone
from syber.integrations import identity as _identity
from syber.scanning import active_scan, webapp
from syber.scanning.active_scan import NotAuthorized, _require_authorized
from syber.scanning.authorization import get_auth_store
from syber.waf import build_waf_integration
from syber.waf.integration import WAFBlockError
from syber.scoring.gate import gate_candidate
from syber.seed_data import ACTOR, build_scenario
from syber.tools.behaviour import score_behaviour as _score_behaviour
from syber.tools.data_lake_tool import query_data_lake as _query_data_lake
from syber.tools.findings import (get_findings_sink, publish_finding as _publish_finding,
                                  request_hitl as _request_hitl)
from syber.tools.graph_context import get_graph_context as _get_graph_context
from syber.tools.scope_guard import InvestigationScope, set_current_scope

mcp = FastMCP("syber-tools")

# Process-lifetime investigation state (one stdio server == one session).
_STATE: dict[str, Any] = {"scope": None, "trigger": None}


def _ensure_scope() -> InvestigationScope | None:
    """Re-activate the investigation scope on the current call context. FastMCP
    runs each tool call in a fresh async context, so the contextvar set in
    syber_start_investigation does not carry over — we re-set it from _STATE
    (which persists for the lifetime of this stdio server process)."""
    scope = _STATE.get("scope")
    if scope is not None:
        set_current_scope(scope)
    return scope


# --------------------------------------------------------------------------- #
# Ops / lifecycle
# --------------------------------------------------------------------------- #
@mcp.tool()
def syber_start_investigation(
    seed_demo: bool = True,
    entities: list[str] | None = None,
    time_start_utc: str = "",
    time_end_utc: str = "",
    investigation_id: str = "",
) -> dict[str, Any]:
    """Open a scoped investigation. With seed_demo=True, loads the SVC-API-07
    service-account compromise scenario (graph + data lake + behavioural ensemble)
    and returns its behavioural deviation score. Otherwise scopes to the given
    entities/time window. MUST be called before the other syber_* tools."""
    if seed_demo:
        trigger, scope = build_scenario()
        behaviour = score_entity(ACTOR)
        trigger["anomaly_score"] = behaviour["score"]
    else:
        scope = InvestigationScope(
            investigation_id=investigation_id or "INV-ADHOC-001",
            allowed_entities=set(entities or []),
            time_start_utc=time_start_utc,
            time_end_utc=time_end_utc,
        )
        trigger = {"event_type": "anomaly_detected", "entity_id": (entities or [""])[0],
                   "time_start_utc": time_start_utc, "time_end_utc": time_end_utc}
        behaviour = {"score": None}
    set_current_scope(scope)
    _STATE["scope"] = scope
    _STATE["trigger"] = trigger
    return {
        "investigation_id": scope.investigation_id,
        "authorised_entities": sorted(scope.allowed_entities),
        "time_window": [scope.time_start_utc, scope.time_end_utc],
        "behavioural_score": behaviour.get("score"),
        "behavioural_detail": behaviour if seed_demo else None,
        "backends": _backends(),
        "next": "Dispatch the syber-context-graph and syber-behavioural-analytics "
                "subagents, then the syber-threat-investigator subagent.",
    }


@mcp.tool()
def syber_recon_site(site: str) -> dict[str, Any]:
    """Investigate a real website/domain using a REAL BROWSER (agent-browser +
    Chrome) — never curl. Navigates the site with a genuine browser fingerprint
    (so it is not flagged as a bot), and returns DNS, HTTP status + security
    headers (captured via HAR), TLS certificate, server/technology fingerprint
    from the rendered DOM, form/input/link counts, a screenshot path, and risk
    indicators. Ingests the host/web-endpoint/technologies/certificate into the
    attack-surface graph. Then call syber_publish_finding + syber_gate_finding."""
    report = browser_recon_site(site)
    host = report.get("host", site)
    addrs = report.get("dns", {}).get("addresses", []) if isinstance(report.get("dns"), dict) else []

    scope = InvestigationScope(
        investigation_id=f"RECON-{host}", allowed_entities={host, *addrs},
        time_start_utc="", time_end_utc="",
    )
    set_current_scope(scope)
    _STATE["scope"] = scope
    _STATE["trigger"] = {"event_type": "site_recon", "entity_id": host, "report": report}

    graph_ingest = ingest_recon_to_graph(report)
    get_audit_log().write("site_recon", {"host": host, "method": "browser",
                                         "risk_indicators": report.get("risk_indicators", [])})
    return {
        "investigation_id": scope.investigation_id,
        "report": report,
        "graph": graph_ingest,
        "browser_used": browser_available(),
        "suggested_evidence_refs": [f"recon:{k}" for k in ("dns", "http", "tls") if report.get(k)],
        "next": "Optionally drive agent-browser yourself to inspect the page further (snapshot, "
                "click, screenshot). Then call syber_publish_finding (attack_chain steps with "
                "evidence_refs like 'recon:http','recon:tls'; mitre e.g. T1592 Gather Victim Host "
                "Information, T1595 Active Scanning) and syber_gate_finding.",
    }


# --------------------------------------------------------------------------- #
# Active scanning (AUTHORISED targets only — default deny)
# --------------------------------------------------------------------------- #
def _scan(fn, *args, **kwargs) -> dict[str, Any]:
    try:
        out = fn(*args, **kwargs)
        _record_call(fn, args, kwargs, out)
        return out
    except NotAuthorized as e:
        return {"error": "not_authorized", "message": str(e),
                "remedy": "Call syber_authorize_target with an attestation that you own / are "
                          "authorised to test this target, then retry."}


def _record_call(fn, args, kwargs, out) -> None:
    """Log every scan/web tool call to the recall ledger so the agent can avoid
    repeating identical calls. Best-effort — never affects the tool result."""
    try:
        from syber.scanning import recall
        ledger_args = {}
        if args:
            ledger_args["target"] = args[0]
        ledger_args.update({k: v for k, v in (kwargs or {}).items() if v not in (None, "")})
        status, summary = "ok", ""
        if isinstance(out, dict):
            status = str(out.get("status") or out.get("verdict") or
                         ("error" if out.get("error") else "ok"))
            for k in ("verdict", "endpoint_count", "findings"):
                if k in out:
                    v = out[k]
                    summary = f"{k}={len(v) if isinstance(v, list) else v}"
                    break
        recall.record(fn.__name__, ledger_args, summary=summary, status=status)
    except Exception:  # noqa: BLE001
        pass


def _integration(fn, *args, **kwargs) -> dict[str, Any]:
    """Run a comms-integration call (AgentMail / AgentPhone). These touch only the
    agent's OWN accounts, never the target, so there is no target-auth gate — but a
    missing API key surfaces as an actionable error, not a crash."""
    try:
        return fn(*args, **kwargs)
    except IntegrationError as e:
        return {"error": "integration", "message": str(e)}


@mcp.tool()
def syber_authorize_target(target: str, attestation: str, authorized_by: str = "operator") -> dict[str, Any]:
    """Authorise ACTIVE scanning of a target you control. Required before any
    scan tool will run against it (default-deny). `target` is a host, IP, or CIDR;
    `attestation` must affirm you own or are authorised to test it (>= 8 chars)."""
    try:
        auth = get_auth_store().authorize(target, attestation, authorized_by)
        return {"status": "authorized", "target": auth.target, "kind": auth.kind,
                "authorized_by": auth.authorized_by, "at": auth.authorized_at_utc}
    except ValueError as e:
        return {"error": "invalid_attestation", "message": str(e)}


@mcp.tool()
def syber_list_authorized() -> dict[str, Any]:
    """List targets currently authorised for active scanning."""
    return {"authorized": [{"target": a.target, "kind": a.kind, "by": a.authorized_by,
                            "at": a.authorized_at_utc} for a in get_auth_store().list()]}


@mcp.tool()
def syber_recall_tool_calls(limit: int = 30) -> dict[str, Any]:
    """List the scan/web tool calls already made this engagement (tool + key args +
    outcome + repeat count), so you DON'T re-run identical calls. Check this before
    re-scanning or re-crawling — repeating an identical call wastes the loop."""
    from syber.scanning import recall
    return {"calls": [r.to_dict() for r in recall.recent(limit)],
            "summary": recall.summarize(limit)}


def _enumerate_subdomains(domain: str, deep: bool = True) -> dict[str, Any]:
    from syber.scanning.active_scan import _require_authorized
    host = domain.split("//")[-1].split("/")[0].split(":")[0]
    _require_authorized(host)                       # NotAuthorized -> handled by _scan
    from syber.scanning import subdomains as sd
    res = sd.enumerate_subdomains(domain, deep=deep)
    res["ingested"] = sd.ingest_subdomains(res)
    res["guidance"] = (
        "Surface mapped. PRIORITISE the non-prod hosts (uat/cug/staging/dev) — that is "
        "where prod's secrets leak. Each live host is now in the graph and authorised "
        "(subdomain of the authorised apex); scan/crawl each, pull JS bundles for API "
        "bases + secrets, hunt exposed Swagger/OpenAPI, and verify data with "
        "syber_verify_data_exposure. A prod WAF 403 is NOT a result — pivot to non-prod.")
    return res


@mcp.tool()
def syber_enumerate_subdomains(domain: str, deep: bool = True) -> dict[str, Any]:
    """MAP THE WHOLE SURFACE FIRST. Enumerate subdomains of an AUTHORISED domain
    deterministically — Certificate Transparency (crt.sh) + a non-prod-heavy prefix
    wordlist + DNS resolution + a liveness probe — and ingest every live host into the
    attack graph (so the fleet scans/crawls each). Flags non-production hosts
    (uat/cug/staging/dev/qa) separately — that is the soft underbelly where staging
    leaks production's secrets and Swagger. Run this at the START of every engagement;
    authorising the apex authorises its subdomains. Returns {domain, total, nonprod[],
    prod[], subdomains[], ingested}."""
    return _scan(_enumerate_subdomains, domain, deep=deep)


@mcp.tool()
def syber_port_scan(target: str, ports: str = "") -> dict[str, Any]:
    """Active port scan (nmap TCP connect; python fallback). `ports` like '22,80,443'
    or '1-1000'; empty = top 1000. Target must be authorised."""
    return _scan(active_scan.port_scan, target, ports=ports or None)


@mcp.tool()
def syber_service_scan(target: str, ports: str = "") -> dict[str, Any]:
    """Service/version detection + safe default NSE scripts (nmap -sV -sC).
    Target must be authorised."""
    return _scan(active_scan.service_scan, target, ports=ports or None)


@mcp.tool()
def syber_web_scan(target: str) -> dict[str, Any]:
    """Web-server vulnerability scan (nikto). Target must be authorised."""
    return _scan(active_scan.web_scan, target)


@mcp.tool()
def syber_content_discovery(target: str, wordlist: str = "") -> dict[str, Any]:
    """Directory/content discovery (gobuster/ffuf). Target must be authorised."""
    return _scan(active_scan.content_discovery, target, wordlist=wordlist or None)


@mcp.tool()
def syber_vuln_scan(target: str, severity: str = "low,medium,high,critical") -> dict[str, Any]:
    """Templated vulnerability scan (nuclei). Target must be authorised."""
    return _scan(active_scan.vuln_scan, target, severity=severity)


@mcp.tool()
def syber_full_scan(target: str, do_web: bool = True) -> dict[str, Any]:
    """Orchestrated active scan: ports -> services -> (if web) content discovery +
    nuclei, ingesting hosts/ports/services/vulns into the knowledge graph (Neo4j).
    Returns a summary. Target must be authorised."""
    out = _scan(active_scan.full_scan, target, do_web=do_web)
    if isinstance(out, dict) and "summary" in out:
        scope = InvestigationScope(investigation_id=f"SCAN-{target}", allowed_entities={target})
        set_current_scope(scope)
        _STATE["scope"] = scope
        _STATE["trigger"] = {"event_type": "active_scan", "entity_id": target, "scan": out}
    return out


# --------------------------------------------------------------------------- #
# Web-application testing (AUTHORISED targets only — OWASP WSTG / API Top 10)
# --------------------------------------------------------------------------- #
@mcp.tool()
def syber_pentest_plan(target: str) -> dict[str, Any]:
    """Return the Pentest Task Tree (PTT) for a target: the ordered phases/tasks to
    complete for a thorough engagement (auth -> network -> app mapping -> app testing
    -> synthesise). Work through it top-to-bottom; don't conclude with tasks unaddressed.
    No target authorisation needed to view the plan."""
    return webapp.pentest_plan(target)


@mcp.tool()
def syber_crawl(target: str, max_pages: int = 40, max_depth: int = 2, cookies: str = "") -> dict[str, Any]:
    """Crawl an AUTHORISED web target (browser-first) to map its real attack surface:
    endpoints, forms, and PARAMETERS — ingested into the graph. `cookies` (a Cookie
    header string) crawls authenticated areas. This is what application scanners test
    that nmap/nikto/nuclei cannot see."""
    return _scan(webapp.crawl, target, max_pages=max_pages, max_depth=max_depth,
                 cookies=cookies or None)


@mcp.tool()
def syber_test_access_control(url: str, id_param: str = "", cookies_a: str = "",
                              cookies_b: str = "", known_other_ids: list[str] | None = None) -> dict[str, Any]:
    """Test an AUTHORISED endpoint for Broken Object Level Authorization (BOLA/IDOR) —
    OWASP API #1, invisible to template scanners. Varies the object id and compares
    responses; with two accounts (`cookies_a`, `cookies_b` = Cookie header strings) it
    fetches A's object as B to prove ownership isn't enforced. `known_other_ids` are
    ids harvested elsewhere (chained-disclosure testing). Returns confirmed findings
    with evidence."""
    return _scan(webapp.test_access_control, url, id_param=id_param or None,
                 cookies_a=cookies_a or None, cookies_b=cookies_b or None,
                 known_other_ids=known_other_ids or None)


@mcp.tool()
def syber_test_injection(url: str, params: list[str] | None = None, cookies: str = "") -> dict[str, Any]:
    """Probe an AUTHORISED endpoint's parameters for reflected XSS, error-based SQL
    injection, and SSRF (non-destructive, read-only payloads). If `params` is omitted,
    the query parameters in `url` are tested. Returns confirmed findings with the
    payload and response evidence."""
    return _scan(webapp.test_injection, url, params=params or None, cookies=cookies or None)


@mcp.tool()
def syber_http_request(url: str, method: str = "GET", headers: dict[str, str] | None = None,
                       body: str = "", cookies: str = "") -> dict[str, Any]:
    """Send a single crafted HTTP request to an AUTHORISED target and return
    {status, headers, body, length, transport}. Browser-first transport (real
    fingerprint + live session); uses the HTTP client when `cookies` are supplied or
    the browser is unavailable. The low-level primitive for manual web testing."""
    from syber.util.output_hygiene import hygienic_response
    out = _scan(webapp.http_request, url, method=method, headers=headers or None,
                body=body or None, cookies=cookies or None)
    return hygienic_response(out) if isinstance(out, dict) else out


def _verify_data_exposure(url: str, method: str = "GET",
                          headers: dict[str, str] | None = None,
                          cookies: str | None = None) -> dict[str, Any]:
    """Fetch an AUTHORISED endpoint and classify whether it returns REAL sensitive
    data. Raises NotAuthorized (handled by _scan) if the target isn't authorised."""
    from syber.scanning.exfil import scan_sensitive, save_sample, is_confirmed as exfil_is_confirmed
    resp = webapp.http_request(url, method=method, headers=headers, cookies=cookies, timeout=30)
    status = resp.get("status")
    body = resp.get("body", "")
    resp_headers = resp.get("headers", {}) or {}
    ctype = resp_headers.get("content-type", "")
    ev = scan_sensitive(body, ctype)
    # Capture a proof SCREENSHOT only on a CONFIRMED exposure (2xx + real data) — logged
    # in with the same cookies (so it shows the GATED data, not a login page) and only if
    # the rendered page is actually data (capture_screenshot rejects login/denied pages).
    shot = None
    if exfil_is_confirmed(status, ev):
        try:
            from syber.recon.browser_recon import capture_screenshot
            from syber.config import PATHS
            import re as _re, time as _t
            host = _re.sub(r"[^A-Za-z0-9._-]", "_", url.split("://")[-1].split("/")[0]) or "target"
            shot_dir = PATHS.state / "evidence" / host
            shot_path = str(shot_dir / f"{_t.strftime('%Y%m%dT%H%M%S')}-proof.png")
            shot = capture_screenshot(url, shot_path, cookies=cookies, require_data=True)
        except Exception:  # noqa: BLE001
            shot = None
    artefact = save_sample(url, status, body, ev, method=method,
                           request_headers=headers or {}, response_headers=resp_headers,
                           transport=resp.get("transport", ""), screenshot=shot)
    rung = {"REAL_DATA": 4, "STRUCTURED": 3}.get(ev.verdict, 2 if status and 200 <= int(status) < 300 else 0)
    return {
        "url": url, "status": status, "transport": resp.get("transport"),
        "verdict": ev.verdict, "summary": ev.summary(),
        "data_exposed": ev.has_sensitive, "severity": ev.severity,
        "categories": ev.categories, "record_count": ev.record_count,
        "redacted_samples": ev.redacted_samples, "evidence_rung": rung,
        "evidence_artefact": artefact,
        "guidance": (
            "REAL sensitive data confirmed — this is IMPACT (rung 4 / CRITICAL). Publish a "
            "finding citing the redacted samples + evidence_artefact." if ev.has_sensitive else
            "Unauthenticated structured data confirmed — VERIFIED exposure (rung 3 / HIGH)."
            if ev.verdict == "STRUCTURED" else
            "No real data returned — reachable only. Do NOT claim IMPACT/CRITICAL on this "
            "endpoint; try a data-returning route (e.g. GetUserDetails / list endpoints) before "
            "concluding, or treat as at most reachable (rung 0-2)."),
    }


@mcp.tool()
def syber_verify_data_exposure(url: str, method: str = "GET",
                               headers: dict[str, str] | None = None,
                               cookies: str = "") -> dict[str, Any]:
    """Prove (or disprove) that an AUTHORISED endpoint actually exposes REAL sensitive
    data — the IMPACT rung. A 200 / `true` / "structured data present" is NOT impact:
    this tool DOWNLOADS a sample of the response and classifies it for PII (email /
    phone / PAN / Aadhaar / SSN / credit-card / IFSC), secrets/tokens (JWT / AWS / private
    keys / credential fields), and structured records, saving a redacted sample as
    evidence. Use it on every unauthenticated data/API endpoint BEFORE claiming
    CRITICAL — e.g. on a leaked Swagger spec, walk its data-returning routes
    (GetUserDetails, GetBankDetails, list endpoints) through this tool. Returns
    {verdict, data_exposed, severity, categories, record_count, redacted_samples,
    evidence_rung, evidence_artefact, guidance}."""
    return _scan(_verify_data_exposure, url, method=method, headers=headers or None,
                 cookies=cookies or None)


# --------------------------------------------------------------------------- #
# Reporting — email the verifiable report + proofs to the operator
# --------------------------------------------------------------------------- #
@mcp.tool()
def syber_send_report(target: str = "", attachments: list[str] | None = None,
                      subject: str = "") -> dict[str, Any]:
    """Email the engagement report with ATTACHED PROOFS to the OPERATOR so they can verify
    each finding is real and forward it to the target organisation. The report lists every
    published finding (severity, attack chain, MITRE, evidence_refs) and attaches the actual
    artefacts: the downloaded data samples (redacted) from syber_verify_data_exposure and the
    confirmation screenshot the system captured (logged-in, showing the actual gated data).
    PROOFS ARE AUTOMATIC AND CONFIRMED-ONLY: only artefacts from a CONFIRMED capture (2xx + real
    data) are attached — the system screenshots the data itself and REJECTS login / access-denied /
    error pages. Do NOT pass login-page or "Access Denied" screenshots; a screenshot without
    accessed data is not proof and is ignored. `attachments` is for non-image operator files only.
    Call this as the FINAL step, after findings are published + gated.

    The RECIPIENT is fixed by the operator (SYBER_REPORT_TO in the environment) — you do NOT and
    cannot choose it; the report always goes to the operator's own address. Requires RESEND_API_KEY."""
    from syber.reporting import build_and_send
    return _integration(build_and_send, to=None, target=target,
                        extra_attachments=attachments, subject=subject or None)


# --------------------------------------------------------------------------- #
# Identity provisioning (AgentMail / AgentPhone) — for multi-account IDOR/BOLA
# --------------------------------------------------------------------------- #
@mcp.tool()
def syber_provision_identity(label: str = "acct", want_phone: bool = False) -> dict[str, Any]:
    """Stand up a fresh TEST IDENTITY for the agent — a real email inbox (always),
    plus the provisioned phone number if `want_phone` and AgentPhone is configured.
    Returns {email, inbox_id, phone, number_id}. Use it to REGISTER an account on the
    AUTHORISED target's own signup form: provision two identities (label 'A' and 'B'),
    register both, then feed their session cookies to syber_test_access_control to
    prove IDOR/BOLA. Touches only the agent's own AgentMail/AgentPhone account, never
    the target — no target authorisation needed to provision."""
    return _integration(_identity.provision_identity, label=label, want_phone=want_phone)


@mcp.tool()
def syber_check_inbox(inbox_id: str, match: str = "", wait_seconds: int = 60) -> dict[str, Any]:
    """Read a provisioned inbox to complete a target signup: waits up to
    `wait_seconds` for a (optionally `match`-substring) message, then returns the
    extracted verification {email_links, email_otp, raw_subject}. Call this right
    after submitting the target's signup form to grab the confirmation link / OTP."""
    if wait_seconds > 0:
        return _integration(_identity.harvest_verification, inbox_id, timeout=wait_seconds)
    msgs = _integration(_agentmail.list_messages, inbox_id, limit=10)
    return {"messages": msgs} if not isinstance(msgs, dict) else msgs


@mcp.tool()
def syber_read_sms(match: str = "", wait_seconds: int = 60) -> dict[str, Any]:
    """Read inbound SMS on the agent's provisioned number to capture a signup OTP:
    waits up to `wait_seconds` for a (optionally `match`) message and returns
    {otp, body}. Requires AgentPhone configured. Receive-only — there is no tool to
    send SMS/calls to arbitrary numbers."""
    def _go() -> dict[str, Any]:
        if wait_seconds > 0:
            sms = _agentphone.wait_for_sms(match=match or None, timeout=wait_seconds)
            if not sms:
                return {"otp": None, "body": None, "note": "no SMS within wait window"}
            return {"otp": _agentphone.extract_otp(sms), "body": _agentphone._sms_body(sms)}
        return {"messages": _agentphone.read_sms(limit=10)}
    return _integration(_go)


@mcp.tool()
def syber_phone_status() -> dict[str, Any]:
    """Report whether AgentPhone is configured and the provisioned number's status."""
    if not _agentphone.configured():
        return {"configured": False,
                "message": "AgentPhone not set up. Run scripts/syber_phone_signup.sh "
                           "(one-time) and add the creds to .env."}
    return _integration(_agentphone.status)


# --------------------------------------------------------------------------- #
# Cloudflare WAF traversal (AUTHORISED targets only — waf-spec §4)
# --------------------------------------------------------------------------- #
_WAF: dict[str, Any] = {"integration": None}


def _waf() -> Any:
    if _WAF["integration"] is None:
        _WAF["integration"] = build_waf_integration()
    return _WAF["integration"]


@mcp.tool()
def syber_waf_request(url: str, method: str = "GET", headers: dict[str, str] | None = None,
                      body: str = "") -> dict[str, Any]:
    """Fetch an AUTHORISED Cloudflare-protected URL, traversing the WAF automatically
    (waf-spec §4): L1 browser-TLS impersonation -> L2 cf_clearance session reuse ->
    L3 challenge solver (real browser) -> L4 CAPTCHA service. Returns the final
    {status, headers, body, layer, transport, cookie_used}. Use this when an
    ordinary fetch of the target hits a 'Just a moment…' interstitial or Turnstile.
    On a hard block it returns {error:'waf_block', ...} with the challenge details."""
    from urllib.parse import urlparse
    host = urlparse(url).netloc.split("@")[-1].split(":")[0]
    try:
        _require_authorized(host)
    except NotAuthorized as e:
        return {"error": "not_authorized", "message": str(e),
                "remedy": "Call syber_authorize_target first."}
    try:
        from syber.util.output_hygiene import hygienic_response
        resp = _waf().request(url, method=method, headers=headers or None, body=body or None)
        return hygienic_response(resp.to_dict())
    except WAFBlockError as e:
        return e.to_dict()


@mcp.tool()
def syber_waf_refresh(domain: str) -> dict[str, Any]:
    """Proactively solve the Cloudflare challenge for an AUTHORISED domain and cache
    the cf_clearance cookie before it expires (waf-spec §3.6), so later requests
    skip the challenge. Returns {refreshed, cookie_present}."""
    try:
        _require_authorized(domain)
    except NotAuthorized as e:
        return {"error": "not_authorized", "message": str(e),
                "remedy": "Call syber_authorize_target first."}
    try:
        ok = _waf().refresh_session(domain)
        return {"refreshed": bool(ok), "cookie_present": _waf().get_cookie(domain) is not None}
    except WAFBlockError as e:
        return e.to_dict()


@mcp.tool()
def syber_waf_session_status(domain: str) -> dict[str, Any]:
    """Report the cached WAF session for a domain: whether a valid cf_clearance
    cookie is held, the configured TLS-impersonation target, solver engine, and
    whether curl_cffi / proxies / a CAPTCHA service are active (waf-spec §4)."""
    from syber.waf.tls_client import curl_cffi_available
    waf = _waf()
    return {
        "domain": domain,
        "cf_clearance_cached": waf.get_cookie(domain) is not None,
        "tls_impersonation": waf.config.tls_impersonation,
        "tls_transport": "curl_cffi" if curl_cffi_available() else "urllib (fallback)",
        "solver_engine": getattr(waf.solver, "name", None),
        "solver_available": bool(waf.solver and waf.solver.available()),
        "proxies_configured": waf.proxies.configured,
        "captcha_configured": waf.captcha.configured,
    }


@mcp.tool()
def syber_waf_fallback(url: str, probe: bool = True) -> dict[str, Any]:
    """When WAF traversal dead-ends (a hard block, an interactive Turnstile with no
    solver, or plain exhaustion), pivot AROUND the edge instead of giving up. Finds
    an unprotected path to the AUTHORISED target and returns a ranked alternate-
    vector plan (waf-spec §2.5/§3.8):

      * resolves sibling subdomains + certificate-transparency hosts, classifying
        each IP as a Cloudflare edge vs a candidate ORIGIN (off-Cloudflare) IP;
      * if `probe`, hits each candidate origin directly with the right Host header —
        a real answer means the WAF is BYPASSED (returns the origin response +
        origin_ip, `bypassed: true`);
      * always returns `vectors`: non-edge subdomains, non-proxied ports (SSH/mail/
        DB/8080/8443), subdomain enumeration, DNS/mail, and API/mobile hosts to
        work next.

    Use this the moment a Cloudflare target stops yielding to syber_waf_request, so
    the engagement keeps hunting vulnerabilities on surfaces the WAF does not cover."""
    from urllib.parse import urlparse

    from syber.waf.fallback import explore_alternate_vectors
    host = urlparse(url if "://" in url else f"//{url}").netloc.split("@")[-1].split(":")[0]
    try:
        _require_authorized(host)
    except NotAuthorized as e:
        return {"error": "not_authorized", "message": str(e),
                "remedy": "Call syber_authorize_target first."}
    return explore_alternate_vectors(url, probe=probe).to_dict()


@mcp.tool()
def syber_backend_status() -> dict[str, Any]:
    """Report which real backends are active (Neo4j / Kafka / Postgres) and the LLM."""
    return _backends()


def _backends() -> dict[str, Any]:
    from syber.bus.bus import get_bus

    return {
        "graph": type(get_graph()).__name__,
        "memory": type(get_memory_store()).__name__,
        "bus": type(get_bus()).__name__,
        "llm": f"deepseek ({LLM.resolve_model(LLM.orchestrator_model)})",
        "neo4j_uri": os.environ.get("NEO4J_URI", "(in-memory)"),
        "kafka_bootstrap": os.environ.get("KAFKA_BOOTSTRAP", "(in-process)"),
        "database_url_set": bool(os.environ.get("DATABASE_URL")),
    }


# --------------------------------------------------------------------------- #
# Granular component tools (reuse the exact platform handlers)
# --------------------------------------------------------------------------- #
@mcp.tool()
def syber_query_data_lake(
    entity_id: str,
    time_window_start_utc: str = "",
    time_window_end_utc: str = "",
    event_classes: list[str] | None = None,
    max_results: int = 500,
) -> dict[str, Any]:
    """Query the Security Data Lake for CSIM-normalised events (scope-guarded,
    StruQ injection-filtered, audited). Returns evidence chunks for the entity."""
    if _ensure_scope() is None:
        return {"error": "call syber_start_investigation first"}
    args = {"entity_id": entity_id, "max_results": max_results}
    if time_window_start_utc:
        args["time_window_start_utc"] = time_window_start_utc
    if time_window_end_utc:
        args["time_window_end_utc"] = time_window_end_utc
    if event_classes:
        args["event_classes"] = event_classes
    return _query_data_lake.handler(args)


@mcp.tool()
def syber_get_graph_context(entity_id: str, k_paths: int = 5) -> dict[str, Any]:
    """Attack-path graph context for an entity: Yen's k-shortest attack paths,
    blast radius, top betweenness-centrality pivots (Neo4j when configured)."""
    if _ensure_scope() is None:
        return {"error": "call syber_start_investigation first"}
    return _get_graph_context.handler({"entity_id": entity_id, "k_paths": k_paths})


@mcp.tool()
def syber_score_behaviour(entity_id: str) -> dict[str, Any]:
    """Ensemble behavioural deviation score (Isolation Forest + LSTM Autoencoder
    + One-Class SVM) for an entity. >0.70 is anomalous."""
    if _ensure_scope() is None:
        return {"error": "call syber_start_investigation first"}
    return _score_behaviour.handler({"entity_id": entity_id})


@mcp.tool()
def syber_publish_finding(
    summary: str,
    attack_chain: list[dict[str, Any]],
    evidence_refs: list[str],
    mitre_techniques: list[str],
    confidence_estimate: float,
    severity: str,
) -> dict[str, Any]:
    """Publish a candidate forensic finding (schema-validated). Each attack_chain
    step needs step, description, status ('confirmed'|'inferred'); include
    mitre_technique and evidence_refs per step. Call syber_gate_finding after."""
    if _ensure_scope() is None:
        return {"error": "call syber_start_investigation first"}
    return _publish_finding.handler({
        "summary": summary, "attack_chain": attack_chain, "evidence_refs": evidence_refs,
        "mitre_techniques": mitre_techniques, "confidence_estimate": confidence_estimate,
        "severity": severity,
    })


@mcp.tool()
def syber_request_hitl(reason: str, evidence_so_far: list[str] | None = None,
                       severity_estimate: str = "") -> dict[str, Any]:
    """Escalate to a human analyst when the evidence threshold cannot be met."""
    if _ensure_scope() is None:
        return {"error": "call syber_start_investigation first"}
    try:
        return _request_hitl.handler({"reason": reason, "evidence_so_far": evidence_so_far or [],
                                      "severity_estimate": severity_estimate})
    except HumanApprovalRequired as h:
        return {"status": "hitl_requested", **h.payload}


@mcp.tool()
def syber_gate_finding() -> dict[str, Any]:
    """Apply the Composite Evidence Score gate (structural consistency +
    Platt-calibrated confidence + two-pass self-consistency) to the latest
    published finding. CES >= 0.82 verifies the finding for escalation."""
    candidate = get_findings_sink().latest()
    if not candidate:
        return {"error": "no published finding to gate; call syber_publish_finding first"}
    ces = gate_candidate(candidate)
    scope = _ensure_scope()
    _publish_bus_events(candidate, ces, scope)
    get_audit_log().write("ces_gate", {**ces.to_dict(),
                                       "investigation_id": getattr(scope, "investigation_id", None)})
    return {"verdict": "verified_finding" if ces.escalate else "below_ces_threshold",
            "ces": ces.to_dict(), "finding": candidate}


@mcp.tool()
def syber_run_response_playbook(dry_run: bool = True) -> dict[str, Any]:
    """Match the latest finding against response playbooks and execute (dry-run by
    default; HITL-gated in production). Rolls back reversible steps on failure."""
    candidate = get_findings_sink().latest()
    if not candidate:
        return {"error": "no finding to act on"}
    if not matches_trigger(CRED_REVOKE_PLAYBOOK, candidate):
        return {"status": "no_matching_playbook", "finding_mitre": candidate.get("mitre_techniques")}
    integrations = {"azure_ad": mock_integration("azure_ad"),
                    "itsm_servicenow": mock_integration("itsm_servicenow")}
    ctx = {"entity_id": candidate.get("investigation_id"), "entity": ACTOR,
           "evidence_refs": ",".join(candidate.get("evidence_refs", []))}
    ctx["entity_id"] = ACTOR
    outcome = execute_playbook(CRED_REVOKE_PLAYBOOK, ctx, integrations, dry_run=dry_run)
    return {"playbook": CRED_REVOKE_PLAYBOOK["playbook_id"], **outcome, "dry_run": dry_run}


@mcp.tool()
def syber_verify_integrity() -> dict[str, Any]:
    """Verify the immutable audit-log hash chain and the memory-store hash chain."""
    return {"audit_chain_valid": get_audit_log().verify_chain(),
            "memory_chain_valid": get_memory_store().verify_chain()}


@mcp.tool()
def syber_run_full_investigation(seed_demo: bool = True) -> dict[str, Any]:
    """One-shot: run the entire in-house orchestrator end-to-end (parallel
    subagents -> threat investigator -> CES gate -> response) against DeepSeek and
    return the result. Use when you want the platform to drive itself rather than
    orchestrating via the subagents yourself."""
    if seed_demo:
        trigger, scope = build_scenario()
        trigger["anomaly_score"] = score_entity(ACTOR)["score"]
    else:
        scope = _ensure_scope()
        trigger = _STATE.get("trigger")
        if scope is None or trigger is None:
            return {"error": "call syber_start_investigation first or pass seed_demo=True"}
    return run_investigation(trigger, scope)


# --------------------------------------------------------------------------- #
def _publish_bus_events(candidate: dict[str, Any], ces, scope) -> None:
    try:
        from syber.bus.bus import get_bus
        from syber.bus.schemas import SecurityEvent

        bus = get_bus()
        inv = getattr(scope, "investigation_id", None)
        bus.publish("findings", SecurityEvent(
            event_type="finding", originating_agent="threat-investigator", investigation_id=inv,
            confidence=ces.value, payload=json.dumps(candidate, default=str),
            evidence_refs=candidate.get("evidence_refs", [])).sign())
        if ces.escalate:
            bus.publish("verified_findings", SecurityEvent(
                event_type="verified_finding", originating_agent="orchestrator", investigation_id=inv,
                confidence=ces.value, payload=json.dumps(candidate, default=str),
                evidence_refs=candidate.get("evidence_refs", [])).sign())
    except Exception:  # noqa: BLE001 - bus is best-effort
        pass


# --------------------------------------------------------------------------- #
# Parallel fleet (persistent, multi-agent engagement — syber/fleet)
# --------------------------------------------------------------------------- #
# A process-lifetime board (the shared blackboard) so the interactive fleet tools
# accumulate state across MCP calls. Built over the live attack graph.
_FLEET: dict[str, Any] = {"board": None, "planner": None}


def _fleet():
    if _FLEET["board"] is None:
        from syber.fleet import Board, Planner
        board = Board(graph=get_graph())
        _FLEET["board"] = board
        _FLEET["planner"] = Planner(board, graph=get_graph())
    return _FLEET["board"], _FLEET["planner"]


@mcp.tool()
def syber_fleet_run(target: str, max_seconds: int = 1200, concurrency: int = 6,
                    persist: bool = True, stop_on_first_find: bool = False,
                    max_waves: int = 1000) -> dict[str, Any]:
    """Run a PERSISTENT, PARALLEL autonomous engagement against an AUTHORISED target.

    The fan-out → pool → re-divide loop: a planner reads the attack graph and fans out
    workers across vectors IN PARALLEL (service scan, crawl, vuln scan, injection,
    IDOR/BOLA) via a thread pool, each pooling discoveries back into the graph, which
    grows the frontier for the next wave. Uses Syber's existing tools (no extra LLM).

    PERSISTENCE (default on): it does NOT stop at a shallow fixpoint — when the frontier
    drains it DEEPENS (revives failed tasks, deeper content discovery, lateral movement
    to reachable hosts, expansion to ALREADY-AUTHORISED siblings) until the whole chain
    is exhausted. stop_on_first_find=True stops on the first vuln/finding/foothold.

    BOUNDED + RESUMABLE: each call runs at most `max_seconds` (default 1200s, under the
    MCP tool ceiling) and CHECKPOINTS at every wave boundary. If it returns
    `resumable: true` (work still open), just call it again with the same target — it
    reloads the checkpoint and continues from where it stopped. `done: true` means the
    chain is exhausted. Returns coverage, found, dead-letters, and the attack surface."""
    from urllib.parse import urlparse
    host = (urlparse(target if "://" in target else f"//{target}").netloc or target).split("@")[-1].split(":")[0]
    try:
        _require_authorized(host)
    except NotAuthorized as e:
        return {"error": "not_authorized", "message": str(e),
                "remedy": "Call syber_authorize_target first."}
    from syber.config import PATHS
    from syber.fleet import (Coordinator, EngagementBudget, PersistencePolicy,
                             make_tool_worker)
    from syber.graph import model
    model.upsert_host(host)                              # seed the frontier
    board, planner = _fleet()
    cp_dir = PATHS.state / "fleet"
    try:
        cp_dir.mkdir(parents=True, exist_ok=True)
    except Exception:  # noqa: BLE001
        pass
    coord = Coordinator(board, planner, worker=make_tool_worker(),
                        concurrency=max(1, concurrency),
                        budget=EngagementBudget(max_waves=max_waves, max_seconds=float(max_seconds)),
                        checkpoint_path=str(cp_dir / f"{host}.json"),
                        engagement_id=host,
                        persistence=PersistencePolicy() if persist else None,
                        stop_on_first_find=stop_on_first_find)
    summary = coord.run()
    try:
        summary["attack_surface"] = get_graph().attack_surface(limit=10)
    except Exception:  # noqa: BLE001
        pass
    if summary.get("resumable"):
        summary["resume_hint"] = (f"Time budget reached with work still open — call "
                                  f"syber_fleet_run('{target}') again to continue.")
    return summary


@mcp.tool()
def syber_fleet_status() -> dict[str, Any]:
    """Report the fleet blackboard (read-only): task coverage counts, the open frontier
    (what's left to work), and any dead-lettered tasks. Use it to see fleet progress
    between syber_fleet_run calls."""
    board, _ = _fleet()
    return {"coverage": board.coverage(),
            "open_tasks": [t.to_dict() for t in board.open_tasks()][:60]}


@mcp.tool()
def syber_coverage_status() -> dict[str, Any]:
    """THE objective 'are we done?' signal — computed from the attack graph + lead
    registry, NOT from anyone's say-so. Returns {complete, remaining, remaining_count,
    stats}: `remaining` lists exactly what surface is still untested (subdomains not
    enumerated, hosts not scanned, web hosts not crawled, parametered endpoints not
    probed, high-value leads not verified/exhausted). The engagement is finished ONLY
    when complete=true. Use it as the loop condition: while not complete, keep working the
    `remaining` items. Never conclude while remaining_count > 0."""
    from syber.fleet.coverage import engagement_coverage
    board, _ = _fleet()
    try:
        from syber.graph.store import get_graph
        graph = get_graph()
    except Exception:  # noqa: BLE001
        graph = None
    return engagement_coverage(graph=graph, leads=getattr(board, "leads", None))


@mcp.tool()
def syber_engagement_digest() -> dict[str, Any]:
    """Carry-forward memory: a concise summary of everything already discovered, confirmed,
    and tried-and-exhausted across prior work, PLUS the remaining untested surface to work
    now. Read this FIRST when resuming so you build on prior passes instead of repeating
    them (don't re-probe what's in 'already executed', don't retry EXHAUSTED leads)."""
    from syber.fleet.coverage import engagement_digest
    board, _ = _fleet()
    try:
        from syber.graph.store import get_graph
        graph = get_graph()
    except Exception:  # noqa: BLE001
        graph = None
    return {"digest": engagement_digest(graph=graph, leads=getattr(board, "leads", None))}


@mcp.tool()
def syber_fleet_plan_wave(max_size: int = 6) -> dict[str, Any]:
    """Preview the next PARALLEL wave (read-only introspection): the ranked, disjoint
    (one-per-host) batch the planner would dispatch next, with each task's score. This
    is informational — syber_fleet_run executes the waves itself (in-process thread
    pool); you do not need to dispatch these manually."""
    board, planner = _fleet()
    board.materialize_frontier()
    batch = planner.next_batch(max_size=max_size)
    return {"next_wave": [st.to_dict() for st in batch],
            "note": "Informational only — syber_fleet_run runs these in parallel for you."}


@mcp.tool()
def syber_leads_status() -> dict[str, Any]:
    """List the engagement's LEADS and where each sits on the evidence ladder. A lead
    is a discovery that must be VERIFIED, not just reported: exposed admin/console,
    version-matched product (CVE candidate), exposed secret, default-cred-able service,
    datastore, injection/auth-bypass candidate. Each carries a rung (0 reachable / 1
    version-matches-CVE / 2 precondition / 3 verified-exploit=HIGH / 4 impact=CRITICAL)
    and a state (open/verifying/verified/exhausted). **OPEN high-value leads are NOT
    done** — verify them (syber_verify_lead, or the web/scan/waf tools) before
    concluding. This is how you avoid stopping at 'found but unverified'."""
    board, _ = _fleet()
    board.materialize_frontier()
    return board.leads.summary()


@mcp.tool()
def syber_verify_lead(lead_id: str) -> dict[str, Any]:
    """Get a verification plan for a LEAD: its class, product/version, the hypotheses
    to test, and — when a product+version is known — the matching CVE *descriptions and
    public-PoC pointers pulled into context* (the single highest-leverage step:
    exploitation success jumps ~7%→87% once the CVE text is in front of you, Fang et al.
    arXiv 2404.08144). Use the returned hypotheses + CVE notes to drive verification with
    syber_http_request / agent-browser / the scan tools, then record what you confirmed
    via syber_publish_finding (severity = the highest rung you have EVIDENCE for)."""
    board, _ = _fleet()
    board.materialize_frontier()
    lead = board.leads.get(lead_id)
    if lead is None:
        return {"error": "unknown lead", "hint": "call syber_leads_status for lead ids"}
    plan = lead.to_dict()
    plan["cve_intel"] = _cve_intel_for(lead.product, lead.version)
    plan["how"] = ("Test each hypothesis. A reachable surface is rung 0 — climb it: pin the "
                   "exact version, correlate CVEs (below), attempt safe verification (default "
                   "creds / documented bypass / template), and only claim a rung you have "
                   "evidence for. Do NOT conclude while this lead is open.")
    return plan


def _cve_intel_for(product: str, version: str) -> dict[str, Any]:
    """Best-effort CVE-description injection (Fang 2404.08144). Queries the NVD public
    API for the product+version; returns id + description + references for the top hits.
    Degrades to a hint if offline / no key — never blocks verification."""
    if not product:
        return {"note": "no product/version pinned yet — fingerprint the exact version first"}
    import urllib.parse
    import urllib.request
    kw = urllib.parse.quote(f"{product} {version}".strip())
    url = ("https://services.nvd.nist.gov/rest/json/cves/2.0"
           f"?keywordSearch={kw}&resultsPerPage=8")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "syber-fleet"})
        with urllib.request.urlopen(req, timeout=15) as r:  # noqa: S310 (public NVD API)
            data = json.loads(r.read(2_000_000).decode("utf-8", "replace"))
    except Exception as e:  # noqa: BLE001
        return {"note": f"NVD lookup unavailable ({e}); use searchsploit/nuclei in-container",
                "query": f"{product} {version}"}
    out = []
    for item in data.get("vulnerabilities", [])[:8]:
        cve = item.get("cve", {})
        desc = next((d.get("value") for d in cve.get("descriptions", [])
                     if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        score = None
        for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30"):
            if metrics.get(key):
                score = metrics[key][0].get("cvssData", {}).get("baseScore")
                break
        out.append({"id": cve.get("id"), "cvss": score, "description": (desc or "")[:600],
                    "refs": [r.get("url") for r in cve.get("references", [])[:4]]})
    return {"query": f"{product} {version}", "candidates": out,
            "note": "These are HYPOTHESES (rung 1). Confirm with a template/PoC before claiming the score."}


if __name__ == "__main__":
    mcp.run()
