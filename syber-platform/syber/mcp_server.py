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
from syber.recon.site_recon import recon_site
from syber.response.executor import execute_playbook, mock_integration
from syber.response.playbooks import CRED_REVOKE_PLAYBOOK, matches_trigger
from syber.scanning import active_scan
from syber.scanning.active_scan import NotAuthorized
from syber.scanning.authorization import get_auth_store
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
    """Investigate a real website/domain: passive reconnaissance returning DNS,
    HTTP + security headers, TLS certificate, server/technology fingerprint,
    exposed sensitive paths, and risk indicators. Opens a recon investigation
    scope and registers the host in the knowledge graph, so you can then call
    syber_publish_finding (citing the recon observations as evidence_refs) and
    syber_gate_finding. Pass a domain or URL (e.g. 'example.com')."""
    report = recon_site(site)
    host = report.get("host", site)
    addrs = report.get("dns", {}).get("addresses", []) if isinstance(report.get("dns"), dict) else []

    scope = InvestigationScope(
        investigation_id=f"RECON-{host}",
        allowed_entities={host, *addrs},
        time_start_utc="", time_end_utc="",
    )
    set_current_scope(scope)
    _STATE["scope"] = scope
    _STATE["trigger"] = {"event_type": "site_recon", "entity_id": host, "report": report}

    # Register the host (and its IPs) in the attack graph (spec §6).
    try:
        g = get_graph()
        g.add_node(host, "Asset", hostname=host, asset_class="web", ip=(addrs[0] if addrs else ""))
        for ip in addrs:
            g.add_node(ip, "Asset", hostname=host, ip=ip, asset_class="web_endpoint")
            g.add_edge(host, ip, "RESOLVES_TO", edge_weight=1.0)
    except Exception:  # noqa: BLE001
        pass

    get_audit_log().write("site_recon", {"host": host, "risk_indicators": report.get("risk_indicators", [])})
    return {
        "investigation_id": scope.investigation_id,
        "report": report,
        "suggested_evidence_refs": [f"recon:{k}" for k in ("dns", "http", "tls", "exposed_paths")
                                    if report.get(k)],
        "next": "Analyse the report, then call syber_publish_finding with an attack_chain of "
                "the exposure observations (each step: status confirmed, evidence_refs like "
                "'recon:http', 'recon:tls'), mitre_techniques (e.g. T1595 Active Scanning, "
                "T1592 Gather Victim Host Information), confidence_estimate, severity. Then "
                "call syber_gate_finding.",
    }


# --------------------------------------------------------------------------- #
# Active scanning (AUTHORISED targets only — default deny)
# --------------------------------------------------------------------------- #
def _scan(fn, *args, **kwargs) -> dict[str, Any]:
    try:
        return fn(*args, **kwargs)
    except NotAuthorized as e:
        return {"error": "not_authorized", "message": str(e),
                "remedy": "Call syber_authorize_target with an attestation that you own / are "
                          "authorised to test this target, then retry."}


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


if __name__ == "__main__":
    mcp.run()
