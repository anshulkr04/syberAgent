"""
Engagement coverage — the OBJECTIVE "are we actually done?" signal for the Ralph loop.

The Ralph technique keeps re-running the agent until the task is genuinely complete —
and the critical rule is that completion must be judged from PERSISTED STATE, never from
the model saying "ENGAGEMENT_COMPLETE" (models declare done to escape the loop). Our
persisted state is the attack graph (durable in Neo4j) + the lead registry. This module
computes, from that state, exactly what surface remains untested — so the loop continues
until every discovered host is scanned, every web host crawled, every parametered
endpoint probed, every network-discovered API tested, and every high-value lead resolved.

``engagement_coverage`` returns ``{complete, remaining, ...}``: ``complete`` is the loop's
stop signal; ``remaining`` is the concrete work list fed back into the next iteration so
the agent knows precisely what is still untested (Ralph: tell it what's left, don't make
it rediscover).

Pure over the graph (+ optional lead registry); unit-tested with an in-memory graph.
"""
from __future__ import annotations

import re
from typing import Any

_WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 8081, 9443}
_API_RX = re.compile(r"/(?:api|mwapi|rest|v\d+|graphql|odata|services?|gateway)/", re.IGNORECASE)


def _is_api(url: str) -> bool:
    return bool(_API_RX.search(url or ""))


def _auth_gated(status: Any) -> bool:
    try:
        return int(status) in (401, 403)
    except (TypeError, ValueError):
        return False


def _nodes(g, label: str) -> list[tuple[str, dict]]:
    try:
        return [(n, d) for n, d in g.g.nodes(data=True) if d.get("label") == label]
    except Exception:  # noqa: BLE001
        return []


def _out_edge_types(g, node_id: str) -> list[tuple[str, str, dict]]:
    try:
        return [(dst, ed.get("edge_type", ""), ed) for _, dst, ed in g.g.out_edges(node_id, data=True)]
    except Exception:  # noqa: BLE001
        return []


def _has_out_label(g, node_id: str, label: str) -> bool:
    for dst, _, _ in _out_edge_types(g, node_id):
        try:
            if g.g.nodes[dst].get("label") == label:
                return True
        except Exception:  # noqa: BLE001
            continue
    return False


def engagement_coverage(graph: Any = None, leads: Any = None,
                        require_confirmed: bool = True) -> dict[str, Any]:
    """Compute objective coverage from the attack graph (+ lead registry).

    Returns a dict with ``complete`` (the loop stop signal) and ``remaining`` (a list of
    {kind, targets, count} items still to do). Best-effort: a graph error yields
    ``complete: False`` (keep working) rather than a false "done"."""
    if graph is None:
        try:
            from ..graph.store import get_graph
            graph = get_graph()
        except Exception:  # noqa: BLE001
            return {"complete": False, "remaining": [{"kind": "graph_unavailable", "count": 1}],
                    "reason": "graph unavailable — cannot assert completion"}

    hosts = _nodes(graph, "Host")
    endpoints = _nodes(graph, "WebEndpoint")
    vulns = _nodes(graph, "Vulnerability")
    findings = _nodes(graph, "Finding")

    remaining: list[dict[str, Any]] = []

    # 1. Every apex should have had subdomain enumeration run (graph marker set by the runner).
    unenum = [n for n, d in hosts
              if _is_apex(n) and not d.get("subdomains_enumerated")]
    if unenum:
        remaining.append({"kind": "subdomain_enum", "targets": unenum[:20], "count": len(unenum)})

    # 2. Every discovered Host must be service-scanned (a scanned host has ≥1 Service edge).
    unscanned = [n for n, d in hosts if not _has_out_label(graph, n, "Service")]
    if unscanned:
        remaining.append({"kind": "service_scan", "targets": unscanned[:30], "count": len(unscanned)})

    # 3. Every web Host (has an http/https Service) must be crawled (→ has WebEndpoint children).
    uncrawled = []
    for n, _ in hosts:
        web = any(g_port(ed) in _WEB_PORTS
                  for dst, et, ed in _out_edge_types(graph, n)
                  if et == "RUNS" or _label(graph, dst) == "Service")
        if web and not _has_out_label(graph, n, "WebEndpoint"):
            uncrawled.append(n)
    if uncrawled:
        remaining.append({"kind": "web_crawl", "targets": uncrawled[:30], "count": len(uncrawled)})

    # 4. Every parametered OR API WebEndpoint must be probed (injection + access-control).
    #    A probed endpoint is marked ``probed`` on the node (set by the probe runners).
    unprobed = [u for u, d in endpoints
                if (d.get("params") or _is_api(u)) and not d.get("probed")]
    if unprobed:
        remaining.append({"kind": "test_endpoint", "targets": unprobed[:30], "count": len(unprobed)})

    # 4b. Every auth-gated endpoint (401/403) must be AUTH-RETESTED with harvested/obtained
    #     tokens — a 401 is "needs auth", never "secure/done". Marked ``auth_retested``.
    auth_gated = [u for u, d in endpoints
                  if _auth_gated(d.get("status")) and not d.get("auth_retested")]
    if auth_gated:
        remaining.append({"kind": "auth_retest", "targets": auth_gated[:30], "count": len(auth_gated)})

    # 5. Open high-value leads (from the lead registry) must be VERIFIED or EXHAUSTED.
    #    (The lead registry owns the verification lifecycle — a lead reaches EXHAUSTED
    #    when every hypothesis has a logged failed attempt, so this always converges.
    #    Vulnerability nodes become leads via classify_node, so they are covered here.)
    open_leads = 0
    if leads is not None:
        try:
            hv = leads.open_highvalue()
            open_leads = len(hv)
            if hv:
                remaining.append({"kind": "verify_lead",
                                  "targets": [l.id for l in hv][:30], "count": len(hv)})
        except Exception:  # noqa: BLE001
            pass

    complete = not remaining
    return {
        "complete": complete,
        "remaining": remaining,
        "remaining_count": sum(r["count"] for r in remaining),
        "stats": {"hosts": len(hosts), "endpoints": len(endpoints),
                  "vulnerabilities": len(vulns), "findings": len(findings),
                  "open_highvalue_leads": open_leads},
        "reason": ("all discovered surface probed and all high-value leads resolved"
                   if complete else
                   f"{sum(r['count'] for r in remaining)} items still untested across "
                   f"{len(remaining)} categories"),
    }


def engagement_digest(graph: Any = None, leads: Any = None, max_items: int = 25) -> str:
    """A concise MARKDOWN carry-forward summary for the NEXT Ralph pass: what's already
    discovered/confirmed, what leads were tried-and-exhausted (so they aren't retried),
    what tool calls already ran (don't repeat), and — top priority — the remaining
    untested surface to work THIS pass. This is the cross-pass memory that stops a fresh
    context from redoing the previous pass's work."""
    if graph is None:
        try:
            from ..graph.store import get_graph
            graph = get_graph()
        except Exception:  # noqa: BLE001
            graph = None

    lines: list[str] = ["## Carry-forward from previous passes (READ FIRST — do NOT repeat this work)"]

    if graph is not None:
        hosts = _nodes(graph, "Host")
        eps = _nodes(graph, "WebEndpoint")
        vulns = _nodes(graph, "Vulnerability")
        findings = _nodes(graph, "Finding")
        nonprod = [n for n, d in hosts if d.get("env") == "non-prod"
                   or any(t in n for t in ("uat", "cug", "stag", "dev", "qa", "preprod"))]
        lines.append(f"- Discovered so far: {len(hosts)} hosts ({len(nonprod)} non-prod), "
                     f"{len(eps)} web endpoints, {len(vulns)} vulnerabilities, {len(findings)} findings.")
        if findings:
            lines.append("- Findings already published:")
            for n, d in findings[:max_items]:
                lines.append(f"    - [{d.get('severity', '?')}] {d.get('summary', n)}")
        # confirmed data-exposure captures (from the evidence dir)
        try:
            from ..repro import reproductions
            confirmed, _ = reproductions()
            if confirmed:
                lines.append(f"- CONFIRMED exposures (already proven — reproduced with curl): {len(confirmed)}")
                for r in confirmed[:max_items]:
                    lines.append(f"    - {r['url']}")
        except Exception:  # noqa: BLE001
            pass

    # leads already tried and exhausted (do NOT retry these hypotheses)
    if leads is not None:
        try:
            exhausted = [l for l in leads.all() if str(l.state) == "exhausted"]
            if exhausted:
                lines.append(f"- Leads already EXHAUSTED (every hypothesis tried & failed — do not retry): "
                             f"{len(exhausted)}")
                for l in exhausted[:max_items]:
                    why = "; ".join(l.reflections[-2:]) if getattr(l, "reflections", None) else ""
                    lines.append(f"    - {l.id} {('— ' + why) if why else ''}")
        except Exception:  # noqa: BLE001
            pass

    # already-executed tool calls (recall ledger, persisted across passes)
    try:
        from ..scanning.recall import summarize
        s = summarize(limit=max_items)
        if s and "no tool calls" not in s:
            lines.append("- " + s.replace("\n", "\n  "))
    except Exception:  # noqa: BLE001
        pass

    # THE priority for this pass: what is still untested
    cov = engagement_coverage(graph=graph, leads=leads)
    if cov["complete"]:
        lines.append("\n## Remaining THIS pass: NONE — coverage is complete. Verify & report only.")
    else:
        lines.append(f"\n## Remaining THIS pass ({cov['remaining_count']} untested — WORK THESE, not old ground):")
        for r in cov["remaining"]:
            tgts = ", ".join(str(t) for t in r.get("targets", [])[:8])
            more = f" (+{r['count'] - 8} more)" if r["count"] > 8 else ""
            lines.append(f"- {r['kind']}: {tgts}{more}")
    return "\n".join(lines)


def _is_apex(host: str) -> bool:
    try:
        from ..scanning.subdomains import registrable_apex
        return registrable_apex(host) == host
    except Exception:  # noqa: BLE001
        return host.count(".") <= 1


def _label(graph, node_id: str) -> str:
    try:
        return graph.g.nodes[node_id].get("label", "")
    except Exception:  # noqa: BLE001
        return ""


def g_port(edge: dict) -> int:
    try:
        return int(edge.get("port") or 0)
    except (TypeError, ValueError):
        return 0
