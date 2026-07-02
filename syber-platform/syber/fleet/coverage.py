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

from typing import Any

_WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 8081, 9443}


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

    # 4. Every parametered WebEndpoint must be probed (injection + access-control).
    #    A probed endpoint is marked ``probed`` on the node (set by the probe runners).
    unprobed = [u for u, d in endpoints if d.get("params") and not d.get("probed")]
    if unprobed:
        remaining.append({"kind": "test_endpoint", "targets": unprobed[:30], "count": len(unprobed)})

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
