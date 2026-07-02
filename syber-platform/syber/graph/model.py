"""
Attack-surface graph model (spec §6, enriched).

A typed ingestion API over the knowledge graph. Instead of dumping flat
Host/Service/Vuln nodes, this builds a connected attack-surface model with
provenance, so the graph becomes the single source of truth for an engagement:

  (:Domain)            name
  (:Host)              id, hostname, ip, os, source
  (:Service)           id=ip:port, port, protocol, service, product, version, cpe
  (:Technology)        name, version, category
  (:WebEndpoint)       url, status, title
  (:Vulnerability)     id, name, severity, cvss, source
  (:Certificate)       fingerprint, subject_cn, issuer, not_after, sans
  (:Finding)           id, severity, mitre, ces, summary

  (Host)-[:EXPOSES]->(Service)
  (Service)-[:RUNS_TECH]->(Technology)
  (Host)-[:SERVES]->(WebEndpoint)
  (Service)-[:VULNERABLE_TO]->(Vulnerability)   (Host too, when service unknown)
  (Host)-[:PRESENTS]->(Certificate)
  (Certificate)-[:COVERS]->(Domain)
  (Host)-[:PART_OF]->(Domain)
  (Finding)-[:ABOUT]->(Host)

Every upsert is idempotent (MERGE semantics in store.add_node) and updates
last_seen, so re-scanning a target enriches rather than duplicates.
"""
from __future__ import annotations

from typing import Any

from .store import get_graph

# Edge weights model "ease of traversal" for attack-path analysis: a vulnerable
# service is a cheaper hop than a hardened one.
_W_EXPOSES = 0.5
_W_RUNS_TECH = 0.8
_W_SERVES = 0.6
_W_VULN = 0.3
_W_PRESENTS = 1.0
_W_COVERS = 1.0
_W_PART_OF = 0.2
_W_REACH = 0.4          # network reachability hop (MulVAL hacl) — a cheap precondition edge


def _host_root_domain(hostname: str) -> str | None:
    parts = (hostname or "").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 and not hostname.replace(".", "").isdigit() else None


def upsert_host(host: str, ip: str | None = None, os: str | None = None, source: str = "scan") -> str:
    g = get_graph()
    g.add_node(host, "Host", hostname=host, ip=ip, os=os, source=source)
    if ip and ip != host:
        g.add_node(ip, "Host", hostname=host, ip=ip, source=source)
        g.add_edge(host, ip, "RESOLVES_TO", edge_weight=0.1)
    dom = _host_root_domain(host)
    if dom and dom != host:
        g.add_node(dom, "Domain", name=dom)
        g.add_edge(host, dom, "PART_OF", edge_weight=_W_PART_OF)
    return host


def upsert_service(host: str, port: int, protocol: str = "tcp", service: str | None = None,
                   product: str | None = None, version: str | None = None,
                   cpe: list[str] | None = None, scripts: list[dict] | None = None) -> str:
    g = get_graph()
    ip = g.g.nodes.get(host, {}).get("ip") or host
    sid = f"{ip}:{port}"
    g.add_node(sid, "Service", port=port, protocol=protocol, service=service,
               product=product, version=version,
               cpe=",".join(cpe) if cpe else None,
               banner=(product or "") + (" " + version if version else "") or None)
    g.add_edge(host, sid, "EXPOSES", edge_weight=_W_EXPOSES)
    return sid


def upsert_technology(host_or_service: str, name: str, version: str | None = None,
                      category: str | None = None) -> str:
    g = get_graph()
    tid = f"tech:{name.lower()}"
    g.add_node(tid, "Technology", name=name, version=version, category=category)
    g.add_edge(host_or_service, tid, "RUNS_TECH", edge_weight=_W_RUNS_TECH)
    return tid


def upsert_web_endpoint(host: str, url: str, status: int | None = None, title: str | None = None,
                        method: str | None = None, params: list[str] | None = None) -> str:
    g = get_graph()
    # Merge params across re-crawls so the endpoint accrues its full parameter set.
    existing = g.g.nodes.get(url, {}).get("params", "") if g.has(url) else ""
    merged = sorted({*(p for p in existing.split(",") if p), *(params or [])})
    g.add_node(url, "WebEndpoint", url=url, status=status, title=title,
               method=method, params=",".join(merged) or None)
    g.add_edge(host, url, "SERVES", edge_weight=_W_SERVES)
    return url


def mark_endpoint_probed(url: str) -> None:
    """Mark a WebEndpoint as probed (injection/access-control run) so coverage converges."""
    g = get_graph()
    if g.has(url):
        g.add_node(url, "WebEndpoint", probed=True)


def mark_vuln_verified(vid: str, verified: bool = True) -> None:
    """Mark a Vulnerability as verified/exhausted so coverage stops re-listing it."""
    g = get_graph()
    if g.has(vid):
        g.add_node(vid, "Vulnerability", verified=verified)


def upsert_vulnerability(target: str, vid: str, name: str | None = None, severity: str = "unknown",
                         cvss: float | None = None, source: str = "nuclei",
                         service_id: str | None = None) -> str:
    g = get_graph()
    g.add_node(vid, "Vulnerability", id=vid, name=name, severity=str(severity).lower(),
               cvss=cvss, source=source)
    g.add_edge(service_id or target, vid, "VULNERABLE_TO", edge_weight=_W_VULN, weaponised=False)
    return vid


def upsert_certificate(host: str, fingerprint: str, subject_cn: str | None = None,
                       issuer: str | None = None, not_after: str | None = None,
                       sans: list[str] | None = None) -> str:
    g = get_graph()
    cid = f"cert:{fingerprint}" if fingerprint else f"cert:{host}"
    g.add_node(cid, "Certificate", fingerprint=fingerprint, subject_cn=subject_cn,
               issuer=issuer, not_after=not_after, sans=",".join(sans or []) or None)
    g.add_edge(host, cid, "PRESENTS", edge_weight=_W_PRESENTS)
    # SANs reveal sibling hosts/domains — model them so the graph links related assets.
    for san in (sans or [])[:25]:
        dom = san.lstrip("*.")
        g.add_node(dom, "Domain", name=dom)
        g.add_edge(cid, dom, "COVERS", edge_weight=_W_COVERS)
    return cid


# --------------------------------------------------------------------------- #
# Reachability + host access-state (attack-graph layer, MulVAL hacl/netAccess)
# --------------------------------------------------------------------------- #
# Syber's surface graph (Host-Service-Vuln) becomes a true *attack* graph when it
# also models (a) which hosts can reach which (the precondition for any remote
# exploit) and (b) each host's foothold state. Compromising a host then DERIVES
# reachability to its neighbours — the recursion that is a multi-step attack path
# (MulVAL: execCode(H1) ∧ hacl(H1,H2) ⇒ netAccess(H2)).
_ACCESS_LEVELS = {"none", "user", "root"}


def set_host_state(host: str, *, discovered: bool | None = None,
                   reachable: bool | None = None, compromised: bool | None = None,
                   access: str | None = None, value: float | None = None) -> str:
    """Set a host's attack-state properties (idempotent merge). ``access`` is one of
    none|user|root; ``value`` marks crown-jewel criticality for path ranking."""
    g = get_graph()
    g.add_node(host, "Host", hostname=host)
    props: dict[str, Any] = {}
    if discovered is not None:
        props["discovered"] = discovered
    if reachable is not None:
        props["reachable"] = reachable
    if compromised is not None:
        props["compromised"] = compromised
    if access is not None and access in _ACCESS_LEVELS:
        props["access"] = access
    if value is not None:
        props["value"] = value
    if props:
        g.add_node(host, "Host", **props)
    return host


def upsert_reachability(src_host: str, dst_host: str, protocol: str = "tcp",
                        port: int | None = None) -> str:
    """Record that ``src_host`` can reach ``dst_host`` (MulVAL hacl). The destination
    is therefore network-reachable (netAccess) — mark it discovered+reachable."""
    g = get_graph()
    g.add_node(src_host, "Host", hostname=src_host)
    g.add_node(dst_host, "Host", hostname=dst_host)
    g.add_edge(src_host, dst_host, "CAN_REACH", edge_weight=_W_REACH,
               protocol=protocol, port=port)
    g.add_node(dst_host, "Host", discovered=True, reachable=True)
    return dst_host


def mark_compromised(host: str, access: str = "user") -> list[str]:
    """Record a foothold on ``host`` (execCode) and DERIVE reachability to every host
    it CAN_REACH (netAccess). Returns the hosts newly made reachable — the
    lateral-movement frontier the fleet will pick up. This is the incremental,
    monotone graph update that turns a single foothold into an attack path."""
    g = get_graph()
    g.add_node(host, "Host", hostname=host, compromised=True, discovered=True,
               access=access if access in _ACCESS_LEVELS else "user")
    derived: list[str] = []
    try:
        for _, dst, ed in g.g.out_edges(host, data=True):
            if ed.get("edge_type") == "CAN_REACH":
                dnode = g.g.nodes.get(dst, {})
                if not dnode.get("compromised"):
                    g.add_node(dst, "Host", discovered=True, reachable=True)
                    derived.append(dst)
    except Exception:  # noqa: BLE001 - derivation is best-effort
        pass
    return derived


def upsert_finding(finding: dict[str, Any], host: str | None = None) -> str:
    """Store a published finding as a node linked to its host (graph = source of truth)."""
    g = get_graph()
    fid = "finding:" + str(finding.get("investigation_id") or finding.get("summary", "")[:40])
    g.add_node(fid, "Finding", id=fid, severity=finding.get("severity"),
               mitre=",".join(finding.get("mitre_techniques", [])),
               confidence=finding.get("confidence_estimate"),
               summary=(finding.get("summary") or "")[:300])
    if host and g.has(host):
        g.add_edge(fid, host, "ABOUT", edge_weight=0.1)
    return fid
