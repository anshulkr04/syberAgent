"""
The specialist roster (fleet Phase 4).

HPTSA's ablations are unambiguous: **specialization** and **per-specialist
technique docs** each account for ~4× of its pass@1 over a single agent
(research_papers.md §4). So the fleet's workers are narrow specialists, each with a
restricted tool subset and a small curated doc-pack, and — when several run in one
wave — a **counterfactual dedup directive** ("assume the others' findings don't
exist; find a different path", PenHeal) so parallel workers don't re-hit the same
hole for free.

Two products here:

  * ``SPECIALISTS`` + ``specialist_system_prompt`` — the LLM-specialist specs the
    harness/agent dispatch uses (Phase 5): name, kinds handled, tool subset,
    doc-pack, counterfactual. Pure data + string assembly (testable).
  * ``make_tool_worker`` — a **deterministic** ``WorkerFn`` that runs Syber's
    EXISTING tools per task kind (service_scan/web_crawl/vuln_scan/test_injection/
    test_access_control), pooling results into the graph so the frontier grows.
    This makes the fleet immediately useful with no LLM: a fully autonomous,
    parallel scan→crawl→test engagement coordinated by board+planner+coordinator.
    Kinds that need reasoning (exploit) are parked ``blocked`` for the agent worker.

Everything is import-guarded and exception-tolerant (the platform's "never
hard-crash" contract): a missing tool or an unauthorized target becomes a clean
``WorkerResult(failed)``, never a crash that wedges the wave.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .board import Board, Task
from .coordinator import WorkerFn, WorkerResult

__all__ = ["Specialist", "SPECIALISTS", "specialist_for", "specialist_system_prompt",
           "counterfactual_directive", "make_tool_worker", "default_runners"]


# --------------------------------------------------------------------------- #
# Specialist specs (for the LLM/agent dispatch)
# --------------------------------------------------------------------------- #
@dataclass
class Specialist:
    name: str
    kinds: list[str]                 # task kinds this specialist handles
    tools: list[str]                 # MCP tool names it may use (restricted subset)
    docs: str                        # curated technique doc-pack (HPTSA: +4x)
    focus: str = ""                  # one-line objective

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "kinds": list(self.kinds), "tools": list(self.tools),
                "focus": self.focus}


SPECIALISTS: list[Specialist] = [
    Specialist(
        name="recon",
        kinds=["service_scan", "port_scan", "recon", "tech_fingerprint", "cert_recon"],
        tools=["syber_port_scan", "syber_service_scan", "syber_recon_site",
               "syber_http_request"],
        focus="Enumerate the host: ports, service versions, technologies, certificate SANs.",
        docs=("Run -sV -sC service detection on open ports; fingerprint the web stack; pull "
              "certificate SANs (they reveal sibling hosts to add to scope). Prefer the top "
              "ports first, then widen. Record every banner/version verbatim — version is what "
              "the vuln stage matches against."),
    ),
    Specialist(
        name="web-mapper",
        kinds=["web_crawl"],
        tools=["syber_crawl", "syber_http_request", "syber_recon_site"],
        focus="Map the app: endpoints, forms, parameters — and the inferred REST surface.",
        docs=("Crawl breadth-first; capture every PARAMETER (that is the attack surface the "
              "scanners miss). Note id-bearing endpoints (id/user/order/doc/invoice/org_id) for "
              "the IDOR specialist. The crawl also returns inferred_endpoints (synthesised REST "
              "routes) — feed those forward."),
    ),
    Specialist(
        name="vuln-triage",
        kinds=["vuln_scan"],
        tools=["syber_vuln_scan", "syber_web_scan", "syber_http_request"],
        focus="Templated + web vuln scan; triage by demonstrated exploitability.",
        docs=("Run nuclei across web services; corroborate each hit before trusting it. A "
              "template match is a lead, not a confirmed finding — rate by exploitability, not "
              "the scanner's label. Public keys/banners/standard files are NOT findings."),
    ),
    Specialist(
        name="injection",
        kinds=["test_injection"],
        tools=["syber_test_injection", "syber_http_request"],
        focus="Reflected XSS / error-based SQLi / SSRF on parameterised endpoints.",
        docs=("Use a unique canary per probe. A reflected payload is NOT execution — confirm the "
              "raw <...> survived un-entity-encoded for XSS; require a DBMS error signature for "
              "error-based SQLi; SSRF needs an out-of-band hit, so a metadata marker is only "
              "POSSIBLE. Non-destructive payloads only. Only CONFIRMED verdicts ship."),
    ),
    Specialist(
        name="idor-bola",
        kinds=["test_access_control"],
        tools=["syber_test_access_control", "syber_http_request", "syber_provision_identity",
               "syber_check_inbox"],
        focus="Broken Object Level Authorization (OWASP API #1) — the priority bug class.",
        docs=("Two accounts give the strongest signal: fetch A's object as B; if B gets a 2xx with "
              "A's content, ownership isn't enforced. Without two accounts, vary the id (±1, "
              "harvested ids) in the SAME session and diff the response — identical length/body to "
              "a not-mine baseline is the confirmation. Reason across all six BOLA families "
              "(direct-ref, action-level, tenant, workflow, chained, object-rebinding)."),
    ),
    Specialist(
        name="waf-origin",
        kinds=["waf_bypass"],
        tools=["syber_waf_request", "syber_waf_fallback", "syber_waf_session_status",
               "syber_http_request"],
        focus="Traverse Cloudflare; on a hard block pivot to the origin / siblings.",
        docs=("If a target is behind Cloudflare, requests traverse automatically. On a hard block "
              "(1020/1010) DO NOT grind — call the origin-pivot: resolve sibling/CT hosts off "
              "Cloudflare, hit the origin IP directly with the right Host header, and work the "
              "non-proxied ports. Record a hard block and move on."),
    ),
    Specialist(
        name="exploit",
        kinds=["exploit", "priv_esc", "lateral"],
        tools=["syber_http_request", "syber_recall_tool_calls"],
        focus="Weaponise a confirmed vuln into a demonstrated, evidence-grounded exploit.",
        docs=("Reason from the exact running version to a concrete exploit. A claimed flag/secret "
              "MUST appear verbatim in real tool output or it is a hallucination — discard it. "
              "'Found the file' ≠ 'got the contents'. Stop on first solid proof; do not over-claim "
              "severity. This specialist requires the LLM agent (no deterministic runner)."),
    ),
]

_BY_KIND: dict[str, Specialist] = {k: s for s in SPECIALISTS for k in s.kinds}


def specialist_for(kind: str) -> Specialist | None:
    return _BY_KIND.get(kind)


def counterfactual_directive(peer_names: list[str]) -> str:
    """PenHeal counterfactual dedup: tell a worker to assume its peers' targets are
    already handled and to pursue a DIFFERENT path — near-free parallel de-dup."""
    if not peer_names:
        return ""
    peers = ", ".join(sorted(set(peer_names)))
    return ("\n\nParallel-fleet note: other specialists are working concurrently "
            f"({peers}). Assume the vulnerabilities THEY are pursuing do not exist — "
            "do not duplicate their effort; pursue a different path/vector. Coordinate only "
            "through the shared attack graph (read it; write your findings to it).")


def specialist_system_prompt(spec: Specialist, peer_names: list[str] | None = None,
                             base: str = "") -> str:
    """Assemble a specialist's system prompt: base doctrine + its focus + doc-pack +
    counterfactual dedup directive. Used by the agent dispatch (Phase 5)."""
    parts = []
    if base:
        parts.append(base.strip())
    parts.append(f"You are the **{spec.name}** specialist in the Syber parallel fleet.")
    if spec.focus:
        parts.append(f"Objective: {spec.focus}")
    parts.append(f"Allowed tools: {', '.join(spec.tools)}.")
    parts.append("Technique notes:\n" + spec.docs)
    cf = counterfactual_directive(peer_names or [])
    if cf:
        parts.append(cf.strip())
    parts.append("Write every confirmed discovery to the attack graph (the shared blackboard); "
                 "return a terse summary of what you confirmed and the evidence refs.")
    return "\n\n".join(parts)


# --------------------------------------------------------------------------- #
# Deterministic tool runners (run Syber's existing tools; pool into the graph)
# --------------------------------------------------------------------------- #
Runner = Callable[[Task, Board, str], WorkerResult]


def _unavailable(r: dict[str, Any]) -> str | None:
    if r.get("available") is False:
        return r.get("note") or "tool unavailable"
    if r.get("error"):
        return str(r.get("error"))
    if r.get("error") == "not_authorized" or r.get("remedy"):
        return r.get("message") or "not authorized"
    return None


def _run_subdomain_enum(task: Task, board: Board, wid: str) -> WorkerResult:
    """Map the surface FIRST: enumerate subdomains (CT logs + prefix brute) and ingest
    every live host so the scan/crawl/vuln rules fan out across ALL of them — including
    the non-prod (uat/cug/staging) hosts where exposure usually lives. Deterministic, so
    it happens every run regardless of the model's choices."""
    from ..scanning import subdomains as sd
    from ..graph import model
    domain = task.target_id
    try:
        res = sd.enumerate_subdomains(domain, deep=True)
    except Exception as e:  # noqa: BLE001
        return WorkerResult(status="failed", note=str(e))
    n = sd.ingest_subdomains(res)
    try:                                        # mark apex enumerated so we don't repeat
        g = model.get_graph()
        if g.has(domain):
            g.g.nodes[domain]["subdomains_enumerated"] = True
    except Exception:  # noqa: BLE001
        pass
    nonprod = len(res.get("nonprod", []))
    return WorkerResult(status="done", result_ref=f"subdomain_enum:{domain}",
                        note=f"subs={res.get('total', 0)} nonprod={nonprod} ingested={n}", steps=1)


def _run_service_scan(task: Task, board: Board, wid: str) -> WorkerResult:
    from ..scanning import active_scan
    host = task.target_id
    r = active_scan.service_scan(host)
    bad = _unavailable(r)
    if bad:
        # fall back to the dependency-free port scan so the fleet still makes progress
        r = active_scan.port_scan(host)
        bad = _unavailable(r)
        if bad:
            return WorkerResult(status="failed", note=bad)
    try:
        active_scan.ingest_scan_to_graph(host, r)
    except Exception as e:  # noqa: BLE001
        return WorkerResult(status="done", note=f"scanned; ingest warn: {e}")
    return WorkerResult(status="done", result_ref=f"service_scan:{host}",
                        note=f"ports={len(r.get('open_ports', []))}", steps=1)


def _run_vuln_scan(task: Task, board: Board, wid: str) -> WorkerResult:
    from ..scanning import active_scan
    host = task.target_id
    r = active_scan.vuln_scan(host)
    bad = _unavailable(r)
    if bad:
        return WorkerResult(status="failed", note=bad)
    try:
        active_scan.ingest_scan_to_graph(host, {"ip": host, "open_ports": []}, r)
    except Exception:  # noqa: BLE001
        pass
    return WorkerResult(status="done", result_ref=f"vuln_scan:{host}",
                        note=f"findings={r.get('finding_count', 0)}", steps=1)


def _run_web_crawl(task: Task, board: Board, wid: str) -> WorkerResult:
    from ..scanning import webapp
    host = task.target_id
    try:
        r = webapp.crawl(host)            # crawl auto-ingests endpoints to the graph
    except Exception as e:  # noqa: BLE001 - e.g. NotAuthorized
        return WorkerResult(status="failed", note=str(e))
    return WorkerResult(status="done", result_ref=f"web_crawl:{host}",
                        note=f"endpoints={r.get('endpoint_count', 0)}", steps=1)


def _mark_probed(url: str) -> None:
    try:
        from ..graph import model
        model.mark_endpoint_probed(url)
    except Exception:  # noqa: BLE001 - marker is best-effort (coverage convergence)
        pass


def _run_test_injection(task: Task, board: Board, wid: str) -> WorkerResult:
    from ..scanning import webapp
    try:
        r = webapp.test_injection(task.target_id)
    except Exception as e:  # noqa: BLE001
        return WorkerResult(status="failed", note=str(e))
    _mark_probed(task.target_id)
    n = len(r.get("findings", []))
    return WorkerResult(status="done", result_ref=f"test_injection:{task.target_id}",
                        note=f"verdict={r.get('verdict')} findings={n}", steps=1)


def _run_test_access_control(task: Task, board: Board, wid: str) -> WorkerResult:
    from ..scanning import webapp
    try:
        r = webapp.test_access_control(task.target_id)
    except Exception as e:  # noqa: BLE001
        return WorkerResult(status="failed", note=str(e))
    _mark_probed(task.target_id)
    n = len(r.get("findings", []))
    return WorkerResult(status="done", result_ref=f"test_access_control:{task.target_id}",
                        note=f"verdict={r.get('verdict')} findings={n}", steps=1)


def _run_content_discovery(task: Task, board: Board, wid: str) -> WorkerResult:
    """Deeper endpoint enumeration (gobuster/ffuf), ingesting hits as WebEndpoints so
    new injection/access-control frontier tasks spawn — the persistence deepening step."""
    from ..scanning import active_scan
    from ..graph import model
    host = task.target_id
    try:
        r = active_scan.content_discovery(host)
    except Exception as e:  # noqa: BLE001
        return WorkerResult(status="failed", note=str(e))
    bad = _unavailable(r)
    if bad:
        return WorkerResult(status="failed", note=bad)
    found = r.get("found", []) or []
    base = host if "://" in host else f"https://{host}"
    for item in found:
        path = item.get("path") if isinstance(item, dict) else str(item)
        if not path:
            continue
        url = base.rstrip("/") + "/" + path.lstrip("/")
        try:
            model.upsert_web_endpoint(host, url, status=(item.get("status") if isinstance(item, dict) else None))
        except Exception:  # noqa: BLE001
            pass
    return WorkerResult(status="done", result_ref=f"content_discovery:{host}",
                        note=f"paths={len(found)}", steps=1)


def default_runners() -> dict[str, Runner]:
    """The deterministic runner registry: task kind -> existing-tool runner, merged
    with the Phase-8 verification runners (cve_lookup/cve_verify/tls_audit/
    default_login_check/exposed_artifact_check/http_verb_tampering/
    datastore_unauth_probe/service_probe) so discovered leads get verified."""
    reg: dict[str, Runner] = {
        "subdomain_enum": _run_subdomain_enum,
        "service_scan": _run_service_scan,
        "port_scan": _run_service_scan,
        "vuln_scan": _run_vuln_scan,
        "web_crawl": _run_web_crawl,
        "content_discovery": _run_content_discovery,
        "test_injection": _run_test_injection,
        "test_access_control": _run_test_access_control,
    }
    try:
        from .verify_runners import verify_runners
        reg.update(verify_runners())
    except Exception:  # noqa: BLE001 - verification layer optional
        pass
    return reg


def make_tool_worker(runners: dict[str, Runner] | None = None,
                     block_unrunnable: bool = True) -> WorkerFn:
    """Build a deterministic ``WorkerFn`` that runs the existing tools per task kind.

    Kinds with no deterministic runner (exploit/priv_esc/lateral) are returned as
    ``blocked`` by default (they need the LLM agent worker, wired in Phase 5) so a
    pure tool-only fleet parks them cleanly instead of thrashing retries. Set
    ``block_unrunnable=False`` to surface them as ``failed`` (e.g. when a composite
    worker will route them to an agent)."""
    reg = runners if runners is not None else default_runners()

    def _worker(task: Task, board: Board, worker_id: str) -> WorkerResult:
        runner = reg.get(task.kind)
        if runner is None:
            if block_unrunnable:
                return WorkerResult(status="blocked",
                                    note=f"kind '{task.kind}' needs an agent specialist")
            return WorkerResult(status="failed",
                                note=f"no deterministic runner for kind '{task.kind}'")
        return runner(task, board, worker_id)

    return _worker
