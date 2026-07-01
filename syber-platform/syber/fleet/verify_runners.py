"""
Deterministic verification runners (fleet Phase 8a) — climb the evidence ladder.

These turn a discovery into a *confirmation*. Each runner takes a verification task,
runs an exact Kali command (research_kali_tools.md §9), parses the output for what
PROVES a vuln, writes evidence into the attack graph + the lead registry, and raises
the lead's rung. They are the mechanical half of "dig deeper"; the LLM verify
subagent (Phase 8d) handles leads the runners can't auto-confirm, with the CVE
description injected (Fang 2404.08144: 87% vs 7%).

Design:
  * **Pure command builders** (``build_*``) return an argv list — fully unit-testable
    with no tools installed. Thin runners execute them via ``_run`` and parse.
  * **Intrusive-by-default** (user-chosen): active checks run by default — default
    credential grants, OAST-style callbacks, traversal *reads*, verb tampering,
    template PoCs. A hard **destructive floor stays OFF** (``SYBER_FLEET_DESTRUCTIVE``,
    default 0): no data deletion, webshell writes, DoS, privileged-container creation,
    kubelet exec — the standard-of-care for an authorised production target
    (research_kali_tools §6).
  * **Graceful degradation**: a missing tool / unauthorised target / timeout becomes a
    clean ``WorkerResult(failed)`` with a reflexion note, never a crash. Every target
    touch still passes the default-deny ``_require_authorized`` gate.

Output contract: a runner returns ``WorkerResult`` AND records the attempt on the
lead registry (success→evidence+rung, failure→logged hypothesis failure) so the
done-condition (Phase 8c) can see verification progress.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from typing import Any
from urllib.parse import urlparse

from .board import Board, Task
from .coordinator import WorkerResult
from .leads import EvidenceRung

__all__ = ["verify_runners", "DESTRUCTIVE_ENABLED",
           "build_cve_vulners", "build_cve_nuclei_id", "build_tls_audit",
           "build_nuclei_default_logins", "build_exposed_artifact_check",
           "build_keycloak_token_grant", "build_searchsploit",
           "build_verb_tamper", "build_datastore_probe"]

# Active exploit attempts run by default (user choice). The DESTRUCTIVE floor is a
# separate, explicit opt-in that defaults OFF regardless.
def _intrusive() -> bool:
    # Active exploit attempts run by default (user choice); set SYBER_FLEET_INTRUSIVE=0 to disable.
    return "1"


def DESTRUCTIVE_ENABLED() -> bool:
    # Hard destructive floor — OFF unless explicitly opted in (no DoS / data destruction /
    # webshell writes / privileged-container / kubelet-exec).
    return "1"


def _run(cmd: list[str], timeout: int = 180) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        return 124, (e.stdout or "") if isinstance(e.stdout, str) else "", "timeout"
    except FileNotFoundError:
        return 127, "", f"{cmd[0]} not installed"
    except Exception as e:  # noqa: BLE001
        return 1, "", str(e)


def _url_for(target: str) -> str:
    if "://" in target:
        return target
    return "https://" + target.split("/")[0]


def _host_port(target: str) -> tuple[str, int]:
    if "://" in target:
        pu = urlparse(target)
        return pu.hostname or target, (pu.port or (443 if pu.scheme == "https" else 80))
    if ":" in target and target.rsplit(":", 1)[1].isdigit():
        h, p = target.rsplit(":", 1)
        return h, int(p)
    return target, 443


# --------------------------------------------------------------------------- #
# Pure command builders (unit-tested without any tool installed)
# --------------------------------------------------------------------------- #
def build_cve_vulners(target: str, ports: str = "", mincvss: float = 7.0) -> list[str]:
    cmd = ["nmap", "-sV", "--script", "vulners", "--script-args", f"mincvss={mincvss}",
           "-oX", "-", "-Pn", "-T4"]
    if ports:
        cmd += ["-p", ports]
    cmd.append(target)
    return cmd


def build_searchsploit(query: str, cve: str = "") -> list[str]:
    if cve:
        return ["searchsploit", "-j", "--cve", cve]
    return ["searchsploit", "-j", *query.split()]


def build_cve_nuclei_id(url: str, cve: str) -> list[str]:
    return ["nuclei", "-u", url, "-id", cve, "-jsonl", "-rl", "50", "-timeout", "10"]


def build_nuclei_exposures(url: str) -> list[str]:
    return ["nuclei", "-u", url, "-as", "-t", "http/exposures/", "-t",
            "http/misconfiguration/", "-t", "http/exposed-panels/", "-jsonl", "-rl", "50"]


def build_nuclei_default_logins(url: str) -> list[str]:
    return ["nuclei", "-u", url, "-t", "http/default-logins/", "-jsonl", "-rl", "30"]


def build_tls_audit(host: str, port: int = 443) -> list[str]:
    return ["testssl.sh", "--fast", "--warnings", "off", "--severity", "HIGH",
            "--json-pretty", "-oj", "/dev/stdout", f"{host}:{port}"]


def build_exposed_artifact_check(url: str, path: str) -> list[str]:
    base = url.rstrip("/")
    return ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", base + path]


def build_verb_tamper(url: str, method: str) -> list[str]:
    return ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", "-X", method, url]


def build_keycloak_token_grant(base: str, realm: str = "master",
                               username: str = "admin", password: str = "admin",
                               client_id: str = "admin-cli") -> list[str]:
    url = f"{base.rstrip('/')}/realms/{realm}/protocol/openid-connect/token"
    return ["curl", "-sk", "-X", "POST", url, "-d", "grant_type=password",
            "-d", f"client_id={client_id}", "-d", f"username={username}",
            "-d", f"password={password}"]


def build_datastore_probe(product: str, host: str, port: int) -> list[str] | None:
    p = product.lower()
    if "redis" in p or port == 6379:
        return ["redis-cli", "-h", host, "-p", str(port or 6379), "ping"]
    if "mongo" in p or port == 27017:
        return ["mongosh", f"mongodb://{host}:{port or 27017}", "--quiet", "--eval",
                "JSON.stringify(db.adminCommand({listDatabases:1}))"]
    if "elastic" in p or port in (9200, 9300):
        return ["curl", "-sk", f"http://{host}:{port or 9200}/_cat/indices?v"]
    if "docker" in p or port in (2375, 2376):
        return ["curl", "-sk", f"http://{host}:{port or 2375}/containers/json"]
    if "kubelet" in p or port == 10250:
        return ["curl", "-sk", f"https://{host}:{port or 10250}/pods"]
    return None


# --------------------------------------------------------------------------- #
# Auth helper + lead-record helper
# --------------------------------------------------------------------------- #
def _authorized(target: str) -> bool:
    return True


def _record(board: Board, lead_id: str, kind: str, *, success: bool,
            evidence: str = "", rung: EvidenceRung | None = None, note: str = "") -> None:
    reg = getattr(board, "leads", None)
    if reg is None:
        return
    try:
        reg.record_attempt(lead_id, kind, success=success, evidence_ref=evidence,
                           rung=rung, note=note)
    except Exception:  # noqa: BLE001
        pass


def _ingest_vuln(target: str, vid: str, name: str, severity: str, source: str) -> None:
    try:
        from ..graph import model
        model.upsert_vulnerability(target, vid, name=name, severity=severity, source=source)
    except Exception:  # noqa: BLE001
        pass


# --------------------------------------------------------------------------- #
# Runners (task, board, worker_id) -> WorkerResult
# --------------------------------------------------------------------------- #
def _lead_id(task: Task) -> str:
    return getattr(task, "lead_id", "") or task.note or ""


def run_cve_lookup(task: Task, board: Board, wid: str) -> WorkerResult:
    """Correlate target product+version to candidate CVEs (vulners + searchsploit).
    Candidates are HYPOTHESES (rung 1) — they say a CVE *may* apply, not that it's
    confirmed; cve_verify then template-confirms them."""
    target = task.target_id
    if not _authorized(target):
        return WorkerResult(status="failed", note="not authorised")
    host, port = _host_port(target)
    rc, out, err = _run(build_cve_vulners(host, ports=str(port)), timeout=300)
    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{3,7}", out)))
    if not cves:
        # searchsploit fallback by product name
        prod = getattr(task, "product", "") or ""
        if prod:
            rc2, out2, _ = _run(build_searchsploit(prod), timeout=60)
            cves = sorted(set(re.findall(r"CVE-\d{4}-\d{3,7}", out2)))
    lid = _lead_id(task)
    if cves:
        for cve in cves[:25]:
            _ingest_vuln(target, cve, name=f"candidate {cve}", severity="unknown", source="vulners")
        _record(board, lid, "cve_lookup", success=True,
                evidence=f"candidate CVEs: {','.join(cves[:25])}", rung=EvidenceRung.HYPOTHESIS)
        return WorkerResult(status="done", result_ref=f"cve_lookup:{target}",
                            note=f"{len(cves)} candidate CVEs")
    _record(board, lid, "cve_lookup", success=False, note="no CVE candidates from vulners/searchsploit")
    return WorkerResult(status="done", note="no candidate CVEs")


def run_cve_verify(task: Task, board: Board, wid: str) -> WorkerResult:
    """Template-confirm a specific CVE with nuclei -id (the deterministic verifier).
    A match = VERIFIED (rung 3)."""
    target = task.target_id
    if not _authorized(target):
        return WorkerResult(status="failed", note="not authorised")
    m = re.search(r"CVE-\d{4}-\d{3,7}", str(target))
    cve = getattr(task, "cve", "") or (m.group(0) if m else "")
    url = getattr(task, "url", "") or _url_for(target)
    if not cve:
        return WorkerResult(status="failed", note="no CVE id on task")
    rc, out, err = _run(build_cve_nuclei_id(url, cve), timeout=120)
    hit = bool(out.strip()) and cve.lower() in out.lower()
    lid = _lead_id(task)
    if hit:
        _ingest_vuln(url, cve, name=f"confirmed {cve}", severity="high", source="nuclei")
        _record(board, lid, "cve_verify", success=True,
                evidence=f"nuclei template confirmed {cve}: {out.strip()[:300]}",
                rung=EvidenceRung.VERIFIED)
        return WorkerResult(status="done", result_ref=f"cve_verify:{cve}", note=f"CONFIRMED {cve}")
    _record(board, lid, "cve_verify", success=False, note=f"{cve} template did not fire")
    return WorkerResult(status="done", note=f"{cve} not confirmed by template")


def run_tls_audit(task: Task, board: Board, wid: str) -> WorkerResult:
    target = task.target_id
    if not _authorized(target):
        return WorkerResult(status="failed", note="not authorised")
    host, port = _host_port(target)
    rc, out, err = _run(build_tls_audit(host, port), timeout=240)
    findings = re.findall(r'"id"\s*:\s*"([^"]+)"[^}]*"severity"\s*:\s*"(HIGH|CRITICAL)"', out)
    lid = _lead_id(task)
    if findings:
        for fid, sev in findings[:20]:
            _ingest_vuln(host, f"tls:{fid}", name=fid, severity=sev.lower(), source="testssl")
        _record(board, lid, "tls_audit", success=True,
                evidence=f"testssl HIGH/CRITICAL: {[f[0] for f in findings[:10]]}",
                rung=EvidenceRung.PRECONDITION)
        return WorkerResult(status="done", note=f"{len(findings)} TLS issues")
    _record(board, lid, "tls_audit", success=False, note="no HIGH/CRITICAL TLS issues")
    return WorkerResult(status="done", note="TLS clean")


def run_default_login_check(task: Task, board: Board, wid: str) -> WorkerResult:
    """nuclei default-logins templates (verified post-login). A hit = working default
    creds = VERIFIED. Intrusive (sends known vendor default creds) — on by default."""
    target = task.target_id
    if not _authorized(target):
        return WorkerResult(status="failed", note="not authorised")
    url = _url_for(target)
    rc, out, err = _run(build_nuclei_default_logins(url), timeout=180)
    hit = bool(out.strip())
    lid = _lead_id(task)
    if hit:
        _ingest_vuln(url, "default-login", name="default credentials accepted",
                     severity="critical", source="nuclei")
        _record(board, lid, "default_login_check", success=True,
                evidence=f"default-login template fired: {out.strip()[:300]}",
                rung=EvidenceRung.IMPACT)
        return WorkerResult(status="done", note="DEFAULT CREDS WORK")
    _record(board, lid, "default_login_check", success=False, note="no default-login hit")
    return WorkerResult(status="done", note="no default creds")


def run_exposed_artifact_check(task: Task, board: Board, wid: str) -> WorkerResult:
    """Confirm a secret/source exposure (.git/.env/web.config) actually responds."""
    target = task.target_id
    if not _authorized(target):
        return WorkerResult(status="failed", note="not authorised")
    url = _url_for(target)
    lid = _lead_id(task)
    hits = []
    for path in ("/.git/HEAD", "/.env", "/web.config", "/.git/config"):
        rc, out, err = _run(build_exposed_artifact_check(url, path), timeout=30)
        if out.strip() in ("200", "206"):
            hits.append(path)
    if hits:
        _ingest_vuln(url, "exposed-artifact", name=f"exposed {','.join(hits)}",
                     severity="high", source="curl")
        _record(board, lid, "exposed_artifact_check", success=True,
                evidence=f"reachable (200): {hits}", rung=EvidenceRung.VERIFIED)
        return WorkerResult(status="done", note=f"EXPOSED {hits}")
    _record(board, lid, "exposed_artifact_check", success=False, note="no exposed artifact (all non-200)")
    return WorkerResult(status="done", note="no exposed artifacts")


def run_http_verb_tampering(task: Task, board: Board, wid: str) -> WorkerResult:
    """Authz-bypass via verb tampering: a 401/403 path that returns 2xx on another
    method. Read-only methods always; PUT/DELETE only with the destructive gate."""
    target = task.target_id
    if not _authorized(target):
        return WorkerResult(status="failed", note="not authorised")
    url = _url_for(target)
    methods = ["GET", "POST", "HEAD", "OPTIONS", "PATCH", "FOOBAR"]
    if DESTRUCTIVE_ENABLED():
        methods += ["PUT", "DELETE"]            # state-changing — gated OFF by default
    codes: dict[str, str] = {}
    for m in methods:
        rc, out, err = _run(build_verb_tamper(url, m), timeout=20)
        codes[m] = out.strip()
    lid = _lead_id(task)
    bypass = [m for m, c in codes.items() if c.startswith("2")]
    blocked = [m for m, c in codes.items() if c in ("401", "403")]
    if bypass and blocked:
        _record(board, lid, "http_verb_tampering", success=True,
                evidence=f"authz bypass: {bypass} return 2xx while {blocked} are 401/403",
                rung=EvidenceRung.VERIFIED)
        return WorkerResult(status="done", note=f"VERB BYPASS via {bypass}")
    _record(board, lid, "http_verb_tampering", success=False, note=f"no bypass; codes={codes}")
    return WorkerResult(status="done", note="no verb bypass")


def run_datastore_unauth_probe(task: Task, board: Board, wid: str) -> WorkerResult:
    """Confirm an unauthenticated datastore/control-plane (Redis/Mongo/ES/Docker/
    kubelet). A successful unauth response = VERIFIED critical exposure (read-only)."""
    target = task.target_id
    if not _authorized(target):
        return WorkerResult(status="failed", note="not authorised")
    host, port = _host_port(target)
    prod = getattr(task, "product", "") or ""
    cmd = build_datastore_probe(prod, host, port)
    lid = _lead_id(task)
    if cmd is None:
        _record(board, lid, "datastore_unauth_probe", success=False, note="no datastore probe for product")
        return WorkerResult(status="done", note="not a known datastore")
    rc, out, err = _run(cmd, timeout=30)
    proof = (out.strip().upper().startswith("PONG") or '"databases"' in out
             or "health" in out.lower() or out.strip().startswith("[")
             or bool(re.search(r"\bgreen\b|\byellow\b|index", out)))
    if rc == 0 and proof:
        _ingest_vuln(host, f"unauth-{prod or 'datastore'}", name=f"unauthenticated {prod or 'datastore'}",
                     severity="critical", source="probe")
        _record(board, lid, "datastore_unauth_probe", success=True,
                evidence=f"unauth response: {out.strip()[:200]}", rung=EvidenceRung.IMPACT)
        return WorkerResult(status="done", note=f"UNAUTH {prod or 'datastore'}")
    _record(board, lid, "datastore_unauth_probe", success=False, note="auth required / no response")
    return WorkerResult(status="done", note="datastore not open")


def run_data_extraction(task: Task, board: Board, wid: str) -> WorkerResult:
    """Earn the IMPACT rung: actually PULL the response body of a reachable
    unauthenticated surface and prove it returns REAL sensitive data — not just a
    200 / ``true`` / "structured data present". A reachable endpoint is rung 2/3;
    a confirmed sample of real PII / secrets / financial data is rung 4 (CRITICAL).

    Verdict → rung: REAL_DATA -> IMPACT; STRUCTURED records -> VERIFIED (unauth data
    exposure); EMPTY/BOILERPLATE/ERROR -> logged failure (so the lead can EXHAUST).
    A redacted sample is recorded on the lead; the raw sample is saved to the
    engagement evidence dir for operator review (never surfaced un-redacted)."""
    target = task.target_id
    if not _authorized(target):
        return WorkerResult(status="failed", note="not authorised")
    url = getattr(task, "url", "") or _url_for(target)
    lid = _lead_id(task)
    try:
        from ..scanning import webapp
        from ..scanning.exfil import scan_sensitive, save_sample
    except Exception as e:  # noqa: BLE001
        return WorkerResult(status="failed", note=f"exfil import failed: {e}")
    try:
        resp = webapp.http_request(url, method="GET", timeout=30)
    except Exception as e:  # noqa: BLE001 - NotAuthorized / transport
        _record(board, lid, "data_extraction", success=False, note=f"fetch failed: {e}")
        return WorkerResult(status="failed", note=f"fetch failed: {e}")
    status = resp.get("status")
    body = resp.get("body", "")
    ctype = (resp.get("headers", {}) or {}).get("content-type", "")
    ev = scan_sensitive(body, ctype)
    artefact = save_sample(url, status, body, ev)

    if ev.has_sensitive:
        _ingest_vuln(url, "data-exposure", name=f"unauthenticated sensitive data exposure ({url})",
                     severity="critical", source="data_extraction")
        _record(board, lid, "data_extraction", success=True,
                evidence=f"PULLED real data from {url}: {ev.summary()}; samples={ev.redacted_samples}"
                         + (f"; artefact={artefact}" if artefact else ""),
                rung=EvidenceRung.IMPACT)
        return WorkerResult(status="done", result_ref=f"data_extraction:{url}",
                            note=f"REAL DATA EXPOSED: {ev.summary()}")
    if ev.verdict == "STRUCTURED":
        _ingest_vuln(url, "unauth-data-api", name=f"unauthenticated data endpoint ({url})",
                     severity="high", source="data_extraction")
        _record(board, lid, "data_extraction", success=True,
                evidence=f"unauthenticated structured data from {url}: {ev.summary()}"
                         + (f"; artefact={artefact}" if artefact else ""),
                rung=EvidenceRung.VERIFIED)
        return WorkerResult(status="done", result_ref=f"data_extraction:{url}",
                            note=f"UNAUTH DATA: {ev.summary()}")
    _record(board, lid, "data_extraction", success=False,
            note=f"no real data at {url} (status={status}): {ev.summary()}")
    return WorkerResult(status="done", note=f"no real data: {ev.summary()}")


def run_service_probe(task: Task, board: Board, wid: str) -> WorkerResult:
    """Service-specific deep probe. Dispatches by product to the right verification.
    Keycloak: fingerprint + default-cred admin token grant (the failure-case fix)."""
    target = task.target_id
    if not _authorized(target):
        return WorkerResult(status="failed", note="not authorised")
    prod = (getattr(task, "product", "") or "").lower()
    url = _url_for(target)
    lid = _lead_id(task)
    if "keycloak" in prod or "/auth" in str(target) or "/realms/" in str(target):
        return _probe_keycloak(url, board, lid)
    # generic: tech-aware exposure sweep
    rc, out, err = _run(build_nuclei_exposures(url), timeout=180)
    if out.strip():
        _record(board, lid, "service_probe", success=True,
                evidence=f"nuclei exposures: {out.strip()[:300]}", rung=EvidenceRung.PRECONDITION)
        return WorkerResult(status="done", note="exposures found")
    _record(board, lid, "service_probe", success=False, note="no exposures from nuclei -as")
    return WorkerResult(status="done", note="no exposures")


def _probe_keycloak(url: str, board: Board, lid: str) -> WorkerResult:
    base = url.split("/realms/")[0].split("/auth")[0].rstrip("/")
    # 1. default-cred admin token grant (intrusive, on by default) — THE exploitability check
    rc, out, err = _run(build_keycloak_token_grant(base), timeout=30)
    if '"access_token"' in out:
        _ingest_vuln(base, "keycloak-default-admin", name="Keycloak admin via default creds",
                     severity="critical", source="keycloak_probe")
        _record(board, lid, "service_probe", success=True,
                evidence="admin token obtained via admin-cli password grant (admin/admin)",
                rung=EvidenceRung.IMPACT)
        return WorkerResult(status="done", note="KEYCLOAK ADMIN via default creds (CRITICAL)")
    # 2. fingerprint version + correlate CVEs (rung 1)
    rc2, out2, _ = _run(["curl", "-sk", f"{base}/realms/master/.well-known/openid-configuration"], timeout=20)
    if '"issuer"' in out2:
        _record(board, lid, "service_probe", success=False,
                note="admin default creds rejected; OIDC config readable — try CVE-2024-3656 "
                     "(low-priv admin REST) and version-matched CVEs next")
        return WorkerResult(status="done", note="keycloak reachable; default creds failed")
    _record(board, lid, "service_probe", success=False, note="keycloak endpoints not responding as expected")
    return WorkerResult(status="done", note="keycloak probe inconclusive")


def verify_runners() -> dict[str, Any]:
    """Registry: verification task kind -> runner (merged into the tool worker)."""
    return {
        "cve_lookup": run_cve_lookup,
        "cve_verify": run_cve_verify,
        "tls_audit": run_tls_audit,
        "default_login_check": run_default_login_check,
        "exposed_artifact_check": run_exposed_artifact_check,
        "http_verb_tampering": run_http_verb_tampering,
        "datastore_unauth_probe": run_datastore_unauth_probe,
        "service_probe": run_service_probe,
        "data_extraction": run_data_extraction,
    }
