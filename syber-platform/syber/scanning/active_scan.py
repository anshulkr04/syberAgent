"""
Active scanning engine — for AUTHORISED targets only (spec: response/recon §13).

Wraps real security tools with authorization enforcement, timeouts, structured
parsing, and knowledge-graph ingestion. Designed to run inside the Kali Linux
container (infra/kali) where all tools are present; on hosts missing a tool it
degrades gracefully (and uses a pure-python TCP connect scanner for ports).

Tools used (all standard, present in Kali):
  nmap     -> port + service/version + default NSE scripts
  nikto    -> web server vulnerability scan
  gobuster -> content/directory discovery (ffuf fallback)
  nuclei   -> templated vulnerability scan
  sslscan  -> TLS configuration (optional)

Every scan calls _require_authorized(target) first. Default-deny.
"""
from __future__ import annotations

import json
import shutil
import socket
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .authorization import get_auth_store

# Reasonable common-port set for the pure-python fallback scanner.
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445,
                465, 587, 993, 995, 1433, 1723, 2049, 3306, 3389, 5432, 5900,
                5985, 6379, 8000, 8080, 8443, 8888, 9200, 11211, 27017]

# A small built-in wordlist so content discovery works without system wordlists.
BUILTIN_WORDLIST = [
    "admin", "login", "dashboard", "api", "uploads", "backup", "config", "test",
    ".git", ".env", "robots.txt", "sitemap.xml", "wp-admin", "phpinfo.php",
    "server-status", "actuator", "swagger", "graphql", ".well-known/security.txt",
]


class NotAuthorized(Exception):
    pass


def _require_authorized(target: str) -> None:
    allowed, reason = get_auth_store().is_authorized(target)
    if not allowed:
        raise NotAuthorized(f"Active scan of '{target}' refused: {reason}")
    from ..audit.log import get_audit_log
    get_audit_log().write("active_scan_authorized", {"target": target, "reason": reason}, "scan_guard")


def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


def _run(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        return 124, (e.stdout or "") if isinstance(e.stdout, str) else "", "timeout"
    except FileNotFoundError:
        return 127, "", "tool not found"


# --------------------------------------------------------------------------- #
# Port scan
# --------------------------------------------------------------------------- #
def port_scan(target: str, ports: str | None = None, timeout: int = 300) -> dict[str, Any]:
    """nmap TCP connect scan (no root needed). Falls back to a python scanner."""
    _require_authorized(target)
    if _have("nmap"):
        cmd = ["nmap", "-sT", "-Pn", "-T4", "-oX", "-"]
        cmd += ["-p", ports] if ports else ["--top-ports", "1000"]
        cmd.append(target)
        rc, out, err = _run(cmd, timeout)
        if rc in (0, 1) and out.strip().startswith("<?xml"):
            return {"tool": "nmap", "target": target, **_parse_nmap_xml(out)}
        return {"tool": "nmap", "target": target, "error": err or "nmap failed",
                "fallback": _python_port_scan(target, ports)}
    return {"tool": "python-tcp-connect", "target": target, **_python_port_scan(target, ports)}


def _python_port_scan(target: str, ports: str | None) -> dict[str, Any]:
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror as e:
        return {"error": f"DNS resolution failed: {e}", "open_ports": []}
    port_list = _expand_ports(ports) if ports else COMMON_PORTS

    def check(p: int) -> int | None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        try:
            return p if s.connect_ex((ip, p)) == 0 else None
        finally:
            s.close()

    open_ports = []
    with ThreadPoolExecutor(max_workers=100) as pool:
        for r in pool.map(check, port_list):
            if r is not None:
                open_ports.append({"port": r, "protocol": "tcp", "state": "open",
                                   "service": _guess_service(r)})
    return {"ip": ip, "open_ports": sorted(open_ports, key=lambda x: x["port"]),
            "ports_checked": len(port_list)}


def _parse_nmap_xml(xml: str) -> dict[str, Any]:
    root = ET.fromstring(xml)
    hosts_out = []
    for host in root.findall("host"):
        addr = next((a.get("addr") for a in host.findall("address")
                     if a.get("addrtype") in ("ipv4", "ipv6")), None)
        state = host.find("status")
        ports = []
        for port in host.findall("./ports/port"):
            st = port.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = port.find("service")
            scripts = [{"id": s.get("id"), "output": (s.get("output") or "")[:500]}
                       for s in port.findall("script")]
            ports.append({
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "state": "open",
                "service": (svc.get("name") if svc is not None else None),
                "product": (svc.get("product") if svc is not None else None),
                "version": (svc.get("version") if svc is not None else None),
                "cpe": [c.text for c in (svc.findall("cpe") if svc is not None else [])],
                "scripts": scripts,
            })
        hosts_out.append({"ip": addr, "state": (state.get("state") if state is not None else None),
                          "open_ports": ports})
    primary = hosts_out[0] if hosts_out else {"open_ports": []}
    return {"ip": primary.get("ip"), "host_state": primary.get("state"),
            "open_ports": primary.get("open_ports", []), "hosts": hosts_out}


# --------------------------------------------------------------------------- #
# Service / version + NSE default scripts
# --------------------------------------------------------------------------- #
def service_scan(target: str, ports: str | None = None, timeout: int = 420) -> dict[str, Any]:
    """nmap -sV -sC: service versions + safe default NSE scripts."""
    _require_authorized(target)
    if not _have("nmap"):
        return {"tool": "nmap", "available": False, "note": "nmap not installed; use port_scan fallback"}
    cmd = ["nmap", "-sT", "-sV", "-sC", "-Pn", "-T4", "-oX", "-"]
    cmd += ["-p", ports] if ports else ["--top-ports", "200"]
    cmd.append(target)
    rc, out, err = _run(cmd, timeout)
    if out.strip().startswith("<?xml"):
        return {"tool": "nmap -sV -sC", "target": target, **_parse_nmap_xml(out)}
    return {"tool": "nmap -sV -sC", "target": target, "error": err or "failed"}


# --------------------------------------------------------------------------- #
# Web vulnerability scan (nikto)
# --------------------------------------------------------------------------- #
def web_scan(target: str, timeout: int = 300) -> dict[str, Any]:
    _require_authorized(target)
    if not _have("nikto"):
        return {"tool": "nikto", "available": False, "note": "nikto not installed"}
    url = _as_url(target)
    rc, out, err = _run(["nikto", "-h", url, "-maxtime", "120s", "-Tuning", "123bde",
                         "-nointeractive"], timeout)
    findings = [ln.strip() for ln in (out or "").splitlines() if ln.strip().startswith("+ ")]
    return {"tool": "nikto", "target": url, "findings": findings,
            "finding_count": len(findings)}


# --------------------------------------------------------------------------- #
# Content discovery (gobuster -> ffuf -> none)
# --------------------------------------------------------------------------- #
def content_discovery(target: str, wordlist: str | None = None, timeout: int = 240) -> dict[str, Any]:
    _require_authorized(target)
    url = _as_url(target)
    wl = wordlist or _ensure_wordlist()
    if _have("gobuster"):
        rc, out, err = _run(["gobuster", "dir", "-u", url, "-w", wl, "-q", "-t", "30",
                             "--no-error", "-z"], timeout)
        paths = []
        for ln in (out or "").splitlines():
            ln = ln.strip()
            if ln.startswith("/"):
                parts = ln.split()
                paths.append({"path": parts[0], "info": " ".join(parts[1:])[:120]})
        return {"tool": "gobuster", "target": url, "wordlist": wl, "found": paths,
                "found_count": len(paths)}
    if _have("ffuf"):
        with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False) as tf:
            out_file = tf.name
        _run(["ffuf", "-u", f"{url}/FUZZ", "-w", wl, "-of", "json", "-o", out_file,
              "-mc", "200,204,301,302,307,401,403", "-s"], timeout)
        try:
            data = json.loads(open(out_file).read())
            paths = [{"path": "/" + r["input"]["FUZZ"], "status": r["status"]}
                     for r in data.get("results", [])]
        except (json.JSONDecodeError, FileNotFoundError, KeyError):
            paths = []
        return {"tool": "ffuf", "target": url, "found": paths, "found_count": len(paths)}
    return {"tool": "content_discovery", "available": False, "note": "gobuster/ffuf not installed"}


# --------------------------------------------------------------------------- #
# Templated vulnerability scan (nuclei)
# --------------------------------------------------------------------------- #
def vuln_scan(target: str, severity: str = "low,medium,high,critical", timeout: int = 420) -> dict[str, Any]:
    _require_authorized(target)
    if not _have("nuclei"):
        return {"tool": "nuclei", "available": False, "note": "nuclei not installed"}
    url = _as_url(target)
    rc, out, err = _run(["nuclei", "-u", url, "-jsonl", "-silent", "-severity", severity,
                         "-rate-limit", "50", "-timeout", "8"], timeout)
    findings = []
    for ln in (out or "").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            f = json.loads(ln)
            info = f.get("info", {})
            findings.append({"template": f.get("template-id"), "name": info.get("name"),
                             "severity": info.get("severity"), "matched_at": f.get("matched-at")})
        except json.JSONDecodeError:
            continue
    return {"tool": "nuclei", "target": url, "findings": findings, "finding_count": len(findings)}


# --------------------------------------------------------------------------- #
# Orchestrated full scan + graph ingestion
# --------------------------------------------------------------------------- #
def full_scan(target: str, do_web: bool = True, timeout_each: int = 300) -> dict[str, Any]:
    """Port + service scan; if web ports are open, content discovery + nuclei.
    Ingests the result into the knowledge graph (Neo4j when configured)."""
    _require_authorized(target)
    result: dict[str, Any] = {"target": target, "stages": {}}
    svc = service_scan(target, timeout=timeout_each + 120)
    if "open_ports" not in svc:  # nmap absent -> fall back to plain port scan
        svc = port_scan(target, timeout=timeout_each)
    result["stages"]["service_scan"] = svc

    open_ports = svc.get("open_ports", [])
    web_open = any(p["port"] in (80, 443, 8080, 8443, 8000, 8888) for p in open_ports)
    if do_web and web_open:
        result["stages"]["content_discovery"] = content_discovery(target, timeout=timeout_each)
        result["stages"]["vuln_scan"] = vuln_scan(target, timeout=timeout_each + 120)

    result["graph"] = ingest_scan_to_graph(target, svc, result["stages"].get("vuln_scan"))
    result["summary"] = _summarise(target, result)
    return result


def ingest_scan_to_graph(target: str, port_result: dict[str, Any],
                         vuln_result: dict[str, Any] | None = None) -> dict[str, Any]:
    """Write hosts/ports/services/vulns into the knowledge graph (spec §6)."""
    from ..graph.store import get_graph

    g = get_graph()
    ip = port_result.get("ip") or target
    host_id = target
    g.add_node(host_id, "Asset", hostname=target, ip=ip, asset_class="scanned_host")
    if ip and ip != host_id:
        g.add_node(ip, "Asset", hostname=target, ip=ip, asset_class="ip_endpoint")
        g.add_edge(host_id, ip, "RESOLVES_TO", edge_weight=1.0)

    n_ports = 0
    for p in port_result.get("open_ports", []):
        pid = f"{ip}:{p['port']}"
        g.add_node(pid, "Service", port=p["port"], protocol=p.get("protocol"),
                   service=p.get("service"), product=p.get("product"), version=p.get("version"))
        g.add_edge(ip if ip in g.g else host_id, pid, "HAS_PORT", edge_weight=0.5)
        n_ports += 1

    n_vulns = 0
    for f in (vuln_result or {}).get("findings", []):
        vid = f.get("template") or f.get("name") or "vuln"
        g.add_node(vid, "Vulnerability", cve_id=vid, name=f.get("name"),
                   severity=f.get("severity"))
        g.add_edge(host_id, vid, "HAS_VULN", edge_weight=0.3, weaponised=False)
        n_vulns += 1

    return {"host": host_id, "ip": ip, "ports_ingested": n_ports, "vulns_ingested": n_vulns,
            "backend": type(g).__name__}


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _summarise(target: str, result: dict[str, Any]) -> dict[str, Any]:
    svc = result["stages"].get("service_scan", {})
    ports = svc.get("open_ports", [])
    vulns = result["stages"].get("vuln_scan", {}).get("findings", [])
    return {
        "open_port_count": len(ports),
        "open_ports": [f"{p['port']}/{p.get('service') or '?'}"
                       + (f" ({p.get('product')} {p.get('version') or ''})".rstrip() if p.get("product") else "")
                       for p in ports],
        "vuln_count": len(vulns),
        "vuln_severities": _severity_tally(vulns),
    }


def _severity_tally(vulns: list[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for v in vulns:
        s = v.get("severity", "unknown")
        out[s] = out.get(s, 0) + 1
    return out


def _as_url(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return target
    return "http://" + target


def _expand_ports(spec: str) -> list[int]:
    out: list[int] = []
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-", 1)
            out.extend(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    return out


def _ensure_wordlist() -> str:
    for candidate in ("/usr/share/wordlists/dirb/common.txt",
                      "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
                      "/usr/share/seclists/Discovery/Web-Content/common.txt"):
        if shutil.os.path.isfile(candidate):
            return candidate
    tf = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
    tf.write("\n".join(BUILTIN_WORDLIST))
    tf.close()
    return tf.name


_SERVICE_HINTS = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
                  80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "microsoft-ds",
                  3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc",
                  6379: "redis", 8080: "http-proxy", 8443: "https-alt", 27017: "mongodb"}


def _guess_service(port: int) -> str:
    return _SERVICE_HINTS.get(port, "unknown")
