"""
Reproduction-script generation — turn saved evidence into copy-pasteable proof.

The operator's ask: the report must let them *verify* a finding themselves, not trust
the agent's prose or a screenshot of an inaccessible page. So for every CONFIRMED
capture (a 2xx response that actually returned real/structured data) we emit the exact
`curl` command that reproduces it, plus the expected result. Inaccessible attempts
(401/403/blocked/empty) are NOT reproductions of a vulnerability and are excluded.

Pure functions over the evidence JSONs written by ``exfil.save_sample`` (which record
method/url/request-headers/status/verdict/confirmed). Unit-tested without network.
"""
from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Any

from .config import PATHS

__all__ = ["curl_for", "expected_result", "load_evidence", "build_verify_script",
           "reproductions"]


def _shq(s: str) -> str:
    return shlex.quote(str(s))


def curl_for(ev: dict[str, Any]) -> str:
    """Build the EXACT, runnable curl that reproduces a capture — real method, URL, and
    the actual request headers the agent used (so the operator can paste-and-run it).
    `-k` accepts the target cert; `-i` prints status+headers as proof."""
    method = (ev.get("method") or "GET").upper()
    url = ev.get("url", "")
    body = ev.get("request_body") or ""
    parts = ["curl", "-sk", "-i"]
    if method != "GET":
        parts += ["-X", method]
    for k, v in (ev.get("request_headers") or {}).items():
        if v:
            parts += ["-H", f"{k}: {v}"]
    if body:
        parts += ["--data-raw", str(body)]
    parts.append(url)
    return " ".join(_shq(p) if (" " in p or '"' in p or "'" in p) else p for p in parts)


def is_unauthenticated(ev: dict[str, Any]) -> bool:
    """True if the confirmed request carried no auth — the strongest finding (anyone can
    hit it). Curl reproduces it as-is with zero setup."""
    hdrs = {k.lower() for k in (ev.get("request_headers") or {})}
    return not (hdrs & {"authorization", "cookie", "x-api-key", "authtoken", "token"})


def expected_result(ev: dict[str, Any]) -> str:
    """One line telling the operator what a successful reproduction looks like."""
    status = ev.get("status")
    verdict = ev.get("verdict", "")
    cats = ev.get("categories") or {}
    if verdict == "REAL_DATA":
        what = "real sensitive data — " + ", ".join(f"{k}×{v}" for k, v in sorted(cats.items()))
        return f"HTTP {status} returning {what} (no authentication) → confirms the exposure."
    if verdict == "STRUCTURED":
        n = ev.get("record_count", "")
        return f"HTTP {status} returning {n} structured records with no authentication → confirms unauth data access."
    return f"HTTP {status}."


def load_evidence(root: Path | None = None) -> list[dict[str, Any]]:
    """Load every evidence JSON in the engagement evidence dir."""
    root = root or (PATHS.state / "evidence")
    out: list[dict[str, Any]] = []
    if not Path(root).is_dir():
        return out
    for p in sorted(Path(root).rglob("*.json")):
        try:
            out.append(json.loads(p.read_text()))
        except Exception:  # noqa: BLE001
            continue
    return out


def reproductions(root: Path | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split saved captures into (confirmed, inaccessible). A confirmed capture has a
    curl command + expected result; inaccessible ones are reported separately so a 403
    screenshot is never dressed up as a finding."""
    confirmed, inaccessible = [], []
    for ev in load_evidence(root):
        entry = {"url": ev.get("url"), "method": ev.get("method", "GET"),
                 "status": ev.get("status"), "verdict": ev.get("verdict"),
                 "curl": curl_for(ev), "expected": expected_result(ev),
                 "unauthenticated": is_unauthenticated(ev),
                 "screenshot": ev.get("screenshot"),
                 "summary": ev.get("summary", "")}
        if ev.get("confirmed"):
            confirmed.append(entry)
        else:
            inaccessible.append(entry)
    return confirmed, inaccessible


def build_verify_script(confirmed: list[dict[str, Any]], target: str = "") -> str:
    """A runnable verify.sh: each confirmed finding as a curl the operator can run to
    independently reproduce it. Only confirmed (2xx + real data) captures are included."""
    lines = [
        "#!/usr/bin/env bash",
        f"# Syber — reproduction script for {target or 'engagement'}",
        "# Each block reproduces one CONFIRMED finding. Run and compare to 'expected'.",
        "# (-k accepts the target cert; -i shows status+headers as proof.)",
        "set -u",
        "",
    ]
    if not confirmed:
        lines.append('echo "No CONFIRMED findings to reproduce — nothing returned real data under 2xx."')
        return "\n".join(lines) + "\n"
    for i, r in enumerate(confirmed, 1):
        auth = "UNAUTHENTICATED (no creds needed)" if r.get("unauthenticated") else \
               "uses the request headers below (real values included)"
        lines += [
            f"echo '=== [{i}] {r['url']} ({r['method']}) — {auth} ==='",
            f"# expected: {r['expected']}",
            r["curl"],
            'echo; echo "----------------------------------------"',
            "",
        ]
    return "\n".join(lines) + "\n"
