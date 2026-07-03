"""
Engagement reporting — assemble a verifiable report and email it with PROOFS.

The point (operator's ask): make findings *verifiable*. The report is not the agent's
prose — it is the gated findings PLUS the real artefacts that prove them: the downloaded
data samples (redacted), screenshots, and HTTP request/response captures collected during
the engagement. The operator receives it, confirms each finding is real, and forwards it
to the target organisation.

Evidence is auto-collected from the engagement evidence directory
(`.investigation_state/evidence/`, where the data-exposure verifier saves samples) plus any
explicit file paths the agent passes (e.g. screenshots it captured). Findings come from the
in-process findings sink (the same process serves the MCP tools, so they are present).
"""
from __future__ import annotations

import base64
from html import escape
from pathlib import Path
from typing import Any

from .config import PATHS
from .integrations import IntegrationError, IntegrationNotConfigured, env, resend
from .tools.findings import get_findings_sink

# Attachment guards (Resend total limit ~40 MB; base64 inflates ~33%).
_MAX_ATTACHMENTS = 25
_MAX_TOTAL_BYTES = 15 * 1024 * 1024
_PROOF_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".json", ".body",
               ".har", ".txt", ".log", ".pdf", ".html"}
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def evidence_dir() -> Path:
    return PATHS.state / "evidence"


import json as _json


def _confirmed_evidence() -> list[dict[str, Any]]:
    """Evidence JSONs whose capture is CONFIRMED (2xx + real data). Only these back a
    finding; everything else (login pages, 403s, empty responses) is excluded from proof."""
    d = evidence_dir()
    out: list[dict[str, Any]] = []
    if not d.is_dir():
        return out
    for p in sorted(d.rglob("*.json")):
        try:
            ev = _json.loads(p.read_text())
        except Exception:  # noqa: BLE001
            continue
        if ev.get("confirmed"):
            ev["_json_path"] = str(p)
            out.append(ev)
    return out


def _attach_file(path: Path, base_dir: Path, out: list, seen: set, total: list) -> None:
    rp = str(path.resolve())
    if rp in seen or not path.is_file():
        return
    seen.add(rp)
    try:
        data = path.read_bytes()
    except Exception:  # noqa: BLE001
        return
    if total[0] + len(data) > _MAX_TOTAL_BYTES or len(out) >= _MAX_ATTACHMENTS:
        return
    total[0] += len(data)
    name = f"{path.parent.name}__{path.name}" if path.parent != base_dir else path.name
    out.append({"filename": name, "content": base64.b64encode(data).decode()})


def collect_attachments(extra_paths: list[str] | None = None) -> list[dict[str, str]]:
    """Attach ONLY confirmed-tied proofs (Resend format {filename, content}): for each
    CONFIRMED capture (2xx + real data) — its evidence JSON, the raw response body, and
    its data-verified screenshot (captured logged-in; login/denied/error pages are
    rejected by capture_screenshot before they're ever saved).

    Agent-supplied `extra_paths` screenshots are DELIBERATELY IGNORED: they were the
    source of the login-page / "Access Denied" images that prove nothing. The only
    screenshots that ship are the ones the system itself captured against verified data.
    (Non-image operator files are still allowed through.)"""
    d = evidence_dir()
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    total = [0]
    confirmed = _confirmed_evidence()
    for ev in confirmed:
        jp = Path(ev["_json_path"])
        _attach_file(jp, d, out, seen, total)                       # the evidence summary
        _attach_file(jp.with_suffix(".body"), d, out, seen, total)  # the raw data returned
        shot = ev.get("screenshot")
        if shot:
            _attach_file(Path(shot), d, out, seen, total)           # the data-verified screenshot
    # operator-supplied NON-IMAGE files may ride along when real confirmed evidence exists;
    # images are never taken on trust (that's what capture-on-confirmation is for).
    if confirmed:
        for x in (extra_paths or []):
            p = Path(x)
            if p.suffix.lower() not in {".png", ".jpg", ".jpeg", ".gif", ".webp"}:
                _attach_file(p, d, out, seen, total)
    return out


def _sev_sorted(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(findings, key=lambda f: _SEV_ORDER.get(str(f.get("severity", "INFO")).upper(), 5))


def _repro_html(confirmed: list[dict[str, Any]], inaccessible: list[dict[str, Any]]) -> str:
    """The 'how to verify it yourself' section: curl per confirmed finding + an honest
    list of inaccessible attempts (which are NOT findings)."""
    if not confirmed and not inaccessible:
        return ""
    blocks = ["<h2>How to verify (reproduction)</h2>"]
    if confirmed:
        blocks.append("<p>Run each command below (or the attached <code>verify.sh</code>) to "
                      "independently reproduce a CONFIRMED finding. The commands include the exact "
                      "request that returned the data — paste and run as-is:</p>")
        for i, r in enumerate(confirmed, 1):
            auth = ("<span style='color:#b00'><b>UNAUTHENTICATED</b> — no credentials needed</span>"
                    if r.get("unauthenticated") else
                    "authenticated — the working request headers are included in the command below")
            shot = ""
            if r.get("screenshot"):
                import os as _os
                shot = (f"<br><small>Screenshot proof attached: "
                        f"<code>{escape(_os.path.basename(str(r['screenshot'])))}</code></small>")
            blocks.append(
                f"<div style='margin:8px 0'><b>[{i}] {escape(str(r['url']))}</b> — {auth}"
                f"<pre style='background:#111;color:#0f0;padding:10px;overflow:auto;white-space:pre-wrap'>"
                f"{escape(r['curl'])}</pre>"
                f"<small><b>Expected:</b> {escape(r['expected'])}</small>{shot}</div>")
    if inaccessible:
        blocks.append("<h3>Attempts that did NOT confirm (not findings)</h3>"
                      "<p><small>These endpoints were probed but returned an inaccessible / "
                      "no-data response (401/403/blocked/empty). They are listed for transparency "
                      "and are <b>not</b> vulnerabilities:</small></p><ul>")
        for r in inaccessible[:40]:
            blocks.append(f"<li><code>{escape(str(r['url']))}</code> → HTTP "
                          f"{escape(str(r['status']))} ({escape(str(r['verdict']))})</li>")
        blocks.append("</ul>")
    return "".join(blocks)


def render_html(findings: list[dict[str, Any]], target: str, attach_names: list[str],
                confirmed: list[dict[str, Any]] | None = None,
                inaccessible: list[dict[str, Any]] | None = None) -> str:
    findings = _sev_sorted(findings)
    rows = "".join(
        f"<tr><td>{i + 1}</td><td><b>{escape(str(f.get('severity', 'INFO')))}</b></td>"
        f"<td>{escape(str(f.get('summary', '') or (f.get('attack_chain') or [{}])[0].get('description', '')))}</td>"
        f"<td>{escape(', '.join(f.get('mitre_techniques', []) or []))}</td>"
        f"<td>{f.get('confidence_estimate', '')}</td></tr>"
        for i, f in enumerate(findings)) or "<tr><td colspan=5>No findings published.</td></tr>"

    def chain_block(f: dict[str, Any]) -> str:
        steps = "".join(
            f"<li>[{escape(str(s.get('status', '')))}] {escape(str(s.get('description', '')))}"
            f"{(' — ' + escape(str(s.get('mitre_technique')))) if s.get('mitre_technique') else ''}"
            f"{(' <code>' + escape(', '.join(s.get('evidence_refs', []))) + '</code>') if s.get('evidence_refs') else ''}</li>"
            for s in (f.get("attack_chain") or []))
        refs = escape(", ".join(f.get("evidence_refs", []) or []))
        return (f"<h3>{escape(str(f.get('severity')))} — {escape(str(f.get('summary', '')))}</h3>"
                f"<ul>{steps}</ul><p><small>evidence_refs: <code>{refs}</code></small></p>")

    details = "".join(chain_block(f) for f in findings)
    proofs = "".join(f"<li><code>{escape(n)}</code></li>" for n in attach_names) or "<li>(none)</li>"
    repro = _repro_html(confirmed or [], inaccessible or [])
    n_conf = len(confirmed or [])
    return f"""<div style="font-family:system-ui,Arial,sans-serif;max-width:820px">
<h2>Syber — Security Engagement Report</h2>
<p><b>Target:</b> {escape(target or 'n/a')}<br><b>Findings:</b> {len(findings)}
&nbsp;<b>Reproducible (confirmed 2xx + real data):</b> {n_conf}
&nbsp;<b>Attached proofs:</b> {len(attach_names)}</p>
<table border=1 cellpadding=6 cellspacing=0 style="border-collapse:collapse;width:100%">
<thead><tr><th>#</th><th>Severity</th><th>Finding</th><th>MITRE</th><th>Conf.</th></tr></thead>
<tbody>{rows}</tbody></table>
<h2>Details &amp; attack chains</h2>{details}
{repro}
<h2>Attached proofs</h2><ul>{proofs}</ul>
<p><small>Reproduce each confirmed finding with the curl commands above / the attached
<code>verify.sh</code>. A screenshot or capture of an inaccessible (401/403/blocked) page is
NOT a finding and is listed separately. Verify, then forward to the target organisation.
Generated by Syber.</small></p></div>"""


def render_text(findings: list[dict[str, Any]], target: str, attach_names: list[str],
                confirmed: list[dict[str, Any]] | None = None,
                inaccessible: list[dict[str, Any]] | None = None) -> str:
    confirmed, inaccessible = confirmed or [], inaccessible or []
    lines = [f"Syber — Security Engagement Report", f"Target: {target or 'n/a'}",
             f"Findings: {len(findings)} | Reproducible: {len(confirmed)} | "
             f"Attached proofs: {len(attach_names)}", ""]
    for i, f in enumerate(_sev_sorted(findings), 1):
        lines.append(f"{i}. [{f.get('severity')}] {f.get('summary', '')}")
        lines.append(f"   MITRE: {', '.join(f.get('mitre_techniques', []) or [])}"
                     f" | evidence: {', '.join(f.get('evidence_refs', []) or [])}")
    if confirmed:
        lines += ["", "HOW TO VERIFY (reproduce each confirmed finding):"]
        for i, r in enumerate(confirmed, 1):
            lines += [f"  [{i}] {r['url']}", f"      {r['curl']}", f"      expected: {r['expected']}"]
    if inaccessible:
        lines += ["", "Attempts that did NOT confirm (not findings):"]
        lines += [f"  - {r['url']} -> HTTP {r['status']} ({r['verdict']})" for r in inaccessible[:40]]
    lines += ["", "Attached proofs:"] + [f"  - {n}" for n in attach_names]
    return "\n".join(lines)


def build_and_send(to: str | None = None, target: str = "",
                   extra_attachments: list[str] | None = None,
                   subject: str | None = None) -> dict[str, Any]:
    """Gather findings + proofs and email the report via Resend.

    SECURITY: the recipient ALWAYS comes from the operator's env (SYBER_REPORT_TO) —
    NOT from the caller/agent. The report contains real findings + downloaded PII/secret
    samples, so the destination must be operator-controlled; a model must never be able to
    redirect it. A model-supplied `to` is honoured only if it exactly matches SYBER_REPORT_TO
    (or an allowlisted SYBER_REPORT_ALLOWED address); anything else is refused."""
    configured = env("SYBER_REPORT_TO")
    if not configured:
        raise IntegrationNotConfigured(
            "SYBER_REPORT_TO is not set. The report recipient is operator-controlled and must be "
            "configured in .env (it is never taken from the agent). Set SYBER_REPORT_TO=you@example.com.")
    allowed = {configured.strip().lower()}
    for extra in (env("SYBER_REPORT_ALLOWED") or "").split(","):
        if extra.strip():
            allowed.add(extra.strip().lower())
    if to and to.strip().lower() not in allowed:
        raise IntegrationError(
            f"Refusing to send the report to '{to}': not the operator-configured recipient. "
            f"The report goes only to SYBER_REPORT_TO (+ SYBER_REPORT_ALLOWED). Ignoring the "
            f"agent-supplied address.")
    recipient = configured   # always the operator's address, regardless of what the agent passed
    findings = list(get_findings_sink().candidates)
    attachments = collect_attachments(extra_attachments)

    # Reproduction: split captured evidence into confirmed (2xx + real data) vs
    # inaccessible, generate curl commands, and attach a runnable verify.sh.
    from . import repro as _repro
    confirmed, inaccessible = _repro.reproductions()
    script = _repro.build_verify_script(confirmed, target=target)
    attachments.append({"filename": "verify.sh",
                        "content": base64.b64encode(script.encode()).decode()})

    names = [a["filename"] for a in attachments]
    subject = subject or (f"[Syber] Engagement report — {target or 'target'} "
                          f"({len(findings)} findings, {len(confirmed)} reproducible)")
    html = render_html(findings, target, names, confirmed, inaccessible)
    text = render_text(findings, target, names, confirmed, inaccessible)
    resp = resend.send_email(recipient, subject, html, text=text, attachments=attachments)
    return {"sent": True, "to": recipient, "finding_count": len(findings),
            "reproducible_count": len(confirmed), "inaccessible_count": len(inaccessible),
            "attachment_count": len(attachments), "attachments": names,
            "message_id": resp.get("id") if isinstance(resp, dict) else None,
            "note": ("Report emailed with proofs + verify.sh (curl repro per confirmed finding). "
                     "Inaccessible/403 captures are listed separately as NON-findings. If it did not "
                     "arrive with the default sender, the recipient must be your Resend account email, "
                     "or set SYBER_REPORT_FROM to a verified-domain sender.")}
