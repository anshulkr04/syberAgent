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


def collect_attachments(extra_paths: list[str] | None = None) -> list[dict[str, str]]:
    """Base64 every proof file in the evidence dir + any explicit paths, deduped and
    size-capped, in Resend attachment format {filename, content}."""
    candidates: list[Path] = []
    d = evidence_dir()
    if d.is_dir():
        candidates += sorted(p for p in d.rglob("*")
                             if p.is_file() and p.suffix.lower() in _PROOF_EXTS)
    for x in (extra_paths or []):
        p = Path(x)
        if p.is_file():
            candidates.append(p)

    out: list[dict[str, str]] = []
    seen: set[str] = set()
    total = 0
    for p in candidates:
        rp = str(p.resolve())
        if rp in seen:
            continue
        seen.add(rp)
        try:
            data = p.read_bytes()
        except Exception:  # noqa: BLE001
            continue
        if total + len(data) > _MAX_TOTAL_BYTES:
            continue
        total += len(data)
        # namespace the filename with its parent (host) dir so proofs don't collide
        name = f"{p.parent.name}__{p.name}" if p.parent != d else p.name
        out.append({"filename": name, "content": base64.b64encode(data).decode()})
        if len(out) >= _MAX_ATTACHMENTS:
            break
    return out


def _sev_sorted(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(findings, key=lambda f: _SEV_ORDER.get(str(f.get("severity", "INFO")).upper(), 5))


def render_html(findings: list[dict[str, Any]], target: str, attach_names: list[str]) -> str:
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
    return f"""<div style="font-family:system-ui,Arial,sans-serif;max-width:820px">
<h2>Syber — Security Engagement Report</h2>
<p><b>Target:</b> {escape(target or 'n/a')}<br><b>Findings:</b> {len(findings)}
&nbsp;<b>Attached proofs:</b> {len(attach_names)}</p>
<table border=1 cellpadding=6 cellspacing=0 style="border-collapse:collapse;width:100%">
<thead><tr><th>#</th><th>Severity</th><th>Finding</th><th>MITRE</th><th>Conf.</th></tr></thead>
<tbody>{rows}</tbody></table>
<h2>Details &amp; attack chains</h2>{details}
<h2>Attached proofs (verify these)</h2><ul>{proofs}</ul>
<p><small>Every finding above is backed by an attached artefact — downloaded data samples
(redacted), screenshots, or HTTP request/response captures. Verify, then forward to the
target organisation. Generated by Syber.</small></p></div>"""


def render_text(findings: list[dict[str, Any]], target: str, attach_names: list[str]) -> str:
    lines = [f"Syber — Security Engagement Report", f"Target: {target or 'n/a'}",
             f"Findings: {len(findings)} | Attached proofs: {len(attach_names)}", ""]
    for i, f in enumerate(_sev_sorted(findings), 1):
        lines.append(f"{i}. [{f.get('severity')}] {f.get('summary', '')}")
        lines.append(f"   MITRE: {', '.join(f.get('mitre_techniques', []) or [])}"
                     f" | evidence: {', '.join(f.get('evidence_refs', []) or [])}")
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
    names = [a["filename"] for a in attachments]
    subject = subject or (f"[Syber] Engagement report — {target or 'target'} "
                          f"({len(findings)} findings, {len(attachments)} proofs)")
    html = render_html(findings, target, names)
    text = render_text(findings, target, names)
    resp = resend.send_email(recipient, subject, html, text=text, attachments=attachments)
    return {"sent": True, "to": recipient, "finding_count": len(findings),
            "attachment_count": len(attachments), "attachments": names,
            "message_id": resp.get("id") if isinstance(resp, dict) else None,
            "note": ("Report emailed with proofs attached. If it did not arrive and you used the "
                     "default sender, the recipient must be your Resend account email, or set "
                     "SYBER_REPORT_FROM to a verified-domain sender.")}
