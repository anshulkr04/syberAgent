"""Tests for emailed reporting (Resend client + report builder). No network."""
from __future__ import annotations

import base64

import pytest

from syber.integrations import resend, IntegrationError, IntegrationNotConfigured
from syber import reporting


# --- Resend client ---------------------------------------------------------- #
def test_configured_reflects_key(monkeypatch):
    monkeypatch.delenv("RESEND_API_KEY", raising=False)
    assert resend.configured() is False
    monkeypatch.setenv("RESEND_API_KEY", "re_test")
    assert resend.configured() is True


def test_send_email_builds_request(monkeypatch):
    monkeypatch.setenv("RESEND_API_KEY", "re_test")
    monkeypatch.delenv("SYBER_REPORT_FROM", raising=False)
    captured = {}

    def fake_http_json(method, url, *, token, body, timeout, **kw):
        captured.update(method=method, url=url, token=token, body=body)
        return {"id": "email_123"}
    monkeypatch.setattr(resend, "http_json", fake_http_json)

    out = resend.send_email("me@x.com", "Subj", "<b>hi</b>", text="hi",
                            attachments=[{"filename": "a.png", "content": "Zg=="}])
    assert out["id"] == "email_123"
    assert captured["method"] == "POST" and captured["url"].endswith("/emails")
    assert captured["token"] == "re_test"
    b = captured["body"]
    assert b["to"] == ["me@x.com"]                    # string coerced to list
    assert b["subject"] == "Subj" and b["html"] == "<b>hi</b>"
    assert b["attachments"][0]["filename"] == "a.png"
    assert "onboarding@resend.dev" in b["from"]        # default sandbox sender


def test_send_email_no_key(monkeypatch):
    monkeypatch.delenv("RESEND_API_KEY", raising=False)
    with pytest.raises(IntegrationNotConfigured):
        resend.send_email("me@x.com", "s", "<p>x</p>")


# --- Attachment collection (confirmed-tied only) ---------------------------- #
def test_collect_attachments_confirmed_bundle_and_b64(monkeypatch, tmp_path):
    import json as _j
    ev = tmp_path / "evidence" / "host.com"
    ev.mkdir(parents=True)
    (ev / "cap.json").write_text(_j.dumps({"url": "https://host.com/api", "confirmed": True,
                                           "screenshot": str(ev / "cap.png")}))
    (ev / "cap.body").write_bytes(b"\x89PNG-bytes")   # stand-in raw body bytes
    (ev / "cap.png").write_bytes(b"realdata-png")
    monkeypatch.setattr(reporting, "evidence_dir", lambda: tmp_path / "evidence")

    atts = reporting.collect_attachments()
    names = [a["filename"] for a in atts]
    assert any(n.endswith("cap.json") for n in names)
    assert any(n.endswith("cap.body") for n in names)
    assert any(n.endswith("cap.png") for n in names)
    body = next(a for a in atts if a["filename"].endswith("cap.body"))
    assert base64.b64decode(body["content"]) == b"\x89PNG-bytes"


def test_collect_attachments_size_cap(monkeypatch, tmp_path):
    import json as _j
    ev = tmp_path / "evidence"
    ev.mkdir()
    big = b"x" * (2 * 1024 * 1024)
    for i in range(10):
        d = ev / f"h{i}"
        d.mkdir()
        (d / "c.json").write_text(_j.dumps({"url": f"u{i}", "confirmed": True}))
        (d / "c.body").write_bytes(big)
    monkeypatch.setattr(reporting, "evidence_dir", lambda: ev)
    monkeypatch.setattr(reporting, "_MAX_TOTAL_BYTES", 5 * 1024 * 1024)
    atts = reporting.collect_attachments()
    # bodies are 2MB each; cap 5MB → at most 3 bodies (json files are tiny)
    assert sum(1 for a in atts if a["filename"].endswith(".body")) <= 3


# --- Report render + build/send -------------------------------------------- #
_FINDINGS = [
    {"severity": "CRITICAL", "summary": "Unauth data exposure", "mitre_techniques": ["T1190"],
     "confidence_estimate": 0.9, "evidence_refs": ["ev1"],
     "attack_chain": [{"step": 1, "description": "pulled PII", "status": "confirmed",
                       "mitre_technique": "T1190", "evidence_refs": ["ev1"]}]},
    {"severity": "LOW", "summary": "Missing headers", "mitre_techniques": [],
     "confidence_estimate": 0.8, "evidence_refs": [], "attack_chain": []},
]


def test_render_html_orders_by_severity_and_escapes():
    html = reporting.render_html([{"severity": "LOW", "summary": "<xss>", "attack_chain": []},
                                  {"severity": "CRITICAL", "summary": "crit", "attack_chain": []}],
                                 "acme.com", ["p.png"])
    assert "&lt;xss&gt;" in html                       # escaped
    assert html.index("crit") < html.index("&lt;xss&gt;")   # CRITICAL rendered before LOW
    assert "acme.com" in html and "p.png" in html


def test_build_and_send_always_uses_operator_env(monkeypatch):
    monkeypatch.setenv("RESEND_API_KEY", "re_test")
    monkeypatch.setenv("SYBER_REPORT_TO", "operator@corp.com")
    monkeypatch.delenv("SYBER_REPORT_ALLOWED", raising=False)
    sent = {}

    class _Sink:
        candidates = _FINDINGS
    monkeypatch.setattr(reporting, "get_findings_sink", lambda: _Sink())
    monkeypatch.setattr(reporting, "collect_attachments", lambda extra=None: [{"filename": "shot.png", "content": "Zg=="}])

    def fake_send(to, subject, html, *, text=None, attachments=None, **kw):
        sent.update(to=to, subject=subject, n_att=len(attachments or []))
        return {"id": "email_9"}
    monkeypatch.setattr(reporting.resend, "send_email", fake_send)

    # no `to` -> operator env used
    out = reporting.build_and_send(target="acme.com")
    assert out["to"] == "operator@corp.com" and sent["to"] == "operator@corp.com"

    # an agent-supplied recipient that ISN'T the configured one is REFUSED (anti-exfil)
    with pytest.raises(IntegrationError):
        reporting.build_and_send(to="attacker@evil.com", target="acme.com")

    # a `to` that matches the configured recipient is accepted, still sends to the operator
    out2 = reporting.build_and_send(to="operator@corp.com", target="acme.com")
    assert out2["to"] == "operator@corp.com"


def test_build_and_send_requires_configured_recipient(monkeypatch):
    monkeypatch.setenv("RESEND_API_KEY", "re_test")
    monkeypatch.delenv("SYBER_REPORT_TO", raising=False)
    with pytest.raises(IntegrationNotConfigured):
        reporting.build_and_send(to="anything@x.com", target="x")


def test_gather_findings_reads_durable_graph(monkeypatch):
    # a standalone send (empty in-process sink) still reports graph Finding nodes
    class _Empty:
        candidates: list = []
    monkeypatch.setattr(reporting, "get_findings_sink", lambda: _Empty())
    from syber.graph import model
    model.upsert_host("acme.com")
    model.upsert_finding({"investigation_id": "FDUR", "severity": "CRITICAL",
                          "summary": "Durable graph finding for report",
                          "mitre_techniques": ["T1190"], "confidence_estimate": 0.9}, host="acme.com")
    fs = reporting._gather_findings()
    assert any(f["summary"] == "Durable graph finding for report" and f["severity"] == "CRITICAL"
               for f in fs)


def test_reporting_cli_main_reports_failure_cleanly(monkeypatch):
    # main() never raises; returns 1 and prints on failure (so teardown isn't blocked)
    monkeypatch.delenv("SYBER_REPORT_TO", raising=False)
    monkeypatch.setenv("RESEND_API_KEY", "re_test")
    rc = reporting.main(["--target", "x"])
    assert rc == 1
