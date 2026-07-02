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


# --- Attachment collection -------------------------------------------------- #
def test_collect_attachments_filters_dedupes_and_b64(monkeypatch, tmp_path):
    ev = tmp_path / "evidence" / "host.com"
    ev.mkdir(parents=True)
    (ev / "shot.png").write_bytes(b"\x89PNG-bytes")
    (ev / "sample.json").write_text('{"verdict":"REAL_DATA"}')
    (ev / "ignore.zip").write_bytes(b"nope")          # not a proof ext -> skipped
    monkeypatch.setattr(reporting, "evidence_dir", lambda: tmp_path / "evidence")

    extra = tmp_path / "extra.png"
    extra.write_bytes(b"extra")
    atts = reporting.collect_attachments([str(extra), str(extra)])   # dup extra -> once
    names = [a["filename"] for a in atts]
    assert any(n.endswith("shot.png") for n in names)
    assert any(n.endswith("sample.json") for n in names)
    assert not any("ignore.zip" in n for n in names)
    assert sum(1 for n in names if n.endswith("extra.png")) == 1   # dup path collapsed to one
    # content is valid base64 of the file bytes
    shot = next(a for a in atts if a["filename"].endswith("shot.png"))
    assert base64.b64decode(shot["content"]) == b"\x89PNG-bytes"


def test_collect_attachments_size_cap(monkeypatch, tmp_path):
    ev = tmp_path / "evidence"
    ev.mkdir()
    big = b"x" * (2 * 1024 * 1024)
    for i in range(10):
        (ev / f"f{i}.body").write_bytes(big)
    monkeypatch.setattr(reporting, "evidence_dir", lambda: ev)
    monkeypatch.setattr(reporting, "_MAX_TOTAL_BYTES", 5 * 1024 * 1024)
    atts = reporting.collect_attachments()
    assert len(atts) <= 3                             # 5MB cap / 2MB files


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
