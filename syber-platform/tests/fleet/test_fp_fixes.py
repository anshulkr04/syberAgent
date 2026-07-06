"""Regression tests for the false-positive fixes (careers PII, wildcard ghosts, repro reconciliation)."""
from __future__ import annotations

import json
from syber.scanning import exfil
from syber.scanning import subdomains as sd
from syber import reporting


# --- A: public-content / weak-signal is NOT a CRITICAL PII exposure --------- #
def test_careers_phone_not_real_data():
    body = json.dumps([{"title": "Engineer", "phone": "9712345608"},
                       {"title": "PM", "phone": "9812345678"}])
    ev = exfil.scan_sensitive(body, "application/json", url="https://hinge.co/api/careers/all")
    assert ev.verdict != "REAL_DATA"          # public careers listing != PII leak
    assert not ev.has_sensitive


def test_lone_weak_signal_not_real_data():
    ev = exfil.scan_sensitive('[{"phone":"9712345608"},{"phone":"9812345678"}]',
                              "application/json", url="https://api.x/thing/list")
    assert ev.verdict != "REAL_DATA"          # 2 phones, no strong signal


def test_strong_signal_is_real_data():
    ev = exfil.scan_sensitive('{"pan":"ABCDE1234F","email":"a@b.com"}', "application/json",
                              url="https://api.x/user/1")
    assert ev.verdict == "REAL_DATA"          # PAN = strong PII


def test_user_dump_is_real_data():
    dump = json.dumps([{"email": f"u{i}@x.com"} for i in range(8)])
    ev = exfil.scan_sensitive(dump, "application/json", url="https://api.x/admin/users")
    assert ev.verdict == "REAL_DATA"          # many records each with PII = a dump


def test_jwt_flagged_even_on_public_path():
    # a real session token / private key leaking anywhere IS a finding
    jwt = "eyJhbGciOiJI.eyJzdWIiOiIx.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    ev = exfil.scan_sensitive(f'{{"token":"{jwt}"}}', "application/json", url="https://x.co/careers")
    assert ev.verdict == "REAL_DATA"


def test_api_key_on_public_page_not_auto_critical():
    # a bare Google Maps-style api-key is NOT auto-CRITICAL (the original FP) — needs syber_test_api_key
    ev = exfil.scan_sensitive('{"apiKey":"AIzaSyBrealkey_prod_value_1234567890abcd"}',
                              "application/json", url="https://x.co/careers")
    assert ev.verdict != "REAL_DATA"


# --- C: wildcard-DNS ghosts dropped ---------------------------------------- #
def test_drop_wildcard_ghosts():
    resolved = {
        "real-ct.x.com": ["1.2.3.4"],       # from CT source -> keep
        "ghost1.x.com": ["9.9.9.9"],        # brute, wildcard IP -> drop
        "ghost2.x.com": ["9.9.9.9"],        # brute, wildcard IP -> drop
        "distinct.x.com": ["5.6.7.8"],      # brute but distinct IP -> keep
    }
    discovered = {"real-ct.x.com"}
    kept, dropped = sd._drop_wildcard_ghosts(resolved, discovered, {"9.9.9.9"}, "x.com")
    assert dropped == 2
    assert "real-ct.x.com" in kept and "distinct.x.com" in kept
    assert "ghost1.x.com" not in kept and "ghost2.x.com" not in kept


def test_no_wildcard_keeps_all():
    resolved = {"a.x.com": ["1.1.1.1"]}
    kept, dropped = sd._drop_wildcard_ghosts(resolved, set(), set(), "x.com")
    assert dropped == 0 and kept == resolved


# --- B: report never claims CRITICAL without a confirmed reproduction ------- #
def test_unbacked_critical_becomes_unverified():
    findings = [{"severity": "CRITICAL", "summary": "PII at https://x/api/careers/all",
                 "evidence_refs": [], "attack_chain": []}]
    rec = reporting._reconcile_findings(findings, confirmed=[])   # no reproductions
    assert rec[0]["severity"] == "UNVERIFIED" and rec[0]["_verified"] is False


def test_backed_finding_stays():
    findings = [{"severity": "HIGH", "summary": "dump at https://x/api/users",
                 "evidence_refs": [], "attack_chain": []}]
    rec = reporting._reconcile_findings(findings, confirmed=[{"url": "https://x/api/users"}])
    assert rec[0]["severity"] == "HIGH" and rec[0]["_verified"] is True
