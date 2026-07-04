"""API-key impact tester + severity over-suppression fix."""
from __future__ import annotations

from syber.scanning import apikey
from syber.scoring.severity import cap_severity


def test_is_google_key():
    assert apikey.is_google_key("AIzaSyBJf_37l53rmFj2Sjbk7Phi4VuBsUjULCg")
    assert not apikey.is_google_key("not-a-key")


def test_google_probes_cover_billable_apis():
    probes = apikey.google_probes("AIzaTESTKEY")
    apis = {p["api"] for p in probes}
    assert "geocoding" in apis and "roads" in apis
    assert any("referer-bypass" in a for a in apis)      # static/streetview bypass APIs present


def test_classify_denied_vs_ok():
    p = {"api": "geocoding", "kind": "json"}
    assert apikey._classify(p, 200, b'{"status":"REQUEST_DENIED"}')[0] is False
    assert apikey._classify(p, 200, b'{"results":[],"status":"OK"}')[0] is True
    assert apikey._classify(p, 200, b'{"status":"ZERO_RESULTS"}')[0] is True   # accepted = billable


def test_classify_image():
    img = {"api": "staticmap", "kind": "image"}
    assert apikey._classify(img, 200, b"\x89PNG\r\n\x1a\ndata")[0] is True
    assert apikey._classify(img, 200, b'{"error":"denied"}')[0] is False


def test_result_severity():
    assert apikey.ApiKeyResult(key="k").severity == "INFO"                 # restricted = not a finding
    r = apikey.ApiKeyResult(key="k", usable=[{"api": "geocoding", "price": "$5"}])
    assert r.severity == "LOW" and r.is_unrestricted
    r2 = apikey.ApiKeyResult(key="k", usable=[{"api": "roads", "price": "$10"}])
    assert r2.severity == "MEDIUM"


# --- severity: don't over-suppress a genuinely-confirmed finding ------------ #
def test_confirmed_finding_keeps_high():
    f = {"severity": "HIGH", "summary": "Unauth API returns customer PII",
         "attack_chain": [{"step": 1, "description": "pulled 500 records", "status": "confirmed",
                           "evidence_refs": ["ev1"]}]}
    out, reason = cap_severity(f)
    assert out["severity"] == "HIGH" and reason is None   # confirmed+evidence = not capped


def test_hygiene_forced_to_info_even_if_confirmed():
    # missing headers marked HIGH with a confirmed step must STILL become INFO (noise killer)
    f = {"severity": "HIGH", "summary": "Missing security headers (HSTS, CSP, X-Frame-Options)",
         "attack_chain": [{"step": 1, "description": "observed missing headers", "status": "confirmed",
                           "evidence_refs": ["ev1"]}]}
    out, reason = cap_severity(f)
    assert out["severity"] == "INFO"


def test_unproven_high_demoted_to_medium():
    f = {"severity": "CRITICAL", "summary": "Swagger spec exposed with 462 endpoints",
         "attack_chain": [{"step": 1, "description": "found swagger", "status": "inferred"}]}
    out, reason = cap_severity(f)
    assert out["severity"] == "MEDIUM" and "exploitability" in reason
