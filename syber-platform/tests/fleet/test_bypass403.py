"""401/403 bypass engine — mutation builders + baseline-diff success detection."""
from __future__ import annotations

from syber.scanning import bypass403 as b


def test_header_mutations_cover_trust_headers():
    m = b.header_mutations("https://x.com/admin")
    labels = [x.label for x in m]
    assert any("X-Forwarded-For: 127.0.0.1" == l for l in labels)
    assert any("X-Real-IP" in l for l in labels)
    # path-rewrite header uses the blocked path
    assert any(x.headers.get("X-Original-URL") == "/admin" for x in m)


def test_path_mutations_include_nginx_tricks():
    m = b.path_mutations("https://x.com/admin")
    urls = [x.url for x in m]
    assert any("/admin/..;/" in u for u in urls)
    assert any(u.endswith("/admin/") for u in urls)
    assert any("/admin.json" in u for u in urls)
    assert any("/ADMIN" in u for u in urls)          # case toggle


def test_method_mutations():
    ms = {x.method for x in b.method_mutations("https://x/y")}
    assert {"POST", "PUT", "OPTIONS", "TRACE"} <= ms and "GET" not in ms


def test_vercel_secret_extraction():
    assert b.vercel_bypass_secret('"x-vercel-protection-bypass":"Ab12Cd34Ef56Gh78Ij90kk"') == "Ab12Cd34Ef56Gh78Ij90kk"
    assert b.vercel_bypass_secret('VERCEL_AUTOMATION_BYPASS_SECRET=Zz99yy88xx77ww66vv55') == "Zz99yy88xx77ww66vv55"
    assert b.vercel_bypass_secret("nothing here") is None


def test_improved_requires_status_and_body_change():
    # 403 -> 200 with a much bigger body = win
    assert b._improved(403, 200, base_len=20, new_len=5000) is True
    # 403 -> 200 but same tiny body (another block page) = not a win
    assert b._improved(403, 200, base_len=20, new_len=25) is False
    # 403 -> 403 = not a win
    assert b._improved(403, 403, base_len=20, new_len=9000) is False
    # wasn't blocked to begin with
    assert b._improved(200, 200, base_len=20, new_len=9000) is False


def test_run_bypass403_finds_working_mutation():
    def fetch(url, method="GET", headers=None):
        headers = headers or {}
        if headers.get("X-Forwarded-For") == "127.0.0.1":
            return {"status": 200, "body": "SECRET ADMIN CONTENT " * 40, "headers": {}}
        return {"status": 403, "body": "Forbidden", "headers": {"server": "nginx"}}
    r = b.run_bypass403("https://x.com/admin", fetch)
    assert r.bypassed and r.winner["kind"] == "header"


def test_run_bypass403_no_false_win():
    # every mutation returns another 403 page -> no bypass
    def fetch(url, method="GET", headers=None):
        return {"status": 403, "body": "Forbidden", "headers": {}}
    r = b.run_bypass403("https://x.com/admin", fetch)
    assert r.bypassed is False and r.tried > 0


def test_vercel_bypass_via_harvested_secret():
    def fetch(url, method="GET", headers=None):
        headers = headers or {}
        if any(k.lower() == "x-vercel-protection-bypass" for k in headers) or "x-vercel-protection-bypass=" in url:
            return {"status": 200, "body": "REAL DASHBOARD " * 50, "headers": {}}
        return {"status": 403, "body": "blocked", "headers": {"server": "Vercel"}}
    r = b.run_bypass403("https://app.x/dash", fetch, harvested_text="x-vercel-protection-bypass=SecretTokenValue123456")
    assert r.bypassed and r.winner["kind"] == "vercel"
