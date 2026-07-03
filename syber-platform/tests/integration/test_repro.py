"""Reproduction-script generation + confirmed-vs-inaccessible evidence split."""
from __future__ import annotations

import json

from syber import repro
from syber.scanning import exfil


# --- is_confirmed: the anti-'403 screenshot is proof' gate ------------------ #
def test_is_confirmed_requires_2xx_and_data():
    real = exfil.scan_sensitive('[{"email":"a@b.com"}]', "application/json")
    assert exfil.is_confirmed(200, real) is True
    assert exfil.is_confirmed(403, real) is False          # blocked page: not proof
    assert exfil.is_confirmed(401, real) is False
    empty = exfil.scan_sensitive("true", "application/json")
    assert exfil.is_confirmed(200, empty) is False         # 200 but no real data
    boiler = exfil.scan_sensitive("<html>Access Denied</html>", "text/html")
    assert exfil.is_confirmed(200, boiler) is False        # inaccessible HTML


# --- curl generation is faithful to the captured request ------------------- #
def test_curl_for_get():
    ev = {"method": "GET", "url": "https://x/api/users", "request_headers": {}}
    c = repro.curl_for(ev)
    assert c.startswith("curl -sk -i") and "https://x/api/users" in c and "-X" not in c


def test_curl_for_post_includes_real_headers():
    # operator-locked report: the curl must be runnable as-is, incl. the working auth
    ev = {"method": "POST", "url": "https://x/api/map",
          "request_headers": {"Content-Type": "application/json", "Authorization": "Bearer abc123"}}
    c = repro.curl_for(ev)
    assert "-X POST" in c
    assert "Content-Type: application/json" in c
    assert "Bearer abc123" in c                            # real value, so it actually reproduces


def test_is_unauthenticated():
    assert repro.is_unauthenticated({"request_headers": {}}) is True
    assert repro.is_unauthenticated({"request_headers": {"Accept": "*/*"}}) is True
    assert repro.is_unauthenticated({"request_headers": {"Authorization": "Bearer x"}}) is False
    assert repro.is_unauthenticated({"request_headers": {"Cookie": "s=1"}}) is False


def test_expected_result_wording():
    ev = {"status": 200, "verdict": "REAL_DATA", "categories": {"email": 3, "pan": 1}}
    assert "real sensitive data" in repro.expected_result(ev) and "email" in repro.expected_result(ev)
    ev2 = {"status": 200, "verdict": "STRUCTURED", "record_count": 12}
    assert "12 structured records" in repro.expected_result(ev2)


# --- end-to-end over a temp evidence dir ----------------------------------- #
def _write_ev(d, name, obj):
    (d / name).write_text(json.dumps(obj))


def test_reproductions_split_and_script(tmp_path):
    ed = tmp_path / "evidence" / "host.com"
    ed.mkdir(parents=True)
    _write_ev(ed, "a.json", {"url": "https://host.com/api/GetUserDetails", "method": "GET",
                             "status": 200, "verdict": "REAL_DATA", "confirmed": True,
                             "categories": {"email": 2}, "request_headers": {}})
    _write_ev(ed, "b.json", {"url": "https://host.com/login", "method": "GET",
                             "status": 403, "verdict": "BOILERPLATE", "confirmed": False,
                             "request_headers": {}})
    confirmed, inaccessible = repro.reproductions(root=tmp_path / "evidence")
    assert len(confirmed) == 1 and confirmed[0]["url"].endswith("GetUserDetails")
    assert len(inaccessible) == 1 and inaccessible[0]["status"] == 403

    script = repro.build_verify_script(confirmed, target="host.com")
    assert script.startswith("#!/usr/bin/env bash")
    assert "GetUserDetails" in script and "curl -sk -i" in script
    # the inaccessible/403 endpoint is NOT in the runnable repro script
    assert "/login" not in script


def test_verify_script_empty_when_nothing_confirmed():
    s = repro.build_verify_script([], target="x")
    assert "No CONFIRMED findings" in s


# --- gated-page detector: login/403 pages are NOT proof --------------------- #
def test_is_gated_page_rejects_login_and_denied():
    assert exfil.is_gated_page("Please log in to your account", 200) is True
    assert exfil.is_gated_page("<h1>Access Denied</h1>", 200) is True
    assert exfil.is_gated_page("Attention Required! Cloudflare", 200) is True
    assert exfil.is_gated_page("anything", 403) is True          # non-2xx is gated
    assert exfil.is_gated_page("", 200) is True                  # empty
    assert exfil.is_gated_page("404 Not Found", 200) is True


def test_is_gated_page_accepts_real_data_view():
    # a logged-in/data page passes even if it mentions 'logout'
    assert exfil.is_gated_page('{"account_number":"12345","balance":9000}', 200) is False
    assert exfil.is_gated_page("Welcome, Asha — Dashboard | Logout | Holdings", 200) is False


# --- attachments: only confirmed-tied proofs ------------------------------- #
def test_collect_attachments_only_confirmed(monkeypatch, tmp_path):
    import json as _j
    from syber import reporting
    ed = tmp_path / "evidence" / "host.com"
    ed.mkdir(parents=True)
    # a CONFIRMED capture with body + screenshot
    (ed / "good.json").write_text(_j.dumps({"url": "https://host.com/api/data", "confirmed": True,
                                            "screenshot": str(ed / "good.png")}))
    (ed / "good.body").write_text('{"email":"a@b.com"}')
    (ed / "good.png").write_bytes(b"\x89PNGdata")
    # an UNCONFIRMED capture (403 login page) + an arbitrary agent screenshot
    (ed / "bad.json").write_text(_j.dumps({"url": "https://host.com/login", "confirmed": False,
                                           "screenshot": str(ed / "bad.png")}))
    (ed / "bad.png").write_bytes(b"loginpage")
    (ed / "random-screenshot.png").write_bytes(b"accessdenied")
    monkeypatch.setattr(reporting, "evidence_dir", lambda: tmp_path / "evidence")

    names = [a["filename"] for a in reporting.collect_attachments([str(ed / "random-screenshot.png")])]
    assert any(n.endswith("good.json") for n in names)
    assert any(n.endswith("good.body") for n in names)
    assert any(n.endswith("good.png") for n in names)
    # the login-page screenshot + unconfirmed json are NOT attached
    assert not any("bad" in n for n in names)
    # an agent-supplied SCREENSHOT is never taken on trust (only capture-on-confirmation ships)
    assert not any("random-screenshot" in n for n in names)


def test_collect_attachments_empty_when_nothing_confirmed(monkeypatch, tmp_path):
    import json as _j
    from syber import reporting
    ed = tmp_path / "evidence" / "h"
    ed.mkdir(parents=True)
    (ed / "x.json").write_text(_j.dumps({"url": "u", "confirmed": False}))
    (ed / "shot.png").write_bytes(b"img")
    monkeypatch.setattr(reporting, "evidence_dir", lambda: tmp_path / "evidence")
    # no confirmed evidence → nothing attached, and an agent screenshot is withheld
    assert reporting.collect_attachments([str(ed / "shot.png")]) == []
