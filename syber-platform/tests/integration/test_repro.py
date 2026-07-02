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
