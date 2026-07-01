"""
WAF fallback / pivot — deterministic tests (no network).

Covers the pure logic of the dead-end pivot (syber/waf/fallback.py): Cloudflare-IP
classification, apex/subdomain generation, HTTP-response parsing, origin candidate
classification, the direct-origin bypass decision, and the end-to-end
explore_alternate_vectors orchestration with DNS + socket monkeypatched out.

Run: python -m pytest tests/waf/test_fallback.py   (from syber-platform/)
"""
from __future__ import annotations

import syber.waf.fallback as fb
from syber.waf.fallback import (FallbackResult, OriginCandidate, _parse_http_response,
                                candidate_subdomains, explore_alternate_vectors,
                                find_origin_candidates, is_cloudflare_ip)


# --- IP classification ------------------------------------------------------ #
def test_cloudflare_ip_inside_range():
    assert is_cloudflare_ip("104.16.5.5") is True       # 104.16.0.0/13
    assert is_cloudflare_ip("172.64.1.1") is True       # 172.64.0.0/13
    assert is_cloudflare_ip("162.158.0.1") is True      # 162.158.0.0/15


def test_non_cloudflare_ip():
    assert is_cloudflare_ip("8.8.8.8") is False
    assert is_cloudflare_ip("203.0.113.10") is False
    assert is_cloudflare_ip("not-an-ip") is False       # malformed -> not CF


def test_cloudflare_ipv6():
    assert is_cloudflare_ip("2606:4700::1") is True
    assert is_cloudflare_ip("2001:4860:4860::8888") is False


# --- subdomain generation --------------------------------------------------- #
def test_candidate_subdomains_apex_first_and_deduped():
    subs = candidate_subdomains("www.example.com")
    assert subs[0] == "example.com"                     # bare apex first
    assert "direct.example.com" in subs
    assert "mail.example.com" in subs
    assert len(subs) == len(set(subs))                  # deduped


# --- HTTP response parsing -------------------------------------------------- #
def test_parse_http_response_clean_origin():
    raw = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: nginx\r\n\r\n"
           b"<html><body>real origin</body></html>")
    out = _parse_http_response(raw, "203.0.113.5", "example.com")
    assert out is not None
    assert out["status"] == 200
    assert "real origin" in out["body"]
    assert out["origin_ip"] == "203.0.113.5"
    assert out["transport"] == "origin-direct:203.0.113.5"


def test_parse_http_response_still_cloudflare_is_rejected():
    raw = (b"HTTP/1.1 403 Forbidden\r\nServer: cloudflare\r\ncf-ray: abc-LHR\r\n\r\n"
           b"<html>Sorry, you have been blocked error code: 1020</html>")
    # A direct hit that is STILL Cloudflare is not a bypass -> None.
    assert _parse_http_response(raw, "104.16.1.1", "example.com") is None


def test_parse_http_response_garbage():
    assert _parse_http_response(b"", "1.2.3.4", "x.com") is None
    assert _parse_http_response(b"not http at all", "1.2.3.4", "x.com") is None


# --- candidate classification (DNS monkeypatched) --------------------------- #
def test_find_origin_candidates_splits_cf_and_origin(monkeypatch):
    mapping = {
        "example.com": ["104.16.10.10"],            # CF edge
        "direct.example.com": ["203.0.113.7"],      # real origin
        "mail.example.com": ["198.51.100.4"],       # real origin
    }
    monkeypatch.setattr(fb, "resolve_host", lambda h, timeout=3.0: mapping.get(h, []))
    monkeypatch.setattr(fb, "harvest_ct_subdomains", lambda d, **k: [])
    cands = find_origin_candidates("example.com", use_ct=False)
    by_host = {c.host: c for c in cands}
    assert by_host["example.com"].cloudflare is True
    assert by_host["direct.example.com"].cloudflare is False
    assert by_host["mail.example.com"].cloudflare is False
    # non-CF candidates are sorted before CF edges
    assert cands[0].cloudflare is False


# --- end-to-end pivot ------------------------------------------------------- #
def test_explore_finds_origin_and_returns_direct_hit(monkeypatch):
    mapping = {
        "example.com": ["104.16.10.10"],
        "direct.example.com": ["203.0.113.7"],
    }
    monkeypatch.setattr(fb, "resolve_host", lambda h, timeout=3.0: mapping.get(h, []))
    monkeypatch.setattr(fb, "harvest_ct_subdomains", lambda d, **k: [])

    def fake_probe(ip, domain, scheme="https", path="/", timeout=8.0):
        if ip == "203.0.113.7":
            return {"status": 200, "headers": {}, "body": "origin home",
                    "length": 11, "transport": f"origin-direct:{ip}",
                    "origin_ip": ip, "host": domain}
        return None
    monkeypatch.setattr(fb, "probe_origin", fake_probe)

    res = explore_alternate_vectors("https://www.example.com/", use_ct=False)
    assert res.bypassed is True
    assert res.origin_ip == "203.0.113.7"
    assert res.direct_hit["body"] == "origin home"
    # the high-priority direct-origin vector is present
    assert any(v["vector"] == "direct-origin" for v in res.vectors)


def test_explore_no_origin_still_returns_vector_plan(monkeypatch):
    # Every host is a Cloudflare edge -> no bypass, but a full vector plan.
    monkeypatch.setattr(fb, "resolve_host",
                        lambda h, timeout=3.0: ["104.16.1.1"] if h.endswith("example.com") else [])
    monkeypatch.setattr(fb, "harvest_ct_subdomains", lambda d, **k: [])
    monkeypatch.setattr(fb, "probe_origin", lambda *a, **k: None)

    res = explore_alternate_vectors("example.com", use_ct=False)
    assert res.bypassed is False
    assert res.origin_ip is None
    assert res.non_cf_hosts == []
    vectors = {v["vector"] for v in res.vectors}
    assert "non-proxied-ports" in vectors
    assert "subdomain-enumeration" in vectors
    assert "dns-and-mail" in vectors
    assert any("Cloudflare edge" in n for n in res.notes)


def test_explore_no_dns_resolution_degrades_gracefully(monkeypatch):
    monkeypatch.setattr(fb, "resolve_host", lambda h, timeout=3.0: [])
    monkeypatch.setattr(fb, "harvest_ct_subdomains", lambda d, **k: [])
    res = explore_alternate_vectors("example.com", use_ct=False)
    assert res.bypassed is False
    assert res.candidates == []
    # still hands back the network-layer vectors to pursue
    assert any(v["vector"] == "non-proxied-ports" for v in res.vectors)
    assert any("DNS" in n or "resolve" in n for n in res.notes)


def test_fallback_result_to_dict_roundtrips():
    res = FallbackResult(domain="x.com",
                         candidates=[OriginCandidate("x.com", "1.2.3.4", False, "apex")])
    d = res.to_dict()
    assert d["domain"] == "x.com"
    assert d["bypassed"] is False
    assert d["candidates"][0]["ip"] == "1.2.3.4"
