"""Tests for deterministic subdomain enumeration + subdomain authorization scoping."""
from __future__ import annotations

import json

from syber.scanning import subdomains as sd
from syber.scanning.authorization import AuthorizationStore


# --- registrable apex ------------------------------------------------------- #
def test_registrable_apex():
    assert sd.registrable_apex("nuvamawealth.com") == "nuvamawealth.com"
    assert sd.registrable_apex("vamauat.nuvamawealth.com") == "nuvamawealth.com"
    assert sd.registrable_apex("https://nwmwuat.nuvamawealth.com/x") == "nuvamawealth.com"
    assert sd.registrable_apex("a.b.example.co.uk") == "example.co.uk"


# --- non-prod classification (the priority-hunt signal) --------------------- #
def test_classify_env_nonprod():
    for h in ["vamauat.nuvamawealth.com", "nwmwuat.nuvamawealth.com",
              "nmwuat1.nuvamawealth.com", "onboardinguat.nuvamawealth.com",
              "vamacug.nuvamawealth.com", "dev.x.com", "stg.x.com", "qa.x.com",
              "staging.api.x.com", "preprod.x.com"]:
        assert sd.classify_env(h) == "non-prod", h


def test_classify_env_prod():
    for h in ["www.nuvamawealth.com", "api.x.com", "website.x.com",  # "sit" in website != non-prod
              "login.x.com", "gateway.x.com", "x.com"]:
        assert sd.classify_env(h) == "prod", h


# --- crt.sh parsing --------------------------------------------------------- #
def test_parse_crtsh_filters_domain_and_wildcards():
    rows = [
        {"name_value": "vamauat.nuvamawealth.com\nwww.nuvamawealth.com"},
        {"common_name": "*.nuvamawealth.com"},          # wildcard dropped
        {"name_value": "unrelated.example.org"},         # other domain dropped
        {"name_value": "nuvamawealth.com"},              # apex kept
    ]
    got = sd.parse_crtsh(json.dumps(rows), "nuvamawealth.com")
    assert got == {"vamauat.nuvamawealth.com", "www.nuvamawealth.com", "nuvamawealth.com"}


def test_parse_crtsh_bad_json():
    assert sd.parse_crtsh("not json", "x.com") == set()


# --- candidate generation --------------------------------------------------- #
def test_candidate_hosts_covers_nonprod_and_generic():
    c = sd.candidate_hosts("nuvamawealth.com")
    assert "uat.nuvamawealth.com" in c
    assert "www.nuvamawealth.com" in c
    assert "staging.nuvamawealth.com" in c


def test_env_variants_catches_concatenated_twins():
    v = sd.env_variants({"nwmw", "onboarding", "vama"}, "nuvamawealth.com")
    # the concatenated-env naming that CT alone misses when crt.sh is down
    assert "nwmwuat.nuvamawealth.com" in v
    assert "onboardinguat.nuvamawealth.com" in v
    assert "vamauat.nuvamawealth.com" in v
    assert "onboarding-cug.nuvamawealth.com" in v
    # an already-non-prod label is not re-expanded
    assert not any(h.startswith("devuat.") for h in sd.env_variants({"dev"}, "x.com"))


# --- authorization scoping: apex covers subdomains -------------------------- #
def test_apex_authorization_covers_subdomains(tmp_path, monkeypatch):
    # make DNS inert so only the explicit/subdomain rules decide (hermetic)
    import syber.scanning.authorization as authz

    def _no_dns(*a, **k):
        raise authz.socket.gaierror("no dns in test")
    monkeypatch.setattr(authz.socket, "getaddrinfo", _no_dns)

    store = AuthorizationStore(path=tmp_path / "auth.json")
    store.authorize("nuvamawealth.com", "I own and am authorised to test this", "operator")

    assert store.is_authorized("nuvamawealth.com")[0] is True
    assert store.is_authorized("vamauat.nuvamawealth.com")[0] is True       # subdomain
    assert store.is_authorized("nwmwuat.nuvamawealth.com")[0] is True       # deep subdomain
    assert store.is_authorized("evil.com")[0] is False                      # unrelated
    assert store.is_authorized("notnuvamawealth.com")[0] is False           # suffix trick, not a subdomain


def test_bare_host_authorization_does_not_extend(tmp_path, monkeypatch):
    import syber.scanning.authorization as authz

    def _no_dns(*a, **k):
        raise authz.socket.gaierror("no dns in test")
    monkeypatch.setattr(authz.socket, "getaddrinfo", _no_dns)
    store = AuthorizationStore(path=tmp_path / "auth.json")
    # localhost is pre-authorised but has no dot -> must NOT authorise "evil.localhost"? it ends with
    # ".localhost"; localhost has no dot so the subdomain rule requires a dotted apex -> stays denied.
    assert store.is_authorized("evil.localhost")[0] is False
