"""Credential harvesting + auth-header replay variants + persistent store."""
from __future__ import annotations

from syber.scanning import credentials as cred


def test_harvest_jwt_and_bearer():
    jwt = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ."
           "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
    creds = cred.harvest(f'{{"appIdKey":"{jwt}"}} Authorization: Bearer {jwt}')
    kinds = {c.kind for c in creds}
    assert "jwt" in kinds


def test_harvest_api_key_field_and_credpair():
    text = '{"api_key":"PlatformYh2k7QSu4l8CZg5p6X3Pna9hy7Client","username":"tester","password":"Secret123"}'
    creds = cred.harvest(text)
    assert any(c.kind == "field" and "PlatformYh2k7" in c.value for c in creds)
    assert any(c.kind == "cred_pair" and c.username == "tester" and c.password == "Secret123" for c in creds)


def test_harvest_ignores_junk():
    # plain words / urls / booleans are not credentials
    creds = cred.harvest('{"token":"true","password":"password","url":"https://x/api"}')
    assert all(c.value not in ("true", "password") for c in creds if c.kind == "field")


def test_auth_headers_variants():
    c = cred.Credential(kind="jwt", value="TOK123456789", name="appIdKey")
    variants = cred.auth_headers(c)
    # must include a proper Bearer variant, and the token under its own field name
    assert {"Authorization": "Bearer TOK123456789"} in variants
    assert {"appIdKey": "TOK123456789"} in variants


def test_auth_headers_basic_from_credpair():
    c = cred.Credential(kind="cred_pair", username="admin", password="admin")
    variants = cred.auth_headers(c)
    assert any(v.get("Authorization", "").startswith("Basic ") for v in variants)


def test_store_persists_across_instances(tmp_path):
    path = str(tmp_path / "creds.json")
    s1 = cred.CredentialStore(path=path)
    s1.add_from_text('Authorization: Bearer eyJhbGciOi.eyJzdWIiOiIx.abcdefghij', source="js")
    s1.add_cookie("np.acme.com", "SESSION=abc123")
    # next pass (new store) loads them from disk
    s2 = cred.CredentialStore(path=path)
    assert s2.summary()["total"] >= 2
    assert any(c.name == "Cookie" and "SESSION=abc123" in c.value for c in s2.all())
