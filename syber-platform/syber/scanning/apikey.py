"""
API-key impact tester — "you found a key; now prove where it's usable."

The failure this fixes: the agent finds a key (e.g. a Google `AIzaSy…` in page source)
and reports it — without testing whether it is actually UNRESTRICTED and abusable. A
restricted key is harmless (INFO); an unrestricted billable key is a real finding
(quota/billing abuse). This module makes that determination deterministically instead of
leaving it to the model.

For a Google API key it calls the billable endpoints directly (KeyHacks/gmapsapiscanner
methodology) and classifies each as usable vs restricted from the response — including the
nuance that Static Maps / Street View ignore HTTP-referer restrictions, so they can be
billable even when the JS Maps API says "restricted".

Pure request builders (unit-tested) + a thin live tester. Only touches the key's own
provider APIs (Google), never the engagement target, so it needs no target auth.
"""
from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

__all__ = ["is_google_key", "google_probes", "test_google_key", "ApiKeyResult"]

_GOOGLE_KEY_RX = re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")
_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
       "Chrome/124.0 Safari/537.36")


def is_google_key(s: str) -> bool:
    return bool(_GOOGLE_KEY_RX.fullmatch(s.strip())) or bool(_GOOGLE_KEY_RX.search(s))


def find_google_keys(text: str) -> list[str]:
    return sorted(set(_GOOGLE_KEY_RX.findall(text or "")))


def google_probes(key: str) -> list[dict[str, str]]:
    """One request per billable Google API (name, url, price/1k). A 200 with a real body
    (not an error/REQUEST_DENIED) confirms the key is usable+billable for that API."""
    k = urllib.parse.quote(key, safe="")
    return [
        {"api": "geocoding", "price": "$5", "kind": "json",
         "url": f"https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key={k}"},
        {"api": "directions", "price": "$5", "kind": "json",
         "url": f"https://maps.googleapis.com/maps/api/directions/json?origin=NYC&destination=Boston&key={k}"},
        {"api": "places-findplace", "price": "$17", "kind": "json",
         "url": ("https://maps.googleapis.com/maps/api/place/findplacefromtext/json"
                 f"?input=cafe&inputtype=textquery&fields=name&key={k}")},
        {"api": "distancematrix", "price": "$5", "kind": "json",
         "url": f"https://maps.googleapis.com/maps/api/distancematrix/json?origins=NYC&destinations=Boston&key={k}"},
        {"api": "timezone", "price": "$5", "kind": "json",
         "url": f"https://maps.googleapis.com/maps/api/timezone/json?location=40,30&timestamp=0&key={k}"},
        {"api": "elevation", "price": "$5", "kind": "json",
         "url": f"https://maps.googleapis.com/maps/api/elevation/json?locations=40,30&key={k}"},
        {"api": "geolocation", "price": "$5", "kind": "json", "method": "POST",
         "url": f"https://www.googleapis.com/geolocation/v1/geolocate?key={k}"},
        {"api": "roads", "price": "$10", "kind": "json",
         "url": f"https://roads.googleapis.com/v1/nearestRoads?points=60.17,24.94&key={k}"},
        # referer-restriction-BYPASSABLE APIs: billable even when the key is "restricted".
        {"api": "staticmap(referer-bypass)", "price": "$2", "kind": "image",
         "url": f"https://maps.googleapis.com/maps/api/staticmap?center=40,30&zoom=7&size=200x200&key={k}"},
        {"api": "streetview(referer-bypass)", "price": "$7", "kind": "image",
         "url": f"https://maps.googleapis.com/maps/api/streetview?size=200x200&location=40,30&key={k}"},
    ]


@dataclass
class ApiKeyResult:
    key: str
    provider: str = "google"
    usable: list[dict[str, Any]] = field(default_factory=list)     # APIs the key works on
    restricted: list[str] = field(default_factory=list)            # APIs that denied it
    errors: list[str] = field(default_factory=list)

    @property
    def is_unrestricted(self) -> bool:
        return bool(self.usable)

    @property
    def severity(self) -> str:
        # Impact-based: unrestricted billable key = LOW-MEDIUM (quota/billing abuse);
        # a referer-bypassable API being open bumps it (can't be fixed by referer alone).
        if not self.usable:
            return "INFO"
        if any("referer-bypass" in u["api"] or u["api"] in ("roads", "geolocation") for u in self.usable):
            return "MEDIUM"
        return "LOW"

    def summary(self) -> str:
        if not self.usable:
            return f"Google key is RESTRICTED (no billable API accepted it) — not a finding ({len(self.restricted)} tested)."
        apis = ", ".join(f"{u['api']}({u['price']}/1k)" for u in self.usable)
        return (f"UNRESTRICTED Google key — billable on: {apis}. Unlimited unauthenticated calls "
                f"= quota/billing abuse charged to the target.")

    def to_dict(self) -> dict[str, Any]:
        return {"key": self.key[:10] + "…", "provider": self.provider, "unrestricted": self.is_unrestricted,
                "severity": self.severity, "usable_apis": self.usable, "restricted_apis": self.restricted,
                "summary": self.summary(), "errors": self.errors[:5]}


def _get(url: str, method: str = "GET", timeout: int = 12) -> tuple[int | None, bytes]:
    try:
        req = urllib.request.Request(url, method=method, headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - Google API host
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read()
        except Exception:  # noqa: BLE001
            return e.code, b""
    except Exception:  # noqa: BLE001
        return None, b""


def _classify(probe: dict[str, str], status: int | None, body: bytes) -> tuple[bool, str]:
    """(usable, reason). Usable = the key was accepted and billed, not denied."""
    if status is None:
        return False, "no response"
    if probe.get("kind") == "image":
        # a real PNG/JPEG body = billable image served; an error is small text/JSON
        if status == 200 and body[:8] in (b"\x89PNG\r\n\x1a\n",) or body[:3] == b"\xff\xd8\xff":
            return True, "served a real image (billable)"
        return False, f"status {status}, not an image"
    txt = body.decode("utf-8", "replace")[:500]
    if '"REQUEST_DENIED"' in txt or "not authorized to use this API" in txt or "API_KEY_HTTP_REFERRER" in txt:
        return False, "REQUEST_DENIED / referer-restricted"
    if '"error"' in txt and ("API key not valid" in txt or "PERMISSION_DENIED" in txt):
        return False, "key invalid / permission denied"
    if status == 200 and ('"status" : "OK"' in txt or '"status": "OK"' in txt
                          or '"results"' in txt or '"rows"' in txt or '"location"' in txt
                          or '"ZERO_RESULTS"' in txt or '"snappedPoints"' in txt):
        # ZERO_RESULTS still means the key was ACCEPTED and the call was billable
        return True, "accepted (billable call succeeded)"
    return False, f"status {status}: {txt[:120]}"


def test_google_key(key: str, timeout: int = 12) -> ApiKeyResult:
    """Live-test a Google API key against each billable endpoint and classify impact."""
    res = ApiKeyResult(key=key)
    for probe in google_probes(key):
        status, body = _get(probe["url"], method=probe.get("method", "GET"), timeout=timeout)
        usable, reason = _classify(probe, status, body)
        if usable:
            res.usable.append({"api": probe["api"], "price": probe["price"], "reason": reason})
        else:
            res.restricted.append(f"{probe['api']}: {reason}")
    return res
