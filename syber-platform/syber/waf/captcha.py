"""
L4 — CAPTCHA-solving services (waf-spec §3.4, §4.1).

When Turnstile runs in *interactive* mode (or a site uses hCaptcha/reCAPTCHA), a
headless browser (L3) cannot clear it; an external solving service is required.
The pattern (waf-spec §3.4): extract the sitekey + page URL → submit to the
service → poll for the token → inject it back into the page's hidden Turnstile
input and fire the callback.

This adapter covers the token-retrieval half (the network round-trip to the
service) for the two most common providers, behind one interface. The token
*injection* half is the caller's job in the browser (it varies per page); the
integration layer hands the token to the solver session.

The service is OFF by default (no provider, no key). With no key configured every
call returns an actionable "not configured" result rather than raising — matching
the platform's posture for the AgentMail/AgentPhone integrations.
"""
from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

__all__ = ["CaptchaResult", "CaptchaSolver"]


@dataclass
class CaptchaResult:
    ok: bool
    token: str | None = None
    provider: str = ""
    error: str | None = None
    cost_note: str = ""


class CaptchaSolver:
    """2captcha / capsolver Turnstile token retrieval (waf-spec §3.4)."""

    def __init__(self, provider: str | None = None, api_key: str | None = None,
                 poll_interval: float = 5.0, max_wait: float = 120.0,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic):
        self.provider = (provider or "").lower() or None
        self.api_key = api_key
        self.poll_interval = poll_interval
        self.max_wait = max_wait
        self._sleep = sleep
        self._clock = clock

    @property
    def configured(self) -> bool:
        return bool(self.provider and self.api_key)

    def solve_turnstile(self, sitekey: str, page_url: str) -> CaptchaResult:
        if not self.configured:
            return CaptchaResult(ok=False, provider=self.provider or "none",
                                 error="CAPTCHA service not configured "
                                       "(set captcha_service.provider + api_key)")
        if not sitekey:
            return CaptchaResult(ok=False, provider=self.provider,
                                 error="no Turnstile sitekey extracted from the page")
        try:
            if self.provider == "2captcha":
                return self._solve_2captcha(sitekey, page_url)
            if self.provider == "capsolver":
                return self._solve_capsolver(sitekey, page_url)
        except Exception as e:  # noqa: BLE001 - report, don't crash the request flow
            return CaptchaResult(ok=False, provider=self.provider, error=str(e))
        return CaptchaResult(ok=False, provider=self.provider,
                             error=f"unsupported CAPTCHA provider '{self.provider}'")

    # ---- providers ----------------------------------------------------- #
    def _http_json(self, url: str, payload: dict[str, Any] | None = None,
                   method: str = "GET") -> dict[str, Any]:
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"} if data else {}
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))

    def _solve_2captcha(self, sitekey: str, page_url: str) -> CaptchaResult:
        # Submit (in.php), then poll (res.php) for the token (waf-spec §3.4).
        submit = "https://2captcha.com/in.php?" + urllib.parse.urlencode({
            "key": self.api_key, "method": "turnstile", "sitekey": sitekey,
            "pageurl": page_url, "json": 1})
        r = self._http_json(submit)
        if str(r.get("status")) != "1":
            return CaptchaResult(ok=False, provider="2captcha",
                                 error=f"submit failed: {r.get('request')}")
        cap_id = r["request"]
        deadline = self._clock() + self.max_wait
        poll = "https://2captcha.com/res.php?" + urllib.parse.urlencode({
            "key": self.api_key, "action": "get", "id": cap_id, "json": 1})
        while self._clock() < deadline:
            self._sleep(self.poll_interval)
            pr = self._http_json(poll)
            if str(pr.get("status")) == "1":
                return CaptchaResult(ok=True, token=pr["request"], provider="2captcha",
                                     cost_note="~$2.99/1000 solves")
            if pr.get("request") != "CAPCHA_NOT_READY":
                return CaptchaResult(ok=False, provider="2captcha",
                                     error=f"poll error: {pr.get('request')}")
        return CaptchaResult(ok=False, provider="2captcha", error="solve timed out")

    def _solve_capsolver(self, sitekey: str, page_url: str) -> CaptchaResult:
        create = self._http_json("https://api.capsolver.com/createTask",
                                 {"clientKey": self.api_key,
                                  "task": {"type": "AntiTurnstileTaskProxyLess",
                                           "websiteURL": page_url,
                                           "websiteKey": sitekey}}, method="POST")
        if create.get("errorId"):
            return CaptchaResult(ok=False, provider="capsolver",
                                 error=create.get("errorDescription", "createTask failed"))
        task_id = create.get("taskId")
        deadline = self._clock() + self.max_wait
        while self._clock() < deadline:
            self._sleep(self.poll_interval)
            res = self._http_json("https://api.capsolver.com/getTaskResult",
                                  {"clientKey": self.api_key, "taskId": task_id},
                                  method="POST")
            if res.get("status") == "ready":
                token = (res.get("solution") or {}).get("token")
                return CaptchaResult(ok=True, token=token, provider="capsolver",
                                     cost_note="~$0.8–2/1000 solves")
            if res.get("errorId"):
                return CaptchaResult(ok=False, provider="capsolver",
                                     error=res.get("errorDescription", "getTaskResult failed"))
        return CaptchaResult(ok=False, provider="capsolver", error="solve timed out")
