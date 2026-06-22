# Hardening your own endpoints behind Cloudflare (waf-spec §6)

The other half of the WAF spec: if the Syber harness *exposes* APIs (`/api/v1/call`,
`/tts`, `/transcribe`, `/agent`), protect them with Cloudflare while still letting
your own authenticated agents through. This directory holds the deployment config;
the runtime traversal code lives in `syber/waf/`.

## 1. Custom WAF rules (§6.1)
`waf_rules.example.json` is the ordered rule set (allow authed agents → block bad
ASNs → rate-limit the API → block AI scrapers → challenge low-score bots). Apply it
either way:

- **Dashboard:** Security → WAF → Custom Rules, transcribe each rule (first match wins).
- **API:** PUT the ruleset to the `http_request_firewall_custom` phase:
  ```bash
  curl -X PUT \
    "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/rulesets/phases/http_request_firewall_custom/entrypoint" \
    -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" \
    --data @waf_rules.example.json
  ```
Replace `<YOUR_AGENT_TOKEN>` and the `<ABUSE_ASN_*>` placeholders first.

## 2. Three-tier auth (§6.2)
```
Internet → Cloudflare (WAF + Bot Mgmt) → Nginx/API Gateway (Auth + Rate Limit)
  → Backend (Authorisation + Input Validation) → LLM / Database
```
The WAF filters obvious abuse; the gateway validates the `X-Agent-Token`/JWT and
enforces app-level limits; the backend does per-resource authorisation. Bypassing
one tier still leaves the others.

## 3. Bot Management (§6.3)
Enable Bot Fight Mode, the AI-Bot-Block toggle, Super Bot Fight Mode (challenge
score < 30, block < 10), and Session scoring.

## 4. Allowlist your own agents (§6.4)
- **A — `X-Agent-Token` header** (rule 1 above): simplest and most reliable.
- **B — IP Access Rules:** allow your agents' static egress IPs.
- **C — Agent Registry / Web Bot Auth:** the future-proof cryptographic option
  (waf-spec §3.7) when it ships.

Send a consistent `User-Agent` for logging even though you don't authenticate on it
(UA is trivially spoofed).
