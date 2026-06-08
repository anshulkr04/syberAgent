---
description: Investigate a website with a REAL browser (agent-browser) — never curl — then graph + DeepSeek finding
argument-hint: "<site>  e.g. example.com"
---

Investigate the site **$ARGUMENTS** using a real browser. **Do not use curl/wget/urllib for any
web content** — use the real browser so the target is not flagged as a bot.

1. **Browser recon.** Call `mcp__syber-tools__syber_recon_site` with `site="$ARGUMENTS"`. This
   navigates with real Chrome (agent-browser), captures status + security headers via HAR, reads
   the rendered DOM (title, technologies, forms/inputs/links), takes a screenshot, inspects DNS
   and the TLS certificate, and ingests the host/web-endpoint/technologies/certificate into the
   Neo4j attack-surface graph.

2. **Look closer with the browser (encouraged).** Drive `agent-browser` yourself to inspect
   anything interesting: `agent-browser open <url> && agent-browser snapshot -i`, examine
   forms/login pages, `agent-browser screenshot evidence.png`. Re-snapshot after any navigation.

3. **Read the graph.** Call `mcp__syber-tools__syber_get_graph_context` for the host to see its
   exposure (technologies, web endpoints, certificate, risk score) and the ranked attack surface.

4. **Report** clearly: host/IPs, HTTP status + redirect chain, **the real User-Agent the site
   saw** (proving browser-based access), present/missing security headers (and why each matters),
   detected technologies, TLS cert (issuer/validity/SANs), forms present, and the risk indicators.

5. **Finding.** Call `mcp__syber-tools__syber_publish_finding` — attack_chain steps with
   `evidence_refs` (`recon:http`, `recon:tls`, `recon:dns`), MITRE T-IDs (e.g. T1592 Gather Victim
   Host Information, T1595 Active Scanning), `confidence_estimate`, an `exploitability`
   (none/theoretical/known-exploit/poc/confirmed/weaponized/unknown), and a `severity` by
   **evidence**. Then `mcp__syber-tools__syber_gate_finding`.

**Severity discipline (don't over-rate).** Severity = exploitability × exposure × impact, not
instinct. Missing HSTS/CSP is LOW at most. Version/server banners and **public keys** (TLS cert
keys, SSH host keys — they are *meant* to be public) are **INFO, not vulnerabilities**. A valid
TLS cert is normal. Reserve HIGH/CRITICAL for concrete exploitability — an exposed `/.git`/`.env`
with live contents, default/weak creds, a confirmed exploit. When unsure, rate LOWER.

Passive recon only here (no exploitation). Report factually.
