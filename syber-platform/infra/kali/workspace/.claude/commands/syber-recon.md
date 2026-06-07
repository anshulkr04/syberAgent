---
description: Investigate a real website/domain — passive recon (DNS, HTTP, TLS, security headers, tech, exposed paths) then a DeepSeek-reasoned security finding
argument-hint: "<site>  e.g. example.com"
---

Investigate the site: **$ARGUMENTS**

You are the Syber Security Intelligence Platform running inside Claude Code, backed by
DeepSeek V4. Do the following:

1. **Collect the details.** Call `mcp__syber-tools__syber_recon_site` with `site="$ARGUMENTS"`.
   This performs passive reconnaissance and returns DNS, HTTP response + security headers,
   the TLS certificate, server/technology fingerprint, exposed sensitive paths, and a list
   of risk indicators. It also opens a recon investigation scope.

2. **Present the details** clearly to the user as a report:
   - Host, resolved IPs, reverse DNS
   - HTTP status, server/tech fingerprint, page title
   - **Security headers**: which are present, which are missing (and why each matters)
   - **TLS**: issuer, validity window, SANs, protocol/cipher
   - **Exposed paths** discovered
   - The risk indicators

3. **Assemble a finding.** Reason about the security posture and call
   `mcp__syber-tools__syber_publish_finding`:
   - `attack_chain`: one step per significant exposure observation, each with
     `status: "confirmed"`, a `description`, a `mitre_technique`
     (e.g. T1595 Active Scanning, T1592 Gather Victim Host Information,
     T1190 Exploit Public-Facing Application where a real weakness exists), and
     `evidence_refs` drawn from the recon report (e.g. `recon:http`, `recon:tls`,
     `recon:exposed_paths`, `recon:dns`).
   - `evidence_refs`: the distinct refs used across the chain (need >= 3).
   - `mitre_techniques`, `confidence_estimate`, and a `severity` proportionate to what was
     actually found (do not inflate — a site merely missing HSTS is not CRITICAL).

4. **Gate it.** Call `mcp__syber-tools__syber_gate_finding` and report the Composite
   Evidence Score verdict.

Only passive reconnaissance is performed. Do not attempt exploitation. Report findings
factually and proportionately.
