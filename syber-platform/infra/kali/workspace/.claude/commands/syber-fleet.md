---
description: Persistent PARALLEL engagement of an AUTHORISED target — the fleet fans out across vectors at once, pools evidence into the attack graph, re-divides, and does not stop until the chain is exhausted
argument-hint: "<target>  e.g. localhost:3000 (must be authorised)"
---

Run a persistent, PARALLEL engagement against **$ARGUMENTS** using the fleet. Unlike the linear
`/syber-pentest` flow (one vector at a time), the fleet fans out across vectors CONCURRENTLY, pools
every discovery into the shared attack graph, and re-divides each wave — and it does not give up at an
empty result; it deepens until the whole attack chain is exhausted.

1. **Authorise.** `mcp__syber-tools__syber_list_authorized`; if **$ARGUMENTS** isn't listed and isn't a
   built-in test host (scanme.nmap.org / localhost), STOP and have the operator attest ownership, then
   `mcp__syber-tools__syber_authorize_target`. Never test an unauthorised target.

2. **Run the parallel engine to exhaustion.** Call `mcp__syber-tools__syber_fleet_run` with
   `target="$ARGUMENTS"`. It runs the autonomous parallel loop in-process (a thread pool): port/service
   scan, crawl, vuln scan, injection, and IDOR/BOLA across discovered hosts at once, pooling into the
   graph and re-dividing each wave; it deepens (revives failed tasks, deeper content discovery, lateral
   movement to reachable hosts, expansion to already-authorised siblings) until exhausted.
   - Each call is **time-bounded + checkpointed**. If the result has `"resumable": true`, call
     `syber_fleet_run` **again** with the same target — it resumes from the checkpoint. **Repeat until
     `"done": true`.** Use `mcp__syber-tools__syber_fleet_status` between calls to watch coverage and the
     open frontier (and `syber_fleet_plan_wave` to preview the next wave — read-only).

3. **VERIFY every lead — a reachable thing is not a finding.** `mcp__syber-tools__syber_leads_status` lists
   discoveries on an evidence ladder (0 reachable / 1 version-matches-CVE / 2 precondition / 3 verified=HIGH
   / 4 impact=CRITICAL). For each OPEN high-value lead (exposed admin/console, version-matched product,
   exposed secret, default-cred service, datastore, auth-bypass candidate), call
   `mcp__syber-tools__syber_verify_lead <id>` — it returns the hypotheses to test AND pulls the matching
   **CVE descriptions + PoC pointers into context** (do this the moment you pin a version; it takes
   exploitation from ~7% to ~87%). Then prove it with `syber_http_request` / `agent-browser` / the scan
   tools, following the `deep-verification` skill's per-service playbooks. **Do not conclude while any
   high-value lead is unverified** — keep digging; an exposed Keycloak admin console must end at "admin via
   default creds / CVE confirmed" (CRITICAL), not "reachable" (MEDIUM).

4. **Finish the parked, reasoning-heavy work.** `syber_fleet_status` lists `blocked`/dead-lettered tasks;
   work them directly with `syber_http_request`, `agent-browser`, and `syber_waf_*`.

5. **Synthesise + gate.** `mcp__syber-tools__syber_get_graph_context` to review the ranked attack surface,
   then `syber_publish_finding` per VERIFIED issue (attack_chain + per-step `evidence_refs` + MITRE + the
   rung you have evidence for) → `syber_gate_finding`. Conclude only when `syber_leads_status` shows no
   open high-value lead.

**Discipline.** Only CONFIRMED issues ship — a reflected payload is not execution; a claimed secret must
appear verbatim in real tool output. No HIGH/CRITICAL without concrete demonstrated exploitability; when
unsure, rate LOWER. Test only what is authorised.
