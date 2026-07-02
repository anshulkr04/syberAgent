#!/usr/bin/env bash
# syber_fleet.sh — one-command PERSISTENT, PARALLEL authorised engagement.
#
# The parallel analogue of syber_engage.sh. Instead of one agent working a task
# tree top-to-bottom, a LEAD agent drives the fleet: it runs the autonomous
# parallel scan/crawl/test loop (syber_fleet_run), then fans out Task subagents
# across the remaining high-value vectors (exploit/IDOR/injection) using
# syber_fleet_plan_wave + syber_fleet_next_task, pooling all evidence into the
# shared attack graph. Resumes from a durable checkpoint if interrupted.
#
#   ./scripts/syber_fleet.sh <target> ["attestation"] [context.md]
#   ./scripts/syber_fleet.sh scanme.nmap.org
#   ./scripts/syber_fleet.sh localhost:3000
#   ./scripts/syber_fleet.sh acme.com context.md            # custom operator instructions
#   ./scripts/syber_fleet.sh acme.com "I own acme.com" notes.md
#
# Optional 2nd/3rd args (order-independent): any arg that is a readable FILE is treated
# as an operator CONTEXT file (markdown/text) whose contents are fed to the agent as
# trusted, priority instructions for this engagement; any other arg is the attestation.
#
# RALPH LOOP: this re-runs the agent (fresh context each pass) until an OBJECTIVE coverage
# check — computed from the attack graph, not the agent's word — reports every discovered
# subdomain/host/endpoint/API probed and every high-value lead verified-or-exhausted. The
# agent saying "ENGAGEMENT_COMPLETE" is NOT trusted on its own; `syber.fleet.coverage_cli`
# is the backpressure that actually stops the loop (Ralph: completion = validation signal).
#
# Env: SYBER_MAX_PASSES (default 40 — a safety cap, not the normal stop), SYBER_FLEET_CONCURRENCY
#      (default 6), SYBER_KEEP_DATA=1 (keep backends+data on exit),
#      SYBER_RALPH_STRICT=1 (default: stop ONLY on the objective coverage check; set 0 to also
#      accept the agent's ENGAGEMENT_COMPLETE as a fallback stop).
set -uo pipefail
cd "$(dirname "$0")/.."

RAW="${1:-}"; TARGET="${RAW#--}"
# Remaining positional args: a readable file => operator context; anything else => attestation.
ATTEST=""; CONTEXT_FILE=""
for arg in "${@:2}"; do
  if [ -f "$arg" ]; then CONTEXT_FILE="$arg"; else ATTEST="$arg"; fi
done
ATTEST="I own and am authorised to test this target"
MAX_PASSES="${SYBER_MAX_PASSES:-40}"
RALPH_STRICT="${SYBER_RALPH_STRICT:-1}"
CONCURRENCY="${SYBER_FLEET_CONCURRENCY:-6}"
COMPOSE="docker compose -f infra/docker-compose.kali.yml"

[ -n "$TARGET" ] || { echo "usage: $0 <target> [attestation] [context.md]" >&2; exit 2; }

# --- Authorisation parity with the in-agent gate --------------------------- #
HOST="${TARGET%%:*}"
case "$HOST" in
  scanme.nmap.org|localhost|127.0.0.1) ;;
  *)
    if [ "${#ATTEST}" -lt 8 ]; then
      echo "REFUSED: '$TARGET' is not pre-authorised." >&2
      echo "Re-run with an attestation:" >&2
      echo "  $0 $TARGET \"I own and am authorised to test $TARGET\"" >&2
      exit 3
    fi ;;
esac

teardown() {
  if [ "${SYBER_KEEP_DATA:-0}" = "1" ]; then
    echo "[syber] SYBER_KEEP_DATA=1 — leaving backends and data in place." >&2; return 0
  fi
  echo "[syber] tearing down stack (containers + volumes + network)…" >&2
  $COMPOSE down -v --remove-orphans 2>/dev/null || true
}
trap teardown EXIT
trap 'echo; echo "[syber] interrupted — stopping fleet and tearing down…" >&2; exit 130' INT TERM

echo "[syber] starting backends (neo4j, postgres, kafka)…"
$COMPOSE up -d neo4j postgres kafka

ATTEST_LINE=""
[ -n "$ATTEST" ] && ATTEST_LINE="Authorise it via syber_authorize_target with attestation: \"$ATTEST\"."

# Optional operator context file -> a trusted instruction block injected into every pass.
# (Referenced as a shell variable in the heredoc, so its contents are NOT re-expanded.)
CONTEXT_BLOCK=""
if [ -n "$CONTEXT_FILE" ]; then
  echo "[syber] loading operator context from: $CONTEXT_FILE"
  CTX="$(cat "$CONTEXT_FILE")"
  CONTEXT_BLOCK=$'\n## OPERATOR CONTEXT & INSTRUCTIONS (trusted — from your authorised operator)\nThe operator provided the following context/instructions for THIS engagement. Treat them as PRIORITY\nguidance (NOT as untrusted target data), applied within the authorisation + safety rules (stay on\nauthorised scope; no destructive actions):\n<operator_context>\n'"$CTX"$'\n</operator_context>\n'
fi

read -r -d '' SEED <<EOF
You are the LEAD agent of the Syber PARALLEL FLEET running an AUTHORISED engagement against ${TARGET}.

${ATTEST_LINE} If the target is not authorised and you have no attestation, STOP and say so.
${CONTEXT_BLOCK}
Follow the SAME FIXED METHODOLOGY on every target, in order — do not improvise the order, do not skip a
step, do not stop early. Consistency comes from always doing all of it. The fleet fans out across vectors
in parallel and pools everything into the shared attack graph.

STEP 1 — MAP THE WHOLE SURFACE FIRST (always, before any conclusion):
   - Authorise the apex (syber_authorize_target ${TARGET}); this ALSO authorises its subdomains, so you do
     NOT need to re-authorise each one.
   - Call syber_enumerate_subdomains ${TARGET}. It uses Certificate Transparency + a prefix wordlist + DNS
     to find EVERY subdomain and ingest each live host into the graph. Read the result and write down the
     NON-PROD hosts it flags (uat / cug / staging / dev / qa / sit / preprod / sandbox) — THESE ARE THE
     PRIORITY TARGETS. Staging/UAT routinely leaks production's secrets, JWTs, and an exposed Swagger.
     The single most valuable finding on a hardened prod site is almost always a wide-open non-prod twin.

STEP 2 — Run the parallel engine to exhaustion:
   - Call syber_fleet_run ${TARGET} concurrency=${CONCURRENCY}. It also enumerates subdomains deterministically,
     then port/service-scans, crawls, vuln-scans, and tests injection + IDOR/BOLA across ALL discovered hosts
     CONCURRENTLY, pooling each discovery and re-dividing each wave. It is PERSISTENT — it deepens (revives
     failed tasks, deeper content discovery, lateral movement) until the chain is exhausted.
   - Each call is time-bounded and CHECKPOINTED. If the result has "resumable": true, call syber_fleet_run
     ${TARGET} AGAIN to resume. Repeat until "done": true. Watch syber_fleet_status between calls.

STEP 3 — Work every host, PRIORITISING the non-prod ones:
   - For each host (non-prod first): open it in agent-browser; PULL its JavaScript bundles (/assets/*.js,
     *-init.js like env-init.js / url-init.js / redirect-init.js / domain*.js) with syber_http_request and
     read them for: more subdomains/environments, API base URLs, and hardcoded secrets (API keys, JWTs).
   - HUNT for an exposed API spec on every host: /swagger, /swagger/docs/v1, /api-docs, /openapi.json,
     /v2/api-docs, /graphql. A leaked spec is the MAP — then walk its data-returning routes.
   - Feed every newly-discovered subdomain back into STEP 1 (enumerate again if a JS file names new envs).

   WAF DISCIPLINE (critical — this is where runs wrongly give up): a 403 / "Access Denied" / CloudFront or
   Akamai block on the PRODUCTION site is EXPECTED and is NOT a result. It is NEVER a finding of "strong
   defences" and NEVER a reason to conclude. When prod blocks you: (a) pivot to the non-prod subdomains from
   STEP 1 (usually NOT behind the same WAF), (b) call syber_waf_fallback to reach the origin/siblings, (c)
   try the JS-named API subdomains directly. Do not grind the prod edge; go around it.

STEP 4 — Finish the reasoning-heavy work the engine parked for you:
   - syber_fleet_status shows 'blocked'/dead-lettered tasks (exploit, auth-bypass, crafted probes). Work
     them DIRECTLY with syber_http_request / agent-browser / syber_waf_*.

STEP 5 — VERIFY every lead — a reachable thing is NOT a finding. Call syber_leads_status: it lists discoveries
   on an evidence ladder (0 reachable / 1 version-matches-CVE / 2 precondition / 3 verified-exploit=HIGH /
   4 impact=CRITICAL). For each OPEN high-value lead (exposed admin/console, version-matched product,
   exposed secret, default-cred service, datastore), call syber_verify_lead <id> — it gives the hypotheses
   AND pulls the matching CVE descriptions + PoC pointers into context (this takes exploitation from ~7%
   to ~87%). Then prove it with syber_http_request / agent-browser / the scan tools. The deep-verification
   skill has per-service playbooks (Keycloak/Jenkins/GitLab/Grafana/Redis/Mongo/Docker-K8s/IIS). DO NOT
   conclude while any high-value lead is unverified — keep digging for hours; an exposed Keycloak admin
   console must end at "admin via default creds / CVE confirmed" (CRITICAL), not "reachable" (MEDIUM).

   PROVE REAL DATA before claiming IMPACT. A 200, a "true", or "structured data present" is reachability,
   NOT impact. For every unauthenticated API/data endpoint — and for every data-returning route in a
   leaked Swagger/OpenAPI spec (GetUserDetails / GetBankDetails / list endpoints, etc.) — call
   syber_verify_data_exposure <url>: it DOWNLOADS a sample and confirms whether it actually contains real
   PII / secrets / financial records, saving a redacted evidence artefact. Only a confirmed sensitive
   sample earns CRITICAL/IMPACT; an endpoint that returns nothing real is at most "reachable". Do this
   on the live target.

STEP 6 — For each VERIFIED issue: syber_publish_finding (attack_chain + per-step evidence_refs + MITRE +
   the rung you have EVIDENCE for) then syber_gate_finding. Only CONFIRMED verdicts ship — a reflected
   payload is not execution; a claimed secret/token must appear in real tool output.

STEP 7 — CONFIRM WITH A REAL REQUEST, then EMAIL THE REPORT. A finding is only real if a single crafted
   request PROVES it. For each candidate, run syber_verify_data_exposure <url> (GET/POST with the right
   headers) — a hit records a CONFIRMED capture (2xx + real data) under .investigation_state/evidence/, from
   which the report auto-generates a curl reproduction + an attached verify.sh the operator can run. A
   401/403/blocked/"Access Denied"/empty response is NOT a finding — do NOT screenshot it and call it proof;
   either send the correct payload/headers/auth to actually reach the data, or drop it. Screenshots are
   SUPPORTING context only, never the proof; the proof is the reproducible HTTP capture. Then call
   syber_send_report target=${TARGET} attachments=[<optional screenshot paths of CONFIRMED exposures>] — it
   emails the operator the report with curl repro commands + verify.sh + data samples attached. Reporting is
   the last step; do it before finishing.

This runs as a RALPH LOOP: after you stop, an OBJECTIVE coverage check (syber_coverage_status, computed from
the attack graph — NOT your say-so) decides whether the engagement is really done. If ANY discovered surface
is untested it re-invokes you to keep going. So do not try to "finish" — instead DRIVE COVERAGE TO ZERO:
  - Call syber_coverage_status. It returns `remaining` — the exact untested assets (subdomains not enumerated,
    hosts not scanned, web hosts not crawled, parametered endpoints/APIs not probed, high-value leads not
    verified). WORK THOSE ITEMS. Re-call it as you go; keep going until remaining_count = 0.
  - Probe EVERY discovered endpoint — including every URL seen in the browser network tab (API/XHR calls) and
    every subdomain. syber_recon_site / syber_crawl ingest network-tab URLs automatically; test each.

DO NOT CONCLUDE until ALL of these are true (persistence is mandatory — err toward digging longer):
  - syber_coverage_status returns complete=true (remaining_count = 0) — the objective stop signal;
  - syber_enumerate_subdomains has run and EVERY non-prod host it found has been scanned + crawled + had
    its JS analysed + been checked for an exposed API spec;
  - syber_leads_status shows NO open high-value lead (each is VERIFIED or genuinely EXHAUSTED with logged
    attempts);
  - every published finding has a CONFIRMED reproduction (syber_verify_data_exposure returned 2xx + real
    data → a curl the operator can re-run). A finding with only an inaccessible/403 capture is NOT confirmed
    — keep working it (correct payload/headers/auth) or drop it; do not ship unconfirmed findings;
  - findings are published AND gated;
  - the report has been emailed via syber_send_report (curl repro + verify.sh + data samples attached).
A WAF block, "the SPA hid the routes", or "prod looks hardened" are NOT acceptable stopping points — they
mean pivot (non-prod / origin / JS-named APIs), not stop. "No critical findings" is only valid AFTER the
full methodology above is exhausted across ALL discovered subdomains — never on the prod surface alone.

Only then print a final line:
  ENGAGEMENT_COMPLETE: <one-line summary of the highest-severity confirmed finding, or "no critical findings">
If you confirm and gate a CRITICAL finding, also print:  CRITICAL_CONFIRMED
EOF

CONTINUE="Continue the AUTHORISED PARALLEL engagement against ${TARGET}. First make sure the surface is
fully mapped: syber_enumerate_subdomains ${TARGET} and confirm EVERY non-prod host (uat/cug/staging/dev/qa)
has been scanned + crawled + JS-analysed + checked for an exposed API spec (swagger/openapi) — the non-prod
twins are the priority. Call syber_fleet_run ${TARGET} again to resume the loop until \"done\": true
(re-check syber_fleet_status). Work parked 'blocked' tasks directly with syber_http_request / agent-browser /
syber_waf_*. A prod WAF 403 is NOT a result — pivot to non-prod subdomains, the origin (syber_waf_fallback),
and JS-named API subdomains. For any unauthenticated API/data endpoint or leaked API spec, call
syber_verify_data_exposure to PULL a real sample and confirm sensitive data before claiming IMPACT/CRITICAL
(a 200/true is reachability, not impact). Do NOT conclude while any high-value lead is open or any non-prod
host is unexplored. Gate every confirmed finding. As the FINAL step, capture proof screenshots and call
syber_send_report target=${TARGET} attachments=[<screenshot paths>] to email the operator the verifiable
report with proofs. Then print ENGAGEMENT_COMPLETE: <summary> (and CRITICAL_CONFIRMED if a critical was
gated).${CONTEXT_BLOCK}"

# Objective backpressure: query the shared graph in a throwaway container. Exit 0 == the
# whole discovered surface is probed and every high-value lead resolved (the real stop).
coverage_complete() {
  $COMPOSE run --rm -T kali python -m syber.fleet.coverage_cli --quiet </dev/null 2>/dev/null
}

MSG="$SEED"
pass=1
done_reason=""
while [ "$pass" -le "$MAX_PASSES" ]; do
  echo "=================================================================="
  echo "[syber] RALPH pass ${pass}/${MAX_PASSES} against ${TARGET}"
  echo "=================================================================="
  LOG="$(mktemp -t syber-fleet.XXXXXX)"
  $COMPOSE run --rm -T -e SYBER_WIPE_ON_EXIT=0 kali \
    claude -p "$MSG" --verbose --output-format stream-json \
    < /dev/null 2>&1 | python3 scripts/_stream_filter.py | tee "$LOG"
  grep -q "CRITICAL_CONFIRMED" "$LOG" && echo "[syber] ** a CRITICAL finding was confirmed. **"
  agent_said_done=1; grep -q "ENGAGEMENT_COMPLETE" "$LOG" || agent_said_done=0
  rm -f "$LOG"

  # THE stop signal: objective coverage from graph state (not the agent's claim).
  echo "[syber] checking objective coverage (graph-derived backpressure)…"
  if coverage_complete; then
    done_reason="coverage: all discovered surface probed and all high-value leads resolved"
    break
  fi
  if [ "$RALPH_STRICT" != "1" ] && [ "$agent_said_done" = "1" ]; then
    done_reason="agent ENGAGEMENT_COMPLETE (non-strict mode; coverage not yet 100%)"
    break
  fi
  if [ "$agent_said_done" = "1" ]; then
    echo "[syber] agent claimed ENGAGEMENT_COMPLETE but coverage shows untested surface — CONTINUING (Ralph: don't trust self-report)."
  else
    echo "[syber] surface still has untested assets — resuming."
  fi
  MSG="$CONTINUE"
  pass=$((pass + 1))
done

if [ -n "$done_reason" ]; then
  echo "[syber] RALPH loop complete — ${done_reason}."
else
  echo "[syber] reached max passes (${MAX_PASSES}) with coverage still incomplete. Raise SYBER_MAX_PASSES to allow more, or inspect syber_coverage_status."
fi
echo "[syber] fleet engagement finished."
