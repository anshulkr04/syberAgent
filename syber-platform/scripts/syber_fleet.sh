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
# Env: SYBER_MAX_PASSES (default 12 — each pass digs deep + carries state forward), SYBER_FLEET_CONCURRENCY
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
MAX_PASSES="${SYBER_MAX_PASSES:-12}"
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

# Rebuild the kali image so code/doctrine changes are always in the running container.
# `docker compose run` does NOT rebuild on its own once the image exists, so without this
# every engagement would silently run stale code. Docker layer caching makes this ~seconds
# when nothing changed. Skip with SYBER_NO_BUILD=1.
if [ "${SYBER_NO_BUILD:-0}" != "1" ]; then
  echo "[syber] building kali image (cached if unchanged; SYBER_NO_BUILD=1 to skip)…"
  if ! $COMPOSE build kali; then
    echo "[syber] image build FAILED — aborting so we don't run stale code." >&2
    exit 1
  fi
fi

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
You are the LEAD of the Syber offensive-security fleet on an AUTHORISED engagement against ${TARGET}.
${ATTEST_LINE} If it is not authorised and you have no attestation, STOP and say so.
${CONTEXT_BLOCK}
Your job is to find and PROVE real, high-impact vulnerabilities — not to file hygiene noise. Work like a
top bug-bounty hunter: map the whole surface, then relentlessly deep-dive each promising thing to IMPACT.

RUN THE ENGINE (it does the mechanical breadth for you):
  syber_authorize_target ${TARGET} (also authorises subdomains), then syber_fleet_run ${TARGET}
  concurrency=${CONCURRENCY}. It enumerates subdomains, scans, crawls, harvests tokens, and probes
  injection/IDOR/auth across all hosts in parallel. If the result says "resumable": true, call it AGAIN
  until "done": true. syber_coverage_status shows exactly what surface is still untested — drive it to zero.

THE ONE RULE THAT MATTERS — reachability is NOT a finding; IMPACT is. After EVERY discovery ask
"what does this unlock?" and take the next hop until you either PROVE impact or genuinely exhaust it:
  - Exposed API key  -> syber_test_api_key <key>: is it unrestricted/billable? A restricted key = INFO, drop it.
  - JWT / token      -> harvested automatically; syber_auth_retest <url> replays it against 401/403 endpoints.
                        Also decode it, try alg:none / weak-secret / forge an admin claim (jwt_tool).
  - 401/403 API      -> NOT "secure". Get a token (syber_harvest_credentials / log in) then syber_auth_retest.
  - Exposed API/data -> syber_verify_data_exposure <url>: pull a REAL sample. Real PII/secrets = impact.
  - Swagger/API docs -> walk the data routes; with two accounts test IDOR/BOLA (fetch A's object as B).
  - Login/signup     -> actually register (syber_provision_identity -> OTP via syber_check_inbox/read_sms ->
                        syber_add_session), then test the authenticated surface + IDOR + password-reset/ATO.
  - .git/.env/creds  -> dump, extract secrets, then USE them (aws sts get-caller-identity, DB, other APIs).
  - CHAIN low findings: exposed .env -> signing secret -> forge admin JWT -> admin endpoint from the docs =
    one CRITICAL, not three LOWs. Severity is the impact at the END of the chain.
  The deep-verification skill has the exact commands per case — read it. A WAF 403 on prod is expected: pivot
  to non-prod subdomains / the origin (syber_waf_fallback) / JS-named API hosts. Never conclude on a 403.
  GET PAST 403s: on any 401/403 endpoint call syber_bypass_403 <url> — it auto-tries IP-trust headers
  (X-Forwarded-For=127.0.0.1…), path normalization (/..;/  //  /%2e/  case), method fuzzing, AND the Vercel
  x-vercel-protection-bypass secret (harvested from JS/env) — and tells you the exact header/path/method that
  worked. For a Vercel-WAF'd site, hunt the bypass secret in JS bundles/env; a *.vercel.app preview deployment
  often escapes the custom-domain WAF rules too. (True Cloudflare/Akamai JS challenges still need agent-browser
  render / syber_waf_fallback — bypass_403 is for app-level/IP-allowlist/Vercel-protection blocks.)
  ASSESS WITH THE REAL BROWSER: when the HTTP client / an XHR gets a CloudFront/Akamai 403 or challenge, that
  is NOT the page — drive agent-browser to NAVIGATE to the URL, let the JS challenge auto-solve, and read the
  rendered DOM (agent-browser open <url>; wait; get the HTML). syber_http_request now auto-renders on a
  challenge, but for anything blocked, use agent-browser directly to see the real content before deciding.
  If even the real browser is blocked on EVERY host (challenge never clears), you are IP/egress-blocked from
  this container — say so explicitly as a coverage limitation; do NOT report that as "the target is secure".

SEVERITY = demonstrated impact (Bugcrowd VRT / CVSS): RCE, auth bypass, IDOR exposing others' data, an
unrestricted key with real abuse, secrets that actually authenticate = HIGH/CRITICAL. Missing headers,
version banners, restricted keys, self-XSS = INFO/LOW — do NOT dress these up. Report FEW, REAL, proven bugs.

PROOF: only what is CONFIRMED (a request that returned real data / a secret that authenticated / a forged
token the server accepted) ships. syber_publish_finding (attack_chain + evidence_refs + the rung you have
EVIDENCE for) -> syber_gate_finding. The report attaches proofs automatically. Then syber_send_report target=${TARGET}.

HONESTY (non-negotiable): chase impact hard, but NEVER invent or inflate a finding. If, after genuinely
exhausting the surface (logged in or login_exhausted, tokens replayed, data routes tested across all
subdomains), there is no critical, then "no critical findings" is the correct, honest result — a fabricated
critical is a failure. Keep going only while syber_coverage_status still lists untested surface.

When coverage is genuinely zero and confirmed findings are gated + reported, print:
  ENGAGEMENT_COMPLETE: <one-line summary of the highest-severity CONFIRMED finding, or "no critical findings">
If you confirmed and gated a CRITICAL, also print:  CRITICAL_CONFIRMED
EOF

CONTINUE="Resume the AUTHORISED engagement against ${TARGET}. Call syber_coverage_status — it lists the exact
untested surface; WORK THOSE items (they carry forward from prior passes; don't repeat finished work). Keep
calling syber_fleet_run ${TARGET} until \"done\": true. DEEP-DIVE every discovery to IMPACT (test API keys
with syber_test_api_key, replay tokens with syber_auth_retest, pull data with syber_verify_data_exposure,
log in and test IDOR/ATO) — reachability is not a finding. Chase HIGH/CRITICAL impact, not hygiene noise;
never fabricate. Gate every confirmed finding, then syber_send_report target=${TARGET}. When coverage is zero
print ENGAGEMENT_COMPLETE: <summary> (and CRITICAL_CONFIRMED if a critical was gated).${CONTEXT_BLOCK}"

# Objective backpressure: query the shared graph in a throwaway container. Exit 0 == the
# whole discovered surface is probed and every high-value lead resolved (the real stop).
coverage_complete() {
  $COMPOSE run --rm -T kali python -m syber.fleet.coverage_cli --quiet </dev/null 2>/dev/null
}

# Carry-forward digest: markdown summary of what's already discovered/confirmed/tried +
# the remaining untested surface. Injected into the NEXT pass so a fresh context builds on
# prior work instead of repeating it (Ralph: state lives on disk, read it first).
engagement_digest() {
  $COMPOSE run --rm -T kali python -m syber.fleet.coverage_cli --digest </dev/null 2>/dev/null
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
  # Carry the prior passes' state into this one so the fresh context builds forward.
  echo "[syber] building carry-forward digest for the next pass…"
  DIGEST="$(engagement_digest)"
  if [ -n "$DIGEST" ]; then
    MSG="${CONTINUE}

${DIGEST}"
  else
    MSG="$CONTINUE"
  fi
  pass=$((pass + 1))
done

if [ -n "$done_reason" ]; then
  echo "[syber] RALPH loop complete — ${done_reason}."
else
  echo "[syber] reached max passes (${MAX_PASSES}) with coverage still incomplete. Raise SYBER_MAX_PASSES to allow more, or inspect syber_coverage_status."
fi

# GUARANTEED REPORT: send the email ourselves from durable state (graph findings + evidence
# volume), regardless of what the agent did or the result. Runs BEFORE teardown wipes data.
# Skip with SYBER_NO_REPORT=1. Retried once on a transient Resend/network hiccup.
if [ "${SYBER_NO_REPORT:-0}" != "1" ]; then
  echo "[syber] sending engagement report to the operator (guaranteed, from durable state)…"
  sent=0
  for attempt in 1 2; do
    OUT="$($COMPOSE run --rm -T kali python -m syber.reporting --target "${TARGET}" </dev/null 2>&1)"
    echo "$OUT"
    case "$OUT" in
      *"[report] sent"*) sent=1; break ;;
      *) echo "[syber] report attempt ${attempt} did not confirm send; retrying…" >&2; sleep 3 ;;
    esac
  done
  [ "$sent" = "1" ] || echo "[syber] WARNING: report email could not be confirmed sent — check RESEND_API_KEY / SYBER_REPORT_TO / verified sender domain." >&2
fi
echo "[syber] fleet engagement finished."
