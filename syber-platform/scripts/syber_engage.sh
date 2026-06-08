#!/usr/bin/env bash
# syber_engage.sh — one-command AUTHORISED engagement.
#
# Boots the backends, seeds the agent with a thorough Pentest-Task-Tree prompt for
# a target, and runs it. If the agent stops BEFORE completing the coverage checklist
# (a crash, a timeout, a context compaction), it is resumed to finish — bounded by a
# max pass count. It stops cleanly when coverage is complete, a critical finding is
# confirmed, or the agent judges it is done. On exit the whole stack is torn down.
#
#   ./scripts/syber_engage.sh <target> ["attestation you own / are authorised to test it"]
#   ./scripts/syber_engage.sh scanme.nmap.org            # pre-authorised, no attestation
#   ./scripts/syber_engage.sh localhost:3000             # your local app
#
# Env: SYBER_MAX_PASSES (default 6), SYBER_KEEP_DATA=1 (keep backends+data on exit).
#
# NOTE ON SCOPE: this resumes THOROUGHNESS — it does not pressure the agent past a
# refusal or an authorisation boundary, and "no critical found" is a valid result,
# not a reason to keep grinding. Active recon is for targets you are authorised to
# test; pre-authorised hosts are scanme.nmap.org / localhost, everything else needs
# a truthful attestation (the same control the in-agent gate enforces).
set -uo pipefail
cd "$(dirname "$0")/.."

RAW="${1:-}"; TARGET="${RAW#--}"          # accept "--target" or "target"
ATTEST="I own and am authorised to test"
MAX_PASSES="${SYBER_MAX_PASSES:-6}"
COMPOSE="docker compose -f infra/docker-compose.kali.yml"

[ -n "$TARGET" ] || { echo "usage: $0 <target> [attestation]" >&2; exit 2; }

# --- Authorisation parity with the in-agent gate --------------------------- #
HOST="${TARGET%%:*}"
case "$HOST" in
  scanme.nmap.org|localhost|127.0.0.1) ;;
  *)
    if [ "${#ATTEST}" -lt 8 ]; then
      echo "REFUSED: '$TARGET' is not pre-authorised." >&2
      echo "Active recon is only for targets you own or are authorised to test." >&2
      echo "Re-run with an attestation:" >&2
      echo "  $0 $TARGET \"I own and am authorised to test $TARGET\"" >&2
      exit 3
    fi ;;
esac

# --- Teardown the entire stack on exit (unless told to keep) ---------------- #
teardown() {
  if [ "${SYBER_KEEP_DATA:-0}" = "1" ]; then
    echo "[syber] SYBER_KEEP_DATA=1 — leaving backends and data in place." >&2; return 0
  fi
  echo "[syber] tearing down stack (containers + volumes + network)…" >&2
  $COMPOSE down -v --remove-orphans 2>/dev/null || true
}
# EXIT runs cleanup once. A single Ctrl+C must STOP the engagement loop (not just
# interrupt the current pass and roll on to the next), so INT/TERM exits — which
# fires the EXIT trap and tears down exactly once.
trap teardown EXIT
trap 'echo; echo "[syber] interrupted — stopping engagement and tearing down…" >&2; exit 130' INT TERM

echo "[syber] starting backends (neo4j, postgres, kafka)…"
$COMPOSE up -d neo4j postgres kafka

ATTEST_LINE=""
[ -n "$ATTEST" ] && ATTEST_LINE="Authorise it via syber_authorize_target with attestation: \"$ATTEST\"."

read -r -d '' SEED <<EOF
You are the Syber agent running an AUTHORISED security engagement against ${TARGET}.

First call syber_pentest_plan ${TARGET} and follow the Pentest Task Tree top-to-bottom.
${ATTEST_LINE} If the target is not authorised and you have no attestation, STOP and say so.

Work the full tree, waiting for each tool to finish (scans take minutes — do not abandon them):
  1. syber_full_scan  — ports, services/versions, nuclei.
  2. syber_crawl      — map endpoints, forms, and PARAMETERS.
  3. syber_test_access_control on every object-bearing endpoint  — IDOR/BOLA is the priority.
  4. syber_test_injection on parameterised endpoints  — reflected XSS / error-based SQLi / SSRF.
  5. Inspect web services in the real browser (agent-browser); use syber_http_request for crafted probes.
  6. syber_get_graph_context to review the attack surface.
  7. syber_publish_finding for each CONFIRMED issue (attack_chain + per-step evidence_refs +
     exploitability + EVIDENCE-BASED severity), then syber_gate_finding.

Severity discipline: rate by demonstrated exploitability, not instinct. Confirm before reporting;
one unverified signal is not a finding. Do not fabricate or inflate — "no critical issue found" is
a valid, correct outcome if that is what the evidence shows.

When you have completed every task in the tree (or recorded why a task is N/A), print a final line:
  ENGAGEMENT_COMPLETE: <one-line summary of the highest-severity confirmed finding, or "no critical findings">
If you confirm and gate a CRITICAL finding, also print:  CRITICAL_CONFIRMED
EOF

CONTINUE="Continue the AUTHORISED engagement against ${TARGET}. Re-check syber_pentest_plan and
complete any task still outstanding (service enum, crawl, IDOR/BOLA, injection, browser inspection,
graph review). If a scan timed out, re-run it with a longer SYBER_SCAN_TIMEOUT rather than skipping
it. When every task is done, print ENGAGEMENT_COMPLETE: <summary> (and CRITICAL_CONFIRMED if a
critical was gated). Do not repeat work already completed; do not pad with speculation."

MSG="$SEED"
pass=1
while [ "$pass" -le "$MAX_PASSES" ]; do
  echo "=================================================================="
  echo "[syber] engagement pass ${pass}/${MAX_PASSES} against ${TARGET}"
  echo "=================================================================="
  LOG="$(mktemp -t syber-pass.XXXXXX)"
  # Keep data across passes so the graph/findings accumulate; the final teardown wipes it.
  #   -T            : no pseudo-TTY (we're piping)
  #   < /dev/null   : don't wait 3s for stdin in headless print mode
  #   --verbose --output-format stream-json : emit each step as it happens (no silent blob)
  #   _stream_filter.py : show only assistant text + one-line tool markers (drops the JSON)
  $COMPOSE run --rm -T -e SYBER_WIPE_ON_EXIT=0 kali \
    claude -p "$MSG" --verbose --output-format stream-json \
    < /dev/null 2>&1 | python3 scripts/_stream_filter.py | tee "$LOG"

  if grep -q "ENGAGEMENT_COMPLETE" "$LOG"; then
    echo "[syber] agent reported coverage complete."
    grep -q "CRITICAL_CONFIRMED" "$LOG" && echo "[syber] ** a CRITICAL finding was confirmed. **"
    rm -f "$LOG"; break
  fi
  echo "[syber] agent stopped before completing coverage — resuming to finish the task tree."
  rm -f "$LOG"
  MSG="$CONTINUE"
  pass=$((pass + 1))
done

[ "$pass" -gt "$MAX_PASSES" ] && \
  echo "[syber] reached max passes (${MAX_PASSES}); stopping. Raise SYBER_MAX_PASSES to allow more."
echo "[syber] engagement finished."
