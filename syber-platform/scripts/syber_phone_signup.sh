#!/usr/bin/env bash
# syber_phone_signup.sh — ONE-TIME AgentPhone bootstrap.
#
# Provisions a real phone number for the agent to RECEIVE signup OTP/SMS during
# IDOR/BOLA multi-account testing. Prints the creds to paste into syberAgent/.env.
# This costs real money (≈$3/mo per number; ~$5 signup credit covers month one).
#
#   ./scripts/syber_phone_signup.sh you@example.com            # OTP goes to your email
#   ./scripts/syber_phone_signup.sh --auto                     # OTP auto-read via AgentMail
#
# --auto needs AGENTMAIL_API_KEY in .env: it creates a throwaway AgentMail inbox,
# uses it as the signup email, and reads the OTP back automatically (no human step).
set -uo pipefail
cd "$(dirname "$0")/.."
API="https://api.agentphone.ai"
[ -f ../.env ] && set -a && . ../.env && set +a   # load keys

need() { command -v "$1" >/dev/null || { echo "missing: $1" >&2; exit 1; }; }
need curl; need jq

AUTO=0; HUMAN_EMAIL="${1:-}"
[ "${1:-}" = "--auto" ] && { AUTO=1; HUMAN_EMAIL=""; }

PYBIN="../.venv/bin/python"; [ -x "$PYBIN" ] || PYBIN="python3"

if [ "$AUTO" = "1" ]; then
  [ -n "${AGENTMAIL_API_KEY:-}" ] || { echo "REFUSED: --auto needs AGENTMAIL_API_KEY in .env" >&2; exit 2; }
  echo "[phone] creating a fresh throwaway AgentMail inbox for the signup OTP…"
  # Unique client_id per run: a fixed one makes AgentMail REUSE the inbox, which would
  # then hold stale OTP emails from earlier attempts and we'd extract the wrong code.
  HUMAN_EMAIL="$("$PYBIN" -c 'import time; from syber.integrations import agentmail as m; print(m.address_of(m.create_inbox(client_id="syber-phone-%d" % int(time.time()))))')"
  echo "[phone] signup email: $HUMAN_EMAIL"
fi
[ -n "$HUMAN_EMAIL" ] || { echo "usage: $0 <your-email> | --auto" >&2; exit 2; }

echo "[phone] requesting signup…"
VID="$(curl -s -X POST "$API/v0/agent/sign-up" -H 'Content-Type: application/json' \
  -d "{\"human_email\":\"$HUMAN_EMAIL\",\"agent_name\":\"syber-agent\"}" | jq -r '.verification_id')"
[ -n "$VID" ] && [ "$VID" != "null" ] || { echo "signup failed (no verification_id)"; exit 3; }

if [ "$AUTO" = "1" ]; then
  echo "[phone] waiting for the OTP email (up to ~2 min)…"
  OTP="$("$PYBIN" -c "from syber.integrations import agentmail as m; msg=m.wait_for_message('$HUMAN_EMAIL', timeout=150); print(m.extract_otp(msg) if msg else '')")"
  [ -n "$OTP" ] || { echo "did not receive an OTP email in time"; exit 4; }
  echo "[phone] OTP received: $OTP"
else
  read -r -p "[phone] enter the 6-digit code emailed to $HUMAN_EMAIL: " OTP
fi

echo "[phone] verifying & provisioning the number…"
RESP="$(curl -s -X POST "$API/v0/agent/verify" -H 'Content-Type: application/json' \
  -d "{\"verification_id\":\"$VID\",\"otp_code\":\"$OTP\"}")"
API_KEY="$(echo "$RESP"   | jq -r '.api_key // empty')"
AGENT_ID="$(echo "$RESP"  | jq -r '.agent_id // empty')"
NUMBER_ID="$(echo "$RESP" | jq -r '.number_id // empty')"
PHONE="$(echo "$RESP"     | jq -r '.phone_number // empty')"
[ -n "$API_KEY" ] || { echo "verify failed: $RESP"; exit 5; }

cat <<EOF

================ AgentPhone provisioned — number: $PHONE ================
Paste these into syberAgent/.env (replace the commented placeholders):

AGENTPHONE_API_KEY=$API_KEY
AGENTPHONE_AGENT_ID=$AGENT_ID
AGENTPHONE_NUMBER_ID=$NUMBER_ID
AGENTPHONE_NUMBER=$PHONE
# Optional, to receive 'engagement complete' notifications on YOUR phone:
# SYBER_OPERATOR_PHONE=+1XXXXXXXXXX
========================================================================
EOF
