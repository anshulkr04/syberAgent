#!/usr/bin/env bash
# Ephemeral Syber session: bring up the backends, run the agent inside Kali, and
# on exit TEAR EVERYTHING DOWN — remove the backend containers + volumes + network
# (docker compose down -v) and purge any host-side artefacts. Closing the agent
# leaves nothing behind.
#
#   ./scripts/syber_session.sh
#
# Keep data between sessions instead:  SYBER_KEEP_DATA=1 ./scripts/syber_session.sh
set -uo pipefail
cd "$(dirname "$0")/.."

COMPOSE="docker compose -f infra/docker-compose.kali.yml"

teardown() {
  if [ "${SYBER_KEEP_DATA:-0}" = "1" ]; then
    echo "[syber] SYBER_KEEP_DATA=1 — leaving backends and data in place." >&2
    return 0
  fi
  echo "[syber] tearing down: removing backend containers, volumes, and network…" >&2
  $COMPOSE down -v --remove-orphans 2>/dev/null || true
  # Host-side artefacts (in case any tool wrote outside the container).
  ../.venv/bin/python -m syber.cleanup --quiet 2>/dev/null \
    || python3 -m syber.cleanup --quiet 2>/dev/null || true
  echo "[syber] teardown complete — nothing persisted." >&2
}
trap teardown EXIT
trap 'echo; echo "[syber] interrupted — tearing down…" >&2; exit 130' INT TERM

echo "[syber] starting backends (neo4j, postgres, kafka)…"
$COMPOSE up -d neo4j postgres kafka

echo "[syber] launching the agent in Kali (exit the agent to tear everything down)…"
$COMPOSE run --rm kali
