#!/usr/bin/env bash
# Kali entrypoint (runs as non-root 'syber'): wire DeepSeek V4 + in-network
# backends, ensure permission prompts are off, then launch Claude Code.
set -e

# --- DeepSeek V4 pro, directly (no LiteLLM, no local model) ----------------
: "${DEEPSEEK_API_KEY:?Set DEEPSEEK_API_KEY (env_file ../../.env)}"
export ANTHROPIC_BASE_URL="https://api.deepseek.com/anthropic"
export ANTHROPIC_AUTH_TOKEN="${DEEPSEEK_API_KEY}"
export ANTHROPIC_API_KEY="${DEEPSEEK_API_KEY}"
export ANTHROPIC_MODEL="deepseek-v4-pro"
export ANTHROPIC_SMALL_FAST_MODEL="deepseek-v4-pro"
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1

# --- Ephemeral by default: wipe all engagement data when the agent closes ---
# Set SYBER_WIPE_ON_EXIT=0 to keep the graph/memory/artefacts between sessions.
export SYBER_WIPE_ON_EXIT="${SYBER_WIPE_ON_EXIT:-1}"

# --- Long-running scans: don't let MCP tool calls time out -----------------
# nmap -sV -sC / nuclei can run for minutes. Give MCP generous ceilings and a
# default scan timeout the engine honours (syber.scanning.active_scan).
export MCP_TIMEOUT="${MCP_TIMEOUT:-120000}"            # server startup (ms)
export MCP_TOOL_TIMEOUT="${MCP_TOOL_TIMEOUT:-2700000}" # per tool call: 45 min (ms) — > full_scan budget
export SYBER_SCAN_TIMEOUT="${SYBER_SCAN_TIMEOUT:-600}"  # per STANDALONE scan stage: 10 min (s)
export SYBER_FULLSCAN_BUDGET="${SYBER_FULLSCAN_BUDGET:-1800}" # TOTAL full_scan budget, split across stages: ~30 min
# --- Thorough-engagement depth defaults (override to trade depth for speed) ---
export SYBER_DISCOVERY_RECURSIVE="${SYBER_DISCOVERY_RECURSIVE:-1}"  # feroxbuster recursion on
export SYBER_DISCOVERY_DEPTH="${SYBER_DISCOVERY_DEPTH:-2}"          # recurse 2 levels into found dirs
export SYBER_CRAWL_PAGES="${SYBER_CRAWL_PAGES:-150}"               # crawl up to 150 pages
export SYBER_CRAWL_DEPTH="${SYBER_CRAWL_DEPTH:-3}"                 # to depth 3
export SYBER_NUCLEI_FULL="${SYBER_NUCLEI_FULL:-1}"                # wide nuclei tag coverage
export SYBER_SUBDOMAIN_BRUTE="${SYBER_SUBDOMAIN_BRUTE:-1}"        # active puredns DNS brute on

# --- In-network backends (docker compose service names) --------------------
export NEO4J_URI="${NEO4J_URI:-bolt://neo4j:7687}"
export NEO4J_USER="${NEO4J_USER:-neo4j}"
export NEO4J_PASSWORD="${NEO4J_PASSWORD:-changeme}"
export DATABASE_URL="${DATABASE_URL:-postgresql://postgres:changeme@postgres:5432/syber_memory}"
export KAFKA_BOOTSTRAP="${KAFKA_BOOTSTRAP:-kafka:9092}"

# --- Disable permission prompts at user scope (container = sandbox) ---------
mkdir -p "$HOME/.claude"
if [ ! -f "$HOME/.claude/settings.json" ]; then
  cat > "$HOME/.claude/settings.json" <<'JSON'
{
  "permissions": { "defaultMode": "bypassPermissions" },
  "skipDangerousModePermissionPrompt": true,
  "enableAllProjectMcpServers": true,
  "includeCoAuthoredBy": false
}
JSON
fi

# --- Pre-answer first-run prompts so Claude Code starts straight into work --
# (onboarding/theme, the "trust this folder?" dialog, AND the "Detected a custom
# API key — use it?" prompt). Auth is the DeepSeek token above, so there is no
# login prompt. The custom-API-key approval is keyed by the LAST 20 CHARS of the
# key (what Claude Code stores when you answer "Yes"); we pre-approve it so the
# agent never stops to ask. Only write if absent (don't clobber an existing file).
if [ ! -f "$HOME/.claude.json" ]; then
  KEY_SUFFIX="${ANTHROPIC_API_KEY: -20}"
  cat > "$HOME/.claude.json" <<JSON
{
  "hasCompletedOnboarding": true,
  "theme": "dark",
  "hasSeenTasksHint": true,
  "autoUpdates": false,
  "customApiKeyResponses": { "approved": ["${KEY_SUFFIX}"], "rejected": [] },
  "projects": {
    "/home/syber/workspace": {
      "hasTrustDialogAccepted": true,
      "hasCompletedProjectOnboarding": true
    }
  }
}
JSON
fi

# On exit (the operator quits the agent), purge all engagement data so nothing
# persists on the host or in the backends. NOTE: we deliberately do NOT `exec`,
# so this shell survives the agent and runs the trap.
cleanup_on_exit() {
  [ "${SYBER_WIPE_ON_EXIT:-1}" = "1" ] || return 0
  echo "[syber] purging session data (graph, memory, bus, host artefacts)…" >&2
  python -m syber.cleanup --quiet 2>/dev/null || true
}
trap cleanup_on_exit EXIT

echo "================================================================"
echo " Syber on Kali — Claude Code + DeepSeek V4 (deepseek-v4-pro)"
echo " autonomous: permission prompts disabled (container sandbox)"
echo " scanners : $(command -v nmap nikto gobuster ffuf nuclei masscan | tr '\n' ' ')"
echo " browser  : $(command -v agent-browser)"
echo " backends : Neo4j=$NEO4J_URI  Kafka=$KAFKA_BOOTSTRAP"
echo " ephemeral: wipe-on-exit=$SYBER_WIPE_ON_EXIT (graph + memory + artefacts)"
echo " try      : /syber-pentest localhost:3000  |  /syber-scan scanme.nmap.org"
echo "================================================================"

"$@"
