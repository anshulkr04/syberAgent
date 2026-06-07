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

echo "================================================================"
echo " Syber on Kali — Claude Code + DeepSeek V4 (deepseek-v4-pro)"
echo " autonomous: permission prompts disabled (container sandbox)"
echo " scanners : $(command -v nmap nikto gobuster ffuf nuclei masscan | tr '\n' ' ')"
echo " browser  : $(command -v agent-browser)"
echo " backends : Neo4j=$NEO4J_URI  Kafka=$KAFKA_BOOTSTRAP"
echo " try      : /syber-scan scanme.nmap.org   |   'open example.com and snapshot it'"
echo "================================================================"

exec "$@"
