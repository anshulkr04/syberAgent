#!/usr/bin/env bash
# Launch Claude Code driven by DeepSeek V4 — directly, no LiteLLM, no local LLM.
#
# DeepSeek ships a native Anthropic-compatible endpoint (api.deepseek.com/anthropic),
# so Claude Code talks to it straight via ANTHROPIC_BASE_URL + auth token. The
# model itself runs on DeepSeek's servers; nothing runs locally here.
#
#   ./scripts/run_syber_claude.sh
#   # inside Claude Code:
#   #   /plugin marketplace add ../claude-code
#   #   /plugin install syber@claude-code-plugins
#   #   /syber-recon example.com         <- type a site, get all the details
#   #   /syber-investigate demo          <- the seeded data-lake scenario
set -euo pipefail
cd "$(dirname "$0")/.."

REPO="$(cd .. && pwd)/claude-code"
KEY="${DEEPSEEK_API_KEY:-$(grep -m1 '^DEEPSEEK_API_KEY=' ../.env | cut -d= -f2-)}"

# --- Point Claude Code straight at DeepSeek's Anthropic-compatible endpoint ---
export ANTHROPIC_BASE_URL="https://api.deepseek.com/anthropic"
export ANTHROPIC_AUTH_TOKEN="$KEY"
export ANTHROPIC_API_KEY="$KEY"
export ANTHROPIC_MODEL="deepseek-chat"             # DeepSeek V4 (flash) — supports tools
export ANTHROPIC_SMALL_FAST_MODEL="deepseek-chat"  # background/util model
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1

# --- Backend env for the Syber MCP server (falls back if the stack is down) ---
export NEO4J_URI="${NEO4J_URI:-bolt://localhost:7687}"
export NEO4J_USER="${NEO4J_USER:-neo4j}"
export NEO4J_PASSWORD="${NEO4J_PASSWORD:-changeme}"
export DATABASE_URL="${DATABASE_URL:-postgresql://postgres:changeme@localhost:5432/syber_memory}"
export KAFKA_BOOTSTRAP="${KAFKA_BOOTSTRAP:-localhost:9092}"

echo ">> Claude Code -> DeepSeek V4 (https://api.deepseek.com/anthropic). No local LLM."
echo ">> Inside Claude Code:"
echo "     /plugin marketplace add $REPO"
echo "     /plugin install syber@claude-code-plugins"
echo "     /syber-recon example.com"
exec claude
