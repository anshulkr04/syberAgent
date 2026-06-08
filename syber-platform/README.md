# Syber — Multi-Agent Security Intelligence Platform

A runnable implementation of the Syber Engineering Specification v3.0. It ingests
security telemetry, maintains a live attack graph, detects behavioural anomalies
with an unsupervised ensemble, and runs a **live DeepSeek-V4 multi-agent
investigation** that assembles MITRE ATT&CK-mapped forensic evidence chains,
gates them through a composite evidence score, and drives policy-bounded
response playbooks — hardened end-to-end against prompt-injection, RAG-poisoning,
and memory-poisoning attacks.

The LLM is **DeepSeek V4** (the spec's chosen provider, §8). The platform calls
DeepSeek directly via its OpenAI-compatible endpoint; the LiteLLM + Claude Agent
SDK harness path from the spec is also shipped (`litellm/`) for that deployment.

---

## Quick start

```bash
cd syber-platform
python -m venv .venv && source .venv/bin/activate     # repo ships a .venv already
pip install -r requirements.txt

# DEEPSEEK_API_KEY is auto-loaded from ../.env (or syber-platform/.env)
python -m syber.demo            # live end-to-end investigation of the seeded case
python -m pytest tests -q       # deterministic test batteries (no LLM spend)
python -m tests.injection.runner    # prompt-injection battery (spec §15.1)
python -m tests.poisoning.rag_sim   # RAG-poisoning simulation (spec §15.2)
```

`python -m syber.demo` seeds the **SVC-API-07 service-account compromise** case
(spec §5.2 CSIM example), scores it with the behavioural ensemble, then runs the
orchestrator → parallel subagents → threat investigator → CES gate → response
playbook, printing the recovered attack chain and verifying both hash chains.

---

## Architecture → code map

| Spec section | Component | Implementation |
|---|---|---|
| §3 Agent orchestration (Claude Agent SDK) | Agent loop, subagents, parallel fan-out, compaction, HITL | `syber/llm/agent_loop.py`, `syber/agents/orchestrator.py` |
| §3.4 In-process MCP tools | scope→audit→query→injection-filter pipeline | `syber/tools/*.py` |
| §4 Message bus | Event envelope + HMAC signing, DLQ retry | `syber/bus/` , `bus_config/` |
| §5 Telemetry + CSIM + Data Lake | CSIM events, partitioned query | `syber/data_lake.py`, `syber/seed_data.py` |
| §6 Knowledge graph | Dijkstra / Yen's k-shortest / betweenness | `syber/graph/store.py`, `graph_cypher/` |
| §7 Behavioural analytics | iForest + LSTM-AE + OCSVM ensemble | `syber/analytics/` |
| §8 LLM provider (DeepSeek V4) | client, model routing, CLAUDE.md | `syber/llm/client.py`, `.claude/CLAUDE.md`, `litellm/` |
| §9 Prompt-injection defence | StruQ dual-channel + classifier | `syber/harness/injection_guard.py` |
| §9.2/§10 TI / RAG poisoning defence | distribution check + provenance + self-consistency | `syber/harness/ti_integrity.py`, `rag_defence.py` |
| §11 Memory poisoning defence | append-only hash-chained store + scanner | `syber/harness/memory_integrity.py` |
| §12 Composite Evidence Score gate | structural + Platt-calibrated + self-consistency | `syber/scoring/` |
| §13 Response orchestrator | atomic playbook execution + rollback | `syber/response/` |
| §14 Immutable audit log | hash-chained, HMAC-signed, append-only | `syber/audit/log.py` |
| §15 Security testing | injection battery + poisoning sim | `tests/` |
| §16 Infrastructure | docker-compose, Kafka, LiteLLM, vLLM | `infra_docker-compose.yml`, `litellm/` |

---

## What is real vs. simulated

This runs on a laptop, so production infrastructure is substituted with
behaviour-equivalent local backends. **Every algorithm and security control in
the spec is implemented**; only the heavy *infrastructure* is swapped, behind
interfaces that accept the real backend via env vars.

| Spec calls for | Here, by default | Swap in the real backend |
|---|---|---|
| DeepSeek V4 (live LLM) | **Live DeepSeek API** ✅ | — (already live) |
| Claude Agent SDK + LiteLLM | In-house agent loop (`agent_loop.py`) | run `litellm/proxy_config.yaml` + `ANTHROPIC_BASE_URL` |
| Neo4j Enterprise + GDS | NetworkX (same algorithms) | set `NEO4J_URI` |
| Apache Kafka | in-process queue + DLQ logic | `confluent-kafka` + `bus_config/` |
| Parquet/Arrow Data Lake | in-memory CSIM store | point connectors at Arrow/DuckDB |
| Postgres + pgvector memory | SQLite (same hash-chain) | `DATABASE_URL` |
| torch LSTM Autoencoder | numpy PCA-sequence reconstructor | `pip install torch` (auto-detected) |
| DeBERTa-v3 injection classifier | high-precision heuristic classifier | `SYBER_INJECTION_MODEL` (needs torch) |
| SBERT embeddings | deterministic hashed-n-gram embeddings | `SYBER_SBERT_MODEL` |

> Python 3.14 (this machine) has no torch/transformers wheels yet, which is why
> those default to the dependency-light fallbacks. On 3.12 you can install them
> and the code auto-detects and uses them — no code change.

### Switching on the real backends (Neo4j / Kafka / Postgres)
The driver packages (`neo4j`, `confluent-kafka`, `psycopg`) are installed. The
adapters activate purely from env vars and fall back to the in-process backend on
any connection error, so nothing breaks if a service is down:

```bash
# Requires Docker Desktop running:
./scripts/up_backends.sh                     # starts services + applies Neo4j schema/RBAC
source <(./scripts/up_backends.sh --env)     # exports NEO4J_URI / KAFKA_BOOTSTRAP / DATABASE_URL
python -m syber.demo                          # now uses Neo4j graph, Kafka bus, Postgres memory
```

| Backend | Switch | Adapter |
|---|---|---|
| Neo4j graph (persist + RBAC, GDS Cypher in `graph_cypher/`) | `NEO4J_URI` | `syber/graph/neo4j_backend.py` |
| Kafka bus (topics from `bus_config/topics.yaml`) | `KAFKA_BOOTSTRAP` | `syber/bus/bus.py` |
| Postgres memory (same hash chain) | `DATABASE_URL` | `syber/harness/memory_integrity.py` |

### On the references
The spec distils ~45 papers/repos (StruQ, PoisonedRAG, MINJA, the iForest+LSTM+
OCSVM ensemble, Yen's, self-consistency/Platt calibration, …) into concrete
algorithms and code. Those algorithms are what this repo implements; each module
header cites the specific paper/repo it follows so you can trace any control back
to its source. The reference list lives in `spec.md` §17.

---

## Claude Code integration (the agent harness)

The spec's premise is that *"the Claude Agent SDK is the same runtime that powers
Claude Code."* That is realised as a **Claude Code plugin** at
`../claude-code/plugins/syber`: Claude Code becomes the orchestration harness, its
subagents call the Syber **MCP server** (`server/syber_mcp.py`, 11 tools wrapping
graph / data lake / analytics / findings / CES gate / response / integrity), and
the whole platform runs inside Claude Code.

```
Claude Code  ──/syber-investigate──►  syber-context-graph + syber-behavioural-analytics (parallel)
                                       └─► syber-threat-investigator
                                              └─ mcp__syber-tools__*  ─►  syber package  ─►  Neo4j / Kafka / Postgres / DeepSeek
```

```bash
# 1. real backends (verified live):
cd syber-platform && docker compose -f infra/docker-compose.dev.yml up -d
pip install -e .            # makes `syber` importable to the MCP server

# 2. drive Claude Code itself with DeepSeek (DIRECT — no LiteLLM, no local LLM):
./scripts/run_syber_claude.sh
#   then, inside Claude Code:
#     /plugin marketplace add ../claude-code
#     /plugin install syber@claude-code-plugins
#     /syber-recon example.com      <- type a site, get all the details
#     /syber-investigate demo       <- seeded data-lake scenario
```

**LLM connection.** Claude Code points straight at DeepSeek's native Anthropic-compatible
endpoint (`ANTHROPIC_BASE_URL=https://api.deepseek.com/anthropic`). No LiteLLM, no proxy,
nothing hosted locally. The model is the **full `deepseek-v4-pro`** (not flash) — pinned
explicitly, since `deepseek-chat`/`deepseek-reasoner` silently downgrade to flash. (LiteLLM
is only for the Phase 2 self-hosted vLLM path, which has no Anthropic endpoint.)

**Active scanning (authorised targets only).** `/syber-scan <target>` runs nmap / nikto /
gobuster / nuclei, ingests hosts/ports/services/vulns into the **Neo4j** graph, and produces
a DeepSeek finding. It is default-deny: a target must be authorised first
(`scanme.nmap.org` and `localhost` are pre-authorised).

**Autonomous Kali agent (recommended).** A self-contained image runs Claude Code inside Kali
with the scanning toolchain + the `agent-browser` browser + the baked Syber workspace:
```bash
docker compose -f infra/docker-compose.kali.yml up -d neo4j postgres kafka
docker compose -f infra/docker-compose.kali.yml build kali      # or: docker load -i ~/syber-dist/syber-kali-image.tar.gz
docker compose -f infra/docker-compose.kali.yml run --rm kali   # Claude Code inside Kali
#   /syber-scan scanme.nmap.org          # scan -> Neo4j -> finding
#   open example.com and snapshot it     # agent-browser, on by default
```
- **No permission prompts:** runs as non-root `syber` with `--dangerously-skip-permissions` +
  `bypassPermissions` (the container is the sandbox; the Bash *sandbox* is intentionally not
  used since it would block scanning/browsing network access).
- **Browser:** `agent-browser` + system `chromium`, known to Claude by default via a bundled
  skill. Verified: open/snapshot/click/screenshot headless in-container.
- **Packaged:** `~/syber-dist/syber-kali-image.tar.gz` (~3-4GB, slimmed) — `docker load -i ~/syber-dist/syber-kali-image.tar.gz` to run anywhere.

**Try the recon flow without the interactive session:**
```bash
python -m syber.recon.demo example.com   # passive recon -> DeepSeek finding -> CES gate
```

The MCP path is covered end-to-end by `tests/integration/test_mcp_server.py` (spawns
the server over real MCP stdio and calls the tools).

## A note on security posture
Investigation scope, the StruQ injection filter, the audit hash-chain, and the
memory write-restriction are enforced **inside every tool call**, so a
prompt-injected instruction inside retrieved evidence cannot exfiltrate data,
escape investigation scope, or corrupt memory. The injection battery
(`tests/injection`) and poisoning simulation (`tests/poisoning`) verify this.
