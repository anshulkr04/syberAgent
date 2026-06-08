# Syber Agent — Progress & Handoff

> Read this top-to-bottom before continuing. It captures **what was built, why, what
> works, what's in progress, and the current blocker** so the next session resumes cleanly.

---

## 0. TL;DR — current state & next step

We built an autonomous offensive-security agent: **Claude Code (harness) + DeepSeek V4
(`deepseek-v4-pro`, brain), running inside Kali Linux**, with the full scanning toolchain,
a real browser (`agent-browser`), and a Neo4j attack-surface graph. The platform code lives
in `syber-platform/`; the Claude Code plugin lives in `claude-code/plugins/syber/`.

**Disk blocker RESOLVED** (2026-06-08): the macOS data disk now has ~51 GiB free and Docker
works again. The earlier ENOSPC/corruption is gone.

**§7 work COMPLETE & verified on host** (2026-06-08): the false-positive/severity-discipline fix,
persistence doctrine, env-configurable scan timeouts, and smooth-startup config are all done.
`cap_severity` is wired into `coerce_and_validate`; the `SEVERITY_RUBRIC` is injected into both
analysis prompts; the doctrine/commands/agents (workspace + plugin copies) carry the severity +
coverage discipline; `entrypoint.sh` pre-seeds `~/.claude.json` and raises MCP/scan timeouts.
Verified: 10/10 tests pass; public-key CRITICAL→INFO and banner HIGH→INFO while a real
RCE+PoC stays CRITICAL; the live recon demo now rates `example.com` **LOW** (was prone to
inflation). See §7 for the per-step record.

**Kali image REBUILT** (2026-06-08): `syber-kali:latest`, 3.45 GB (the slimmed target), build
exit 0, ~41 GiB still free. Ready to run (see §9). Optional: re-package to `~/syber-dist/` with
`docker save syber-kali:latest | gzip > ~/syber-dist/syber-kali-image.tar.gz` for a portable
tarball — not required to run locally.

---

## 1. What this project is

`spec.md` is the source spec ("Syber Multi-Agent Security Intelligence Platform v3.0"). The
spec describes a production multi-agent SOC platform (Kafka, Neo4j, eBPF, behavioural ML,
LLM investigation, injection/RAG/memory defences). Over the sessions it evolved per the
user's direction into a **real, runnable offensive-security agent**:

- **LLM = DeepSeek V4** via the user's API key (in `.env`). Not local, no LiteLLM.
- **Harness = Claude Code** (the `claude-code` repo here = the anthropics/claude-code plugin
  marketplace, NOT the system CLI). The agent runs as a Claude Code plugin.
- **Runs inside Kali** (Docker) with nmap/nikto/gobuster/ffuf/nuclei/masscan + `agent-browser`.
- **Capabilities:** active scanning (authorised-only), browser-first web recon, Neo4j
  attack-surface graph, DeepSeek findings gated by a Composite Evidence Score (CES).

---

## 2. Repo layout

- **`syberAgent/`** — repo root
  - `.env` — `DEEPSEEK_API_KEY` (secret; gitignored)
  - `.gitignore` — root gitignore (written this session)
  - `progress.md` — this file
  - `spec.md` — original product spec v3.0
  - `README.md` — operator's guide (how to run)
  - `.venv/` — Python 3.14 venv (syber installed editable)
  - `agent-browser/` — third-party clone (gitignored); the npm-global `agent-browser` binary is what's actually used
  - **`syber-platform/`** — THE PLATFORM (python package + infra + tests)
    - **`syber/`** — the python package
      - `config.py` — LLM config, model pinning, thresholds, `.env` loader
      - `mcp_server.py` — FastMCP stdio server = the 20 MCP tools (canonical)
      - `llm/` — `client.py` (DeepSeek), `agent_loop.py` (in-house SDK), `exceptions.py`
      - `agents/` — `orchestrator.py`, `definitions.py`, `prompts.py`
      - `graph/` — `store.py` (NetworkX), `neo4j_backend.py`, `model.py` (rich schema)
      - `scanning/` — `active_scan.py`, `authorization.py`, `demo.py`
      - `recon/` — `browser_recon.py` (real browser), `site_recon.py` (DNS/TLS helpers), `demo.py`
      - `analytics/` — iForest + LSTM-AE + OCSVM ensemble (behavioural)
      - `harness/` — `injection_guard.py` (StruQ), `schema_validator.py`, `memory_integrity.py`, `rag_defence.py`, `embeddings.py`, `ti_integrity.py`
      - `scoring/` — `composite_evidence.py` (CES), `gate.py`, `severity.py` (new, in progress), `calibration/`
      - `response/` — `executor.py` (playbooks + rollback), `playbooks.py`
      - `audit/log.py` — hash-chained, fcntl-locked audit log
      - `bus/` — `bus.py` (Kafka/in-process), `schemas.py`, `dead_letter.py`
      - `data_lake.py` — CSIM event store
      - `seed_data.py` — SVC-API-07 demo scenario
    - **`infra/`**
      - `kali/Dockerfile` — self-contained Kali + Claude Code + tools + browser
      - `kali/entrypoint.sh` — sets DeepSeek + backend env, no-prompt config, launches claude
      - `kali/workspace/` — baked project workspace → `/home/syber/workspace` in image
        - `CLAUDE.md` — the agent's operating doctrine (system prompt)
        - `.mcp.json` — registers the syber-tools MCP server
        - `.claude/` — `commands/`, `agents/`, `skills/`, `settings.json`
      - `docker-compose.kali.yml` — kali + neo4j + postgres + kafka on one network
      - `docker-compose.dev.yml` — backends only (host dev)
    - `scripts/run_syber_claude.sh` — drive Claude Code on DeepSeek from the host
    - `tests/` — 10 tests (component + injection + poisoning + MCP)
    - `pyproject.toml` — `pip install -e .`; entrypoints `syber-demo`, `syber-recon`
  - **`claude-code/`** — anthropics/claude-code plugin marketplace (has its own nested `.git`)
    - `.claude-plugin/marketplace.json` — the `syber` plugin is registered here
    - `plugins/syber/` — the plugin: `.mcp.json`, `server/run.sh`, `commands/`, `agents/`, `skills/`, `README`

---

## 3. Architecture & data flow

**Request flow (top to bottom):**

1. **You** issue `/syber-scan ...` or natural language to **Claude Code** — running in Kali, on DeepSeek `v4-pro`, with no permission prompts.
2. Claude Code dispatches subagents (`agents/*.md`) and calls MCP tools (`mcp__syber-tools__*`).
3. Those tools execute inside the **Syber MCP server** (`python -m syber.mcp_server`) — a child process of Claude Code, in the same Kali container.
4. The MCP server drives the backends:
   - **Kali tools** — nmap, nikto, gobuster, ffuf, nuclei
   - **agent-browser** — real Chrome (web recon / interaction)
   - **Neo4j** — attack-surface graph
   - **Postgres** — hash-chained memory
   - **Kafka** — event bus

**Cross-container connectivity (PROVEN):** Docker Compose puts kali + neo4j + postgres + kafka
on one network (`infra_syber`); Docker DNS resolves service names (`neo4j`→container IP). The
MCP server (in the kali container) connects to `bolt://neo4j:7687`, `postgres:5432`,
`kafka:9092`. We verified by writing a unique marker from kali and reading it back directly
from all three other containers.

**LLM connection:** Claude Code → `ANTHROPIC_BASE_URL=https://api.deepseek.com/anthropic`
(DeepSeek's NATIVE Anthropic-compatible endpoint) + `ANTHROPIC_AUTH_TOKEN=$DEEPSEEK_API_KEY`,
`ANTHROPIC_MODEL=deepseek-v4-pro`. No LiteLLM, no proxy, nothing local.

---

## 4. KEY FACTS you must not get wrong

- **Model:** only two real DeepSeek ids exist: `deepseek-v4-pro` and `deepseek-v4-flash`.
  The aliases `deepseek-chat`/`deepseek-reasoner` **silently downgrade to flash** — so we PIN
  `deepseek-v4-pro` everywhere (`config.py` defaults, run scripts, `ANTHROPIC_MODEL`). The user
  insisted on the full (non-flash) model for scan-analysis quality.
- **DeepSeek API key** is in `syberAgent/.env`; `config._load_dotenv()` auto-loads it. The live
  key works; `/models` returns the two ids above.
- **No-prompt config:** Claude Code blocks `--dangerously-skip-permissions` as ROOT, so the
  container runs as **non-root user `syber`** + `permissions.defaultMode:bypassPermissions` +
  `skipDangerousModePermissionPrompt:true`. The Bash *sandbox* feature is deliberately NOT used
  (it restricts network → would break scanning/browsing). Container = the isolation boundary.
- **agent-browser:** npm-global CLI driving real Chrome. In the image it points at system
  `/usr/bin/chromium` via `AGENT_BROWSER_EXECUTABLE_PATH`; needs `cap_add: SYS_ADMIN` +
  `shm_size:1gb`. HAR usage: `agent-browser network har stop <path>` (path on STOP). `eval`
  output is double-JSON-encoded (json.loads twice).
- **Authorization:** active scanning is DEFAULT-DENY (`scanning/authorization.py`).
  `scanme.nmap.org` + `localhost` pre-authorised; everything else needs `syber_authorize_target`
  with an attestation.
- **Tests:** `cd syber-platform && ../.venv/bin/python -m pytest tests -q` → 10 pass (no LLM
  spend). Run in BOTH modes (in-process default; real backends via NEO4J_URI/DATABASE_URL/
  KAFKA_BOOTSTRAP env).
- **Two compose stacks bind the same host ports (7687/5432/9092)** — run only ONE at a time.
- **Kali Dockerfile gotcha:** Kali (Debian sid) did the t64 lib transition (libasound2→
  libasound2t64). DON'T hand-list Chrome libs — install `chromium` (pulls correct deps).
- **NEVER let `dist/` or `*.tar.gz` into the Docker build context** — a packaged image tarball
  got pulled in once and the recursive copy filled the disk. `.dockerignore` now excludes it;
  packaging goes to `~/syber-dist/` (OUTSIDE the repo).

---

## 5. What works today (verified this session)

- Live DeepSeek multi-agent investigation of the seeded SVC-API-07 scenario (`python -m syber.demo`).
- Real backends live: Neo4j graph, Postgres memory (hash-chain), Kafka bus (publish+consume).
- Claude Code plugin: 20 MCP tools reachable over real MCP stdio.
- **Inside the Kali image (verified before the disk filled):** non-root, no-prompt `claude -p`
  on DeepSeek; calls MCP tools (Graph→Neo4j etc.); `agent-browser open+snapshot`; full scan of
  scanme.nmap.org → Neo4j → v4-pro finding.
- **Browser-first recon (no curl):** target sees a real Chrome User-Agent. `python -m
  syber.recon.demo <site>` works on the host.
- **Rich attack-surface graph** persists to Neo4j (Host/Service/Technology/WebEndpoint/
  Certificate/Vulnerability/Domain/Finding with provenance + risk scoring).
- 10/10 tests pass.

---

## 6. Session-by-session history (what & WHY)

1. **Build from spec.** Implemented the whole platform (~48 modules) — orchestrator, subagents,
   in-process MCP tools, CSIM data lake, Neo4j graph (Dijkstra/Yen's/betweenness), behavioural
   ensemble (IsolationForest+LSTM-AE+OCSVM), StruQ injection defence, RAG/memory poisoning
   defences, CES gate, response playbooks, hash-chained audit log, tests. WHY: realise the spec
   as runnable code. LLM via DeepSeek directly (OpenAI-compatible). Python 3.14 → numpy/heuristic
   fallbacks for torch/transformers/SBERT (no 3.14 wheels), all behind interfaces.
2. **Real backends.** Neo4j/Kafka/Postgres adapters behind env-var switches, fallback to
   in-process. Fixed spec's broken Kafka compose (added KRaft). Made audit log multi-writer safe
   (fcntl). Fixed CES self-consistency to compare prose-vs-prose (was JSON-vs-prose → noisy).
3. **Claude Code plugin integration.** "claude code" = the repo's plugin marketplace. Built the
   `syber` plugin (FastMCP stdio MCP server, subagents, slash commands), registered in
   marketplace.json. Moved MCP server into the package (`syber/mcp_server.py`).
4. **Drop LiteLLM.** User asked why LiteLLM / no local LLM. DeepSeek has a native Anthropic
   endpoint → Claude Code points straight at it. Added passive site recon + `/syber-recon`.
5. **Active scanning + Kali + model.** Built the scanning engine (nmap/nikto/gobuster/ffuf/
   nuclei) with default-deny authorization. Pinned `deepseek-v4-pro` (flash was too weak). Built
   the Kali image so Claude Code runs inside Kali with the toolchain on the backends' network.
6. **No-prompt container + browser + packaging.** Self-contained image, non-root user, bypass
   permissions, agent-browser + chromium, baked workspace. `docker save` package. Proved
   cross-container data flow with a unique marker.
7. **Root .gitignore.** Protect `.env` (secret), exclude venv/dist/caches/runtime state.
8. **Browser-first + rich graph.** User: agent used curl (bot-detected) — wanted real browser;
   and a better graph. Built `browser_recon.py` (real Chrome via agent-browser, HAR headers,
   DOM tech via eval); retired the curl path. Built `graph/model.py` (rich typed schema +
   provenance + risk scoring + exposure/attack-surface queries); scan+recon ingest through it;
   findings stored in graph; `get_graph_context` returns the rich view. Rewrote `CLAUDE.md`
   doctrine: MANDATE agent-browser, FORBID curl, Kali tools, graph as source of truth. **During
   the image rebuild the disk filled** (the `dist/` tarball got pulled into the build context →
   recursive copy). Slimmed the Dockerfile (dropped seclists/wordlists + template prefetch; added
   an 81-path built-in wordlist) and moved packaging to `~/syber-dist/`.
9. **(IN PROGRESS) startup + false positives + persistence.** See §7.

---

## 7. Severity / persistence / startup fix — DONE (2026-06-08)

**Status: complete and host-verified.** All steps below were applied; `pytest tests -q` → 10
pass; the live `example.com` recon demo now rates **LOW** instead of inflating. What was done:

1. ✅ `cap_severity` wired into `harness/schema_validator.py::coerce_and_validate` (runs right
   before `validate_finding`; deterministic, never upgrades — caps inflated severities).
2. ✅ `SEVERITY_RUBRIC` prepended to the analysis prompts in `recon/demo.py` and
   `scanning/demo.py`; both prompts now also request an `exploitability` field.
3. ✅ Severity discipline added to `infra/kali/workspace/CLAUDE.md` (rule 5 rewritten), the
   `syber-scan`/`syber-recon` commands, and the `syber-scanner` agent — and synced to the
   `claude-code/plugins/syber/` copies.
4. ✅ Persistence: `CLAUDE.md` gained a "Be thorough — scans take time" coverage checklist
   (ports → service enum → web content → nuclei → browser-inspect → graph review); the
   `syber-scanner` agent echoes it.
5. ✅ Env-configurable scan timeouts: `scanning/active_scan.py` reads `SYBER_SCAN_TIMEOUT`
   (via `_env_timeout`, overrides per-stage defaults when set) across port/service/web/
   content/vuln/full scans. `entrypoint.sh` exports `MCP_TIMEOUT=120000`,
   `MCP_TOOL_TIMEOUT=1800000` (30 min), `SYBER_SCAN_TIMEOUT=900` (15 min).
6. ✅ Smooth startup: `entrypoint.sh` pre-seeds `~/.claude.json` (`hasCompletedOnboarding`,
   `theme:dark`, per-project `hasTrustDialogAccepted`/`hasCompletedProjectOnboarding`) when
   absent. Auth is the DeepSeek token → no login prompt.
7. ✅ Host verification done (tests + recon demo). **Remaining: rebuild the Kali image** (disk is
   now free) and re-package — see §9.

---

## 7b. (historical) original IN-PROGRESS notes — research & design (kept for reference)

User asks, with research backing:
- **(a) Smooth startup:** stop Claude Code asking first-run config (theme/color, login method,
  trust dialog). We say NO to Anthropic login (we use the DeepSeek token).
- **(b) False positives:** the model over-rates (e.g. flags a *public key* as CRITICAL). Make
  the prompts + system disciplined about severity.
- **(c) Persistence:** scans take time — the agent must keep scanning thoroughly, not stop early.

**Research (done):**
- PentestGPT (arXiv 2308.06782, github.com/GreyDGL/PentestGPT): persistence via a **Pentest Task
  Tree** — decompose the engagement into tracked sub-tasks, prioritise, complete coverage; many
  bounded steps beat one giant call.
- Severity over-rating (arXiv 2510.18508): LLMs inflate (risk-averse + training-skewed). Fixes:
  **SSVC-style decomposition** (exploitability×exposure×impact → derive severity), **negative
  exemplars** (what is NOT a vuln), **allow INFO/Unknown**, **exploitability-gating**.

**Done so far:** `syber/scoring/severity.py` created — `SEVERITY_RUBRIC` (SSVC-style + a
"NOT A FINDING" list incl. public keys, version banners, missing headers), and `cap_severity()`
(deterministic: caps HIGH/CRITICAL with no exploitability signal → MEDIUM; benign/public artefacts
→ INFO). Added `exploitability` enum to the finding schema in `schema_validator.py`.

**Remaining steps (each is a small edit — do these once disk is freed):**
1. **Wire `cap_severity` into `harness/schema_validator.py::coerce_and_validate`** — was the edit
   that hit ENOSPC. Add, right before `validate_finding(f)`:
   `from ..scoring.severity import cap_severity; f, _ = cap_severity(f)`.
2. **Inject `SEVERITY_RUBRIC` into the analysis prompts:** prepend it to `ANALYSIS_INSTRUCTIONS`
   in `syber/recon/demo.py` and `syber/scanning/demo.py`, and ask the model to also return an
   `exploitability` field. (The CLAUDE.md doctrine + commands should reference the same rubric.)
3. **Severity discipline in the doctrine/commands/agents:** add the rubric + "public keys are not
   vulns; require exploitability for HIGH/CRITICAL; prefer INFO when unsure" to
   `infra/kali/workspace/CLAUDE.md`, `.claude/commands/syber-scan.md`, `syber-recon.md`, and the
   scanner/threat-investigator agents (sync to `claude-code/plugins/syber/` copies too).
4. **Persistence:** in `CLAUDE.md` add a **coverage checklist / task-tree** the agent must
   complete before concluding (full port scan → service enum per open port → web content
   discovery → nuclei → browser-inspect each web service → graph review), with "scans take time;
   wait for them; don't stop until coverage is complete." Optionally add a `syber_scan_plan(target)`
   MCP tool returning the checklist as an explicit task tree (PentestGPT PTT idea, kept simple).
5. **Longer scans:** in `scanning/active_scan.py` bump timeouts (service_scan ~600-900s, full_scan
   stages) and make them env-configurable (e.g. `SYBER_SCAN_TIMEOUT`); add a full-port option.
   In `infra/kali/entrypoint.sh` raise `MCP_TIMEOUT`/`MCP_TOOL_TIMEOUT` so long tool calls don't
   time out.
6. **Smooth startup:** in `infra/kali/entrypoint.sh`, write `~/.claude.json` (if absent) with the
   pre-answered flags (confirmed from the live config):
   ```json
   {"hasCompletedOnboarding": true, "theme": "dark", "hasSeenTasksHint": true,
    "lastOnboardingVersion": "2.1.167", "autoUpdates": false,
    "projects": {"/home/syber/workspace": {"hasTrustDialogAccepted": true,
                                            "hasCompletedProjectOnboarding": true}}}
   ```
   Login is already the DeepSeek token (ANTHROPIC_AUTH_TOKEN) → no login prompt.
7. **Verify on host** (recon demo should now rate example.com proportionately, e.g. LOW/INFO, and
   never flag public keys as critical); run `pytest tests -q` (10 pass). **Then rebuild the image**
   (only when ≥15 GB free) and `docker save | gzip > ~/syber-dist/syber-kali-image.tar.gz`.

---

## 8. The disk-full incident & recovery (CRITICAL)

**Cause:** the macOS data volume (`/System/Volumes/Data`) was already ~99% full (~187 GB of user
data). The Kali image build pulled the 1.5 GB `dist/syber-kali-image.tar.gz` into the build
context and tried to COPY it into the image — doubling usage until the disk hit 100%. That
corrupted Docker's containerd/buildkit store (I/O errors reading its own blobs). Now even file
writes fail with ENOSPC, so NO tool works.

**What's safe / lost:** running containers' data is regenerable (demo/scan data only). The code
is intact. `severity.py` was written; the schema_validator wiring did NOT apply.

**Recovery (user runs in their own terminal):**
```bash
# quick safe reclaims
rm -rf "$TMPDIR"agent-browser-chrome-*  ~/Library/Caches/pip  /tmp/*.har
# Empty Trash.
# Big reclaim (~34 GB) — Docker's disk is corrupted anyway:
#   Quit Docker Desktop, then:
rm -f ~/Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw
#   (or Docker Desktop -> Troubleshoot -> Clean / Purge data). Docker recreates it fresh
#   (wipes images/containers — all regenerable here).
df -h /System/Volumes/Data    # aim for a few GB to finish code; 15+ GB to rebuild the image
```
**Already hardened so it can't recur:** `.dockerignore` excludes `dist/`/`*.tar.gz`; packaging
target moved to `~/syber-dist/` (outside the build context); Dockerfile slimmed (~3-4 GB).

After freeing space: restart Docker Desktop, confirm `docker images` lists without I/O errors,
then re-create the backends (`docker compose -f infra/docker-compose.kali.yml up -d neo4j
postgres kafka`) and rebuild the kali image.

---

## 9. How to run & verify

**Host (no Docker needed for code work):**
```bash
cd syber-platform && source ../.venv/bin/activate
python -m pytest tests -q                              # 10 pass
python -m syber.recon.demo example.com                 # browser recon -> DeepSeek finding (real Chrome)
python -m syber.scanning.demo scanme.nmap.org 22,80    # active scan -> graph -> finding
python -m syber.demo                                   # seeded multi-agent investigation
```
**Real backends (host):** `export NEO4J_URI=bolt://localhost:7687 NEO4J_USER=neo4j
NEO4J_PASSWORD=changeme DATABASE_URL=postgresql://postgres:changeme@localhost:5432/syber_memory
KAFKA_BOOTSTRAP=localhost:9092` (after `docker compose -f infra/docker-compose.kali.yml up -d
neo4j postgres kafka`).

**Container (the real agent):**
```bash
cd syber-platform
docker compose -f infra/docker-compose.kali.yml up -d neo4j postgres kafka
docker compose -f infra/docker-compose.kali.yml build kali   # or docker load -i ~/syber-dist/syber-kali-image.tar.gz
docker compose -f infra/docker-compose.kali.yml run --rm kali   # Claude Code opens in Kali
#   /syber-scan scanme.nmap.org   |   /syber-recon example.com   |   "open <url> and snapshot it"
```

---

## 10. Research references
- PentestGPT — arXiv 2308.06782 ; github.com/GreyDGL/PentestGPT (Pentest Task Tree, persistence)
- Prompting the Priorities (LLM vuln triage / severity over-rating) — arXiv 2510.18508
- Minimizing False Positives in Static Bug Detection via LLMs — arXiv 2506.10322
- StruQ (prompt injection), PoisonedRAG, MINJA, iForest+LSTM+OCSVM, self-consistency/Platt — see
  `spec.md` §17.

---

## 11. Web-application pentest layer — ADDED (2026-06-08)

The agent did network scanning (nmap/nikto/gobuster/nuclei) but **no application-layer testing**
— so it missed IDOR/BOLA, injection, etc. Researched the SOTA (autonomous LLM pentest agents +
OWASP methodology) and built the application layer. All active functions are **default-deny
authorization-gated** (same gate as the network scanners — that control is unchanged).

**New module `syber/scanning/webapp.py`:**
- `http_request` — crafted-HTTP primitive. Browser-first transport (real Chrome fingerprint +
  live session via agent-browser sync-XHR); HTTP-client fallback when the browser is unavailable
  or explicit session cookies must be set (browsers forbid setting Cookie on XHR).
- `crawl` — BFS app map; extracts endpoints, forms, **parameters**; ingests into the graph.
- `test_access_control` — **BOLA/IDOR engine**, six-family taxonomy (direct-object-reference,
  action-level, tenant isolation, workflow-context, chained disclosure, object rebinding). Dual-
  session (`cookies_a`/`cookies_b`) when creds are available; sequential-id + chained-disclosure
  (`known_other_ids`) when not. FP guards: a hit requires a 2xx with real content that differs
  materially from the owner baseline.
- `test_injection` — reflected XSS (unique canary, must reflect unencoded), error-based SQLi (DBMS
  error signatures), SSRF canary. Non-destructive, read-only payloads.
- `pentest_plan` — explicit Pentest Task Tree (PTT) / state machine for coverage persistence
  (AutoPT/PentestGPT lesson).
- Pure detection helpers (`sqli_errors`, `xss_reflected`, `responses_differ`, `extract_surface`,
  `_locate_id`/`_swap_id`) are unit-tested without network.

**5 new MCP tools** (now 25 total): `syber_pentest_plan`, `syber_crawl`,
`syber_test_access_control`, `syber_test_injection`, `syber_http_request` (`syber/mcp_server.py`).

**Graph:** `model.upsert_web_endpoint` now carries `method` + `params` (merged across re-crawls).

**Doctrine/commands:** new `/syber-pentest` command (workspace + plugin); CLAUDE.md gained a
"Web-application testing" section + PTT reference + updated tool list; `syber-scanner` agent gets
the new tools and the app-testing protocol (workspace + plugin synced).

**Verified (host, 2026-06-08):** 22/22 tests pass (10 + 12 new in `tests/integration/test_webapp.py`).
End-to-end against a local deliberately-vulnerable server: crawl mapped endpoints+params; the IDOR
engine confirmed a sequential-id BOLA; injection found reflected XSS and error-based SQLi. Research
refs: arXiv 2411.01236 (AutoPT/PSM), 2510.05605 (AutoPentester), 2308.06782 (PentestGPT/PTT),
2502.15506 (semi-autonomous PT modules), 2605.25865 (six-family BOLA taxonomy), OWASP API Top 10
2023, OWASP WSTG.

**Next (optional):** business-logic/auth-flow tests (action-level BOLA writes, password reset,
rate limiting), OOB SSRF confirmation, blind/time-based SQLi, and authenticated-crawl login
automation via agent-browser. Rebuild the Kali image to bake the new module/doctrine in
(`docker compose -f infra/docker-compose.kali.yml build kali`).

## 12. Ephemeral teardown — wipe data on agent close (2026-06-08)

The graph (Neo4j), memory (Postgres), bus (Kafka) and host artefacts used to persist after the
agent closed. Added automatic, narrowly-scoped cleanup so an engagement leaves nothing behind.

**New module `syber/cleanup.py`** — `purge_all()` (+ per-store functions, CLI `python -m
syber.cleanup [--keep-host] [--quiet]`):
- Neo4j: `MATCH (n) DETACH DELETE n` (only when `NEO4J_URI` set).
- Postgres: `TRUNCATE memory_store` (only when `DATABASE_URL` set).
- Kafka: best-effort delete of Syber's topics (only when `KAFKA_BOOTSTRAP` set).
- In-process graph singleton: cleared.
- Host artefacts: `.investigation_state/`, `.audit_log`, `.memory_store.sqlite`,
  `.scan_authorization.json`, and this session's browser HARs/screenshots in tmp (only the
  `recon-*`/`crawl-*`/`pt-*` prefixes — never a broad temp wipe). Scope is strictly Syber's own
  data; it never touches a non-Syber DB. Every step best-effort (a backend may already be down).

**Container (`infra/kali/entrypoint.sh`):** exports `SYBER_WIPE_ON_EXIT=1` (default on; set 0 to
keep data) and installs a `trap cleanup_on_exit EXIT` that runs `python -m syber.cleanup` when the
agent process ends. **Removed the `exec`** so the entrypoint shell survives the agent and runs the
trap (this was the key change — `exec` would have replaced the shell and skipped cleanup).

**Host wrapper `scripts/syber_session.sh`:** up backends → `run --rm kali` → on exit
`docker compose down -v --remove-orphans` (removes backend containers + volumes + network) + host
purge. `SYBER_KEEP_DATA=1` to persist. This is the "close the agent → containers cleaned" path for
the host operator (the agent container can't tear down its siblings — no docker socket, by design).

**One-command engagement `scripts/syber_engage.sh <target> ["attestation"]`:** boots the stack,
seeds the agent with a thorough PTT-driven recon prompt for the target, and runs it. **Bounded
resumable persistence** (`SYBER_MAX_PASSES`, default 6): if the agent stops BEFORE completing the
coverage checklist (crash/timeout/compaction) it is resumed to finish; stops cleanly on
ENGAGEMENT_COMPLETE / CRITICAL_CONFIRMED / max passes. Authorisation parity with the in-agent gate
(pre-authorised hosts free; others require a ≥8-char attestation — refuses before any Docker call).
Per-pass `SYBER_WIPE_ON_EXIT=0` so findings accumulate across passes; final teardown wipes via
`down -v`. **Deliberately NOT built:** the requested "escalating-persuasion, loop-until-critical"
design — that is a guardrail-pressure pattern with no valid terminal state. This resumes
*thoroughness* only; it never pressures past a refusal/authorisation boundary, and "no critical
found" is treated as a valid result.

**Verified (host, 2026-06-08):** cleanup purges in-process graph + all host artefacts; backends
skipped gracefully when unconfigured; both scripts pass `bash -n`; 22/22 tests still pass.

**REBUILD REQUIRED:** §11 (webapp module) and §12 (cleanup + entrypoint trap) are baked into the
Kali image — rebuild before using them in the container:
`docker compose -f infra/docker-compose.kali.yml build kali`.

---

*Bottom line for the next session: free disk space first (§8), then complete the §7 steps
(small edits + host verification), then rebuild the slimmed Kali image. Everything else is built,
verified, and documented above. §11 added the web-app pentest layer (IDOR/BOLA + injection + PTT);
§12 added ephemeral teardown (wipe graph + memory + bus + artefacts when the agent closes).*
