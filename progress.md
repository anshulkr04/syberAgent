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

## 13. Identity provisioning for IDOR/BOLA — AgentMail + AgentPhone (2026-06-08)

**Problem:** the agent kept concluding "site is safe" because it stopped at the *unauthenticated*
surface. Real IDOR/BOLA needs **two verified accounts** (fetch A's object as B), and signup
confirmation arrives by email link or SMS OTP — which the agent had no way to receive. This layer
gives it its own inboxes + a phone number to register real test accounts on the target.

**New package `syber/integrations/`** (stdlib urllib, no new runtime deps):
- `__init__.py` — `http_json()` helper, `IntegrationError` / `IntegrationNotConfigured`, `env()`.
  Documents the SCOPE BOUNDARY (see below).
- `agentmail.py` — REST client for https://api.agentmail.to (Bearer `AGENTMAIL_API_KEY`):
  `create_inbox` (idempotent via client_id), `delete_inbox`, `list_inboxes`, `list_messages`,
  `get_message` (URL-encodes the RFC822 Message-ID), `wait_for_message` (poll, falls back to the
  list summary if get_message fails), `extract_links` (verify-link-first), `extract_otp`.
  `inbox_id` IS the address.
- `agentphone.py` — REST client for https://api.agentphone.ai (Bearer `AGENTPHONE_API_KEY`):
  `signup`/`verify` (one-time bootstrap), `status`, `read_sms`, `wait_for_sms`, `extract_otp`.
  Outbound `notify_operator_sms`/`call_operator` are **operator-only** (guard `_assert_operator`
  refuses any number != `SYBER_OPERATOR_PHONE`).
- `identity.py` — `provision_identity(label, want_phone)` → `{email, inbox_id, phone, number_id}`;
  `harvest_verification(inbox_id, want_sms)` → `{email_links, email_otp, sms_otp}`.

**SCOPE BOUNDARY (deliberate):** these touch only the agent's OWN AgentMail/AgentPhone account,
never the target — so they are NOT behind the target-auth gate (the gate still governs the target).
Inbound is fully enabled (receive signup mail / OTP). **Outbound calling/SMS to arbitrary numbers
is NOT exposed** — that is vishing/smishing, a separate consent domain; outbound is library-only and
restricted to the operator's own number for the consensual "call me" notification.

**4 new MCP tools** (mcp_server.py, via `_integration()` wrapper — actionable error on missing key):
`syber_provision_identity`, `syber_check_inbox`, `syber_read_sms`, `syber_phone_status`. Total
syber_ tools now 29.

**Skill:** `npx skills add agentmail-to/agentmail-skills` installed on host
(`.claude/skills/`); the `agentmail` + `agent-email-patterns` skills baked into the container
workspace (`infra/kali/workspace/.claude/skills/`). `agentmail` pip pkg added to the Dockerfile venv.

**Wiring:** keys flow `syberAgent/.env` → compose `env_file` → container; passed through both
`.mcp.json` files (workspace + plugin). Both `AGENTMAIL_API_KEY` and the full AgentPhone cred set
are now in `.env` (gitignored, outside the git root `/Users/anshulkumar/syberAgent`). AgentPhone
was bootstrapped via `scripts/syber_phone_signup.sh --auto` (creates a throwaway AgentMail inbox,
self-reads the emailed OTP, verifies) → provisioned number **+17017867337**
(`AGENTPHONE_AGENT_ID` / `AGENTPHONE_NUMBER_ID` in `.env`).

**Free-tier caps (operational):** AgentMail free = **3 inboxes** — the agent must `delete_inbox`
test identities after use (IDOR wants 2 fresh per target). AgentPhone free = 10 numbers /
1000 SMS / 250 voice-min per month.

**Live-testing bug fixes (all fixed + verified):**
1. `get_message` 400 — RFC822 Message-IDs contain `<…@…>`; URL-encode the path segment (+ fall
   back to the list summary in `wait_for_message`).
2. Stale OTP — a fixed `client_id` made AgentMail REUSE the inbox, so old OTP emails were read;
   `syber_phone_signup.sh` now uses a unique (timestamped) `client_id` → fresh inbox per signup.
3. Cloudflare 1010 `browser_signature_banned` on AgentPhone `v1` GETs — the default
   `Python-urllib` UA is banned; `http_json` now sends a real Chrome User-Agent.
4. AgentPhone wraps SMS in a `data` key (not `messages`) — `read_sms` handles `data`/`messages`/`items`.

**Docs taught the multi-account IDOR workflow:** workspace CLAUDE.md (new step 2 "Register real
test accounts", coverage-checklist item "App / authenticated", capabilities list), `/syber-pentest`
(new step 5), `syber-scanner` agent (frontmatter tools + protocol step b). Plugin copies synced.

**Verified (host, 2026-06-08):** live AgentMail provisioned + deleted real inboxes; AgentPhone
`status()` + `read_sms()` return live data over the provisioned number; 10 new integration tests +
22 webapp tests pass (30 total in the integration dir); `py_compile` clean. (`mcp` is container-only,
so mcp_server is import-checked in-container, not on host py3.14.)

**REBUILT & VERIFIED IN-CONTAINER (2026-06-08):** `docker compose -f infra/docker-compose.kali.yml
build kali` succeeded. Inside `syber-kali:latest`: `syber/integrations/` present, `agentmail` SDK
imports, skills `agent-browser`/`agent-email-patterns`/`agentmail` baked, all 4 identity MCP tools
register, and `env_file` delivers `AGENTMAIL_API_KEY`(70 chars) + `AGENTPHONE_API_KEY` +
`AGENTPHONE_NUMBER=+17017867337` → both `agentmail.configured()` and `agentphone.configured()`
return True. Nothing left to rebuild for §13.

---

## 14. Cloudflare WAF traversal layer — ADDED (2026-06-14)

Implemented `waf-spec.md` (v1.0.0): a layered Cloudflare-WAF traversal module so the agent
reaches WAF-protected targets instead of being blocked at the "Just a moment…" interstitial,
and recognises/handles the challenge types. Same engineering posture as the rest of the
platform — real where it can be, dependency-light fallbacks, never hard-crashes.

**New package `syber/waf/`** (10 modules, all host-tested):
- `detect.py` — PURE challenge detection (waf-spec §2): classifies js_challenge / turnstile_managed
  / turnstile_interactive / managed_challenge / rate_limited / blocked from (status, headers, body);
  extracts Turnstile sitekey, cf-ray, Retry-After, cf_clearance. Unit-tested without network.
- `cookie_store.py` — cf_clearance store keyed by **(domain, IP, UA)** (§4.4 — CF binds the cookie
  to the solving IP+UA). InMemory LRU+TTL (default), SQLite (persistent), Redis (import-guarded).
- `rate_limiter.py` — token-bucket RPS per-domain/global + JitterEngine + exp backoff (cap 60s) +
  429/Retry-After cool-down that progressively slows a 429-ing host (§4.6). **Fixed a real bug**:
  the "first call" sentinel `last_refill==0.0` collided with a clock reading 0.0 → bucket refilled
  full every call; now an explicit `initialized` flag.
- `proxy_pool.py` — rotation + **sticky sessions** (one IP per domain while the cookie is valid),
  health, geo targeting, fallback chains (§4.5). Empty pool == direct connection.
- `config.py` — dataclasses + YAML/JSON loader with `default` + per-target override deep-merge (§5).
- `tls_client.py` — **L1** browser-TLS impersonation via `curl_cffi` when present; **urllib fallback**
  (no curl_cffi wheel on Py3.14, same story as torch/transformers). Browser fingerprint then comes
  from the L3 solver instead.
- `solver.py` — **L3** challenge solvers: `AgentBrowserSolver` (default — reuses the platform's own
  agent-browser+Chromium; reads the **HttpOnly** cf_clearance via `cookies get`/CDP, which
  `document.cookie` can't see), `FlareSolverrSolver` (REST), `PyDollSolver` (import-guarded seam).
- `captcha.py` — **L4** 2captcha/CapSolver Turnstile token retrieval (§3.4); OFF by default, returns
  actionable "not configured" rather than raising.
- `integration.py` — `WAFIntegration` orchestrating the **8-step flow** (§4.3): L0 API-first →
  L2 session reuse → L1 fetch → L3 solve+retry → L4 → `WAFBlockError`. `request`/`batch_request`/
  `refresh_session`/`get_cookie`. **Synchronous** (matches the platform; the spec's async interface
  is a trivial wrapper if ever needed).

**Wiring:**
- `scanning/webapp.py::http_request` now **auto-escalates** to the WAF module when an ordinary fetch
  returns a Cloudflare challenge (opt-in via `SYBER_WAF`, default on; best-effort, falls back to the
  raw challenge response on any WAF error). So the existing crawl/IDOR/injection layer is WAF-aware.
- **3 new MCP tools** (now **32** total): `syber_waf_request`, `syber_waf_refresh`,
  `syber_waf_session_status` — all default-deny **authorization-gated** (they actively reach the target).
- `infra/waf.example.yaml` (§5 config) + `infra/cloudflare/` (§6 origin-hardening: `waf_rules.example.json`
  custom-rule set + README for the three-tier auth / bot-management / allowlisting guidance).
- `requirements.txt`: `curl_cffi` + `redis` added as commented optional upgrades (auto-detected).

**Verified (host, 2026-06-14):** new `tests/waf/test_waf.py` = **29 tests** (detection signatures,
cookie keying+TTL+LRU+SQLite, rate-limiter bucket/jitter/429-cooldown, proxy sticky/geo/fallback,
config target-merge, and the full L0→L3 flow with a faked transport+solver). **Full suite 61 passed.**
Real-network smoke: `waf.request('https://example.com/')` → 200 via L1 urllib, clean detection.
`py_compile` clean on `mcp_server.py` + all of `syber/waf/` (FastMCP import is container-only).

**Next (optional):** (a) sync the new tools + a "WAF traversal" section into the workspace/plugin
`CLAUDE.md` doctrine, `/syber-pentest` command, and `syber-scanner` agent frontmatter (so the agent
knows the tools exist) — same doctrine-sync done for §11/§13; (b) rebuild the Kali image to bake the
`syber/waf/` package + infra files in; (c) install `curl_cffi` on a Py≤3.12 image for real JA3/JA4
impersonation (L1 then clears more sites without invoking the browser); (d) wire the L4 token back into
the agent-browser solver session for end-to-end interactive-Turnstile solving.

### 14a. syber_engage wiring + real-site testing (2026-06-14)
**Engagement integration done:** `scripts/syber_engage.sh` SEED + CONTINUE prompts now teach the agent
the WAF behaviour (crawl/http_request auto-traverse Cloudflare; use `syber_waf_request` for crafted
probes; a hard block 1020/1010 is unsolvable — note it, don't grind). `.env.example` documents the
optional knobs: `SYBER_WAF` (default on), `SYBER_WAF_CONFIG`, `SYBER_WAF_PROXIES`,
`SYBER_WAF_CAPTCHA_PROVIDER`/`_KEY` (wired into `build_waf_integration`). **In-container path:**
`env_file: ../../.env` delivers all of these to the agent; `SYBER_WAF` defaults ON when unset, so
auto-escalation is active with zero extra wiring. The MCP server inherits the container env, so the 3
`syber_waf_*` tools + the auto-escalation both work once the image is rebuilt.

**REBUILD REQUIRED:** the image does `COPY . /opt/syber-platform` + `pip install -e` at build time
(no volume mount), and `mcp_server.py` now imports `syber.waf` at module top — so the Kali image MUST
be rebuilt (`docker compose -f infra/docker-compose.kali.yml build kali`) before `syber_engage.sh`
runs, or the MCP server won't import. Same rebuild step as §11/§13.

**Bugs found + fixed while testing on a live Cloudflare site (`nowsecure.nl`):**
1. **Headless Chrome DOES solve Cloudflare** — confirmed: `agent-browser cookies get` returned a real
   `cf_clearance` token. The solver just read the page wrong.
2. `agent-browser get html` returns a **truncated** 73-char string → the solver saw "no markers" and
   declared a false clear. Fixed: read the live DOM via `eval document.documentElement.outerHTML`
   (~183K chars) + guard `len(html) < 256` is never treated as "cleared".
3. `agent-browser cookies get` emits **cookie-header format** (`cf_clearance=…`), not JSON — the parser
   dropped it. Fixed: `parse_ab_cookies` now handles JSON *and* `k=v`/`;`-separated forms (skipping
   cookie attributes).
4. **cf_clearance is bound to the solving UA.** The browser solves as `HeadlessChrome/149` but L1 was
   replaying with the config UA (`Chrome/120`) → Cloudflare rejected the cookie → infinite re-solve →
   misleading "no response". Fixed: per-domain effective-UA (`_domain_ua`) so the cookie store + L1
   replay both use the UA the browser actually solved with (same machine = same IP, so all three match).
5. Terminal error is now informative (reports the real challenge/transport error, and **returns the
   browser-rendered page** when cookie replay can't be honoured) instead of "no response".

**Verified (host, 2026-06-14):** full suite **61 passed**; the L3 solver reads the real DOM + captures
the UA end-to-end against a live site (`example.com` → 544 chars real HTML, UA captured, no false
cookie); captcha env override works. The cf_clearance-issuing solve on `nowsecure.nl` was demonstrated
earlier (real cookie captured); a clean re-run was blocked only by that domain's intermittent DNS in
the dev sandbox (example.com/cloudflare.com/google.com resolve; nowsecure.nl flaps) — an environment
quirk, not the code.

### 14b. WAF dead-end FALLBACK — pivot to alternate vectors (2026-06-26)
When the layered traversal cannot clear Cloudflare (a hard block 1020/1010, an interactive Turnstile
with no solver, or plain exhaustion), the engagement no longer dead-ends — it **pivots around the edge**.
Cloudflare only protects the proxied HTTP edge; the origin server, sibling subdomains, and the network
layer routinely sit outside it.

**New module `syber/waf/fallback.py`** (stdlib only — `socket`/`ssl`/`ipaddress`/`urllib`):
- `is_cloudflare_ip()` — classifies an IP against Cloudflare's published v4/v6 edge ranges (an IP
  *outside* them resolved for a sibling/CT host is a candidate origin).
- `find_origin_candidates()` — resolves common origin-revealing subdomains (`direct`/`origin`/`mail`/
  `dev`/`staging`/`api`/`cpanel`…) **plus** certificate-transparency hosts (crt.sh OSINT — against the
  public CT record, not the target), and splits each resolved IP into CF-edge vs candidate-origin.
- `probe_origin()` — connects to a candidate IP directly with the correct `Host` header (SNI pinned,
  cert-verify off, like an origin pull). A real, non-challenge answer means **the WAF is bypassed**.
- `explore_alternate_vectors()` — the top-level pivot: returns a `FallbackResult` with the direct-origin
  hit (if any) **and** a ranked vector plan (direct-origin → non-edge subdomains → non-proxied ports
  SSH/mail/DB/8080/8443 → subdomain enumeration → DNS/mail → api.*/m.* hosts).

**Wiring:**
- `scanning/webapp.py` `_waf_escalate` now calls `_waf_fallback()` on a `WAFBlockError` *or any* WAF
  error. If a direct origin answers, it returns **that** un-WAF'd response (so crawl/IDOR/injection run
  on real content) with `waf_bypassed: true` + `origin_ip`; otherwise it attaches `waf_fallback` (the
  vector plan) to the original challenge response. Best-effort — never raises into the probe.
- New MCP tool **`syber_waf_fallback(url, probe=True)`** (authorization-gated) — now **33** WAF-aware
  tools. The agent calls it the moment a Cloudflare target stops yielding.
- `syber_engage.sh` SEED + CONTINUE prompts now instruct: *if the WAF will not yield, DO NOT stop and
  DO NOT hammer — call `syber_waf_fallback`, then work the alternate vectors extensively.*

**Verified (host, 2026-06-26):** all fallback logic exercised offline (DNS/socket monkeypatched) —
IP classification (v4/v6/malformed), apex/subdomain generation, HTTP-response parsing, CF-vs-origin
candidate split, the direct-origin bypass decision, and graceful degradation when DNS resolves nothing
or every host is a CF edge. New tests in `tests/waf/test_fallback.py`. All four touched files parse +
import clean; `_waf_fallback` confirmed wired into `_waf_escalate`. (pytest itself runs in the Kali
image; local host has no pytest, so logic was exercised via a manual runner.)

### 15. Cross-repo improvements — distilled from VulnClaw + CAI (2026-06-29)
After a deep, line-by-line study of **VulnClaw** (Unclecheng-li) and **CAI** (Alias Robotics), the
genuinely transferable techniques were ported (the rest — their multi-agent SDK forks, cost tracking,
in-process Python interpreters, allow-by-default authz — were deliberately NOT copied; the Claude Code
harness or Syber's existing design already cover them, and several are regressions for us). Themes:
VulnClaw's strength is anti-hallucination/verification; CAI's is context/output hygiene & safety tiers.

**New modules (all pure, dependency-light, unit-tested — same posture as `waf/`):**
- `syber/util/output_hygiene.py` *(CAI Phase-1 compaction + VulnClaw lead-first)* — content-type-aware
  head+tail truncation with a `[… N truncated …]` marker, and lead-first reordering that floats
  secrets/confirmed-leads/auth surfaces above the bulk so a downstream cap never drops a finding.
  Wired into the body-returning MCP tools (`syber_http_request`, `syber_waf_request`) via
  `hygienic_response`. NOT applied inside `webapp.http_request` (internal callers like `crawl` need the
  full body to parse).
- `syber/scanning/verify.py` *(VulnClaw `_completion_is_grounded` + verified-only report)* — sentinel
  `Verdict` (CONFIRMED/POSSIBLE/REJECTED, **default-reject**) and `evidence_grounded(claims, captured)`
  (a claimed flag/secret must appear verbatim in real tool output, else it's a hallucination). The
  `webapp` probes now stamp a `verdict` on every finding: XSS-reflected / error-based-SQLi / cross-
  session-BOLA / IDOR = CONFIRMED; SSRF-canary = POSSIBLE (needs OOB). Complements CES (which scores a
  finished finding) by guarding the cheaper binary "is this real" boundary.
- `syber/scanning/risk.py` *(CAI sensitive-command taxonomy + VulnClaw payload-signature intent)* —
  `classify_command` (a shlex tokenizer that ignores quoted args, so `grep 'sudo'` ≠ privilege) and
  `classify_payload` (intent by payload content, not HTTP verb) → `RiskTier`; `decision()` is
  default-deny on DESTRUCTIVE/EXFILTRATION/REVERSE_SHELL/PRIVILEGE unless explicitly opted in. Each tier
  carries a MITRE tactic tag for graph/audit enrichment.
- `syber/scanning/recall.py` *(VulnClaw blackboard tool-call ledger)* — a thread-safe, LRU, process-
  lifetime dedup ledger keyed by `sha1(tool + sorted-args)`. Auto-recorded for every scan/web tool in
  the MCP `_scan` helper; surfaced to the agent via the new **`syber_recall_tool_calls`** tool so it
  stops re-issuing identical calls (the #1 cause of wasted loops).

**Other wiring:**
- `harness/injection_guard.py` *(CAI detective guardrails)* — StruQ's untrusted-channel classifier now
  NFKC-normalises + folds Unicode homoglyphs (Cyrillic/Greek/fullwidth → ASCII) and **decodes
  base64/base32 runs to inspect for hidden injections/reverse-shells** before the pattern bank runs.
- `scanning/webapp.py` — `infer_endpoints()` synthesises likely-but-unlinked REST routes (API-base ×
  entity nouns × {item ids, CRUD sub-routes}); `crawl` now returns `inferred_endpoints` for the probes
  to test. *(VulnClaw js_recon combinatorial expansion — amplified by our real-Chromium crawl.)*
- Doctrine: `infra/kali/workspace/CLAUDE.md` gained a **"Verify with evidence — don't fool yourself"**
  rule (reflection ≠ execution; claimed secret must be in real output; "found the file" ≠ "got it";
  don't repeat — check `syber_recall_tool_calls`; WAF block → `syber_waf_fallback`), and the new tools
  are registered. New skill **`web-bypass-cheats`** front-loads pre-verified tables (MD5/SHA1 magic
  hashes, PHP type-juggling, filter/WAF encodings, SSRF targets) so the agent stops brute-forcing
  known-solved problems.

**Verified (host, 2026-06-29):** `tests/improvements/test_improvements.py` — **33 passed, 0 failed**
(output hygiene, homograph+base64 injection detection, verdicts+grounding, endpoint inference, risk
taxonomy incl. quoted-sudo edge case, recall LRU/dedup). All 9 touched files parse + import clean; WAF
fallback suite still green. One real bug fixed in the destructive-command regex (`rm -rf /` — a trailing
`/` can't be followed by `\b`). MCP tool count: 33 → **34** (`syber_recall_tool_calls`; the WAF fallback
tool from §14b made 33). pytest runs in-container; host has no pytest so a manual runner was used.

**REBUILD REQUIRED:** new files under `syber/` + new MCP tool ⇒ rebuild the Kali image
(`docker compose -f infra/docker-compose.kali.yml build kali`) before `syber_engage.sh` picks them up.

### 16. Persistent PARALLEL fleet — syber/fleet/ (2026-06-29)
After a deep 4-front literature review (reports in scratchpad: research_papers / _orchestration / _graph /
_persistence — HPTSA 2406.01637, PentestGPT 2308.06782, AutoPT 2411.01236, VulnBot 2501.13411, CAI
2504.06017; Anthropic orchestrator-worker + blackboard 2507.01701 + LangGraph; MulVAL + NASim + GraphRAG;
Temporal/SKIP-LOCKED leasing), built the thing **no published pentest system ships**: a tight,
intra-target PARALLEL fleet that fans out specialists across vectors at once, pools evidence into the
attack graph (the blackboard), then re-divides — vs the *sequential* specialist dispatch of HPTSA/VulnBot.
Decision (confirmed with user): **in-memory-first + scale-up seam**, **Claude Code harness world first
(MCP tools)**, **build all phases with a per-phase check-in**.

Architecture = Orchestrator-Worker control + Graph-as-blackboard + durable wave-checkpointing.
New package `syber/fleet/` (pure, dependency-light, in-memory-first; degrades to today's single-agent
behaviour if unused):
- **board.py** (Phase 1) — the blackboard task layer. `Task`/`TaskStatus`, `InMemoryTaskStore` with an
  **atomic claim/lease** protocol (claim/claim_next priority+dep-gated, heartbeat with lost-lease
  detection, reaper for crashed workers, complete/fail→requeue→dead-letter, block). `Board` derives the
  **frontier** from graph facts via idempotent deterministic rules (Host→service_scan; web Service→
  web_crawl; Service→vuln_scan; parametered WebEndpoint→test_injection+test_access_control; un-weaponised
  Vuln→exploit). snapshot/restore for checkpointing. Backend seam (SYBER_FLEET_BACKEND) for
  Neo4j/Postgres later (SKIP-LOCKED/CAS), falls back to memory.
- **planner.py** (Phase 2) — expected-value frontier ranking (value+risk+betweenness+path-gain+severity+
  info-gain − cost − attempts), **reusing the existing risk_score/betweenness_top/yens_k_shortest/
  critical_targets**. Disjoint **one-task-per-host** batching (low contention) + phase-aware wave sizing
  (fan-out reads, serialize writes — the Anthropic↔Cognition reconciliation).
- **coordinator.py** (Phase 3) — the persistent **plan→fan-out→pool→re-divide** loop (ThreadPoolExecutor
  waves), per-engagement + per-worker budgets, `StuckDetector` (action-hash + empty-coverage-delta),
  failed/looped→requeue-with-reflexion→dead-letter→HITL, **durable JSON checkpoint + resume-not-restart**,
  done = **coverage fixpoint** (no open tasks AND re-materialize yields nothing new). Worker is injected
  → fully testable without an LLM.
- **specialists.py** (Phase 4) — the roster (recon, web-mapper, vuln-triage, injection, idor-bola,
  waf-origin, exploit), each with a tool subset + curated **doc-pack** (HPTSA: +4× pass@1) +
  **counterfactual dedup** directive (PenHeal). `make_tool_worker` = a **deterministic** WorkerFn that runs
  Syber's EXISTING tools per kind and pools results into the graph → the fleet runs a full autonomous
  parallel scan/crawl/test engagement **with no LLM**; reasoning kinds (exploit) park `blocked` for the
  agent worker.
- **MCP tools** (Phase 5, in mcp_server.py): `syber_fleet_run` (one-call autonomous parallel engagement,
  resumable), `syber_fleet_status`, `syber_fleet_plan_wave`, `syber_fleet_next_task` (atomic claim +
  returns the specialist system prompt with peers), `syber_fleet_complete`. Lets the harness LEAD agent
  fan out Task subagents over the shared board. Plus **scripts/syber_fleet.sh** (parallel analogue of
  syber_engage.sh) and a "Work in PARALLEL" doctrine section in the workspace CLAUDE.md.

**Verified (host venv w/ networkx+pytest, 2026-06-29):** **58 fleet tests pass** (board claim/lease +
8-thread/200-task no-double-dispatch concurrency; planner ranking + disjoint/phase batching; coordinator
full loop + evidence-pooling-grows-frontier + budgets + dead-letter/HITL + checkpoint/resume across a
simulated crash; specialist roster + prompts + deterministic tool worker + full no-LLM fleet run; harness
multi-subagent flow incl. 8-thread concurrent safe claiming). Full regression **132 passed** (fleet + waf
+ improvements). MCP server AST-validates; syber_fleet.sh lints clean. Three test-harness bugs found and
fixed along the way — each actually confirmed a real invariant works (dep-gating refuses premature claim;
is_quiescent is a pure pre-materialize read). pytest runs in-container; host lacked networkx/pytest so a
scratchpad venv was used.

**Phase 6 — attack-graph reachability (MulVAL hacl/netAccess):** `graph/model.py` gained
`set_host_state` (discovered/reachable/compromised/access/value), `upsert_reachability` (CAN_REACH edge,
marks dst reachable), and `mark_compromised` (records a foothold AND derives reachability to CAN_REACH
neighbours — the monotone update that turns one foothold into an attack path). `graph/store.py` gained
`reachable_from` / `compromised_hosts` / `lateral_frontier`. `fleet/board.py` adds a `_rule_lateral`
frontier rule (inert until a foothold exists; then spawns lateral-movement tasks to reachable-but-
uncompromised neighbours). Verified end-to-end: a worker that compromises a host mid-run makes the
neighbour reachable → it gets scanned + a lateral task → all worked to fixpoint. **8 reachability tests;
fleet total now 66; full regression 140 passed.**

**Phase 7 — persistence (never stop early), per user request "loop till it finds something / explores
the whole attack chain":** `fleet/persistence.py` `PersistencePolicy` makes the coordinator NOT stop at
a shallow fixpoint. When the frontier drains, it DEEPENS before allowing a stop: (1) **revive_dead** —
bring DEAD/BLOCKED tasks back (capped per task, the direct anti-premature-abandonment lever — AutoPT's
#1 failure mode at 75.6%); (2) **deepen_web** — add a content_discovery task (new `_run_content_discovery`
runner ingests found paths as WebEndpoints → spawns more injection/IDOR tasks); (3) **expand_scope** —
promote discovered sibling hosts (cert SANs) to scan targets **only if already AUTHORISED** (default-deny
is never bypassed; out-of-scope siblings are leads, not scans). Lateral movement (Phase 6) covers in-scope
reachable hosts. The loop stops only at a **deep fixpoint** (materialize AND deepen both yield nothing) or
budget; `found_something` (Finding / Vulnerability≥floor / compromised host) labels the outcome, and
`stop_on_first_find` optionally short-circuits. `syber_fleet_run` enables persistence by default and raises
max_waves 40→200. Coordinator without a policy keeps the old shallow-stop behaviour (back-compat).
Verified: **12 persistence tests** (revive cap, deepen-web idempotent, authorised-only scope expansion,
safe-without-auth-store, severity floor, coordinator revives-before-stopping, stop-on-first-find,
back-compat). Fleet total **78**; full regression **152 passed**.

**REBUILD REQUIRED** before the fleet works in-container (new `syber/fleet/` + 5 MCP tools + graph
reachability + persistence):  `docker compose -f infra/docker-compose.kali.yml build kali`.

### 16b. VERIFICATION / evidence-ladder layer — "verify, don't just discover" (2026-06-30)
Triggered by a real run: the agent found an exposed Keycloak admin console + master realm and declared
ENGAGEMENT_COMPLETE at "MEDIUM — no confirmed exploit" instead of digging in. Root cause (confirmed in
code): the fleet taxonomy ended at mechanical scanning and PARKED verification; `found_something()` returned
True on ANY vuln so "done" fired too early; `cap_severity()` correctly capped HIGH→MEDIUM with no exploit
evidence — but the agent never DID the verification to earn it. Researched first (2 deep reports in
scratchpad: research_verify.md + research_kali_tools.md — Fang 2404.08144 "CVE-desc 87% vs 7%", PentestGPT
PTT, AutoPenBench 21%→64% milestone gap, AutoPT PSM, VulnBot, Reflexion, Anthropic long-run harness, CVSS
v4, HackerOne/Bugcrowd triage, PTES/WSTG; + exact Kali commands for searchsploit/vulners/nuclei -id/testssl/
default-logins/Keycloak/per-service). User decisions: intrusive-by-default, runners + LLM verify subagent,
all phases.

New layer in `syber/fleet/`:
- **leads.py** — the **evidence ladder** (rung 0 reachable/INFO → 1 version-matches-CVE/LOW → 2 precondition/
  MEDIUM → 3 verified-exploit/HIGH → 4 impact/CRITICAL) + **lead taxonomy** (EXPOSED_ADMIN, DEFAULT_CRED,
  VERSION_CVE, EXPOSED_SECRET, AUTH_BYPASS, INJECTION, DATASTORE_UNAUTH, UNAUTH_STATE_CHANGE; HIGH_VALUE set)
  + `classify_node` (graph node → Lead; Keycloak→default_cred, /auth/admin→exposed_admin, /.git→secret,
  versioned product→version_cve, redis/mongo/es ports→datastore) + `LeadRegistry` with the **done-gate
  `no_open_highvalue_lead()`** and `record_attempt` (success→climb ladder; fail→logged hypothesis failure→
  EXHAUSTED only when ALL hypotheses tried). Severity is EARNED by evidence, never claimed blind.
- **verify_runners.py** — 8 deterministic verification runners (pure command builders + guarded subprocess):
  cve_lookup (nmap vulners + searchsploit → candidate CVEs, rung 1), cve_verify (`nuclei -id <CVE>` → rung 3),
  tls_audit (testssl), default_login_check (nuclei default-logins → rung 4), exposed_artifact_check (.git/.env),
  http_verb_tampering, datastore_unauth_probe (redis/mongo/es/docker/kubelet), service_probe (Keycloak default-
  cred admin token grant = the failure-case fix; dispatches per product). **Intrusive-by-default** (user choice)
  with a hard **destructive floor OFF** (`SYBER_FLEET_DESTRUCTIVE`, default 0 — no DoS/data-destruction/webshell/
  privileged-container/kubelet-exec; PUT/DELETE verb tampering gated). Every runner passes `_require_authorized`.
- **Wiring:** Board gained a `LeadRegistry`; `materialize_frontier` now derives leads + spawns a verify task per
  open high-value lead's untried hypothesis (Task gained lead_id/product/version/cve/url fields, persisted).
  Coordinator done-condition: will NOT declare complete while a high-value lead is open — it spawns verify
  tasks, and only `_exhaust_stuck_leads` (with logged reason) lets the loop converge for LLM-only leads; lead
  registry is checkpointed/restored. specialists.default_runners merges verify_runners; planner learns the new
  read-kinds + costs.
- **MCP tools (8d):** `syber_leads_status` (the ladder + open high-value leads), `syber_verify_lead <id>`
  (hypotheses + **CVE-description injection** via the NVD public API — the 7%→87% lever; degrades offline).
  Now 3 fleet + 2 lead tools.
- **Doctrine/skill (8d):** new **deep-verification skill** with per-service playbooks (Keycloak/Jenkins/GitLab/
  Grafana/Redis/Mongo/Docker-K8s/IIS) + safe-discipline; a "VERIFY, don't just discover" section in CLAUDE.md;
  `syber_fleet.sh` + `/syber-fleet` now drive leads_status→verify_lead→prove→gate and forbid concluding while
  a high-value lead is unverified. Also **restored the recurring `_expand_scope`/`_authorized` always-allow
  stub** (3rd time) to default-deny.
- **Image (8e):** Dockerfile adds exploitdb(searchsploit), feroxbuster, wafw00f, hydra, redis-tools, testssl.sh,
  vulners.nse, git-dumper, arjun.

**Verified (host venv, 2026-06-30):** **16 new verification tests** (evidence ladder, classification incl.
Keycloak/secret/datastore, done-gate blocks-until-resolved, record_attempt climb/exhaust, command builders,
board spawns verify tasks, and the END-TO-END fix: an exposed high-value lead is NOT left at the surface — it
reaches VERIFIED-CRITICAL when default creds confirm, or EXHAUSTED-with-logged-attempts when a mechanical-only
worker can't verify). Fleet total **96**; full regression **170 passed**; all files parse; script lints; both
auth stubs confirmed default-deny. (NVD CVE-intel reachable in sandbox, degrades cleanly offline.)

**REBUILD REQUIRED** before this works in-container (new modules + 2 MCP tools + Dockerfile tools):
`docker compose -f infra/docker-compose.kali.yml build kali`.

### 16a. Fleet runtime-integration hardening (2026-06-29)
A code-path audit of the *real* run path (syber_fleet.sh → claude -p → syber-tools MCP) surfaced gaps
between "153 unit tests pass" and "usable in-container". Fixed (user-approved: in-process threads /
state volume / all three):
- **P1 — bounded, resumable fleet_run.** `syber_fleet_run` was synchronous-to-fixpoint with a 1-hour
  budget, but `entrypoint.sh` sets `MCP_TOOL_TIMEOUT=30min` → the harness would kill it mid-engagement.
  Now each call is **time-bounded** (`max_seconds`, default 1200s < ceiling) and **checkpoints every
  wave**; returns `resumable: true` when work remains → call again to continue, `done: true` when the
  chain is exhausted. Coordinator budget made **per-call** (`_call_start`, measured from this run()
  invocation) so a resumed call gets a fresh window instead of instantly expiring. Fixed a falsy-`0.0`
  guard bug found by the new test (a clock reading 0.0 must still be honoured).
- **P2 — durable state volume.** `kali` service had no volume → the in-memory board + disk checkpoint
  reset every `--rm` pass. Added a named `syber-state` volume at
  `/opt/syber-platform/.investigation_state` (+ Dockerfile pre-creates/chowns it so the non-root `syber`
  user can write) so the checkpoint persists across passes.
- **P3 — simplified to in-process threads.** The harness-subagent-claim layer (`syber_fleet_next_task`/
  `syber_fleet_complete`) was **not wired** (custom agents' tool whitelists exclude fleet tools; no fleet
  agent) and redundant with fleet_run's internal thread pool. Removed those two MCP tools; kept `fleet_run`
  + read-only `fleet_status`/`fleet_plan_wave`. Rewrote `syber_fleet.sh` to **loop fleet_run until done**
  then work parked tasks directly; updated the workspace CLAUDE.md doctrine; added a real
  `/syber-fleet` command (the doctrine referenced a non-existent one).

**Also restored a recurring auth regression:** `_expand_scope` (persistence.py) and `_authorized`
(board.py) had both been silently stubbed to always-allow (`allowed = True` / `return True`), defeating
the default-deny scope check and failing a test. Restored both to consult `get_auth_store().is_authorized`
(fail-safe to deny). **NOTE: this stub keeps reappearing across edits — re-verify these two lines after any
external edit.** MCP fleet tools: 5 → **3**. Verified host venv: **154 passed** (fleet 80 incl. per-call
budget+resume); compose YAML + volume wiring validated; syber_fleet.sh lints; MCP server AST-clean.

### 17. Data-exposure verification + optional operator-context file (2026-06-30)
Triggered by a real `syber_fleet.sh nuvamawealth.com` run: the agent found an exposed UAT env
(leaked Swagger of 462 endpoints, JWT in HTML, unauth `MonitorDB`/`AccountMonitor` returning `true`)
and declared CRITICAL — but never **pulled real data** to prove sensitive records were actually
exposed. "Returns 200 / `true` / structured data present" was being treated as the rung-4 IMPACT proof.

**(a) Data-exposure verification — earn the IMPACT rung by sampling real data:**
- **`syber/scanning/exfil.py`** (new, pure, unit-tested) — `scan_sensitive(body, content_type)` classifies
  a response body: PII (email/phone/PAN/Aadhaar/SSN/credit-card+Luhn/IFSC), secrets/tokens (JWT/AWS/
  private-key/credential-fields/bearer), and structured-record counting (JSON array/obj, NDJSON, CSV).
  Verdict ladder: REAL_DATA→CRITICAL, STRUCTURED→HIGH, EMPTY/BOILERPLATE/ERROR→not-a-finding. `redact()`
  masks values; `save_sample()` writes a capped raw body + redacted JSON summary to
  `.investigation_state/evidence/<host>/` (a real DOWNLOADED artefact for the operator; only redacted
  data is surfaced to the model/lead).
- **`fleet/verify_runners.py`** — new `run_data_extraction` runner (kind `data_extraction`): fetches the
  endpoint via `webapp.http_request` (WAF/browser-aware), scans it, climbs the lead ladder (REAL_DATA=
  IMPACT, STRUCTURED=VERIFIED, empty=logged failure→EXHAUST). Registered in `verify_runners()`.
- **`fleet/leads.py`** — new high-value class `UNAUTH_API_DATA` (a reachable `/api/`,`/mwapi/`,`/v\d/`,
  graphql… endpoint at 2xx → verify by pulling data); Swagger/OpenAPI/GraphQL doc URLs now classify as
  EXPOSED_SECRET; `data_extraction` added to EXPOSED_SECRET + UNAUTH_STATE_CHANGE + the new class. So the
  done-gate won't let the engagement end while a data endpoint is unverified.
- **`fleet/planner.py`** — `data_extraction` added to READ_KINDS + action cost (1.5).
- **MCP tool `syber_verify_data_exposure(url, …)`** (mcp_server.py) — the LLM agent calls this directly to
  pull a sample, confirm real sensitive data, save the redacted artefact, and get a verdict/rung/guidance.
  The doctrine (workspace CLAUDE.md "VERIFY" section + tool list) and the **deep-verification skill** gained
  a "is there real data?" playbook: walk a leaked Swagger's data routes (GetUserDetails/GetBankDetails/…)
  through this tool; a confirmed sample is CRITICAL, `MonitorDB→true` is only reachable. `syber_fleet.sh`
  SEED + CONTINUE prompts now mandate it before any IMPACT/CRITICAL claim.

**(b) Optional operator-context file — `./syber_fleet.sh <target> [attestation] [context.md]`:**
args after the target are order-independent — any readable FILE is loaded as a trusted OPERATOR CONTEXT
block (priority instructions, applied within the authorisation/safety rules) and injected into BOTH the
SEED and every CONTINUE prompt (each pass is a fresh `claude -p`, so it must be re-injected). Anything
else is the attestation. Fully optional; no behaviour change when omitted. The file is read on the host
and embedded as a shell *variable* in the heredoc, so its contents are not re-expanded.

**Also restored (the recurring stub regression, 4th time — progress §16a/§16b):** `DESTRUCTIVE_ENABLED()`
and `_intrusive()` in verify_runners.py had been hard-stubbed to `return "1"`; restored to env-gated
(`SYBER_FLEET_DESTRUCTIVE` default OFF; `SYBER_FLEET_INTRUSIVE` default ON). `persistence._expand_scope`
was again `allowed = True` (always-allow); restored to `auth.is_authorized(name)[0]` default-deny (note:
`is_authorized` returns a `(bool, reason)` TUPLE — must index `[0]`). **Re-verify these 3 lines after any edit.**

**Verified (host venv, 2026-06-30):** new `tests/fleet/test_exfil.py` (14 tests: scanner verdicts,
Luhn, redaction, lead classification, runner IMPACT/exhaust/unauth paths) — **full suite 216 passed**;
all changed files `py_compile` clean; `syber_fleet.sh` lints + arg-parsing/context-injection verified
in isolation. **REBUILD REQUIRED** before in-container use: new `syber/scanning/exfil.py` + MCP tool ⇒
`docker compose -f infra/docker-compose.kali.yml build kali`.

### 18. External-benchmark harness — `syber/bench/` (CTIBench, Phase 1) (2026-06-30)
User wants Syber benchmarked against other models on three published cyber-LLM evals (web-researched
this session): **ExCyTIn-Bench** (`microsoft/SecRL`, MIT, ICML'26 — agentic SQL threat-investigation,
discounted-reward 0-1, GPT-4o judge, best=Claude-Opus-4.5 0.606, no DeepSeek baseline), **CTIBench**
(`xashru/cti-bench`, NeurIPS'24, arXiv 2406.07599 — notebook harness, CC-BY-NC-SA data), **CAIBench**
(`aliasrobotics/cai`, arXiv 2510.24317 — meta-bench; knowledge slice open via `eval.py`+litellm, CTF/A&D
capability slice gated behind CAI PRO). Decisions (user): **phased (both model-only + pipeline)**,
**DeepSeek-only** (compare to published tables; for ExCyTIn use DeepSeek-as-judge w/ caveat), **CTIBench first**.

**Built `syber/bench/`** (own clean harness rather than fighting 3 upstream harnesses): `datasets.py`
(auto-downloads+caches CTIBench TSVs to `.bench_cache/`, gitignored — NC data, never committed),
`models.py` (provider-agnostic OpenAI-compatible `ModelRunner`, paper-exact decoding temp=0/top_p=1/
seed=42/max_tokens=2048, reuses the platform DeepSeek config), `scoring.py` (pure: CWE extraction+exact-
match accuracy for RCM; ATT&CK technique extraction+micro-F1 for ATE), `prompts.py` (`bench`-faithful vs
`subagent`-persona modes — RCM=exposure-analyst, ATE=threat-investigator), `baselines.py` (published
GPT-4/GPT-3.5/Gemini-1.5/Llama-3 numbers), `run.py` CLI (`python -m syber.bench.run --task all`). The
dataset `Prompt` column is the verbatim paper prompt → numbers are apples-to-apples. 10 pure unit tests
(`tests/bench/test_bench.py`) green.

**RESULTS (deepseek-v4-pro, bench-faithful, 2026-06-30, 0 errors):**
- **CTI-RCM (CVE→CWE, n=1000): 0.745 accuracy — BEATS GPT-4 (0.720)**, best in the table (>GPT-3.5 .672,
  Gemini-1.5 .666, Llama3-70B .659).
- **CTI-ATE (report→ATT&CK techniques, n=60): 0.512 micro-F1 — 2nd to GPT-4 (0.639)**, ahead of Llama3-70B
  (.472)/Gemini-1.5 (.461)/GPT-3.5 (.311). (ATE is the benchmark's own 60-instance set → noisier.)
Artefacts in `.bench_results/`. NOTE: the original CTIBench paper has no DeepSeek/Claude baseline, so this
is a novel datapoint. These measure the MODEL (±subagent persona), not Syber's pipeline differentiators.

**Next:** (a) optional `--prompt subagent` re-run (tests the personas, another ~1060 calls); (b) **Phase 2
ExCyTIn-Bench** — the flagship "does the pipeline investigate correctly" eval; model-only run first
(DeepSeek agent + DeepSeek-as-judge, documented), then a Syber-orchestrator/threat-investigator adapter
into its SQL env; its failure modes (premature submission, stopping early, over-reliance on alerts) are
exactly what the CES gate targets — leading into (c) the CES-vs-failure correlation study (the CAIBench
knowledge-vs-capability idea, instrumented on our own runs rather than the gated CTF infra). Setup cost:
ExCyTIn needs Python 3.11 + MySQL-in-Docker + ~10GB dataset.

### 19. Consistency/robustness/persistence — surface-first methodology (2026-07-01)
User hit non-determinism: two `syber_fleet.sh nuvamawealth.com` runs gave wildly different results — one
found the catastrophic UAT exposure (462-endpoint Swagger, leaked JWT), another gave up at the first
CloudFront 403 and declared "strong defences, no critical findings". Root cause: the winning methodology
(**enumerate ALL subdomains, esp. non-prod uat/cug/staging → find the exposed twin → walk its API → verify
data**) lived only in the LLM's head, so it happened by luck. (Also diagnosed: the "good run" only worked
because the user passed `scripts/a.md` — which is the *prior good run's log* — as the operator-context file,
handing the agent the roadmap.) Fix = move the critical path into deterministic engine steps + hard doctrine.

**New `syber/scanning/subdomains.py`** — deterministic subdomain enumeration: multi-source **Certificate
Transparency** (crt.sh with retries — it frequently 502s — UNION certspotter fallback) + non-prod-heavy
prefix wordlist + **base×env brute** (catches concatenated twins: onboarding→onboardinguat, nwmw→nwmwuat,
vama→vamauat) + DNS resolve + liveness probe. Flags non-prod hosts (classify_env) and ingests every live
host into the graph. Pure helpers unit-tested. **Verified live on nuvamawealth.com: 0→4 non-prod hosts
found deterministically incl. the real `onboardinguat.nuvamawealth.com`** (crt.sh was down; certspotter +
env-brute still delivered). When crt.sh is up, coverage is far higher (vamauat/nwmwuat family).

**Authorization scoping (`authorization.py`):** authorising an apex now authorises its subdomains
(`is_authorized`: subdomain-of-authorised-dotted-apex → allowed). Removes the per-subdomain re-auth friction
that was derailing runs, and lets the enumerator's discovered hosts be scanned immediately. (Bare labels
like `localhost` don't extend — requires a dotted apex.)

**Fleet integration:** `subdomain_enum` is now the FIRST frontier rule (`_rule_subdomain_enum`, apex-only,
top priority 2.0, once per apex via a `subdomains_enumerated` graph marker) + runner `_run_subdomain_enum`
(specialists) + planner READ_KINDS/cost. So EVERY `syber_fleet_run` maps the surface deterministically and
fans scan/crawl/vuln out across all discovered hosts — no LLM luck required. New MCP tool
**`syber_enumerate_subdomains(domain, deep)`**.

**Doctrine rewrite (the LLM-lead consistency lever):** `syber_fleet.sh` SEED + CONTINUE now impose a FIXED
ORDERED methodology (STEP 1 map surface first → prioritise non-prod → STEP 2 fleet_run → STEP 3 per-host:
browser + pull JS bundles for API bases/secrets/more-subdomains + hunt Swagger → STEP 4 parked work → STEP
5 verify → STEP 6 publish/gate) with **hard persistence gates**: a prod WAF 403 is explicitly "NOT a
result / NOT 'secure'" (pivot to non-prod/origin/JS-named APIs); may NOT conclude while any non-prod host is
unexplored or any high-value lead is open. Same doctrine folded into workspace `CLAUDE.md` (surface-first
step 2, WAF-block rule rewritten, enumerate tool registered).

**Verified (host venv, 2026-07-01):** 9 new tests (`tests/fleet/test_subdomains.py` — apex parsing, non-prod
classification incl. nuvama patterns, crt.sh parsing, env-variant brute, **apex→subdomain auth scoping**);
full suite **233 passed** (only the 2 intentionally-reverted stub tests fail — DESTRUCTIVE/`_expand_scope`,
unrelated). `syber_fleet.sh` lints; all changed files compile. **REBUILD REQUIRED** (new module + MCP tool +
fleet rule): `docker compose -f infra/docker-compose.kali.yml build kali`.

### 20. Emailed verifiable reports (Resend) (2026-07-02)
User added `RESEND_API_KEY` and wants the agent to email an engagement report with PROOFS attached, so they
can verify findings are real and forward to the target org. Built:
- **`syber/integrations/resend.py`** — Resend REST client via the shared `http_json` helper (Bearer
  `RESEND_API_KEY`, POST /emails, base64 attachments). `configured()`; actionable error on missing key.
  Default sender `onboarding@resend.dev` (Resend sandbox — only delivers to the account owner's email;
  set `SYBER_REPORT_FROM` to a verified-domain sender to email anyone).
- **`syber/reporting.py`** — `build_and_send(to, target, extra_attachments, subject)`: gathers published
  findings from the in-process findings sink, auto-collects PROOF files from `.investigation_state/evidence/`
  (the data-exposure samples) + any explicit screenshot paths, base64s them (deduped, ext-filtered, capped
  25 files / 15 MB), renders an HTML+text report (severity-sorted findings table + attack chains + evidence
  refs + proof list), emails via Resend. Recipient = `to` or `SYBER_REPORT_TO`.
- **MCP tool `syber_send_report(to, target, attachments, subject)`** (via `_integration`). Doctrine: new
  STEP 7 in `syber_fleet.sh` SEED + CONTINUE (capture screenshots → send_report as the FINAL step, added to
  the don't-conclude gate) and a Reporting entry in workspace `CLAUDE.md`.
- **Wiring:** `RESEND_API_KEY` + `SYBER_REPORT_TO` + `SYBER_REPORT_FROM` added to BOTH `.mcp.json` env
  blocks (workspace + plugin) and documented in `.env.example`. Flows .env → compose env_file → container →
  .mcp.json → MCP server.
- **Verified (host venv, 2026-07-02):** 8 new tests (`tests/integration/test_reporting.py` — client request
  shape, attachment collect/dedupe/cap/b64, render ordering+escaping, build_and_send, recipient-required),
  all pass. All new files compile; both .mcp.json valid; script lints. **REBUILD REQUIRED** (new modules +
  MCP tool): `docker compose -f infra/docker-compose.kali.yml build kali`.

**FULLY-RUNNABLE REPRO + SCREENSHOT-ON-CONFIRM (2026-07-02):** user: the `<YOUR_AUTHORIZATION_HERE>`
placeholder made the curl unusable, and screenshots showed inaccessible pages. Since the report is
operator-locked (SYBER_REPORT_TO), the PoC must be paste-and-run: `save_sample` now stores the REAL request
headers (no redaction) so `curl_for` emits the exact working request; `is_unauthenticated()` flags the
strongest case (no creds → curl runs as-is) and the report/verify.sh label each finding UNAUTHENTICATED vs
"headers included". Screenshots are now captured AT CONFIRMATION: `browser_recon.capture_screenshot(url,path)`
+ `_verify_data_exposure` screenshots ONLY when `is_confirmed` (2xx+real data) into the evidence dir, recorded
as `screenshot` on the evidence JSON and referenced in the report — so the attached image shows the actual
exposed data, never a 403 page. 246 pass; tests updated (real-header curl, is_unauthenticated).

**REPRODUCTION SCRIPTS + PROOF-QUALITY GATE (2026-07-02):** user: agent stops early, ships unconfirmed
findings, and its "proof" screenshots showed inaccessible/403 pages (not vulns) or the browser didn't send
the payload. Fixes:
- `exfil.save_sample` now records the EXACT request (method/url/redacted-headers/transport) + response
  content-type/server + a `confirmed` flag (`is_confirmed()` = 2xx AND REAL_DATA/STRUCTURED). A 401/403/
  blocked/empty capture is `confirmed:false` and can never be presented as a finding.
- New `syber/repro.py`: `curl_for()` builds a faithful copy-pasteable curl from a saved capture (redacted
  auth shown as `<YOUR_..._HERE>`, never faked), `expected_result()`, `reproductions()` splits evidence into
  confirmed vs inaccessible, `build_verify_script()` emits a runnable verify.sh of ONLY confirmed findings.
- `reporting`: report gained a "How to verify (reproduction)" section (curl per confirmed finding) + an
  "Attempts that did NOT confirm (not findings)" list (403s shown honestly, not as vulns); attaches
  **verify.sh**; headline now counts "Reproducible (2xx + real data)". Screenshots are supporting-only.
- Doctrine (syber_fleet.sh STEP 7 + don't-conclude gate): a finding is real ONLY with a CONFIRMED capture
  (syber_verify_data_exposure → 2xx + real data → curl repro); a 403/inaccessible page is NOT proof — send
  the correct payload/headers/auth or drop it; don't ship unconfirmed findings. 245 pass (8 known auth
  fails). New tests: `test_repro.py` + is_confirmed cases.

**RECIPIENT LOCKED TO OPERATOR (2026-07-02):** a run emailed the report to `operator@syber.ai` (a model-
invented address) instead of `.env`'s SYBER_REPORT_TO — because the MCP tool exposed a `to` param and
`build_and_send` did `to or env(...)`, so an agent-supplied `to` OVERRODE the env. Since the report carries
real findings + downloaded PII/secret samples, letting the model pick the destination is a data-exfil risk.
Fixed: recipient now ALWAYS = SYBER_REPORT_TO (operator env); a model-supplied `to` is honoured only if it
exactly matches SYBER_REPORT_TO or SYBER_REPORT_ALLOWED, else refused. Dropped `to` from the `syber_send_report`
MCP signature (passes to=None); doctrine (CLAUDE.md + it already used target= in syber_fleet.sh) says the
recipient is operator-fixed, never invented. Tests updated (operator-env-always + anti-exfil refusal); 239 pass.

**⚠ AUTH REGRESSION (needs a decision):** `authorization.py::is_authorized` is currently
`return True, f"...{self._auths[target].kind}"` (always-allow) — this defeats default-deny AND KeyErrors for
any target not already in `_auths` (crashes the tool instead of a clean refusal). It fails 8 tests
(webapp auth-gating ×4, subdomain auth-scoping ×2, expand_scope, destructive-floor). Flagged to the user;
left unchanged pending their call (clean always-allow vs restore default-deny + the apex→subdomain scoping).

### 21. full_scan timeout right-sizing — stop ~45-min tool calls (2026-07-02)
User hit `syber_full_scan` "stuck" 5+ min (on a WAF'd target, lalpathlabs.com). Root cause: `_env_timeout`
made `SYBER_SCAN_TIMEOUT` (=900 in the container) OVERRIDE even explicitly-passed per-stage timeouts, so
full_scan's 3 stages each ran to 900s ⇒ ~45 min, and a WAF'd target burns the full window for ~0 results.
Fix (`active_scan.py`): new `_resolve_timeout` (explicit caller timeout WINS; env only fills a None default)
+ `_fullscan_budget` (a TOTAL wall-clock budget, `SYBER_FULLSCAN_BUDGET` default 600s, split 40/30/30 across
service/content/vuln) — full_scan is now bounded ~10 min instead of 45. All stage fns switched to
`_resolve_timeout`. Entrypoint defaults lowered: `SYBER_SCAN_TIMEOUT` 900→300 (standalone stage) +
`SYBER_FULLSCAN_BUDGET=600`. Immediate no-rebuild lever: set `SYBER_SCAN_TIMEOUT` lower in .env (compose
env_file passes it; entrypoint's `:-` keeps it). 4 new tests (`tests/integration/test_scan_timeouts.py`);
**239 passed** (same 8 intentional auth-revert failures only). REBUILD to bake in. NOTE (still open, offered
not yet done): the fleet coordinator blocks on `future.result()` with no per-future timeout — a single hung
worker can still stall `syber_fleet_run` past its budget; that's the remaining defense-in-depth fix.

### 22. Robust multi-source subdomain enumeration — kill the crt.sh SPOF (2026-07-02)
crt.sh (the only real source in §19) constantly 502s/rate-limits → runs saw "crt.sh returned empty" and
missed the non-prod cluster. Researched (3 agents: tooling, data sources, community/academic) and
re-architected `syber/scanning/subdomains.py` into a multi-tier, no-single-point-of-failure enumerator
(user chose: passive+validate default, brute opt-in; wire free OTX key):
- **Tier 1** — shell out to **`subfinder`** (~30 passive sources) when installed (`run_subfinder`).
- **Tier 2** — parallel **union of keyless passive sources** (`passive_union`): certspotter, crt.sh(retry),
  hackertarget, urlscan, wayback CDX, + AlienVault OTX when `OTX_API_KEY` set. Each best-effort with a
  browser UA + timeout; one source failing never zeroes coverage.
- **prefix wordlist + base×env twin brute** (kept from §19).
- **Resolve/validate**: **`dnsx`** when installed (fast, wildcard-aware) else stdlib socket (`resolve_hosts`).
- Active DNS brute (puredns/massdns) deliberately NOT default (noisy) — belongs behind an opt-in flag later.
Return dict gained `sources` (per-source hit counts); pure helpers (registrable_apex/classify_env/parse_crtsh/
candidate_hosts/env_variants) unchanged (still tested).

**Wiring:** Dockerfile apt-installs `subfinder dnsx amass massdns puredns`; `OTX_API_KEY` added to both
.mcp.json env blocks + `.env.example`.

**VALIDATED LIVE on nuvamawealth.com (2026-07-02, host):** with **crt.sh DOWN (0 hits) and no OTX key**, the
enumerator returned **34 live subdomains / 14 non-prod — the entire money cluster**: vamauat, vamacug,
nwmwuat, nwstuat, nmwuat1, onboardinguat, nwopmsuat, nwmwcug, nwopmscug, authuat, smallcasesuat, nwuat…
(subfinder 19 + hackertarget 11 + urlscan 8 + wayback 15 unioned; env-variant brute + DNS caught the
`nw*uat`/`*cug` family). The old crt.sh-only path found ZERO of these when crt.sh was down. Full suite
**239 passed** (only the 8 intentional auth-revert failures). REBUILD to bake in the new tools.

Research refs: subfinder/dnsx/amass/puredns/massdns (ProjectDiscovery/OWASP/d3mondev), n0kovo wordlist,
trickest/resolvers, Hadrian Subwiz (nanoGPT subdomain prediction, +~10%), GAN-for-subdomains (ACM SAC 2022
10.1145/3477314.3506967). Passive sources verified live: certspotter/hackertarget/urlscan work keyless;
crt.sh flaky; OTX needs free key (429 unauth); wayback works in-container.

### 23. Depth boosts — "probe more" (thorough profile, ~60min/target) (2026-07-02)
User: agent "isn't probing enough". Root causes found in code: content-discovery used an 81-path builtin
wordlist (seclists omitted from slim image) + only level-1 gobuster (feroxbuster installed but UNUSED);
crawl capped at 40 pages/depth 2; nuclei ran a narrow default; inferred endpoints were returned but never
INGESTED (so injection/IDOR never tested them); subdomain brute was off. User chose ALL boosts + Thorough
(60min+). Applied:
- **content_discovery** → prefers **feroxbuster RECURSIVE** (`SYBER_DISCOVERY_DEPTH=2`, `-C 404..`, JSON
  parse) over gobuster; `_ensure_wordlist` now picks **raft-medium (~30k)** / dirbuster-medium / seclists
  before the 81-path builtin (`SYBER_WORDLIST` override).
- **crawl** defaults raised to **150 pages / depth 3** (`SYBER_CRAWL_PAGES`/`SYBER_CRAWL_DEPTH`); crawl now
  **ingests inferred endpoints** as WebEndpoints → fleet injection/IDOR rules spawn tasks for them.
- **nuclei** → rate-limit 150, `-c 40`, `-fr`, wide `-tags cve,exposure,misconfig,exposed-panels,
  default-login,takeover,sqli,xss,lfi,rce,ssrf,auth-bypass…` (`SYBER_NUCLEI_FULL`).
- **full_scan budget** 600→**1800s** (~30min), split 20/40/40 (service/content/vuln) so content+nuclei get
  the bulk; `MCP_TOOL_TIMEOUT` 30→45min so the harness doesn't kill it mid-scan; `SYBER_SCAN_TIMEOUT` 300→600.
- **Active subdomain brute** ON by default (`run_puredns_brute`, `SYBER_SUBDOMAIN_BRUTE=1`): puredns +
  seclists DNS wordlist + trickest resolvers, wildcard-filtered; empty-safe if tools/lists absent.
- **Dockerfile**: apt-install **seclists** (content + DNS wordlists) + fetch **trickest resolvers.txt** to
  /opt/resolvers.txt. entrypoint exports all the thorough-profile env defaults (all overridable to go faster).
Every knob is env-tunable, so "too slow" → lower SYBER_FULLSCAN_BUDGET / set SYBER_SUBDOMAIN_BRUTE=0 /
SYBER_DISCOVERY_RECURSIVE=0. **239 passed** (only the 8 intentional auth-revert failures); updated my own
timeout tests to the new 1800 default. REBUILD REQUIRED (Dockerfile + new tool usage).

**BUILD FIX (2026-07-02):** adding the enum tools inline to the core apt-get install broke the build on the
user's VM (exit 100 — one of `subfinder dnsx amass massdns puredns seclists` doesn't resolve under that name
in their Kali mirror, likely `puredns`, and a single bad name fails the WHOLE install → took down all core
tools). Split into: CORE install (must succeed) + a BEST-EFFORT loop (`for pkg in …; do apt-get install "$pkg"
|| echo WARN; done`) so a missing/renamed pkg only warns. The Python layer already degrades gracefully for
every one (`_have()` gates subfinder/dnsx/puredns/massdns; `_ensure_wordlist` falls back without seclists).

NOTE (tension acknowledged): §21 cut scan time to fix a 45-min hang; this §23 raises it again for depth per
the user's "thorough" choice. The coordinator per-future-deadline fix (offered, not built) is still the
right way to bound a genuinely-hung worker independent of these depth budgets.

---

### 24. RALPH LOOP — probe until objective coverage = 0 (2026-07-02)
User: loop should run until ALL vulns found — probe every discovered endpoint, subdomain, and network-tab
API. Researched the Ralph technique (ghuntley.com/ralph; Anthropic ralph-wiggum plugin): a loop that re-runs
the agent on fresh context until done, where **completion = an external validation/backpressure signal, NOT
the model's self-report** (models lie "done" to escape). Our bug was exactly that — `syber_fleet.sh` stopped
when the model printed ENGAGEMENT_COMPLETE. Fix = make the stop OBJECTIVE, computed from the attack graph.
- **`syber/fleet/coverage.py`** `engagement_coverage(graph, leads)` → `{complete, remaining[], remaining_count}`
  from durable state: apex not enumerated / host not service-scanned / web host not crawled / parametered
  WebEndpoint not `probed` / open high-value lead. Converges (lead registry owns VERIFIED/EXHAUSTED lifecycle;
  probes mark endpoints `probed`). Pure, 8 tests.
- **`syber/fleet/coverage_cli.py`** (`python -m syber.fleet.coverage_cli --quiet`, exit 0=complete) — the
  loop's INDEPENDENT backpressure, queries the same Neo4j the agent populated.
- **MCP `syber_coverage_status`** — same signal for the in-agent loop; returns the exact `remaining` untested
  assets to work. Registered in CLAUDE.md.
- **Convergence markers:** `graph/model.mark_endpoint_probed`/`mark_vuln_verified`; injection + access-control
  runners mark endpoints `probed`.
- **Network-tab ingestion (the "probe every URL on the network tab" ask):** `browser_recon._har_network_urls`
  harvests EVERY same-site XHR/fetch/API URL from the HAR (was discarding all but the main doc); `recon_site`
  returns `network_endpoints` and `ingest_recon_to_graph` upserts each as a WebEndpoint → coverage tracks them
  → they get probed.
- **`syber_fleet.sh` = true Ralph loop:** MAX_PASSES 6→40 (safety cap, not the stop); after each pass runs
  `coverage_cli` in a throwaway container — stops ONLY when coverage=complete (SYBER_RALPH_STRICT=1 default;
  =0 accepts agent ENGAGEMENT_COMPLETE as fallback). If the agent claims done but coverage shows untested
  surface, it CONTINUES. SEED/CONTINUE tell the agent to drive syber_coverage_status `remaining` to zero.
254 pass (8 known auth-revert fails). REBUILD required (new modules + MCP tool). Security caveats honoured:
scope allowlist + injection guard + rate limiting already in path; MAX_PASSES + teardown are the safety nets.

### 25. Ralph carry-forward — build on prior passes, don't repeat (2026-07-02)
User: across the 40 Ralph passes, carry state forward so a new pass finds NEW things instead of repeating.
What already persisted: the attack graph (Neo4j service stays up across passes) + syber-state volume
(fleet checkpoint, evidence). The gap: the **recall ledger was in-memory** (reset every --rm pass → agent
re-issued identical probes), and nothing summarised prior work into the fresh-context pass. Fixes:
- **Persistent recall ledger** (`scanning/recall.py`): loads/saves `PATHS.state/recall_ledger.json` (in the
  shared state volume) so "already executed (tool,args)" dedup survives across passes; capacity 500→2000;
  `SYBER_RECALL_PATH` override, empty disables. Scoped per-engagement (wiped at teardown → never a stale
  cross-target cache). Atomic write, best-effort.
- **Carry-forward digest** (`fleet/coverage.py::engagement_digest`): markdown for the next pass — prior
  findings, CONFIRMED exposures (from repro), EXHAUSTED leads + why (don't retry), already-executed calls
  (don't repeat), and TOP: the remaining untested surface to work THIS pass. `coverage_cli --digest` prints
  it (exit 0); MCP `syber_engagement_digest` for the in-agent loop.
- **`syber_fleet.sh`** injects the digest into each CONTINUE pass (captured from a throwaway container), so
  every fresh context starts with "here's what's done/found/tried — work only what's left." SEED already
  tells the agent to drive coverage `remaining` to zero.
259 pass (8 known auth-revert fails). REBUILD required. This closes the Ralph loop: durable graph + durable
recall + per-pass digest = each pass provably builds forward instead of redoing the last one.

### 26. Proof discipline: only accessed-data proofs; Ralph=5 + more persistence (2026-07-03)
User's report showed screenshots of LOGIN pages / "Access Denied" — proving nothing ("accessing a login page
is not a vuln; logging in and showing the data IS"). Also wanted Ralph=5 passes + more persistence. (Note:
their report was the OLD pre-rebuild format — image wasn't rebuilt with §23-25.) Fixes:
- **Gated-page detector** (`exfil.is_gated_page`): login/auth-wall / access-denied / WAF / error / empty /
  non-2xx ⇒ not proof (login/denied markers with no logged-in/data markers).
- **capture_screenshot** now (a) takes `cookies` → screenshots the AUTHENTICATED view (the gated data, not the
  login page), and (b) `require_data`: reads the DOM after load and REFUSES to save if it's a login/denied/
  error page. `_verify_data_exposure` passes the finding's cookies + require_data=True.
- **collect_attachments rewritten to confirmed-tied ONLY**: attaches just each CONFIRMED capture's JSON +
  raw body + its data-verified screenshot. **Agent-supplied screenshots are IGNORED** (that was the source of
  the login/403 images) — only system capture-on-confirmation ships; non-image operator files still allowed.
  No confirmed evidence ⇒ no attachments.
- Tool/doctrine: `syber_send_report` proofs are automatic + confirmed-only (don't pass screenshots); fleet
  STEP 7 rewritten: "confirm by ACCESSING the data (log in / pull records); a login page or access-denied is
  NOT a finding."
- **Ralph = 5 passes** (SYBER_MAX_PASSES 40→5, each pass digs deep + carries state fwd). **More persistence**:
  PersistencePolicy.max_revivals 1→3 (SYBER_MAX_REVIVALS), EngagementBudget.max_stall_waves 3→6
  (SYBER_MAX_STALL_WAVES); entrypoint exports both. **Fixed** coverage_cli._load_leads path bug (was
  fleet_checkpoint.json; coordinator writes PATHS.state/fleet/<host>.json) so open leads actually block the
  loop's completion.
263 pass (8 known auth-revert). REBUILD REQUIRED — critically, the user MUST rebuild to get §23-26 at all.

### 27. Auto-rebuild in the engagement scripts (2026-07-03)
User asked "will ./syber_fleet rebuild it" — it did NOT. The scripts only ran `compose up -d` + `compose run
--rm kali`, and `docker compose run` rebuilds ONLY when the image is missing (why an earlier purge auto-built).
Once syber-kali:latest existed, every engagement silently ran STALE code — the root cause of "my fixes aren't
taking effect / old report format." Fixed: `syber_fleet.sh`, `syber_engage.sh`, `syber_session.sh` now
`$COMPOSE build kali` once at startup (before `up -d`), abort on build failure, skip with SYBER_NO_BUILD=1.
Docker layer caching → ~seconds when unchanged. This removes the recurring stale-image footgun; no separate
manual `docker compose build` needed anymore.

### 28. Authenticated testing — 401/403 is the START, not "secure" (2026-07-03)
Regression: on nuvamawealth the agent FOUND the map (`/partner-documentation/` = 73 API pages + auth flows +
sample payloads, `np.*` trading API with 30+ endpoints, documented vendor creds) then declared "auth properly
enforced, secure" on 401s and "Akamai properly blocks" on 403s → 2 LOW findings, COMPLETE. Root causes: (1)
nothing harvested/replayed the publicly-exposed tokens; (2) coverage only required *parametered* endpoints
probed, so auth-header APIs weren't counted; (3) 401/403 counted as "done"; (4) the AgentMail/AgentPhone
identity layer was never driven. Built the authenticated-testing layer:
- **`syber/scanning/credentials.py`** — harvest replayable auth material (JWT/Bearer/Basic/AWS/api-key fields/
  documented user:pass) from any JS/doc/response; persistent engagement-wide store (survives Ralph passes);
  `auth_headers()` emits replay variants incl. the target's CUSTOM header names (appIdKey/jwt/mwAuth/X-API-Key)
  — verified it reproduces nuvama's `appIdKey` header from a JS blob.
- **NEEDS_AUTH lead**: `classify_node` now maps a 401/403 (and any /api/) endpoint → AUTH_BYPASS lead with
  verify kinds `auth_retest, http_verb_tampering, data_extraction`. Coverage counts ALL api endpoints (not
  just parametered) + a new `auth_retest` remaining item for any 401/403 not yet `auth_retested` → the loop
  can't complete while auth-gated endpoints are untested-with-auth.
- **`run_auth_retest`** (verify_runners) + MCP `syber_auth_retest`/`syber_harvest_credentials`/`syber_add_session`:
  replay every harvested token/cred (bounded fan-out) against a 401/403 endpoint; 2xx+real data via exfil →
  CONFIRMED broken-auth/token-reuse (IMPACT). Graph marker `auth_retested` (model.mark_endpoint_auth_retested).
- **JS/doc harvesting in crawl**: every crawled body auto-harvests tokens into the store AND
  `extract_api_paths()` pulls same-site API URLs from JS bundles/API docs → ingested as WebEndpoints (on their
  own host) so documented/JS-referenced APIs (np.* routes) actually get probed + auth-retested.
- **Doctrine**: syber_fleet.sh new STEP 3b "GET AUTHENTICATED then RE-TEST" (harvest tokens → auth_retest
  every 401; AND register real accounts via provision_identity→OTP→login→add_session→retest+IDOR), don't-
  conclude gate requires every 401/403 auth-retested; CLAUDE.md tool list updated. Planner learns auth_retest.
- **Tests**: test_credentials.py (7) + test_auth_retest.py (broken-auth confirm, auth-holds, api-path extract,
  coverage auth-gate) + updated exfil test. **274 pass** (8 known auth-revert). REBUILD required.

### 29. Force authenticated depth; honest terminal (NOT loop-until-critical) (2026-07-03)
Report came back shallow again (Maps key MEDIUM + missing headers LOW, Reproducible=0) — the agent did recon
and never logged in / replayed tokens / tested the documented API. User asked to "loop until it finds a
critical (login / data leak)." DELIBERATELY DID NOT implement literal loop-until-critical (progress §12 anti-
pattern: against a genuinely-secure target it forces fabrication or abuse). Instead forced the *authenticated
depth that actually yields criticals*, with an HONEST terminal:
- **Login-attempt coverage gate** (`coverage._is_login_surface` + gate): if a login/signup/onboarding surface
  exists but no host has a `login_attempted` marker → open `login_attempt` item; the loop can't complete on
  recon of a login page. Cleared by `model.mark_login_attempted` (outcome session|exhausted).
- **MCP**: `syber_add_session` now marks login_attempted(session); new `syber_login_exhausted(host, reason)`
  = honest escape after a genuine failed attempt (no open signup / CAPTCHA / KYC wall).
- **Ralph passes 5→12.** Doctrine (syber_fleet.sh + CLAUDE.md): STEP-3b/gate now require an ACTUAL login
  (provision→register→OTP→add_session) or login_exhausted; "DIG FOR THE REAL BUG — missing headers/Maps key
  are LOW noise, chase IMPACT (IDOR/broken-auth/PII/takeover)"; plus an explicit HONESTY clause — never
  fabricate/inflate to end the loop; a thoroughly-earned "no critical" is a valid success.
- Tests: login-gate coverage test; **275 pass** (8 known auth-revert). REBUILD via ./scripts/syber_fleet.sh
  (auto-builds since §27).
RATIONALE surfaced to user: refused "never stop until critical" (fabrication/abuse risk); delivered "never
stop while authenticated surface is untested" — the legitimate lever. Still LLM-dependent: the actual
register→login form-driving is the model's job (tools all wired); offered a deterministic login runner next.

### 30. Fix the regression: deep-dive to impact, cut FP noise, slim the prompt (2026-07-04)
User: performance regressed — used to get HIGH/CRITICAL, now only LOW noise (Maps key MEDIUM + missing
headers) with high FP rate, and it never deep-dives (finds an API key, doesn't test where it's usable). Two
web-research reports (FP-reduction + escalation playbooks) confirmed the causes + fix:
- **ROOT CAUSE 1: prompt bloat.** The SEED had grown to 1,769 words of process/gates — Anthropic context-eng
  + arXiv 2507.00829 say long checklist prompts make agents dumber/brittle (~40% variance). **Rewrote the SEED
  to ~550 words**: goal + the ONE rule (reachability≠impact; after every discovery ask "what does this
  unlock?" and take the next hop) + a per-finding-type deep-dive line + impact-based severity + honesty. Moved
  mechanics into tools/skill, not prose. CONTINUE slimmed to match.
- **ROOT CAUSE 2: the agent confuses reachability with impact.** Added deterministic **`syber/scanning/apikey.py`
  + MCP `syber_test_api_key`**: tests a Google `AIza…` key against every billable API (geocoding/roads/
  staticmap/streetview…) → unrestricted=finding / REQUEST_DENIED=INFO (handles the referer-bypass nuance).
  Directly fixes the "found key, didn't test it" example. Expanded the **deep-verification skill** with
  escalation playbooks (API key, JWT alg:none/crack/forge, Swagger→BOLA with 2 accounts, .git→use secrets,
  login→ATO, and CHAINING lows into a critical) — the exact next-hop commands.
- **ROOT CAUSE 3: over-suppression + noise.** Per arXiv 2601.22952 (aggressive capping drops real bugs):
  `cap_severity` now (a) treats a CONFIRMED attack-chain step with evidence_refs (output of auth_retest/
  verify_data_exposure) as real exploit evidence so a genuinely-proven HIGH/CRITICAL is NOT capped; (b) forces
  pure-hygiene artefacts (missing headers/public key/banner) to INFO even if marked "confirmed" — kills the
  LOW/MEDIUM noise. Doctrine: severity = demonstrated impact (Bugcrowd VRT/CVSS); report FEW, REAL, proven bugs.
- Tests: test_apikey.py (8: classification + severity over-suppression/hygiene/demote cases). **283 pass**
  (8 known auth-revert). REBUILD via ./scripts/syber_fleet.sh (auto-builds).
NET: fewer, deeper, impact-proven findings; the agent now has both the mandate (lean prompt) and the tools/
playbooks to escalate a discovery instead of filing it as noise. Research: XBOW PoC-oracle, arXiv 2506.10322/
2601.22952/2507.00829, Bugcrowd VRT, KeyHacks/gmapsapiscanner, jwt_tool, git-dumper, PayloadsAllTheThings.

*Bottom line: the platform is built, the Kali image is rebuilt, and every layer is verified
in-container — there is no outstanding build/setup step. §7 (severity/persistence/startup) done;
§11 added the web-app pentest layer (IDOR/BOLA + injection + PTT); §12 added ephemeral teardown
(wipe graph + memory + bus + artefacts when the agent closes); §13 added AgentMail/AgentPhone
identity provisioning (number +17017867337 live) so the agent registers real accounts and runs
authenticated IDOR/BOLA instead of stopping at the unauthenticated surface.*

*Next session — actual engagement testing: run `./scripts/syber_session.sh` (or
`./scripts/syber_engage.sh <target> "<attestation>"`) against an AUTHORISED app that has signup/login
and a known IDOR, and confirm the agent (a) provisions two identities, (b) registers + verifies both
via `syber_check_inbox`/`syber_read_sms`, (c) captures both sessions, (d) confirms the BOLA via
`syber_test_access_control` — i.e. that the false-negative "site is safe" behaviour is actually
gone end-to-end. Optionally set `SYBER_OPERATOR_PHONE` to enable the consensual completion call/SMS.*
