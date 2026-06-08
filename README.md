# Syber — Security Intelligence Agent

An autonomous cybersecurity agent. **Claude Code is the harness, DeepSeek V4 (`deepseek-v4-pro`)
is the brain**, and it runs inside a **Kali Linux** container with a full offensive toolchain
(nmap, nikto, gobuster, ffuf, nuclei, masscan) and a real **browser** (`agent-browser`). It does
active scanning of authorised targets, passive web recon, attack-path graph analysis in **Neo4j**,
and assembles MITRE-mapped findings gated by a composite evidence score — hardened against
prompt-injection / RAG-poisoning / memory-poisoning.

> The model runs on DeepSeek's servers via your API key. Nothing is hosted locally; there is no
> LiteLLM proxy. Claude Code talks straight to DeepSeek's Anthropic-compatible endpoint.

This is an operator's guide. For internals and the spec→code map, see
[`syber-platform/README.md`](syber-platform/README.md).

---

## 1. Prerequisites

- **Docker Desktop** running.
- A DeepSeek API key in **`.env`** at this directory:
  ```
  DEEPSEEK_API_KEY=sk-...
  ```
  (Already present in this repo.)

That's all you need for the recommended (container) path. The host Python venv (`.venv/`) is only
for running the CLI demos without Docker (section 5).

---

## 2. Start the agent (recommended: inside Kali)

```bash
cd syber-platform

# a) start the backends (Neo4j graph, Postgres memory, Kafka bus)
docker compose -f infra/docker-compose.kali.yml up -d neo4j postgres kafka

# b) build the Kali agent image (first time only) ...
docker compose -f infra/docker-compose.kali.yml build kali
#    ... or load the pre-packaged image instead of building:
#    docker load -i ~/syber-dist/syber-kali-image.tar.gz

# c) open Claude Code inside Kali (this drops you into the agent)
docker compose -f infra/docker-compose.kali.yml run --rm kali
```

Claude Code opens already wired to DeepSeek V4, **with permission prompts disabled** (the
container is the sandbox), and with the scanners + browser on `PATH`. You can just talk to it.

To stop the backends when done: `docker compose -f infra/docker-compose.kali.yml down`.

---

## 3. What to do once it's open

Type natural language, or use the slash commands. Examples:

| Goal | Do this |
|---|---|
| **Active scan** a host you control | `/syber-scan scanme.nmap.org` |
| **Browser recon** of a website | `/syber-recon example.com` (real Chrome, **never curl**) |
| **Browse / test** a web app | `open https://example.com and snapshot the page`, then ask it to click/fill/screenshot |
| **Seeded investigation** demo | `/syber-investigate demo` |
| **Check status / integrity** | `/syber-status` |

> All web interaction goes through a **real browser** (`agent-browser` + Chrome) — genuine TLS
> fingerprint and User-Agent, JavaScript rendered — so targets don't flag it as a bot. The agent
> is instructed never to use `curl`/`wget`/`urllib` for web content. Scans and recon ingest into a
> rich **Neo4j attack-surface graph** (hosts · services · technologies · web endpoints · vulns ·
> certificates · findings, with risk scoring); `syber_get_graph_context` reads it back.

A typical engagement: authorise a target → `/syber-scan` it → the agent ingests the open
ports/services/vulns into Neo4j → it opens the discovered web service in the browser to inspect
it → it publishes a finding and runs the evidence-score gate.

### Authorising a scan target (required)
Active scanning is **default-deny**. `scanme.nmap.org` and `localhost` are pre-authorised for
testing. For your own targets, authorise first — the agent will do this when you confirm you
control the target, e.g.:

> "I own `app.mycorp.com` and authorise testing it. Scan it."

It records an attestation, then scans. It will **refuse** any target you haven't authorised.

---

## 4. What's running (backends)

| Service | Role | Where |
|---|---|---|
| Neo4j | attack-path knowledge graph (hosts, ports, services, vulns) | `bolt://localhost:7687` — browser UI at http://localhost:7474 (neo4j / changeme) |
| Postgres | append-only, hash-chained agent memory | `localhost:5432` |
| Kafka | event bus (anomalies, findings) | `localhost:9092` |
| DeepSeek V4 | the LLM (`deepseek-v4-pro`) | DeepSeek API |

The agent **falls back** to in-process equivalents if a backend is down, so it never hard-crashes
on a backend outage.

---

## 5. Running without Docker (CLI demos)

To try the capabilities directly from the host (uses the same DeepSeek key):

```bash
cd syber-platform
source ../.venv/bin/activate        # repo ships a ready venv

python -m syber.scanning.demo scanme.nmap.org 22,80   # scan -> graph -> DeepSeek finding
python -m syber.recon.demo example.com                # passive recon -> finding
python -m syber.demo                                  # seeded data-lake investigation
python -m pytest tests -q                             # test suite (no LLM spend)
```

For scanning your own target from the host, pass an attestation as the 3rd arg:
```bash
python -m syber.scanning.demo app.mycorp.com 1-1000 "I own and am authorised to test app.mycorp.com"
```

To drive Claude Code on DeepSeek from the host (no container):
```bash
./scripts/run_syber_claude.sh
```

---

## 6. Safety & scope

- **Authorised targets only.** Active scanning refuses anything not explicitly authorised. Keep
  it to assets you own or have written permission to test. Recon (`/syber-recon`) is passive.
- **Proportionate findings.** The agent rates severity to what it actually finds (open SSH is not
  CRITICAL; an exposed `/.git` or an unauthenticated RCE is).
- **Untrusted data.** Scanned/retrieved content is treated as untrusted — the agent will not
  follow instructions embedded in a target's responses (StruQ dual-channel + injection filter).
- The container runs with permission prompts off **because it is the isolation boundary**. Don't
  point it at production assets you don't control.

---

## 7. Troubleshooting

| Symptom | Fix |
|---|---|
| `DEEPSEEK_API_KEY not set` | Ensure `.env` has the key at the repo root. |
| Port conflict on 7687/5432/9092 | Only run **one** stack. `docker compose -f infra/docker-compose.dev.yml down` before using the Kali stack (and vice-versa). |
| Scan says "not authorized" | Authorise the target first (section 3). Expected for any non-pre-authorised host. |
| Browser won't open in container | The Kali compose already grants `SYS_ADMIN` + `shm_size:1gb` for Chrome; rebuild if you changed it. |
| Backends show as in-process in `/syber-status` | The Docker stack isn't up — `docker compose -f infra/docker-compose.kali.yml up -d neo4j postgres kafka`. |

---

## Layout

```
syberAgent/
├── .env                     # DEEPSEEK_API_KEY
├── spec.md                  # the product specification (v3.0)
├── syber-platform/          # the platform: package, scanners, MCP server, infra, tests
│   ├── syber/               # python package (graph, harness, analytics, scanning, recon, scoring)
│   ├── infra/kali/          # Kali Dockerfile + baked Claude Code workspace
│   ├── infra/docker-compose.kali.yml
└── claude-code/             # Claude Code plugin marketplace (the `syber` plugin lives here)
```
