---
description: Show Syber platform backend status (Neo4j / Kafka / Postgres / DeepSeek) and verify audit + memory integrity
---

Report the operational status of the Syber Security Intelligence Platform:

1. Call `mcp__syber-tools__syber_backend_status` and present which backends are active:
   the graph backend (Neo4j vs in-memory), the memory backend (Postgres vs SQLite), the
   bus backend (Kafka vs in-process), and the DeepSeek model in use.

2. Call `mcp__syber-tools__syber_verify_integrity` and report whether the immutable audit
   log hash chain and the memory-store hash chain are intact.

Summarise in a short table. If any real backend shows as a fallback, note that the Docker
stack may be down (`syber-platform/infra/docker-compose.dev.yml`).
