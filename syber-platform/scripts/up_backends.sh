#!/usr/bin/env bash
# Bring up the real backends (Neo4j, Kafka, Postgres) and print the env vars that
# switch the platform onto them. Requires Docker Desktop to be running.
#
#   ./scripts/up_backends.sh        # start services + apply Neo4j schema
#   source <(./scripts/up_backends.sh --env)   # just print/export the env vars
set -euo pipefail
cd "$(dirname "$0")/.."

ENV_LINES=$(cat <<'EOF'
export NEO4J_URI=bolt://localhost:7687
export NEO4J_USER=neo4j
export NEO4J_PASSWORD=changeme
export KAFKA_BOOTSTRAP=localhost:9092
export DATABASE_URL=postgresql://postgres:changeme@localhost:5432/syber_memory
EOF
)

if [[ "${1:-}" == "--env" ]]; then
  echo "$ENV_LINES"
  exit 0
fi

if ! docker info >/dev/null 2>&1; then
  echo "ERROR: Docker daemon is not running. Start Docker Desktop first." >&2
  exit 1
fi

echo ">> starting kafka, neo4j, postgres (litellm optional)…"
docker compose -f infra_docker-compose.yml up -d kafka neo4j postgres

echo ">> waiting for Neo4j to accept bolt connections…"
for i in $(seq 1 60); do
  if docker compose -f infra_docker-compose.yml exec -T neo4j \
       cypher-shell -u neo4j -p changeme "RETURN 1;" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

echo ">> applying Neo4j schema + RBAC (graph_cypher/schema.cypher)…"
docker compose -f infra_docker-compose.yml exec -T neo4j \
  cypher-shell -u neo4j -p changeme < graph_cypher/schema.cypher || true

echo ">> Kafka topics are created automatically on first publish (bus_config/topics.yaml)."
echo ""
echo ">> Done. Export these to switch the platform onto the real backends:"
echo "$ENV_LINES"
echo ""
echo "Then run:  source <(./scripts/up_backends.sh --env) && python -m syber.demo"
