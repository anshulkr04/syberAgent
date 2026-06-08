"""
Session teardown — wipe Syber's OWN data when the agent/container closes.

An engagement leaves data behind: the attack-surface graph in Neo4j, the
hash-chained memory in Postgres, session events in Kafka, and host-side artefacts
(scan authorisations, the audit log, investigation state, browser HARs/screenshots).
For ephemeral, self-cleaning operation we purge all of it on exit.

Scope is deliberately narrow — this only ever touches data Syber created:
  * Neo4j   : MATCH (n) DETACH DELETE n   (the dedicated syber graph DB)
  * Postgres: TRUNCATE memory_store        (the dedicated syber_memory table)
  * Kafka   : best-effort topic delete     (events are regenerable; `down -v` also clears)
  * Host    : the .investigation_state / .audit_log / .memory_store.sqlite /
              .scan_authorization.json under the package root, and this session's
              browser HARs/screenshots in the temp dir (recon-*/crawl-*/pt-* only).

It never deletes broad temp globs or any non-Syber database. Each step is
best-effort (a backend may already be down) and reports what it did.

Invoked automatically by the container entrypoint on exit (SYBER_WIPE_ON_EXIT=1),
and runnable directly:  python -m syber.cleanup   (--keep-host to keep host files).
"""
from __future__ import annotations

import glob
import os
import shutil
import sys
import tempfile
from typing import Any

from .config import PATHS


def purge_neo4j() -> dict[str, Any]:
    """Delete every node/relationship in the Neo4j graph DB (no-op if not configured)."""
    uri = os.environ.get("NEO4J_URI")
    if not uri:
        return {"store": "neo4j", "skipped": "NEO4J_URI not set"}
    try:
        from neo4j import GraphDatabase

        user = os.environ.get("NEO4J_USER", "neo4j")
        pwd = os.environ.get("NEO4J_PASSWORD", "neo4j")
        db = os.environ.get("NEO4J_DATABASE", "neo4j")
        driver = GraphDatabase.driver(uri, auth=(user, pwd))
        try:
            with driver.session(database=db) as s:
                rec = s.run("MATCH (n) DETACH DELETE n RETURN count(n) AS n").single()
                deleted = rec["n"] if rec else 0
        finally:
            driver.close()
        return {"store": "neo4j", "nodes_deleted": deleted}
    except Exception as e:  # noqa: BLE001 - backend may be down already
        return {"store": "neo4j", "error": str(e)}


def purge_postgres() -> dict[str, Any]:
    """Truncate the syber memory_store table (no-op if not configured)."""
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        return {"store": "postgres", "skipped": "DATABASE_URL not set"}
    try:
        import psycopg

        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute("TRUNCATE TABLE memory_store")
        return {"store": "postgres", "truncated": "memory_store"}
    except Exception as e:  # noqa: BLE001
        return {"store": "postgres", "error": str(e)}


def purge_kafka() -> dict[str, Any]:
    """Best-effort delete of Syber's Kafka topics (no-op if not configured)."""
    bootstrap = os.environ.get("KAFKA_BOOTSTRAP")
    if not bootstrap:
        return {"store": "kafka", "skipped": "KAFKA_BOOTSTRAP not set"}
    try:
        from kafka.admin import KafkaAdminClient

        admin = KafkaAdminClient(bootstrap_servers=bootstrap, request_timeout_ms=5000)
        topics = [t for t in admin.list_topics()
                  if t in ("findings", "verified_findings", "security_events", "anomalies")]
        if topics:
            admin.delete_topics(topics)
        admin.close()
        return {"store": "kafka", "topics_deleted": topics}
    except Exception as e:  # noqa: BLE001 - topics auto-recreate; not critical
        return {"store": "kafka", "error": str(e)}


def purge_in_process_graph() -> dict[str, Any]:
    """Clear the in-memory graph singleton (covers the no-backend / fallback case)."""
    try:
        from .graph import store as store_mod

        g = getattr(store_mod, "_graph", None)
        if g is not None and hasattr(g, "g"):
            g.g.clear()
        store_mod._graph = None  # force a fresh empty graph next access
        return {"store": "in_process_graph", "cleared": True}
    except Exception as e:  # noqa: BLE001
        return {"store": "in_process_graph", "error": str(e)}


def purge_host_artifacts() -> dict[str, Any]:
    """Remove Syber's host-side state files and this session's browser artefacts."""
    removed: list[str] = []
    targets = [
        PATHS.state,                              # .investigation_state/
        PATHS.audit,                              # .audit_log
        PATHS.memory_db,                          # .memory_store.sqlite
        PATHS.root / ".scan_authorization.json",  # active-scan allowlist
    ]
    for path in targets:
        try:
            if path.is_dir():
                shutil.rmtree(path, ignore_errors=True)
                removed.append(str(path))
            elif path.exists():
                path.unlink()
                removed.append(str(path))
        except OSError:
            pass
    # Session browser artefacts (our own prefixes only — never a broad temp wipe).
    tmp = tempfile.gettempdir()
    for pat in ("recon-*.har", "recon-*.png", "crawl-*", "pt-*"):
        for f in glob.glob(os.path.join(tmp, pat)):
            try:
                os.remove(f)
                removed.append(f)
            except OSError:
                pass
    return {"store": "host_artifacts", "removed_count": len(removed), "removed": removed}


def purge_all(host_artifacts: bool = True) -> dict[str, Any]:
    """Wipe every Syber data store. Returns a per-store report.

    Order: data stores first, host artefacts last (the audit log is a host
    artefact, so wiping it last keeps the run auditable up to the final moment)."""
    report = {
        "neo4j": purge_neo4j(),
        "postgres": purge_postgres(),
        "kafka": purge_kafka(),
        "in_process_graph": purge_in_process_graph(),
    }
    if host_artifacts:
        report["host_artifacts"] = purge_host_artifacts()
    return report


def main(argv: list[str]) -> int:
    keep_host = "--keep-host" in argv
    quiet = "--quiet" in argv
    report = purge_all(host_artifacts=not keep_host)
    if not quiet:
        import json
        print("[syber] session data purged:", file=sys.stderr)
        print(json.dumps(report, indent=2), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
