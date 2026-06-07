#!/usr/bin/env bash
# Per-agent Kafka ACL enforcement (spec §4.1). Least privilege per principal.
set -euo pipefail

# Telemetry ingestion agent: write raw_events only
kafka-acls --add --allow-principal User:telemetry-agent --operation Write --topic raw_events

# Context graph agent: read raw_events, write graph_updates
kafka-acls --add --allow-principal User:context-graph-agent --operation Read  --topic raw_events
kafka-acls --add --allow-principal User:context-graph-agent --operation Write --topic graph_updates

# Behavioural analytics agent: read raw_events, write anomaly_detected
kafka-acls --add --allow-principal User:behavioural-agent --operation Read  --topic raw_events
kafka-acls --add --allow-principal User:behavioural-agent --operation Write --topic anomaly_detected

# Threat investigator (Syber LLM): read graph_updates + anomaly_detected, write findings
kafka-acls --add --allow-principal User:threat-investigator --operation Read  --topic graph_updates
kafka-acls --add --allow-principal User:threat-investigator --operation Read  --topic anomaly_detected
kafka-acls --add --allow-principal User:threat-investigator --operation Write --topic findings

# Response orchestrator: read verified_findings only, no write to bus
kafka-acls --add --allow-principal User:response-orchestrator --operation Read --topic verified_findings
