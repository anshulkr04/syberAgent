"""
Seed scenario: SVC-API-07 service-account credential compromise.

Built from the CSIM example in the spec (section 5.2). It populates:
  * the knowledge graph (identities, assets, a CII crown jewel, attack edges),
  * the Security Data Lake (a forensic event trail with distinct evidence_refs),
  * the behavioural ensemble (normal baseline + an anomalous feature snapshot).

The resulting trigger drives a live DeepSeek investigation that should recover
the chain: Valid Accounts (T1078) -> Remote Services (T1021) -> Data from
Information Repositories (T1213) -> Exfiltration Over C2 (T1041).
"""
from __future__ import annotations

import random
from typing import Any

from .analytics.ensemble import get_ensemble
from .analytics.service import build_training_matrix, register_features
from .data_lake import get_data_lake
from .graph.store import get_graph
from .harness import rag_defence, ti_integrity
from .tools.scope_guard import InvestigationScope

ACTOR = "SVC-API-07@dubaipolice.ae"
DB = "192.168.14.23"            # srv-db-prod-01
CII = "10.0.99.5"              # crown-jewel CII asset
ATTACKER_IP = "192.168.14.88"  # novel source subnet


# --------------------------------------------------------------------------- #
def seed_graph() -> None:
    g = get_graph()
    g.add_node(ACTOR, "Identity", principal_name="SVC-API-07", identity_type="service",
               department="api_platform", mfa_enabled=False)
    g.add_node(DB, "Asset", hostname="srv-db-prod-01", ip=DB, asset_class="database",
               criticality="CII", os="linux", patch_level="n-2")
    g.add_node(CII, "Asset", hostname="srv-cii-core-01", ip=CII, asset_class="identity_infrastructure",
               criticality="CII", os="linux", patch_level="current")
    g.add_node("192.168.14.0/24", "NetworkSegment", name="prod-app", zone_type="internal",
               internet_facing=False)
    g.add_node("CVE-2026-30000", "Vulnerability", cve_id="CVE-2026-30000", cvss_base=9.1,
               cvss_exploitability=3.9, patch_available=True)

    # Access + reachability edges (lower weight => easier / preferred path).
    g.add_edge(ACTOR, DB, "HAS_ACCESS", edge_weight=1.0, permission_level="read_write", method="api_key")
    g.add_edge(DB, CII, "REACHABLE_FROM", edge_weight=1.5, protocol="tcp", port=389, authenticated_required=True)
    g.add_edge(ACTOR, CII, "HAS_ACCESS", edge_weight=4.0, permission_level="read", method="inherited")
    g.add_edge(DB, "192.168.14.0/24", "BELONGS_TO", edge_weight=0.1)
    g.add_edge(DB, "CVE-2026-30000", "HAS_VULN", edge_weight=0.5, exploitability_score=3.9, weaponised=True)


# --------------------------------------------------------------------------- #
def seed_data_lake() -> None:
    dl = get_data_lake()
    base = "2026-06-03T02:"
    events: list[dict[str, Any]] = [
        _ev("EV-0001", "authentication", "interactive_logon", f"{base}14:33.441Z", ACTOR, DB,
            ATTACKER_IP, "success", ["off_hours", "novel_source_subnet"],
            note="First interactive logon ever observed for this service account"),
        _ev("EV-0002", "authentication", "token_request", f"{base}15:02.110Z", ACTOR, DB,
            ATTACKER_IP, "success", ["off_hours"],
            note="OAuth token minted with elevated db_admin scope"),
        _ev("EV-0003", "lateral_movement", "remote_service", f"{base}17:48.900Z", ACTOR, DB,
            ATTACKER_IP, "success", ["novel_source_subnet"],
            note="SSH session opened to srv-db-prod-01 from non-platform host"),
        _ev("EV-0004", "discovery", "schema_query", f"{base}19:20.005Z", ACTOR, DB,
            ATTACKER_IP, "success", [],
            note="information_schema enumeration: 412 tables listed"),
        _ev("EV-0005", "collection", "bulk_read", f"{base}24:51.700Z", ACTOR, DB,
            ATTACKER_IP, "success", ["large_data_volume"],
            note="SELECT * across citizen_records; 2.3 GB read"),
        _ev("EV-0006", "exfiltration", "egress_transfer", f"{base}31:12.300Z", ACTOR, CII,
            ATTACKER_IP, "success", ["large_data_volume", "novel_destination"],
            note="2.1 GB outbound to external endpoint over TLS"),
        # Corroborating events from the target's perspective (distinct refs).
        _ev("EV-0101", "authentication", "session_open", f"{base}17:49.010Z", DB, DB,
            ATTACKER_IP, "success", [], note="sshd accepted publickey for svc-api-07"),
        _ev("EV-0102", "data_access", "query_executed", f"{base}25:01.220Z", DB, DB,
            ATTACKER_IP, "success", ["large_result_set"], note="DB audit: 2.3 GB result set returned"),
    ]
    dl.bulk_ingest(events)


def _ev(eid, klass, subclass, ts, actor, target, src_ip, outcome, risk, note=""):
    target_host = {DB: "srv-db-prod-01", CII: "srv-cii-core-01"}.get(target, "")
    return {
        "csim_version": "1.0",
        "event_class": klass,
        "event_subclass": subclass,
        "timestamp_utc": ts,
        "source_connector": "azure_ad_signin" if klass == "authentication" else "ebpf_collector",
        "event_id": eid,
        "entity": {"type": "identity" if actor == ACTOR else "asset", "id": actor, "display_name": actor.split("@")[0]},
        "target_resource": {"type": "asset", "id": target, "hostname": target_host},
        "source_ip": src_ip,
        "outcome": outcome,
        "risk_indicators": risk,
        "raw_ref": f"sha256:{eid}",
        "note": note,
    }


# --------------------------------------------------------------------------- #
def seed_behavioural_ensemble() -> None:
    """Train the ensemble on a normal baseline, then register the anomaly."""
    rng = random.Random(42)
    baseline_rows: list[dict[str, float]] = []
    for _ in range(400):
        baseline_rows.append({
            "auth_count": rng.randint(2, 8),
            "auth_success_rate": rng.uniform(0.97, 1.0),
            "unique_targets": rng.randint(1, 2),
            "novel_subnet_flag": 0,
            "off_hours_flag": 0,
            "privileged_ops_count": rng.randint(0, 1),
            "data_volume_bytes": rng.uniform(1e4, 5e5),
            "schema_query_flag": 0,
            "lateral_move_score": rng.uniform(0.0, 0.15),
            "hour_of_day": rng.randint(8, 18),
            "day_of_week": rng.randint(0, 4),
            "days_since_first_seen": rng.randint(120, 400),
        })
    get_ensemble().fit(build_training_matrix(baseline_rows))

    # The compromise window's feature snapshot for SVC-API-07 (clearly anomalous).
    register_features(ACTOR, {
        "auth_count": 9,
        "auth_success_rate": 1.0,
        "unique_targets": 6,
        "novel_subnet_flag": 1,
        "off_hours_flag": 1,
        "privileged_ops_count": 7,
        "data_volume_bytes": 2.3e9,
        "schema_query_flag": 1,
        "lateral_move_score": 0.92,
        "hour_of_day": 2,
        "day_of_week": 2,
        "days_since_first_seen": 365,
    })


# --------------------------------------------------------------------------- #
def seed_ti_baselines() -> None:
    """Teach the TI/RAG defences what each source's clean output looks like."""
    clean_ti = [
        "indicator malicious ip address command and control beacon observed",
        "malware hash sha256 trojan dropper persistence registry run key",
        "phishing domain credential harvest office365 lookalike typosquat",
        "cve remote code execution unauthenticated exploit in the wild patch",
    ]
    ti_integrity.learn_source_centroid("misp_feed", clean_ti)
    rag_defence.learn_source_cluster("misp_feed", clean_ti)


# --------------------------------------------------------------------------- #
def build_scenario() -> tuple[dict[str, Any], InvestigationScope]:
    seed_graph()
    seed_data_lake()
    seed_behavioural_ensemble()
    seed_ti_baselines()

    trigger_event = {
        "event_type": "anomaly_detected",
        "entity_id": ACTOR,
        "anomaly_score": 0.0,  # filled by the ensemble at runtime in the demo
        "timestamp_utc": "2026-06-03T02:14:33.441Z",
        "summary": "Off-hours interactive logon by a service account from a novel subnet.",
    }
    scope = InvestigationScope(
        investigation_id="INV-2026-0603-001",
        allowed_entities={ACTOR, DB, CII},
        time_start_utc="2026-06-03T02:00:00Z",
        time_end_utc="2026-06-03T03:00:00Z",
    )
    return trigger_event, scope
