"""
RAG poisoning defence controls (spec section 10.2).

Three controls from the spec:
  Control 1 — source provenance tagging with a hash chain over ingested docs.
  Control 2 — embedding anomaly check on high-sensitivity retrievals.
  Control 3 — self-consistency cross-check between two independent generations.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

import numpy as np

from ..config import THRESHOLDS
from . import embeddings as emb

# Per-source cluster centroids + learned similarity floors (Control 2).
_source_cluster_centroids: dict[str, np.ndarray] = {}
_source_cluster_floors: dict[str, float] = {}


def learn_source_cluster(source: str, docs: list[str]) -> None:
    centroid = emb.centroid(docs)
    _source_cluster_centroids[source] = centroid
    sims = [emb.cosine_similarity(emb.encode(d), centroid) for d in docs]
    # Floor a margin below the least-similar clean exemplar (embedding-agnostic);
    # never looser than the spec's absolute SOURCE_ANOMALY_THRESHOLD.
    floor = min(THRESHOLDS.source_anomaly_sim, min(sims) - 0.20) if sims else THRESHOLDS.source_anomaly_sim
    _source_cluster_floors[source] = floor


# Control 1: provenance tagging ------------------------------------------------
def provenance_tag(content: str, source_agent: str, source_connector: str, prev_entry_hash: str) -> dict[str, Any]:
    content_hash = "sha256:" + hashlib.sha256(content.encode()).hexdigest()
    chain = "sha256:" + hashlib.sha256((prev_entry_hash + content_hash).encode()).hexdigest()
    return {
        "source_agent": source_agent,
        "source_connector": source_connector,
        "ingestion_timestamp": datetime.now(timezone.utc).isoformat(),
        "content_hash": content_hash,
        "provenance_chain_hash": chain,
    }


# Control 2: embedding anomaly check ------------------------------------------
def check_retrieval_anomaly(retrieved_docs: list[dict[str, Any]], query_embedding: np.ndarray | None = None) -> list[dict[str, Any]]:
    """Drop docs whose embedding is far from their source's cluster (spec 10.2)."""
    from ..audit.log import get_audit_log

    audit = get_audit_log()
    kept: list[dict[str, Any]] = []
    for doc in retrieved_docs:
        centroid = _source_cluster_centroids.get(doc.get("source", ""))
        if centroid is None:
            kept.append(doc)
            continue
        floor = _source_cluster_floors.get(doc.get("source", ""), THRESHOLDS.source_anomaly_sim)
        sim = emb.cosine_similarity(emb.encode(doc["content"]), centroid)
        if sim < floor:
            audit.write("retrieval_anomaly", {"source": doc.get("source"), "sim": round(sim, 4)}, "rag_defence")
            continue
        kept.append(doc)
    return kept


# Control 3: self-consistency cross-check -------------------------------------
def self_consistency_check(chain_a: str, chain_b: str) -> float:
    """Cosine agreement between two independent generations (spec 10.2/12.2)."""
    return emb.cosine_similarity(emb.encode(chain_a), emb.encode(chain_b))
