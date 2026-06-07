"""
Behavioural scoring service (spec section 7 / orchestrator subagent in 3.2).

The spec's behavioural_analytics_agent calls an analytics REST API at
http://analytics-service:8082/score. To keep the platform self-contained we
expose the same scoring as an in-process function (and the optional FastAPI app
below can serve it on :8082 if a real HTTP hop is wanted).

Per-entity feature snapshots are registered by the telemetry pipeline (seed_data
in the demo). score_entity() runs the fitted ensemble over the snapshot.
"""
from __future__ import annotations

from typing import Any

import numpy as np

from . import features as F
from .ensemble import get_ensemble

# entity_id -> latest 15-minute feature dict (spec 7.2)
_entity_features: dict[str, dict[str, float]] = {}


def register_features(entity_id: str, features: dict[str, float]) -> None:
    _entity_features[entity_id] = features


def get_features(entity_id: str) -> dict[str, float] | None:
    return _entity_features.get(entity_id)


def score_entity(entity_id: str) -> dict[str, Any]:
    feats = _entity_features.get(entity_id)
    if feats is None:
        return {"entity_id": entity_id, "error": "no behavioural features registered for entity"}
    vec = F.vectorise(feats)
    result = get_ensemble().score(entity_id, vec)
    return result.to_dict()


def build_training_matrix(rows: list[dict[str, float]]) -> np.ndarray:
    return np.vstack([F.vectorise(r) for r in rows])
