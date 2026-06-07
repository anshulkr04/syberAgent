"""
Per-entity feature engineering (spec section 7.2).

Computes the 15-minute-window feature vector described in the spec. The LSTM
consumes a sequence of 96 consecutive windows (24h); helpers here assemble both
the single vector (iForest / OCSVM) and the sequence (LSTM).
"""
from __future__ import annotations

import numpy as np

from .lstm_autoencoder import time_embedding

# Stable feature ordering so train/score vectors align.
FEATURE_ORDER = [
    "auth_count",
    "auth_success_rate",
    "unique_targets",
    "novel_subnet_flag",
    "off_hours_flag",
    "privileged_ops_count",
    "data_volume_bytes",
    "schema_query_flag",
    "lateral_move_score",
    "hour_of_day",
    "day_of_week",
    "days_since_first_seen",
]

SEQ_LEN = 96  # 24h of 15-minute windows (spec 7.2)


def vectorise(features: dict[str, float]) -> np.ndarray:
    return np.array([float(features.get(k, 0.0)) for k in FEATURE_ORDER], dtype=np.float64)


def with_time_embedding(features: dict[str, float]) -> np.ndarray:
    base = vectorise(features)
    te = time_embedding(int(features.get("hour_of_day", 0)), int(features.get("day_of_week", 0)))
    return np.concatenate([base, te])


def to_sequence(feature_vec: np.ndarray, seq_len: int = SEQ_LEN) -> np.ndarray:
    """Tile a single window into a (seq_len, dim) sequence when full history is
    unavailable (used by the ensemble's LSTM branch, spec 7.5 to_sequence)."""
    return np.tile(feature_vec, (seq_len, 1))
