"""
Behavioural ensemble (spec section 7.5).

Combines Isolation Forest, LSTM Autoencoder, and One-Class SVM into a single
deviation score in [0,1]. >0.70 => emit an anomaly_detected event (spec 7.5).

Each detector is trained on a synthesised per-entity baseline at bootstrap
(seed_data builds the training matrix). Normalisation ranges are learned from
the training distribution so the three heterogeneous scores are comparable.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from ..config import THRESHOLDS
from . import features as F
from .isolation_forest import IForestDetector
from .lstm_autoencoder import LSTMAutoencoder
from .ocsvm import OCSVMDetector


@dataclass
class EnsembleScore:
    entity_id: str
    score: float
    contributing_models: dict[str, float]
    top_anomalous_features: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "entity_id": self.entity_id,
            "score": round(self.score, 4),
            "contributing_models": {k: round(v, 4) for k, v in self.contributing_models.items()},
            "top_anomalous_features": self.top_anomalous_features,
            "is_anomalous": self.score > THRESHOLDS.anomaly_publish,
        }


class BehaviouralEnsemble:
    def __init__(self) -> None:
        self.iforest = IForestDetector()
        self.ocsvm = OCSVMDetector()
        self.lstm: LSTMAutoencoder | None = None
        self._baseline_mean: np.ndarray | None = None
        self._baseline_std: np.ndarray | None = None
        self.fitted = False

    def fit(self, baseline_matrix: np.ndarray) -> "BehaviouralEnsemble":
        """baseline_matrix: (n_windows, n_features) of normal behaviour."""
        self.iforest.fit(baseline_matrix)
        self.ocsvm.fit(baseline_matrix)
        self.lstm = LSTMAutoencoder(input_dim=baseline_matrix.shape[1])
        seqs = np.stack([F.to_sequence(row) for row in baseline_matrix])
        self.lstm.fit(seqs)
        self._baseline_mean = baseline_matrix.mean(axis=0)
        self._baseline_std = baseline_matrix.std(axis=0) + 1e-9
        self.fitted = True
        return self

    def score(self, entity_id: str, feature_vec: np.ndarray) -> EnsembleScore:
        if not self.fitted:
            raise RuntimeError("ensemble not fitted")
        iforest_norm = _clip(self.iforest.score(feature_vec))
        lstm_norm = _clip(self.lstm.reconstruction_error(F.to_sequence(feature_vec)))
        ocsvm_norm = _clip(self.ocsvm.score(feature_vec))

        w1, w2, w3 = THRESHOLDS.ensemble_weights
        composite = w1 * iforest_norm + w2 * lstm_norm + w3 * ocsvm_norm

        return EnsembleScore(
            entity_id=entity_id,
            score=composite,
            contributing_models={"iforest": iforest_norm, "lstm": lstm_norm, "ocsvm": ocsvm_norm},
            top_anomalous_features=self._top_features(feature_vec),
        )

    def _top_features(self, x: np.ndarray, k: int = 3) -> list[str]:
        if self._baseline_mean is None:
            return []
        z = np.abs((x - self._baseline_mean) / self._baseline_std)
        idx = np.argsort(z)[::-1][:k]
        return [F.FEATURE_ORDER[i] for i in idx if i < len(F.FEATURE_ORDER) and z[i] > 1.0]


def _clip(v: float) -> float:
    return float(min(1.0, max(0.0, v)))


_singleton: BehaviouralEnsemble | None = None


def get_ensemble() -> BehaviouralEnsemble:
    global _singleton
    if _singleton is None:
        _singleton = BehaviouralEnsemble()
    return _singleton
