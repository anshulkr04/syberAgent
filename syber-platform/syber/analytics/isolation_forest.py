"""Isolation Forest detector (spec section 7.3)."""
from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest


class IForestDetector:
    def __init__(self, contamination: float = 0.01, n_estimators: int = 200):
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=42,
            n_jobs=-1,
        )
        self.fitted = False

    def fit(self, X: np.ndarray) -> "IForestDetector":
        self.model.fit(X)
        self.fitted = True
        return self

    def score(self, x: np.ndarray) -> float:
        """Higher => more anomalous, roughly in [0, 1] (spec 7.3)."""
        raw = self.model.decision_function(x.reshape(1, -1))[0]
        offset = self.model.offset_
        denom = (1.0 - offset) or 1e-9
        return float(1.0 - (raw - offset) / denom)
