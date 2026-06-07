"""One-Class SVM detector (spec section 7.1) — sparse-entity coverage."""
from __future__ import annotations

import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM


class OCSVMDetector:
    def __init__(self, nu: float = 0.05, gamma: str = "scale"):
        self.model = OneClassSVM(nu=nu, gamma=gamma, kernel="rbf")
        self.scaler = StandardScaler()
        self.fitted = False

    def fit(self, X: np.ndarray) -> "OCSVMDetector":
        Xs = self.scaler.fit_transform(X)
        self.model.fit(Xs)
        self.fitted = True
        return self

    def score(self, x: np.ndarray) -> float:
        """Higher => more anomalous. Maps the signed distance to ~[0,1]."""
        xs = self.scaler.transform(x.reshape(1, -1))
        raw = self.model.decision_function(xs)[0]  # >0 inlier, <0 outlier
        return float(1.0 / (1.0 + np.exp(raw)))     # logistic squashing
