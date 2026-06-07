"""
Platt scaler calibration (spec section 12.3).

Fits a logistic regression mapping a raw LLM confidence signal to a calibrated
probability, addressing softmax overconfidence (spec 12.1). Persists the fitted
scaler and reports ECE if netcal is available.
"""
from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression

from ...config import PATHS

SCALER_PATH = PATHS.calibration / "platt_scaler.joblib"


def fit_platt_scaler(validation_logits: list[float], labels: list[int], out_path: Path | None = None) -> LogisticRegression:
    out_path = out_path or SCALER_PATH
    out_path.parent.mkdir(parents=True, exist_ok=True)
    X = np.array(validation_logits).reshape(-1, 1)
    platt = LogisticRegression()
    platt.fit(X, labels)
    joblib.dump(platt, out_path)
    try:  # pragma: no cover - optional dependency
        from netcal.metrics import ECE

        ece = ECE(15)
        score = ece.measure(platt.predict_proba(X)[:, 1], np.array(labels))
        print(f"ECE after Platt scaling: {score:.4f}")
    except Exception:  # noqa: BLE001
        pass
    return platt


def load_scaler(path: Path | None = None) -> LogisticRegression:
    """Load the fitted scaler, or synthesise a reasonable default.

    The default is fitted on a small synthetic monotone set so the platform is
    usable before a labelled validation set exists (spec 12.3 expects 2,400
    labelled scenarios in production).
    """
    path = path or SCALER_PATH
    if path.exists():
        return joblib.load(path)
    rng = np.random.default_rng(42)
    logits = np.linspace(0.0, 1.0, 200)
    # Correctness rises with confidence but with realistic slack (overconfidence).
    labels = (rng.random(200) < (0.15 + 0.7 * logits)).astype(int)
    return fit_platt_scaler(list(logits), list(labels), out_path=path)


if __name__ == "__main__":  # bootstrap a default scaler
    load_scaler()
    print(f"Platt scaler written to {SCALER_PATH}")
