"""
LSTM Autoencoder for temporal anomaly detection (spec section 7.3).

The spec defines a torch LSTM autoencoder that reconstructs a sequence of 96
15-minute feature vectors; high reconstruction error => sequential anomaly
(auth -> pivot -> exfil patterns iForest misses, spec 7.1).

torch has no Python 3.14 wheel, so this module provides:
  * the exact torch implementation (used automatically if torch is importable),
  * a dependency-free numpy PCA-based sequence reconstructor with the SAME
    `reconstruction_error(sequence) -> float` interface as the fallback.

Both expose reconstruction error normalised against the training distribution.
"""
from __future__ import annotations

import numpy as np

try:  # pragma: no cover - exercised only where torch wheels exist
    import torch
    import torch.nn as nn

    _TORCH = True
except Exception:  # noqa: BLE001
    _TORCH = False


if _TORCH:  # pragma: no cover

    class _TorchLSTMAutoencoder(nn.Module):
        def __init__(self, input_dim: int, hidden_dim: int = 64, num_layers: int = 2):
            super().__init__()
            self.encoder = nn.LSTM(input_dim, hidden_dim, num_layers, batch_first=True)
            self.decoder = nn.LSTM(hidden_dim, input_dim, num_layers, batch_first=True)

        def forward(self, x):
            _, (hidden, _) = self.encoder(x)
            decoder_input = hidden[-1].unsqueeze(1).repeat(1, x.size(1), 1)
            reconstruction, _ = self.decoder(decoder_input)
            return reconstruction


class LSTMAutoencoder:
    """Unified interface over the torch model or the numpy fallback."""

    def __init__(self, input_dim: int, hidden_dim: int = 64, num_layers: int = 2):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self._err_mean = 0.0
        self._err_std = 1.0
        self.fitted = False
        if _TORCH:  # pragma: no cover
            self._net = _TorchLSTMAutoencoder(input_dim, hidden_dim, num_layers)
        else:
            # numpy fallback: flatten the sequence, project onto top-k principal
            # components of the training set, reconstruct, measure residual.
            self._components: np.ndarray | None = None
            self._mean: np.ndarray | None = None

    # ------------------------------------------------------------------ #
    def fit(self, sequences: np.ndarray, epochs: int = 20) -> "LSTMAutoencoder":
        """sequences: (n_samples, seq_len, input_dim)."""
        if _TORCH:  # pragma: no cover
            self._fit_torch(sequences, epochs)
        else:
            self._fit_numpy(sequences)
        errs = np.array([self._raw_error(s) for s in sequences])
        self._err_mean = float(errs.mean())
        self._err_std = float(errs.std() or 1.0)
        self.fitted = True
        return self

    def reconstruction_error(self, sequence: np.ndarray) -> float:
        """Normalised reconstruction error; higher => more anomalous (spec 7.3)."""
        raw = self._raw_error(sequence)
        z = (raw - self._err_mean) / self._err_std
        return float(1.0 / (1.0 + np.exp(-z)))  # logistic -> ~[0,1]

    # ------------------------------------------------------------------ #
    def _raw_error(self, sequence: np.ndarray) -> float:
        if _TORCH:  # pragma: no cover
            x = torch.tensor(sequence[None, ...], dtype=torch.float32)
            with torch.no_grad():
                recon = self._net(x)
                return float(torch.mean((x - recon) ** 2).item())
        flat = sequence.reshape(-1)
        if self._components is None or self._mean is None:
            return float(np.mean(flat ** 2))
        centred = flat - self._mean
        proj = self._components @ centred
        recon = self._components.T @ proj
        return float(np.mean((centred - recon) ** 2))

    def _fit_numpy(self, sequences: np.ndarray) -> None:
        flat = sequences.reshape(sequences.shape[0], -1)
        self._mean = flat.mean(axis=0)
        centred = flat - self._mean
        # top-k principal directions via SVD
        k = min(8, centred.shape[1], max(1, centred.shape[0] - 1))
        _, _, vt = np.linalg.svd(centred, full_matrices=False)
        self._components = vt[:k]

    def _fit_torch(self, sequences: np.ndarray, epochs: int) -> None:  # pragma: no cover
        import torch

        x = torch.tensor(sequences, dtype=torch.float32)
        opt = torch.optim.Adam(self._net.parameters(), lr=1e-3)
        loss_fn = torch.nn.MSELoss()
        self._net.train()
        for _ in range(epochs):
            opt.zero_grad()
            loss = loss_fn(self._net(x), x)
            loss.backward()
            opt.step()
        self._net.eval()


def time_embedding(hour: int, dow: int, dim: int = 8) -> np.ndarray:
    """Sinusoidal temporal positional embedding (spec 7.4)."""
    emb = np.zeros(dim)
    emb[0] = np.sin(2 * np.pi * hour / 24)
    emb[1] = np.cos(2 * np.pi * hour / 24)
    emb[2] = np.sin(2 * np.pi * dow / 7)
    emb[3] = np.cos(2 * np.pi * dow / 7)
    return emb
