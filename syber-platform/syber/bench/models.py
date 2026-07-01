"""
Provider-agnostic single-shot model runner for the benchmark.

Defaults to the platform's DeepSeek config (OpenAI-compatible). Any other
OpenAI-compatible endpoint can be benchmarked by passing base_url/api_key. Decoding
params default to the CTIBench paper's (temperature=0, top_p=1, seed=42,
max_tokens=2048) for comparable results.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from openai import OpenAI

from ..config import LLM


@dataclass
class ModelRunner:
    model: str = "deepseek-v4-pro"
    temperature: float = 0.0
    top_p: float = 1.0
    seed: int = 42
    max_tokens: int = 2048
    base_url: str | None = None       # defaults to the DeepSeek endpoint
    api_key: str | None = None
    retries: int = 3

    def __post_init__(self) -> None:
        self._client = OpenAI(
            api_key=self.api_key or LLM.api_key,
            base_url=self.base_url or LLM.base_url,
            timeout=LLM.request_timeout_s,
            max_retries=0,            # we retry ourselves with backoff
        )
        self._resolved = LLM.resolve_model(self.model)

    def generate(self, system: str, user: str) -> str:
        kwargs = dict(
            model=self._resolved,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            temperature=self.temperature,
            top_p=self.top_p,
            max_tokens=self.max_tokens,
        )
        # seed is best-effort (DeepSeek/OpenAI support it; harmless if ignored).
        if self.seed is not None:
            kwargs["seed"] = self.seed
        last: Exception | None = None
        for attempt in range(self.retries):
            try:
                resp = self._client.chat.completions.create(**kwargs)
                return resp.choices[0].message.content or ""
            except TypeError:
                # endpoint rejected an unsupported kwarg (e.g. seed) — drop it and retry once
                kwargs.pop("seed", None)
            except Exception as e:  # noqa: BLE001
                last = e
                if attempt < self.retries - 1:
                    time.sleep(2.0 ** attempt)
        raise RuntimeError(f"model call failed after {self.retries} attempts: {last}")
