"""
DeepSeek V4 client (spec section 8).

The spec routes the Claude Agent SDK to DeepSeek through a LiteLLM proxy that
translates the Anthropic wire format to DeepSeek's OpenAI-compatible endpoint.
For a self-contained, runnable platform we talk to DeepSeek directly with the
OpenAI SDK (same OpenAI-compatible endpoint the proxy targets). The LiteLLM
proxy config is still shipped under litellm/ for the SDK deployment path.

This module exposes a thin wrapper that supports:
  - plain completions (used by the self-consistency pair generator, spec 12.2)
  - tool/function calling (the agent loop, spec 3)
  - logprob extraction for calibrated confidence (spec 12.2 S_calibrated)
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import Any

from openai import OpenAI

from ..config import LLM


@dataclass
class LLMResponse:
    text: str
    tool_calls: list[dict[str, Any]]
    finish_reason: str
    raw_message: dict[str, Any]
    logit_confidence: float | None  # mean token probability, when logprobs requested


class DeepSeekClient:
    """OpenAI-compatible client pinned to the DeepSeek endpoint."""

    def __init__(self) -> None:
        self._client = OpenAI(
            api_key=LLM.api_key,
            base_url=LLM.base_url,
            timeout=LLM.request_timeout_s,
            max_retries=LLM.num_retries,
        )

    # ------------------------------------------------------------------ #
    # core call
    # ------------------------------------------------------------------ #
    def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        model: str,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str = "auto",
        temperature: float = 0.2,
        max_tokens: int = 4096,
        want_logprobs: bool = False,
    ) -> LLMResponse:
        resolved = LLM.resolve_model(model)
        kwargs: dict[str, Any] = {
            "model": resolved,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = tool_choice
        # The reasoner tier does not accept logprobs; only request them on the
        # chat tier and degrade gracefully if the provider rejects them.
        logprobs_ok = want_logprobs and "reason" not in resolved
        if logprobs_ok:
            kwargs["logprobs"] = True

        resp = self._with_retry(lambda: self._client.chat.completions.create(**kwargs))
        choice = resp.choices[0]
        msg = choice.message

        tool_calls: list[dict[str, Any]] = []
        for tc in (msg.tool_calls or []):
            tool_calls.append(
                {
                    "id": tc.id,
                    "name": tc.function.name,
                    "arguments": tc.function.arguments,
                }
            )

        confidence = None
        if logprobs_ok and choice.logprobs and choice.logprobs.content:
            probs = [math.exp(t.logprob) for t in choice.logprobs.content if t.logprob is not None]
            if probs:
                confidence = sum(probs) / len(probs)

        # Preserve the exact assistant message so it can be appended to history
        # (tool_calls must round-trip verbatim for the next turn).
        raw_message: dict[str, Any] = {"role": "assistant", "content": msg.content or ""}
        if msg.tool_calls:
            raw_message["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                }
                for tc in msg.tool_calls
            ]

        return LLMResponse(
            text=msg.content or "",
            tool_calls=tool_calls,
            finish_reason=choice.finish_reason or "stop",
            raw_message=raw_message,
            logit_confidence=confidence,
        )

    def complete(self, prompt: str, *, model: str | None = None, temperature: float = 0.2) -> str:
        """Single-shot completion (spec 12.2 generate_finding_pair)."""
        model = model or LLM.orchestrator_model
        resp = self.chat([{"role": "user", "content": prompt}], model=model, temperature=temperature)
        return resp.text

    # ------------------------------------------------------------------ #
    def _with_retry(self, fn):
        last = None
        for attempt in range(LLM.num_retries):
            try:
                return fn()
            except Exception as exc:  # noqa: BLE001 - provider-agnostic backoff
                last = exc
                if attempt == LLM.num_retries - 1:
                    break
                time.sleep(2.0 ** attempt)
        raise RuntimeError(f"DeepSeek request failed after {LLM.num_retries} attempts: {last}")


_singleton: DeepSeekClient | None = None


def get_client() -> DeepSeekClient:
    global _singleton
    if _singleton is None:
        _singleton = DeepSeekClient()
    return _singleton
