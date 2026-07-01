"""
syber.bench — external-benchmark harness for benchmarking Syber's LLM/subagents
against published baselines.

Phase 1 (this package): **CTIBench** RCM (CVE→CWE) and ATE (report→ATT&CK techniques)
— per-subagent unit tests for the exposure-analyst (root-cause/CWE reasoning) and the
threat-investigator (technique extraction). Single-shot, zero-shot, scored with the
benchmark's own metrics (exact-match accuracy / micro-F1) so results are directly
comparable to the CTIBench paper table.

Design notes:
  * The dataset's ``Prompt`` column is the *verbatim* paper prompt → using it makes our
    numbers apples-to-apples with the published GPT-4/Gemini/Llama baselines.
  * Decoding params match the paper: temperature=0, top_p=1, seed=42, max_tokens=2048.
  * DeepSeek is called through the platform's own OpenAI-compatible config; the runner
    is provider-agnostic so other OpenAI-compatible endpoints can be added later.
  * CTIBench data is **CC-BY-NC-SA-4.0 (non-commercial)** — cached locally, never
    committed (see .gitignore). Attribution: Alam et al., NeurIPS 2024 (arXiv 2406.07599).
"""
from __future__ import annotations

__all__ = ["datasets", "scoring", "prompts", "models", "baselines"]
