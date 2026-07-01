# syber.bench — external benchmark harness

Benchmarks Syber's LLM (DeepSeek-v4-pro by default) and subagent personas against
published cybersecurity-LLM baselines.

## Phase 1 — CTIBench (implemented)

Two tasks, used as **per-subagent unit tests**:

| Task | Maps to subagent | Input → Output | Metric | Size |
|---|---|---|---|---|
| `cti_rcm` | exposure-analyst | CVE description → CWE id | exact-match accuracy | 1000 |
| `cti_ate` | threat-investigator | threat report → set of ATT&CK technique ids | micro-F1 | 60 |

The dataset's `Prompt` column is the **verbatim** CTIBench prompt, and decoding params
match the paper (temperature=0, top_p=1, seed=42, max_tokens=2048), so our numbers are
directly comparable to the published GPT-4 / GPT-3.5 / Gemini-1.5 / Llama-3 table
(`baselines.py`). The original paper evaluated no DeepSeek/Claude — so our run is a
novel datapoint against that set.

### Run

```bash
# full run, both tasks, against DeepSeek-v4-pro (the platform default)
python -m syber.bench.run --task all --workers 10

# single task / smoke / a different model id on the same endpoint
python -m syber.bench.run --task cti_rcm --limit 50
python -m syber.bench.run --task cti_ate --model deepseek-v4-flash

# subagent-persona framing instead of the bench-faithful system prompt
python -m syber.bench.run --task all --prompt subagent
```

Results (per-example details + the comparison table) are written to
`.bench_results/ctibench-<model>-<prompt>-<ts>.json`. Requires `DEEPSEEK_API_KEY` in
`.env` (auto-loaded by `config.py`).

### `--prompt` modes
- `bench` (default): the exact CTIBench system prompt → paper-comparable.
- `subagent`: Syber's exposure-analyst (RCM) / threat-investigator (ATE) persona, to
  measure the *subagent* on the same task. The task instruction is identical; only the
  framing changes.

### Adding another OpenAI-compatible model
`ModelRunner(model=..., base_url=..., api_key=...)` — point at any OpenAI-compatible
endpoint. (We currently run DeepSeek only; comparators are cited from the paper.)

## Licensing / attribution
CTIBench data is **CC-BY-NC-SA-4.0 (non-commercial)** — cached under `.bench_cache/`,
never committed. Cite: *Alam, Bhusal, Nguyen, Rastogi — "CTIBench", NeurIPS 2024
(arXiv 2406.07599)*. Numbers feeding a commercial deliverable must respect the NC terms.

## Roadmap
- **Phase 2 — ExCyTIn-Bench** (`microsoft/SecRL`, MIT): the agentic SQL-investigation
  eval — the primary "does the multi-agent pipeline investigate correctly" signal.
  Model-only run first (DeepSeek as agent + DeepSeek-as-judge, documented), then a
  Syber-pipeline adapter. Its failure modes (premature submission, stopping early,
  over-reliance on alerts) are what the CES gate targets.
- **CES correlation study** (the CAIBench knowledge-vs-capability idea): record Syber's
  CES per investigation and show low CES correlates with ExCyTIn multi-step failures.
