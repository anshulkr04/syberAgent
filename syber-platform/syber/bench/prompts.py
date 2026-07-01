"""
System prompts for the two prompting modes.

  * ``bench``    — the exact CTIBench system prompt (for paper-comparable numbers).
  * ``subagent`` — Syber's exposure-analyst (RCM) / threat-investigator (ATE) persona,
    so we can measure the *subagent* on the same task, not just the raw model. The
    task instruction itself always comes from the dataset's verbatim Prompt column,
    so only the framing differs.
"""
from __future__ import annotations

# CTIBench paper system prompt (evaluation/model-prediction.ipynb), verbatim.
BENCH_SYSTEM = "You are a cybersecurity expert specializing in cyberthreat intelligence."

# Syber subagent personas (concise; aligned to the platform's agent definitions).
SUBAGENT_SYSTEM = {
    "cti_rcm": (
        "You are Syber's exposure analyst. You reason from a vulnerability's technical "
        "description to its underlying software weakness (root-cause mapping to CWE), "
        "disciplined and precise. Answer only with evidence-grounded reasoning and the "
        "single most specific applicable CWE."
    ),
    "cti_ate": (
        "You are Syber's threat investigator. You read threat/malware reports and extract "
        "the adversary behaviours as MITRE ATT&CK techniques, mapping each described "
        "behaviour to its technique id. Be complete but precise — list only techniques the "
        "text supports."
    ),
}


def system_prompt(task: str, mode: str) -> str:
    if mode == "subagent":
        return SUBAGENT_SYSTEM.get(task, BENCH_SYSTEM)
    return BENCH_SYSTEM
