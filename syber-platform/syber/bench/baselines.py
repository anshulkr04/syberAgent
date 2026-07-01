"""
Published CTIBench baselines (Alam et al., NeurIPS 2024 — arXiv 2406.07599, Table).
Used only for side-by-side reporting. RCM = accuracy; ATE = micro-F1.
The original paper evaluated no Claude/DeepSeek baseline — so our DeepSeek numbers
are a novel datapoint against this set.
"""
from __future__ import annotations

# model -> {"cti_rcm": accuracy, "cti_ate": micro_f1}
PUBLISHED = {
    "GPT-4 (paper)":        {"cti_rcm": 0.720, "cti_ate": 0.6388},
    "GPT-3.5 (paper)":      {"cti_rcm": 0.672, "cti_ate": 0.3108},
    "Gemini-1.5 (paper)":   {"cti_rcm": 0.666, "cti_ate": 0.4612},
    "LLAMA3-70B (paper)":   {"cti_rcm": 0.659, "cti_ate": 0.4720},
    "LLAMA3-8B (paper)":    {"cti_rcm": 0.447, "cti_ate": 0.1562},
}

METRIC = {"cti_rcm": "accuracy", "cti_ate": "micro_f1"}
