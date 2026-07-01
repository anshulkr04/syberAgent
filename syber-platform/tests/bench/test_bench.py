"""Tests for the CTIBench scoring/extraction (pure — no network or LLM)."""
from __future__ import annotations

from syber.bench import scoring


# --- CTI-RCM: CWE extraction + exact-match accuracy ------------------------- #
def test_extract_cwe_prefers_last_line():
    text = "This is a use-after-free.\nThe weakness is memory corruption.\nCWE-416"
    assert scoring.extract_cwe(text) == "CWE-416"


def test_extract_cwe_handles_formatting_variants():
    assert scoring.extract_cwe("Answer: cwe 79") == "CWE-79"
    assert scoring.extract_cwe("final: CWE-0089") == "CWE-89"   # leading zeros normalised
    assert scoring.extract_cwe("no id here") == ""


def test_extract_cwe_falls_back_to_last_mention():
    text = "Could be CWE-20 or CWE-787; I conclude it is the latter."
    assert scoring.extract_cwe(text) == "CWE-787"


def test_score_rcm_exact_match():
    assert scoring.score_rcm("CWE-416", "CWE-416") is True
    assert scoring.score_rcm("CWE-79", "CWE-89") is False
    assert scoring.score_rcm("", "CWE-79") is False
    assert scoring.score_rcm("cwe 79", "CWE-79") is True   # normalised match


# --- CTI-ATE: technique extraction + micro-F1 ------------------------------- #
def test_extract_techniques_base_collapses_subtechniques():
    s = scoring.extract_techniques("We saw T1059.001 and T1071, also t1083.")
    assert s == {"T1059", "T1071", "T1083"}


def test_parse_gt():
    assert scoring.parse_technique_gt("T1071, T1573, T1083, T1070") == {"T1071", "T1573", "T1083", "T1070"}


def test_micro_f1_perfect():
    m = scoring.micro_f1([({"T1059", "T1071"}, {"T1059", "T1071"})])
    assert m.f1 == 1.0 and m.precision == 1.0 and m.recall == 1.0


def test_micro_f1_partial_and_pooled():
    # instance 1: pred {A,B} gt {A}  -> tp1 fp1 fn0
    # instance 2: pred {C}   gt {C,D}-> tp1 fp0 fn1
    pairs = [({"T1001", "T1002"}, {"T1001"}), ({"T1003"}, {"T1003", "T1004"})]
    m = scoring.micro_f1(pairs)
    assert (m.tp, m.fp, m.fn) == (2, 1, 1)
    assert abs(m.precision - 2 / 3) < 1e-9
    assert abs(m.recall - 2 / 3) < 1e-9
    assert abs(m.f1 - 2 / 3) < 1e-9


def test_micro_f1_empty():
    m = scoring.micro_f1([])
    assert m.f1 == 0.0


def test_rcm_result_accuracy():
    r = scoring.RcmResult(total=4, correct=3)
    assert r.accuracy == 0.75
