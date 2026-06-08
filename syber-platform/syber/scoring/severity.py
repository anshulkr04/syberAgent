"""
Severity discipline — reduce LLM false positives in security findings.

LLMs over-rate severity: they are risk-averse and their pretraining is skewed
toward high-impact vulnerabilities, so they inflate (e.g. flagging a *public*
key as CRITICAL). Mitigations here follow the literature:

  * SSVC-style decomposition: derive severity from exploitability x exposure x
    impact rather than asking "is it critical?" directly.
    (Prompting the Priorities, arXiv:2510.18508)
  * Negative exemplars: an explicit "this is NOT a vulnerability" list.
    (Chain-of-thought / few-shot-with-explanations reduce over-rating.)
  * Allow INFO/Informational so the model isn't forced to inflate.
  * Exploitability gating: HIGH/CRITICAL require concrete exploitability evidence;
    otherwise cap. This is a deterministic safety net under the prompt guidance.

Used by the prompts (injected guidance) AND enforced in code (cap_severity).
"""
from __future__ import annotations

import re
from typing import Any

SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# Injected into every analysis prompt. Keep it tight and exemplar-driven.
SEVERITY_RUBRIC = """\
SEVERITY DISCIPLINE (assign severity by EVIDENCE, not by instinct — LLMs over-rate):

Decompose before rating. Assess each dimension, THEN derive severity:
  - Exploitability: is there a concrete, demonstrated way to exploit this here and now?
    (none / theoretical / known-exploit-for-this-exact-version / confirmed-PoC)
  - Exposure: is it internet-reachable and unauthenticated?
  - Impact: would exploiting it actually compromise confidentiality/integrity/availability?

Severity mapping:
  CRITICAL = confirmed exploitability + unauthenticated exposure + high impact
             (e.g. unauthenticated RCE, exposed admin with default creds, leaked live secret/.env/.git contents).
  HIGH     = strong exploitability evidence (known exploit for the exact running version,
             confirmed weak/default credentials, exposed sensitive data) with real impact.
  MEDIUM   = a real weakness with a plausible but unproven exploit path, or auth/preconditions required.
  LOW      = hardening gaps with limited direct impact (missing security headers, weak TLS config,
             verbose error pages, outdated-but-not-known-exploitable versions).
  INFO     = observations that are normal or not weaknesses (see NOT-A-FINDING below).

Do NOT assign HIGH/CRITICAL without concrete exploitability evidence. When unsure, say so and
rate LOWER (prefer INFO/LOW). It is better to under-rate than to cry wolf.

NOT A FINDING (rate INFO, or omit) — these are normal/expected, NOT vulnerabilities:
  - PUBLIC KEYS of any kind: TLS certificate public keys, SSH host public keys, published PGP
    public keys. Public keys are MEANT to be public — never a vulnerability on their own.
  - Software/version/server banners disclosed (e.g. "Server: nginx 1.18") — INFO, not a vuln by itself.
  - A valid TLS certificate, or TLS 1.2/1.3 in use.
  - Open ports running patched, current services with no known exploit.
  - Standard files served as intended: robots.txt, sitemap.xml, favicon, public /.well-known/.
  - Missing security headers (HSTS/CSP/X-Frame-Options) — LOW at most, not HIGH/CRITICAL.
  - Directory listing of clearly public/static assets.
A real finding needs an actual weakness with impact — not merely the presence of a normal artefact.
"""

# Signals that justify HIGH/CRITICAL (presence of real exploitability/impact).
_EXPLOIT_SIGNALS = [
    r"\brce\b", r"remote code execution", r"unauthenticated\s+(rce|access|admin|exec)",
    r"default\s+credential", r"weak\s+credential", r"credential\s+stuffing", r"brute[- ]?forc",
    r"exposed\s+(\.env|\.git|secret|api[ _-]?key|private\s+key|password|credential|token)",
    r"sql\s*injection", r"\bxxe\b", r"\bssrf\b", r"path\s+traversal", r"directory\s+traversal",
    r"deserializ", r"command\s+injection", r"auth(entication)?\s+bypass", r"privilege\s+escalation",
    r"known\s+exploit", r"exploit\s+available", r"poc\b", r"actively\s+exploited", r"in\s+the\s+wild",
    r"arbitrary\s+(file|code)\s+(read|write|exec)", r"takeover",
]
_EXPLOIT_RX = re.compile("|".join(_EXPLOIT_SIGNALS), re.IGNORECASE)

# Signals that a finding is about a benign/public artefact (force INFO/LOW).
_BENIGN_RX = re.compile(
    r"public\s+key|host\s+key|ssh-?rsa|ssh-?ed25519|certificate\s+public|pgp\s+public|"
    r"version\s+(disclosure|banner)|server\s+banner|banner\s+disclosure|"
    r"missing\s+(hsts|csp|security\s+header|x-frame)|robots\.txt|sitemap\.xml|favicon",
    re.IGNORECASE,
)


def _finding_text(finding: dict[str, Any]) -> str:
    parts = [str(finding.get("summary", ""))]
    for step in finding.get("attack_chain", []) or []:
        parts.append(str(step.get("description", "")))
        parts.append(str(step.get("mitre_technique", "")))
    parts.extend(map(str, finding.get("evidence_refs", []) or []))
    parts.append(str(finding.get("exploitability", "")))
    return " \n ".join(parts)


def cap_severity(finding: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    """Deterministic exploitability gate (safety net under the prompt guidance).

    Returns (possibly-downgraded finding, reason | None). Never UPGRADES.
    - HIGH/CRITICAL without any exploitability signal -> capped to MEDIUM.
    - A finding that is only about a benign/public artefact -> capped to INFO,
      unless it also carries a genuine exploit signal.
    """
    sev = str(finding.get("severity", "INFO")).upper()
    if sev not in _RANK:
        return finding, None
    text = _finding_text(finding)
    has_exploit = bool(_EXPLOIT_RX.search(text))
    explicit = str(finding.get("exploitability", "")).lower()
    has_exploit = has_exploit or explicit in {"confirmed", "poc", "weaponized", "known-exploit", "known_exploit"}

    new_sev, reason = sev, None
    # Benign-only artefact inflated above INFO -> INFO.
    if _BENIGN_RX.search(text) and not has_exploit and _RANK[sev] > _RANK["LOW"]:
        new_sev, reason = "INFO", "benign/public artefact (e.g. public key, version banner) is not a vulnerability"
    # HIGH/CRITICAL without exploitability evidence -> MEDIUM.
    elif _RANK[sev] >= _RANK["HIGH"] and not has_exploit:
        new_sev, reason = "MEDIUM", "no concrete exploitability evidence to justify HIGH/CRITICAL"

    if new_sev != sev:
        finding = {**finding, "severity": new_sev, "severity_capped_from": sev, "severity_cap_reason": reason}
    return finding, reason
