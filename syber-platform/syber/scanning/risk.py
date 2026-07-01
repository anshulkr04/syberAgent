"""
Risk-tiered action classification — sharpen default-deny from binary to graded.

``authorization.py`` answers *may I touch this target at all?* (default-deny
allowlist). This module answers the orthogonal question *how dangerous is this
action?* — so the platform can permit recon freely on an authorised target while
still refusing destructive / exfiltration / reverse-shell actions unless they are
explicitly enabled. Modelled on CAI's sensitive-command taxonomy
(``util/user_prompts.py``), but as a pure classifier with a default-deny policy
the MCP layer and audit log consume.

  * ``classify_command`` — bucket a shell command into a RiskTier by inspecting
    its real binaries/operators (a tokenizer that ignores quoted strings, so
    ``grep 'sudo'`` is not flagged).
  * ``classify_payload`` — bucket a web request by attack-payload content
    (``UNION SELECT``, ``../``, ``php://``) rather than HTTP method, so benign
    POST recon isn't mistaken for exploitation (VulnClaw's ``infer_tool_action``).
  * ``decision`` — apply the default policy: RECON/READ allowed; DESTRUCTIVE /
    EXFILTRATION / REVERSE_SHELL denied unless their tier is in ``allow``.

Pure functions over strings — unit-tested without a network. The MITRE tag each
classifier emits also enriches the attack-graph / audit trail.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from enum import Enum
from typing import Any

__all__ = ["RiskTier", "RiskDecision", "classify_command", "classify_payload",
           "decision", "DEFAULT_ALLOWED_TIERS"]


class RiskTier(str, Enum):
    READ = "read"                    # benign read/info (cat, ls, GET)
    RECON = "recon"                  # active recon (nmap, nikto, sqlmap probe)
    WRITE = "write"                  # state-changing but in-scope (POST/PUT)
    EXPLOIT = "exploit"              # injection/traversal payloads
    DESTRUCTIVE = "destructive"      # rm -rf /, mkfs, dd of=/dev, shred
    EXFILTRATION = "exfiltration"    # piping env/secrets out of the host
    REVERSE_SHELL = "reverse_shell"  # bind/reverse shells, pipe-to-shell
    PRIVILEGE = "privilege"          # sudo / privilege escalation

    def __str__(self) -> str:
        return self.value


# Tiers permitted by default on an already-authorised target. The dangerous tiers
# must be explicitly opted into per-engagement.
DEFAULT_ALLOWED_TIERS = frozenset({RiskTier.READ, RiskTier.RECON, RiskTier.WRITE,
                                   RiskTier.EXPLOIT})

# MITRE ATT&CK tactic tag per tier, for graph/audit enrichment.
_MITRE = {
    RiskTier.RECON: "TA0043",         # Reconnaissance
    RiskTier.EXPLOIT: "TA0001",       # Initial Access
    RiskTier.WRITE: "TA0040",         # Impact (state change)
    RiskTier.DESTRUCTIVE: "TA0040",   # Impact
    RiskTier.EXFILTRATION: "TA0010",  # Exfiltration
    RiskTier.REVERSE_SHELL: "TA0011", # Command and Control
    RiskTier.PRIVILEGE: "TA0004",     # Privilege Escalation
    RiskTier.READ: "TA0007",          # Discovery
}


@dataclass
class RiskDecision:
    tier: RiskTier
    allowed: bool
    reason: str
    mitre: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"tier": str(self.tier), "allowed": self.allowed,
                "reason": self.reason, "mitre": self.mitre}


# --- command classification ------------------------------------------------- #
_DESTRUCTIVE_RX = re.compile(
    r"\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(?:/\S*|~|\$HOME)(?:\s|$)|\bmkfs\b|\bdd\s+[^\n]*of=/dev/"
    r"|\bshred\b|:\(\)\s*\{|\bfork\s*bomb|>\s*/dev/sd|\bwipefs\b", re.IGNORECASE)
_REVERSE_SHELL_RX = re.compile(
    r"/dev/tcp/|\bnc\b[^\n]*\s-e\b|\bncat\b[^\n]*--exec|\bbash\s+-i\b|\bsh\s+-i\b"
    r"|socat\b[^\n]*exec|\bmkfifo\b[^\n]*\|.*sh|python[0-9.]*\s+-c[^\n]*socket", re.IGNORECASE)
_PIPE_TO_SHELL_RX = re.compile(r"\b(?:curl|wget|fetch)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|d)?sh\b",
                               re.IGNORECASE)
_EXFIL_RX = re.compile(
    r"\b(?:curl|wget)\b[^\n]*(?:-d|--data|-F|-T|--upload-file)[^\n]*\$\("
    r"|\bcat\b[^\n]*(?:/etc/shadow|/etc/passwd|id_rsa|\.aws/credentials|\.env)[^\n]*\|"
    r"|\benv\b\s*\|\s*(?:curl|wget|nc)\b", re.IGNORECASE)
_RECON_BINS = {"nmap", "masscan", "nikto", "sqlmap", "hydra", "gobuster", "ffuf",
               "dirb", "dirsearch", "nuclei", "wpscan", "amass", "subfinder",
               "feroxbuster", "whatweb", "wfuzz", "medusa", "metasploit", "msfconsole"}
_READ_BINS = {"cat", "ls", "head", "tail", "grep", "find", "stat", "file", "wc",
              "echo", "pwd", "whoami", "id", "uname", "which", "dig", "host",
              "nslookup", "ps", "env", "printenv"}


def _binaries(command: str) -> list[str]:
    """Extract the actual program names from a (possibly piped) command, ignoring
    quoted arguments — so ``grep 'sudo foo'`` reports only ``grep``."""
    bins: list[str] = []
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()
    expect_cmd = True
    for tok in tokens:
        if tok in ("|", "||", "&&", ";", "&"):
            expect_cmd = True
            continue
        if expect_cmd:
            if "=" in tok and re.match(r"^\w+=", tok):   # VAR=val env prefix
                continue
            bins.append(tok.split("/")[-1])
            expect_cmd = False
    return bins


def _has_shell_sudo(command: str) -> bool:
    return "sudo" in _binaries(command) or bool(re.search(r"\bsudo\s+-\w", command))


def classify_command(command: str) -> RiskTier:
    """Classify a shell command into its highest-risk tier."""
    c = command or ""
    if _DESTRUCTIVE_RX.search(c):
        return RiskTier.DESTRUCTIVE
    if _REVERSE_SHELL_RX.search(c) or _PIPE_TO_SHELL_RX.search(c):
        return RiskTier.REVERSE_SHELL
    if _EXFIL_RX.search(c):
        return RiskTier.EXFILTRATION
    if _has_shell_sudo(c):
        return RiskTier.PRIVILEGE
    bins = set(_binaries(c))
    if bins & _RECON_BINS:
        return RiskTier.RECON
    if bins and bins <= _READ_BINS:
        return RiskTier.READ
    return RiskTier.RECON  # unknown active command on an authorised target == recon-ish


# --- web payload classification --------------------------------------------- #
_EXPLOIT_PAYLOAD_RX = re.compile(
    r"union\s+select|';|\"\)|or\s+1=1|sleep\s*\(|benchmark\s*\(|xp_cmdshell"          # SQLi
    r"|<script|onerror\s*=|javascript:|<img[^>]+onerror"                              # XSS
    r"|\.\./|\.\.\\|%2e%2e%2f|/etc/passwd|php://|file://|data://|expect://"           # LFI/RFI/traversal
    r"|169\.254\.169\.254|metadata\.google|\bgopher://|\bdict://"                     # SSRF
    r"|\$\{jndi:|;\s*\w+\s*=|`[^`]+`|\$\([^)]+\)",                                    # log4shell/cmdi
    re.IGNORECASE)


def classify_payload(method: str, url: str, body: str = "") -> RiskTier:
    """Classify a web request by PAYLOAD content, not HTTP verb: an attack payload
    anywhere in the URL or body is EXPLOIT; otherwise a write verb is WRITE and a
    safe verb is READ."""
    blob = f"{url}\n{body or ''}"
    if _EXPLOIT_PAYLOAD_RX.search(blob):
        return RiskTier.EXPLOIT
    if (method or "GET").upper() in ("POST", "PUT", "PATCH", "DELETE"):
        return RiskTier.WRITE
    return RiskTier.READ


def decision(tier: RiskTier, allow: frozenset[RiskTier] | set[RiskTier] | None = None) -> RiskDecision:
    """Apply the default-deny-dangerous policy. ``allow`` extends the default
    permitted set for this engagement (e.g. operator opts into REVERSE_SHELL)."""
    permitted = set(DEFAULT_ALLOWED_TIERS) | set(allow or ())
    ok = tier in permitted
    reason = (f"{tier} permitted" if ok else
              f"{tier} denied by default policy — enable explicitly to allow")
    return RiskDecision(tier=tier, allowed=ok, reason=reason, mitre=_MITRE.get(tier, ""))
