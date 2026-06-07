"""
Central configuration for the Syber Multi-Agent Security Intelligence Platform.

All tunable thresholds from the engineering spec (v3.0) are collected here so the
rest of the codebase reads from a single source of truth. Secrets (the DeepSeek
API key) are loaded from a .env file without requiring python-dotenv.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------- #
# .env loading (no external dependency)
# --------------------------------------------------------------------------- #

def _load_dotenv() -> None:
    """Populate os.environ from the nearest .env file, if present.

    Searches the package root and two parents up so the platform works whether
    it is run from syber-platform/ or the repo root.
    """
    here = Path(__file__).resolve()
    candidates = [
        here.parent.parent / ".env",          # syber-platform/.env
        here.parent.parent.parent / ".env",    # syberAgent/.env  (user's key lives here)
    ]
    for env_path in candidates:
        if not env_path.is_file():
            continue
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip().strip('"').strip("'")
            # First file wins; do not clobber an already-exported value.
            os.environ.setdefault(key, value)


_load_dotenv()


# --------------------------------------------------------------------------- #
# LLM provider
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class LLMConfig:
    """DeepSeek V4 provider settings (spec section 8)."""

    api_key: str = field(default_factory=lambda: os.environ.get("DEEPSEEK_API_KEY", ""))
    base_url: str = field(default_factory=lambda: os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com"))

    # Spec section 8.2. We use the FULL DeepSeek V4 model — `deepseek-v4-pro` —
    # everywhere, NOT the flash tier. The live API confirms only two ids exist
    # (deepseek-v4-pro, deepseek-v4-flash) and that the aliases `deepseek-chat`
    # and `deepseek-reasoner` BOTH silently downgrade to flash — so we pin the
    # explicit `deepseek-v4-pro` id to guarantee the proper model (required for
    # quality reasoning over scan output). Override via SYBER_ORCH_MODEL.
    orchestrator_model: str = field(default_factory=lambda: os.environ.get("SYBER_ORCH_MODEL", "deepseek-v4-pro"))
    subagent_model: str = field(default_factory=lambda: os.environ.get("SYBER_SUB_MODEL", "deepseek-v4-pro"))

    request_timeout_s: int = 120
    num_retries: int = 3
    max_turns: int = 40

    def resolve_model(self, name: str) -> str:
        """Map spec / Anthropic aliases to currently served DeepSeek model ids.

        The real served ids are `deepseek-v4-pro` and `deepseek-v4-flash`. We map
        the spec's Claude aliases to the PRO tier (never flash) so the agent runs
        on the full model. `deepseek-chat`/`deepseek-reasoner` are left as-is
        (they resolve to flash server-side) only if a caller explicitly opts in.
        """
        alias = {
            "claude-opus-4-20250514": "deepseek-v4-pro",
            "claude-sonnet-4-20250514": "deepseek-v4-pro",
            "deepseek-reasoner": "deepseek-v4-pro",  # prefer the full model
        }
        return alias.get(name, name)


# --------------------------------------------------------------------------- #
# Detection / scoring thresholds (spec sections 7, 9, 10, 12)
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Thresholds:
    # Behavioural ensemble (spec 7.5): >0.70 emits an anomaly_detected event.
    anomaly_publish: float = 0.70
    ensemble_weights: tuple[float, float, float] = (0.40, 0.40, 0.20)  # iforest, lstm, ocsvm

    # Composite Evidence Score (spec 12.2): CES >= 0.82 escalates to analyst.
    ces_escalate: float = 0.82
    ces_weights: tuple[float, float, float] = (0.45, 0.30, 0.25)  # consistency, calibrated, selfcheck

    # Threat investigator publish gate (spec 3.3 / 8.4).
    corroboration_ratio: float = 0.70
    min_distinct_evidence_refs: int = 3
    max_retrieval_iterations: int = 5

    # Prompt-injection classifier decision boundary (spec 9.1).
    injection_prob: float = 0.85

    # TI / RAG distribution-shift gates (spec 9.2 / 10.2).
    ti_anomaly_cosine: float = 0.35       # reject if cosine DISTANCE above this
    source_anomaly_sim: float = 0.55      # flag if cosine SIMILARITY below this

    # Injection test battery pass criterion (spec 15.1).
    injection_pass_rate: float = 0.98


@dataclass(frozen=True)
class Paths:
    root: Path = field(default_factory=lambda: Path(__file__).resolve().parent.parent)

    @property
    def state(self) -> Path:
        return self.root / ".investigation_state"

    @property
    def audit(self) -> Path:
        return self.root / ".audit_log"

    @property
    def memory_db(self) -> Path:
        return self.root / ".memory_store.sqlite"

    @property
    def calibration(self) -> Path:
        return self.root / "syber" / "scoring" / "calibration"


LLM = LLMConfig()
THRESHOLDS = Thresholds()
PATHS = Paths()


def assert_configured() -> None:
    if not LLM.api_key:
        raise RuntimeError(
            "DEEPSEEK_API_KEY is not set. Add it to syberAgent/.env or export it. "
            "The platform uses DeepSeek V4 as its LLM (spec section 8)."
        )
