"""Control-flow exceptions for the agent loop (kept dependency-free to avoid
import cycles between the loop and the tools that raise them)."""
from __future__ import annotations

from typing import Any


class HumanApprovalRequired(Exception):
    """Raised by a tool to pause the loop for analyst approval (spec 3.5)."""

    def __init__(self, payload: dict[str, Any]):
        super().__init__(payload.get("reason", "approval required"))
        self.payload = payload
