"""
Event envelope + signing (spec section 4.2).

All bus events share the SecurityEvent envelope. `signature` is an HMAC-SHA256
over the remaining fields using the originating agent's signing key (from the
HSM in production; derived here for the demo).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

SECURITY_EVENT_AVRO = {
    "type": "record",
    "name": "SecurityEvent",
    "fields": [
        {"name": "event_id", "type": "string"},
        {"name": "event_type", "type": "string"},
        {"name": "investigation_id", "type": ["null", "string"], "default": None},
        {"name": "originating_agent", "type": "string"},
        {"name": "timestamp_us", "type": "long"},
        {"name": "confidence", "type": ["null", "float"], "default": None},
        {"name": "payload", "type": "string"},
        {"name": "evidence_refs", "type": {"type": "array", "items": "string"}, "default": []},
        {"name": "signature", "type": "string"},
    ],
}


def _signing_key(agent: str) -> bytes:
    return hashlib.sha256(f"syber-agent-key::{agent}".encode()).digest()


@dataclass
class SecurityEvent:
    event_type: str
    originating_agent: str
    payload: str
    investigation_id: str | None = None
    confidence: float | None = None
    evidence_refs: list[str] = field(default_factory=list)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp_us: int = field(default_factory=lambda: int(time.time() * 1e6))
    signature: str = ""

    def sign(self) -> "SecurityEvent":
        body = asdict(self)
        body.pop("signature")
        digest = hmac.new(_signing_key(self.originating_agent), json.dumps(body, sort_keys=True).encode(), "sha256")
        self.signature = digest.hexdigest()
        return self

    def verify(self) -> bool:
        body = asdict(self)
        sig = body.pop("signature")
        digest = hmac.new(_signing_key(self.originating_agent), json.dumps(body, sort_keys=True).encode(), "sha256")
        return hmac.compare_digest(digest.hexdigest(), sig)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
