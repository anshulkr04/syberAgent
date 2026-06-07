"""
score_behaviour in-process MCP tool — wraps the ensemble (spec section 7).

Exposes the Isolation Forest + LSTM Autoencoder + One-Class SVM ensemble to the
behavioural_analytics_agent subagent without an external HTTP hop.
"""
from __future__ import annotations

from typing import Any

from ..analytics.service import score_entity
from ..audit.log import get_audit_log
from .registry import ToolSpec, tool
from .scope_guard import get_current_scope

SCORE_BEHAVIOUR_PARAMS = {
    "type": "object",
    "properties": {"entity_id": {"type": "string", "description": "Entity to score"}},
    "required": ["entity_id"],
}


@tool("score_behaviour", "Ensemble behavioural deviation score (iForest+LSTM+OCSVM) for an entity.", SCORE_BEHAVIOUR_PARAMS)
def score_behaviour(args: dict[str, Any]) -> dict[str, Any]:
    scope = get_current_scope()
    entity_id = args["entity_id"]
    if not scope.allows_entity(entity_id):
        get_audit_log().write_scope_violation("score_behaviour", args)
        return {"error": "ScopeViolation", "message": f"{entity_id} outside scope"}
    get_audit_log().write_tool_call("score_behaviour", args, scope)
    return score_entity(entity_id)


def get_tool() -> ToolSpec:
    return score_behaviour
