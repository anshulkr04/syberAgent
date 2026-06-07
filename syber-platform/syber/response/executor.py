"""
Response playbook executor (spec section 13.2).

Atomic execution with rollback: steps run in topological order; on any
IntegrationError, completed reversible steps are rolled back in reverse order.
Integrations are pluggable; the demo ships mock integrations that record calls.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from graphlib import TopologicalSorter
from typing import Any, Callable

from ..audit.log import get_audit_log


class IntegrationError(Exception):
    pass


class PlaybookExecutionError(Exception):
    def __init__(self, msg: str, completed_steps: list[dict[str, Any]]):
        super().__init__(msg)
        self.completed_steps = completed_steps


@dataclass
class Integration:
    """A named external system (azure_ad, itsm_servicenow, ...)."""

    name: str
    handler: Callable[[str, dict[str, Any]], dict[str, Any]]
    fail_actions: set[str] = field(default_factory=set)  # for testing rollback

    def execute(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        if action in self.fail_actions:
            raise IntegrationError(f"{self.name}.{action} failed")
        return self.handler(action, params)


def mock_integration(name: str, fail_actions: set[str] | None = None) -> Integration:
    calls: list[dict[str, Any]] = []

    def handler(action: str, params: dict[str, Any]) -> dict[str, Any]:
        calls.append({"action": action, "params": params})
        return {"ok": True, "action": action, "integration": name}

    integ = Integration(name=name, handler=handler, fail_actions=fail_actions or set())
    integ.handler.calls = calls  # type: ignore[attr-defined]
    return integ


def render_params(params: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    """Substitute {{var}} placeholders from context (spec 13.1 templating)."""
    def sub(value: Any) -> Any:
        if isinstance(value, str):
            return re.sub(r"\{\{(\w+)\}\}", lambda m: str(context.get(m.group(1), m.group(0))), value)
        if isinstance(value, dict):
            return {k: sub(v) for k, v in value.items()}
        if isinstance(value, list):
            return [sub(v) for v in value]
        return value

    return {k: sub(v) for k, v in params.items()}


def _topological_sort(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {s["step_id"]: s for s in steps}
    ts = TopologicalSorter({s["step_id"]: set(s.get("depends_on", [])) for s in steps})
    return [by_id[sid] for sid in ts.static_order()]


def execute_playbook(
    playbook: dict[str, Any],
    context: dict[str, Any],
    integrations: dict[str, Integration],
    dry_run: bool = False,
) -> dict[str, Any]:
    audit = get_audit_log()
    completed: list[dict[str, Any]] = []
    try:
        for step in _topological_sort(playbook["steps"]):
            if dry_run:
                _validate_step(step, integrations)
                completed.append(step)
                continue
            result = integrations[step["integration"]].execute(
                step["action"], render_params(step["params"], context)
            )
            audit.write_step_execution(step, result)
            completed.append(step)
        return {"status": "completed" if not dry_run else "validated", "steps": [s["step_id"] for s in completed]}

    except IntegrationError as exc:
        for step in reversed(completed):
            if step.get("reversible") and step.get("rollback_action"):
                try:
                    integrations[step["integration"]].execute(
                        step["rollback_action"], render_params(step["params"], context)
                    )
                    audit.write_rollback(step)
                except Exception as rb_err:  # noqa: BLE001
                    audit.write_rollback_failure(step, rb_err)
        raise PlaybookExecutionError(str(exc), completed_steps=completed) from exc


def _validate_step(step: dict[str, Any], integrations: dict[str, Integration]) -> None:
    if step["integration"] not in integrations:
        raise PlaybookExecutionError(f"unknown integration {step['integration']}", [])
    for field_name in ("step_id", "action", "params"):
        if field_name not in step:
            raise PlaybookExecutionError(f"step missing {field_name}", [])
