"""
syber.fleet — persistent, parallel multi-agent engagement layer.

Turns Syber's single-agent loop into an orchestrator-worker fleet that fans out
specialist workers across attack vectors, pools their evidence into the attack
graph (the shared *blackboard*), then re-divides the next wave — running long and
resuming after interruption.

Design (see scratchpad/FLEET_PLAN.md and the research reports):
  * board.py       — the blackboard task layer: Task/Claim state over the graph,
                     atomic claim/lease + heartbeat + reaper, idempotent frontier
                     materialization. In-memory-first, thread-safe; backend seam
                     for Neo4j/Postgres when present.
  * planner.py     — expected-value frontier ranking + disjoint batching (later phase).
  * coordinator.py — the persistent plan->fan-out->pool->re-divide loop (later phase).
  * specialists.py — the narrow specialist roster (later phase).

Everything degrades gracefully: with no extra backends it runs single-process with
thread workers on the in-memory graph — the platform's standard contract.
"""
from __future__ import annotations

from .board import (Board, InMemoryTaskStore, Task, TaskStatus, TaskStore,
                    make_board)
from .coordinator import (Coordinator, EngagementBudget, StuckDetector,
                          WorkerResult)
from .leads import (EvidenceRung, Lead, LeadClass, LeadRegistry, LeadState,
                    classify_node, severity_for_rung)
from .persistence import PersistencePolicy
from .planner import Planner, PlannerWeights, ScoredTask
from .specialists import (SPECIALISTS, Specialist, make_tool_worker,
                          specialist_for, specialist_system_prompt)

__all__ = ["Board", "Task", "TaskStatus", "TaskStore", "InMemoryTaskStore",
           "make_board", "Planner", "PlannerWeights", "ScoredTask",
           "Coordinator", "EngagementBudget", "StuckDetector", "WorkerResult",
           "PersistencePolicy",
           "SPECIALISTS", "Specialist", "make_tool_worker", "specialist_for",
           "specialist_system_prompt",
           "LeadRegistry", "Lead", "LeadClass", "LeadState", "EvidenceRung",
           "classify_node", "severity_for_rung"]
