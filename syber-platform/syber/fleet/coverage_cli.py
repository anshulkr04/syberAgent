"""
Coverage CLI — the Ralph loop's INDEPENDENT backpressure check.

Run between loop iterations (in a throwaway container against the shared Neo4j) to decide
whether the engagement is genuinely finished — from graph state, NOT the agent's word.
This is the "tests pass" signal for a security engagement: the loop stops only when this
says so.

  python -m syber.fleet.coverage_cli            # prints JSON, exits 0 if complete else 1
  python -m syber.fleet.coverage_cli --quiet    # exit code only

Reads the attack graph (Neo4j when NEO4J_URI is set, else the in-process graph) and, if a
coordinator checkpoint with a lead registry is present, folds that in too.
"""
from __future__ import annotations

import json
import sys

from .coverage import engagement_coverage


def _load_leads():
    """Best-effort: restore the lead registry from the durable coordinator checkpoint so
    open high-value leads count against completion. Absent → graph-only coverage."""
    try:
        import os
        from ..config import PATHS
        from .leads import LeadRegistry
        ckpt = PATHS.state / "fleet_checkpoint.json"
        path = os.environ.get("SYBER_FLEET_CHECKPOINT", str(ckpt))
        with open(path) as f:
            data = json.load(f)
        reg = LeadRegistry()
        reg.restore(data.get("leads") or data.get("lead_registry") or {})
        return reg
    except Exception:  # noqa: BLE001 - no checkpoint / different schema -> graph-only
        return None


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    quiet = "--quiet" in argv
    digest = "--digest" in argv
    try:
        from ..graph.store import get_graph
        graph = get_graph()
    except Exception:  # noqa: BLE001
        graph = None
    leads = _load_leads()
    if digest:
        # Markdown carry-forward for the next Ralph pass (always exit 0; this is context,
        # not the stop signal).
        from .coverage import engagement_digest
        print(engagement_digest(graph=graph, leads=leads))
        return 0
    cov = engagement_coverage(graph=graph, leads=leads)
    if not quiet:
        print(json.dumps(cov, indent=2))
    else:
        print("COVERAGE_COMPLETE" if cov.get("complete") else
              f"COVERAGE_INCOMPLETE remaining={cov.get('remaining_count', '?')}")
    return 0 if cov.get("complete") else 1


if __name__ == "__main__":
    raise SystemExit(main())
