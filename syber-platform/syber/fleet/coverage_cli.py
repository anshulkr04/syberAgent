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
    """Best-effort: restore the lead registry from the durable coordinator checkpoint(s)
    so open high-value leads count against completion. The coordinator writes one
    checkpoint per host under PATHS.state/fleet/<host>.json with a `leads` snapshot; we
    merge them. Absent → graph-only coverage (leads are also re-derived from the graph)."""
    try:
        from ..config import PATHS
        from .leads import LeadRegistry
    except Exception:  # noqa: BLE001
        return None
    reg = LeadRegistry()
    found = False
    import os
    override = os.environ.get("SYBER_FLEET_CHECKPOINT")
    paths = [override] if override else []
    fleet_dir = PATHS.state / "fleet"
    if fleet_dir.is_dir():
        paths += [str(p) for p in sorted(fleet_dir.glob("*.json"))]
    for path in paths:
        try:
            with open(path) as f:
                data = json.load(f)
            snap = data.get("leads") or {}
            # snapshot format is {"leads": [ ... ]}; restore merges into the registry
            for ld in (snap.get("leads", []) if isinstance(snap, dict) else []):
                from .leads import Lead
                lead = Lead.from_dict(ld)
                reg._leads.setdefault(lead.id, lead)
            found = True
        except Exception:  # noqa: BLE001
            continue
    return reg if found else None


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
