"""
CTIBench runner + report.

  python -m syber.bench.run --task cti_rcm --model deepseek-v4-pro --limit 50
  python -m syber.bench.run --task all --prompt bench --workers 8
  python -m syber.bench.run --task cti_ate --model deepseek-v4-flash

Runs a model over a CTIBench task, scores with the task metric, writes a results
artefact to .bench_results/, and prints a table alongside the published baselines.
"""
from __future__ import annotations

import argparse
import json
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from ..config import PATHS, assert_configured
from . import baselines, datasets, prompts, scoring
from .models import ModelRunner

_RESULTS = PATHS.root / ".bench_results"


def _run_task(task: str, runner: ModelRunner, mode: str, limit: int | None,
              workers: int) -> dict:
    examples = datasets.load(task, limit=limit)
    system = prompts.system_prompt(task, mode)
    t0 = time.time()

    def one(ex):
        try:
            out = runner.generate(system, ex.prompt)
            return ex, out, None
        except Exception as e:  # noqa: BLE001
            return ex, "", str(e)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        raw = list(pool.map(one, examples))   # map preserves input order

    details, errors = [], 0
    if task == "cti_rcm":
        res = scoring.RcmResult()
        for ex, out, err in raw:
            if err:
                errors += 1
            pred = scoring.extract_cwe(out)
            ok = scoring.score_rcm(pred, ex.gt)
            res.total += 1
            res.correct += int(ok)
            details.append({"idx": ex.idx, "pred": pred, "gt": scoring.norm_cwe(ex.gt),
                            "correct": ok, "error": err})
        metric = {"accuracy": round(res.accuracy, 4), "correct": res.correct, "total": res.total}
        headline = res.accuracy
    elif task == "cti_ate":
        pairs = []
        for ex, out, err in raw:
            if err:
                errors += 1
            pred = scoring.extract_techniques(out)
            gt = scoring.parse_technique_gt(ex.gt)
            pairs.append((pred, gt))
            details.append({"idx": ex.idx, "pred": sorted(pred), "gt": sorted(gt), "error": err})
        m = scoring.micro_f1(pairs)
        metric = m.to_dict()
        headline = m.f1
    else:
        raise ValueError(task)

    return {"task": task, "model": runner.model, "prompt_mode": mode,
            "n": len(examples), "errors": errors, "metric": metric,
            "headline": round(headline, 4), "elapsed_s": round(time.time() - t0, 1),
            "details": details}


def _print_report(summary: dict) -> None:
    task, model = summary["task"], summary["model"]
    metric_name = baselines.METRIC[task]
    print(f"\n=== CTIBench {task}  ({metric_name}) — prompt={summary['prompt_mode']} ===")
    print(f"  n={summary['n']}  errors={summary['errors']}  elapsed={summary['elapsed_s']}s")
    rows = [(f"{model} (ours)", summary["headline"])]
    for name, vals in baselines.PUBLISHED.items():
        rows.append((name, vals.get(task)))
    rows = [(n, v) for n, v in rows if v is not None]
    rows.sort(key=lambda r: r[1], reverse=True)
    width = max(len(n) for n, _ in rows)
    print(f"  {'model'.ljust(width)}   {metric_name}")
    print(f"  {'-' * width}   {'-' * len(metric_name)}")
    for name, val in rows:
        star = "  <--" if name.endswith("(ours)") else ""
        print(f"  {name.ljust(width)}   {val:.4f}{star}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run CTIBench tasks against a model.")
    ap.add_argument("--task", choices=["cti_rcm", "cti_ate", "all"], default="all")
    ap.add_argument("--model", default="deepseek-v4-pro")
    ap.add_argument("--prompt", choices=["bench", "subagent"], default="bench")
    ap.add_argument("--limit", type=int, default=None, help="cap examples (smoke runs)")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--out", default=None, help="results json path (default .bench_results/)")
    args = ap.parse_args(argv)
    assert_configured()

    runner = ModelRunner(model=args.model)
    tasks = ["cti_rcm", "cti_ate"] if args.task == "all" else [args.task]
    summaries = []
    for task in tasks:
        s = _run_task(task, runner, args.prompt, args.limit, args.workers)
        _print_report(s)
        summaries.append(s)

    _RESULTS.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path(args.out) if args.out else _RESULTS / f"ctibench-{args.model}-{args.prompt}-{stamp}.json"
    out.write_text(json.dumps({"model": args.model, "prompt_mode": args.prompt,
                               "limit": args.limit, "results": summaries}, indent=2))
    print(f"\n[bench] wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
