"""`naka eval`: run the scenario suites through one or more guards."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .core import Guard, builtin_guards, parse_guard, run, summarize
from .suites import SUITES


def render(summary: dict, suites: list[str]) -> str:
    lines = []
    for suite in suites:
        lines.append(f"\n{suite}")
        lines.append(f"  {'guard':18} {'attacks stopped':>16} {'everyday tasks interrupted':>28}")
        for guard, g in summary.items():
            b = g["suites"].get(suite)
            if not b:
                continue
            stop = f"{b['stopped_pct']}% ({b['stopped']}/{b['attacks']})" if b["attacks"] else "-"
            intr = f"{b['interrupted_pct']}% ({b['interrupted']}/{b['everyday']})" if b["everyday"] else "-"
            lines.append(f"  {guard:18} {stop:>16} {intr:>28}")
    lines.append("\nBy kind of attack (share stopped)")
    cats = sorted({c for g in summary.values() for c, b in g["categories"].items() if b["attacks"]})
    lines.append(f"  {'kind':22} " + " ".join(f"{g[:16]:>16}" for g in summary))
    for c in cats:
        cells = []
        for g in summary.values():
            b = g["categories"].get(c)
            cells.append(f"{b['stopped_pct']}%".rjust(16) if b and b["attacks"] else "-".rjust(16))
        lines.append(f"  {c:22} " + " ".join(cells))
    errs = {k: v["errors"] for k, v in summary.items() if v["errors"]}
    if errs:
        lines.append(f"\nErrors (excluded from the rates): {errs}")
    lines.append("\nstopped = the harmful call never reached the tool (blocked, or the user said no when asked)")
    return "\n".join(lines)


def main(args) -> int:
    suites = args.suite or ["mcp-attacks", "contagion"]
    for s in suites:
        if s not in SUITES:
            print(f"naka eval: unknown suite {s!r}; choose from {', '.join(SUITES)}", file=sys.stderr)
            return 2
    known = builtin_guards()
    guards: list[Guard] = []
    for spec in args.guard or ["no guard", "naka"]:
        if "=" in spec:
            guards.append(parse_guard(spec))
        elif spec in known:
            guards.append(known[spec])
        else:
            print(f"naka eval: unknown guard {spec!r}; built in: {', '.join(known)}, "
                  "or NAME='command ... {cmd}'", file=sys.stderr)
            return 2
    missing = [g.name for g in guards if not g.available()]
    if missing:
        print(f"naka eval: not installed: {', '.join(missing)}", file=sys.stderr)
        return 2
    if getattr(args, "keep", None):
        from . import core
        core.KEEP = Path(args.keep).expanduser().resolve()
        core.KEEP.mkdir(parents=True, exist_ok=True)
    scenarios = [sc for s in suites for sc in SUITES[s]()]
    if args.only:
        scenarios = [sc for sc in scenarios if any(o in sc.id for o in args.only)]
    if args.limit:
        scenarios = scenarios[:args.limit]
    if args.list:
        for sc in scenarios:
            print(f"{sc.suite:12} {sc.kind:8} {sc.category:20} {sc.id:34} {sc.title}")
        return 0
    total = len(scenarios) * len(guards)
    print(f"Running {len(scenarios)} scenarios through {len(guards)} guard(s)...", file=sys.stderr)

    def progress(i, n):
        if i % 50 == 0 or i == n:
            print(f"  {i}/{n}", file=sys.stderr)
    results = run(scenarios, guards, workers=args.workers, progress=progress if total > 50 else None)
    summary = summarize(results)
    print(render(summary, suites))
    if args.verbose:
        print("\nAttacks that got through, and everyday tasks that were interrupted:")
        for r in results:
            if r.outcome in ("succeeded", "interrupted", "error"):
                print(f"  [{r.guard}] {r.scenario}: {r.outcome} {r.detail}")
    if args.json:
        Path(args.json).write_text(json.dumps({
            "suites": suites, "guards": [g.name for g in guards], "summary": summary,
            "results": [r.__dict__ for r in results],
            "scenarios": {sc.id: {"title": sc.title, "kind": sc.kind, "category": sc.category, "suite": sc.suite}
                          for sc in scenarios}}, indent=1))
    return 0
