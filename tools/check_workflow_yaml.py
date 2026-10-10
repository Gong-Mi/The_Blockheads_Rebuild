#!/usr/bin/env python3
"""Parse every workflow YAML. A broken workflow file fails CI on push, late and loudly.

Why this exists: an edit that inserted a step at the wrong indentation split an existing step in
android.yml, and the first thing to notice was a red CI run on the pushed commit - the local gate had
no opinion about YAML at all. A workflow file is code that runs before every other check, so it
belongs in the cheap gate.

Usage:
  python3 tools/check_workflow_yaml.py [file ...]     # defaults to .github/workflows/*.yml
Exit 1 if any file fails to parse, or if an expected workflow has no jobs/steps.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def check(paths: list[Path]) -> tuple[list[str], int]:
    import yaml
    problems: list[str] = []
    steps_total = 0
    for p in paths:
        try:
            doc = yaml.safe_load(p.read_text())
        except Exception as exc:                                  # noqa: BLE001 - report, do not raise
            problems.append(f"{p}: does not parse: {exc}")
            continue
        jobs = (doc or {}).get("jobs")
        if not isinstance(jobs, dict) or not jobs:
            problems.append(f"{p}: parses but has no jobs")
            continue
        for name, job in jobs.items():
            steps = (job or {}).get("steps")
            if not isinstance(steps, list) or not steps:
                problems.append(f"{p}: job {name!r} has no steps")
                continue
            for i, st in enumerate(steps):
                if not isinstance(st, dict) or not ({"run", "uses"} & set(st)):
                    problems.append(f"{p}: job {name!r} step {i} has neither run nor uses")
            steps_total += len(steps)
    return problems, steps_total


def main(argv: list[str]) -> int:
    paths = [Path(a) for a in argv[1:]] or sorted((ROOT / ".github/workflows").glob("*.yml"))
    if not paths:
        print("no workflow files found", file=sys.stderr)
        return 1
    problems, total = check(paths)
    for p in problems:
        print(f"WORKFLOW YAML FAILED: {p}", file=sys.stderr)
    if problems:
        return 1
    print(f"workflow yaml: {len(paths)} file(s) parse, {total} steps total")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
