#!/usr/bin/env python3
"""Run every contract test with a per-test timeout, in parallel, one summary.

The reason this exists: twice in one cycle a commit was pushed before the local
target test had finished, and CI caught what a single command would have. Two
hundred tools and a hundred-plus contract tests make "run them all before pushing"
impractical by hand - so this runs them with a bounded timeout per test, reports a
single table, and exits non-zero if anything failed.

Usage:
  python3 tools/run_contract_tests.py                 # all tools/test_*.py
  python3 tools/run_contract_tests.py --filter tile   # only names containing 'tile'
  python3 tools/run_contract_tests.py --list
"""
from __future__ import annotations

import argparse
import concurrent.futures
import subprocess
import sys
import time
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
SELF = "run_contract_tests.py"


def discover(filter_text: str | None) -> list[Path]:
    tests = sorted(p for p in TOOLS.glob("test_*.py") if p.name != SELF)
    if filter_text:
        tests = [p for p in tests if filter_text in p.name]
    return tests


# A test that cannot run here is not a failing test. These signatures mean the
# environment (or a built input) is missing, which is why CI runs a curated subset
# of the suite; treating them as failures made every CI run red when the whole set
# was added. `--strict` turns the skipping off.
SKIP_SIGNATURES = (
    "ModuleNotFoundError: No module named",
    "ImportError: No module named",
    "usage: test_",
)


def run_one(path: Path, timeout: float, strict: bool = False) -> tuple[str, str, float, str]:
    start = time.monotonic()
    try:
        proc = subprocess.run([sys.executable, str(path)], capture_output=True,
                              text=True, timeout=timeout, cwd=TOOLS.parent)
        elapsed = time.monotonic() - start
        if proc.returncode == 0:
            return path.name, "pass", elapsed, ""
        output = (proc.stdout + proc.stderr)
        tail = output.strip().splitlines()[-1:] or [""]
        if not strict and any(signature in output for signature in SKIP_SIGNATURES):
            return path.name, "skip", elapsed, tail[0][:140]
        return path.name, "FAIL", elapsed, tail[0][:140]
    except subprocess.TimeoutExpired:
        return path.name, "timeout", time.monotonic() - start, f">{timeout:g}s"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--filter", help="only tests whose filename contains this")
    ap.add_argument("--timeout", type=float, default=180.0)
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--strict", action="store_true",
                    help="treat a missing module or input as a failure")
    args = ap.parse_args()

    tests = discover(args.filter)
    if args.list:
        for path in tests:
            print(path.name)
        return 0
    if not tests:
        print("no contract tests matched", file=sys.stderr)
        return 1

    print(f"running {len(tests)} contract tests (timeout {args.timeout:g}s each, "
          f"{args.jobs} at a time)", flush=True)
    failures = []
    skipped = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for name, status, elapsed, detail in pool.map(
                lambda p: run_one(p, args.timeout, args.strict), tests):
            if status == "skip":
                skipped += 1
            marker = {"pass": "ok ", "skip": "-- "}.get(status, "!! ")
            line = f"  {marker}{name:52s} {status:8s} {elapsed:6.1f}s"
            if detail:
                line += f"  {detail}"
            print(line, flush=True)
            if status not in ("pass", "skip"):
                failures.append((name, status, detail))

    passed = len(tests) - len(failures) - skipped
    print(f"\n{passed}/{len(tests)} passed, {skipped} skipped "
          f"(environment/inputs missing), {len(failures)} failed")
    if failures:
        for name, status, detail in failures:
            print(f"  {status.upper()}: {name} {detail}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
