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


def run_one(path: Path, timeout: float) -> tuple[str, str, float, str]:
    start = time.monotonic()
    try:
        proc = subprocess.run([sys.executable, str(path)], capture_output=True,
                              text=True, timeout=timeout, cwd=TOOLS.parent)
        elapsed = time.monotonic() - start
        if proc.returncode == 0:
            return path.name, "pass", elapsed, ""
        tail = (proc.stdout + proc.stderr).strip().splitlines()[-1:] or [""]
        return path.name, "FAIL", elapsed, tail[0][:140]
    except subprocess.TimeoutExpired:
        return path.name, "timeout", time.monotonic() - start, f">{timeout:g}s"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--filter", help="only tests whose filename contains this")
    ap.add_argument("--timeout", type=float, default=180.0)
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--list", action="store_true")
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
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for name, status, elapsed, detail in pool.map(
                lambda p: run_one(p, args.timeout), tests):
            marker = "ok " if status == "pass" else "!! "
            line = f"  {marker}{name:52s} {status:8s} {elapsed:6.1f}s"
            if detail:
                line += f"  {detail}"
            print(line, flush=True)
            if status != "pass":
                failures.append((name, status, detail))

    print(f"\n{len(tests) - len(failures)}/{len(tests)} passed")
    if failures:
        for name, status, detail in failures:
            print(f"  {status.upper()}: {name} {detail}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
