#!/usr/bin/env python3
"""Pre-push gate: the four checks that have to pass before a commit goes out.

Every CI failure in the last cycles was caught by one of these, and twice the commit
was pushed before its own contract test had finished. This runs them in order and
stops at the first failure:

  1. tools/lint_evidence_scan.py          - raw-byte regex, vacuous --check, split views
  2. tools/check_artifact_consumers.py    - reads of columns no artifact has
  3. tools/validate_reverse_evidence.py   - the evidence contract over the artifacts
  4. tools/run_contract_tests.py          - every contract test, bounded timeout

`--changed-only` narrows step 4 to the tests whose tool or artifact was modified in the
working tree (fast path while iterating); the default runs everything.

Usage:
  python3 tools/prepush_gate.py [--changed-only] [--timeout 300]
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"


def run(label: str, argv: list[str]) -> tuple[bool, str]:
    print(f"== {label}", flush=True)
    proc = subprocess.run(argv, capture_output=True, text=True, cwd=ROOT)
    output = (proc.stdout + proc.stderr).strip()
    if output:
        print(output, flush=True)
    return proc.returncode == 0, output


def changed_test_names() -> set[str]:
    """Contract tests whose subject file is dirty in the working tree."""
    try:
        status = subprocess.run(["git", "status", "--porcelain"], capture_output=True,
                                text=True, cwd=ROOT).stdout
    except OSError:
        return set()
    if not status.strip():
        return set()
    dirty = {Path(line[3:].strip()).name for line in status.splitlines() if line.strip()}
    names = set()
    for name in dirty:
        if name.startswith("test_"):
            names.add(name)
            continue
        stem = name.removesuffix(".py")
        names.add(f"test_{stem}.py")
        # artifacts are covered by the test named after the tool that produces them
        for candidate in dirty:
            if candidate.startswith(stem):
                names.add(f"test_{stem}.py")
    return {n for n in names if (TOOLS / n).exists()}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--changed-only", action="store_true")
    ap.add_argument("--timeout", type=float, default=300.0)
    args = ap.parse_args()

    steps: list[tuple[str, list[str]]] = [
        ("evidence-scan lint", [sys.executable, str(TOOLS / "lint_evidence_scan.py")]),
        ("artifact consumers", [sys.executable, str(TOOLS / "check_artifact_consumers.py")]),
        ("reverse-evidence contract", [sys.executable, str(TOOLS / "validate_reverse_evidence.py")]),
    ]
    for label, argv in steps:
        ok, _ = run(label, argv)
        if not ok:
            print(f"\nGATE FAILED at: {label}", file=sys.stderr)
            return 1

    argv = [sys.executable, str(TOOLS / "run_contract_tests.py"),
            "--timeout", str(args.timeout), "--jobs", "4"]
    if args.changed_only:
        names = sorted(changed_test_names())
        if not names:
            print("== contract tests: nothing changed, skipping")
            print("\npre-push gate: PASS")
            return 0
        for name in names:
            argv += ["--filter", name[5:-3]]
        print(f"== contract tests (changed only: {len(names)})")
    ok, _ = run("contract tests", argv)
    if not ok:
        print("\nGATE FAILED at: contract tests", file=sys.stderr)
        return 1

    print("\npre-push gate: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
