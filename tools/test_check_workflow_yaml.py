#!/usr/bin/env python3
"""Contract test for tools/check_workflow_yaml.py.

The checker is a gate, so it needs a POSITIVE control (the repo's real workflows parse) and a
NEGATIVE control (a synthetic file with the exact defect that shipped: a step inserted at column 0,
which splits the preceding step) - otherwise "all green" only means the checker looked at nothing.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import check_workflow_yaml as c  # noqa: E402

GOOD = """name: x
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: a
        run: echo a
      - name: b
        run: echo b
"""

# the defect that actually shipped: a step that lost its indentation, splitting step "a"
BROKEN_INDENT = """name: x
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: a
- name: inserted at column zero
  run: echo oops
        run: echo a
      - name: b
        run: echo b
"""

BROKEN_NO_STEPS = """name: x
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps: []
"""

BROKEN_STEP_SHAPE = """name: x
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: a
"""


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        good = tmp / "good.yml"; good.write_text(GOOD)
        problems, total = c.check([good])
        assert problems == [] and total == 2, (problems, total)

        for label, text, needle in (("indent", BROKEN_INDENT, "does not parse"),
                                    ("no steps", BROKEN_NO_STEPS, "has no steps"),
                                    ("step shape", BROKEN_STEP_SHAPE, "neither run nor uses")):
            bad = tmp / f"{label}.yml"; bad.write_text(text)
            problems, _ = c.check([bad])
            assert problems and any(needle in p for p in problems), (label, problems)

    real = sorted((ROOT / ".github/workflows").glob("*.yml"))
    assert real, "the repo must have workflow files for this control to mean anything"
    problems, total = c.check(real)
    assert problems == [], problems
    assert total > 50, f"step count looks wrong: {total}"
    print(f"controls verified; {len(real)} real workflow file(s) parse, {total} steps")
    return 0


if __name__ == "__main__":
    sys.exit(main())
