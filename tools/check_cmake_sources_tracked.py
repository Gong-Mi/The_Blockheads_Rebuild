#!/usr/bin/env python3
"""Fail if the recovered CMakeLists references a source that is not in git.

This exists because of a real incident: the DynamicObjectNetData model's .h and its tests were committed while
its .cpp was not, so the local build kept working on a file CI never received, and CI failed at configure time
with "Cannot find source file: dynamic_object_net_data.cpp" - reported against the add_library line, which
points nowhere near the actual omission. A local build can never catch that; git can.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CM = ROOT / "reconstruction/recovered/CMakeLists.txt"


def main() -> int:
    text = CM.read_text()
    tracked = set(subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True,
                                 text=True).stdout.split())
    problems = []
    # (a) every source the CMakeLists lists
    for name in sorted(set(re.findall(r"\b([A-Za-z0-9_]+\.cpp)\b", text))):
        for rel in (f"reconstruction/recovered/{name}", f"tools/{name}"):
            if (ROOT / rel).exists() and rel not in tracked:
                problems.append(rel)
    # (b) every header those sources include - the gap that let dynamic_object_net_data.h through: the guard
    #     checked sources only, and the header was the one CI could not find
    for name in sorted(set(re.findall(r"\b([A-Za-z0-9_]+\.cpp)\b", text))):
        src = ROOT / "reconstruction/recovered" / name
        if not src.exists():
            continue
        for inc in re.findall(r'#include\s+"([^"]+)"', src.read_text()):
            rel = f"reconstruction/recovered/{inc.lstrip('./')}"
            if (ROOT / rel).exists() and rel not in tracked:
                problems.append(rel)
    # (c) contract tests that exist on disk but were never committed - they would silently stop running
    #     rather than fail a build
    for p in sorted((ROOT / "tools").glob("test_*.py")):
        rel = f"tools/{p.name}"
        if rel not in tracked:
            problems.append(rel)
    if problems:
        print("CMakeLists references files that exist but are NOT in git:")
        for p in problems:
            print("   ", p)
        print("This is exactly the failure a local build cannot see - add them before pushing.")
        return 1
    n_src = len(set(re.findall(r"[A-Za-z0-9_]+\.cpp", text)))
    print(f"cmake-sources-tracked: {n_src} referenced sources; every included header and every "
          f"tools/test_*.py is present in git")
    return 0


if __name__ == "__main__":
    sys.exit(main())
