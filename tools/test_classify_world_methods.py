#!/usr/bin/env python3
"""Contract test for tools/classify_world_methods.py.

The classification decides what can be executed and what is declared live-only, so the test pins the
rule's consequences rather than the numbers alone:

  * the three execution-verified methods must land on their known verdicts (the same controls the tool
    enforces - duplicated here so a broken in-tool check cannot silently pass);
  * a "unicorn-clean" row must have zero calls outside the method table, and a "needs-runtime" row must
    have at least one objc_msgSend/unidentified call - the rule applied to its own output;
  * the counts must add up to the row count.

Self-skips when the pinned ELF is absent.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "reconstruction/reverse-v3/native/world_method_classification.json"


def main() -> int:
    src = (ROOT / "tools/classify_world_methods.py").read_text()
    assert "SELF_CHECK" in src and "needs-runtime" in src
    pinned = Path(os.environ.get("BH_ELF",
                  ROOT.parent.parent / "extracted/lib/armeabi-v7a/libApplication.so"))
    if not pinned.is_file():
        print("skip: pinned ELF not present")
        return 0
    run = subprocess.run([sys.executable, str(ROOT / "tools/classify_world_methods.py"),
                          str(pinned), "--methods",
                          str(ROOT / "reconstruction/reverse-v3/native/libApplication_objc_methods.tsv"),
                          "--self-check"], capture_output=True, text=True)
    assert run.returncode == 0, run.stdout[-500:] + run.stderr[-500:]
    rep = json.loads(ART.read_text())
    counts = rep["counts"]
    assert counts["unicorn-clean"] + counts["unicorn-with-abstraction"] + counts["needs-runtime"] \
        == counts["methods"], counts
    for m in rep["methods"]:
        cats = {c[0] for c in m["call_categories"]}
        if m["verdict"] == "unicorn-clean":
            assert not (cats & {"objc-msgSend", "unidentified"}), m
        elif m["verdict"] == "needs-runtime":
            assert cats & {"objc-msgSend", "unidentified"}, m
    by = {m["selector"]: m["verdict"] for m in rep["methods"]}
    assert by.get("fastForward") == "unicorn-clean", by.get("fastForward")
    assert by.get("doubleTimeUnlocked") == "unicorn-clean"
    assert by.get("worldTime") == "unicorn-with-abstraction"
    print(f"classification consistent: {counts['unicorn-clean']} clean, "
          f"{counts['unicorn-with-abstraction']} with abstraction, {counts['needs-runtime']} live-only")
    return 0


if __name__ == "__main__":
    sys.exit(main())
