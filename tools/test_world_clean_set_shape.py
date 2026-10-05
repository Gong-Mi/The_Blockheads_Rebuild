#!/usr/bin/env python3
"""Contract test: re-measure the branch shape of the clean set.

`unicorn-clean` is used to decide what to execute next, so the claim that it means "straight-line
accessor" must be measured, not asserted. This recounts conditional branches over every World method
and fails if a clean method has one - or if the needs-runtime row stops containing the logic.

Excluding `bx lr` is the whole point: it is a return, and counting it would make almost every method
look branchy.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "reconstruction/reverse-v3/native/world_clean_set_shape.json"
COND = {"beq", "bne", "bgt", "blt", "bge", "ble", "bhi", "bls", "bcs", "bcc", "bmi", "bpl", "bvs",
        "bvc", "cbz", "cbnz"}


def main() -> int:
    pinned = Path(os.environ.get("BH_ELF",
                  ROOT.parent.parent / "extracted/lib/armeabi-v7a/libApplication.so"))
    if not pinned.is_file():
        print("skip: pinned ELF not present")
        return 0
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    blob = pinned.read_bytes()
    rep = json.loads(ART.read_text())
    for row in rep["methods"]:
        imp = int(row["imp"], 16)
        # the artifact stores counts, not bodies; re-measure over the recorded span
        span = max(row["instructions"] * 4, 16)
        insns = list(md.disasm(blob[imp:imp + span], imp))
        got = sum(1 for i in insns if i.mnemonic in COND)
        if row["verdict"] == "unicorn-clean":
            assert got == 0, f"{row['selector']} now has {got} conditional branch(es): {row['imp']}"
        assert row["conditional_branches"] == 0 or row["verdict"] == "needs-runtime", row
    assert rep["counts"]["clean_with_conditionals"] == 0
    assert rep["counts"]["live_with_conditionals"] > 0, "the logic must be somewhere"
    print(f"clean set: {rep['counts']['clean']} methods, 0 conditional branches; "
          f"live set: {rep['counts']['live']} methods, {rep['counts']['live_with_conditionals']} with logic")
    return 0


if __name__ == "__main__":
    sys.exit(main())
