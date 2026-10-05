#!/usr/bin/env python3
"""Contract test for the recovered UIManager layout (generated): re-read the ivar table and match every row.

The rule for what a row looks like lives in the generator, not here, so the two cannot drift apart.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ROW = re.compile(r'^\s*\{(\d+), "([^"]+)", (0x[0-9a-f]+)U\},$', re.M)


def main() -> int:
    if not (ROOT / "tools/gen_layout_model.py").is_file():
        print("skip: generator not present")
        return 0
    pinned = Path(os.environ.get("BH_ELF", ROOT.parent.parent / "extracted/lib/armeabi-v7a/libApplication.so"))
    if not pinned.is_file():
        print("skip: pinned ELF not present")
        return 0
    sys.path.insert(0, str(ROOT / "tools"))
    from gen_layout_model import read_table

    rows = read_table(pinned, "UIManager")
    hdr = (ROOT / "reconstruction/recovered/u_i_manager_layout.h").read_text()
    got = [(int(o), n, int(c, 16)) for o, n, c in ROW.findall(hdr)]
    assert len(got) == len(rows), (len(got), len(rows))
    for x, y in zip(got, rows):
        assert x == y, (x, y)
    print(f"u_i_manager layout: {len(rows)} ivars matched")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
