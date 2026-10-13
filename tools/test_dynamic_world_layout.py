#!/usr/bin/env python3
"""Contract test for the recovered DynamicWorld layout: re-read the ivar table and match every row."""
from __future__ import annotations

import os
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HDR = ROOT / "reconstruction/recovered/dynamic_world_layout.h"


def main() -> int:
    pinned = Path(os.environ.get("BH_ELF",
                  ROOT.parent.parent / "extracted/lib/armeabi-v7a/libApplication.so"))
    if not pinned.is_file():
        print("skip: pinned ELF not present")
        return 0
    from elftools.elf.elffile import ELFFile
    blob = pinned.read_bytes()
    rows = []
    with pinned.open("rb") as fh:
        for s in ELFFile(fh).get_section_by_name(".dynsym").iter_symbols():
            pre = "OBJC_IVAR_$_DynamicWorld."
            if s.name.startswith(pre) and s["st_value"]:
                rows.append((struct.unpack_from("<i", blob, s["st_value"])[0], s.name[len(pre):],
                             s["st_value"]))
    rows.sort()
    hdr = HDR.read_text()
    got = [(int(o), n, int(c, 16)) for o, n, c in
           re.findall(r'^\s*\{(\d+), "([^"]+)", (0x[0-9a-f]+)U\},$', hdr, re.M)]
    assert len(got) == len(rows), (len(got), len(rows))
    for a, b in zip(got, rows):
        assert a == b, (a, b)
    offsets = {n: o for o, n, _ in rows}
    assert offsets["dynamicObjects"] == 60
    assert offsets["dynamicObjectsToAdd"] - offsets["dynamicObjects"] == 780
    assert offsets["dynamicObjectsByWorldPosIndex"] - offsets["dynamicObjectsToAdd"] == 780
    print(f"dynamic world layout: {len(rows)} ivars re-read and matched, container stride 780 asserted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
