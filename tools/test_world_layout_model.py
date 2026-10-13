#!/usr/bin/env python3
"""Contract test for the recovered World layout model.

The model is only worth having if it is re-read rather than trusted: this walks the binary's own
OBJC_IVAR_$_World.* cells and requires the header to carry exactly those (offset, name, cell) rows, and
that the header's own compile-time ordering claim is true of what came out of the binary.
"""
from __future__ import annotations

import os
import re
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HDR = ROOT / "reconstruction/recovered/world_layout.h"


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
            pre = "OBJC_IVAR_$_World."
            if s.name.startswith(pre) and s["st_value"]:
                rows.append((struct.unpack_from("<i", blob, s["st_value"])[0], s.name[len(pre):],
                             s["st_value"]))
    rows.sort()
    hdr = HDR.read_text()
    got = [(int(o), n, int(c, 16)) for o, n, c in
           re.findall(r'^\s*\{(\d+), "([^"]+)", (0x[0-9a-f]+)\},$', hdr, re.M)]
    assert len(got) == len(rows), (len(got), len(rows))
    for (o, n, c), (o2, n2, c2) in zip(got, rows):
        assert (o, n, c) == (o2, n2, c2), ((o, n, hex(c)), (o2, n2, hex(c2)))
    assert all(got[i][0] < got[i + 1][0] for i in range(len(got) - 1)), "offsets must be strictly rising"
    print(f"world layout: {len(rows)} ivars re-read and matched exactly")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
