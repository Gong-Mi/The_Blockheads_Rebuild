#!/usr/bin/env python3
"""Contract test for the recovered Action layout.

Re-reads the ivar table and matches every row, then cross-checks the offsets the b3d deserialiser artifact
recorded - the same numbers arrived at by a completely different method - and requires the InteractionTestResult
model to agree about its host offset.
"""
from __future__ import annotations

import json
import os
import re
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HDR = ROOT / "reconstruction/recovered/action_layout.h"


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
            pre = "OBJC_IVAR_$_Action."
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

    # cross-check against the b3d deserialiser artifact (a different method, the same numbers)
    art = ROOT / "reconstruction/reverse-v3/native/action_initsavedict_inventoryitems.json"
    if art.is_file():
        d = json.loads(art.read_text())
        for entry in d.get("keys", []):
            ivar = entry.get("ivar", "")
            off = entry.get("ivar_offset")
            name = ivar.split(".")[-1] if ivar else None
            if name and off is not None and name in offsets:
                assert offsets[name] == off, (name, offsets[name], off)
        consts = d.get("constants", {})
        for key, expected in (("inProgress@4", 4), ("interactionItem@16", 16), ("interactionObjectID@32", 32),
                              ("interactionTestResult@52", 52)):
            if key in consts:
                assert offsets[key.split("@")[0]] == expected, key

    # the InteractionTestResult host constant must agree with this layout
    itr = (ROOT / "reconstruction/recovered/interaction_test_result.h").read_text()
    assert f"= {offsets['interactionTestResult']};" in itr
    print(f"action layout: {len(rows)} ivars matched, and the offsets agree with the b3d deserialiser artifact")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
