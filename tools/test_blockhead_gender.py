#!/usr/bin/env python3
"""Re-derive Blockhead -[isMale]'s ivar from the pinned binary and match the model against it.

The model file blockhead_gender.h states three things: an IMP, an ivar cell and an offset, plus the truth rule.
Asserting those constants back would be worthless. So this walks the same cell chain out of the ELF - the two pool
loads, the cell, the offset word - and requires the model to agree, which means a wrong constant, a wrong reading of
the chain, or a changed binary all fail here.

It also pins the truth rule's FORM, not just its intent: the original returns a signed byte and callers branch on
its truth, so any non-zero value means male. "== 1" is the reading this project got wrong once already for the
DynamicObject flags, and a rule written that way would still look right in a comment.
"""
from __future__ import annotations

import os
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ELF = ROOT.parent.parent / "extracted/lib/armeabi-v7a/libApplication.so"
HDR = ROOT / "reconstruction/recovered/blockhead_gender.h"
PIC = 0x105FAF4          # the project's PIC base, used by every cell-chain derivation


def main() -> int:
    elf = Path(os.environ.get("BH_ELF", DEFAULT_ELF))
    if not elf.is_file():
        print("skip: pinned ELF not present")
        return 0
    blob = elf.read_bytes()
    hdr = HDR.read_text()

    def const(name: str) -> int:
        m = re.search(rf"k{name}\s*=\s*(0x[0-9a-fA-F]+|\d+)", hdr)
        assert m, f"constant k{name} missing from {HDR.name}"
        return int(m.group(1), 0)

    def word(va: int) -> int:
        return struct.unpack_from("<I", blob, va)[0]

    imp = const("ImpIsMale")
    # the getter's first two pool loads, read straight at the addresses the disassembly shows
    # 0xc8654c is imp+4: ldr r2,[pc,#0x2c] ; add r2,pc,r2
    a1 = imp + 4
    r2 = ((a1 + 8) + word(a1 + 8 + 0x2C)) & 0xFFFFFFFF
    # 0xc86554 is imp+12: ldr r3,[pc,#0x20]
    a2 = imp + 12
    r3 = word(a2 + 8 + 0x20)
    cell_va = (r3 + r2) & 0xFFFFFFFF
    cell = word(cell_va)
    offset = struct.unpack_from("<i", blob, cell)[0]

    assert r2 == PIC - 4, f"the first load should land on the PIC region minus 4, got {r2:#x}"
    assert offset == const("OffsetShoesCube"), (offset, const("OffsetShoesCube"))
    assert cell == const("CellShoesCube"), (hex(cell), hex(const("CellShoesCube")))

    # and the cell must belong to the ivar the model names
    from elftools.elf.elffile import ELFFile
    names = []
    with elf.open("rb") as fh:
        for s in ELFFile(fh).get_section_by_name(".dynsym").iter_symbols():
            if s.name.startswith("OBJC_IVAR_$_") and s["st_value"] == cell:
                names.append(s.name)
    assert names == ["OBJC_IVAR_$_Blockhead.shoesCube"], names

    # the IMP must be the table's entry for Blockhead -[isMale]
    table = (ROOT / "reconstruction/reverse-v3/native/libApplication_objc_methods.tsv").read_text().splitlines()
    want = f"{imp:#010x}"
    rows = [l.split("\t") for l in table[1:] if l.split("\t")[0].lower() == want]
    assert len(rows) == 1 and rows[0][1] == "Blockhead" and rows[0][3] == "isMale", rows

    # the rule's FORM: any non-zero byte, not "== 1"
    assert "shoes_cube != 0" in hdr, "the truth rule must stay 'non-zero', not '== 1'"
    assert "!= 0" in hdr and "== 1" not in hdr.split("isMaleFromShoesCube")[1], "no '== 1' reading"

    print(f"blockhead-gender: re-derived from the binary - {imp:#x} reads "
          f"{names[0].split('$_')[-1]} at {offset} (cell {cell:#x}), truth rule non-zero")
    return 0


if __name__ == "__main__":
    sys.exit(main())
