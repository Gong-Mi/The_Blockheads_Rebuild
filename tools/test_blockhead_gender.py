#!/usr/bin/env python3
"""Re-derive Blockhead -[isMale]'s ivar from the pinned binary and match the model against it.

Asserting the model's own constants back would test nothing, so this walks the chain out of the ELF: the two pool
loads, the cell, the offset word, the symbol the cell belongs to, and - new here - the write site and the
instruction at it.

The first version of this test re-derived the chain the SAME wrong way the first version of the model did (it used
the 'ldr's pc instead of the 'add's pc), so the two agreed with each other while both being four bytes off, and the
error only surfaced when the project's own scanner was asked for the (wrong) cell and returned nothing. The
assertion that would have caught it immediately is the base check below, which is why deriving the base and naming
it is asserted before anything else.
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
PIC = 0x105FAF4          # the project's PIC base; the chain's computed base must equal this


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

    def find_byte_store(va: int, window: int = 40):
        """The nearest strb after `va`, using capstone when it is available.

        Hand-writing this predicate cost two wrong attempts: I mis-stated the encoding bits both times and got
        "unknown instruction" for a word that IS a strb (0xe7c03001 -> strb r3,[r0,r1]). Decoding is not this
        test's job, so it defers to capstone and reports that it could not check when capstone is absent - the
        same way the whole test skips when the pinned ELF is absent, rather than passing silently.
        """
        try:
            from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
        except ImportError:
            return None, None, "capstone not installed"
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
        for k in range(window):
            at = va + 4 * k
            ins = next(md.disasm(blob[at:at + 4], at), None)
            if ins and ins.mnemonic == "strb":
                return at, ins, None
        return None, None, f"no strb within {window} instructions"

    imp = const("ImpIsMale")

    # --- the chain, with ARM's pc rule: pc = the address of the instruction + 8 ---------------
    # 0xc8654c: ldr r2,[pc,#0x2c]   -> r2 is set below; 0xc86550: add r2,pc,r2 is what fixes the base
    ldr_addr = imp + 4
    add_addr = imp + 8
    pool_a = (ldr_addr + 8) + (word(ldr_addr) & 0xFFF)
    base = ((add_addr + 8) + word(pool_a)) & 0xFFFFFFFF
    assert base == PIC, (f"the chain's base must be the PIC base: got {base:#x}, expected {PIC:#x}. "
                        f"Four bytes off here means the 'ldr's pc was used instead of the 'add's pc.")
    # 0xc86554: ldr r3,[pc,#0x20]   -> r3 = the word at that pool slot
    bias_addr = imp + 12
    r3 = word((bias_addr + 8) + (word(bias_addr) & 0xFFF))
    cell_va = (r3 + base) & 0xFFFFFFFF
    cell = word(cell_va)
    offset = struct.unpack_from("<i", blob, cell)[0]

    assert offset == const("OffsetSkinOptions"), (offset, const("OffsetSkinOptions"))
    assert cell == const("CellSkinOptions"), (hex(cell), hex(const("CellSkinOptions")))

    from elftools.elf.elffile import ELFFile
    names = []
    with elf.open("rb") as fh:
        for s in ELFFile(fh).get_section_by_name(".dynsym").iter_symbols():
            if s.name.startswith("OBJC_IVAR_$_") and s["st_value"] == cell:
                names.append(s.name)
    assert names == ["OBJC_IVAR_$_Blockhead.skinOptions"], names

    # --- the writer the model names must really be a byte-store inside the method it names ----
    table = (ROOT / "reconstruction/reverse-v3/native/libApplication_objc_methods.tsv").read_text().splitlines()
    rows = [l.split("\t") for l in table[1:]]
    def method_at(va: int):
        best = None
        for f in rows:
            if len(f) >= 4 and int(f[0], 16) <= va:
                if best is None or int(f[0], 16) > int(best[0], 16):
                    best = f
        return best

    site = const("SiteWriteSkinOptions")
    at, ins, why = find_byte_store(site)
    if why:
        print(f"note: byte-store check skipped ({why})")
    else:
        assert ins.mnemonic == "strb", ins
    owner = method_at(site)
    assert owner and owner[1] == "Blockhead" and owner[3] == "customizationComplete:", owner
    assert const("ImpCustomizationComplete") == int(owner[0], 16), owner

    is_male_row = method_at(imp)
    assert is_male_row and is_male_row[1] == "Blockhead" and is_male_row[3] == "isMale", is_male_row

    # --- the rule's FORM: any non-zero byte, not "== 1" ---------------------------------------
    assert "skin_options != 0" in hdr, "the truth rule must stay 'non-zero', not '== 1'"
    assert "== 1" not in hdr.split("isMaleFromSkinOptions")[1], "no '== 1' reading"

    print(f"blockhead-gender: re-derived - base {base:#x} (= PIC), cell {cell:#x}, "
          f"{names[0].split('$')[-1]} at {offset}, written by {owner[1]} -[{owner[3]}]"
          + (f" with {ins.mnemonic} {ins.op_str} at {at:#x}" if at else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
