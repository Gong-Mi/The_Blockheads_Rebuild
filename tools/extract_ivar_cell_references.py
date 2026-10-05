#!/usr/bin/env python3
"""Map every reference to every Objective-C ivar's *offset cell* in the pinned ELF.

Why this exists
---------------
An ivar's runtime offset is not a literal anywhere in the code. `OBJC_IVAR_$_C.name`
denotes a 4-byte *cell* in `__objc_ivar`; the compiler reaches it through a
two-word position-independent idiom whose middle address lands in `.got`, and the
`.got` entry's file contents ARE the cell VA:

    ldr  rA, [pc, #kA]        ; wA - bias word
    ldr  rB, [pc, #kB]        ; wB
    add  rB, pc, rB           ; v = (add_addr + 8) + wB   (== PIC base 0x105faf4)
    ldr  rX, [rA, rB]         ; slot = wA + v      -- a .got entry
    ldr  rX, [rX]             ; the cell VA -> then the runtime offset

so `cell = *(.got slot)` and a reference exists exactly when `*(wA + v)` is a known
cell VA. Every mapped site is then classified by how the offset is consumed:
a load (read), a store (write), or neither (the ivar is passed as a pointer).

This is how "who writes World.fastForward?" gets answered by evidence instead of by
staring at the four classes that seemed likely.

Discipline carried from previous decode bugs in this project:
  * the instruction masks must leave Rd FREE and pin Rn=pc
    ((w & 0xFFFF0000) == 0xE59F0000 / 0xE08F0000). Masking Rd as well silently
    scans only rd=0 instructions and returns zero hits with no error.
  * `--self-check` requires the known positive control (the `- [World worldTime]`
    getter at 0x5d99a4 must reference the World.worldTime cell), and fails the run
    otherwise. Never trust a zero-hit sweep without it.
  * method attribution uses a prologue scan (nearest preceding push-with-lr), and is
    reported as `fn_start`; `method` is filled only when fn_start is exactly a method
    table IMP. Unmatched sites keep method=null rather than a guessed name.

Usage:
  python3 tools/extract_ivar_cell_references.py <libApplication.so> \
      --methods <objc_methods.tsv> [--json OUT] [--tsv OUT] [--self-check] [--ivar Name]
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile

TEXT_LO, TEXT_HI = 0x001C4500, 0x00DB8AA8        # this family's code window
PIC_BASE = 0x105FAF4                            # verified: v resolves to this everywhere
POSITIVE_CONTROL = {"method_imp": 0x005D99A4, "ivar": "World.worldTime",
                    "within": (0x005D99A0, 0x005D99D0)}
LOADS = ("ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "vldr")
STORES = ("str", "strb", "strh", "vstr")


def ldr_pc(w: int, rd: int) -> bool:
    return (w & 0xFFFF0000) == 0xE59F0000 and ((w >> 12) & 0xF) == rd


def add_pc_self(w: int, rd: int) -> bool:
    return (w & 0xFFFF0000) == 0xE08F0000 and ((w >> 12) & 0xF) == rd and (w & 0xF) == rd


def is_push_lr(w: int) -> bool:
    return (w & 0xFFFF0000) == 0xE92D0000 and bool(w & 0x4000)


def prologue_start(blob: bytes, addr: int, lo: int) -> int | None:
    """Nearest preceding push-with-lr, 4 bytes at a time (A32)."""
    a = addr - 4
    while a >= lo:
        if len(blob) >= a + 4 and is_push_lr(struct.unpack_from("<I", blob, a)[0]):
            return a
        a -= 4
    return None


def read_methods(path: Path | None) -> dict[int, str]:
    if not path or not path.is_file():
        return {}
    out = {}
    for line in path.read_text().splitlines()[1:]:
        p = line.split("\t")
        if len(p) >= 2:
            try:
                out[int(p[0], 16)] = f"{p[1]} -[{p[3]}]" if len(p) > 3 else p[1]
            except ValueError:
                continue
    return out


def build_cell_map(e) -> dict[int, str]:
    """cell VA -> 'Class.ivar', from OBJC_IVAR_$_ symbols (the cell is the symbol value)."""
    cells = {}
    for s in e.get_section_by_name(".dynsym").iter_symbols():
        if s.name.startswith("OBJC_IVAR_$_") and s["st_value"]:
            cells[s["st_value"]] = s.name[len("OBJC_IVAR_$_"):]
    return cells


def scan(blob: bytes, cells: dict[int, str], methods: dict[int, str], disasm,
         lo: int = TEXT_LO, hi: int = TEXT_HI) -> tuple[list[dict], dict]:
    W = lambda a: struct.unpack_from("<I", blob, a)[0] if a + 4 <= len(blob) else None
    sites: list[dict] = []
    stats = {"window": [hex(lo), hex(hi)], "add_sites": 0, "slots_checked": 0, "pairs_resolved": 0, "instr_stream_hits": 0}
    for a in range(lo, hi, 4):
        w = W(a)
        if w is None:
            continue
        rd = (w >> 12) & 0xF
        if not add_pc_self(w, rd):
            continue
        stats["add_sites"] += 1
        la = a - 4
        if la < lo or W(la) is None or not ldr_pc(W(la), rd):
            continue
        v = (a + 8 + W(la + 8 + (W(la) & 0xFFF))) & 0xFFFFFFFF
        # The bias word may sit BEFORE the add (the order this tool was written for) or AFTER it: Blockhead
        # -[isMale] computes its base first, loads the bias word second, and only then dereferences. A
        # backwards-only search silently drops that ordering, which is how the ivar that getter reads ended up
        # absent from this tool's own output.
        candidates = list(range(la - 4, max(lo - 4, la - 4 * 240), -4)) + list(range(a + 4, min(hi, a + 4 * 8), 4))
        for b in candidates:
            w2 = W(b)
            if w2 is None:
                continue
            r2 = (w2 >> 12) & 0xF
            if r2 == rd or not ldr_pc(w2, r2):
                continue
            slot = (W(b + 8 + (w2 & 0xFFF)) + v) & 0xFFFFFFFF
            stats["pairs_resolved"] += 1
            cell = W(slot)
            stats["slots_checked"] += 1
            if cell in cells:
                sites.append(classify(blob, a, slot, cell, cells[cell], methods, disasm, lo))
                stats["instr_stream_hits"] += 1
            break
    stats["pic_base_seen"] = sum(1 for s in sites if s.get("pic_base") == PIC_BASE)
    return sites, stats


def classify(blob, add_addr, slot, cell, ivar, methods, disasm, prologue_lo=TEXT_LO) -> dict:
    """How the resolved cell is consumed: read, write, or neither (passed as a pointer).

    Idle shape in this build (register names differ per site, which is the whole point):

        add  rC, pc, rC          ; add_addr - the site; rC holds the cell VA below
        ldr  rT, [rB, rC]        ; the .got slot whose contents are the cell VA
        ldr  rO, [rT]            ; the runtime offset (source = rT, dest may differ)
        add  rF, rObj, rO        ; the field address
        ldr/ldrb/vldr rZ, [rF]   ; read          |
        str/strb/vstr rZ, [rF]   ; write         | neither => pointer-or-unknown
    """
    insns = list(disasm(blob[add_addr:add_addr + 96], add_addr))[:24]
    off_reg = field_reg = None
    access, detail = "pointer-or-unknown", None
    if not insns or insns[0].mnemonic != "add":
        pass
    else:
        add_rd = insns[0].op_str.split(",")[0].strip()
        # 1. the cell VA: destination of the first load that indexes with the add's reg
        cell_idx = None
        for i, ins in enumerate(insns[1:], 1):
            if ins.mnemonic == "ldr" and "," in ins.op_str and add_rd in ins.op_str.split(",", 1)[1]:
                cell_reg, cell_idx = ins.op_str.split(",", 1)[0].strip(), i
                break
        # 2. the offset: `ldr rO, [rCELL]` strictly AFTER that load. It must be searched
        #    from cell_idx+1: when the cell load's destination happens to equal the object
        #    register (ldr r3,[r3,ip]), the cell load itself looks like an offset load and
        #    the real access instruction then gets swallowed by the same branch.
        if cell_idx is not None:
            for i, ins in enumerate(insns[cell_idx + 1:], cell_idx + 1):
                if off_reg is not None:
                    break
                if ins.mnemonic in LOADS and "," in ins.op_str:
                    lhs, _, rhs = ins.op_str.partition(",")
                    if rhs.strip().strip("[]").split(",")[0].strip() == cell_reg:
                        off_reg = lhs.strip()
        # 3a. The FUSED form: the compiler often folds `add rF, rObj, rO` into the access itself, so a
        #     byte flag is written as `strb r3, [r0, r1]` with r1 holding the cell's content and no
        #     separate add anywhere. Requiring that add - which this classifier used to do - silently
        #     files the most common way a flag is SET as "pointer-or-unknown", and that is exactly how a
        #     "0 writers" conclusion gets drawn from a tool gap. Checked before the add form, since a
        #     fused site has no add to find.
        if off_reg and access == "pointer-or-unknown":
            for i, ins in enumerate(insns[cell_idx + 1:], cell_idx + 1):
                if ins.mnemonic in LOADS + STORES and "," in ins.op_str:
                    inner = ins.op_str.partition(",")[2].strip()
                    if inner.startswith("[") and inner.rstrip("]").split(",")[-1].strip() == off_reg:
                        access = "read" if ins.mnemonic in LOADS else "write"
                        detail = f"{ins.mnemonic} {ins.op_str} (fused: offset register is the index)"
                        break
        # 3. the field address, then the first real access through it
        if off_reg:
            for i, ins in enumerate(insns[cell_idx + 1:], cell_idx + 1):
                txt = ins.op_str
                if field_reg is None:
                    if ins.mnemonic == "add" and txt.replace(" ", "").endswith("," + off_reg):
                        field_reg = txt.split(",")[0].strip()
                    continue
                if f"[{field_reg}" in txt and ins.mnemonic in LOADS + STORES:
                    access = "read" if ins.mnemonic in LOADS else "write"
                    detail = f"{ins.mnemonic} {txt}"
                    break
    fn_start = prologue_start(blob, add_addr, prologue_lo)
    inside = sorted((imp, name) for imp, name in methods.items()
                    if fn_start is not None and fn_start <= imp <= add_addr)
    return {"add_site": hex(add_addr), "got_slot": hex(slot), "cell": hex(cell),
            "ivar": ivar, "access": access, "site_instruction": detail,
            "fn_start": hex(fn_start) if fn_start else None,
            "method": methods.get(fn_start) if fn_start in methods else None,
            "method_entries_in_range": [{"imp": hex(i), "method": n} for i, n in inside],
            "attribution": ("unique" if len(inside) == 1 else "none" if not inside else "ambiguous"),
            "pic_base": PIC_BASE}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("libapplication")
    ap.add_argument("--methods", type=Path, default=None)
    ap.add_argument("--json", type=Path, default=None)
    ap.add_argument("--tsv", type=Path, default=None)
    ap.add_argument("--self-check", action="store_true")
    ap.add_argument("--ivar", default=None, help="restrict the report to one Class.ivar")
    args = ap.parse_args()

    p = Path(args.libapplication)
    blob = p.read_bytes()
    with p.open("rb") as fh:
        e = ELFFile(fh)
        cells = build_cell_map(e)
    methods = read_methods(args.methods)

    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    disasm = md.disasm

    sites, stats = scan(blob, cells, methods, disasm)

    # --- positive control: a zero-hit sweep is not a result without this ---------
    ctrl = [s for s in sites if s["ivar"] == POSITIVE_CONTROL["ivar"]
            and POSITIVE_CONTROL["within"][0] <= int(s["add_site"], 16) <= POSITIVE_CONTROL["within"][1]]
    control_ok = bool(ctrl)
    if args.self_check and not control_ok:
        print(json.dumps({"self_check": "FAILED", "reason": "known getter reference not found",
                          "stats": stats}, indent=1))
        return 1

    by_ivar: dict[str, list[dict]] = {}
    for s in sites:
        by_ivar.setdefault(s["ivar"], []).append(s)

    report = {
        "schema": 1,
        "elf_sha256": __import__("hashlib").sha256(blob).hexdigest(),
        "mechanism": "ivar offset cell reached via a .got entry whose file contents are the cell VA",
        "text_window": [hex(TEXT_LO), hex(TEXT_HI)],
        "ivar_symbols": len(cells),
        "self_check": {"positive_control": POSITIVE_CONTROL, "passed": control_ok},
        "stats": stats,
        "ivars_with_references": len(by_ivar),
        "reference_counts": {k: len(v) for k, v in sorted(by_ivar.items())},
        "sites": sites,
    }
    if args.ivar:
        report["restricted_to"] = args.ivar
        report["restricted_sites"] = by_ivar.get(args.ivar, [])

    if args.tsv:
        with args.tsv.open("w") as fh:
            fh.write("ivar\tcell\tgot_slot\tadd_site\taccess\tfn_start\tmethod\tsite_instruction\n")
            for s in sites:
                fh.write("\t".join(str(s[k]) for k in
                                   ("ivar", "cell", "got_slot", "add_site", "access",
                                    "fn_start", "method", "site_instruction")) + "\n")
    payload = json.dumps(report, indent=2) + "\n"
    if args.json:
        args.json.write_text(payload)
    else:
        print(f"ivars with references: {len(by_ivar)} / {len(cells)}  sites: {len(sites)}")
        print(f"self-check: {'pass' if control_ok else 'FAIL'}")
        for name, lst in sorted(by_ivar.items()):
            kinds = {}
            for s in lst:
                kinds[s["access"]] = kinds.get(s["access"], 0) + 1
            print(f"  {name:44s} {len(lst):3d}  {kinds}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
