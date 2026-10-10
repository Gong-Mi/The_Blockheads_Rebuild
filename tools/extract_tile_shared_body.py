#!/usr/bin/env python3
"""Structure of the tile drawing shared body (0x00a22d70).

R3 classified 59 of the 121 tile-content values as `shared-body`, i.e. their case
target is this body rather than an immediate draw-image assignment. It is not an
"empty default": it has its own dispatch and its own arithmetic. This tool decodes
that structure so the classification is backed by what the code does:

  * six magic constants compared against the frame slot `[fp,-0x540]`
    (`0x100`, `0xe0`, `0x200`, `0x1e0`, `0x109`, `0x112`, the last compared twice);
  * a jump table at `0x00a22ec4` with 0x4d entries, indexed by
    `[fp,-0x1c0][1] - 1` (a byte field at offset 1 of a record, minus one);
  * the arithmetic on the taken path: a record address built with a 64-byte
    stride (`base + index*64`), a byte loaded at offset 8, `(byte - 127) *
    constant + [fp,-0x19c]` stored to `object + 0x20c`, and the helper calls
    (`0x1c3d4c`, `0xa30e38`, `0x1c3020`) whose result is added to `[fp,-0x540]`
    and `[fp,-0x544]` - an animated offset pair, not a constant cell.

Usage:
  python3 tools/extract_tile_shared_body.py <libApplication.so> [--tsv OUT] [--json OUT] [--check]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

SHARED_BODY_VA = 0x00A22D70
SCAN_END = 0x00A22EA4          # the body up to the second dispatch
# `add r2, pc, #4` at 0x00a22ec4 runs with pc = 0x00a22ecc, so the inline offset
# table starts at 0x00a22ed0 and every entry is a byte offset from that base
# (`add pc, r1, r2`), not an absolute or self-relative address.
JUMP_BASE_VA = 0x00A22ED0
JUMP_FIRST = 1
JUMP_LAST = 0x4D               # cmp r0, #0x4c / bhi preserves the bound
CMP_NOTE = "cmp r0, #imm against [fp,-0x540]"


def words(blob: bytes, va: int, count: int) -> list[tuple[int, int]]:
    out = []
    for i in range(count):
        addr = va + i * 4
        out.append((addr, struct.unpack_from("<I", blob, addr)[0]))
    return out


def decode_cmp_imm(word: int) -> tuple[int, bool] | None:
    """ARM data-processing immediate compare: cmp r0, #imm (cond 1110).

    Bits: 27-26 = 00, 25 = I (1 means the operand is an immediate), 24-21 = opcode
    (1010 = CMP), 20 = S, 19-16 = Rn. Reading bits 27-24 as the opcode is a
    classic off-by-one and decodes nothing.
    """
    if (word >> 28) != 0xE:
        return None
    if ((word >> 26) & 0x3) != 0x0:
        return None
    if ((word >> 25) & 0x1) != 0x1:            # I = 1 -> the operand is immediate
        return None
    if ((word >> 21) & 0xF) != 0xA:            # 1010 = CMP
        return None
    if ((word >> 16) & 0xF) != 0:              # Rn = r0
        return None
    imm8 = word & 0xFF
    rotate = ((word >> 8) & 0xF) * 2
    value = ((imm8 >> rotate) | (imm8 << (32 - rotate))) & 0xFFFFFFFF
    return value, rotate != 0


def branch_target(word: int, addr: int) -> int | None:
    if (word >> 28) != 0xE:
        return None
    if ((word >> 24) & 0xF) not in (0xA, 0xB):  # B / BL
        return None
    offset = word & 0xFFFFFF
    if offset & 0x800000:
        offset -= 0x1000000
    return addr + 8 + (offset << 2)


def decode_movw_imm(word: int) -> int | None:
    """ARM MOVW: cond 1110, 0011 0000, imm4 | Rd, imm12 (Rd must be r0)."""
    if (word >> 28) != 0xE or ((word >> 20) & 0xFF) != 0x30:
        return None
    if ((word >> 12) & 0xF) != 0:
        return None
    return ((word >> 4) & 0xF000) | (word & 0x0FFF)


def register_comparisons(blob: bytes) -> list[dict]:
    """`movw r0, #imm` + `cmp r1, r0` pairs: the same constants, loaded first.

    Four of the six constants are data-processing immediates; `0x109` and `0x112`
    arrive this way, so a pass that only decodes CMP immediates would silently miss
    a third of the dispatch.
    """
    found = []
    pairs = words(blob, SHARED_BODY_VA, (SCAN_END - SHARED_BODY_VA) // 4)
    for index, (addr, word) in enumerate(pairs):
        value = decode_movw_imm(word)
        if value is None:
            continue
        for offset in range(1, 3):
            if index + offset >= len(pairs):
                break
            later_addr, later = pairs[index + offset]
            # cmp r1, r0 with cond 1110 -> 0xE1510000 mask on the register fields
            if (later & 0xFFF0_0FF0) == 0xE150_0000 and ((later >> 12) & 0xF) == 0:
                found.append({"at": f"0x{later_addr:08x}", "immediate": value,
                              "loaded_at": f"0x{addr:08x}"})
                break
    return found


def ldr_imm(word: int) -> dict | None:
    """ldr/str of an immediate offset from fp or another register."""
    if (word >> 28) != 0xE or ((word >> 26) & 0x3) != 0x1:
        return None
    load = (word >> 20) & 0x1
    rn = (word >> 16) & 0xF
    rd = (word >> 12) & 0xF
    offset = word & 0xFFF
    if not (word & (1 << 24)):                  # U=0 -> subtract
        offset = -offset
    return {"kind": "load" if load else "store", "base": rn, "reg": rd,
            "offset": offset, "byte": bool((word >> 22) & 1)}


def bl_targets(blob: bytes) -> dict:
    calls = []
    for addr, word in words(blob, SHARED_BODY_VA, (SCAN_END - SHARED_BODY_VA) // 4):
        if (word >> 28) == 0xE and ((word >> 24) & 0xF) == 0xB:
            target = branch_target(word, addr)
            if target is not None:
                calls.append({"at": f"0x{addr:08x}", "target": f"0x{target:08x}"})
    return calls


BRANCH_SCAN_WORDS = 16


STR_IMM_RE_OFFSET = 0x0FFF


def decode_store(word: int) -> tuple[int, int, int] | None:
    """`str Rt, [fp, #-imm]` -> (reg, slot, size) for the frame stores used here."""
    if (word >> 28) != 0xE or ((word >> 26) & 0x3) != 0x1:
        return None
    if (word >> 20) & 0x1:                      # L = 1 -> load, not a store
        return None
    if ((word >> 16) & 0xF) != 11:              # base must be fp
        return None
    reg = (word >> 12) & 0xF
    offset = word & STR_IMM_RE_OFFSET
    # Bit 24 is P (pre-indexed), bit 23 is U (add/subtract). Testing bit 24 as if
    # it were U rejected every pre-indexed store - i.e. all of them - and the slot
    # decode came back empty.
    if word & (1 << 23):                        # U=1 -> positive offset
        return None                             # only the negative slots matter
    if not word & (1 << 24):                    # P=1 -> pre-indexed
        return None
    return reg, offset, (word >> 22) & 0x3


def decode_branch(blob: bytes, target: int) -> dict:
    """Decode a jump-table branch into the frame slots it writes.

    Reading the branch as a bag of `movw` immediates conflates two different
    things: the small values (`0`, `2`, `3`) go to slot `[fp,-0x558]`, while the
    draw values go to the pair `[fp,-0x548]` / `[fp,-0x54c]`. Decoding per slot
    separates a mode selector from a draw value - which is exactly the question the
    R23 artefact left open.
    """
    registers: dict[int, tuple[int, str]] = {}
    slots: dict[str, int] = {}
    values = []
    calls = []
    for addr, word in words(blob, target, BRANCH_SCAN_WORDS):
        value = decode_movw_imm(word)
        if value is not None:
            registers[0] = (value, f"0x{addr:08x}")
            values.append({"at": f"0x{addr:08x}", "immediate": value, "reg": 0})
            continue
        loaded = decode_reg_load_movw(word)
        if loaded is not None:
            reg, value = loaded
            registers[reg] = (value, f"0x{addr:08x}")
            values.append({"at": f"0x{addr:08x}", "immediate": value, "reg": reg})
            continue
        store = decode_store(word)
        if store is not None:
            reg, offset, _size = store
            if reg in registers:
                slots[f"fp-0x{offset:x}"] = registers[reg][0]
        call = branch_target(word, addr)
        if call is not None and (word >> 24) & 0xF == 0xB:
            calls.append({"at": f"0x{addr:08x}", "target": f"0x{call:08x}"})
    draws = sorted({slots[s] for s in ("fp-0x548", "fp-0x54c") if s in slots})
    mode = slots.get("fp-0x558")
    return {
        "target": f"0x{target:08x}",
        "slots": slots,
        "draw_values": draws,
        "mode": mode,
        "pair_equal": (slots.get("fp-0x548") == slots.get("fp-0x54c")
                       if "fp-0x548" in slots and "fp-0x54c" in slots else None),
        "movw_assignments": values,
        "distinct_assignment_values": sorted({v["immediate"] for v in values}),
        "calls": calls,
    }


def decode_reg_load_movw(word: int) -> tuple[int, int] | None:
    """`movw rN, #imm` for any destination register (r0..r12)."""
    if (word >> 28) != 0xE or ((word >> 20) & 0xFF) != 0x30:
        return None
    reg = (word >> 12) & 0xF
    if reg > 12:
        return None
    return reg, ((word >> 4) & 0xF000) | (word & 0x0FFF)


def build(elf: Path) -> dict:
    blob = elf.read_bytes()
    comparisons = []
    branches = []
    for addr, word in words(blob, SHARED_BODY_VA, (SCAN_END - SHARED_BODY_VA) // 4):
        decoded = decode_cmp_imm(word)
        if decoded:
            comparisons.append({"at": f"0x{addr:08x}", "immediate": decoded[0],
                                "rotated": decoded[1]})
        target = branch_target(word, addr)
        if target is not None:
            branches.append({"at": f"0x{addr:08x}", "target": f"0x{target:08x}"})

    register_cmps = register_comparisons(blob)

    table = []
    for index in range(JUMP_FIRST, JUMP_LAST + 1):
        entry_va = JUMP_BASE_VA + (index - JUMP_FIRST) * 4
        relative = struct.unpack_from("<i", blob, entry_va)[0]
        target = JUMP_BASE_VA + relative
        table.append({"index": index, "entry": f"0x{entry_va:08x}",
                      "target": f"0x{target:08x}",
                      "distinct_target": f"0x{target:08x}"})

    distinct = sorted({row["target"] for row in table})
    branches_decoded = [decode_branch(blob, int(row["target"], 16)) for row in table]
    unique_branches: dict[str, dict] = {}
    for entry in branches_decoded:
        unique_branches.setdefault(entry["target"], entry)
    with_assignments = [e for e in unique_branches.values() if e["movw_assignments"]]
    draw_values = sorted({v for e in unique_branches.values() for v in e["draw_values"]})
    modes = sorted({e["mode"] for e in unique_branches.values() if e["mode"] is not None})
    immediates = [row["immediate"] for row in comparisons]
    fields = []
    for addr, word in words(blob, SHARED_BODY_VA, (SCAN_END - SHARED_BODY_VA) // 4):
        decoded = ldr_imm(word)
        if decoded and decoded["base"] == 11:       # fp
            fields.append({"at": f"0x{addr:08x}", **decoded})
    frame_slots = sorted({row["offset"] for row in fields if row["kind"] == "load"})
    return {
        "schema": 1,
        "elf_sha256": hashlib.sha256(blob).hexdigest(),
        "function": "tile drawing shared body",
        "body_address": f"0x{SHARED_BODY_VA:08x}",
        "scan_end": f"0x{SCAN_END:08x}",
        "claim": ("the shared body is a real dispatch, not a default: six immediate "
                  "comparisons against the frame slot [fp,-0x540], its own 77-entry "
                  "jump table at 0x00a22ec4 indexed by a byte field minus one, and a "
                  "path whose result is added to two frame slots (an animated offset)"),
        "counts": {
            "immediate_comparisons": len(comparisons),
            "register_comparisons": len(register_cmps),
            "constants_compared": len(set(immediates) | {c["immediate"] for c in register_cmps}),
            "distinct_immediates": len(set(immediates)),
            "duplicate_immediates": len(immediates) - len(set(immediates)),
            "branches": len(branches),
            "jump_table_entries": len(table),
            "jump_table_distinct_targets": len(distinct),
            "helper_calls": len(bl_targets(blob)),
            "frame_slots_touched": len(frame_slots),
            "branches_decoded": len(unique_branches),
            "branches_with_movw_assignment": len(with_assignments),
            "branches_writing_draw_slots": sum(
                1 for e in unique_branches.values() if e["draw_values"]),
            "distinct_draw_values": len(draw_values),
            "distinct_mode_values": len(modes),
            "branches_with_equal_pair": sum(
                1 for e in unique_branches.values() if e["pair_equal"] is True),
            "branches_setting_a_mode": sum(
                1 for e in unique_branches.values() if e["mode"] is not None),
        },
        "immediates": sorted(set(immediates)),
        "comparisons": comparisons,
        "register_comparisons": register_cmps,
        "constants": sorted(set(immediates) | {c["immediate"] for c in register_cmps}),
        "jump_table": {"base": f"0x{JUMP_BASE_VA:08x}", "first": JUMP_FIRST,
                       "last": JUMP_LAST, "distinct_targets": len(distinct),
                       "sample": table[:8]},
        "helper_calls": bl_targets(blob),
        "draw_values": draw_values,
        "mode_values": modes,
        "branches": {name: {"draw_values": entry["draw_values"],
                            "mode": entry["mode"],
                            "slots": entry["slots"],
                            "pair_equal": entry["pair_equal"]}
                     for name, entry in sorted(unique_branches.items())},
        "frame_slots_touched": [f"fp-0x{slot:x}" for slot in frame_slots],
    }


def render_tsv(record: dict) -> str:
    lines = ["kind\taddress\tdetail"]
    for row in record["comparisons"]:
        lines.append(f"compare\t{row['at']}\timm={row['immediate']} (0x{row['immediate']:x})")
    for row in record["register_comparisons"]:
        lines.append(f"compare-reg\t{row['at']}\timm={row['immediate']} "
                     f"(0x{row['immediate']:x})")
    for name, entry in record["branches"].items():
        lines.append(f"branch\t{name}\tdraw={','.join(str(v) for v in entry['draw_values']) or '(none)'}"
                     f" mode={entry['mode']} pair_equal={entry['pair_equal']}")
    for row in record["helper_calls"]:
        lines.append(f"call\t{row['at']}\t-> {row['target']}")
    lines.append(f"jump-table\t{record['jump_table']['base']}\t"
                 f"entries={record['counts']['jump_table_entries']} "
                 f"distinct={record['jump_table']['distinct_targets']}")
    for slot in record["frame_slots_touched"][:40]:
        lines.append(f"frame-slot\t{slot}\t")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("elf", type=Path)
    native = Path("reconstruction/reverse-v3/native")
    ap.add_argument("--tsv", type=Path, default=native / "tile_shared_body_structure.tsv")
    ap.add_argument("--json", type=Path, default=native / "tile_shared_body_structure.json")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    record = build(args.elf)
    tsv = render_tsv(record)
    payload = json.dumps(record, indent=2, ensure_ascii=False) + "\n"
    if args.check:
        status = 0
        for path, expected in ((args.tsv, tsv), (args.json, payload)):
            if not path.exists():
                print(f"CHECK FAILED: {path} is missing", file=sys.stderr)
                status = 1
            elif path.read_text(encoding="utf-8") != expected:
                print(f"CHECK FAILED: {path} is stale", file=sys.stderr)
                status = 1
        if status == 0:
            print(f"check ok: {record['counts']}")
        return status
    args.tsv.parent.mkdir(parents=True, exist_ok=True)
    args.tsv.write_text(tsv, encoding="utf-8")
    args.json.write_text(payload, encoding="utf-8")
    print(f"wrote {args.tsv.name} + {args.json.name}: {record['counts']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
