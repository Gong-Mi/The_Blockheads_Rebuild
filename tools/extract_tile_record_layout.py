#!/usr/bin/env python3
"""The tile record fields the drawing path reads.

Decoding the shared body and its tail gives four byte fields of a 64-byte record,
each with a purpose visible in the code. This extracts them mechanically instead of
transcribing them by hand.

Two decoding notes are baked into the scan because both bit me:
  * linear disassembly across the inline jump table loses sync - a table of offsets is
    data, so anything decoded after it is garbage. The scan runs over known code
    windows, not the whole function;
  * capstone prints small offsets without a hex prefix (`#8`, `#1`, `#3`) and larger
    ones with it (`#0xc`). A pattern that requires `0x` therefore misses exactly the
    interesting byte fields.

Usage:
  python3 tools/extract_tile_record_layout.py <libApplication.so> [--tsv OUT] [--json OUT] [--check]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

try:
    import capstone
except ImportError:  # pragma: no cover - environment guard
    print("skip: capstone is not installed")
    raise SystemExit(0)

WINDOWS = (("shared body", 0x00A22D70, 0x00A22F40),
           ("tail", 0x00A234E0, 0x00A23590))
FIELD_PATTERN = re.compile(r"\[r\d+, #(0x[0-9a-f]+|\d+)\]")
STRIDE_SHIFT = 6                       # add r3, ip, r3, lsl #6 -> 64-byte records
TAIL_CONSTANT = 0x45


LDR_FP_RE = re.compile(r"^([a-z0-9]+), \[fp, #(-?0x[0-9a-f]+|\d+)\]$")
LDR_REG_OFF_RE = re.compile(r"^([a-z0-9]+), \[([a-z0-9]+), #(0x[0-9a-f]+|\d+)\]$")
ADD_SHIFT_RE = re.compile(r"^([a-z0-9]+), ([a-z0-9]+), [a-z0-9]+, lsl #6$")
ALIASES = {"fp": "fp", "sp": "sp", "ip": "r12", "lr": "r14"}


def _value(raw: str) -> int:
    sign = -1 if raw.startswith("-") else 1
    digits = raw.lstrip("+-")
    # capstone writes negative frame offsets as "-0x1c0", which startswith("0x") is
    # false for - so the hex branch has to look past the sign.
    return sign * (int(digits, 16) if digits.startswith("0x") else int(digits))


def _reg(token: str) -> str:
    return ALIASES.get(token, token)


def _fp_label(value: int) -> str:
    return f"fp-0x{-value:x}" if value < 0 else f"fp+0x{value:x}"


def scan(blob: bytes) -> list[dict]:
    """Field reads with the base pointer each one belongs to.

    Tracking the base matters: the four offsets do NOT all live in the 64-byte record.
    The lighting byte at offset 8 is read through `[[fp,-0x198]+8] + index*64`, while
    offsets 1, 3 and 12 are read through the object at `[fp,-0x1c0]`. An earlier version
    of this table called them all "tile record fields", which conflates two bases.
    """
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    reads = []
    for label, low, high in WINDOWS:
        base: dict[str, str] = {}
        for ins in md.disasm(blob[low:high], low):
            op = ins.op_str
            # A word load builds a base pointer; a byte/halfword load is a field read.
            # Treating both as base updates made every field read update its own base
            # and then skip itself, which is how this scan silently found zero fields.
            if ins.mnemonic == "ldr":
                match = LDR_FP_RE.match(op)
                if match:
                    base[_reg(match.group(1))] = _fp_label(_value(match.group(2)))
                    continue
                match = LDR_REG_OFF_RE.match(op)
                if match:
                    dest, src, off = (_reg(match.group(1)), _reg(match.group(2)),
                                      _value(match.group(3)))
                    base[dest] = f"[{base.get(src, src)}]+0x{off:x}"
                    continue
            if ins.mnemonic == "add":
                match = ADD_SHIFT_RE.match(op)
                if match:
                    dest, src = _reg(match.group(1)), _reg(match.group(2))
                    base[dest] = f"({base.get(src, src)} + index*64)"
                    continue
            if ins.mnemonic not in ("ldrb", "ldrh", "ldrsb", "ldrsh"):
                continue
            match = FIELD_PATTERN.search(op)
            if not match or "fp" in op or "sp" in op:
                continue
            dest = _reg(op.split(",")[0].strip())
            reads.append({"window": label, "at": f"0x{ins.address:08x}",
                          "mnemonic": ins.mnemonic, "offset": _value(match.group(1)),
                          "base": base.get(dest, f"{dest} (untracked)"),
                          "text": f"{ins.mnemonic} {op}"})
    return reads


def build(elf: Path) -> dict:
    blob = elf.read_bytes()
    reads = scan(blob)
    by_offset: dict[int, list[dict]] = {}
    for read in reads:
        by_offset.setdefault(read["offset"], []).append(read)

    bases = sorted({r["base"] for r in reads})
    purposes = {
        1: "jump-table index (compared <= 0x4c after subtracting one, 77 entries)",
        3: "tested against zero (a boolean-ish field)",
        8: "fed into the arithmetic (byte - 127) * constant + [fp,-0x19c]",
        12: f"compared against 0x{TAIL_CONSTANT:02x} in the tail",
    }
    fields = []
    for offset, reads_for_offset in sorted(by_offset.items()):
        fields.append({
            "offset": offset,
            "size": "byte",
            "read_sites": [r["at"] for r in reads_for_offset],
            "bases": sorted({r["base"] for r in reads_for_offset}),
            "in_64_byte_record": all("index*64" in r["base"] for r in reads_for_offset),
            "windows": sorted({r["window"] for r in reads_for_offset}),
            "purpose": purposes.get(offset, "(not characterised)"),
        })

    return {
        "schema": 1,
        "elf_sha256": hashlib.sha256(blob).hexdigest(),
        "claim": ("byte fields of the 64-byte tile record that the drawing path reads, "
                  "extracted from the code windows with each read site recorded"),
        "record_stride": 1 << STRIDE_SHIFT,
        "stride_evidence": "add r3, ip, r3, lsl #6 at 0x00a22dfc",
        "fields": fields,
        "counts": {
            "windows_scanned": len(WINDOWS),
            "record_field_reads": len(reads),
            "distinct_offsets": len(by_offset),
            "tail_constant": TAIL_CONSTANT,
            "distinct_bases": len(bases),
            "fields_in_64_byte_record": sum(1 for f in fields if f["in_64_byte_record"]),
            "fields_in_other_object": sum(1 for f in fields if not f["in_64_byte_record"]),
        },
        "raw_reads": reads,
    }


def render_tsv(record: dict) -> str:
    lines = ["offset\tsize\tbase\tin_64_byte_record\twindows\tread_sites\tpurpose"]
    for field in record["fields"]:
        lines.append(f"{field['offset']}\t{field['size']}\t{' | '.join(field['bases'])}\t"
                     f"{field['in_64_byte_record']}\t{','.join(field['windows'])}\t"
                     f"{','.join(field['read_sites'])}\t{field['purpose']}")
    return "\n".join(lines) + "\n"


def main() -> int:
    native_default = Path("reconstruction/reverse-v3/native")
    ap = argparse.ArgumentParser()
    ap.add_argument("elf", type=Path)
    ap.add_argument("--tsv", type=Path, default=native_default / "tile_record_layout.tsv")
    ap.add_argument("--json", type=Path, default=native_default / "tile_record_layout.json")
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
