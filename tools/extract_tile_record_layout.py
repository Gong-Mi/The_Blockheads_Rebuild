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


def scan(blob: bytes) -> list[dict]:
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    reads = []
    for label, low, high in WINDOWS:
        for ins in md.disasm(blob[low:high], low):
            if not ins.mnemonic.startswith("ldr"):
                continue
            match = FIELD_PATTERN.search(ins.op_str)
            if not match or "fp" in ins.op_str or "sp" in ins.op_str:
                continue
            raw = match.group(1)
            offset = int(raw, 16) if raw.startswith("0x") else int(raw)
            reads.append({"window": label, "at": f"0x{ins.address:08x}",
                          "mnemonic": ins.mnemonic, "offset": offset,
                          "text": f"{ins.mnemonic} {ins.op_str}"})
    return reads


def build(elf: Path) -> dict:
    blob = elf.read_bytes()
    reads = scan(blob)
    by_offset: dict[int, list[dict]] = {}
    for read in reads:
        by_offset.setdefault(read["offset"], []).append(read)

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
        },
        "raw_reads": reads,
    }


def render_tsv(record: dict) -> str:
    lines = ["offset\tsize\twindows\tread_sites\tpurpose"]
    for field in record["fields"]:
        lines.append(f"{field['offset']}\t{field['size']}\t{','.join(field['windows'])}\t"
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
