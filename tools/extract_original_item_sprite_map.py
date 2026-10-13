#!/usr/bin/env python3
"""Extract the Items.png sprite-cell domain for every known ItemType.

Two original paths produce item imagery:

1. `-[World texCoordsForItemType:...:]` @ 0x004d6040 -- the inventory-icon
   (Items.png) sprite cell. It normalises the item type into a 2048x1024
   atlas with 64x64 cells laid out 32 columns x 16 rows:

       col = type % 32          (u = col / 32 + 1/2048)
       row = type / 32          (v = row / 16 + 1/2048)
       u span = 126/2048, v span = 62/2048

   The pool constants below are read from the pinned ELF and asserted, so the
   table can never silently drift from the binary it claims to describe.

2. `imageTypeForItemType` @ 0x004d71dc -- the collectible/free-block domain
   (1024..1105 plus three low specials) whose image index and cell come from a
   jump table; that part is already tabulated by
   tools/extract_original_item_image_map.py and is joined in here rather than
   recomputed.

Coverage: every item type in original_item_types.tsv gets a row. Types >= 1024
that the jump table does not resolve stay labelled `unresolved` - never guessed.

Usage:
  python3 tools/extract_original_item_sprite_map.py <libApplication.so> \
      [--types TSV] [--explicit TSV] [--tsv OUT] [--json OUT] [--check]
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from extract_original_tile_item_map import Elf32Arm  # noqa: E402

FUNCTION = "texCoordsForItemType"
FUNCTION_VA = 0x004D6040
GRID_COLS = 32
GRID_ROWS = 16
# The function loads three 64-bit pool doubles (d1/d2/d4) and two 32-bit pool
# floats (s0/s6): the spans are single-precision in the binary, so they must be
# read with the matching width or the assertion below misfires.
POOL_F64 = {
    0x004D6108: ("half_texel", 1.0 / 2048.0),
    0x004D6110: ("v_step", 1.0 / 16.0),
    0x004D6118: ("u_step", 1.0 / 32.0),
}
POOL_F32 = {
    0x004D6120: ("u_span", 126.0 / 2048.0),
    0x004D6124: ("v_span", 62.0 / 2048.0),
}
JUMP_DOMAIN_FIRST = 1024


def read_pool_double(elf: Elf32Arm, addr: int) -> float:
    lo = struct.unpack("<I", elf.read_va(addr, 4))[0]
    hi = struct.unpack("<I", elf.read_va(addr + 4, 4))[0]
    return struct.unpack("<d", struct.pack("<II", lo, hi))[0]


def read_pool_float(elf: Elf32Arm, addr: int) -> float:
    raw = struct.unpack("<I", elf.read_va(addr, 4))[0]
    return struct.unpack("<f", struct.pack("<I", raw))[0]


def verify_constants(elf: Elf32Arm) -> dict:
    out = {}
    for width, pool in (("f64", POOL_F64), ("f32", POOL_F32)):
        for addr, (role, expected) in pool.items():
            actual = (
                read_pool_double(elf, addr) if width == "f64" else read_pool_float(elf, addr)
            )
            if actual != expected:
                raise SystemExit(
                    f"pool 0x{addr:08x} ({role}, {width}) reads {actual!r}, "
                    f"expected {expected!r}"
                )
            out[role] = {"pool": f"0x{addr:08x}", width: actual}
    return out


def load_types(path: Path) -> list[int]:
    ids = []
    with path.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh, delimiter="\t"):
            raw = row.get("item_type", "")
            if raw.strip().isdigit():
                ids.append(int(raw))
    return sorted(set(ids))


def load_explicit(path: Path) -> dict[int, dict]:
    out = {}
    if not path.exists():
        return out
    with path.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh, delimiter="\t"):
            try:
                item = int(row["item_type"])
            except (KeyError, ValueError):
                continue
            out[item] = {
                "image": row.get("image_dataA0", ""),
                "col": row.get("col_from_image_a0", ""),
                "row": row.get("row_from_image_a0", ""),
            }
    return out


def cval(constants: dict, name: str) -> float:
    entry = constants[name]
    return entry["f64"] if "f64" in entry else entry["f32"]


def build(elf: Elf32Arm, sha: str, types: list[int], explicit: dict[int, dict]):
    constants = verify_constants(elf)
    rows = []
    counts = {"formula": 0, "jump_table": 0, "unresolved": 0}
    for item in types:
        if item < JUMP_DOMAIN_FIRST:
            col = item % GRID_COLS
            row = item // GRID_COLS
            rows.append(
                {
                    "item_type": item,
                    "atlas": "Items.png",
                    "image": "",
                    "col": col,
                    "row": row,
                    "u": col / GRID_COLS + cval(constants, "half_texel"),
                    "v": row / GRID_ROWS + cval(constants, "half_texel"),
                    "u_span": cval(constants, "u_span"),
                    "v_span": cval(constants, "v_span"),
                    "source": f"formula@{FUNCTION_VA:#08x}",
                }
            )
            counts["formula"] += 1
            continue
        found = explicit.get(item)
        if found and found["image"]:
            rows.append(
                {
                    "item_type": item,
                    "atlas": found["image"],
                    "image": found["image"],
                    "col": found["col"],
                    "row": found["row"],
                    "u": "",
                    "v": "",
                    "u_span": "",
                    "v_span": "",
                    "source": "imageTypeForItemType@0x004d71dc",
                }
            )
            counts["jump_table"] += 1
        else:
            rows.append(
                {
                    "item_type": item,
                    "atlas": "Items.png",
                    "image": "",
                    "col": "",
                    "row": "",
                    "u": "",
                    "v": "",
                    "u_span": "",
                    "v_span": "",
                    "source": "unresolved",
                }
            )
            counts["unresolved"] += 1
    record = {
        "schema": 1,
        "elf_sha256": sha,
        "function": FUNCTION,
        "function_address": f"0x{FUNCTION_VA:08x}",
        "grid": {"cols": GRID_COLS, "rows": GRID_ROWS, "cell_px": 64,
                 "atlas": "Items.png 2048x1024"},
        "constants": constants,
        "jump_domain_first": JUMP_DOMAIN_FIRST,
        "counts": counts,
        "claim": ("inventory-icon cells: col = type %% %d, row = type / %d on a "
                  "2048x1024 atlas with 64px cells; the collectible domain keeps "
                  "its jump-table image index instead" % (GRID_COLS, GRID_COLS)),
        "rows": rows,
    }
    return record


def render_tsv(rows: list[dict]) -> str:
    header = ["item_type", "atlas", "image", "col", "row", "u", "v",
              "u_span", "v_span", "source"]
    lines = ["\t".join(header)]
    for row in rows:
        lines.append("\t".join(str(row[h]) for h in header))
    return "\n".join(lines) + "\n"


def main() -> int:
    here = Path(__file__).resolve().parent.parent
    native = here / "reconstruction/reverse-v3/native"
    ap = argparse.ArgumentParser()
    ap.add_argument("libapplication", type=Path)
    ap.add_argument("--types", type=Path, default=native / "original_item_types.tsv")
    ap.add_argument("--explicit", type=Path,
                    default=native / "original_item_image_map.tsv")
    ap.add_argument("--tsv", type=Path, default=native / "original_item_sprite_map.tsv")
    ap.add_argument("--json", type=Path, default=native / "item_sprite_map.json")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    sha = hashlib.sha256(args.libapplication.read_bytes()).hexdigest()
    record = build(Elf32Arm(args.libapplication), sha,
                   load_types(args.types), load_explicit(args.explicit))
    tsv = render_tsv(record["rows"])
    payload = json.dumps(record, indent=2, ensure_ascii=False) + "\n"

    if args.check:
        bad = 0
        for path, expected in ((args.tsv, tsv), (args.json, payload)):
            if not path.exists() or path.read_text(encoding="utf-8") != expected:
                print(f"CHECK FAILED: {path} is stale", file=sys.stderr)
                bad = 1
        if not bad:
            c = record["counts"]
            print(f"check ok: {len(record['rows'])} rows "
                  f"(formula={c['formula']} jump_table={c['jump_table']} "
                  f"unresolved={c['unresolved']})")
        return bad

    args.tsv.parent.mkdir(parents=True, exist_ok=True)
    args.tsv.write_text(tsv, encoding="utf-8")
    args.json.write_text(payload, encoding="utf-8")
    c = record["counts"]
    print(f"wrote {args.tsv.name} + {args.json.name}: {len(record['rows'])} rows "
          f"(formula={c['formula']} jump_table={c['jump_table']} "
          f"unresolved={c['unresolved']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
