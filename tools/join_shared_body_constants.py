#!/usr/bin/env python3
"""Which tile contents do the shared body's six constants belong to?

The shared body compares `[fp,-0x540]` against six constants (R22). Two questions
follow, and both are joins rather than readings:

  * who writes `[fp,-0x540]`? If the direct cases do, the slot carries the draw image
    they just chose and the six constants are image ids the shared body special-cases.
  * which contents produce those images? That names what is special-cased.

Usage:
  python3 tools/join_shared_body_constants.py <libApplication.so> [--native DIR] [--tsv OUT] [--json OUT] [--check]
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import struct
import sys
from pathlib import Path

SLOTS = (0x540, 0x544, 0x548, 0x54C, 0x558)
CASE_SCAN_WORDS = 40


def writes_to_case_slots(blob: bytes, target: int) -> list[dict]:
    out = []
    for index in range(CASE_SCAN_WORDS):
        addr = target + index * 4
        word = struct.unpack_from("<I", blob, addr)[0]
        # str Rt, [fp, #-imm] with P=1, U=0
        if (word >> 28) != 0xE or ((word >> 26) & 0x3) != 0x1:
            continue
        if (word >> 20) & 0x1 or ((word >> 16) & 0xF) != 11:
            continue
        if word & (1 << 23) or not word & (1 << 24):
            continue
        offset = word & 0xFFF
        if offset in SLOTS:
            out.append({"at": f"0x{addr:08x}", "reg": (word >> 12) & 0xF,
                        "slot": f"fp-0x{offset:x}"})
    return out


def read_tsv(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh, delimiter="\t"))


def build(elf: Path, native: Path) -> dict:
    blob = elf.read_bytes()
    shared = json.loads((native / "tile_shared_body_structure.json").read_text(encoding="utf-8"))
    constants = sorted(int(v) for v in shared["constants"])
    rows = read_tsv(native / "original_tile_content_render_map.tsv")

    image_to_content: dict[int, list[dict]] = {}
    for row in rows:
        if row["draw_image"]:
            image_to_content.setdefault(int(row["draw_image"]), []).append(row)

    entries = []
    for constant in constants:
        producers = image_to_content.get(constant, [])
        entries.append({
            "constant": constant,
            "producers": [{"content_value": int(p["content_value"]),
                           "candidate_name": p["candidate_name"],
                           "draw_cell": [p["draw_col"], p["draw_row"]]} for p in producers],
            "is_leaf_named": any("Leaf" in p["candidate_name"] for p in producers),
        })

    direct = [r for r in rows if r["resolution"] == "direct" and r["case_target"]]
    with_slot_write = 0
    samples = []
    for row in direct:
        writes = writes_to_case_slots(blob, int(row["case_target"], 16))
        if any(w["slot"] in ("fp-0x540", "fp-0x544") for w in writes):
            with_slot_write += 1
            if len(samples) < 6:
                samples.append({"content_value": row["content_value"],
                                "case_target": row["case_target"],
                                "writes": writes[:3]})

    leaf_contents = [r for r in rows if "Leaf" in r["candidate_name"]]
    return {
        "schema": 1,
        "elf_sha256": hashlib.sha256(blob).hexdigest(),
        "claim": ("the six constants the shared body compares against [fp,-0x540] are "
                  "the draw images of six specific tile contents; the direct cases write "
                  "that slot, so the slot carries the case's chosen image"),
        "counts": {
            "constants": len(constants),
            "constants_with_a_producer": sum(1 for e in entries if e["producers"]),
            "constants_with_exactly_one_producer": sum(
                1 for e in entries if len(e["producers"]) == 1),
            "leaf_named_contents": len(leaf_contents),
            "special_cased_are_leaf_named": sum(1 for e in entries if e["is_leaf_named"]),
            "direct_cases_scanned": len(direct),
            "direct_cases_writing_the_compared_slot": with_slot_write,
        },
        "constants": entries,
        "slot_write_samples": samples,
        "leaf_named_content_values": [int(r["content_value"]) for r in leaf_contents],
    }


def render_tsv(record: dict) -> str:
    lines = ["constant\tcontent_value\tcandidate_name\tdraw_col\tdraw_row\tis_leaf"]
    for entry in record["constants"]:
        if not entry["producers"]:
            lines.append(f"{entry['constant']}\t\t\t\t\t{entry['is_leaf_named']}")
            continue
        for producer in entry["producers"]:
            lines.append(f"{entry['constant']}\t{producer['content_value']}\t"
                         f"{producer['candidate_name']}\t{producer['draw_cell'][0]}\t"
                         f"{producer['draw_cell'][1]}\t{entry['is_leaf_named']}")
    return "\n".join(lines) + "\n"


def main() -> int:
    native_default = Path("reconstruction/reverse-v3/native")
    ap = argparse.ArgumentParser()
    ap.add_argument("elf", type=Path)
    ap.add_argument("--native", type=Path, default=native_default)
    ap.add_argument("--tsv", type=Path, default=native_default / "shared_body_constants.tsv")
    ap.add_argument("--json", type=Path, default=native_default / "shared_body_constants.json")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    record = build(args.elf, args.native)
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
