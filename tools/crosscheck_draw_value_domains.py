#!/usr/bin/env python3
"""Are the shared body's draw values the same kind of number as image ids?

Three sets of numbers describe draws in this repository, extracted independently:

  direct tile cases        `draw_image` in original_tile_content_render_map.tsv
  tile map inline cells    `image_dataA0` in original_tile_item_map.tsv
  item sprite image ids    `image` in original_item_sprite_map.tsv (the a0 variant)
  shared body draw values  the 49 values in tile_shared_body_structure.json

If the shared body's values overlap the others, they are image ids of the same
domain and the shared body is choosing real draws - that is a testable claim rather
than a reading. The six constants the shared body compares against `[fp,-0x540]` are
checked the same way.

Usage:
  python3 tools/crosscheck_draw_value_domains.py [--native DIR] [--tsv OUT] [--json OUT] [--check]
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path


def read_tsv(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh, delimiter="\t"))


def build(native: Path) -> dict:
    content_rows = read_tsv(native / "original_tile_content_render_map.tsv")
    tile_rows = read_tsv(native / "original_tile_item_map.tsv")
    sprite_rows = read_tsv(native / "original_item_sprite_map.tsv")
    shared = json.loads((native / "tile_shared_body_structure.json").read_text(encoding="utf-8"))

    direct = sorted({int(r["draw_image"]) for r in content_rows if r["draw_image"]})
    inline = sorted({int(r["image_dataA0"]) for r in tile_rows if r["image_dataA0"]})
    sprite = sorted({int(r["image"]) for r in sprite_rows if r["image"]})
    shared_draw = sorted({int(v) for v in shared["draw_values"]})
    constants = sorted({int(v) for v in shared["constants"]})

    def stats(values: list[int]) -> dict:
        return {"count": len(values), "min": min(values) if values else None,
                "max": max(values) if values else None}

    def overlap(a: list[int], b: list[int]) -> dict:
        sa, sb = set(a), set(b)
        return {"shared": len(sa & sb), "only_a": len(sa - sb), "only_b": len(sb - sa),
                "sample_shared": sorted(sa & sb)[:12]}

    return {
        "schema": 1,
        "claim": ("draw-value domains cross-checked: if the shared body's values "
                  "overlap the independently extracted image-id sets, they are the "
                  "same kind of number (image ids), not a private enum"),
        "sets": {
            "direct_tile_cases": stats(direct),
            "tile_map_inline": stats(inline),
            "item_sprite_images": stats(sprite),
            "shared_body_draw_values": stats(shared_draw),
            "shared_body_constants": {"values": constants, **stats(constants)},
        },
        "overlaps": {
            "shared_body_vs_direct_cases": overlap(shared_draw, direct),
            "shared_body_vs_sprites": overlap(shared_draw, sprite),
            "direct_cases_vs_sprites": overlap(direct, sprite),
            "constants_vs_direct_cases": overlap(constants, direct),
            "constants_vs_shared_body": overlap(constants, shared_draw),
        },
        "values": {"direct_tile_cases": direct, "shared_body_draw_values": shared_draw,
                   "shared_body_constants": constants},
    }


def render_tsv(record: dict) -> str:
    lines = ["scope\tmetric\tvalue"]
    for name, entry in record["sets"].items():
        lines.append(f"set\t{name}\tcount={entry['count']} min={entry['min']} max={entry['max']}")
    for name, entry in record["overlaps"].items():
        lines.append(f"overlap\t{name}\tshared={entry['shared']} only_a={entry['only_a']} "
                     f"only_b={entry['only_b']}")
        if entry["sample_shared"]:
            lines.append(f"overlap-sample\t{name}\t{','.join(str(v) for v in entry['sample_shared'])}")
    return "\n".join(lines) + "\n"


def main() -> int:
    native_default = Path("reconstruction/reverse-v3/native")
    ap = argparse.ArgumentParser()
    ap.add_argument("--native", type=Path, default=native_default)
    ap.add_argument("--tsv", type=Path, default=native_default / "draw_value_domains.tsv")
    ap.add_argument("--json", type=Path, default=native_default / "draw_value_domains.json")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    record = build(args.native)
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
            print(f"check ok: {record['overlaps']['shared_body_vs_direct_cases']}")
        return status
    args.tsv.parent.mkdir(parents=True, exist_ok=True)
    args.tsv.write_text(tsv, encoding="utf-8")
    args.json.write_text(payload, encoding="utf-8")
    print(f"wrote {args.tsv.name} + {args.json.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
