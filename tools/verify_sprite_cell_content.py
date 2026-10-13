#!/usr/bin/env python3
"""Which atlas do the item cells actually come from? Ask the pixels.

`original_item_types.tsv` claims `atlas_domain=TileMap:32x32` for the item domain,
and the geometry contract was corrected to match that claim. A claim is not evidence,
so this crops the recorded cells out of BOTH candidate atlases and counts ink:

  item sprite map, `formula` domain      32x16 grid -> Items.png
  item sprite map, image-id domain       32x32 grid -> TileMap.png (the claim)
                                         also cropped from Items.png to compare

Whichever atlas puts ink in the cells is the one the table is describing.

Usage:
  python3 tools/verify_sprite_cell_content.py <assets-root> [--native DIR] [--json OUT] [--check]
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path

try:
    from PIL import Image
except ImportError:  # pragma: no cover - environment guard
    print("Pillow is required (pip install pillow)", file=sys.stderr)
    raise SystemExit(2)

CELL = 64


def ink(path: Path, col: int, row: int) -> dict:
    if not path.exists():
        return {"present": False, "in_bounds": False, "ink": 0}
    image = Image.open(path).convert("RGBA")
    x, y = col * CELL, row * CELL
    in_bounds = x + CELL <= image.width and y + CELL <= image.height
    if not in_bounds:
        return {"present": True, "in_bounds": False, "ink": 0,
                "atlas": [image.width, image.height]}
    crop = image.crop((x, y, x + CELL, y + CELL))
    return {"present": True, "in_bounds": True,
            "ink": sum(1 for value in crop.getchannel("A").getdata() if value),
            "atlas": [image.width, image.height]}


def read_tsv(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh, delimiter="\t"))


def build(assets: Path, native: Path) -> dict:
    rows = read_tsv(native / "original_item_sprite_map.tsv")
    hd_items = assets / "GameResources" / "HDTex" / "Items.png"
    hd_tile = assets / "GameResources" / "HDTex" / "TileMap.png"

    def evaluate(domain: str, atlas: Path) -> dict:
        subset = [r for r in rows if r["source"].split("@")[0] == domain]
        with_ink = out_of_bounds = empty = 0
        samples = []
        for row in subset:
            col, line = int(row["col"]), int(row["row"])
            result = ink(atlas, col, line)
            if not result.get("in_bounds", False):
                out_of_bounds += 1
            elif result["ink"]:
                with_ink += 1
            else:
                empty += 1
            if len(samples) < 6:
                samples.append({"item_type": row["item_type"], "col": col, "row": line,
                                "ink": result["ink"],
                                "in_bounds": result.get("in_bounds", False)})
        return {"rows": len(subset), "with_ink": with_ink, "empty": empty,
                "out_of_bounds": out_of_bounds, "samples": samples}

    record = {
        "schema": 1,
        "assets_root": str(assets),
        "cell_px": CELL,
        "claim": ("recorded item cells cropped out of both candidate atlases; the atlas "
                  "with ink is the one the table describes"),
        "atlases": {
            "items": {"path": "GameResources/HDTex/Items.png",
                      "sha256": hashlib.sha256(hd_items.read_bytes()).hexdigest()
                      if hd_items.exists() else None},
            "tilemap": {"path": "GameResources/HDTex/TileMap.png",
                        "sha256": hashlib.sha256(hd_tile.read_bytes()).hexdigest()
                        if hd_tile.exists() else None},
        },
        "formula_domain_in_items": evaluate("formula", hd_items),
        "image_domain_in_tilemap": evaluate("imageTypeForItemType", hd_tile),
        "image_domain_in_items": evaluate("imageTypeForItemType", hd_items),
    }
    record["counts"] = {
        "formula_rows": record["formula_domain_in_items"]["rows"],
        "formula_with_ink_in_items": record["formula_domain_in_items"]["with_ink"],
        "image_rows": record["image_domain_in_tilemap"]["rows"],
        "image_with_ink_in_tilemap": record["image_domain_in_tilemap"]["with_ink"],
        "image_with_ink_in_items": record["image_domain_in_items"]["with_ink"],
        "image_out_of_bounds_in_items": record["image_domain_in_items"]["out_of_bounds"],
    }
    return record


def render_tsv(record: dict) -> str:
    lines = ["domain\tatlas\trows\twith_ink\tempty\tout_of_bounds"]
    for key in ("formula_domain_in_items", "image_domain_in_tilemap",
                "image_domain_in_items"):
        entry = record[key]
        atlas = "Items.png" if key.endswith("items") else "TileMap.png"
        lines.append(f"{key}\t{atlas}\t{entry['rows']}\t{entry['with_ink']}\t"
                     f"{entry['empty']}\t{entry['out_of_bounds']}")
        for sample in entry["samples"]:
            lines.append(f"sample\t{sample['item_type']}\tcol={sample['col']} "
                         f"row={sample['row']} ink={sample['ink']}")
    return "\n".join(lines) + "\n"


def main() -> int:
    native_default = Path("reconstruction/reverse-v3/native")
    ap = argparse.ArgumentParser()
    ap.add_argument("assets", type=Path)
    ap.add_argument("--native", type=Path, default=native_default)
    ap.add_argument("--tsv", type=Path, default=native_default / "sprite_cell_content.tsv")
    ap.add_argument("--json", type=Path, default=native_default / "sprite_cell_content.json")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    record = build(args.assets, args.native)
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
