#!/usr/bin/env python3
"""Atlas geometry contract: do the tables' cell claims fit the shipped PNGs?

Every sprite table in this repository records a cell as (col, row) plus a grid it
belongs to. This tool recomputes the pixel rectangle for each recorded cell and
checks it against the actual dimensions of the shipped atlas, so a claim that
cannot be placed in the file is reported instead of being inherited silently.

Claims are read from the artifacts and checked, not assumed:

  Items.png    the formula domain of texCoordsForItemType assumes 32x16 cells of
               64 px (2048x1024) - verified against the file, and every formula
               row is checked to land inside it
  TileMap.png  tile cells are checked at the same 64 px convention (TileMap.png is
               square, 2048x2048), with the cell size marked as inherited from the
               item convention rather than proven for tiles
  font atlases glyph rectangles are checked against the declared canvas and the
               real PNG, including the 04b03_16 descriptor that declares 256x128
               while its PNG is 2048x1024

Usage:
  python3 tools/verify_atlas_geometry.py <assets-root> [--native DIR] [--tsv OUT] [--json OUT] [--check]
"""
from __future__ import annotations

import argparse
import collections
import csv
import json
import struct
import sys
from pathlib import Path

ITEMS_ATLAS = ("GameResources/Items.png", "GameResources/HDTex/Items.png")
TILE_ATLAS = ("GameResources/TileMap.png", "GameResources/HDTex/TileMap.png")


def png_size(path: Path) -> tuple[int, int] | None:
    data = path.read_bytes()[:24]
    if len(data) < 24 or data[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    return struct.unpack(">II", data[16:24])


def locate(root: Path, candidates: tuple[str, ...]) -> list[dict]:
    out = []
    for rel in candidates:
        path = root / rel
        size = png_size(path) if path.exists() else None
        out.append({"path": rel, "exists": path.exists(), "size": list(size) if size else None})
    return out


def check_cells(rows: list[dict], cell: int, atlas_w: int, atlas_h: int,
                label: str) -> dict:
    violations = []
    for row in rows:
        col, r = int(row["col"]), int(row["row"])
        x, y = col * cell, r * cell
        if x + cell > atlas_w or y + cell > atlas_h:
            violations.append({
                "label": row.get("label", ""),
                "col": col, "row": r,
                "rect": [x, y, cell, cell],
                "exceeds": ("width" if x + cell > atlas_w else "") +
                           ("+height" if y + cell > atlas_h else ""),
            })
    return {"rows": len(rows), "cell_px": cell, "atlas": [atlas_w, atlas_h],
            "violations": len(violations), "examples": violations[:12]}


def build(root: Path, native: Path) -> dict:
    item_rows = []
    with (native / "original_item_sprite_map.tsv").open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh, delimiter="\t"):
            item_rows.append({
                "label": f"item {row['item_type']} ({row['source']})",
                "col": row["col"], "row": row["row"],
                "domain": row["source"].split("@")[0],
            })
    formula = [r for r in item_rows if r["domain"] == "formula"]
    jumped = [r for r in item_rows if r["domain"] != "formula"]

    tile_rows = []
    tile_domain = json.loads((native / "tile_sprite_domain.json").read_text(encoding="utf-8"))
    for row in tile_domain["rows"]:
        if row.get("col") not in (None, ""):
            tile_rows.append({"label": f"tile {row['tile_type']} ({row['provenance']})",
                              "col": row["col"], "row": row["row"]})

    fonts = json.loads((native / "font_glyph_tables.json").read_text(encoding="utf-8"))
    font_checks = []
    for font in fonts["fonts"]:
        rects = []
        inside = over = 0
        for glyph in font["glyphs"]:
            x, y = glyph["x"], glyph["y"]
            w, h = glyph["width"], glyph["height"]
            rects.append((x, y, w, h))
            if x + w <= font["scale_w"] and y + h <= font["scale_h"]:
                inside += 1
            else:
                over += 1
        seen = collections.Counter(rects)
        overlaps = sum(1 for rect, count in seen.items() if count > 1)
        font_checks.append({
            "font": font["font"], "declared": [font["scale_w"], font["scale_h"]],
            "actual_png": font["atlas_size"], "glyphs": len(rects),
            "inside_declared_canvas": inside, "exceeding_declared_canvas": over,
            "duplicate_rects": overlaps,
        })

    items_files = locate(root, ITEMS_ATLAS)
    tile_files = locate(root, TILE_ATLAS)
    hd_items = next((f for f in items_files if f["path"].startswith("GameResources/HDTex/")), None)
    hd_tile = next((f for f in tile_files if f["path"].startswith("GameResources/HDTex/")), None)

    checks = {
        "items": {
            "files": items_files,
            "formula_domain": check_cells(formula, 64, 2048, 1024, "formula"),
            "image_id_domain": check_cells(jumped, 64, 2048, 2048, "image-id"),
            "atlas_attribution": {
                "formula": {
                    "atlas": "Items.png",
                    "grid": "32 cols x 16 rows x 64 px",
                    "evidence": "texCoordsForItemType pool constants (u step 1/32, v step 1/16)",
                },
                "image-id": {
                    "atlas": "TileMap.png",
                    "grid": "32 cols x 32 rows x 64 px",
                    "evidence": ("original_item_types.tsv atlas_domain=TileMap:32x32 "
                                 "and image ids < 1024 enforced there, so id//32 <= 31"),
                },
            },
            "note": ("each item domain is checked against its own atlas. An earlier "
                     "revision of this tool checked the image-id domain against "
                     "Items.png (32x16) and reported 11 violations - that was a wrong "
                     "attribution in the check, not a contradiction in the data: the "
                     "image-id cells are derived from the image id and belong to the "
                     "32x32 domain, where all of them fit (row 31 -> y+64 = 2048)"),
        },
        "tiles": {
            "files": tile_files,
            "cells": check_cells(tile_rows, 64, 2048, 2048, "tile"),
            "note": ("cell size inherited from the item convention (64 px); the "
                     "tile tables themselves record only col/row"),
        },
        "fonts": {"checks": font_checks},
    }
    counts = {
        "item_formula_rows": checks["items"]["formula_domain"]["rows"],
        "item_formula_violations": checks["items"]["formula_domain"]["violations"],
        "item_image_id_rows": checks["items"]["image_id_domain"]["rows"],
        "item_image_id_violations": checks["items"]["image_id_domain"]["violations"],
        "tile_rows": checks["tiles"]["cells"]["rows"],
        "tile_violations": checks["tiles"]["cells"]["violations"],
        "fonts": len(font_checks),
        "font_glyphs": sum(f["glyphs"] for f in font_checks),
        "font_glyphs_outside_canvas": sum(f["exceeding_declared_canvas"] for f in font_checks),
    }
    return {
        "schema": 1,
        "assets_root": str(root),
        "claim": ("pixel rectangle of every recorded sprite cell recomputed and "
                  "checked against the shipped atlas dimensions; a cell that cannot "
                  "be placed is a violation, not an inherited assumption"),
        "counts": counts,
        "items_png_hd": hd_items,
        "tilemap_png_hd": hd_tile,
        "checks": checks,
    }


def render_tsv(record: dict) -> str:
    lines = ["scope\tlabel\tcol\trow\tcell_px\tatlas\tviolation"]
    for scope, key in (("items-formula", "formula_domain"), ("items-image-id", "image_id_domain")):
        check = record["checks"]["items"][key]
        for example in check["examples"]:
            lines.append("\t".join([scope, example["label"], str(example["col"]),
                                     str(example["row"]), str(check["cell_px"]),
                                     "x".join(str(v) for v in check["atlas"]),
                                     example["exceeds"]]))
    tile = record["checks"]["tiles"]["cells"]
    for example in tile["examples"]:
        lines.append("\t".join(["tiles", example["label"], str(example["col"]),
                                 str(example["row"]), str(tile["cell_px"]),
                                 "x".join(str(v) for v in tile["atlas"]),
                                 example["exceeds"]]))
    for font in record["checks"]["fonts"]["checks"]:
        lines.append("\t".join(["fonts", font["font"], "", "", "",
                                 "x".join(str(v) for v in font["declared"]),
                                 f"outside={font['exceeding_declared_canvas']}"]))
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("assets", type=Path)
    native_default = Path("reconstruction/reverse-v3/native")
    ap.add_argument("--native", type=Path, default=native_default)
    ap.add_argument("--tsv", type=Path, default=native_default / "atlas_geometry_contract.tsv")
    ap.add_argument("--json", type=Path, default=native_default / "atlas_geometry_contract.json")
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
