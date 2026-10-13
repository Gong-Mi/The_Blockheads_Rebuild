#!/usr/bin/env python3
"""Close the TileType -> sprite-cell domain for all 77 original tile types.

Three independently extracted artifacts describe parts of the answer:

  original_tile_item_map.tsv     the `isForeground == 0` switch of
                                 itemTypeFromTileIsForegorund(): every direct tile
                                 type and the ItemType it maps to; 43 rows also
                                 carry that item's sprite cell inline
  original_item_sprite_map.tsv   the item sprite formula/jump table (426 types,
                                 R2) which gives a cell for any ItemType
  original_tile_conditional.tsv  the conditional tile types, resolved through
                                 contentsType() comparisons

The join records where each cell came from instead of flattening the three
sources, and it cross-checks the two that overlap: for every tile row that
carries an inline cell, that cell must equal the item-domain cell for the same
ItemType. Two independent extractions agreeing is evidence; a mismatch would be
a finding, so mismatches are counted and reported rather than smoothed over.

Usage:
  python3 tools/resolve_tile_sprite_domain.py [--native DIR] [--tsv OUT] [--json OUT] [--check]
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path

FIRST_TILE_TYPE = 1
LAST_TILE_TYPE = 77
PROVENANCE = ("tile-map-inline", "item-sprite-domain", "contents-conditional",
              "unresolved")


def read_tsv(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh, delimiter="\t"))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(native: Path) -> dict:
    tile_path = native / "original_tile_item_map.tsv"
    item_path = native / "original_item_sprite_map.tsv"
    cond_path = native / "original_tile_conditional.tsv"

    tile_rows = {int(r["tile_type"]): r for r in read_tsv(tile_path)}
    item_rows = {int(r["item_type"]): r for r in read_tsv(item_path)}
    cond_rows: dict[int, list[dict]] = {}
    for row in read_tsv(cond_path):
        cond_rows.setdefault(int(row["tile_type"]), []).append(row)

    rows = []
    mismatches = []
    for tile_type in range(FIRST_TILE_TYPE, LAST_TILE_TYPE + 1):
        tile = tile_rows.get(tile_type)
        if tile is None:
            rows.append({"tile_type": tile_type, "provenance": "unresolved",
                         "reason": "no row in original_tile_item_map.tsv"})
            continue
        item_field = (tile.get("item_type") or "").strip()
        item_type = int(item_field) if item_field.isdigit() else None
        inline = {k: (tile.get(k) or "").strip() for k in ("image_dataA0", "col_dataA0", "row_dataA0")}
        has_inline = all(inline[k] != "" for k in inline)
        entry = {
            "tile_type": tile_type,
            "tile_resolution": tile.get("resolution", ""),
            "item_type": item_type,
            "case_target": tile.get("case_target", ""),
            "image": None, "col": None, "row": None, "u": None, "v": None,
            "provenance": "unresolved",
            "note": "",
        }
        if has_inline:
            entry.update({
                "image": inline["image_dataA0"],
                "col": inline["col_dataA0"],
                "row": inline["row_dataA0"],
                "provenance": "tile-map-inline",
            })
        if item_type is not None and item_type in item_rows:
            item = item_rows[item_type]
            derived = {"image": (item.get("image") or "").strip(),
                       "col": item["col"], "row": item["row"],
                       "u": item["u"], "v": item["v"]}
            if has_inline:
                same = (derived["image"] == inline["image_dataA0"]
                        and derived["col"] == inline["col_dataA0"]
                        and derived["row"] == inline["row_dataA0"])
                if not same:
                    mismatches.append({"tile_type": tile_type, "item_type": item_type,
                                       "inline": inline, "derived": derived})
                entry["cell_cross_check"] = "match" if same else "mismatch"
            elif entry["provenance"] == "unresolved":
                entry.update({**derived, "provenance": "item-sprite-domain"})
                entry["note"] = f"cell from the item sprite domain for ItemType {item_type}"
        cond = cond_rows.get(tile_type)
        if cond and entry["provenance"] == "unresolved":
            entry["provenance"] = "contents-conditional"
            entry["conditional_cases"] = len(cond)
            entry["case_target"] = tile.get("case_target", "") or cond[0].get("case_target", "")
            entry["note"] = ("draw depends on contentsType(); the conditional table "
                             "holds the resolved compare chain")
            unresolved_steps = [r for r in cond if r.get("status") != "resolved"]
            if unresolved_steps:
                entry["note"] += f" ({len(unresolved_steps)} steps not marked resolved)"
        rows.append(entry)

    counts = {key: sum(1 for r in rows if r["provenance"] == key) for key in PROVENANCE}
    counts.update({
        "tile_types": LAST_TILE_TYPE - FIRST_TILE_TYPE + 1,
        "cross_checked": sum(1 for r in rows if r.get("cell_cross_check") == "match"),
        "cross_check_mismatches": len(mismatches),
        "with_cell": sum(1 for r in rows if r.get("col") not in (None, "")),
        "conditional_rows_in_table": sum(len(v) for v in cond_rows.values()),
    })
    return {
        "schema": 1,
        "inputs": {
            "tile_item_map": {"path": tile_path.name, "sha256": sha256(tile_path)},
            "item_sprite_map": {"path": item_path.name, "sha256": sha256(item_path)},
            "tile_conditional": {"path": cond_path.name, "sha256": sha256(cond_path)},
        },
        "claim": ("TileType -> sprite cell for the 77 tile types, joined from the "
                  "tile/ItemType switch, the item sprite domain and the "
                  "conditional table, with the provenance of every cell recorded "
                  "and the two overlapping sources cross-checked"),
        "counts": counts,
        "mismatches": mismatches,
        "rows": rows,
    }


TSV_FIELDS = ["tile_type", "tile_resolution", "item_type", "provenance", "image",
              "col", "row", "u", "v", "case_target", "cell_cross_check", "note",
              "conditional_cases", "reason"]


def render_tsv(rows: list[dict]) -> str:
    lines = ["\t".join(TSV_FIELDS)]
    for row in rows:
        lines.append("\t".join(
            "" if row.get(f) is None else str(row.get(f, "")) for f in TSV_FIELDS))
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--native", type=Path,
                    default=Path("reconstruction/reverse-v3/native"))
    ap.add_argument("--tsv", type=Path,
                    default=Path("reconstruction/reverse-v3/native/tile_sprite_domain.tsv"))
    ap.add_argument("--json", type=Path,
                    default=Path("reconstruction/reverse-v3/native/tile_sprite_domain.json"))
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    record = build(args.native)
    tsv = render_tsv(record["rows"])
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
