#!/usr/bin/env python3
"""Cross-check the extracted tile-record fields against the repo's own header.

`app/src/main/cpp/original_save_format.h` documents part of the 64-byte tile record
(`raw[0]` type, `raw[1]` backWallType, `raw[3]` contentsType, `raw[7]`
temperatureScaleByte) and asserts the 64-byte size. R32 extracted the byte fields the
drawing path actually reads from the code (offsets 1, 3, 8, 12). Neither source is
complete, and they overlap - so the two are joined here:

  * the size agrees (64 bytes, both),
  * two extracted offsets have documented names (1 -> backWallType, 3 -> contentsType),
  * two extracted offsets are undocumented in the header (8, 12) - that is new
    information the extraction adds,
  * documented offsets the drawing path never reads stay visible as such.

Usage:
  python3 tools/crosscheck_tile_record_header.py <native DIR> [--header PATH] [--tsv OUT] [--json OUT] [--check]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ACCESSOR_RE = re.compile(
    r"std::(?:u?int\d+_t|array<[^>]+>)\s+(\w+)\(\)\s+const\s*\{\s*return\s+raw\[(\d+)\]")
SIZE_RE = re.compile(r"struct\s+(\w*Tile\w*)\s*\{[^}]*?raw\{\};", re.S)
ASSERT_RE = re.compile(r"kOriginalTileSize")
SIZE_CONST_RE = re.compile(r"kOriginalTileSize\s*=\s*(\d+)")


def parse_header(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    accessors = {int(offset): name for name, offset in ACCESSOR_RE.findall(text)}
    size = None
    for candidate in (path.parent / "original_save_format.h", path.parent / "original_tile_size.h"):
        if candidate.exists() and candidate != path:
            match = SIZE_CONST_RE.search(candidate.read_text(encoding="utf-8"))
            if match:
                size = int(match.group(1))
    if size is None:
        match = SIZE_CONST_RE.search(text)
        size = int(match.group(1)) if match else None
    if size is None:
        # the header asserts the size; look for the definition anywhere in the include tree
        for candidate in path.parent.rglob("*.h"):
            match = SIZE_CONST_RE.search(candidate.read_text(encoding="utf-8", errors="replace"))
            if match:
                size = int(match.group(1))
                break
    return {"path": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "documented_offsets": accessors, "declared_size": size,
            "struct_named_tile": bool(SIZE_RE.search(text)),
            "asserts_size": bool(ASSERT_RE.search(text))}


def build(native: Path, header: Path) -> dict:
    layout = json.loads((native / "tile_record_layout.json").read_text(encoding="utf-8"))
    doc = parse_header(header)
    documented = doc["documented_offsets"]

    rows = []
    for field in layout["fields"]:
        offset = field["offset"]
        rows.append({
            "offset": offset,
            "header_name": documented.get(offset, ""),
            "documented": offset in documented,
            "read_sites": field["read_sites"],
            "windows": field["windows"],
            "path_purpose": field["purpose"],
        })
    unread_documented = sorted(set(documented) - {r["offset"] for r in rows})
    counts = {
        "extracted_offsets": len(rows),
        "documented_offsets": len(documented),
        "agreeing_offsets": sum(1 for r in rows if r["documented"]),
        "undocumented_extracted": sum(1 for r in rows if not r["documented"]),
        "documented_but_not_read_by_drawing_path": len(unread_documented),
        "record_stride_extracted": layout["record_stride"],
        "record_size_declared": doc["declared_size"],
        "size_agrees": doc["declared_size"] == layout["record_stride"],
    }
    return {
        "schema": 1,
        "claim": ("extracted drawing-path record fields joined with the repository's own "
                  "tile record header: overlaps named, undocumented fields surfaced"),
        "header": doc,
        "counts": counts,
        "rows": rows,
        "documented_but_unread": [{"offset": o, "name": documented[o]}
                                  for o in unread_documented],
    }


def render_tsv(record: dict) -> str:
    lines = ["offset\theader_name\tdocumented\tread_sites\tpurpose"]
    for row in record["rows"]:
        lines.append(f"{row['offset']}\t{row['header_name'] or '(undocumented)'}\t"
                     f"{row['documented']}\t{','.join(row['read_sites'])}\t{row['path_purpose']}")
    for entry in record["documented_but_unread"]:
        lines.append(f"{entry['offset']}\t{entry['name']}\ttrue\t\t(documented, not read by the drawing path)")
    return "\n".join(lines) + "\n"


def main() -> int:
    native_default = Path("reconstruction/reverse-v3/native")
    ap = argparse.ArgumentParser()
    ap.add_argument("--native", type=Path, default=native_default)
    ap.add_argument("--header", type=Path,
                    default=Path("app/src/main/cpp/original_save_format.h"))
    ap.add_argument("--tsv", type=Path, default=native_default / "tile_record_header_crosscheck.tsv")
    ap.add_argument("--json", type=Path, default=native_default / "tile_record_header_crosscheck.json")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    record = build(args.native, args.header)
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
