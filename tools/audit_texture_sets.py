#!/usr/bin/env python3
"""Texture resolution sets: which assets ship at two sizes and by how much.

The original ships SD and HD copies side by side (`GameResources/<name>` and
`GameResources/HDTex/<name>`), and the rebuild must not sample the wrong one.
The dangerous part is that the ratio is not uniform - most body parts are 4x
(16x16 -> 64x64, 32x16 -> 128x64) but some HD copies are the same size as their
SD copy - so a single global scale factor is wrong.

Names that are merely duplicated (identical bytes at two paths, typically the
iOS shell copies) are separated from names that genuinely carry two resolutions,
because only the latter need a scale decision. A name with several distinct
copies but no HDTex counterpart is reported for review rather than assumed to be
a variant.

Usage:
  python3 tools/audit_texture_sets.py <assets-root> [--tsv OUT] [--json OUT] [--check]
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import struct
import sys
from pathlib import Path

RASTER = (".png",)
HD_DIR = "HDTex"


def png_size(path: Path) -> tuple[int, int] | None:
    data = path.read_bytes()[:24]
    if len(data) < 24 or data[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    return struct.unpack(">II", data[16:24])


def build(root: Path) -> dict:
    groups: dict[str, list[dict]] = collections.defaultdict(list)
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in RASTER:
            continue
        rel = path.relative_to(root).as_posix()
        size = png_size(path)
        groups[path.name].append({
            "path": rel,
            "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "width": size[0] if size else None,
            "height": size[1] if size else None,
            "is_hd_dir": f"/{HD_DIR}/" in f"/{rel}",
        })

    rows = []
    for name in sorted(groups):
        entries = groups[name]
        if len(entries) < 2:
            continue
        hashes = {e["sha256"] for e in entries}
        dims = {(e["width"], e["height"]) for e in entries}
        hd = [e for e in entries if e["is_hd_dir"]]
        sd = [e for e in entries if not e["is_hd_dir"]]
        if len(hashes) == 1:
            kind = "identical-duplicate"
        elif hd and sd and len(dims) > 1:
            kind = "sd-hd-pair"
        elif len(dims) > 1:
            kind = "distinct-sizes-no-hd"
        else:
            kind = "same-size-distinct-content"
        row = {
            "name": name,
            "kind": kind,
            "copies": len(entries),
            "sd": next((e for e in sd if e["width"] is not None), None),
            "hd": next((e for e in hd if e["width"] is not None), None),
            "entries": entries,
            "ratio": None,
        }
        if kind == "sd-hd-pair" and row["sd"] and row["hd"]:
            sw, sh = row["sd"]["width"], row["sd"]["height"]
            hw, hh = row["hd"]["width"], row["hd"]["height"]
            if sw and sh:
                row["ratio"] = [hw / sw, hh / sh]
                row["ratio_uniform"] = (hw / sw) == (hh / sh)
                row["integral_ratio"] = (hw % sw == 0) and (hh % sh == 0)
        rows.append(row)

    kinds = collections.Counter(r["kind"] for r in rows)
    ratios = collections.Counter(
        f"{r['ratio'][0]:g}x" for r in rows if r.get("ratio"))
    return {
        "schema": 1,
        "assets_root": str(root),
        "counts": {
            "names_with_multiple_copies": len(rows),
            "identical_duplicate": kinds.get("identical-duplicate", 0),
            "sd_hd_pair": kinds.get("sd-hd-pair", 0),
            "same_size_distinct_content": kinds.get("same-size-distinct-content", 0),
            "distinct_sizes_no_hd": kinds.get("distinct-sizes-no-hd", 0),
            "non_uniform_ratio": sum(1 for r in rows if r.get("ratio_uniform") is False),
            "non_integral_ratio": sum(1 for r in rows if r.get("integral_ratio") is False),
            "ratio_1x_hd_copies": sum(
                1 for r in rows if r.get("ratio") == [1, 1]),
        },
        "ratio_histogram": dict(sorted(ratios.items())),
        "claim": ("SD/HD texture sets: every basename that ships more than once, "
                  "classified by whether the copies are identical, a resolution "
                  "pair, or distinct content; ratios per pair, none assumed"),
        "rows": rows,
    }


def render_tsv(rows: list[dict]) -> str:
    header = ["name", "kind", "copies", "sd_path", "sd_size", "hd_path", "hd_size",
              "ratio", "ratio_uniform", "integral_ratio"]
    lines = ["\t".join(header)]
    for row in rows:
        sd, hd = row.get("sd") or {}, row.get("hd") or {}
        lines.append("\t".join(str(v) for v in (
            row["name"], row["kind"], row["copies"],
            sd.get("path", ""),
            f"{sd.get('width')}x{sd.get('height')}" if sd else "",
            hd.get("path", ""),
            f"{hd.get('width')}x{hd.get('height')}" if hd else "",
            "x".join(f"{v:g}" for v in row["ratio"]) if row.get("ratio") else "",
            row.get("ratio_uniform", ""),
            row.get("integral_ratio", ""),
        )))
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("assets", type=Path)
    ap.add_argument("--tsv", type=Path,
                    default=Path("reconstruction/reverse-v3/native/"
                                 "texture_resolution_sets.tsv"))
    ap.add_argument("--json", type=Path,
                    default=Path("reconstruction/reverse-v3/native/"
                                 "texture_resolution_sets.json"))
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    record = build(args.assets)
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
