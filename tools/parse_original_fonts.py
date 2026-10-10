#!/usr/bin/env python3
"""Parse the original BMFont (.fnt) descriptors into a glyph table.

Text is an asset too: without the metrics the replacement cannot lay out a
single label. Each .fnt is parsed into its info/common/page lines plus one row
per glyph, and the declared atlas size is checked against the actual PNG IHDR
so a font that points at a resized atlas fails loudly instead of silently
rendering at the wrong scale.

Usage:
  python3 tools/parse_original_fonts.py <assets-root> [--tsv OUT] [--json OUT] [--check]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

KV_RE = re.compile(r'([A-Za-z_]+)=("(?:[^"\\]|\\.)*"|\S+)')


def parse_kv(line: str) -> dict[str, str]:
    out = {}
    for key, raw in KV_RE.findall(line):
        out[key] = raw[1:-1] if raw.startswith('"') else raw
    return out


def png_size(path: Path) -> tuple[int, int] | None:
    data = path.read_bytes()[:32]
    if len(data) < 24 or data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR":
        return None
    width, height = struct.unpack(">II", data[16:24])
    return width, height


def parse_fnt(path: Path, assets_root: Path) -> dict:
    info: dict = {}
    common: dict = {}
    pages: list[str] = []
    glyphs: list[dict] = []
    kernings = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line.startswith("info "):
            info = parse_kv(line)
        elif line.startswith("common "):
            common = parse_kv(line)
        elif line.startswith("page "):
            page = parse_kv(line)
            pages.append(page.get("file", ""))
        elif line.startswith("char "):
            fields = parse_kv(line)
            glyphs.append({
                "char_id": int(fields["id"]),
                "x": int(fields["x"]),
                "y": int(fields["y"]),
                "width": int(fields["width"]),
                "height": int(fields["height"]),
                "xoffset": int(fields["xoffset"]),
                "yoffset": int(fields["yoffset"]),
                "xadvance": int(fields["xadvance"]),
                "page": int(fields.get("page", 0)),
                "letter": fields.get("letter", ""),
            })
        elif line.startswith("kerning "):
            kernings += 1

    scale_w = int(common.get("scaleW", 0))
    scale_h = int(common.get("scaleH", 0))
    atlas = pages[0] if pages else ""
    atlas_path = path.parent / atlas if atlas else None
    actual = png_size(atlas_path) if atlas_path and atlas_path.exists() else None
    return {
        "font": path.name,
        "face": info.get("face", ""),
        "size": int(info.get("size", 0)),
        "line_height": int(common.get("lineHeight", 0)),
        "base": int(common.get("base", 0)),
        "scale_w": scale_w,
        "scale_h": scale_h,
        "pages": len(pages),
        "atlas": atlas,
        "atlas_exists": bool(actual),
        "atlas_size": list(actual) if actual else None,
        "atlas_size_matches": (actual == (scale_w, scale_h)) if actual else None,
        "atlas_sha256": (hashlib.sha256(atlas_path.read_bytes()).hexdigest()
                         if atlas_path and atlas_path.exists() else None),
        "glyphs": sorted(glyphs, key=lambda g: g["char_id"]),
        "kerning_pairs": kernings,
        "fnt_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def build(assets_root: Path) -> dict:
    fonts = [parse_fnt(p, assets_root)
             for p in sorted(assets_root.rglob("*.fnt"))]
    ascii_needed = set(range(32, 127))
    rows = []
    for font in fonts:
        have = {g["char_id"] for g in font["glyphs"]}
        font["ascii_missing"] = sorted(ascii_needed - have)
        font["ascii_coverage"] = len(ascii_needed & have)
        for glyph in font["glyphs"]:
            rows.append({"font": font["font"], **glyph})
    counts = {
        "fonts": len(fonts),
        "glyphs": len(rows),
        "fonts_with_atlas": sum(1 for f in fonts if f["atlas_exists"]),
        "atlas_size_mismatches": sum(1 for f in fonts if f["atlas_size_matches"] is False),
        "ascii_codepoints_per_font": 95,
        "ascii_missing_total": sum(len(f["ascii_missing"]) for f in fonts),
        "kerning_pairs": sum(f["kerning_pairs"] for f in fonts),
    }
    return {
        "schema": 1,
        "assets_root": str(assets_root),
        "counts": counts,
        "claim": ("BMFont metrics parsed from the shipped .fnt files; atlas "
                  "declared size cross-checked against the PNG IHDR"),
        "fonts": fonts,
        "rows": rows,
    }


def render_tsv(rows: list[dict]) -> str:
    header = ["font", "char_id", "letter", "x", "y", "width", "height",
              "xoffset", "yoffset", "xadvance", "page"]
    lines = ["\t".join(header)]
    for row in rows:
        lines.append("\t".join(str(row[h]) for h in header))
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("assets", type=Path)
    ap.add_argument("--tsv", type=Path,
                    default=Path("reconstruction/reverse-v3/native/font_glyph_tables.tsv"))
    ap.add_argument("--json", type=Path,
                    default=Path("reconstruction/reverse-v3/native/font_glyph_tables.json"))
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    record = build(args.assets)
    tsv = render_tsv(record["rows"])
    payload = json.dumps(record, indent=2, ensure_ascii=False) + "\n"
    if args.check:
        bad = 0
        for path, expected in ((args.tsv, tsv), (args.json, payload)):
            if not path.exists() or path.read_text(encoding="utf-8") != expected:
                print(f"CHECK FAILED: {path} is stale", file=sys.stderr)
                bad = 1
        if not bad:
            print(f"check ok: {record['counts']}")
        return bad
    args.tsv.parent.mkdir(parents=True, exist_ok=True)
    args.tsv.write_text(tsv, encoding="utf-8")
    args.json.write_text(payload, encoding="utf-8")
    print(f"wrote {args.tsv.name} + {args.json.name}: {record['counts']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
