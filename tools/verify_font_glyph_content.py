#!/usr/bin/env python3
"""Do the parsed glyph rectangles point at real glyph pixels?

The font metrics say where each glyph lives; nothing until now checked that the
atlas actually has ink there. This crops every glyph rectangle out of the real PNG
and counts non-transparent pixels, so a metric that points at empty space is a
finding rather than a silently blank label.

Usage:
  python3 tools/verify_font_glyph_content.py <assets-root> [--native DIR] [--tsv OUT] [--json OUT] [--check]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

try:
    from PIL import Image
except ImportError:  # pragma: no cover - environment guard
    print("Pillow is required (pip install pillow)", file=sys.stderr)
    raise SystemExit(2)


def build(assets: Path, native: Path) -> dict:
    fonts = json.loads((native / "font_glyph_tables.json").read_text(encoding="utf-8"))
    results = []
    for font in fonts["fonts"]:
        atlas_path = assets / "GameResources" / "Fonts" / font["atlas"]
        entry = {
            "font": font["font"],
            "atlas": font["atlas"],
            "atlas_present": atlas_path.exists(),
            "atlas_sha256": (hashlib.sha256(atlas_path.read_bytes()).hexdigest()
                             if atlas_path.exists() else None),
            "glyphs": len(font["glyphs"]),
            "glyphs_with_ink": 0,
            "glyphs_empty": 0,
            "empty_samples": [],
            "max_ink_fraction": 0.0,
        }
        if atlas_path.exists():
            image = Image.open(atlas_path).convert("RGBA")
            for glyph in font["glyphs"]:
                box = (glyph["x"], glyph["y"],
                       glyph["x"] + glyph["width"], glyph["y"] + glyph["height"])
                crop = image.crop(box)
                alpha = crop.getchannel("A")
                ink = sum(1 for value in alpha.getdata() if value)
                total = max(1, crop.width * crop.height)
                if ink:
                    entry["glyphs_with_ink"] += 1
                else:
                    entry["glyphs_empty"] += 1
                    if len(entry["empty_samples"]) < 8:
                        entry["empty_samples"].append(
                            {"char_id": glyph["char_id"], "box": list(box)})
                entry["max_ink_fraction"] = max(entry["max_ink_fraction"], ink / total)
            entry["max_ink_fraction"] = round(entry["max_ink_fraction"], 4)

            # Falsification probe: when the PNG is larger than the declared canvas,
            # crop again at the implied scale. If the empties fill in, the metrics are
            # fine and the sampler owes the scale factor - that is the difference
            # between "broken font" and "mis-read atlas".
            if (font["atlas_size"] and font["scale_w"]
                    and font["atlas_size"][0] % font["scale_w"] == 0):
                ratio = font["atlas_size"][0] // font["scale_w"]
                if ratio > 1:
                    scaled_ink = 0
                    for glyph in font["glyphs"]:
                        box = (glyph["x"] * ratio, glyph["y"] * ratio,
                               (glyph["x"] + glyph["width"]) * ratio,
                               (glyph["y"] + glyph["height"]) * ratio)
                        crop = image.crop(box)
                        if any(crop.getchannel("A").getdata()):
                            scaled_ink += 1
                    entry["scale_probe"] = {"ratio": ratio,
                                            "glyphs_with_ink_at_scale": scaled_ink,
                                            "glyphs": len(font["glyphs"])}
        results.append(entry)

    probes = [r for r in results if "scale_probe" in r]
    counts = {
        "fonts": len(results),
        "fonts_needing_scale": len(probes),
        "glyphs_with_ink_at_implied_scale": sum(
            r["scale_probe"]["glyphs_with_ink_at_scale"] for r in probes),
        "atlases_present": sum(1 for r in results if r["atlas_present"]),
        "glyphs": sum(r["glyphs"] for r in results),
        "glyphs_with_ink": sum(r["glyphs_with_ink"] for r in results),
        "glyphs_empty": sum(r["glyphs_empty"] for r in results),
    }
    return {
        "schema": 1,
        "assets_root": str(assets),
        "claim": ("every glyph rectangle from the parsed metrics is cropped out of the "
                  "real atlas and counted for ink; empty rectangles are reported"),
        "counts": counts,
        "fonts": results,
    }


def render_tsv(record: dict) -> str:
    lines = ["font\tatlas\tglyphs\twith_ink\tempty\tmax_ink_fraction"]
    for entry in record["fonts"]:
        lines.append("\t".join(str(v) for v in (
            entry["font"], entry["atlas"], entry["glyphs"], entry["glyphs_with_ink"],
            entry["glyphs_empty"], entry["max_ink_fraction"])))
    for entry in record["fonts"]:
        for sample in entry["empty_samples"]:
            lines.append(f"empty\t{entry['font']}\tchar={sample['char_id']} "
                         f"box={sample['box']}")
    return "\n".join(lines) + "\n"


def main() -> int:
    native_default = Path("reconstruction/reverse-v3/native")
    ap = argparse.ArgumentParser()
    ap.add_argument("assets", type=Path)
    ap.add_argument("--native", type=Path, default=native_default)
    ap.add_argument("--tsv", type=Path, default=native_default / "font_glyph_content.tsv")
    ap.add_argument("--json", type=Path, default=native_default / "font_glyph_content.json")
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
