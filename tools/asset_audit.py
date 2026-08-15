#!/usr/bin/env python3
"""Audit Blockheads asset references against the APK or an extracted asset tree.

This is intentionally stdlib-only so it can run on Termux and in CI.  It does
not infer atlas coordinates.  It only establishes the source-of-truth asset
names and dimensions before renderer work starts.
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import sys
import zipfile
from pathlib import Path

PNG_SIG = b"\x89PNG\r\n\x1a\n"
ASSET_RE = re.compile(r'"([A-Za-z0-9_./+\-]+\.(?:png|wav|fsh|vsh|otf|fnt))"')


def png_size(data: bytes) -> list[int] | None:
    if len(data) < 24 or data[:8] != PNG_SIG or data[12:16] != b"IHDR":
        return None
    return list(struct.unpack(">II", data[16:24]))


def apk_assets(path: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    with zipfile.ZipFile(path) as zf:
        for name in zf.namelist():
            if not name.startswith("assets/") or name.endswith("/"):
                continue
            base = name.rsplit("/", 1)[-1]
            data = zf.read(name)
            row = {"apk_path": name, "bytes": len(data)}
            size = png_size(data)
            if size:
                row["width"], row["height"] = size
            out[base] = row
    return out


def tree_assets(path: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for p in path.rglob("*"):
        if not p.is_file():
            continue
        row = {"path": str(p.relative_to(path)), "bytes": p.stat().st_size}
        if p.suffix.lower() == ".png":
            size = png_size(p.read_bytes()[:32])
            if size:
                row["width"], row["height"] = size
        out[p.name] = row
    return out


def references(repo: Path) -> list[str]:
    files = [
        repo / "app/src/main/cpp/world_renderer.cpp",
        repo / "app/src/main/java/com/noodlecake/blockheads/rebuild/GameActivity.java",
        repo / "app/src/main/java/com/noodlecake/blockheads/rebuild/MainMenuActivity.java",
    ]
    found: set[str] = set()
    for p in files:
        if p.exists():
            found.update(ASSET_RE.findall(p.read_text(errors="replace")))
    return sorted(found)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk", type=Path)
    ap.add_argument("--assets", type=Path)
    ap.add_argument("--repo", type=Path, default=Path("."))
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()
    if bool(args.apk) == bool(args.assets):
        ap.error("choose exactly one of --apk or --assets")

    catalog = apk_assets(args.apk) if args.apk else tree_assets(args.assets)
    refs = references(args.repo)
    missing = [name for name in refs if name not in catalog]
    result = {
        "source": str(args.apk or args.assets),
        "reference_count": len(refs),
        "asset_count": len(catalog),
        "missing_references": missing,
        "assets": catalog,
    }
    text = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(text)
    print(f"source={result['source']}")
    print(f"references={len(refs)} assets={len(catalog)} missing={len(missing)}")
    for name in missing:
        print(f"MISSING {name}")
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
