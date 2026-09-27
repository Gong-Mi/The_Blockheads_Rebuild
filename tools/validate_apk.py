#!/usr/bin/env python3
"""Validate the packaged APK contains the runtime contract checked in source.

The required-asset set is the checked-in baseline PLUS every exact string
world_renderer.cpp passes to AAssetManager (loadTex/loadShaderSource), so a
new renderer asset reference cannot ship without being packaged.
"""
from pathlib import Path
import hashlib
import re
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_ASSETS = {
    "assets/Block.vsh",
    "assets/Block.fsh",
    "assets/Item.vsh",
    "assets/Item.fsh",
    "assets/Items.png",
    "assets/HDTex/TileMap.png",
    "assets/HDTex/TileDestruct.png",
    "assets/HDTex/Items.png",
    "assets/HDTex/TileReflect.png",
    "assets/white.png",
    "assets/ItemNormals.png",
    "assets/selectionBox40.png",
    "assets/yakLegs.png",
    "assets/grizratBodyFront.png",
    "assets/grizratHead.png",
    "assets/gamedata/items.json",
    "assets/gamedata/recipes.json",
}
REQUIRED_NATIVE = {"lib/arm64-v8a/libnative-lib.so", "lib/armeabi-v7a/libnative-lib.so"}
ORIGINAL_ASSET_HASHES = {
    "assets/HDTex/TileMap.png": "69b238ba31507217edf0b4bd72ec33a295f36c368c02fad066007e614b1a84a1",
    "assets/HDTex/TileDestruct.png": "8541a14da0eae3996ddd2ac552e2368dc09bff9a617b40c347dd281a5a5c2b84",
    "assets/HDTex/Items.png": "92907535ff7b7f5d3fe58a08bd67b44573e66bf1faf49c8a86dad5f14bc9efa5",
    "assets/HDTex/TileReflect.png": "4ef1575577a0dedc80a0c9f11c9427a8fdf5ea01c680d97d8b6d9ac91f9ac965",
    "assets/white.png": "22067ea4ca01ce5c8c655ca6956f10480257250e06babd1facc32b095f78d1c1",
}
NATIVE_OPEN_RE = re.compile(r'"([^"]+\.(?:png|fsh|vsh))"')


def renderer_required() -> set:
    """Exact asset strings the renderer passes to AAssetManager_open."""
    src = (ROOT / "app/src/main/cpp/world_renderer.cpp").read_text()
    return {"assets/" + n for n in NATIVE_OPEN_RE.findall(src)}


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} APK", file=sys.stderr)
        return 2
    apk = Path(sys.argv[1])
    if not apk.is_file():
        print(f"APK not found: {apk}", file=sys.stderr)
        return 2
    required = REQUIRED_ASSETS | renderer_required()
    with zipfile.ZipFile(apk) as zf:
        names = set(zf.namelist())
        packaged_hashes = {
            name: hashlib.sha256(zf.read(name)).hexdigest()
            for name in ORIGINAL_ASSET_HASHES
            if name in names
        }
    errors = []
    missing_assets = sorted(required - names)
    if missing_assets:
        errors.append("missing assets: " + ", ".join(missing_assets))
    for name, expected in ORIGINAL_ASSET_HASHES.items():
        actual = packaged_hashes.get(name)
        if actual is not None and actual != expected:
            errors.append(f"original asset hash mismatch: {name} {actual}")
    if not REQUIRED_NATIVE & names:
        errors.append("no native-lib ABI payload found")
    if "AndroidManifest.xml" not in names:
        errors.append("missing AndroidManifest.xml")
    if errors:
        for error in errors:
            print("FAIL", error)
        return 1
    native = sorted(REQUIRED_NATIVE & names)
    print(f"apk-contract: PASS assets={len(required)} native={','.join(native)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
