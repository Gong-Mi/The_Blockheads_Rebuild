#!/usr/bin/env python3
"""Validate the packaged APK contains the runtime contract checked in source."""
from pathlib import Path
import sys
import zipfile

REQUIRED_ASSETS = {
    "assets/Block.vsh",
    "assets/Block.fsh",
    "assets/Item.vsh",
    "assets/Item.fsh",
    "assets/Items.png",
    "assets/ItemNormals.png",
    "assets/selectionBox40.png",
    "assets/yakLegs.png",
    "assets/grizratBodyFront.png",
    "assets/grizratHead.png",
}
REQUIRED_NATIVE = {"lib/arm64-v8a/libnative-lib.so", "lib/armeabi-v7a/libnative-lib.so"}


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} APK", file=sys.stderr)
        return 2
    apk = Path(sys.argv[1])
    if not apk.is_file():
        print(f"APK not found: {apk}", file=sys.stderr)
        return 2
    with zipfile.ZipFile(apk) as zf:
        names = set(zf.namelist())
    errors = []
    missing_assets = sorted(REQUIRED_ASSETS - names)
    if missing_assets:
        errors.append("missing assets: " + ", ".join(missing_assets))
    if not REQUIRED_NATIVE & names:
        errors.append("no native-lib ABI payload found")
    if "AndroidManifest.xml" not in names:
        errors.append("missing AndroidManifest.xml")
    if errors:
        for error in errors:
            print("FAIL", error)
        return 1
    native = sorted(REQUIRED_NATIVE & names)
    print(f"apk-contract: PASS assets={len(REQUIRED_ASSETS)} native={','.join(native)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
