#!/usr/bin/env python3
"""Download pinned Frida release assets and verify SHA-256.

Used both locally (Termux/root device) and in GitHub Actions so the
dynamic-tracing toolchain is reproducible without committing binaries.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
import urllib.request
from pathlib import Path

VERSION = "17.17.0"
ASSETS = {
    "frida-server-android-arm64": {
        "url": f"https://github.com/frida/frida/releases/download/{VERSION}/frida-server-{VERSION}-android-arm64.xz",
        "sha256": "55ef78c3f3e7a55122ca7e0051e2a356d0ff1d9744d84c1660291f90400588e7",
        "decompress": "xz",
        "chmod": 0o755,
    },
    # The tracing target is the original 1.7.6 app: dumpsys reports
    # primaryCpuAbi=armeabi-v7a, so it runs as a 32-bit ARM process and only
    # the arm server can attach to it. arm64 stays for the device's own
    # 64-bit tooling. The compressed digest is the one the GitHub release
    # metadata reports, so it is pinnable without a local download; the
    # decompressed digest is printed on first fetch and can be pinned after.
    "frida-server-android-arm": {
        "url": f"https://github.com/frida/frida/releases/download/{VERSION}/frida-server-{VERSION}-android-arm.xz",
        "xz_sha256": "a102c7f83fce8089394c3cc9a05812c841e8f254a80bcf7162280d7c1cbea208",
        "sha256": None,
        "decompress": "xz",
        "chmod": 0o755,
    },
    "frida-17.17.0-cp37-abi3-manylinux2014_aarch64.whl": {
        "url": "https://files.pythonhosted.org/packages/96/d2/b986cebcd1cbf2f34f57f1103417c99816b98b92b4f90d6bcb933854d6c3/frida-17.17.0-cp37-abi3-manylinux2014_aarch64.whl",
        "sha256": "551ba161dc231a137c300ed86b79fe805f8fb59bc0b665828b15160972c15ad4",
        "decompress": None,
        "chmod": None,
    },
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fetch(name: str, spec: dict, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    raw = out_dir / (name + ".download")
    final = out_dir / name
    if final.exists() and spec["sha256"] and sha256(final) == spec["sha256"]:
        print(f"skip {name} (already present, hash ok)")
        return final
    print(f"download {spec['url']}")
    urllib.request.urlretrieve(spec["url"], raw)
    data = raw.read_bytes()
    if spec.get("xz_sha256"):
        actual_xz = hashlib.sha256(data).hexdigest()
        if actual_xz != spec["xz_sha256"]:
            raw.unlink()
            raise SystemExit(
                f"compressed hash mismatch for {name}: {actual_xz} != {spec['xz_sha256']}"
            )
        print(f"ok {name} xz_sha256={actual_xz}")
    if spec["decompress"] == "xz":
        import lzma
        data = lzma.decompress(data)
    raw.unlink()
    final.write_bytes(data)
    if spec["chmod"]:
        final.chmod(spec["chmod"])
    actual = sha256(final)
    if spec["sha256"]:
        if actual != spec["sha256"]:
            final.unlink()
            raise SystemExit(f"hash mismatch for {name}: {actual} != {spec['sha256']}")
    else:
        print(f"note: {name} extracted sha256={actual} (pin it as \"sha256\" to "
              f"lock the extracted binary)")
    print(f"ok {name} sha256={actual}")
    return final


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", type=Path, default=Path(__file__).resolve().parent.parent / ".tools")
    parser.add_argument("--name", choices=list(ASSETS), action="append")
    args = parser.parse_args()
    names = args.name or list(ASSETS)
    for name in names:
        fetch(name, ASSETS[name], args.out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
