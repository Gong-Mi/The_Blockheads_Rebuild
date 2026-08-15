#!/usr/bin/env python3
"""Extract a stable Objective-C/native inventory from libApplication.so.

The output is an index for reverse-engineering, not decompiled source.  It
keeps the binary evidence separate from the new simulation implementation.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

CLASS_RE = re.compile(r"OBJC_(?:CLASS|METACLASS)_\$_([^\s]+)")
IVAR_RE = re.compile(r"OBJC_IVAR_\$_([^\s]+)")
CPP_RE = re.compile(r"_ZN[^\s]+")


def readelf_symbols(binary: Path) -> str:
    p = subprocess.run(
        ["llvm-readelf", "-Ws", str(binary)],
        check=True,
        capture_output=True,
        text=True,
    )
    return p.stdout


def strings(binary: Path) -> str:
    p = subprocess.run(["strings", "-a", str(binary)], check=True, capture_output=True, text=True)
    return p.stdout


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary", type=Path)
    ap.add_argument("--json", type=Path, required=True)
    args = ap.parse_args()

    sym = readelf_symbols(args.binary)
    raw_strings = strings(args.binary)
    classes = sorted(set(CLASS_RE.findall(sym + "\n" + raw_strings)))
    ivars = sorted(set(IVAR_RE.findall(sym + "\n" + raw_strings)))
    cpp_symbols = sorted(set(CPP_RE.findall(sym)))
    header = subprocess.run(
        ["llvm-readelf", "-h", str(args.binary)], check=True, capture_output=True, text=True
    ).stdout
    result = {
        "binary": str(args.binary),
        "elf_class": "ELF32 ARM" if "Class:" in header and "ELF32" in header and "ARM" in header else "unknown",
        "classes": classes,
        "ivars": ivars,
        "cpp_symbols": cpp_symbols,
        "class_count": len(classes),
        "ivar_count": len(ivars),
        "cpp_symbol_count": len(cpp_symbols),
    }
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(f"classes={len(classes)} ivars={len(ivars)} cpp_symbols={len(cpp_symbols)}")
    print(f"output={args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
