#!/usr/bin/env python3
"""The audio API surface the replacement has to implement.

Two in-repo/ELF sources, joined per class: the ObjC method map (selectors, kind, IMPs)
and the binary's own `OBJC_IVAR_$` entries. The result is the list of calls a sound
system has to answer - `soundNamed:`, `multiSoundNamed:`, `playAtPosition:`, the MP3
lifecycle, interruption handling - which is what wiring the 161 shipped audio files
actually requires.

Usage:
  python3 tools/extract_audio_api.py [--elf PATH] [--methods PATH] [--tsv OUT] [--json OUT] [--check]
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import struct
import sys
from pathlib import Path

CLASSES = ("MJSoundManager", "MJSound", "MJMultiSound", "SoundOptionsUI")
DEFAULT_ELF = Path.home() / "blockheads-work/extracted/lib/armeabi-v7a/libApplication.so"


def ivars(elf_path: Path) -> dict[str, list[str]]:
    elf = elf_path.read_bytes()
    shoff = struct.unpack_from("<I", elf, 32)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", elf, 46)
    secs = {}
    for i in range(shnum):
        f = struct.unpack_from("<10I", elf, shoff + i * shentsize)
        secs[i] = {"type": f[1], "off": f[4], "size": f[5], "link": f[6]}
    out: dict[str, list[str]] = {}
    for sec in secs.values():
        if sec["type"] != 11:
            continue
        stroff = secs[sec["link"]]["off"]
        for k in range(sec["size"] // 16):
            so = sec["off"] + k * 16
            st_name, st_value, st_size = struct.unpack_from("<III", elf, so)
            end = elf.index(b"\0", stroff + st_name)
            name = elf[stroff + st_name:end].decode("latin1", errors="replace")
            if not name.startswith("OBJC_IVAR_$_"):
                continue
            owner, _, field = name[len("OBJC_IVAR_$_"):].partition(".")
            if owner in CLASSES and field:
                out.setdefault(owner, []).append(field)
    return {cls: sorted(set(fields)) for cls, fields in out.items()}


def build(elf_path: Path, methods_path: Path) -> dict:
    methods = {cls: [] for cls in CLASSES}
    with methods_path.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh, delimiter="\t"):
            cls = row["class"]
            if cls in methods:
                methods[cls].append({"kind": row["kind"],
                                     "implementation": row["implementation"],
                                     "selector": row["selector"]})
    for cls in methods:
        methods[cls].sort(key=lambda r: r["selector"])
    ivar_map = ivars(elf_path)
    counts = {
        "classes": len(CLASSES),
        "methods_total": sum(len(v) for v in methods.values()),
        "ivars_total": sum(len(v) for v in ivar_map.values()),
        "classes_with_methods": sum(1 for v in methods.values() if v),
    }
    return {
        "schema": 1,
        "elf_sha256": hashlib.sha256(elf_path.read_bytes()).hexdigest(),
        "claim": ("audio API surface: the MJSound* / SoundOptionsUI selectors the binary "
                  "exposes, with the per-class ivar lists; this is the set of calls a "
                  "sound implementation has to answer for the shipped audio files"),
        "counts": counts,
        "classes": {cls: {"methods": methods[cls], "ivars": ivar_map.get(cls, [])}
                    for cls in CLASSES},
    }


def render_tsv(record: dict) -> str:
    lines = ["class\tkind\timplementation\tselector"]
    for cls, entry in record["classes"].items():
        for method in entry["methods"]:
            lines.append(f"{cls}\t{method['kind']}\t{method['implementation']}\t"
                         f"{method['selector']}")
        for ivar in entry["ivars"]:
            lines.append(f"{cls}\tivar\t\t{ivar}")
    return "\n".join(lines) + "\n"


def main() -> int:
    native = Path("reconstruction/reverse-v3/native")
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", type=Path, default=DEFAULT_ELF)
    ap.add_argument("--methods", type=Path,
                    default=native / "libApplication_objc_methods.tsv")
    ap.add_argument("--tsv", type=Path, default=native / "audio_api_surface.tsv")
    ap.add_argument("--json", type=Path, default=native / "audio_api_surface.json")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    if not args.elf.exists():
        print(f"skip: no ELF at {args.elf}")
        return 0
    record = build(args.elf, args.methods)
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
