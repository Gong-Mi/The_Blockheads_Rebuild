#!/usr/bin/env python3
"""Compare static ELF ivar-offset cells against the live realized values.

The disassembly listings annotate `OBJC_IVAR_$_Class.ivar` storage cells with the
word found in the ELF *file* at that address. This script dumps the same word from
the running process and from the file, side by side, for the four classes whose
live layout was already recorded.

If the two columns differ, the listing annotation is a pre-realization value and
must not be used as a runtime field offset.
"""
from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elftools.elf.elffile import ELFFile  # noqa: E402

ELF = Path(os.environ.get(
    "BH_ELF",
    "/data/data/com.termux/files/home/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so"))
NATIVE = Path(__file__).resolve().parent.parent / "reconstruction/reverse-v3/native"
RW_FILE_OFF = 0x00E32000


def ivar_symbols() -> dict[str, int]:
    """Every OBJC_IVAR_$_<Class>.<ivar> symbol -> its storage-cell VMA in the ELF."""
    out = {}
    with ELF.open("rb") as fh:
        e = ELFFile(fh)
        for s in e.get_section_by_name(".dynsym").iter_symbols():
            if s.name.startswith("OBJC_IVAR_$_") and s["st_value"]:
                out[s.name[len("OBJC_IVAR_$_"):]] = s["st_value"]
    return out


def elf_cells(syms: dict[str, int]) -> dict[str, int]:
    out = {}
    with ELF.open("rb") as fh:
        blob = fh.read()
    for name, addr in syms.items():
        if addr + 4 <= len(blob):
            out[name] = struct.unpack_from("<i", blob, addr)[0]
    return out


def live_cells(pid: str, base_rw: int, syms: dict[str, int]) -> dict[str, int]:
    fd = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
    out = {}
    try:
        for name, addr in syms.items():
            try:
                b = os.pread(fd, 4, base_rw + (addr - RW_FILE_OFF))
            except OSError:
                continue
            if len(b) == 4:
                out[name] = struct.unpack("<i", b)[0]
    finally:
        os.close(fd)
    return out


def main() -> int:
    pid = subprocess.check_output(["pidof", "com.noodlecake.blockheads"]).decode().split()[0]
    base_rw = None
    with open(f"/proc/{pid}/maps") as fh:
        for line in fh:
            if "libApplication.so" in line and "rw-p" in line:
                base_rw = int(line.split("-")[0], 16)
                break
    syms = ivar_symbols()
    static = elf_cells(syms)
    live = live_cells(pid, base_rw, syms)

    same = [k for k in live if k in static and static[k] == live[k]]
    diff = [(k, static[k], live[k]) for k in sorted(live)
            if k in static and static[k] != live[k]]

    print(f"pid={pid} base_rw=0x{base_rw:x}")
    print(f"compared {len(live)} ivar storage cells: {len(same)} identical, {len(diff)} rewritten")
    for key in ("Blockhead.hatCube", "Blockhead.bodyCube", "Blockhead.state",
                "DonkeyLike.bodyMatrix", "DonkeyLike.walkTimer",
                "DynamicObject.floatPos", "World.saveID"):
        if key in live:
            print(f"  {key:34s} static={static.get(key)!s:<7} live={live[key]}")

    payload = {
        "pid": int(pid),
        "lib_rw_base": f"0x{base_rw:x}",
        "cells_compared": len(live),
        "cells_identical": len(same),
        "cells_rewritten": len(diff),
        "live_offsets": dict(sorted(live.items())),
        "claim": ("the ELF file-content and the process-content of OBJC_IVAR_$_ storage cells "
                  "disagree almost everywhere, so an annotated listing's trailing number "
                  "identifies the ivar a method touches but is not a verified runtime offset. "
                  "live_offsets records the process-content reading as a CANDIDATE table: no "
                  "test has yet decided between the two readings, and the object-graph walk "
                  "that would decide it has not been run (see IVAR_OFFSET_READING.md)."),
    }
    out = NATIVE / "live_ivar_offset_divergence.json"
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
