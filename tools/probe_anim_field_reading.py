#!/usr/bin/env python3
"""Decide the ivar reading with the correct access shape.

-[Blockhead updateAnimation] writes the animation id at `[self + ivar_off + 0x4c]`
(the listing is `str rX, [r3, #0x4c]` with `r3 = self + ivar_off`), so `state` is an
embedded member, not a pointer. The right probe is therefore a direct read at
`instance + ivar_off + 0x4c`, and the value must be one of the small animation ids
the same listing assigns (0, 7, 14, 23, 32).
"""
from __future__ import annotations

import os
import re
import struct
import subprocess
from pathlib import Path

from elftools.elf.elffile import ELFFile

ELF = Path("/data/data/com.termux/files/home/blockheads-work/extracted/lib/"
           "armeabi-v7a/libApplication.so")
RW_FILE_OFF = 0x00E32000
ANIM_IDS = {0, 7, 14, 23, 32}


def main() -> int:
    pid = subprocess.check_output(["pidof", "com.noodlecake.blockheads"]).decode().split()[0]
    base_rw = None
    with open(f"/proc/{pid}/maps") as fh:
        for line in fh:
            if "libApplication.so" in line and line.split()[1] == "rw-p":
                base_rw = int(line.split("-")[0], 16)
    fd = os.open(f"/proc/{pid}/mem", os.O_RDONLY)

    def rd(a, n):
        try:
            return os.pread(fd, n, a)
        except OSError:
            return b""

    def dw(a):
        b = rd(a, 4)
        return struct.unpack("<i", b)[0] if len(b) == 4 else None

    def cell(elf):
        return struct.unpack("<i", rd(base_rw + (elf - RW_FILE_OFF), 4))[0]

    with ELF.open("rb") as fh:
        blob = fh.read()
        e = ELFFile(fh)
        syms = {s.name: s["st_value"] for s in e.get_section_by_name(".dynsym").iter_symbols()
                if s["st_value"]}

    isa = dw(base_rw + (syms["OBJC_CLASS_$_Blockhead"] - RW_FILE_OFF))
    print(f"pid={pid} Blockhead realized isa={hex(isa)}")

    pat, objs = struct.pack("<I", isa), []
    with open(f"/proc/{pid}/maps") as fh:
        maps = list(fh)
    for line in maps:
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S+) \S+ \S+ \d+\s*(.*)", line)
        if not m:
            continue
        start, end, perms, path = int(m.group(1), 16), int(m.group(2), 16), m.group(3), m.group(4)
        if start >= 0x100000000 or "rw" not in perms or "dalvik" in path:
            continue
        if path and "[" not in path and "libApplication" not in path:
            continue
        pos = start
        while pos < end and len(objs) < 8:
            data = rd(pos, min(8 << 20, end - pos))
            if not data:
                break
            i = data.find(pat)
            while i >= 0 and len(objs) < 8:
                objs.append(pos + i)
                i = data.find(pat, i + 4)
            pos += len(data)
    print(f"instances: {[hex(o) for o in objs]}")

    elf_state = struct.unpack_from("<i", blob, syms["OBJC_IVAR_$_Blockhead.state"])[0]
    live_state = cell(syms["OBJC_IVAR_$_Blockhead.state"])
    print(f"Blockhead.state  file-content={elf_state}  process-content={live_state}")

    verdict = {"file-content": 0, "process-content": 0}
    for obj in objs:
        for label, off in (("file-content", elf_state), ("process-content", live_state)):
            v = dw(obj + off + 0x4C)
            mark = "  in ANIM_IDS" if v in ANIM_IDS else ""
            if v in ANIM_IDS:
                verdict[label] += 1
            print(f"  obj {hex(obj)} state@{off:<5} ({label:15s}) "
                  f"-> [obj+{off}+0x4c] = {v}{mark}")

    print(f"\nverdict: animation-id hits per reading = {verdict}")
    os.close(fd)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
