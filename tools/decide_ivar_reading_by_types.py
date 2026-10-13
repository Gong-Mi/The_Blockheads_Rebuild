#!/usr/bin/env python3
"""Decide which ivar-offset reading is real, using type invariants.

Value tests that depend on game state are inconclusive (a net-controlled blockhead
skips the whole animation mapping). Types, however, are state-independent:

    DynamicObject.isNet        char   -> must be 0 or 1
    DynamicObject.floatPos     float2 -> finite and |v| < 1e5
    DynamicObject.pos          int2   -> |v| < 1e5

Both candidate readings are applied to every live instance found for a set of
concrete classes; the reading whose fields satisfy the type constraints wins.
"""
from __future__ import annotations

import math
import os
import re
import struct
import subprocess
from pathlib import Path

from elftools.elf.elffile import ELFFile

ELF = Path("/data/data/com.termux/files/home/blockheads-work/extracted/lib/"
           "armeabi-v7a/libApplication.so")
RW_FILE_OFF = 0x00E32000
PROBE_CLASSES = ("Blockhead", "DynamicWorld", "World", "UIManager", "WorldUI", "GameView",
                 "FreeBlock", "Workbench", "Chest", "TradePortal", "AppleTree", "Dodo", "Donkey")


def main() -> int:
    pid = subprocess.check_output(["pidof", "com.noodlecake.blockheads"]).decode().split()[0]
    base_rw = None
    with open(f"/proc/{pid}/maps") as fh:
        maps = list(fh)
    for line in maps:
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

    def dd(a):
        return struct.unpack("<i", rd(a, 4))[0] if len(rd(a, 4)) == 4 else None

    def cell(elf):
        return struct.unpack("<i", rd(base_rw + (elf - RW_FILE_OFF), 4))[0]

    with ELF.open("rb") as fh:
        blob = fh.read()
        e = ELFFile(fh)
        syms = {s.name: s["st_value"] for s in e.get_section_by_name(".dynsym").iter_symbols()
                if s["st_value"]}

    def file_off(name):
        return struct.unpack_from("<i", blob, syms[f"OBJC_IVAR_$_DynamicObject.{name}"])[0]

    def live_off(name):
        return cell(syms[f"OBJC_IVAR_$_DynamicObject.{name}"])

    readings = {
        "file-content": {n: file_off(n) for n in ("isNet", "floatPos", "pos")},
        "process-content": {n: live_off(n) for n in ("isNet", "floatPos", "pos")},
    }
    print(f"pid={pid}  DynamicObject ivar readings: {readings}")

    # realized isa per probe class
    isa_of = {}
    for cls in PROBE_CLASSES:
        v = dw(base_rw + (syms[f"OBJC_CLASS_$_{cls}"] - RW_FILE_OFF))
        if v:
            isa_of[v] = cls
    print(f"resolved {len(isa_of)} of {len(PROBE_CLASSES)} probe classes")

    # one pass over rw memory collecting instance addresses
    pats = {struct.pack("<I", v): c for v, c in isa_of.items()}
    found: dict[str, list[int]] = {c: [] for c in isa_of.values()}
    for line in maps:
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S+) \S+ \S+ \d+\s*(.*)", line)
        if not m:
            continue
        start, end, perms, path = int(m.group(1), 16), int(m.group(2), 16), m.group(3), m.group(4)
        if start >= 0x100000000 or "rw" not in perms or "dalvik" in path:
            continue
        # instances live in anonymous/scudo heaps; a match inside libApplication.so's own
        # mappings is a metadata reference (class refs, method lists), not an object header
        if "libApplication" in path:
            continue
        if path and "[" not in path:
            continue
        pos = start
        while pos < end:
            data = rd(pos, min(8 << 20, end - pos))
            if not data:
                break
            for pat, cls in pats.items():
                i = data.find(pat)
                while i >= 0 and len(found[cls]) < 40:
                    found[cls].append(pos + i)
                    i = data.find(pat, i + 4)
            pos += len(data)

    total = sum(len(v) for v in found.values())
    print(f"instances: " + ", ".join(f"{c}={len(v)}" for c, v in found.items() if v) +
          f"  (total {total})")
    if not total:
        print("no instances reachable; cannot decide")
        os.close(fd)
        return 1

    score = {k: {"isNet": 0, "floatPos": 0, "pos": 0, "objects": 0} for k in readings}
    for cls, addrs in found.items():
        for obj in addrs:
            for label, offs in readings.items():
                s = score[label]
                s["objects"] += 1
                b = rd(obj + offs["isNet"], 1)
                if b and b[0] in (0, 1):
                    s["isNet"] += 1
                raw = rd(obj + offs["floatPos"], 8)
                if len(raw) == 8:
                    fx, fy = struct.unpack("<ff", raw)
                    if math.isfinite(fx) and math.isfinite(fy) and abs(fx) < 1e5 and abs(fy) < 1e5:
                        s["floatPos"] += 1
                raw = rd(obj + offs["pos"], 8)
                if len(raw) == 8:
                    px, py = struct.unpack("<ii", raw)
                    if abs(px) < 1e5 and abs(py) < 1e5:
                        s["pos"] += 1

    print("\ntype-constraint pass rate (higher is the real reading):")
    for label, s in score.items():
        n = max(1, s["objects"])
        print(f"  {label:16s} objects={s['objects']:3d}  "
              f"isNet {s['isNet']:3d}/{n}  floatPos {s['floatPos']:3d}/{n}  pos {s['pos']:3d}/{n}")

    winner = max(score, key=lambda k: sum(score[k][f] for f in ("isNet", "floatPos", "pos")))
    print(f"\nverdict: {winner}")
    os.close(fd)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
