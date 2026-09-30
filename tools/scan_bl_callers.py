#!/usr/bin/env python3
"""Scan the pinned ELF for direct bl callers of a given address."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from trace_objc_dispatch import ELFMemory

TARGET = int(sys.argv[1], 16)
LO = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x001C0000
HI = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x00A00000

mem = ELFMemory(Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so')
hits = []
for a in range(LO, HI, 4):
    w = mem.word(a)
    if (w >> 24) == 0xEB:
        imm = w & 0xFFFFFF
        if imm & 0x800000:
            imm -= 1 << 24
        if (a + 8 + (imm << 2)) & 0xFFFFFFFF == TARGET:
            hits.append(a)
print(f"direct bl callers of {TARGET:#x}:", [hex(h) for h in hits])
