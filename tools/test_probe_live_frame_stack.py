#!/usr/bin/env python3
"""Contract test for tools/probe_live_frame_stack.py.

Two layers:
  1. bookkeeping (runs everywhere, including CI): attribute_word credit / unnamed /
     unresolved rules, words_from_blob filtering, calibration constants shape;
  2. synthetic decode cases (self-skip when capstone is unavailable): hand-assembled
     A32 and Thumb instruction sequences exercising callsite_ok and the prologue
     walk-back on known ground truth.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import probe_live_frame_stack as probe  # noqa: E402


def make_lib(addr: int, words: list[int]) -> bytes:
    blob = bytearray(addr + 4 * len(words) + 0x100)
    for i, w in enumerate(words):
        struct.pack_into("<I", blob, addr + 4 * i, w)
    return bytes(blob)


def main() -> int:
    methods = [(0x1000, "Cls", "instance", "a:"), (0x2000, "Other", "class", "b:")]
    imps = [m[0] for m in methods]
    imp_set = set(imps)

    # --- bookkeeping ---------------------------------------------------------
    rec = probe.attribute_word(0x1050, methods, imps, imp_set, True, 0x1000)
    assert rec["verdict"] == "credited", rec
    assert rec["offset"] == 0x50 and rec["class"] == "Cls", rec

    rec = probe.attribute_word(0x1050, methods, imps, imp_set, True, 0x1040)
    assert rec["verdict"] == "unnamed" and rec["fn_start"] == "0x00001040", rec
    # nearest-below bookkeeping stays available even for unnamed frames
    assert rec["nearest_below"]["class"] == "Cls", rec

    rec = probe.attribute_word(0x1050, methods, imps, imp_set, True, None)
    assert rec["verdict"] == "unresolved", rec

    rec = probe.attribute_word(0x1050, methods, imps, imp_set, False, 0x1000)
    assert rec["callsite"] is False and rec["verdict"] == "credited", rec

    blob = struct.pack("<III", 0x11111111, 1, 0x22222222)
    got = probe.words_from_blob(blob, 0x4000, 0, 2)
    assert got == [(0x4004, 1)], got
    got = probe.words_from_blob(blob, 0x4000, 2, 0x100000000)
    assert got == [(0x4000, 0x11111111), (0x4008, 0x22222222)], got

    assert probe.CALIBRATION["positive_frames"], probe.CALIBRATION
    assert probe.CALIBRATION["negative_noncall"], probe.CALIBRATION
    assert probe.CALIBRATION["unnamed_expected"], probe.CALIBRATION

    # --- synthetic decode cases ---------------------------------------------
    if not probe._HAVE_CAPSTONE:
        print("skip: capstone not available (synthetic decode cases)")
        print("live-frame-probe: PASS (bookkeeping only)")
        return 0

    # A32: push {r4, lr}; mov r4, sp; bl; mov r0, r0
    addr = 0x10000
    lib = make_lib(addr, [0xE92D4010, 0xE1A0400D, 0xEB000004, 0xE1A00000])
    ok, insn = probe.callsite_ok(lib, addr + 12)
    assert ok and insn is not None and "bl" in insn, (ok, insn)
    ok2, _ = probe.callsite_ok(lib, addr + 16)  # after the mov, not a call return
    assert not ok2
    assert probe.fn_start_a32(lib, addr + 12) == addr
    # walk-back bound respected
    assert probe.fn_start_a32(lib, addr + 12, bound=8) is None

    # Thumb: push {lr}; nop; blx r3; nop
    taddr = 0x20000
    tblob = bytearray(taddr + 0x20)
    tblob[taddr:taddr + 8] = b"\x00\xb5\x00\xbf\x98\x47\x00\xbf"
    tlib = bytes(tblob)
    ok, insn = probe.callsite_ok(tlib, taddr + 6)
    assert ok and insn is not None and "blx" in insn, (ok, insn)
    assert probe.fn_start_t16(tlib, taddr + 6) == taddr

    print("live-frame-probe: PASS (bookkeeping + synthetic decode)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
