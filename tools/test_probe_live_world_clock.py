#!/usr/bin/env python3
"""Contract test for tools/probe_live_world_clock.py.

Layer 1 (runs everywhere, incl. CI): pure helpers against hand-built blobs --
`decode_ivar_list` on a synthetic 32-bit ivar_list_t with a POSITIVE control
(two entries decode to the exact names/types/cells written in) and NEGATIVE
controls (degenerate entsize, zero count, absurd count, unterminated string,
out-of-range reads must raise rather than return an empty list); `slope`;
`binding_verdict`.

Layer 2: the live path self-skips (`skip: <reason>`, exit 0) when there is no
running target or no pinned ELF, so "missing input" is never reported as a defect.
"""
from __future__ import annotations

import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import probe_live_world_clock as probe  # noqa: E402

ENTSIZE = 20


def build_synthetic_ivar_list() -> tuple[bytes, int]:
    """[entsize][count] + 2 entries, with the offset cells and strings laid out.

    Every string write slices to the exact payload length: a bytearray slice
    assignment of a different length resizes the buffer and shifts the tail,
    which is how this fixture first decoded to an empty encoding.
    """
    blob = bytearray(0x1000)
    ivars_va, strings, encs = 0x400, 0x600, 0x900
    entries = [(0x500, "worldTime", "d", 8), (0x504, "fastForward", "c", 1)]
    for i, (cell, name, enc, size) in enumerate(entries):
        nb, eb = name.encode() + b"\0", enc.encode() + b"\0"
        no, eo = strings + i * 0x20, encs + i * 0x20
        blob[no:no + len(nb)] = nb
        blob[eo:eo + len(eb)] = eb
        struct.pack_into("<IIII", blob, ivars_va + 8 + i * ENTSIZE, cell, no, eo, size)
    struct.pack_into("<II", blob, ivars_va, ENTSIZE, len(entries))
    struct.pack_into("<i", blob, 0x500, 648)     # the cells hold the runtime offsets
    struct.pack_into("<i", blob, 0x504, 934)
    return bytes(blob), ivars_va


def main() -> int:
    blob, ivars_va = build_synthetic_ivar_list()
    ivars = probe.decode_ivar_list(blob, ivars_va)
    assert len(ivars) == 2, ivars
    assert ivars[0] == {"offset_ptr": 0x500, "name": "worldTime", "encoding": "d",
                        "size": 8}, ivars[0]
    assert ivars[1] == {"offset_ptr": 0x504, "name": "fastForward", "encoding": "c",
                        "size": 1}, ivars[1]
    assert struct.unpack_from("<i", blob, ivars[0]["offset_ptr"])[0] == 648
    assert struct.unpack_from("<i", blob, ivars[1]["offset_ptr"])[0] == 934

    # negative controls: a degenerate header must raise, never silently return []
    for bad_entsize, bad_count in ((0, 2), (12, 2), (ENTSIZE, 99999), (ENTSIZE, 0)):
        broken = bytearray(blob)
        struct.pack_into("<II", broken, ivars_va, bad_entsize, bad_count)
        try:
            probe.decode_ivar_list(bytes(broken), ivars_va)
        except ValueError:
            pass
        else:
            raise AssertionError(f"degenerate header accepted: {bad_entsize},{bad_count}")

    # an unterminated name must raise, not decode to a truncated string
    unterminated = bytearray(blob)
    unterminated[-300:] = b"A" * 300
    struct.pack_into("<I", unterminated, ivars_va + 8 + 4, len(unterminated) - 300)
    try:
        probe.decode_ivar_list(bytes(unterminated), ivars_va)
    except ValueError:
        pass
    else:
        raise AssertionError("unterminated cstring accepted")

    for bad_off in (-4, len(blob) + 8):
        try:
            probe.read_cstr(blob, bad_off)
        except ValueError:
            pass
        else:
            raise AssertionError(f"out-of-range cstring accepted at {bad_off}")
    for bad_off in (-4, len(blob)):
        try:
            probe.read_u32(blob, bad_off)
        except ValueError:
            pass
        else:
            raise AssertionError(f"out-of-range u32 accepted at {bad_off}")

    # slope
    assert probe.slope([0, 1, 2, 3], [0, 1, 2, 3]) == 1.0
    assert abs(probe.slope([0, 1, 2, 3], [0, 2, 4, 6]) - 2.0) < 1e-12
    assert abs(probe.slope([0, 1, 2, 3], [5, 5, 5, 5])) < 1e-12
    for xs, ys in (([0], [1]), ([0, 0], [1, 2]), ([0, 1, 2], [1, 2])):
        try:
            probe.slope(xs, ys)
        except ValueError:
            pass
        else:
            raise AssertionError(f"slope accepted degenerate input {xs} {ys}")

    assert probe.binding_verdict("a" * 64, "a" * 64) == "ok"
    assert probe.binding_verdict("a" * 64, "b" * 64) == "BUILD MISMATCH"

    # the tool must refuse to measure across builds and must never default an output path
    src = (ROOT / "tools/probe_live_world_clock.py").read_text()
    assert "BUILD MISMATCH" in src, "build guard missing"
    assert 'ap.add_argument("--json", default=None' in src, "output path gained a default"

    # layer 2: self-skip when the environment cannot run the live path
    try:
        pid = subprocess.run(["pidof", probe.PKG], capture_output=True,
                             text=True, timeout=10).stdout.split()
    except (OSError, subprocess.SubprocessError):
        pid = []          # no pidof in this environment is not a defect
    pinned = ROOT.parent / "extracted/lib/armeabi-v7a/libApplication.so"
    if not pid:
        print(f"skip: {probe.PKG} is not running (or not visible to this uid)")
        return 0
    if not pinned.is_file():
        print(f"skip: pinned ELF not present at {pinned}")
        return 0
    print("pure helpers verified; live target present (run the probe directly)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
