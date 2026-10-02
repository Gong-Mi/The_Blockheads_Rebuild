#!/usr/bin/env python3
"""Recapture the live UIKitMain frame stack with build binding and two verification gates.

Method (see native/LIVE_FRAME_STACK.md):
  - call-site gate: a bl/blx instruction must end exactly at the candidate address
    (ARM and Thumb decodes are both tried; this binary's code is A32-dominant and a
    Thumb-only decoder misses the world frames);
  - enclosing-function gate: walk back (A32, 4-byte steps) to the nearest
    push-with-lr prologue - for a call-return address that start is the containing
    non-leaf function. An Objective-C method is credited ONLY on an exact method-table
    imp match; otherwise the frame is recorded as an unnamed function by raw start.

The tool refuses to measure when --lib does not match the library file mapped in the
process (BUILD MISMATCH), mirroring probe_live_ivar_offsets.py. When the audited build
(sha256 prefix d09418e9) is in play, an inlined calibration block (2 positive frames
resolve to their imps, 2 byte-verified non-calls stay non-calls, 1 known unnamed region
stays unnamed) must pass or the tool exits without reporting.

Usage (root; the process must already be running):
  su -c '<python3> tools/probe_live_frame_stack.py --pid <pid> \
        --lib <same-build libApplication.so> --methods <same-build methods.tsv> \
        [--out frames.json]'

Environment defaults: BH_LIVE_LIB, BH_LIVE_METHODS.
"""
from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import os
import struct
import sys
from datetime import datetime
from pathlib import Path

try:
    from capstone import CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, Cs

    _HAVE_CAPSTONE = True
except ImportError:  # CI runners do not ship capstone
    _HAVE_CAPSTONE = False

try:
    from elftools.elf.elffile import ELFFile

    _HAVE_ELFTOOLS = True
except ImportError:
    _HAVE_ELFTOOLS = False

AUDITED_BUILD_SHA256 = "d09418e9c0865902054a71358dcff3264d47f7b24ede58667cb5ea0e6f269b96"
CALIBRATION = {
    "positive_frames": [(0xD129B0, 0xD12858), (0x526F2C, 0x526970)],
    "negative_noncall": [0x242744, 0x243178],
    "unnamed_expected": [0xC389C8],
}

DEFAULT_WINDOW = 0x80000
DEFAULT_BOUND = 0x40000
DEFAULT_CAP = 96

_MD_T = None
_MD_A = None


def _mds():
    global _MD_T, _MD_A
    if _MD_T is None:
        _MD_T = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        _MD_A = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        _MD_T.detail = True
        _MD_A.detail = True
    return _MD_T, _MD_A


# --------------------------------------------------------------------------- helpers


def words_from_blob(blob: bytes, start: int, lo: int, hi: int) -> list[tuple[int, int]]:
    """4-byte-aligned words whose bit0-masked value lies in [lo, hi)."""
    out = []
    for i in range(0, len(blob) - 3, 4):
        w = struct.unpack_from("<I", blob, i)[0]
        if lo <= (w & 0xFFFFFFFE) < hi:
            out.append((start + i, w))
    return out


def attribute_word(va: int, methods: list, imps: list, imp_set: set,
                   callsite: bool, start: int | None) -> dict:
    """Bookkeeping: turn (address, call-site verdict, enclosing start) into a record.

    Pure function so the decision rules are testable without any process access."""
    rec = {"file_va": f"0x{va:08x}", "callsite": callsite}
    i = bisect.bisect_right(imps, va) - 1
    if i >= 0:
        imp, cls, kind, sel = methods[i]
        rec["nearest_below"] = {"imp": f"0x{imp:08x}", "class": cls, "kind": kind,
                                "selector": sel, "offset": va - imp}
    if start is not None and start in imp_set:
        imp, cls, kind, sel = methods[imps.index(start)]
        rec["verdict"] = "credited"
        rec["fn_start"] = f"0x{start:08x}"
        rec["class"] = cls
        rec["kind"] = kind
        rec["selector"] = sel
        rec["offset"] = va - start
    elif start is not None:
        rec["verdict"] = "unnamed"
        rec["fn_start"] = f"0x{start:08x}"
    else:
        rec["verdict"] = "unresolved"
        rec["fn_start"] = None
    return rec


def callsite_ok(lib: bytes, va: int) -> tuple[bool, str | None]:
    """A bl/blx must end exactly at va (ARM and Thumb decodes both tried)."""
    md_t, md_a = _mds()
    for w in range(8, 28, 4):
        s = va - w
        if s < 0:
            break
        for off in (0, 2, 4, 6):
            st = s + off
            if st >= va:
                continue
            insns = list(md_t.disasm(lib[st:va], st))
            if (insns and insns[-1].address + insns[-1].size == va
                    and insns[-1].mnemonic.split(".")[0] in ("bl", "blx")):
                return True, f"T32 {insns[-1].mnemonic} {insns[-1].op_str}"
    for k in (1, 2, 3, 4):
        st = va - 4 * k
        if st < 0:
            break
        insns = list(md_a.disasm(lib[st:va], st))
        if (insns and insns[-1].address + insns[-1].size == va
                and insns[-1].mnemonic.split(".")[0] in ("bl", "blx")):
            return True, f"A32 {insns[-1].mnemonic} {insns[-1].op_str}"
    return False, None


def fn_start_a32(lib: bytes, va: int, bound: int = DEFAULT_BOUND) -> int | None:
    """Nearest A32 push-with-lr prologue strictly before va (decode-sanity checked)."""
    _, md_a = _mds()
    a = va - 4
    floor = max(0, va - bound)
    while a >= floor:
        w = struct.unpack_from("<I", lib, a)[0]
        if (w & 0xFFFF0000) == 0xE92D0000 and (w & 0x4000):
            d = next(md_a.disasm(lib[a:a + 8], a), None)
            if d is not None and d.mnemonic.startswith("push") and "lr" in d.op_str:
                return a
        a -= 4
    return None


def fn_start_t16(lib: bytes, va: int, bound: int = DEFAULT_BOUND) -> int | None:
    """Fallback: nearest 2-byte Thumb push-with-lr before va (decode-checked)."""
    md_t, _ = _mds()
    a = va - 2
    floor = max(0, va - bound)
    while a >= floor:
        if lib[a + 1] == 0xB5:
            d = next(md_t.disasm(lib[a:a + 4], a), None)
            if d is not None and d.mnemonic.startswith("push") and "lr" in d.op_str:
                return a
        a -= 2
    return None


def run_calibration(lib: bytes, imp_set: set) -> dict:
    checks = []
    ok = True
    for va, want in CALIBRATION["positive_frames"]:
        got = fn_start_a32(lib, va)
        good = got == want and want in imp_set
        ok &= good
        checks.append({"addr": f"0x{va:08x}", "want_start": f"0x{want:08x}",
                       "got": f"0x{got:08x}" if got is not None else None, "ok": bool(good)})
    for va in CALIBRATION["negative_noncall"]:
        hit, insn = callsite_ok(lib, va)
        ok &= not hit
        checks.append({"addr": f"0x{va:08x}", "want": "no call", "got": insn, "ok": not hit})
    for va in CALIBRATION["unnamed_expected"]:
        got = fn_start_a32(lib, va)
        good = got is not None and got not in imp_set
        ok &= good
        checks.append({"addr": f"0x{va:08x}", "want": "start not an imp",
                       "got": f"0x{got:08x}" if got is not None else None, "ok": bool(good)})
    return {"status": "passed" if ok else "FAILED", "ok": bool(ok), "checks": checks}


# ----------------------------------------------------------------------------- main


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_methods(path: Path) -> list[tuple[int, str, str, str]]:
    methods = []
    with path.open() as fh:
        next(fh)
        for line in fh:
            p = line.rstrip("\n").split("\t")
            methods.append((int(p[0], 16), p[1], p[2], p[3]))
    methods.sort()
    return methods


def read_maps(pid: int) -> list[tuple[int, int, str, str, str]]:
    out = []
    with open(f"/proc/{pid}/maps") as fh:
        for line in fh:
            parts = line.split()
            a, b = parts[0].split("-")
            out.append((int(a, 16), int(b, 16), parts[1], parts[2], " ".join(parts[5:])))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--lib", type=Path, default=os.environ.get("BH_LIVE_LIB"))
    ap.add_argument("--methods", type=Path, default=os.environ.get("BH_LIVE_METHODS"))
    ap.add_argument("--out", type=Path)
    ap.add_argument("--window", type=int, default=DEFAULT_WINDOW)
    ap.add_argument("--bound", type=int, default=DEFAULT_BOUND)
    ap.add_argument("--cap", type=int, default=DEFAULT_CAP)
    args = ap.parse_args()

    if not _HAVE_CAPSTONE:
        print("error: capstone is required to run this probe", file=sys.stderr)
        return 2
    if args.lib is None or args.methods is None:
        ap.error("--lib and --methods are required (or set BH_LIVE_LIB / BH_LIVE_METHODS)")

    lib = args.lib.read_bytes()
    lib_sha = sha256(args.lib)
    methods = load_methods(args.methods)
    imps = [m[0] for m in methods]
    imp_set = set(imps)
    print(f"lib sha256 {lib_sha}")
    print(f"methods: {len(methods)}")

    # ---- build binding vs the running process -------------------------------
    maps = read_maps(args.pid)
    seg = next((m for m in maps if m[3] == "00000000" and "libApplication.so" in m[4]
                and m[2] == "r-xp"), None)
    if seg is None:
        print("error: no libApplication.so r-xp mapping in the process", file=sys.stderr)
        return 2
    base_text = seg[0]
    try:
        mapped_sha = sha256(Path(seg[4]))
    except OSError as exc:
        print(f"error: cannot hash the mapped library for the build check: {exc}",
              file=sys.stderr)
        return 2
    if mapped_sha != lib_sha:
        print(f"BUILD MISMATCH: process maps {seg[4]} ({mapped_sha}) but --lib is {lib_sha}",
              file=sys.stderr)
        return 2
    print(f"build check OK; base_text {hex(base_text)}")

    # ---- live .text range from the same ELF ---------------------------------
    if not _HAVE_ELFTOOLS:
        print("error: pyelftools is required to derive the .text range", file=sys.stderr)
        return 2
    elf = ELFFile(args.lib.open("rb"))
    xseg = next(p for p in elf.iter_segments()
                if p["p_type"] == "PT_LOAD" and (p["p_flags"] & 1))
    text = elf.get_section_by_name(".text")
    lo = base_text + (text["sh_addr"] - xseg["p_vaddr"])
    hi = lo + text["sh_size"]
    print(f"live text range {hex(lo)}..{hex(hi)}")

    # ---- calibration on the audited build -----------------------------------
    if lib_sha == AUDITED_BUILD_SHA256:
        calib = run_calibration(lib, imp_set)
        print("calibration:", calib["status"])
        for c in calib["checks"]:
            print("  ", c)
        if not calib["ok"]:
            print("calibration FAILED; refusing to report capture results",
                  file=sys.stderr)
            return 3
    else:
        calib = {"status": f"skipped (build {lib_sha[:12]} is not the audited one)", "ok": None,
                 "checks": []}
        print("calibration:", calib["status"])

    # ---- capture -------------------------------------------------------------
    mem = os.open(f"/proc/{args.pid}/mem", os.O_RDONLY)

    def rds(a: int, n: int) -> bytes:
        try:
            return os.pread(mem, n, a)
        except OSError:
            return b""

    def comm_of(tid: str) -> str:
        try:
            return Path(f"/proc/{args.pid}/task/{tid}/comm").read_text().strip()
        except OSError:
            return "?"

    raw: dict[str, list] = {}
    for s0, s1, perms, _file_off, name in maps:
        if "stack_and_tls" not in name or perms != "rw-p":
            continue
        tid = name.rsplit(":", 1)[-1].rstrip("]")
        start = max(s0, s1 - args.window)
        blob = rds(start, s1 - start)
        if not blob:
            continue
        raw[tid] = words_from_blob(blob, start, lo, hi)

    uik = [t for t in raw if comm_of(t) == "UIKitMain" and raw[t]]
    if not uik:
        print("error: no UIKitMain thread with text-range words found", file=sys.stderr)
        return 2
    best = max(uik, key=lambda t: len(raw[t]))
    print(f"primary tid {best} ({comm_of(best)}), {len(raw[best])} candidate words")

    frames = []
    words = []
    seen: set[int] = set()
    counts = {"credited": 0, "unnamed": 0, "unresolved": 0, "not_call": 0}
    for stack_addr, w in sorted(raw[best], key=lambda t: -t[0]):
        live = w & 0xFFFFFFFE
        va = live - base_text
        if va in seen:
            continue
        seen.add(va)
        ok, insn = callsite_ok(lib, va)
        start = fn_start_a32(lib, va, args.bound)
        mode = "A32"
        if start is None:
            start = fn_start_t16(lib, va, args.bound)
            mode = "T16"
        rec = attribute_word(va, methods, imps, imp_set, ok, start)
        rec.update({"stack_addr": hex(stack_addr), "raw_word": f"0x{w:08x}",
                    "live_addr": f"0x{live:08x}",
                    "fn_start_mode": mode if start is not None else None,
                    "callsite_insn": insn})
        counts[rec["verdict"]] += 1
        if not ok:
            counts["not_call"] += 1
        words.append(rec)
        if ok and rec["verdict"] in ("credited", "unnamed"):
            frames.append(rec)
        if len(words) >= args.cap:
            break

    print("counts:", counts)
    for f in frames:
        tag = (f"{f['class']} {f['selector']}" if f["verdict"] == "credited"
               else f"UNNAMED@{f['fn_start']}")
        off = f"+0x{f['offset']:x}" if "offset" in f and f["verdict"] == "credited" else ""
        print(f"  [{('C' if f['callsite'] else '-')}] {f['verdict']:9s} {tag} {off}")

    out = {
        "tool": "probe_live_frame_stack.py",
        "pid": args.pid,
        "captured": datetime.now().astimezone().isoformat(timespec="seconds"),
        "build_libApplication_sha256": lib_sha,
        "base_text": hex(base_text),
        "method_table": {"path": str(args.methods), "sha256": sha256(args.methods),
                         "method_count": len(methods)},
        "calibration": calib,
        "primary_tid": best,
        "tid_comm": {t: comm_of(t) for t in raw if raw[t]},
        "tid_counts": {t: len(raw[t]) for t in raw if raw[t]},
        "counts": counts,
        "frames": frames,
        "words": words,
    }
    text_out = json.dumps(out, indent=1) + "\n"
    if args.out:
        args.out.write_text(text_out)
        print(f"wrote {args.out} ({len(frames)} frames, {len(words)} words)")
    else:
        print(text_out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
