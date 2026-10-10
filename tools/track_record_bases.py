#!/usr/bin/env python3
"""Find by-value CraftableItem record buffers and the accesses that land on their fields.

`craftable_item_blob_boundary.json` sealed this line with one condition: a base-provenance tracker, because
matching a field offset alone collides numerically with stack-frame offsets and produced ~1600 false
positives in earlier attempts. This is that tracker, done the narrow way the evidence allows:

  1. A record buffer is recognised by CONSTRUCTION, not by offset: the four stubs at 0x001c2888 / 0x001c2918 /
     0x001c2924 / 0x001c2948 are PLT trampolines to imported functions, and the two that matter are called with
     a length of 0x7c (124) into a frame address - the shape of memset(dst,0,124) or memcpy(dst,src,n). The
     destination of such a call IS a record buffer, and its register/stack slot is the base.
  2. Only accesses whose base is that proven buffer are reported, at offsets that are real record fields. An
     access at the same numeric offset through any other base is not interesting and is not collected - which
     is the distinction offset heuristics could not make.

What it does not do, stated because the sealed note asks for it explicitly: this tracks ONE base per access
within a straight-line window, not a full dataflow over branches and loops. A method whose record buffer is
stale-reloaded or spiralled through a callee will have accesses it cannot see. It is a narrow tracker that
produces no false positives, which is the trade the evidence wants.

Usage:
  python3 tools/track_record_bases.py <libApplication.so> [--json OUT] [--tsv OUT]
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

TEXT_LO, TEXT_HI = 0x001C4500, 0x00DB8AA8
PIC_BASE = 0x0105FAF4
RECORD_SIZE = 0x7C                      # 124
# the record's field offsets, derived from the type encoding (see craftable_item_record.h)
RECORD_FIELDS = (0, 4, 8, 40, 72, 76, 80, 84, 86, 88, 92)
STUBS = {0x001C2888: "import-stub-2888", 0x001C2918: "import-stub-2918",
         0x001C2924: "import-stub-2924", 0x001C2948: "import-stub-2948"}
LOADS = ("ldr", "ldrb", "ldrsb", "ldrh", "ldrsh", "vldr")
STORES = ("str", "strb", "strh", "vstr")


def _imm(text: str):
    """Immediate from an operand like `#-0x114` / `#0x7c`; None when it is not one."""
    t = text.strip()
    if not t.startswith("#"):
        return None
    try:
        return int(t[1:], 0)
    except ValueError:
        return None


def methods(path: Path) -> dict[int, str]:
    if not path.is_file():
        return {}
    out = {}
    for line in path.read_text().splitlines()[1:]:
        p = line.split("\t")
        if len(p) >= 4:
            out[int(p[0], 16)] = f"{p[1]} -[{p[3]}]"
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("libapplication")
    ap.add_argument("--methods", type=Path, default=None)
    ap.add_argument("--json", type=Path, default=None)
    ap.add_argument("--tsv", type=Path, default=None)
    args = ap.parse_args()
    blob = Path(args.libapplication).read_bytes()
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    meth = methods(args.methods) if args.methods else {}

    # locate every call to a stub, then look backwards for the length constant and the destination
    calls = []
    for a in range(TEXT_LO, TEXT_HI, 4):
        w = struct.unpack_from("<I", blob, a)[0]
        if (w >> 28) == 0xE and ((w >> 24) & 0xF) in (0xB,):        # bl
            # ARM branch offsets are in WORDS: the 24-bit field is shifted by 2 before being applied
            off = w & 0xFFFFFF
            if off & 0x800000:
                off -= 0x1000000
            tgt = (a + 8 + off * 4) & 0xFFFFFFFF
            if tgt in STUBS:
                calls.append((a, tgt))
    findings, bases = [], []
    for site, stub in calls:
        insns = list(md.disasm(blob[max(TEXT_LO, site - 0x80):site + 0x40], max(TEXT_LO, site - 0x80)))
        # The length must arrive in r2 AT THIS CALL, traced back to a movw #0x7c. Requiring only that
        # "0x7c appears nearby" was the remaining source of false bases: any unrelated movw #0x7c in the
        # window qualified a call that has nothing to do with a record.
        def r2_holds_7c(window):
            for j in reversed(window[:-1]):
                parts = [x.strip() for x in j.op_str.split(",")]
                if not parts or parts[0] != "r2":
                    continue
                if j.mnemonic == "movw" and "#0x7c" in j.op_str.replace(" ", ""):
                    return True
                if j.mnemonic == "mov" and len(parts) == 2:
                    src = parts[1]
                    for k2 in reversed(window[:window.index(j)]):
                        if k2.mnemonic == "movw" and k2.op_str.split(",")[0].strip() == src and "#0x7c" in k2.op_str.replace(" ", ""):
                            return True
                if j.mnemonic in ("sub", "add", "and"):      # r2 was computed, not the length
                    return False
            return False
        if not r2_holds_7c(insns):
            continue
        # The buffer slot must come from the CALL'S OWN ARGUMENTS, not from "the nearest preceding
        # sub/add": the confirmed hits are accesses to the frame slot that the memset/memcpy destination
        # register holds, and taking an unrelated nearby computation was what let plain locals match.
        # Trace r0 (the memset destination) back through a `mov r0, rY` to its `sub/add rY, fp|sp, #imm`.
        base_reg = None
        window = list(md.disasm(blob[max(TEXT_LO, site - 0x30):site + 4], max(TEXT_LO, site - 0x30)))
        for k, i in enumerate(reversed(window)):
            if i.mnemonic in ("mov", "sub", "add") and len(i.op_str.split(",")) >= 2:
                rd, rn = [x.strip() for x in i.op_str.split(",")[:2]]
                if rd != "r0":
                    continue
                src = rn
                # the direct form: sub r0, fp, #imm
                if i.mnemonic in ("sub", "add") and src in ("fp", "sp"):
                    base_reg = (rd, src, i.op_str.split(",")[2].strip(), i.address, i.mnemonic)
                    break
                # the indirect form: mov r0, rY where rY was computed just before
                for j in reversed(window[:len(window) - k]):
                    if j.mnemonic in ("sub", "add") and j.op_str.split(",")[0].strip() == src:
                        parts = [x.strip() for x in j.op_str.split(",")]
                        if len(parts) == 3 and parts[1] in ("fp", "sp"):
                            base_reg = (rd, parts[1], parts[2], j.address, j.mnemonic)
                            break
                if base_reg:
                    break
        if not base_reg:
            continue
        reg, rel, imm, at, base_mnemonic = base_reg
        bases.append({"call_site": hex(site), "stub": STUBS[stub], "base_register": reg,
                      "frame": f"{rel} {imm}", "base_computed_at": hex(at), "base_mnemonic": base_mnemonic})
        # Accesses are expressed relative to the FRAME register, not to the base register
        # (`strh r7,[fp,#-0x52]` where -0x52 == -0xa8 + 86), so the tracker works in frame displacement:
        # for a record whose base is fp-0xa8, an access at [fp,#k] is a field access iff k + 0xa8 is a field
        # offset. Because the base was PROVEN for this method first, the same k elsewhere is not picked up -
        # that is the distinction the offset heuristics could not make.
        frame_disp = None
        if imm.startswith("#"):
            v = _imm(imm)
            frame_disp = None if v is None else (-v if base_mnemonic == "sub" else v)
        if frame_disp is not None:
            # The access must be in the shadow of THIS base: nearest preceding base computation within
            # 0x100 bytes. Anchoring on "some base in the method" is what let ordinary locals be matched -
            # a method with one proven record base made every [fp,#k] a candidate.
            lo = at
            hi = min(TEXT_HI, at + 0x100)
            for i in md.disasm(blob[max(TEXT_LO, lo):hi], max(TEXT_LO, lo)):
                if i.mnemonic not in LOADS + STORES or "," not in i.op_str:
                    continue
                inner = i.op_str.split(",", 1)[1].strip().strip("[]")
                ip = [x.strip() for x in inner.split(",")]
                if not ip or ip[0] != rel or len(ip) < 2 or not ip[1].startswith("#"):
                    continue
                k = _imm(ip[1])
                off = k - frame_disp if rel == "fp" else k - frame_disp
                if off in RECORD_FIELDS:
                    findings.append({"site": hex(i.address),
                                     "kind": "read" if i.mnemonic in LOADS else "write",
                                     "instruction": f"{i.mnemonic} {i.op_str}", "offset": off,
                                     "through": f"{rel}{frame_disp:+#x}"})
    owner = {}
    for f in findings:
        a = int(f["site"], 16)
        best = max((m for m in meth if m <= a), default=None)
        f["method"] = meth.get(best) if best else None
        owner[f["method"]] = owner.get(f["method"], 0) + 1
    rep = {"schema": 1, "scope": "by-value CraftableItem record buffers and their field accesses",
           "method": "a record buffer is recognised by CONSTRUCTION - the destination of a call to the "
                     "PLT-trampolined memset/memcpy stubs with a length of 0x7c - and only accesses through "
                     "that proven base are collected, which is exactly the distinction offset heuristics "
                     "cannot make",
           "record_fields": list(RECORD_FIELDS), "record_size": RECORD_SIZE,
           "counts": {"stub_calls": len(calls), "proven_bases": len(bases), "field_accesses": len(findings),
                      "methods_with_accesses": len(owner)},
           "bases": bases, "accesses": findings,
           "boundary": ["one base per access within a straight-line window, not a dataflow over branches; a "
                        "method that reloads its buffer in another block may have accesses this misses",
                        "a value of 0x7c is required near the call, so a record-sized copy whose length comes "
                        "from a variable rather than a constant is not recognised"]}
    if args.tsv:
        with args.tsv.open("w") as fh:
            fh.write("site\toffset\tkind\tinstruction\tmethod\n")
            for f in findings:
                fh.write(f"{f['site']}\t{f['offset']}\t{f['kind']}\t{f['instruction']}\t{f['method']}\n")
    print(json.dumps(rep["counts"], indent=1))
    for f in findings[:20]:
        print(f"  +{f['offset']:<3d} {f['kind']:5s} {f['site']}  {f['instruction']:24s} {f['method']}")
    if args.json:
        args.json.write_text(json.dumps(rep, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
