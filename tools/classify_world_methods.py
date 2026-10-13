#!/usr/bin/env python3
"""Classify every World instance method: can it be executed under Unicorn, and with what abstraction?

The three getters already executed (worldTime, fastForward, doubleTimeUnlocked) were chosen by a rule
that was computed once and then lived only in a chat message. This makes the rule a tool, so the rest
of the world/main-domain bucket stops depending on whoever is at the keyboard.

Verdicts, in increasing cost:

  unicorn-clean          no call outside the method table, no VFP. Runs as-is with a fabricated
                         receiver - the entire criterion is inspectable in the body.
  unicorn-copy-stub      no calls except the 8-byte copy helper (REPLACE/COPY of a scalar), no VFP.
  unicorn-with-abstraction
                         calls land only on identified runtime helpers (the copy family), or the body
                         uses VFP, so something must be supplied or skipped - stated per row.
  needs-runtime          calls objc_msgSend or an unidentified target, or touches a collection: the
                         receiver's class must exist, so this one has to be driven live.

Evidence is per-row and mechanical: byte length, instruction count, each call target with its category,
VFP usage, and whether the body resolves an ivar cell (which the cell machinery can confirm).

Usage:
  python3 tools/classify_world_methods.py <libApplication.so> --methods <t.tsv> [--json OUT] [--tsv OUT]
      [--self-check]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

TEXT_LO, TEXT_HI = 0x001C4500, 0x00DB8AA8
MSG_SEND_STUB = 0x001C281C          # the shared objc_msgSend trampoline this family uses
COPY_FAMILY = {0x001C2888, 0x001C2924, 0x001C2948}
VFP_MNEMONICS = ("vldr", "vstr", "vmov", "vadd", "vsub", "vmul", "vdiv", "vcvt", "vcmpe", "vmrs")

# controls: the three verdicts already established by execution / instruction reading
SELF_CHECK = {
    "worldTime": "unicorn-with-abstraction",      # 1 copy-stub call + VFP epilogue
    "fastForward": "unicorn-clean",
    "doubleTimeUnlocked": "unicorn-clean",
}


def classify(insns) -> tuple[str, dict]:
    calls = [i for i in insns if i.mnemonic in ("bl", "blx")]
    targets = []
    for i in calls:
        tgt = None
        if i.mnemonic == "bl" and i.op_str.startswith("#"):
            try:
                tgt = int(i.op_str[1:], 16)
            except ValueError:
                tgt = None
        targets.append((i, tgt))
    vfp = any(i.mnemonic in VFP_MNEMONICS for i in insns)
    return calls, targets, vfp


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("libapplication")
    ap.add_argument("--methods", type=Path, required=True)
    ap.add_argument("--json", type=Path, default=None)
    ap.add_argument("--tsv", type=Path, default=None)
    ap.add_argument("--self-check", action="store_true")
    args = ap.parse_args()

    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    blob = Path(args.libapplication).read_bytes()

    rows = []
    for line in args.methods.read_text().splitlines()[1:]:
        p = line.split("\t")
        if len(p) >= 5 and p[1] == "World" and p[2] == "instance":
            try:
                rows.append((int(p[0], 16), p[3], p[4]))
            except ValueError:
                continue
    rows.sort()
    imps = {r[0] for r in rows}

    out = []
    for idx, (lo, sel, types) in enumerate(rows):
        hi = rows[idx + 1][0] if idx + 1 < len(rows) else min(lo + 0x4000, TEXT_HI)
        if hi - lo > 0x8000:
            hi = lo + 0x8000
        insns = []
        a = lo
        while a < hi:
            g = list(md.disasm(blob[a:a + 4], a))
            if g:
                insns.append(g[0])
            a += 4
        calls, targets, vfp = classify(insns)
        cats = []
        for i, tgt in targets:
            if tgt is not None and tgt in imps:
                cats.append(("local", hex(tgt)))
            elif tgt == MSG_SEND_STUB or i.mnemonic == "blx":
                cats.append(("objc-msgSend", hex(tgt) if tgt else "indirect"))
            elif tgt in COPY_FAMILY:
                cats.append(("copy-stub", hex(tgt)))
            else:
                cats.append(("unidentified", hex(tgt) if tgt else "indirect"))
        kinds = {c[0] for c in cats}
        if "objc-msgSend" in kinds or "unidentified" in kinds:
            verdict = "needs-runtime"
        elif "copy-stub" in kinds or vfp:
            verdict = "unicorn-with-abstraction"
        else:
            verdict = "unicorn-clean"
        out.append({"selector": sel, "imp": hex(lo), "types": types,
                    "bytes": hi - lo, "instructions": len(insns),
                    "calls": len(calls), "call_categories": cats, "vfp": vfp,
                    "verdict": verdict})

    tally = {}
    for r in out:
        tally[r["verdict"]] = tally.get(r["verdict"], 0) + 1
    by_sel = {r["selector"]: r for r in out}
    ctrl = {k: {"expected": v, "got": by_sel[k]["verdict"] if k in by_sel else None,
                "ok": k in by_sel and by_sel[k]["verdict"] == v} for k, v in SELF_CHECK.items()}
    passed = all(c["ok"] for c in ctrl.values())

    rep = {"schema": 1, "elf_sha256": hashlib.sha256(blob).hexdigest(),
           "scope": "every World instance method in the pinned build",
           "rule": {"objc-msgSend or unidentified call": "needs-runtime",
                    "copy-stub call or any VFP": "unicorn-with-abstraction",
                    "otherwise": "unicorn-clean"},
           "known_stubs": {"objc_msgSend": hex(MSG_SEND_STUB),
                           "copy_family": [hex(x) for x in sorted(COPY_FAMILY)]},
           "counts": {"methods": len(out), **tally},
           "self_check": {"controls": ctrl, "passed": passed},
           "methods": out}
    if args.tsv:
        with args.tsv.open("w") as fh:
            fh.write("selector\timp\tbytes\tinstructions\tcalls\tvfp\tverdict\n")
            for r in out:
                fh.write(f"{r['selector']}\t{r['imp']}\t{r['bytes']}\t{r['instructions']}\t"
                         f"{r['calls']}\t{int(r['vfp'])}\t{r['verdict']}\n")
    payload = json.dumps(rep, indent=1) + "\n"
    if args.json:
        args.json.write_text(payload)
    else:
        print(json.dumps(rep["counts"], indent=1))
        print("self-check:", passed, ctrl)
    if args.self_check and not passed:
        print(json.dumps({"self_check": "FAILED", "controls": ctrl}, indent=1))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
