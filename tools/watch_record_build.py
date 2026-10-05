#!/usr/bin/env python3
"""Watch a CraftableItem record being built, instead of inferring its fields from rules.

The static tracker produced 1-in-3 precision because recognising a record buffer from instruction shapes is a
heuristic. This does it the other way round: run the method under the emulator, let the memset/memcpy STUB tell
us at run time which frame slot it is writing 124 bytes into, and then report every store that lands inside
[base, base+124). A store inside that range is a record field write BY CONSTRUCTION - the store address is
observed, not matched against an offset.

The stubs (0x001c2888/0x001c2918/0x001c2924/0x001c2948) are PLT trampolines to imported functions; serving them
means: for the length-124 calls, perform the copy/zero into the emulated memory so the record has real contents
and record the destination as the buffer base.

Limits, stated up front: the receiver is fabricated (all-zero pages), so the method takes whichever branch a
zeroed object implies; selectors it sends are stubbed with r0 = 0; VFP instructions are skipped because
Unicorn's default ARM model rejects them. What this yields is therefore "the writes this run performed into the
record it built", not "every write the original performs".

Usage:
  python3 tools/watch_record_build.py <libApplication.so> --target PaintMixUI:craftButton: [--json OUT]
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from emulate_worldtime_getter import BIAS, OBJ, STACK_TOP, SENTINEL, load_image   # noqa: E402

RECORD = 124
STUBS = {0x001C2888: "stub-2888", 0x001C2918: "stub-2918(memcpy)", 0x001C2924: "stub-2924(memset)",
         0x001C2948: "stub-2948"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("libapplication")
    ap.add_argument("--methods", type=Path, required=True)
    ap.add_argument("--target", required=True, help="Class:selector")
    ap.add_argument("--json", type=Path, default=None)
    ap.add_argument("--max-insns", type=int, default=200_000)
    args = ap.parse_args()
    cls, selector = args.target.split(":", 1)
    elf = Path(args.libapplication)
    imp = None
    for line in args.methods.read_text().splitlines()[1:]:
        p = line.split("\t")
        if len(p) >= 5 and p[1] == cls and p[3] == selector:
            imp = int(p[0], 16)
            break
    if imp is None:
        raise SystemExit(f"{args.target} not in the method table")

    from unicorn import (Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_READ_UNMAPPED,
                         UC_HOOK_MEM_WRITE, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC)
    from unicorn.arm_const import (UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1,
                                   UC_ARM_REG_R2, UC_ARM_REG_SP)
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    blob = elf.read_bytes()

    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    load_image(mu, elf)
    mu.mem_map(OBJ & ~0xFFF, 0x4000, UC_PROT_READ | UC_PROT_WRITE)
    mu.mem_map(BIAS + STACK_TOP - 0x10000, 0x10000, UC_PROT_READ | UC_PROT_WRITE)
    mu.mem_map(SENTINEL & ~0xFFF, 0x1000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
    mu.mem_write(SENTINEL, struct.pack("<I", 0xE1A0F00E))
    mu.mem_write(OBJ, b"\0" * 0x2000)
    st = {"base": None, "stores": [], "stubs": [], "insns": 0, "stopped": None, "vivified": []}

    vfp_at = set()
    for ins in md.disasm(blob[imp:imp + 0x1000], imp):
        if ins.mnemonic.startswith("v"):
            vfp_at.add(BIAS + ins.address)

    def on_write(mu_, access, address, size, value, _):
        lr = mu_.reg_read(UC_ARM_REG_LR)
        st["stores"].append({"address": address, "size": size, "value": value,
                             "site": hex(lr - BIAS - 4),
                             "rel_to_base": (address - st["base"]) if st["base"] is not None else None})
        return True

    def on_unmapped(mu_, access, address, size, value, _):
        try:
            mu_.mem_map(address & ~0xFFF, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
        except Exception:
            return False
        st["vivified"].append(hex(address & ~0xFFF))
        return True

    def hook_code(mu_, addr, size, _):
        st["insns"] += 1
        if st["insns"] > args.max_insns:
            st["stopped"] = "instruction budget"
            mu_.emu_stop()
            return
        if addr in vfp_at:
            mu_.reg_write(UC_ARM_REG_PC, addr + 4)
            return
        if addr in {BIAS + a for a in STUBS}:
            stub = addr - BIAS
            r0, r1, r2 = (mu_.reg_read(UC_ARM_REG_R0), mu_.reg_read(UC_ARM_REG_R1),
                          mu_.reg_read(UC_ARM_REG_R2))
            st["stubs"].append({"stub": STUBS[stub], "site": hex(addr - BIAS), "r0": hex(r0),
                                "r1": hex(r1), "r2": hex(r2)})
            if r2 == RECORD and stub in (0x001C2918, 0x001C2924):
                if st["base"] is None:
                    st["base"] = r0 if stub == 0x001C2924 else r1
                if stub == 0x001C2924:
                    mu_.mem_write(r0, b"\0" * RECORD)
                else:
                    try:
                        mu_.mem_write(r0, bytes(mu_.mem_read(r1, RECORD)))
                    except Exception:
                        mu_.mem_write(r0, b"\0" * RECORD)
            else:
                mu_.reg_write(UC_ARM_REG_R0, 0)
            mu_.reg_write(UC_ARM_REG_PC, mu_.reg_read(UC_ARM_REG_LR))
            return
        if addr == SENTINEL:
            mu_.emu_stop()

    mu.hook_add(UC_HOOK_CODE, hook_code)
    mu.hook_add(UC_HOOK_MEM_WRITE, on_write)
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, on_unmapped)
    mu.reg_write(UC_ARM_REG_R0, OBJ)
    mu.reg_write(UC_ARM_REG_SP, BIAS + STACK_TOP)
    mu.reg_write(UC_ARM_REG_LR, SENTINEL)
    pc = BIAS + imp
    for _ in range(200):
        try:
            mu.emu_start(pc, BIAS + SENTINEL, timeout=20_000_000)
            break
        except Exception as exc:
            msg = f"{type(exc).__name__}: {exc}"
            cur, lr = mu.reg_read(UC_ARM_REG_PC), mu.reg_read(UC_ARM_REG_LR)
            if "fetch" in msg.lower():
                mu.reg_write(UC_ARM_REG_PC, lr)
                mu.reg_write(UC_ARM_REG_R0, 0)
                pc = lr
                continue
            if "invalid instruction" in msg.lower():
                mu.reg_write(UC_ARM_REG_PC, cur + 4)
                pc = cur + 4
                continue
            st["stopped"] = msg
            break

    field_stores = [s for s in st["stores"] if s["rel_to_base"] is not None
                    and 0 <= s["rel_to_base"] < RECORD]
    by_offset = {}
    for s in field_stores:
        by_offset.setdefault(s["rel_to_base"], []).append(s)
    rep = {"schema": 1, "target": args.target, "imp": hex(imp),
           "method": "the record buffer is identified AT RUN TIME by the length-124 memset/memcpy stub call "
                     "(its destination is the base), and every store inside [base, base+124) is a record field "
                     "write by construction - observed addresses, not matched offsets",
           "counts": {"instructions": st["insns"], "stub_calls": len(st["stubs"]),
                      "stores_total": len(st["stores"]), "field_stores": len(field_stores),
                      "distinct_field_offsets": len(by_offset), "zero_pages_invented": len(st["vivified"])},
           "record_base": hex(st["base"]) if st["base"] is not None else None,
           "field_stores": [{"offset": k, "size": v[0]["size"], "site": v[0]["site"],
                             "value": v[0]["value"], "occurrences": len(v)} for k, v in sorted(by_offset.items())],
           "stubs": st["stubs"][:12], "stopped": st["stopped"],
           "boundary": "a fabricated zeroed receiver decides which branch this run takes, sends are stubbed with "
                       "r0 = 0, VFP is skipped: these are the writes THIS RUN performed into the record it "
                       "built, not every write the original performs"}
    if args.json:
        args.json.write_text(json.dumps(rep, indent=1) + "\n")
    print(json.dumps(rep["counts"], indent=1))
    print("record base:", rep["record_base"])
    for f in rep["field_stores"]:
        print(f"  +{f['offset']:<3d} size={f['size']} value={f['value']} site={f['site']} x{f['occurrences']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
