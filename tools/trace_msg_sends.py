#!/usr/bin/env python3
"""Trace the selector sends of a needs-runtime method, with a fabricated receiver.

The clean set turned out to be straight-line accessors, so the decision logic - 168 of 259 methods
carry conditional branches - is only reachable with a runtime. A full runtime is out of reach, but the
SENDS are not: intercept the shared objc_msgSend trampoline, record (call site, selector, receiver,
arguments), and return 0 so the method keeps going.

Evidence grade, stated up front because it is easy to overclaim: **executed, with a fabricated
receiver**. Two consequences:

  * a recorded send is a fact about this body - the instruction really does reach that trampoline with
    that selector - but nothing about the callee, and nothing about the return value, is observed;
  * once the body branches on a stubbed return value, the trace of what follows is fiction. The output
    therefore records the stub frontier: the sequence is trustworthy up to the first branch on a
    stubbed result, and every send after that is marked.

The selector itself is resolved from the runtime, not guessed: at the trampoline r1 holds the SEL, and
the name is read out of the selector structure (pointer-to-name first, name-at-r1 as the fallback -
both are tried and the tool records which one produced a printable string).

Usage:
  python3 tools/trace_msg_sends.py <libApplication.so> --methods <t.tsv> \
      --target DynamicWorld:'update:accurateDT:isSimulation:' [--json OUT] [--limit 200]
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from emulate_worldtime_getter import BIAS, OBJ, STACK_TOP, SENTINEL, load_image   # noqa: E402
from classify_world_methods import MSG_SEND_STUB                                  # noqa: E402


def cstring(mu, addr: int, limit: int = 96) -> str | None:
    try:
        raw = bytes(mu.mem_read(addr, limit))
    except Exception:
        return None
    out = []
    for b in raw:
        if b == 0:
            break
        if 32 <= b < 127:
            out.append(chr(b))
        else:
            return None
    s = "".join(out)
    return s if len(s) >= 2 else None


def resolve_selector(mu, sel_ptr: int, bias: int = 0) -> tuple[str | None, str]:
    """SEL -> name.

    The value handed to objc_msgSend is a **file VA**, not a mapped address: at the first send of
    `-[DynamicWorld update:accurateDT:isSimulation:]` r1 is 0xef9dc7, and the bytes at that offset in
    the file spell that very selector. So the name has to be read at `bias + sel_ptr` (or through one
    indirection from there), never at sel_ptr itself - reading it unbiased is what made every selector
    in the trace come back unresolved.
    """
    for base, label in ((sel_ptr + bias, "file-va"), (sel_ptr, "as-is")):
        try:
            inner = struct.unpack("<I", bytes(mu.mem_read(base, 4)))[0]
        except Exception:
            inner = 0
        if inner:
            s = cstring(mu, inner + bias) or cstring(mu, inner)
            if s:
                return s, f"pointer-to-name/{label}"
        s = cstring(mu, base)
        if s:
            return s, f"name-at-sel/{label}"
    return None, "unresolved"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("libapplication")
    ap.add_argument("--methods", type=Path, required=True)
    ap.add_argument("--target", required=True, help="Class:selector")
    ap.add_argument("--json", type=Path, default=None)
    ap.add_argument("--limit", type=int, default=200)
    ap.add_argument("--max-insns", type=int, default=400_000)
    ap.add_argument("--keep-vfp", action="store_true",
                    help="don't skip VFP instructions (Unicorn's default ARM model rejects them)")
    args = ap.parse_args()

    cls, selector = args.target.split(":", 1)
    elf = Path(args.libapplication)
    blob = elf.read_bytes()
    imp = None
    for line in args.methods.read_text().splitlines()[1:]:
        p = line.split("\t")
        if len(p) >= 5 and p[1] == cls and p[2] == "instance" and p[3] == selector:
            imp = int(p[0], 16)
            types = p[4]
            break
    if imp is None:
        raise SystemExit(f"no {cls} instance method {selector!r} in the method table")

    from unicorn import (Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC,
                         UC_HOOK_CODE, UC_HOOK_MEM_READ_UNMAPPED)
    from elftools.elf.elffile import ELFFile as _ELF
    allowed = []
    with elf.open("rb") as fh:
        for seg in _ELF(fh).iter_segments():
            if seg["p_type"] == "PT_LOAD" and seg["p_memsz"]:
                allowed.append((BIAS + seg["p_vaddr"], BIAS + seg["p_vaddr"] + seg["p_memsz"]))
    from unicorn.arm_const import (UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1,
                                   UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP)
    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    load_image(mu, elf)
    mu.mem_map(OBJ & ~0xFFF, 0x4000, UC_PROT_READ | UC_PROT_WRITE)
    mu.mem_map(BIAS + STACK_TOP - 0x8000, 0x8000, UC_PROT_READ | UC_PROT_WRITE)
    mu.mem_map(SENTINEL & ~0xFFF, 0x1000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
    mu.mem_write(SENTINEL, struct.pack("<I", 0xE1A0F00E))
    mu.mem_write(OBJ, b"\0" * 0x1000)

    st = {"sends": [], "insns": 0, "stopped_by": None, "vfp_skipped": 0, "call_outs": []}
    call_sites = set()

    # Unicorn's default ARM model rejects every VFP instruction with UC_ERR_INSN_INVALID, and this
    # method opens with the x20 division, so without this the trace dies after 9 instructions. VFP is
    # therefore executed as a no-op - an abstraction with a cost that is recorded, not hidden: any float
    # value is unobserved, so a body that branches on one is no longer shape-faithful past that point.
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    _is_vfp_cache: dict[int, bool] = {}

    def is_vfp(addr: int) -> bool:
        """Decide per address, lazily. A precomputed span only covers the target method, and once a
        call-out returns into another function the VFP instructions there are missed - which is how the
        first working run died at 336 instructions with an invalid instruction, not a trace."""
        va = addr - BIAS
        if va in _is_vfp_cache:
            return _is_vfp_cache[va]
        got = False
        if 0 <= va < len(blob):
            for ins in md.disasm(blob[va:va + 4], va):
                got = ins.mnemonic.startswith("v")
                break
        _is_vfp_cache[va] = got
        return got

    def hook(mu_, addr, size, _):
        st["insns"] += 1
        if st["insns"] > args.max_insns:
            st["stopped_by"] = f"instruction budget {args.max_insns} reached"
            mu_.emu_stop()
            return
        if not args.keep_vfp and is_vfp(addr):
            st["vfp_skipped"] += 1
            mu_.reg_write(UC_ARM_REG_PC, addr + 4)
            return
        if addr == BIAS + MSG_SEND_STUB:
            sel_ptr, recv = mu_.reg_read(UC_ARM_REG_R1), mu_.reg_read(UC_ARM_REG_R0)
            name, how = resolve_selector(mu_, sel_ptr, BIAS)
            lr = mu_.reg_read(UC_ARM_REG_LR)
            st["sends"].append({"site": hex(lr - BIAS - 4), "selector": name, "resolved_by": how,
                                "receiver": hex(recv),
                                "arg2": hex(mu_.reg_read(UC_ARM_REG_R2)),
                                "arg3": hex(mu_.reg_read(UC_ARM_REG_R3)),
                                "stubbed": True})
            call_sites.add(lr - BIAS - 4)
            mu_.reg_write(UC_ARM_REG_PC, lr)          # skip the callee
            mu_.reg_write(UC_ARM_REG_R0, 0)           # and lie about the result
            if len(st["sends"]) >= args.limit:
                mu_.emu_stop()
            return
        if addr == SENTINEL:
            mu_.emu_stop()
            return
        # Anything outside the loaded image is a callee this run does not have: record where it was
        # called from and stub it exactly like a send, rather than letting the fetch fault and end the
        # trace. (A zeroed pointer field makes this the common case on a fabricated receiver.)
        if not any(lo <= addr < hi for lo, hi in allowed):
            lr = mu_.reg_read(UC_ARM_REG_LR)
            st["call_outs"].append({"target": hex(addr), "from": hex(lr - BIAS - 4)})
            mu_.reg_write(UC_ARM_REG_PC, lr)
            mu_.reg_write(UC_ARM_REG_R0, 0)

    # A fabricated receiver has zeroed pointer fields, so the body dereferences NULL almost immediately.
    # Rather than die, map a zero page and keep going - but count every such region, because "an object
    # graph that is entirely zeroes" is the strongest boundary in this trace: it means the body walked
    # into a pointer this run invented.
    st["vivified"] = []

    def on_unmapped(mu_, access, address, size, value, _):
        page = address & ~0xFFF
        if len(st["vivified"]) > 64:
            mu_.emu_stop()
            return False
        try:
            mu_.mem_map(page, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
        except Exception:
            return False
        st["vivified"].append(hex(page))
        return True

    h = mu.hook_add(UC_HOOK_CODE, hook)
    hm = mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, on_unmapped)
    mu.reg_write(UC_ARM_REG_R0, OBJ)
    mu.reg_write(UC_ARM_REG_SP, BIAS + STACK_TOP)
    mu.reg_write(UC_ARM_REG_LR, SENTINEL)
    # An unmapped FETCH raises before the code hook can see it (Unicorn translates first), so the
    # recovery has to live at the exception level: treat it as a call-out, return to the caller with
    # r0 = 0, and resume. Without this the trace ends at the first zeroed function pointer.
    pc = BIAS + imp
    for _ in range(200):
        try:
            mu.emu_start(pc, BIAS + SENTINEL, timeout=20_000_000)
            break
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"
            pc_now, lr = mu.reg_read(UC_ARM_REG_PC), mu.reg_read(UC_ARM_REG_LR)
            if "fetch" in message.lower():
                st["call_outs"].append({"target": hex(pc_now), "from": hex(lr - BIAS - 4),
                                        "via": "unmapped fetch"})
                if len(st["call_outs"]) > 64:
                    st["stopped_by"] = message + " (call-out budget reached)"
                    break
                mu.reg_write(UC_ARM_REG_PC, lr)
                mu.reg_write(UC_ARM_REG_R0, 0)
                pc = lr
                continue
            if "invalid instruction" in message.lower():
                # an instruction this model does not implement (VFP, mostly): skip it and say so
                st["skipped_unsupported"] = st.get("skipped_unsupported", 0) + 1
                if st["skipped_unsupported"] > 2000:
                    st["stopped_by"] = message + " (unsupported-instruction budget reached)"
                    break
                mu.reg_write(UC_ARM_REG_PC, pc_now + 4)
                pc = pc_now + 4
                continue
            st["stopped_by"] = message
            break
    mu.hook_del(h)
    mu.hook_del(hm)

    names = [s["selector"] for s in st["sends"]]
    rep = {"schema": 1, "target": {"class": cls, "selector": selector, "imp": hex(imp), "types": types},
           "grade": "executed with a FABRICATED receiver and stubbed sends: a recorded site+selector is "
                    "a fact about this body; return values are invented (0), so every send after the "
                    "body first branches on one is not shape-faithful. VFP instructions are executed "
                    "as no-ops (Unicorn rejects them), so float values are unobserved too; "
                    "vfp_skipped records how many, and a body branching on a float result is equally "
                    "unfaithful past that point",
           "counts": {"sends": len(st["sends"]), "vfp_skipped": st["vfp_skipped"],
                      "skipped_unsupported": st.get("skipped_unsupported", 0),
                      "zero_pages_invented": len(st["vivified"]),
                      "call_outs": len(st["call_outs"]),
                      "distinct_selectors": len(set(names)),
                      "distinct_call_sites": len(call_sites), "instructions": st["insns"],
                      "unresolved_selectors": sum(1 for s in st["sends"] if not s["selector"])},
           "stopped_by": st["stopped_by"], "zero_pages_invented": st["vivified"],
           "call_outs": st["call_outs"][:40],
           "trace": st["sends"]}
    if args.json:
        args.json.write_text(json.dumps(rep, indent=1) + "\n")
    print(json.dumps(rep["counts"], indent=1))
    print("stopped_by:", rep["stopped_by"])
    for s in st["sends"][:24]:
        print(f"  {s['site']}  {str(s['selector'])[:46]:46s} recv={s['receiver']} arg2={s['arg2']} arg3={s['arg3']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
