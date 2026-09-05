#!/usr/bin/env python3
"""Trace ARM register dataflow to pair Objective-C selector loads with blx calls.

This is deliberately conservative: a selector is only paired when the blx
target register can be traced back to a known selector load in the same
function, without intervening redefinitions. Anything else remains unknown.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
from pathlib import Path

SEL_RE = re.compile(r"selrefs|__objc_selrefs")
REG_RE = re.compile(r"\b(r(?:1[0-2]|[0-9])|ip|lr|sl|fp|sp|pc)\b")
BLX_RE = re.compile(r"\bblx\s+(r(?:1[0-2]|[0-9])|ip|lr)\b")
LDR_RE = re.compile(r"^\s*ldr(?:sb|b|h|sh)?\s+(r(?:1[0-2]|[0-9])|ip|lr|sl)\s*,\s*\[0x([0-9a-fA-F]+)\]\s*$")
MOV_RE = re.compile(r"^\s*mov\s+(r(?:1[0-2]|[0-9])|ip|lr|sl)\s*,\s*(r(?:1[0-2]|[0-9])|ip|lr|sl)\s*$")
ADD_BASE_RE = re.compile(r"^\s*add\s+(r(?:1[0-2]|[0-9])|ip|lr|sl)\s*,\s*pc\s*,\s*(r(?:1[0-2]|[0-9])|ip|lr|sl)\s*$")
LDR_OFFSET_RE = re.compile(r"^\s*ldr(?:sb|b|h|sh)?\s+(r(?:1[0-2]|[0-9])|ip|lr|sl)\s*,\s*\[(r(?:1[0-2]|[0-9])|ip|lr|sl)\s*,\s*(r(?:1[0-2]|[0-9])|ip|lr|sl)\]\s*$")


def load_pdfj(elf: Path, imp: int) -> dict:
    cmd = [
        "r2", "-q", "-e", "scr.color=false", "-e", "bin.relocs.apply=true",
        "-e", "asm.arch=arm", "-e", "asm.bits=32",
        "-c", f"af @ 0x{imp:x}; pdfj @ 0x{imp:x}; q", str(elf),
    ]
    raw = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    return json.loads(raw)


def read_elf_word(elf: Path, addr: int) -> int | None:
    """Read a 32-bit word from the ELF at the given virtual address."""
    out = subprocess.check_output(["llvm-readelf", "-l", "--wide", str(elf)], text=True)
    for line in out.splitlines():
        if "LOAD" not in line:
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        try:
            vaddr = int(parts[1], 16)
            offset = int(parts[2], 16)
            filesz = int(parts[4], 16)
        except (ValueError, IndexError):
            continue
        if vaddr <= addr < vaddr + filesz:
            data = elf.read_bytes()
            file_off = offset + (addr - vaddr)
            if file_off + 4 <= len(data):
                return int.from_bytes(data[file_off:file_off+4], "little")
    return None


def selector_names(elf: Path) -> dict[int, str]:
    """Return map of virtual address -> selector name from __objc_selrefs."""
    out = subprocess.check_output(["llvm-readelf", "-S", "--wide", str(elf)], text=True)
    sel_start = sel_size = None
    for line in out.splitlines():
        if "__objc_selrefs" in line and "PROGBITS" in line:
            m = re.search(r"PROGBITS\s+([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)", line)
            if m:
                sel_start = int(m.group(1), 16)
                sel_size = int(m.group(2), 16)
                break
    if sel_start is None:
        raise SystemExit("__objc_selrefs not found")
    data = elf.read_bytes()
    result = {}
    for off in range(sel_start, sel_start + sel_size, 4):
        file_off = off  # vaddr == file offset for this section
        if file_off + 4 > len(data):
            continue
        ptr = int.from_bytes(data[file_off:file_off+4], "little")
        if ptr == 0:
            continue
        end = data.find(b"\0", ptr)
        if end < 0 or end - ptr > 128:
            continue
        try:
            result[off] = data[ptr:end].decode("utf-8", "replace")
        except Exception:
            pass
    return result


def parse_ops(pdfj: dict) -> list[dict]:
    ops = []
    for op in pdfj.get("ops", []):
        if not isinstance(op, dict) or "addr" not in op:
            continue
        ops.append({
            "addr": op["addr"],
            "disasm": op.get("disasm", ""),
            "type": op.get("type", ""),
        })
    ops.sort(key=lambda o: o["addr"])
    return ops


def last_def(ops: list[dict], reg: str, upto_idx: int) -> int | None:
    """Return the index of the last instruction that defines reg before upto_idx."""
    for i in range(upto_idx - 1, -1, -1):
        dis = ops[i]["disasm"]
        m = re.match(r"^\s*(?:movw?|ldr(?:sb|b|h|sh)?|mvn|add|sub)\s+(r(?:1[0-2]|[0-9])|ip|lr|sl)\b", dis)
        if m and m.group(1) == reg:
            return i
    return None


def first_def(ops: list[dict], reg: str) -> int | None:
    """Return the index of the first instruction that defines reg."""
    for i in range(len(ops)):
        dis = ops[i]["disasm"]
        m = re.match(r"^\s*(?:movw?|ldr(?:sb|b|h|sh)?|mvn|add|sub)\s+(r(?:1[0-2]|[0-9])|ip|lr|sl)\b", dis)
        if m and m.group(1) == reg:
            return i
    return None


def trace_selector(ops: list[dict], idx: int, reg: str, sel_names: dict[int, str], elf: Path, imp: int) -> tuple[str, int | None, int | None]:
    """Trace reg backwards from idx to find a selector load. Returns (status, sel_addr, sel_idx)."""
    seen = set()
    cur = idx
    cur_reg = reg
    while cur >= 0 and cur not in seen:
        seen.add(cur)
        d_idx = last_def(ops, cur_reg, cur)
        if d_idx is None:
            return ("unknown", None, None)
        dis = ops[d_idx]["disasm"]
        # Case 1: direct load from a literal address
        m = LDR_RE.match(dis)
        if m and m.group(1) == cur_reg:
            addr = int(m.group(2), 16)
            content = read_elf_word(elf, addr)
            if content is None:
                return ("unknown", None, None)
            # Check if this GOT entry's content points to a selref
            if content in sel_names:
                return ("candidate", content, d_idx)
            return ("unknown", None, None)
        # Case 2: ldr reg, [reg2, reg3] — resolve reg2 as a GOT entry, reg3 as a PIC base
        m = LDR_OFFSET_RE.match(dis)
        if m and m.group(1) == cur_reg:
            base = m.group(2)
            offset_reg = m.group(3)
            b_idx = last_def(ops, base, d_idx)
            if b_idx is None:
                return ("unknown", None, None)
            bdis = ops[b_idx]["disasm"]
            bm = LDR_RE.match(bdis)
            if not bm or bm.group(1) != base:
                return ("unknown", None, None)
            got_addr = int(bm.group(2), 16)
            got_content = read_elf_word(elf, got_addr)
            if got_content is None:
                return ("unknown", None, None)
            # Resolve offset_reg: it should be the result of `add offset_reg, pc, offset_reg_got`
            o_idx = last_def(ops, offset_reg, d_idx)
            if o_idx is not None:
                odis = ops[o_idx]["disasm"]
                am = ADD_BASE_RE.match(odis)
                if am and am.group(1) == offset_reg:
                    src_reg = am.group(2)
                    s_idx = last_def(ops, src_reg, o_idx)
                    if s_idx is not None:
                        sdis = ops[s_idx]["disasm"]
                        sm = LDR_RE.match(sdis)
                        if sm and sm.group(1) == src_reg:
                            src_got = int(sm.group(2), 16)
                            src_content = read_elf_word(elf, src_got)
                            if src_content is not None:
                                # ARM PIC: pc = address of add instruction + 8
                                pc = ops[o_idx]["addr"] + 8
                                offset_val = (pc + src_content) & 0xFFFFFFFF
                                sel_addr = (got_content + offset_val) & 0xFFFFFFFF
                                if sel_addr in sel_names:
                                    return ("candidate", sel_addr, b_idx)
            # Fallback: if offset_reg is the PIC base initialized at function start
            if first_def(ops, offset_reg) is not None and first_def(ops, offset_reg) < 5:
                f_idx = first_def(ops, offset_reg)
                fdis = ops[f_idx]["disasm"]
                fm = LDR_RE.match(fdis)
                if fm and fm.group(1) == offset_reg:
                    src_got = int(fm.group(2), 16)
                    src_content = read_elf_word(elf, src_got)
                    if src_content is not None:
                        # The PIC base is set at the first instruction: pc = addr + 8
                        pc = ops[f_idx]["addr"] + 8
                        offset_val = (pc + src_content) & 0xFFFFFFFF
                        sel_addr = (got_content + offset_val) & 0xFFFFFFFF
                        if sel_addr in sel_names:
                            return ("candidate", sel_addr, b_idx)
            return ("unknown", None, None)
        # Case 3: mov reg, reg — follow source
        m = MOV_RE.match(dis)
        if m and m.group(1) == cur_reg:
            cur_reg = m.group(2)
            cur = d_idx
            continue
        return ("unknown", None, None)
    return ("unknown", None, None)


def analyze(elf: Path, imp: int) -> list[dict]:
    pdfj = load_pdfj(elf, imp)
    ops = parse_ops(pdfj)
    sel_names = selector_names(elf)
    rows = []
    for i, op in enumerate(ops):
        m = BLX_RE.search(op["disasm"])
        if not m:
            continue
        target = m.group(1)
        status, sel_addr, sel_idx = trace_selector(ops, i, target, sel_names, elf, imp)
        rows.append({
            "call_address": f"0x{op['addr']:08x}",
            "target_register": target,
            "selector_status": status,
            "selector_address": f"0x{sel_addr:08x}" if sel_addr is not None else "",
            "selector_name": sel_names.get(sel_addr, "") if sel_addr is not None else "",
            "selector_load_address": f"0x{ops[sel_idx]['addr']:08x}" if sel_idx is not None else "",
            "receiver_status": "unknown",
            "argument_status": "unknown",
        })
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("elf", type=Path)
    parser.add_argument("--imp", required=True, help="Implementation address (hex)")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    imp = int(args.imp, 16)
    rows = analyze(args.elf, imp)
    if not rows:
        raise SystemExit("no blx sites found")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=[
            "call_address", "target_register", "selector_status", "selector_address",
            "selector_name", "selector_load_address", "receiver_status", "argument_status",
        ], delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    paired = sum(1 for r in rows if r["selector_status"] == "candidate")
    print(f"blx-sites={len(rows)} selector-candidates={paired}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
