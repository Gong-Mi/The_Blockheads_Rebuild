#!/usr/bin/env python3
"""Find who sends an ObjC selector in this build, and where the send happens.

Why this works (mechanism established in OBJC_SEND_CHANNEL.md, revised here):
  * a send is `objc_msgSend(receiver, <selref slot addr>, args...)`, and the slot address
    is used *as* the SEL value; the slot's content in the file is the selector cstring VA;
  * code reaches data through a fixed PIC base (0x105faf4 in this binary - the same base
    the listing header records), so the linker leaves base-relative pool words in .text:
        pool_word + PIC_BASE == target address
    and a matching pool word therefore *is* the literal that names the target;
  * the loading instruction is an `ldr rX, [pc, #k]` whose target is that pool word.

So for a selector X: string VA -> selref slot(s) -> pool word (slot - PIC_BASE) -> loader
instruction -> enclosing method (nearest IMP at or below the loader, from the ObjC method
map) -> whether a send follows.

The earlier probe in this repo searched the *slot* value and the *msgrefs* section and found
nothing; both are recorded in OBJC_SEND_CHANNEL.md. This tool takes the pool-word route,
which is where the link actually lives.

Usage:
  python3 tools/find_selector_senders.py --selector soundNamed: [--selector X ...]
  python3 tools/find_selector_senders.py --list tools/selector_watchlist.txt
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import struct
import sys
from pathlib import Path

DEFAULT_ELF = Path.home() / "blockheads-work/extracted/lib/armeabi-v7a/libApplication.so"
PIC_BASE = 0x0105FAF4
METHODS_TSV = Path("reconstruction/reverse-v3/native/libApplication_objc_methods.tsv")
ARM_BLX_MASK = 0xFF000000 | (0x3 << 22) | (0xF << 8)  # rough: top byte + blx bit


def sections(elf: bytes) -> list[dict]:
    shoff = struct.unpack_from("<I", elf, 32)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", elf, 46)
    out = []
    for i in range(shnum):
        f = struct.unpack_from("<10I", elf, shoff + i * shentsize)
        out.append({"index": i, "nameoff": f[0], "type": f[1], "addr": f[3],
                    "off": f[4], "size": f[5]})
    shstr = next(s["off"] for s in out if s["index"] == shstrndx)
    for sec in out:
        end = elf.index(b"\0", shstr + sec["nameoff"])
        sec["name"] = elf[shstr + sec["nameoff"]:end].decode("latin1")
    return out


def is_ldr_pc(word: int) -> bool:
    """ldr rX, [pc, #+/-imm]  (ARM encoding: cond!=1111, 01, I=1, P=1, U=?, B=0, Rn=1111)"""
    if (word >> 28) == 0xF:
        return False
    if ((word >> 26) & 0x3) != 0x1:
        return False
    if ((word >> 24) & 0x1) != 0x1:
        return False
    if ((word >> 23) & 0x1) != 0x1:      # P
        return False
    if ((word >> 22) & 0x1) != 0x0:      # B
        return False
    return ((word >> 16) & 0xF) == 0xF


def ldr_target(word: int, at: int) -> int:
    imm = word & 0xFFF
    return at + 8 + (imm if (word >> 23) & 1 else -imm)


def find_loader(elf: bytes, pool_va: int, max_back: int = 4152) -> int | None:
    for back in range(8, max_back, 4):
        at = pool_va - back
        if at < 0x1000:
            continue
        word = struct.unpack_from("<I", elf, at)[0]
        if is_ldr_pc(word) and ldr_target(word, at) == pool_va:
            return at
    return None


def blx_at(elf: bytes, va: int) -> bool:
    word = struct.unpack_from("<I", elf, va)[0]
    return (word >> 25) & 0x7F == 0x12 or ((word >> 28) != 0xF and ((word >> 4) & 0xF) == 3 and ((word >> 20) & 0xFF) == 0x12)


def cstr(elf: bytes, va: int) -> str:
    end = elf.index(b"\0", va)
    return elf[va:end].decode("latin1", "replace")


def load_methods(path: Path) -> list[tuple[int, str, str]]:
    rows = []
    if not path.exists():
        return rows
    with path.open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh, delimiter="\t"):
            try:
                rows.append((int(row["implementation"], 16), row.get("class", ""),
                             row.get("selector", "")))
            except (KeyError, ValueError):
                continue
    rows.sort()
    return rows


def enclosing(methods: list[tuple[int, str, str]], site: int) -> str:
    lo, hi, best = 0, len(methods) - 1, None
    while lo <= hi:
        mid = (lo + hi) // 2
        if methods[mid][0] <= site:
            best = methods[mid]
            lo = mid + 1
        else:
            hi = mid - 1
    return f"{best[1]} {best[2]}" if best else "?"


def scan(elf: bytes, sed: list[dict], selector: str,
         methods: list[tuple[int, str, str]]) -> dict:
    out: dict = {"selector": selector, "slots": [], "loaders": [], "sends": []}
    needle = selector.encode() + b"\0"
    at = elf.find(needle)
    if at < 0:
        out["error"] = "string not found"
        out["n_sends"] = 0
        return out
    sec = next((s for s in sed if s["off"] <= at < s["off"] + s["size"]), None)
    string_va = sec["addr"] + (at - sec["off"])
    out["string_va"] = f"0x{string_va:x}"

    selref = next((s for s in sed if "selref" in s["name"]), None)
    slots = []
    if selref:
        for o in range(selref["off"], selref["off"] + selref["size"] - 4, 4):
            if struct.unpack_from("<I", elf, o)[0] == string_va:
                slots.append(selref["addr"] + (o - selref["off"]))
    out["slots"] = [f"0x{s:x}" for s in slots]
    if not slots:
        out["n_sends"] = 0
        return out

    for slot in slots:
        want = struct.pack("<I", (slot - PIC_BASE) & 0xFFFFFFFF)
        start = 0
        while True:
            hit = elf.find(want, start)
            if hit < 0:
                break
            start = hit + 1
            loader = find_loader(elf, hit)
            entry = {"slot": f"0x{slot:x}", "pool_word_at": f"0x{hit:x}",
                     "pool_word": f"0x{struct.unpack_from('<I', elf, hit)[0]:08x}",
                     "loader": f"0x{loader:x}" if loader else None}
            if loader is not None:
                entry["method"] = enclosing(methods, loader)
                # a send re-materialises *slot into the selector argument register
                # (ldr rN,[rN]) and then blx's the send target; require both, in order,
                # so an unrelated message in the same window is not counted.
                window = elf[loader:loader + 0x100]
                sends = []
                indirect = None
                for off in range(0, len(window) - 8, 4):
                    w = struct.unpack_from("<I", window, off)[0]
                    if (w >> 28) != 0xF and ((w >> 26) & 3) == 1 and ((w >> 24) & 1) == 0 \
                            and ((w >> 20) & 0xF) != 0xF:
                        indirect = off
                    if indirect is not None and off > indirect and blx_at(window, off):
                        sends.append(f"0x{loader + off:x}")
                        indirect = None
                entry["send_targets_in_window"] = sends
                if sends:
                    out["sends"].append({"at": sends[0], "method": entry["method"]})
            out["loaders"].append(entry)
    out["n_sends"] = len(out["sends"])
    return out


def main() -> int:
    native = Path("reconstruction/reverse-v3/native")
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", type=Path, default=DEFAULT_ELF)
    ap.add_argument("--selector", action="append", default=[])
    ap.add_argument("--list", type=Path, help="file with one selector per line")
    ap.add_argument("--json", type=Path, default=native / "selector_senders.json")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    selectors = list(args.selector)
    if args.list and args.list.exists():
        selectors += [ln.strip() for ln in args.list.read_text(encoding="utf-8").splitlines()
                      if ln.strip() and not ln.startswith("#")]
    if not selectors:
        print("no selectors given", file=sys.stderr)
        return 2
    if not args.elf.exists():
        print(f"skip: no ELF at {args.elf}")
        return 0

    elf = args.elf.read_bytes()
    sed = sections(elf)
    methods = load_methods(METHODS_TSV)
    payload = {
        "elf_sha256": hashlib.sha256(elf).hexdigest(),
        "pic_base": f"0x{PIC_BASE:x}",
        "selectors": [scan(elf, sed, s, methods) for s in selectors],
    }
    text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    if args.check:
        if not args.json.exists():
            print(f"CHECK FAILED: {args.json} missing", file=sys.stderr)
            return 1
        if args.json.read_text(encoding="utf-8") != text:
            print(f"CHECK FAILED: {args.json} stale", file=sys.stderr)
            return 1
        print("check ok: selector senders")
        return 0
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(text, encoding="utf-8")
    total = sum(s.get("n_sends", 0) for s in payload["selectors"])
    print(f"wrote {args.json.name}: {len(selectors)} selectors, {total} send sites")
    for s in payload["selectors"]:
        print(f"  {s['selector']}: slots={len(s.get('slots', []))} "
              f"loaders={len(s.get('loaders', []))} sends={s.get('n_sends', 0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
