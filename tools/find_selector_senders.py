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
instruction -> enclosing method -> whether a send follows.

Loader attribution is **prologue-verified**: walk back to the nearest push-with-lr
prologue (same instrument as tools/probe_live_frame_stack.py), and require an exact
method-table imp match for credit; nearest-IMP is only the recorded fallback when no
prologue is found at all.

The earlier probe in this repo searched the *slot* value and the *msgrefs* section and found
nothing; both are recorded in OBJC_SEND_CHANNEL.md. This tool takes the pool-word route,
which is where the link actually lives.

A second, common send form is a direct `bl objc_msgSend` through the PLT (the stub is
derived from `.rel.plt`, never hardcoded); loader windows are searched for it and the
hits are recorded per loader as `msg_sends`. Both forms are combined into `sends` with a
`via` field. Each `objc_msgSend` send also carries `static_args`: pool words near the
call that resolve into `__DATA,__cfstring` are followed to their cstring (cell+8), which
is how the sound names behind the audio triggers are read out statically.

Usage:
  python3 tools/find_selector_senders.py --selector soundNamed: [--selector X ...]
  python3 tools/find_selector_senders.py --list tools/selector_watchlist.txt
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

DEFAULT_ELF = Path.home() / "blockheads-work/extracted/lib/armeabi-v7a/libApplication.so"
PIC_BASE = 0x0105FAF4
METHODS_TSV = Path("reconstruction/reverse-v3/native/libApplication_objc_methods.tsv")
ARM_BLX_MASK = 0xFF000000 | (0x3 << 22) | (0xF << 8)  # rough: top byte + blx bit

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import probe_live_frame_stack as _frame_probe
except ImportError:  # pragma: no cover - the module ships next to this tool
    _frame_probe = None


def sections(elf: bytes) -> list[dict]:
    shoff = struct.unpack_from("<I", elf, 32)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", elf, 46)
    out = []
    for i in range(shnum):
        f = struct.unpack_from("<10I", elf, shoff + i * shentsize)
        out.append({"index": i, "nameoff": f[0], "type": f[1], "addr": f[3],
                    "off": f[4], "size": f[5], "link": f[6], "entsize": f[9]})
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


def msg_send_stub(elf: bytes, secs: list[dict]) -> int | None:
    """VA of the PLT stub that dispatches objc_msgSend (derived from rel.plt, not hardcoded).

    ARM PLT stubs are `add ip,pc,#i ; add ip,ip,#i ; ldr pc,[ip,#i]!`; the immediates sum
    to the GOT slot, so the stub for a symbol is the one whose slot equals the symbol's
    rel.plt r_offset."""
    if _frame_probe is None:
        return None
    rel = next((s for s in secs if s["name"] == ".rel.plt"), None)
    dynsym = next((s for s in secs if s["name"] == ".dynsym"), None)
    dynstr = next((s for s in secs if s["name"] == ".dynstr"), None)
    plt = next((s for s in secs if s["name"] == ".plt"), None)
    if not (rel and dynsym and dynstr and plt):
        return None
    slot = None
    entsize = rel.get("entsize") or 8
    for k in range(rel["size"] // entsize):
        off, info, _ = struct.unpack_from("<III", elf, rel["off"] + k * entsize)
        nameoff = struct.unpack_from("<I", elf, dynsym["off"] + (info >> 8) * 16)[0]
        end = elf.index(b"\0", dynstr["off"] + nameoff)
        if elf[dynstr["off"] + nameoff:end] == b"objc_msgSend":
            slot = off
            break
    if slot is None:
        return None
    _, md_a = _frame_probe._mds()
    va = plt["addr"]
    while va + 12 <= plt["addr"] + plt["size"]:
        insns = list(md_a.disasm(elf[va:va + 12], va))
        if (len(insns) == 3 and insns[0].mnemonic == "add" and "ip" in insns[0].op_str
                and "pc" in insns[0].op_str and insns[1].mnemonic == "add"
                and insns[1].op_str.startswith("ip") and insns[2].mnemonic == "ldr"
                and insns[2].op_str.startswith("pc")):
            imms = []
            for ins in insns:
                m = re.search(r"#(0x[0-9a-fA-F]+|\d+)", ins.op_str)
                imms.append(int(m.group(1), 0) if m else 0)
            if va + 8 + sum(imms) == slot:
                return va
            va += 12
        else:
            va += 4
    return None


def static_string_args(elf: bytes, secs: list[dict], site: int) -> list[str]:
    """Static NSString args near a msg-send site.

    Pool loads in the preceding window are resolved through the PIC base; targets landing
    in `__DATA,__cfstring` are cells whose cstring pointer sits at cell+8 (layout verified
    across the section - the "fire.wav"/"noPath.wav" trigger args read out this way)."""
    cf = next((s for s in secs if "cfstring" in s["name"]), None)
    if cf is None or _frame_probe is None:
        return []
    _, md_a = _frame_probe._mds()
    out = []
    start = max(0, site - 0x20)
    for ins in md_a.disasm(elf[start:site], start):
        if ins.mnemonic != "ldr" or "pc" not in ins.op_str:
            continue
        m = re.search(r"#(0x[0-9a-fA-F]+|\d+)", ins.op_str)
        if not m:
            continue
        pool = ins.address + 8 + int(m.group(1), 0)
        if not (0 < pool < len(elf) - 4):
            continue
        tgt = (struct.unpack_from("<I", elf, pool)[0] + PIC_BASE) & 0xFFFFFFFF
        if cf["addr"] <= tgt < cf["addr"] + cf["size"]:
            s = cstr(elf, struct.unpack_from("<I", elf, tgt + 8)[0])
            if s:
                out.append(s)
    return out


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


def attribute_site(elf: bytes, site: int, methods: list[tuple[int, str, str]],
                   imps: list[int], imp_set: set) -> dict:
    """Prologue-verified attribution (same walk-back instrument as the frame-stack probe).

    An exact method-table imp match of the enclosing function start is required for
    credit; a non-imp start is recorded as unnamed; nearest-IMP is only the recorded
    fallback when no prologue is found at all."""
    start = _frame_probe.fn_start_a32(elf, site) if _frame_probe else None
    mode = "A32"
    if start is None and _frame_probe is not None:
        start = _frame_probe.fn_start_t16(elf, site)
        mode = "T16"
    if start is not None and start in imp_set:
        imp, cls, sel = methods[imps.index(start)]
        return {"method": f"{cls} {sel}", "fn_start": f"0x{start:08x}",
                "fn_start_mode": mode, "offset": site - start,
                "attribution": "prologue-verified"}
    if start is not None:
        return {"method": f"unnamed @0x{start:08x}", "fn_start": f"0x{start:08x}",
                "fn_start_mode": mode, "offset": site - start, "attribution": "unnamed"}
    return {"method": enclosing(methods, site), "fn_start": None, "fn_start_mode": None,
            "offset": None, "attribution": "nearest-imp-fallback"}


def scan(elf: bytes, sed: list[dict], selector: str,
         methods: list[tuple[int, str, str]], imps: list[int], imp_set: set,
         send_stub: int | None) -> dict:
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
                entry.update(attribute_site(elf, loader, methods, imps, imp_set))
                window = elf[loader:loader + 0x100]
                # the common send form: a direct `bl objc_msgSend` (PLT stub derived from
                # rel.plt) inside the loader's window
                msg_sends = []
                if send_stub is not None:
                    for off in range(0, min(0x80, len(window) - 4), 4):
                        w = struct.unpack_from("<I", window, off)[0]
                        if (w & 0xFF000000) != 0xEB000000:
                            continue
                        imm = w & 0xFFFFFF
                        if imm & 0x800000:
                            imm -= 0x1000000
                        if loader + off + 8 + (imm << 2) == send_stub:
                            msg_sends.append(f"0x{loader + off:x}")
                entry["msg_sends"] = msg_sends
                for at in msg_sends:
                    out["sends"].append({"at": at, "method": entry["method"],
                                         "via": "objc_msgSend",
                                         "static_args": static_string_args(elf, sed, int(at, 16))})
                # the other form: re-materialise *slot into the selector argument register
                # (ldr rN,[rN]) and then blx the send target; require both, in order,
                # so an unrelated message in the same window is not counted.
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
                    out["sends"].append({"at": sends[0], "method": entry["method"],
                                         "via": "blx-window"})
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
    if _frame_probe is None or not _frame_probe._HAVE_CAPSTONE:
        print("skip: capstone required for prologue-verified attribution")
        return 0

    elf = args.elf.read_bytes()
    sed = sections(elf)
    methods = load_methods(METHODS_TSV)
    imps = [m[0] for m in methods]
    imp_set = set(imps)
    send_stub = msg_send_stub(elf, sed)
    payload = {
        "elf_sha256": hashlib.sha256(elf).hexdigest(),
        "pic_base": f"0x{PIC_BASE:x}",
        "objc_msgSend_stub": f"0x{send_stub:x}" if send_stub is not None else None,
        "selectors": [scan(elf, sed, s, methods, imps, imp_set, send_stub)
                      for s in selectors],
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
