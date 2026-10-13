#!/usr/bin/env python3
"""Resolve the string literals that sit in the functions which reference audio selectors.

The audio wiring question is "which game action plays which sound". SELECTOR_SENDERS.md
answers the top half - which functions materialise `soundNamed:` / `playAtPosition:` /
`multiSoundNamed:`. This tool answers the other half for those functions: which **string
literals** does the function load, i.e. which names does it have to hand when it calls the
sound API.

Mechanism (same PIC route as find_selector_senders.py, verified there):
  code reaches data through a fixed base, so a pool word in .text satisfies
      pool_word + PIC_BASE == target address
  and the loading instruction is `ldr rX, [pc, #k]` aimed at that pool word. If the target
  lands in a cstring section and decodes to printable text, that is a literal the function
  uses. Selector slots (`__objc_selrefs`) are resolved the same way but reported as
  selectors, not strings, since that is what they are.

  Function attribution is **prologue-verified** (same walk-back instrument as
  probe_live_frame_stack.py / find_selector_senders.py): the nearest push-with-lr start
  must exactly equal a method-table imp for credit; unnamed starts and a nearest-IMP
  fallback are recorded explicitly. String literals are collected from a LITERAL_WINDOW
  (0x2000-byte) window starting at that function start.

Usage:
  python3 tools/extract_sound_call_sites.py [--elf PATH] [--check]
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
LITERAL_WINDOW = 0x2000
NATIVE = Path("reconstruction/reverse-v3/native")

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import probe_live_frame_stack as _frame_probe
except ImportError:  # pragma: no cover - the module ships next to this tool
    _frame_probe = None
METHODS_TSV = NATIVE / "libApplication_objc_methods.tsv"
AUDIO_ASSETS_TSV = NATIVE / "audio_asset_coverage.tsv"
AUDIO_SELECTORS = [
    "soundNamed:",
    "multiSoundNamed:",
    "playAtPosition:",
    "setSoundVolume:",
    "setMusicVolume:",
    "initWithFile:",
]
STRING_SECTION_HINTS = ("cstring", "objc_methname", "objc_classname", "objc_methtype")


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


def load_methods(elf: bytes, secs: list[dict]) -> list[tuple[int, str, str]]:
    """IMP -> (class, selector), from the committed method map (fall back to dynsym scan)."""
    rows = []
    if METHODS_TSV.exists():
        with METHODS_TSV.open(encoding="utf-8") as fh:
            for row in csv.DictReader(fh, delimiter="\t"):
                try:
                    rows.append((int(row["implementation"], 16), row.get("class", ""),
                                 row.get("selector", "")))
                except (KeyError, ValueError):
                    continue
    rows.sort()
    return rows


def enclosing(methods: list[tuple[int, str, str]], site: int) -> tuple[int, str]:
    lo, hi, best = 0, len(methods) - 1, None
    while lo <= hi:
        mid = (lo + hi) // 2
        if methods[mid][0] <= site:
            best = methods[mid]
            lo = mid + 1
        else:
            hi = mid - 1
    if not best:
        return 0, "?"
    return best[0], f"{best[1]} {best[2]}"


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
        return {"key": start, "method": f"{cls} {sel}", "fn_start": f"0x{start:08x}",
                "fn_start_mode": mode, "attribution": "prologue-verified"}
    if start is not None:
        return {"key": start, "method": f"unnamed @0x{start:08x}",
                "fn_start": f"0x{start:08x}", "fn_start_mode": mode,
                "attribution": "unnamed"}
    imp, name = enclosing(methods, site)
    return {"key": imp, "method": name, "fn_start": None, "fn_start_mode": None,
            "attribution": "nearest-imp-fallback"}


def section_of(secs: list[dict], va: int) -> dict | None:
    return next((s for s in secs if s["off"] <= va < s["off"] + s["size"]), None)


def cstring_at(elf: bytes, va: int) -> str | None:
    if not 0 < va < len(elf) - 1:
        return None
    try:
        end = elf.index(b"\0", va)
    except ValueError:
        return None
    raw = elf[va:end]
    if not 1 <= len(raw) <= 64:
        return None
    if not all(32 <= c < 127 for c in raw):
        return None
    return raw.decode("latin1")


def find_loader(elf: bytes, pool_va: int, max_back: int = 4152) -> int | None:
    for back in range(8, max_back, 4):
        at = pool_va - back
        if at < 0x1000:
            continue
        w = struct.unpack_from("<I", elf, at)[0]
        if (w >> 28) == 0xF or ((w >> 26) & 3) != 1 or ((w >> 24) & 1) != 1:
            continue
        if ((w >> 23) & 1) != 1 or ((w >> 22) & 1) or ((w >> 16) & 0xF) != 0xF:
            continue
        imm = w & 0xFFF
        if at + 8 + imm == pool_va:
            return at
    return None


def shipped_names() -> set[str]:
    names: set[str] = set()
    if not AUDIO_ASSETS_TSV.exists():
        return names
    with AUDIO_ASSETS_TSV.open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh, delimiter="\t"):
            for key in ("name", "file", "asset", "path"):
                val = (row.get(key) or "").strip()
                if val.lower().endswith((".wav", ".mp3", ".caf", ".aif", ".aiff")):
                    names.add(val.rsplit("/", 1)[-1])
    return names


def scan(elf: bytes, secs: list[dict], methods, selector: str, shipped: set[str],
         imps: list[int], imp_set: set) -> dict:
    rec: dict = {"selector": selector, "functions": []}
    needle = selector.encode() + b"\0"
    at = elf.find(needle)
    if at < 0:
        rec["error"] = "selector string not found"
        return rec
    sec = section_of(secs, at)
    string_va = sec["addr"] + (at - sec["off"]) if sec else None
    selref = next((s for s in secs if "selref" in s["name"]), None)
    slots = []
    if selref and string_va:
        for o in range(selref["off"], selref["off"] + selref["size"] - 4, 4):
            if struct.unpack_from("<I", elf, o)[0] == string_va:
                slots.append(selref["addr"] + (o - selref["off"]))
    rec["slots"] = [f"0x{s:x}" for s in slots]

    # 每个槽 -> 池字 -> 装载指令 -> 所属函数
    funcs: dict[int, dict] = {}
    for slot in slots:
        want = struct.pack("<I", (slot - PIC_BASE) & 0xFFFFFFFF)
        start = 0
        while True:
            hit = elf.find(want, start)
            if hit < 0:
                break
            start = hit + 1
            loader = find_loader(elf, hit)
            if loader is None:
                continue
            info = attribute_site(elf, loader, methods, imps, imp_set)
            key = info["key"]
            funcs.setdefault(key, {"imp": f"0x{key:x}", "method": info["method"],
                                   "fn_start": info["fn_start"],
                                   "fn_start_mode": info["fn_start_mode"],
                                   "attribution": info["attribution"],
                                   "sites": []})["sites"].append(f"0x{loader:x}")
    # 每个函数里所有能解成字符串/选择器的池字
    for imp, info in funcs.items():
        literals, selectors = [], []
        for at_va in range(imp, min(imp + LITERAL_WINDOW, len(elf) - 4), 4):
            w = struct.unpack_from("<I", elf, at_va)[0]
            if (w >> 28) == 0xF or ((w >> 26) & 3) != 1 or ((w >> 24) & 1) != 1:
                continue
            if ((w >> 23) & 1) != 1 or ((w >> 22) & 1) or ((w >> 16) & 0xF) != 0xF:
                continue
            imm = w & 0xFFF
            pool_va = at_va + 8 + imm
            if pool_va >= len(elf) - 4:
                continue
            target = (struct.unpack_from("<I", elf, pool_va)[0] + PIC_BASE) & 0xFFFFFFFF
            tsec = section_of(secs, target)
            if tsec is None:
                continue
            if "selref" in tsec["name"]:
                sel_va = struct.unpack_from("<I", elf, target)[0]
                s = cstring_at(elf, sel_va)
                if s:
                    selectors.append({"at": f"0x{at_va:x}", "selector": s})
                continue
            if not any(h in tsec["name"] for h in STRING_SECTION_HINTS):
                continue
            s = cstring_at(elf, target)
            if s:
                literals.append({"at": f"0x{at_va:x}", "text": s,
                                 "is_shipped_audio_name": s.rsplit("/", 1)[-1] in shipped})
        info["literals"] = literals
        info["selectors"] = selectors
        info["shipped_audio_literals"] = [l["text"] for l in literals
                                          if l["is_shipped_audio_name"]]
    rec["functions"] = sorted(funcs.values(), key=lambda f: f["imp"])
    return rec


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", type=Path, default=DEFAULT_ELF)
    ap.add_argument("--json", type=Path, default=NATIVE / "audio_call_site_literals.json")
    ap.add_argument("--tsv", type=Path, default=NATIVE / "audio_call_site_literals.tsv")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    if not args.elf.exists():
        print(f"skip: no ELF at {args.elf}")
        return 0
    if _frame_probe is None or not _frame_probe._HAVE_CAPSTONE:
        print("skip: capstone required for prologue-verified attribution")
        return 0
    elf = args.elf.read_bytes()
    secs = sections(elf)
    methods = load_methods(elf, secs)
    imps = [m[0] for m in methods]
    imp_set = set(imps)
    shipped = shipped_names()
    payload = {
        "elf_sha256": hashlib.sha256(elf).hexdigest(),
        "pic_base": f"0x{PIC_BASE:x}",
        "shipped_audio_names": len(shipped),
        "selectors": [scan(elf, secs, methods, s, shipped, imps, imp_set)
                      for s in AUDIO_SELECTORS],
    }
    rows = ["selector\tfunction\tliteral_count\tselectors_in_function\tshipped_audio_literals"]
    for rec in payload["selectors"]:
        for fn in rec.get("functions", []):
            rows.append("\t".join([
                rec["selector"], fn["method"], str(len(fn["literals"])),
                ";".join(sorted({s["selector"] for s in fn["selectors"]})),
                ";".join(sorted(set(fn["shipped_audio_literals"]))),
            ]))
    tsv = "\n".join(rows) + "\n"
    text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    if args.check:
        status = 0
        for path, expected in ((args.json, text), (args.tsv, tsv)):
            if not path.exists() or path.read_text(encoding="utf-8") != expected:
                print(f"CHECK FAILED: {path} missing or stale", file=sys.stderr)
                status = 1
        if status == 0:
            print("check ok: audio call-site literals")
        return status
    args.json.write_text(text, encoding="utf-8")
    args.tsv.write_text(tsv, encoding="utf-8")
    n_funcs = sum(len(r.get("functions", [])) for r in payload["selectors"])
    n_lits = sum(len(f["literals"]) for r in payload["selectors"] for f in r.get("functions", []))
    n_shipped = sum(len(f["shipped_audio_literals"])
                    for r in payload["selectors"] for f in r.get("functions", []))
    print(f"wrote {args.json.name} + {args.tsv.name}: {n_funcs} functions, "
          f"{n_lits} literals, {n_shipped} matching shipped audio names")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
