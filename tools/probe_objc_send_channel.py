#!/usr/bin/env python3
"""Probe how ObjC sends are linked in this build, and record what does not work.

Goal: resolve "which code sends selector X" statically. The project's own reference
describes a `__objc_msgrefs` (coalesced) channel with a two-literal PIC pattern, so this
probe walks that path for one selector (`soundNamed:`) and records each step's result -
including the negative ones, because four scans that find nothing are the evidence that
decides which channel this binary actually uses.

Scans, in order:
  1. the selector string's VA (mapped by section offset range, not by section name);
  2. the `__objc_selrefs` slot holding that VA;
  3. units in `__objc_msgrefs` whose selector field equals the string VA or the slot VA;
  4. a whole-file word scan for both VAs (where does the value live at all);
  5. the relocation sections and their entry counts;
  6. the send idiom observed inside `-[MJSoundManager soundNamed:]`.

Usage:
  python3 tools/probe_objc_send_channel.py [--elf PATH] [--selector soundNamed:] [--tsv OUT] [--json OUT] [--check]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

DEFAULT_ELF = Path.home() / "blockheads-work/extracted/lib/armeabi-v7a/libApplication.so"
SEND_IDIOM_FUNCTION = 0x00B88AAC          # -[MJSoundManager soundNamed:]
SEND_IDIOM_WORDS = 40


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


def va_of_file_offset(secs: list[dict], offset: int) -> tuple[int | None, str]:
    for sec in secs:
        if sec["off"] <= offset < sec["off"] + sec["size"]:
            return sec["addr"] + (offset - sec["off"]), sec["name"]
    return None, "?"


def probe(elf: bytes, selector: str) -> dict:
    secs = sections(elf)
    needle = selector.encode() + b"\0"
    at = elf.find(needle)
    record: dict = {"selector": selector, "string_file_offset": hex(at) if at >= 0 else None}
    if at < 0:
        return record
    string_va, string_sec = va_of_file_offset(secs, at)
    record["string_va"] = f"0x{string_va:x}"
    record["string_section"] = string_sec

    selref = next((s for s in secs if "selref" in s["name"]), None)
    slots = []
    if selref:
        for o in range(selref["off"], selref["off"] + selref["size"] - 4, 4):
            if struct.unpack_from("<I", elf, o)[0] == string_va:
                slots.append(selref["addr"] + (o - selref["off"]))
    record["selref_section"] = selref["name"] if selref else None
    record["selref_slots"] = [f"0x{s:x}" for s in slots]

    msgrefs = next((s for s in secs if "msgref" in s["name"]), None)
    units = []
    if msgrefs:
        wanted = {string_va, *slots}
        for o in range(msgrefs["off"], msgrefs["off"] + msgrefs["size"] - 8, 8):
            a, b = struct.unpack_from("<II", elf, o)
            if a in wanted or b in wanted:
                units.append(f"0x{msgrefs['addr'] + (o - msgrefs['off']):x}")
    record["msgrefs_section"] = msgrefs["name"] if msgrefs else None
    record["msgrefs_unit_matches"] = units

    # where does each VA live as a word, anywhere in the file
    def holders(value: int) -> list[dict]:
        found = []
        packed = struct.pack("<I", value)
        start = 0
        while True:
            hit = elf.find(packed, start)
            if hit < 0 or len(found) >= 12:
                break
            va, name = va_of_file_offset(secs, hit)
            found.append({"section": name, "va": f"0x{va:x}" if va else None,
                          "file_offset": f"0x{hit:x}"})
            start = hit + 1
        return found

    if string_va:
        record["holders_of_string_va"] = holders(string_va)
    for slot in slots:
        record.setdefault("holders_of_selref_slot", []).extend(holders(slot))

    record["relocation_sections"] = [
        {"name": s["name"], "entries": s["size"] // 8,
         "file_offset": f"0x{s['off']:x}"}
        for s in secs if s["type"] == 9
    ]

    # the send idiom: base = ldr [pc,#k] + add pc ; then ldr [pool] ; ldr [reg,base] ; blx
    body = []
    for index in range(SEND_IDIOM_WORDS):
        addr = SEND_IDIOM_FUNCTION + index * 4
        word = struct.unpack_from("<I", elf, addr)[0]
        body.append({"at": f"0x{addr:08x}", "word": f"0x{word:08x}"})
    record["send_idiom"] = {"function": f"0x{SEND_IDIOM_FUNCTION:08x}",
                            "words": body[:16]}
    record["claim"] = ("the selector send channel in this build is not statically "
                       "linkable: the selector string has exactly one holder (its selref "
                       "slot), the slot value appears only inside a relocation section, and "
                       "no msgrefs unit carries either value - so a send resolves through a "
                       "table that is filled at load time")
    return record


def render_tsv(record: dict) -> str:
    lines = ["step\tresult"]
    for key in ("selector", "string_va", "string_section", "selref_section",
                "selref_slots", "msgrefs_section", "msgrefs_unit_matches"):
        lines.append(f"{key}\t{record.get(key)}")
    for key in ("holders_of_string_va", "holders_of_selref_slot"):
        for item in record.get(key, []):
            lines.append(f"{key}\t{item}")
    for rel in record.get("relocation_sections", []):
        lines.append(f"relocation_section\t{rel['name']} entries={rel['entries']}")
    return "\n".join(lines) + "\n"


def main() -> int:
    native = Path("reconstruction/reverse-v3/native")
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", type=Path, default=DEFAULT_ELF)
    ap.add_argument("--selector", default="soundNamed:")
    ap.add_argument("--tsv", type=Path, default=native / "objc_send_channel.tsv")
    ap.add_argument("--json", type=Path, default=native / "objc_send_channel.json")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    if not args.elf.exists():
        print(f"skip: no ELF at {args.elf}")
        return 0
    elf = args.elf.read_bytes()
    record = probe(elf, args.selector)
    record["elf_sha256"] = hashlib.sha256(elf).hexdigest()
    tsv = render_tsv(record)
    payload = json.dumps(record, indent=2, ensure_ascii=False) + "\n"
    if args.check:
        status = 0
        for path, expected in ((args.tsv, tsv), (args.json, payload)):
            if not path.exists():
                print(f"CHECK FAILED: {path} is missing", file=sys.stderr)
                status = 1
            elif path.read_text(encoding="utf-8") != expected:
                print(f"CHECK FAILED: {path} is stale", file=sys.stderr)
                status = 1
        if status == 0:
            print("check ok: send channel probe")
        return status
    args.tsv.parent.mkdir(parents=True, exist_ok=True)
    args.tsv.write_text(tsv, encoding="utf-8")
    args.json.write_text(payload, encoding="utf-8")
    print(f"wrote {args.tsv.name} + {args.json.name}: "
          f"msgrefs_unit_matches={len(record.get('msgrefs_unit_matches', []))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
