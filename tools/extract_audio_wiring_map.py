#!/usr/bin/env python3
"""Per-sound wiring map: shipped audio name -> the method(s) that reference it in the ELF.

Why this is the missing half of the audio line
----------------------------------------------
`audio_call_site_literals.json` maps *selector send sites* (soundNamed:, multiSoundNamed:, ...). That
channel is nearly empty: for `soundNamed:` it holds one function with `literals: []`, because most
playback happens through a dispatch form the selector tools do not model. Meanwhile the replacement
still does not reference 136 of the 152 sounds the original names.

The names ARE reachable statically, by a different route that needs no dispatch modelling:

    cstring "blockheadDie.wav"  ->  __cfstring struct (+8 points at the cstring)
                                ->  a pool word equal to (cfstring_va - PIC_BASE 0x105faf4)
                                ->  the ldr site that loads it
                                ->  the enclosing method (prologue scan + method table)

Measured samples: blockheadDie.wav -> Blockhead -[dieForGood]; camera.wav ->
World -[doCameraScreenshot]; babyUnicorn.wav -> Donkey -[loadDerivedStuff];
bow.wav -> Blockhead -[update:accurateDT:isSimulation:]; buzz1.wav -> Workbench -[draw:...].

Self-check enforces those five; a zero-hit sweep is not a result without it. Names with no cfstring
struct are reported as `no_cfstring` rather than silently dropped (axe.wav is one).

Usage:
  python3 tools/extract_audio_wiring_map.py <libApplication.so> --coverage <audio_asset_coverage.json>
      --methods <t.tsv> [--json OUT] [--tsv OUT] [--self-check]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

PIC_BASE = 0x105FAF4
TEXT_LO = 0x001C4500
SELF_CHECK = {
    "blockheadDie.wav": "Blockhead -[dieForGood]",
    "camera.wav": "World -[doCameraScreenshot]",
    "babyUnicorn.wav": "Donkey -[loadDerivedStuff]",
    "bow.wav": "Blockhead -[update:accurateDT:isSimulation:]",
    "buzz1.wav": "Workbench -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:"
                 "cameraMinYWorld:cameraMaxYWorld:]",
}


def build(elf_path: Path, coverage: Path, methods_tsv: Path | None) -> dict:
    from elftools.elf.elffile import ELFFile
    blob = elf_path.read_bytes()
    with elf_path.open("rb") as fh:
        e = ELFFile(fh)
        secs = [(s.name, s["sh_addr"], s["sh_offset"], s["sh_size"]) for s in e.iter_sections()]
        cells = {}
        for s in e.get_section_by_name(".dynsym").iter_symbols():
            cells[s["st_value"]] = s.name

    cf = next(s for s in secs if "__cfstring" in s[0])
    cf_va, cf_off, cf_sz = cf[1], cf[2], cf[3]
    cstring_to_cf: dict[int, list[int]] = {}
    for k in range(cf_sz // 16):
        cstr = struct.unpack_from("<I", blob, cf_off + 16 * k + 8)[0]
        cstring_to_cf.setdefault(cstr, []).append(cf_va + 16 * k)

    methods: dict[int, str] = {}
    if methods_tsv and methods_tsv.is_file():
        for line in methods_tsv.read_text().splitlines()[1:]:
            p = line.split("\t")
            if len(p) >= 4:
                try:
                    methods[int(p[0], 16)] = f"{p[1]} -[{p[3]}]"
                except ValueError:
                    continue
    imps = sorted(methods)

    def owner(x: int) -> str | None:
        lo = None
        for imp in imps:
            if imp <= x:
                lo = imp
            else:
                break
        return methods.get(lo)

    def prologue_owner(x: int) -> tuple[int | None, str | None]:
        a = x - 4
        while a >= TEXT_LO:
            w = struct.unpack_from("<I", blob, a)[0]
            if (w & 0xFFFF0000) == 0xE92D0000 and (w & 0x4000):
                return a, methods.get(a)
            a -= 4
        return None, None

    cov = json.loads(coverage.read_text())
    rows = []
    for r in cov.get("rows", []):
        name = r["name"]
        entry = {"name": name, "sha256": r.get("sha256"), "original_class": r.get("original_class"),
                 "replacement_referenced": r.get("replacement_referenced"),
                 "cstring_va": None, "cfstring_structs": [], "sites": [],
                 "methods": [], "status": None}
        # Inherit the coverage artifact's evidence class. Guessing from the shipped name missed all
        # 14 bird1..bird14.wav rows: the original names those through the printf pattern bird%d.wav,
        # and the artifact spells the class "format-string" (hyphen) while its counts use
        # "format_string" - which is exactly how the first attempt got it wrong.
        cls = r.get("original_class")
        entry["original_class"] = cls
        if cls == "format-string":
            entry["status"] = "format_string_named"
            entry["pattern"] = r.get("original_evidence")
            rows.append(entry)
            continue
        if cls == "unattributed":
            # the original never names this file: it cannot be wired from naming evidence at all,
            # which is a different finding from "the name is composed at run time".
            entry["status"] = "unnamed_by_original"
            rows.append(entry)
            continue
        off = blob.find(name.encode() + b"\0")
        if off < 0:
            # a verbatim-class row whose cstring is missing contradicts the coverage artifact
            entry["status"] = "verbatim_but_no_cstring"
            rows.append(entry)
            continue
        entry["cstring_va"] = hex(off)
        structs = cstring_to_cf.get(off, [])
        entry["cfstring_structs"] = [hex(s) for s in structs]
        if not structs:
            entry["status"] = "no_cfstring"
            rows.append(entry)
            continue
        for s in structs:
            needle = struct.pack("<I", (s - PIC_BASE) & 0xFFFFFFFF)
            i = 0
            while True:
                i = blob.find(needle, i)
                if i < 0:
                    break
                fs, m = prologue_owner(i)
                entry["sites"].append({"pool_word_at": hex(i), "fn_start": hex(fs) if fs else None,
                                       "method": m})
                if m:
                    entry["methods"].append(m)
                i += 4
        entry["status"] = "mapped" if entry["methods"] else "no_site"
        rows.append(entry)
    return {"schema": 1, "elf_sha256": hashlib.sha256(blob).hexdigest(),
            "pic_base": hex(PIC_BASE),
            "method": "cstring -> __cfstring -> pool word (va - PIC_BASE) -> ldr site -> method",
            "rows": rows,
            "counts": {
                "names": len(rows),
                "mapped": sum(1 for r in rows if r["status"] == "mapped"),
                "no_cfstring": sum(1 for r in rows if r["status"] == "no_cfstring"),
                "no_site": sum(1 for r in rows if r["status"] == "no_site"),
                "unnamed_by_original": sum(1 for r in rows if r["status"] == "unnamed_by_original"),
                "verbatim_but_no_cstring": sum(1 for r in rows if r["status"] == "verbatim_but_no_cstring"),
                "format_string_named": sum(1 for r in rows if r["status"] == "format_string_named"),
                "format_string_skipped": sum(1 for r in rows if r["status"] == "format_string_skipped"),
            }}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("libapplication")
    ap.add_argument("--coverage", type=Path, required=True)
    ap.add_argument("--methods", type=Path, default=None)
    ap.add_argument("--json", type=Path, default=None)
    ap.add_argument("--tsv", type=Path, default=None)
    ap.add_argument("--self-check", action="store_true")
    args = ap.parse_args()

    rep = build(Path(args.libapplication), args.coverage, args.methods)
    by = {r["name"]: r for r in rep["rows"]}
    ctrl = {}
    for nm, want in SELF_CHECK.items():
        got = by.get(nm, {}).get("methods", [])
        ctrl[nm] = {"expected": want, "found": got, "ok": want in got}
    rep["self_check"] = {"controls": ctrl, "passed": all(c["ok"] for c in ctrl.values())}

    if args.self_check and not rep["self_check"]["passed"]:
        print(json.dumps({"self_check": "FAILED", "controls": ctrl}, indent=1))
        return 1
    if args.tsv:
        with args.tsv.open("w") as fh:
            fh.write("name\tstatus\treplacement_referenced\tmethod\tsite\n")
            for r in rep["rows"]:
                if r["methods"]:
                    for m, s in zip(r["methods"], r["sites"]):
                        fh.write(f"{r['name']}\t{r['status']}\t{r['replacement_referenced']}\t{m}\t"
                                 f"{s.get('pool_word_at')}\n")
                else:
                    fh.write(f"{r['name']}\t{r['status']}\t{r['replacement_referenced']}\t\t\n")
    payload = json.dumps(rep, indent=1) + "\n"
    if args.json:
        args.json.write_text(payload)
    else:
        print(json.dumps(rep["counts"], indent=1))
        print("self-check:", rep["self_check"]["passed"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
