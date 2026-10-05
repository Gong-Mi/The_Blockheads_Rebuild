#!/usr/bin/env python3
"""One card per method: what it touches, what it calls, who calls it.

The per-method work of writing a semantic record was archaeology - re-reading disassembly, hunting for which ivars
a method reads, finding who calls it - even though this project already extracts all of that in separate tools. This
assembles the parts into one view so the expensive part left is judgement rather than searching.

It reuses tools/extract_ivar_cell_references.py's scan() for the ivar sites (rules in one place, and its attribution
already resolves sites to owning methods), and adds the two things it does not do: the call graph (bl targets mapped
to method-table owners, both directions) and a leverage rank.

Ground truth for the contract test comes from facts verified elsewhere in this repository rather than from this
tool's own output: Blockhead -[isMale] reads Blockhead.skinOptions at 728, and Blockhead -[customizationComplete:]
writes it (strb) - both derived from the binary by hand this session and cross-checked against the scanner.

Usage:
  method_card.py <libApplication.so> [--methods tsv] --class Blockhead --selector isMale
  method_card.py <libApplication.so> --rank 40          # the worklist, by leverage
  method_card.py <libApplication.so> --class World --selector worldTime --json out.json
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import extract_ivar_cell_references as ivars  # the scanner, reused rather than re-implemented

DEFAULT_ELF = ROOT.parent.parent / "extracted/lib/armeabi-v7a/libApplication.so"
DEFAULT_TSV = ROOT / "reconstruction/reverse-v3/native/libApplication_objc_methods.tsv"


def load_methods(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text().splitlines()[1:]:
        f = line.split("\t")
        if len(f) >= 5:
            rows.append({"imp": int(f[0], 16), "class": f[1], "kind": f[2], "selector": f[3], "types": f[4]})
    rows.sort(key=lambda r: r["imp"])
    return rows


def owner_of(rows: list[dict], va: int) -> dict | None:
    best = None
    for r in rows:
        if r["imp"] <= va and (best is None or r["imp"] > best["imp"]):
            best = r
    return best


def body(rows: list[dict], i: int, blob: bytes) -> tuple[int, int]:
    """The method's own address range, bounded by the next method-table entry."""
    lo = rows[i]["imp"]
    hi = rows[i + 1]["imp"] if i + 1 < len(rows) else lo + 0x400
    return lo, min(hi, len(blob))


def call_targets(blob: bytes, lo: int, hi: int) -> list[int]:
    """Direct branches in [lo, hi): 'bl' (cond 0xEB) and 'blx' register-immediate are ignored on purpose."""
    out = []
    for a in range(lo & ~3, min(hi, len(blob)) - 3, 4):
        w = struct.unpack_from("<I", blob, a)[0]
        if (w >> 24) & 0xFF == 0xEB:
            imm = w & 0xFFFFFF
            if imm & 0x800000:
                imm -= 0x1000000
            out.append((a + 8 + imm * 4) & 0xFFFFFFFF)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("elf", nargs="?", default=str(DEFAULT_ELF))
    ap.add_argument("--methods", type=Path, default=DEFAULT_TSV)
    ap.add_argument("--imp", default=None)
    ap.add_argument("--class", dest="cls", default=None)
    ap.add_argument("--selector", default=None)
    ap.add_argument("--rank", type=int, default=0, help="print the top N methods by leverage instead of one card")
    ap.add_argument("--json", type=Path, default=None)
    a = ap.parse_args()

    elf = Path(a.elf)
    if not elf.is_file():
        print(f"skip: {elf} not present")
        return 0
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
    except ImportError:
        print("skip: capstone is not installed, and the ivar scanner needs it")
        return 0
    from elftools.elf.elffile import ELFFile
    blob = elf.read_bytes()
    rows = load_methods(a.methods)
    with elf.open("rb") as fh:
        cells = ivars.build_cell_map(ELFFile(fh))          # takes an ELF object, not a path
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    sites, _stats = ivars.scan(blob, cells, {r["imp"]: f'{r["class"]} -[{r["selector"]}]' for r in rows},
                               disasm=md.disasm)
    # Attribute by the scanner's STRUCTURED imp, not by matching its display name: the two sides format method
    # names differently, and a string match silently attributed nothing here at first (isMale showed no ivars
    # despite the scanner having five sites for skinOptions). method_entries_in_range carries the imp itself.
    # Two attributions, kept distinct rather than blended. The scanner's own is prologue-based, which is why it
    # reports "ambiguous" for a site inside a shared outer body - that is information, not noise, so it is used when
    # it is unique. Otherwise the site is attributed by ADDRESS RANGE (the same rule this tool uses for calls) and
    # labelled "range", because "the method-table entry covering this address" and "the function whose prologue
    # encloses it" are different claims and a reader must be able to tell them apart.
    by_method: dict[int, list[dict]] = {}
    for s in sites:
        ent = s.get("method_entries_in_range") or []
        if s.get("attribution") == "unique" and len(ent) == 1:
            by_method.setdefault(int(ent[0]["imp"], 16), []).append(s)
            continue
        owner = owner_of(rows, int(s["add_site"], 16))
        if owner:
            by_method.setdefault(owner["imp"], []).append(dict(s, attribution="range"))

    # call graph, both directions
    calls: dict[int, list[int]] = {}
    called_by: dict[int, list[int]] = {}
    for i, r in enumerate(rows):
        lo, hi = body(rows, i, blob)
        tgts = set()
        for t in call_targets(blob, lo, hi):
            o = owner_of(rows, t)
            if o and o["imp"] != r["imp"]:
                tgts.add(o["imp"])
        calls[r["imp"]] = sorted(tgts)
        for t in tgts:
            called_by.setdefault(t, []).append(r["imp"])

    # Compiler-generated members are not semantic targets: .cxx_construct/.cxx_destruct/.dtor bodies are huge and
    # called from everywhere, and they filled the top of the first worklist this produced (MainMenuUI's
    # .cxx_construct had 441 callers). Filtered here rather than in the reader's head.
    GENERATED = re.compile(r"(\.cxx_construct|\.cxx_destruct|\.dtor|\.cxx_dtor|^__|^_\$)")

    def is_generated(r: dict) -> bool:
        return bool(GENERATED.search(r["selector"]))

    # The score is stated so it can be argued with: callers are reach (who breaks if this is wrong) and sites are
    # state touched (how much semantics it carries). Weighting sites higher because a method that reads and writes
    # many fields is where understanding pays off, while a widely-called one-liner is cheap to get right anyway.
    def leverage(r: dict) -> int:
        return len(called_by.get(r["imp"], [])) + 3 * len(by_method.get(r["imp"], []))

    if a.rank:
        work = sorted((r for r in rows if not is_generated(r)), key=leverage, reverse=True)[: a.rank]
        print(f"{'leverage':>8}  {'callers':>7}  {'sites':>5}  {'words':>6}  method")
        for r in work:
            lo, hi = body(rows, rows.index(r), blob)
            print(f"{leverage(r):>8}  {len(called_by.get(r['imp'], [])):>7}  "
                  f"{len(by_method.get(r['imp'], [])):>5}  {(hi - lo) // 4:>6}  "
                  f'{r["class"]} -[{r["selector"]}]')
        return 0

    want = None
    if a.imp:
        want = next((r for r in rows if r["imp"] == int(a.imp, 16)), None)
    elif a.cls and a.selector:
        want = next((r for r in rows if r["class"] == a.cls and r["selector"] == a.selector), None)
    if not want:
        print("no such method in the table"); return 1
    i = rows.index(want)
    lo, hi = body(rows, i, blob)
    card = {
        "method": f'{want["class"]} -[{want["selector"]}]',
        "imp": f'{want["imp"]:#010x}', "kind": want["kind"], "types": want["types"],
        "body": {"lo": f"{lo:#x}", "hi": f"{hi:#x}", "words": (hi - lo) // 4},
        "ivars": [{"ivar": s.get("ivar"), "offset": s.get("offset"), "access": s.get("access"),
                   "attribution": s.get("attribution"),
                   "at": s.get("add_site"), "instruction": s.get("site_instruction")}
                  for s in by_method.get(want["imp"], [])],
        "calls": [f'{c["class"]} -[{c["selector"]}]'
                  for c in (owner_of(rows, t) for t in calls.get(want["imp"], [])) if c],
        "called_by": [f'{c["class"]} -[{c["selector"]}]'
                      for c in (owner_of(rows, t) for t in called_by.get(want["imp"], [])) if c],
        "leverage": leverage(want),
    }
    if a.json:
        a.json.write_text(json.dumps(card, indent=1) + "\n")
    print(f'{card["method"]}  {card["imp"]}  ({card["kind"]}, {card["body"]["words"]} words)')
    if card["ivars"]:
        print("  ivars:")
        for v in card["ivars"][:12]:
            print(f'    {v["access"]:16s} [{v["attribution"]:9s}] {str(v["ivar"]):30s} off={v["offset"]}  {v["instruction"] or ""}')
    else:
        print("  ivars: none attributed (the scan models cell-idiom access only - absence is not evidence)")
    for label, key in (("calls", "calls"), ("called by", "called_by")):
        if card[key]:
            print(f"  {label} ({len(card[key])}): " + ", ".join(card[key][:6])
                  + (" …" if len(card[key]) > 6 else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
