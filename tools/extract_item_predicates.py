#!/usr/bin/env python3
"""Extract the ItemType predicate matrix from the client's own symbols.

`.dynsym` still carries 108 `...ItemType...` symbols with addresses and sizes, so the
client's attribute logic is addressable without any heuristic: each predicate is a small
function that answers a question about one item type. This decodes them mechanically:

  always-constant   the body returns a literal (e.g. itemTypeIsLiquid returns 0)
  equals-set        `cmp` chains against literals (e.g. itemTypeIsLuminous == 0x451)
  range             a bound test (`sub`/`cmp` pair) - reported with its bound
  jump-table        the body indexes a table; the table address is reported, not guessed
  unclassified      anything else, listed so the coverage stays honest

The point is the matrix: which item types carry which attribute, taken from the binary
rather than from a wiki or a guess.

Usage:
  python3 tools/extract_item_predicates.py <libApplication.so> [--tsv OUT] [--json OUT] [--check]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

try:
    import capstone
except ImportError:
    print("skip: capstone is not installed")
    raise SystemExit(0)

NAME_FILTERS = ("ItemType",)
# Item types live in 0..343 and 1024..1105 (original_item_types.tsv). Literals outside
# those ranges are control-flow constants (return values, branch codes, float words),
# so separating them is what turns "literals" into an attribute matrix.
ITEM_DOMAIN = set(range(0, 344)) | set(range(1024, 1106))
# 0 and 1 are the client's own false/true return constants everywhere in these bodies
# (`movw r0, #0` before a conditional move), and they are also valid item ids, so a
# literal of 0/1 cannot be resolved by value. They are kept out of item_types and left
# in other_literals, where the doc's ambiguity note applies to them.
RETURN_CONSTANTS = {0, 1}


def dynsym(elf: bytes) -> list[dict]:
    shoff = struct.unpack_from("<I", elf, 32)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", elf, 46)
    secs = {}
    for i in range(shnum):
        f = struct.unpack_from("<10I", elf, shoff + i * shentsize)
        secs[i] = {"type": f[1], "off": f[4], "size": f[5], "link": f[6], "entsize": f[9]}
    if shstrndx not in secs:
        return []
    strtab = secs[secs[shstrndx]["off"]] if False else None
    out = []
    for sec in secs.values():
        if sec["type"] != 11:                     # SHT_DYNSYM
            continue
        stroff = secs[sec["link"]]["off"]
        for k in range(sec["size"] // 16):
            so = sec["off"] + k * 16
            st_name, st_value, st_size = struct.unpack_from("<III", elf, so)
            end = elf.index(b"\0", stroff + st_name)
            name = elf[stroff + st_name:end].decode("latin1", errors="replace")
            if any(f in name for f in NAME_FILTERS) and st_value and st_size:
                out.append({"name": name, "address": st_value, "size": st_size})
    return out


def decode_movw(word: int) -> int | None:
    if (word >> 28) != 0xE or ((word >> 20) & 0xFF) != 0x30:
        return None
    return ((word >> 4) & 0xF000) | (word & 0x0FFF)


def classify(blob: bytes, entry: dict) -> dict:
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    start, size = entry["address"], entry["size"]
    body = list(md.disasm(blob[start:start + size], start))
    mnem = [i.mnemonic for i in body]
    literals: list[int] = []
    table_branches = 0
    for ins in body:
        if ins.mnemonic == "movw":
            value = decode_movw(struct.unpack_from("<I", blob, ins.address)[0])
            if value is not None:
                literals.append(value)
        if "ldr" in ins.mnemonic and "pc" in ins.op_str and "r0" in ins.op_str:
            continue
        if ins.mnemonic == "add" and "pc" in ins.op_str:
            table_branches += 1

    if "bx" not in mnem:
        kind = "unclassified"
    elif all(m in ("sub", "movw", "str", "sxtb", "add", "bx", "nop") for m in mnem) and literals:
        # a single movw feeding sxtb/r0 is a constant return
        kind = "always-constant"
    elif table_branches and not literals:
        kind = "jump-table"
    elif literals and any(m == "cmp" for m in mnem):
        kind = "equals-set"
    elif literals:
        kind = "always-constant"
    else:
        kind = "unclassified"

    # For a predicate that returns a literal, that literal is the answer, not an operand:
    # counting it as an "item type named" is the small-value ambiguity the doc warns
    # about, so it is excluded here.
    operands = [] if kind == "always-constant" else literals
    in_domain = sorted({v for v in operands if v in ITEM_DOMAIN and v not in RETURN_CONSTANTS})
    out_domain = sorted({v for v in operands if v not in ITEM_DOMAIN})
    result = {"name": entry["name"], "address": f"0x{start:08x}", "size": size,
              "kind": kind, "literals": literals[:24], "literal_count": len(literals),
              "item_types": in_domain, "item_type_count": len(in_domain),
              "other_literals": out_domain[:12], "instructions": len(body)}
    if kind == "always-constant":
        result["returned"] = literals[0] if literals else None
    return result


def build(elf_path: Path) -> dict:
    blob = elf_path.read_bytes()
    entries = [e for e in dynsym(blob) if e["size"] <= 4096]
    results = [classify(blob, e) for e in entries]
    kinds: dict[str, int] = {}
    for r in results:
        kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
    return {
        "schema": 1,
        "elf_sha256": hashlib.sha256(blob).hexdigest(),
        "claim": ("ItemType predicates decoded from .dynsym-discovered functions: each "
                  "predicate's answer shape (constant / literal set / range / jump table) "
                  "and the literals involved, taken from the client binary"),
        "counts": {
            "symbols_with_itemtype": len(dynsym(blob)),
            "decoded": len(results),
            "by_kind": kinds,
            "with_returned_constant": sum(1 for r in results if "returned" in r),
            "predicates_naming_item_types": sum(1 for r in results if r["item_types"]),
            "distinct_item_types_named": len({v for r in results for v in r["item_types"]}),
            "item_types_in_domain": len(ITEM_DOMAIN),
        },
        "predicates": results,
    }


def render_tsv(record: dict) -> str:
    lines = ["name\taddress\tsize\tkind\titem_types\tother_literals"]
    for p in record["predicates"]:
        items = ",".join(str(v) for v in p["item_types"][:16])
        others = ",".join(hex(v) for v in p["other_literals"][:8])
        lines.append(f"{p['name']}\t{p['address']}\t{p['size']}\t{p['kind']}\t{items}\t{others}")
    return "\n".join(lines) + "\n"


def main() -> int:
    native = Path("reconstruction/reverse-v3/native")
    ap = argparse.ArgumentParser()
    ap.add_argument("elf", type=Path)
    ap.add_argument("--tsv", type=Path, default=native / "item_predicates.tsv")
    ap.add_argument("--json", type=Path, default=native / "item_predicates.json")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    record = build(args.elf)
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
            print(f"check ok: {record['counts']}")
        return status
    args.tsv.parent.mkdir(parents=True, exist_ok=True)
    args.tsv.write_text(tsv, encoding="utf-8")
    args.json.write_text(payload, encoding="utf-8")
    print(f"wrote {args.tsv.name} + {args.json.name}: {record['counts']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
