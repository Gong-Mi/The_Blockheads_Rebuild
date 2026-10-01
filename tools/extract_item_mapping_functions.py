#!/usr/bin/env python3
"""Decode ItemType -> value mapping functions into tables.

These functions answer "given this item type, what is the mapped value" (a cage item to
an NPC type, a seed to a tree type, a dyeable item to its dyed variant). Their shape is
consistent and mechanical:

    cmp r0, #K ; beq -> special case              (single mapping)
    sub r1, r0, #BASE ; cmp r1, #N ; bhi -> default
    lsl r1, r0, #2 ; add r2, pc, #4 ; ldr r1, [r1, r2] ; add pc, r1, r2
                                                  (N+1-entry inline jump table)
    ... case bodies: `movw r0, #V ; str r0, [sp, #x] ; b end`

so each entry's target is read, and the constant that body returns is the mapped value.
Anything that does not fit is reported as unclassified with its size, never guessed.

Usage:
  python3 tools/extract_item_mapping_functions.py <libApplication.so> [--tsv OUT] [--json OUT] [--check]
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

FUNCTIONS = (
    "_Z23npcTypeFromCageItemType8ItemType",
    "_Z23treeTypeForSeedItemType8ItemType",
    "_Z24plantTypeForSeedItemType8ItemType",
    "_Z30genericDyedItemTypeForItemType8ItemType",
)
SCAN_WORDS = 160


def dynsym_by_name(elf: bytes) -> dict[str, dict]:
    shoff = struct.unpack_from("<I", elf, 32)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", elf, 46)
    secs = {}
    for i in range(shnum):
        f = struct.unpack_from("<10I", elf, shoff + i * shentsize)
        secs[i] = {"type": f[1], "off": f[4], "size": f[5], "link": f[6]}
    out: dict[str, dict] = {}
    for sec in secs.values():
        if sec["type"] != 11:
            continue
        stroff = secs[sec["link"]]["off"]
        for k in range(sec["size"] // 16):
            so = sec["off"] + k * 16
            st_name, st_value, st_size = struct.unpack_from("<III", elf, so)
            end = elf.index(b"\0", stroff + st_name)
            name = elf[stroff + st_name:end].decode("latin1", errors="replace")
            if name and st_value:
                out[name] = {"address": st_value, "size": st_size}
    return out


def movw_value(word: int) -> int | None:
    if (word >> 28) != 0xE or ((word >> 20) & 0xFF) != 0x30:
        return None
    return ((word >> 4) & 0xF000) | (word & 0x0FFF)


def return_constant(blob: bytes, target: int, words: int = 24) -> int | None:
    """The constant a case body returns: first `movw r0, #V` in its head."""
    for offset in range(0, words * 4, 4):
        value = movw_value(struct.unpack_from("<I", blob, target + offset)[0])
        if value is not None:
            return value
    return None


def decode(blob: bytes, entry: dict) -> dict:
    """Decode a mapping function into (input -> output) pairs plus any inline table.

    Two shapes appear and both are handled the same way: a sparse switch compiled into a
    comparison tree (`cmp rX, #K ; beq T`) and a dense one compiled into an inline jump
    table. Either way, what is wanted is the pair (compared value, constant the reached
    body returns), so the pairs are collected directly and the table is reported
    alongside when it exists - the pre-table special cases (`cmp`+`beq` before the table)
    would otherwise be lost, which is exactly what an earlier cut of this tool did.
    """
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    start, size = entry["address"], entry["size"]
    body = list(md.disasm(blob[start:start + size], start))

    pairs: list[dict] = []
    pending: list[tuple[int, int]] = []      # (compared value, address)
    table_base = None
    for i, ins in enumerate(body):
        word = struct.unpack_from("<I", blob, ins.address)[0]
        if ins.mnemonic == "movw":
            value = movw_value(word)
            if value is not None:
                pending.append((value, ins.address))
        elif ins.mnemonic == "cmp":
            operand = ins.op_str.split(",")[-1].strip()
            if operand.startswith("#"):
                pending = [(int(operand[1:], 0), ins.address)]
        elif ins.mnemonic in ("beq", "bne") and pending:
            value, _at = pending[-1]
            target = int(ins.op_str.lstrip("#"), 16)
            if ins.mnemonic == "beq":
                pairs.append({"input": value, "branch": f"0x{ins.address:08x}",
                              "target": f"0x{target:08x}",
                              "output": return_constant(blob, target)})
        if (ins.mnemonic == "add" and ins.op_str.startswith("r2, pc, #")
                and i + 2 < len(body) and "ldr" in body[i + 1].mnemonic
                and "pc, r1, r2" in body[i + 2].op_str):
            table_base = ins.address + 8 + int(ins.op_str.split("#")[1], 0)

    result = {"address": f"0x{start:08x}", "size": size, "kind": "pairs",
              "pairs": pairs, "pair_count": len(pairs), "table": None}
    if table_base is not None:
        # the bound right before the table gives the entry count
        domain = 0
        for ins in body:
            if ins.mnemonic == "bhi":
                for other in body:
                    if other.mnemonic == "cmp" and ", #" in other.op_str and other.address < ins.address:
                        candidate = int(other.op_str.split("#")[1], 0)
                        if 0 < candidate < 64:
                            domain = candidate + 1
        entries = []
        for index in range(domain):
            rel = struct.unpack_from("<i", blob, table_base + 4 * index)[0]
            target = table_base + rel
            entries.append({"index": index, "target": f"0x{target:08x}",
                            "output": return_constant(blob, target)})
        result["kind"] = "pairs+jump-table"
        result["table"] = {"base": f"0x{table_base:08x}", "entries": entries,
                           "entry_count": len(entries),
                           "domain_size": domain}
    return result


def build(elf_path: Path) -> dict:
    blob = elf_path.read_bytes()
    symbols = dynsym_by_name(blob)
    functions = []
    for name in FUNCTIONS:
        symbol = symbols.get(name)
        if not symbol or symbol["size"] > 4096:
            functions.append({"name": name, "kind": "missing"})
            continue
        decoded = {"name": name, **decode(blob, symbol)}
        functions.append(decoded)
    counts = {
        "functions": len(functions),
        "with_tables": sum(1 for f in functions if f.get("table")),
        "mapped_entries": sum((f.get("table") or {}).get("entry_count", 0) for f in functions),
        "pairs_decoded": sum(f.get("pair_count", 0) for f in functions),
        "pairs_with_output": sum(1 for f in functions for p in f.get("pairs", [])
                                 if p["output"] is not None),
        "table_values_resolved": sum(1 for f in functions
                                     for e in (f.get("table") or {}).get("entries", [])
                                     if e["output"] is not None),
    }
    return {
        "schema": 1,
        "elf_sha256": hashlib.sha256(blob).hexdigest(),
        "claim": ("ItemType -> value mapping functions decoded as tables: input domain "
                  "from the bound check, targets from the inline table, mapped value from "
                  "each case body's returned constant"),
        "counts": counts,
        "functions": functions,
    }


def render_tsv(record: dict) -> str:
    lines = ["function\tkind\tinput\toutput\ttarget"]
    for f in record["functions"]:
        for pair in f.get("pairs", []):
            lines.append(f"{f['name']}\tcompare\t{pair['input']}\t{pair['output']}\t"
                         f"{pair['target']}")
        table = f.get("table")
        if table:
            for entry in table["entries"]:
                base = int(table["base"], 16)
                lines.append(f"{f['name']}\ttable-index\t{entry['index']}\t"
                             f"{entry['output']}\t{entry['target']}")
    return "\n".join(lines) + "\n"


def main() -> int:
    native = Path("reconstruction/reverse-v3/native")
    ap = argparse.ArgumentParser()
    ap.add_argument("elf", type=Path)
    ap.add_argument("--tsv", type=Path, default=native / "item_mapping_functions.tsv")
    ap.add_argument("--json", type=Path, default=native / "item_mapping_functions.json")
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
