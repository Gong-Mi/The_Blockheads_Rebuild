#!/usr/bin/env python3
"""Extract the client ItemType -> display-name table from the pinned ELF.

`nameForItemType(int)` @ 0x004db268 (bare C function, extent
0x004db268..0x004dde3c) switches through two inline jump tables of per-id
"load the constant CFString, spill it, branch to the shared tail" arms:
343 arms for item ids 1..343 (table @ 0x004db2bc) and 82 arms for ids
1024..1105 (table @ 0x004db840). Everything else branches to the default stub
@ 0x004ddb8c, which loads the 'UNKNOWN' constant string (CFString object @
0x00f76218); the tail @ 0x004ddb9c returns the stored name.

This tool re-derives the whole mapping (425 ids) from the ELF and fails on
drift (--check). The conclusion text and the correction of the older
"not extractable" audits live in ITEM_DISPLAY_NAMES.md.

Usage:
  python3 tools/extract_item_display_names.py <libApplication.so> [--json OUT] [--check]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from extract_original_tile_item_map import Elf32Arm  # noqa: E402

EXPECTED_SHA256 = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
FUNCTION = 0x004DB268
FUNCTION_END = 0x004DDE3C
PIC_BASE = 0x0105FAF4
TABLE1 = 0x004DB2BC
N1 = 343
TABLE2 = 0x004DB840
N2 = 82
DEFAULT_STUB = 0x004DDB8C
TAIL = 0x004DDB9C
CALLERS = [0x004CA164, 0x004DFAE4]


def s32(value: int) -> int:
    return value - (1 << 32) if value & 0x80000000 else value


def decode_encoded(elf: Elf32Arm, word: int) -> int:
    """Apportable CFString cell: object address = PIC base + signed(word)."""
    return (PIC_BASE + s32(word)) & 0xFFFFFFFF


def cstr_at(elf: Elf32Arm, obj: int) -> str | None:
    if not (0x400000 <= obj < len(elf.data)):
        return None
    c = elf.word(obj + 8)
    n = elf.word(obj + 12)
    if not (0x400000 <= c < len(elf.data)) or n == 0 or n > 80:
        return None
    return elf.read_va(c, n).decode('latin1')


def stub_name(elf: Elf32Arm, stub: int) -> tuple[str, int, int | None] | None:
    """Decode one arm -> (name, cfstring_obj, cstr) or None."""
    for off in range(stub, stub + 0x20, 4):
        word = elf.word(off)
        if (word & 0xFFFF0000) == 0xE59F0000:            # ldr r0,[pc,#imm]
            target = (off + 8 + (word & 0xFFF)) & 0xFFFFFFFF
            obj = decode_encoded(elf, elf.word(target))
            name = cstr_at(elf, obj)
            if name:
                return name, obj, elf.word(obj + 8)
        if (word & 0xFF000000) == 0xFF000000:            # inline encoded word
            obj = decode_encoded(elf, word)
            name = cstr_at(elf, obj)
            if name:
                return name, obj, elf.word(obj + 8)
    return None


def extract(elf: Elf32Arm, sha: str) -> dict:
    items = []
    for table, count, base_id in ((TABLE1, N1, 1), (TABLE2, N2, 1024)):
        for k in range(count):
            entry = table + 4 * k
            off = s32(elf.word(entry))
            stub = (table + off) & 0xFFFFFFFF
            decoded = stub_name(elf, stub)
            if decoded is None:
                raise SystemExit(f'undecodable arm: id {base_id + k} stub 0x{stub:08x}')
            name, obj, cstr = decoded
            items.append({
                'item_type': base_id + k,
                'name': name,
                'table': 1 if table == TABLE1 else 2,
                'table_entry': f'0x{entry:08x}',
                'stub': f'0x{stub:08x}',
                'cfstring_obj': f'0x{obj:08x}',
                'cstr': f'0x{cstr:08x}' if cstr is not None else None,
                'len': elf.word(obj + 12),
            })
    unknown = [row['item_type'] for row in items if row['name'] == 'UNKNOWN']
    return {
        'schema': 1,
        'batch': 'E142',
        'elf_sha256': sha,
        'function': 'nameForItemType(int) -> NSString*',
        'function_address': f'0x{FUNCTION:08x}',
        'function_end': f'0x{FUNCTION_END:08x}',
        'pic_base': f'0x{PIC_BASE:08x}',
        'tables': [
            {'addr': f'0x{TABLE1:08x}', 'entries': N1, 'id_first': 1, 'id_last': 343},
            {'addr': f'0x{TABLE2:08x}', 'entries': N2, 'id_first': 1024, 'id_last': 1105},
        ],
        'default_stub': {
            'addr': f'0x{DEFAULT_STUB:08x}',
            'name': 'UNKNOWN',
            'cfstring_obj': '0x00f76218',
        },
        'tail': f'0x{TAIL:08x}',
        'callers': [f'0x{a:08x}' for a in CALLERS],
        'item_type_count': len(items),
        'unknown_count': len(unknown),
        'unknown_ids': unknown,
        'items': items,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('libapplication', type=Path)
    parser.add_argument(
        '--json', type=Path,
        default=Path('reconstruction/reverse-v3/native/item_display_names.json'))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()

    elf = Elf32Arm(args.libapplication)
    sha = hashlib.sha256(elf.data).hexdigest()
    if sha != EXPECTED_SHA256:
        print(f'ELF sha256 mismatch: {sha}', file=sys.stderr)
        return 1
    record = extract(elf, sha)
    payload = json.dumps(record, indent=2, ensure_ascii=False) + '\n'

    if args.check:
        if args.json is None or not args.json.exists():
            print('CHECK FAILED: --json output missing', file=sys.stderr)
            return 1
        if args.json.read_text(encoding='utf-8') != payload:
            print(f'CHECK FAILED: {args.json} is stale', file=sys.stderr)
            return 1
        print(f"check ok: {record['item_type_count']} items, "
              f"unknown {record['unknown_count']}")
        return 0

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(payload, encoding='utf-8')
    else:
        print(payload, end='')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
