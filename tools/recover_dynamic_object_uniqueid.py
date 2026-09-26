#!/usr/bin/env python3
"""Hash-gated recovery of DynamicObject -[uniqueID]."""
import argparse
import hashlib
import io
import json
from pathlib import Path

from elftools.elf.elffile import ELFFile
from trace_objc_dispatch import ELFMemory
from recover_drawframe_slices import verify_disassembly

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
START = 0x0083D08C
CODE_END = 0x0083D0E8
BOUNDARY_END = 0x0083D0F0
BASE_ADD = 0x0083D0AC
BASE_LITERAL = 0x0083D0EC
IVAR_CELL = 0x0083D0E8
EXPECTED_BASE = 0x0105FAF4
EXPECTED_IVAR_SLOT = 0x0105C3F4
EXPECTED_IVAR_STORAGE = 0x00F33E38


def signed(value):
    return value - (1 << 32) if value & 0x80000000 else value


def checked_word(memory, address):
    value = memory.word(address)
    if value is None:
        raise ValueError(f'missing word at {address:#x}')
    return int(value)


def checked_offset(memory, address, size):
    offset = memory.offset(address, size)
    if offset is None:
        raise ValueError(f'missing bytes at {address:#x}')
    return int(offset)


def recover(path: Path) -> dict:
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHA:
        raise ValueError('original ELF SHA mismatch')
    memory = ELFMemory(path)
    text = (NATIVE / 'disasm_dynamicobject_uniqueid.txt').read_text(encoding='utf-8')
    covered_words = verify_disassembly(memory, text, START, BOUNDARY_END)
    if covered_words != (BOUNDARY_END - START) // 4:
        raise ValueError('unexpected dynamic uniqueID coverage')
    words = (CODE_END - START) // 4
    base = (BASE_ADD + 8 + signed(checked_word(memory, BASE_LITERAL))) & 0xffffffff
    if base != EXPECTED_BASE:
        raise ValueError(f'PIC base drift: {base:#x}')
    slot = (base + signed(checked_word(memory, IVAR_CELL))) & 0xffffffff
    if slot != EXPECTED_IVAR_SLOT:
        raise ValueError(f'ivar slot drift: {slot:#x}')

    elf = ELFFile(io.BytesIO(raw))
    dynsym = elf.get_section_by_name('.dynsym')
    if dynsym is None:
        raise ValueError('missing .dynsym')
    symbols = {s['st_value']: s.name for s in getattr(dynsym, 'iter_symbols')()
               if s['st_value'] != 0}
    storage = checked_word(memory, slot)
    if storage != EXPECTED_IVAR_STORAGE:
        raise ValueError(f'ivar storage drift: {storage:#x}')
    symbol = symbols.get(storage)
    if symbol != 'OBJC_IVAR_$_DynamicObject.uniqueID':
        raise ValueError(f'ivar symbol drift: {symbol!r}')
    offset = checked_word(memory, storage)
    if offset != 40:
        raise ValueError(f'ivar offset drift: {offset}')

    body_offset = checked_offset(memory, START, CODE_END - START)
    body = memory.data[body_offset:body_offset + CODE_END - START]
    return {
        'method': 'DynamicObject -[uniqueID]',
        'types': 'Q8@0:4',
        'elf_sha256': hashlib.sha256(raw).hexdigest(),
        'imp': f'0x{START:08x}',
        'code_end': f'0x{CODE_END:08x}',
        'boundary_end': f'0x{BOUNDARY_END:08x}',
        'verified_words': words,
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'pic_base': f'0x{base:08x}',
        'ivar_cell': f'0x{IVAR_CELL:08x}',
        'ivar_slot': f'0x{slot:08x}',
        'ivar_symbol': symbol,
        'ivar_storage': f'0x{storage:08x}',
        'ivar_offset': offset,
        'return': 'uint64 value copied from self + 40',
        'claim': 'bounded static getter; no dynamic object construction or original-app runtime claim',
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'dynamicobject_uniqueid.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text(encoding='utf-8') != payload:
            raise SystemExit('stale dynamicobject_uniqueid.json')
    else:
        args.output.write_text(payload, encoding='utf-8')
    print(f"words={report['verified_words']} ivar={report['ivar_symbol']} offset={report['ivar_offset']}")


if __name__ == '__main__':
    main()
