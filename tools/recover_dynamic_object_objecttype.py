#!/usr/bin/env python3
"""Hash-gated recovery of DynamicObject -[objectType]."""
import argparse
import hashlib
import json
from pathlib import Path

from trace_objc_dispatch import ELFMemory
from recover_drawframe_slices import verify_disassembly

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
START = 0x008399FC
END = 0x00839A18
EXPECTED_CONSTANT_WORD = 0xE3002041
EXPECTED_CONSTANT = 0x41


def checked_word(memory, address):
    value = memory.word(address)
    if value is None:
        raise ValueError(f'missing word at {address:#x}')
    return int(value)


def recover(path: Path) -> dict:
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHA:
        raise ValueError('original ELF SHA mismatch')
    memory = ELFMemory(path)
    text = (NATIVE / 'disasm_dynamicobject_objecttype.txt').read_text(encoding='utf-8')
    words = verify_disassembly(memory, text, START, END)
    if words != 7 or checked_word(memory, 0x00839A00) != EXPECTED_CONSTANT_WORD:
        raise ValueError('objectType constant instruction drift')
    body_offset = memory.offset(START, END - START)
    if body_offset is None:
        raise ValueError('missing objectType body')
    body_offset = int(body_offset)
    body = memory.data[body_offset:body_offset + END - START]
    return {
        'method': 'DynamicObject -[objectType]',
        'types': 'i8@0:4',
        'elf_sha256': hashlib.sha256(raw).hexdigest(),
        'imp': f'0x{START:08x}',
        'boundary_end': f'0x{END:08x}',
        'verified_words': words,
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'constant_instruction': 'movw r2, #0x41 at 0x00839a00',
        'return_value': EXPECTED_CONSTANT,
        'return': 'constant int 0x41; self is not read',
        'argument_stores': ['0x00839a04: self', '0x00839a08: selector'],
        'claim': 'bounded static getter; no dynamic object construction or original-app runtime claim',
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'dynamicobject_objecttype.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text(encoding='utf-8') != payload:
            raise SystemExit('stale dynamicobject_objecttype.json')
    else:
        args.output.write_text(payload, encoding='utf-8')
    print(f"words={report['verified_words']} return={report['return_value']:#x}")


if __name__ == '__main__':
    main()
