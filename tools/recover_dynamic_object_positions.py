#!/usr/bin/env python3
"""Hash-gated recovery of DynamicObject pos/floatPos field getters."""
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
SPECS = [
    dict(name='pos', start=0x0083CFCC, code_end=0x0083D024,
         boundary_end=0x0083D02C, base_add=0x0083CFDC,
         base_literal=0x0083D028, ivar_cell=0x0083D024,
         slot=0x0105C390, storage=0x00F33E28, symbol='OBJC_IVAR_$_DynamicObject.pos',
         offset=16, result='{?=ii}', body_sha256='b9d8450a69c011366e6ab66a94e44506e79acbac199997b0e03d2f117a50bc31',
         copy_call=0x0083D018),
    dict(name='floatPos', start=0x0083D02C, code_end=0x0083D084,
         boundary_end=0x0083D08C, base_add=0x0083D03C,
         base_literal=0x0083D088, ivar_cell=0x0083D084,
         slot=0x0105C3D0, storage=0x00F33E3C, symbol='OBJC_IVAR_$_DynamicObject.floatPos',
         offset=24, result='{Vector2=[2f]}', body_sha256='9274f2322e4187ac871476f40f84d75fc85db64f00a6faf5ef2f3c8c50117266',
         copy_call=0x0083D078),
]


def signed(value):
    return value - (1 << 32) if value & 0x80000000 else value


def checked_word(memory, address):
    value = memory.word(address)
    if value is None:
        raise ValueError(f'missing word at {address:#x}')
    return int(value)


def bl_target(site, word):
    if word >> 24 != 0xEB:
        raise ValueError(f'{site:#x} is not ARM bl')
    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 1 << 24
    return (site + 8 + (imm << 2)) & 0xffffffff


def recover(path: Path) -> dict:
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHA:
        raise ValueError('original ELF SHA mismatch')
    memory = ELFMemory(path)
    elf = ELFFile(io.BytesIO(raw))
    dynsym = elf.get_section_by_name('.dynsym')
    if dynsym is None:
        raise ValueError('missing .dynsym')
    symbols = {s['st_value']: s.name for s in getattr(dynsym, 'iter_symbols')()
               if s['st_value'] != 0}
    methods = []
    for spec in SPECS:
        name = str(spec['name'])
        start = int(spec['start'])
        code_end = int(spec['code_end'])
        boundary_end = int(spec['boundary_end'])
        base_add = int(spec['base_add'])
        base_literal = int(spec['base_literal'])
        ivar_cell = int(spec['ivar_cell'])
        expected_slot = int(spec['slot'])
        expected_storage = int(spec['storage'])
        expected_symbol = str(spec['symbol'])
        expected_offset = int(spec['offset'])
        copy_call = int(spec['copy_call'])
        result_type = str(spec['result'])
        text = (NATIVE / f"disasm_dynamicobject_{name}.txt").read_text(encoding='utf-8')
        covered = verify_disassembly(memory, text, start, boundary_end)
        expected_covered = (boundary_end - start) // 4
        if covered != expected_covered:
            raise ValueError(f"coverage drift for {name}")
        base = (base_add + 8 + signed(checked_word(memory, base_literal))) & 0xffffffff
        if base != 0x0105FAF4:
            raise ValueError(f"PIC base drift for {name}")
        slot = (base + signed(checked_word(memory, ivar_cell))) & 0xffffffff
        if slot != expected_slot:
            raise ValueError(f"ivar slot drift for {name}: {slot:#x}")
        storage = checked_word(memory, slot)
        if storage != expected_storage or symbols.get(storage) != expected_symbol:
            raise ValueError(f"ivar symbol drift for {name}")
        offset = checked_word(memory, storage)
        if offset != expected_offset:
            raise ValueError(f"ivar offset drift for {name}")
        if bl_target(copy_call, checked_word(memory, copy_call)) != 0x001C2888:
            raise ValueError(f"objc_copyStruct call drift for {name}")
        body_offset = memory.offset(start, code_end - start)
        if body_offset is None:
            raise ValueError(f"missing body for {spec['name']}")
        body_offset = int(body_offset)
        body = memory.data[body_offset:body_offset + code_end - start]
        methods.append({
            'name': name,
            'imp': f"0x{start:08x}",
            'code_end': f"0x{code_end:08x}",
            'boundary_end': f"0x{boundary_end:08x}",
            'verified_words': (code_end - start) // 4,
            'coverage_words': covered,
            'body_sha256': hashlib.sha256(body).hexdigest(),
            'pic_base': f"0x{base:08x}",
            'ivar_symbol': spec['symbol'],
            'ivar_offset': offset,
            'return_type': result_type,
            'copy_size': 8,
            'return': f"objc_copyStruct 8 bytes from self + {offset}",
        })
        if methods[-1]['body_sha256'] != str(spec['body_sha256']):
            raise ValueError(f"body hash drift for {name}")
    return {
        'schema': 1,
        'method_group': 'DynamicObject position getters',
        'elf_sha256': hashlib.sha256(raw).hexdigest(),
        'methods': methods,
        'claim': 'bounded static field getters; no dynamic object construction or original-app runtime claim',
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'dynamicobject_positions.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text(encoding='utf-8') != payload:
            raise SystemExit('stale dynamicobject_positions.json')
    else:
        args.output.write_text(payload, encoding='utf-8')
    print('methods=' + str(len(report['methods'])) + ' words=' +
          str(sum(m['verified_words'] for m in report['methods'])))


if __name__ == '__main__':
    main()
