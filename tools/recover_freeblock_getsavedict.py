#!/usr/bin/env python3
"""Hash-gated static inventory for FreeBlock -[getSaveDict]."""
import argparse
import hashlib
import io
import json
import struct
from pathlib import Path

from elftools.elf.elffile import ELFFile
from trace_objc_dispatch import ELFMemory
from recover_drawframe_slices import verify_disassembly

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
START, CODE_END, BOUNDARY = 0x629804, 0x62A410, 0x62A4BC
BASE_PC, BASE_CELL = 0x62981C, 0x62A4B8
SELECTOR_CELLS = {
    0x62A418: 'getSaveDict',
    0x62A42C: 'setObject:forKey:',
    0x62A430: 'numberWithBool:',
    0x62A440: 'numberWithDouble:',
    0x62A44C: 'numberWithInt:',
    0x62A468: 'numberWithFloat:',
    0x62A484: 'countByEnumeratingWithState:objects:count:',
    0x62A488: 'array',
    0x62A490: 'itemType',
    0x62A494: 'addObject:',
    0x62A498: 'saveData',
    0x62A4B4: 'uniqueID',
}
IMPORT_CELLS = {
    0x62A414: 'objc_msgSendSuper2',
    0x62A428: 'objc_msgSend',
}
DIRECT_OBJC_MSGSEND = {0x62A3AC: 0xEBEE611A}

def signed(v):
    return v - (1 << 32) if v & 0x80000000 else v

def checked_word(m, address):
    value = m.word(address)
    if value is None:
        raise ValueError(f'missing word {address:#x}')
    return int(value)

def resolve_cell(m, base, cell):
    return (base + signed(checked_word(m, cell))) & 0xffffffff

def recover(path):
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != SHA:
        raise ValueError('original ELF SHA mismatch')
    m = ELFMemory(path)
    listing = (NATIVE / 'disasm_freeblock_getsavedict.txt').read_text()
    coverage = verify_disassembly(m, listing, START, BOUNDARY)
    base = (BASE_PC + signed(checked_word(m, BASE_CELL))) & 0xffffffff
    if base != 0x0105FAF4:
        raise ValueError('PIC base drift')
    selectors = {}
    for cell, expected in SELECTOR_CELLS.items():
        address = resolve_cell(m, base, cell)
        value = checked_word(m, address)
        actual = m.selectors.get(value)
        if actual != expected:
            raise ValueError(f'selector drift at {cell:#x}: {actual!r} != {expected!r}')
        selectors[expected] = f'0x{cell:08x}'
    imports = {}
    for cell, expected in IMPORT_CELLS.items():
        address = resolve_cell(m, base, cell)
        actual = m.imports.get(address)
        if actual != expected:
            raise ValueError(f'import drift at {cell:#x}: {actual!r} != {expected!r}')
        imports[expected] = f'0x{cell:08x}'

    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    blx_sites = []
    direct_sites = []
    for address in range(START, CODE_END, 4):
        offset = m.offset(address, 4)
        if offset is None:
            raise ValueError(f'missing instruction {address:#x}')
        word = checked_word(m, address)
        ins = list(md.disasm(m.data[offset:offset + 4], address))
        if len(ins) != 1:
            raise ValueError(f'undecodable instruction at {address:#x}')
        if ins[0].mnemonic == 'blx':
            blx_sites.append(f'0x{address:08x}')
    for address, expected_word in DIRECT_OBJC_MSGSEND.items():
        if checked_word(m, address) != expected_word:
            raise ValueError(f'direct objc_msgSend instruction drift at {address:#x}')
        direct_sites.append(f'0x{address:08x}')

    elf = ELFFile(io.BytesIO(raw))
    body_offset = m.offset(START, CODE_END - START)
    if body_offset is None:
        raise ValueError('missing method body')
    body = m.data[int(body_offset):int(body_offset) + CODE_END - START]
    return {
        'schema': 1,
        'method': 'FreeBlock -[getSaveDict]',
        'types': '@8@0:4',
        'elf_sha256': digest,
        'imp': f'0x{START:08x}',
        'code_end': f'0x{CODE_END:08x}',
        'boundary_end': f'0x{BOUNDARY:08x}',
        'code_words': (CODE_END - START) // 4,
        'coverage_words': coverage,
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'pic_base': f'0x{base:08x}',
        'known_selectors': selectors,
        'known_imports': imports,
        'selector_count': len(selectors),
        'blx_sites': blx_sites,
        'blx_count': len(blx_sites),
        'direct_objc_msgsend_sites': direct_sites,
        'direct_objc_msgsend_count': len(direct_sites),
        'super_save_route': {
            'selector': 'getSaveDict',
            'dispatch': 'objc_msgSendSuper2',
            'selector_cell': '0x0062a418',
            'dispatch_cell': '0x0062a414',
        },
        'semantic_inventory': [
            'inherits DynamicObject dictionary via super getSaveDict',
            'boxes boolean/double/float/int values',
            'iterates an array with countByEnumeratingWithState:objects:count:',
            'reads itemType and saveData from contained objects',
            'adds serialized objects to an array',
            'writes additional fields through setObject:forKey:',
            'reads uniqueID',
        ],
        'claim': 'bounded FreeBlock save-method selector/import inventory; object-key pairings and complete FreeBlock schema remain unresolved',
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path, default=NATIVE / 'freeblock_getsavedict.json')
    args = parser.parse_args()
    result = recover(args.elf)
    text = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != text:
            raise SystemExit('stale freeblock_getsavedict.json')
    else:
        args.output.write_text(text)
    print(f"freeblock-getsavedict: selectors={result['selector_count']} blx={result['blx_count']} PASS")

if __name__ == '__main__':
    main()
