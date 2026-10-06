#!/usr/bin/env python3
"""Hash-gated recovery of the WorldHelper per-tile sunlight update pair.

Two class bodies from the pinned original libApplication.so (1.7.6,
armeabi-v7a, SHA-256 733d8210…b94c7):

  +[WorldHelper updateSunLightForTile:atPos:world:]        0x00a1b7d4..0x00a1bd10
  +[WorldHelper updateSunLightRemovedForTile:atPos:world:] 0x00a1c680..0x00a1ca64

These are the leaf entry points of the sunlight propagation system: they
collect the world indices around a tile and hand them to the recursive
sunlight engines (recursivelyUpdateSunLightWithList:openIndices:world: /
recursivelyRemoveAllSunLightWithList:…), which are NOT mapped here.

Every instruction word is re-verified against the pinned ELF; PIC base,
selector cells, class-reference relocations, the objc_msgSend import, call
routes, every branch destination and the direct worldIndexAtWorldPosition
target are anchored, and the tool refuses to emit on any drift.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from trace_objc_dispatch import ELFMemory
from recover_drawframe_slices import verify_disassembly

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
EXPECTED_SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
EXPECTED_BASE = 0x0105FAF4
MSGSEND_GOT_SLOT = 0x0105B7A0
WORLD_INDEX_AT_POSITION = 0x00A156A8   # _Z25worldIndexAtWorldPositioniiP5World
RECURSIVE_UPDATE = 'recursivelyUpdateSunLightWithList:openIndices:world:'
RECURSIVE_REMOVE = ('recursivelyRemoveAllSunLightWithList:openIndices:'
                    'lightWasRemovedList:removeIndices:world:minx:maxX:')

SPECS = [
    dict(
        name='updateSunLightForTile',
        method='WorldHelper +[updateSunLightForTile:atPos:world:]',
        types='v24@0:4^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}8{?=ii}12@20',
        start=0x00A1B7D4, end=0x00A1BD10,
        disasm='disasm_worldhelper_updatesunlight.txt',
        base_add=0x00A1B7E4, base_literal=0x00A1BD0C,
        boundary=('no own ARM.exidx entry; closed by the next method IMP '
                  '0x00a1bd10 (+[recursivelyRemoveAllSunLightWithList:…])'),
        selectors={
            0x00A1BCE4: (0x00E84CB4, 'indexSet'),
            0x00A1BCEC: (0x00E84CB0, 'array'),
            0x00A1BCF4: (0x00E84C9C, 'addIndex:'),
            0x00A1BCF8: (0x00E84C98, 'addObject:'),
            0x00A1BCFC: (0x00E84C94, 'numberWithInt:'),
            0x00A1BD04: (0x00E84CB8, 'count'),
            0x00A1BD08: (0x00E84CBC, RECURSIVE_UPDATE),
        },
        classrefs={
            0x00A1BCE8: (0x00E8AE7C, 'OBJC_CLASS_$_NSMutableIndexSet'),
            0x00A1BCF0: (0x00E8AE78, 'OBJC_CLASS_$_NSMutableArray'),
            0x00A1BD00: (0x00E8AE74, 'OBJC_CLASS_$_NSNumber'),
        },
        imports={0x00A1BCE0: (MSGSEND_GOT_SLOT, 'objc_msgSend')},
        calls=[
            (0x00A1B848, 'blx r5', 'objc_msgSend: [NSMutableArray array]'),
            (0x00A1B86C, 'blx r3', 'objc_msgSend: [NSMutableIndexSet indexSet]'),
            (0x00A1B880, 'bl sym.worldIndexAtWorldPosition_int__int__World_',
             'worldIndexAtWorldPosition(x, y, world) -> index'),
            (0x00A1B8FC, 'blx r4', 'objc_msgSend: [NSNumber numberWithInt:index]'),
            (0x00A1B91C, 'blx r3', 'objc_msgSend: [array addObject:number]'),
            (0x00A1B934, 'blx r3', 'objc_msgSend: [indexSet addIndex:index]'),
            (0x00A1B948, 'bl sym.worldIndexAtWorldPosition_int__int__World_',
             'worldIndexAtWorldPosition(x, y+1, world) -> index'),
            (0x00A1B9C4, 'blx r4', 'objc_msgSend: [NSNumber numberWithInt:index]'),
            (0x00A1B9E4, 'blx r3', 'objc_msgSend: [array addObject:number]'),
            (0x00A1B9FC, 'blx r3', 'objc_msgSend: [indexSet addIndex:index]'),
            (0x00A1BA10, 'bl sym.worldIndexAtWorldPosition_int__int__World_',
             'worldIndexAtWorldPosition(x, y-1, world) -> index'),
            (0x00A1BA8C, 'blx r4', 'objc_msgSend: [NSNumber numberWithInt:index]'),
            (0x00A1BAAC, 'blx r3', 'objc_msgSend: [array addObject:number]'),
            (0x00A1BAC4, 'blx r3', 'objc_msgSend: [indexSet addIndex:index]'),
            (0x00A1BAD8, 'bl sym.worldIndexAtWorldPosition_int__int__World_',
             'worldIndexAtWorldPosition(x+1, y, world) -> index'),
            (0x00A1BB54, 'blx r4', 'objc_msgSend: [NSNumber numberWithInt:index]'),
            (0x00A1BB74, 'blx r3', 'objc_msgSend: [array addObject:number]'),
            (0x00A1BB8C, 'blx r3', 'objc_msgSend: [indexSet addIndex:index]'),
            (0x00A1BBA0, 'bl sym.worldIndexAtWorldPosition_int__int__World_',
             'worldIndexAtWorldPosition(x-1, y, world) -> index'),
            (0x00A1BC1C, 'blx r4', 'objc_msgSend: [NSNumber numberWithInt:index]'),
            (0x00A1BC3C, 'blx r3', 'objc_msgSend: [array addObject:number]'),
            (0x00A1BC54, 'blx r3', 'objc_msgSend: [indexSet addIndex:index]'),
            (0x00A1BC84, 'blx r2', 'objc_msgSend: [array count] (drain loop gate)'),
            (0x00A1BCD0, 'blx ip',
             f'objc_msgSend: [+WorldHelper {RECURSIVE_UPDATE}] with '
             '(list=array, openIndices=indexSet, world)'),
        ],
        branches=[
            (0x00A1B890, 'blt', 0x00A1B938),
            (0x00A1B958, 'blt', 0x00A1BA00),
            (0x00A1BA20, 'blt', 0x00A1BAC8),
            (0x00A1BAE8, 'blt', 0x00A1BB90),
            (0x00A1BBB0, 'blt', 0x00A1BC58),
            (0x00A1BC58, 'b', 0x00A1BC5C),
            (0x00A1BC8C, 'bls', 0x00A1BCD8),
            (0x00A1BCD4, 'b', 0x00A1BC5C),
        ],
        instructions=[
            (0x00A1B818, 'str r3, [fp, -0x20]'),
            (0x00A1B93C, 'ldr r1, [fp, -0x1c]'),
            (0x00A1B940, 'add r1, r1, 1'),
            (0x00A1BA08, 'sub r1, r1, 1'),
            (0x00A1BACC, 'add r0, r0, 1'),
            (0x00A1BB94, 'sub r0, r0, 1'),
            (0x00A1BC88, 'cmp r0, 0'),
        ],
        semantics=(
            'array = [NSMutableArray array]; open = [NSMutableIndexSet indexSet]; '
            'for (dx, dy) in [(0,0), (0,+1), (0,-1), (+1,0), (-1,0)]: '
            'index = worldIndexAtWorldPosition(x+dx, y+dy, world); '
            'if (index >= 0) { [array addObject:[NSNumber numberWithInt:index]]; '
            '[open addIndex:index]; } '
            'while ([array count] > 0) '
            '+[WorldHelper recursivelyUpdateSunLightWithList:array '
            'openIndices:open world:world]. '
            'The five blocks are worldIndex checks in the order self, y+1, '
            'y-1, x+1, x-1; the drain loop re-invokes the engine until the '
            'work list is consumed. Engine internals are outside this body.'),
    ),
    dict(
        name='updateSunLightRemovedForTile',
        method='WorldHelper +[updateSunLightRemovedForTile:atPos:world:]',
        types='v24@0:4^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}8{?=ii}12@20',
        start=0x00A1C680, end=0x00A1CA64,
        disasm='disasm_worldhelper_updatesunlightremoved.txt',
        base_add=0x00A1C690, base_literal=0x00A1CA60,
        boundary=('no own ARM.exidx entry; closed by the next method IMP '
                  '0x00a1ca64 (+[recalculateLightingForPhysicalBlockIfNeeded:…])'),
        selectors={
            0x00A1CA30: (0x00E84CB4, 'indexSet'),
            0x00A1CA38: (0x00E84CB0, 'array'),
            0x00A1CA40: (0x00E84C98, 'addObject:'),
            0x00A1CA44: (0x00E84C94, 'numberWithInt:'),
            0x00A1CA4C: (0x00E84CB8, 'count'),
            0x00A1CA50: (0x00E84C90, 'containsIndex:'),
            0x00A1CA54: (0x00E84C9C, 'addIndex:'),
            0x00A1CA58: (0x00E84CBC, RECURSIVE_UPDATE),
            0x00A1CA5C: (0x00E84CC0, RECURSIVE_REMOVE),
        },
        classrefs={
            0x00A1CA34: (0x00E8AE7C, 'OBJC_CLASS_$_NSMutableIndexSet'),
            0x00A1CA3C: (0x00E8AE78, 'OBJC_CLASS_$_NSMutableArray'),
            0x00A1CA48: (0x00E8AE74, 'OBJC_CLASS_$_NSNumber'),
        },
        imports={0x00A1CA2C: (MSGSEND_GOT_SLOT, 'objc_msgSend')},
        calls=[
            (0x00A1C6FC, 'blx r5', 'objc_msgSend: [NSMutableArray array] (list)'),
            (0x00A1C720, 'blx r3', 'objc_msgSend: [NSMutableArray array] (lightWasRemovedList)'),
            (0x00A1C744, 'blx r3', 'objc_msgSend: [NSMutableIndexSet indexSet] (openIndices)'),
            (0x00A1C768, 'blx r3', 'objc_msgSend: [NSMutableIndexSet indexSet] (removeIndices)'),
            (0x00A1C77C, 'bl sym.worldIndexAtWorldPosition_int__int__World_',
             'worldIndexAtWorldPosition(x, y, world) -> index0'),
            (0x00A1C7E8, 'blx ip', 'objc_msgSend: [NSNumber numberWithInt:index0]'),
            (0x00A1C808, 'blx r3', 'objc_msgSend: [list addObject:number]'),
            (0x00A1C84C, 'blx r2', 'objc_msgSend: [list count] (removal drain gate)'),
            (0x00A1C8B8, 'blx ip',
             f'objc_msgSend: [+WorldHelper {RECURSIVE_REMOVE}] with '
             '(list, openIndices, lightWasRemovedList, removeIndices, world, '
             'minx = x-32, maxX = x+32)'),
            (0x00A1C8F0, 'blx r3', 'objc_msgSend: [removeIndices containsIndex:index0]'),
            (0x00A1C968, 'blx r4', 'objc_msgSend: [NSNumber numberWithInt:index0]'),
            (0x00A1C988, 'blx r3', 'objc_msgSend: [lightWasRemovedList addObject:number]'),
            (0x00A1C9A0, 'blx r3', 'objc_msgSend: [removeIndices addIndex:index0]'),
            (0x00A1C9D0, 'blx r2', 'objc_msgSend: [lightWasRemovedList count] (re-update gate)'),
            (0x00A1CA1C, 'blx ip',
             f'objc_msgSend: [+WorldHelper {RECURSIVE_UPDATE}] with '
             '(list = lightWasRemovedList, openIndices = removeIndices, world)'),
        ],
        branches=[
            (0x00A1C78C, 'bge', 0x00A1C794),
            (0x00A1C790, 'b', 0x00A1CA24),
            (0x00A1C854, 'bls', 0x00A1C8C0),
            (0x00A1C8BC, 'b', 0x00A1C824),
            (0x00A1C8FC, 'bne', 0x00A1C9A4),
            (0x00A1C9A4, 'b', 0x00A1C9A8),
            (0x00A1C9D8, 'bls', 0x00A1CA24),
            (0x00A1CA20, 'b', 0x00A1C9A8),
        ],
        instructions=[
            (0x00A1C810, 'sub r0, r0, 0x20'),
            (0x00A1C81C, 'add r0, r0, 0x20'),
            (0x00A1C8F4, 'sxtb r0, r0'),
            (0x00A1C8F8, 'cmp r0, 0'),
        ],
        semantics=(
            'list = [NSMutableArray array]; lightWasRemovedList = '
            '[NSMutableArray array]; openIndices = [NSMutableIndexSet indexSet]; '
            'removeIndices = [NSMutableIndexSet indexSet]; '
            'index0 = worldIndexAtWorldPosition(x, y, world); if (index0 < 0) return; '
            '[list addObject:[NSNumber numberWithInt:index0]]; '
            'while ([list count] > 0) '
            '+[WorldHelper recursivelyRemoveAllSunLightWithList:list '
            'openIndices:openIndices lightWasRemovedList:lightWasRemovedList '
            'removeIndices:removeIndices world:world minx:x-32 maxX:x+32]; '
            'if (![removeIndices containsIndex:index0]) { '
            '[lightWasRemovedList addObject:[NSNumber numberWithInt:index0]]; '
            '[removeIndices addIndex:index0]; '
            'while ([lightWasRemovedList count] > 0) '
            '+[WorldHelper recursivelyUpdateSunLightWithList:lightWasRemovedList '
            'openIndices:removeIndices world:world]; } '
            'The two arrays and two index sets are allocated up front; the '
            'first collect touches only the list (openIndices is the removal '
            'engine\'s accumulator), the second touches both the list and the '
            'removeIndices set. Engine internals are outside this body.'),
    ),
]


def signed(v: int) -> int:
    return v - (1 << 32) if v & 0x80000000 else v


def bl_target(site: int, word: int) -> int:
    if word >> 24 != 0xEB:
        raise ValueError(f'{site:#x} is not ARM bl')
    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 1 << 24
    return (site + 8 + (imm << 2)) & 0xffffffff


def reloc_symbols(path: Path) -> dict:
    """r_offset -> symbol name for every relocation that names a symbol."""
    elf = ELFFile(io.BytesIO(path.read_bytes()))
    out = {}
    for section in elf.iter_sections():
        if not hasattr(section, 'iter_relocations'):
            continue
        try:
            symbols = elf.get_section(section['sh_link'])
        except Exception:
            continue
        for rel in section.iter_relocations():
            if rel['r_info_sym']:
                out[rel['r_offset']] = symbols.get_symbol(rel['r_info_sym']).name
    return out


def recover(path: Path) -> dict:
    data = path.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    if sha != EXPECTED_SHA:
        raise ValueError('unsupported ELF SHA-256; fixed-IMP analysis requires pinned original')
    memory = ELFMemory(path)
    relocs = reloc_symbols(path)

    def cstr(addr):
        off = memory.offset(addr, 1)
        if off is None:
            return None
        end = data.find(b'\0', off, off + 256)
        return data[off:end].decode('utf-8', 'replace') if end >= 0 else None

    methods = []
    for spec in SPECS:
        text = (NATIVE / spec['disasm']).read_text()
        words = verify_disassembly(memory, text, spec['start'], spec['end'])
        rows = {}
        for m in re.finditer(r'\b(0x[0-9a-f]{8})\s+[0-9a-f]{8}\s+(.*)', text):
            rows[int(m.group(1), 16)] = m.group(2).split(';')[0].strip()

        base = (spec['base_add'] + 8 + signed(memory.word(spec['base_literal']))) & 0xffffffff
        if base != EXPECTED_BASE:
            raise ValueError(f"{spec['name']}: PIC base drift {base:#x}")

        selectors = {}
        for cell, (expected_slot, expected_name) in spec['selectors'].items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: selector cell {cell:#x} -> "
                                 f"{slot:#x}, expected {expected_slot:#x}")
            got = cstr(memory.word(slot))
            if got != expected_name:
                raise ValueError(f"{spec['name']}: selector cell drifted at "
                                 f"{cell:#x}: {got!r} != {expected_name!r}")
            selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'selector': got}

        classrefs = {}
        for cell, (expected_slot, expected_symbol) in spec['classrefs'].items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: classref cell {cell:#x} -> {slot:#x}")
            got = relocs.get(slot)
            if got != expected_symbol:
                raise ValueError(f"{spec['name']}: classref drifted at {cell:#x}: {got!r}")
            classrefs[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'class': got}

        for cell, (expected_slot, expected_name) in spec['imports'].items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: import cell {cell:#x} -> {slot:#x}")
            got = memory.imports.get(slot)
            if got != expected_name:
                raise ValueError(f"{spec['name']}: import drifted at {cell:#x}: {got!r}")
            selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'import': got}

        listed = {a for a, ins in rows.items() if re.match(r'^blx?\s', ins)}
        expected_sites = {site for site, *_ in spec['calls']}
        if listed != expected_sites:
            raise ValueError(f"{spec['name']}: call site set drifted: "
                             f"{sorted(listed ^ expected_sites)}")
        calls = []
        for site, route, note in spec['calls']:
            if rows[site] != route:
                raise ValueError(f"{spec['name']}: call route drifted at "
                                 f"{site:#x}: {rows[site]!r} != {route!r}")
            target = None
            if route.startswith('bl '):
                target = bl_target(site, memory.word(site))
                if target != WORLD_INDEX_AT_POSITION:
                    raise ValueError(f"{spec['name']}: bl target drifted at "
                                     f"{site:#x}: {target:#x}")
            calls.append({'site': f'0x{site:08x}', 'route': route,
                          'callee': f'0x{target:08x}' if target else None,
                          'note': note})

        listed_branches = {(a, m.group(1), int(m.group(2), 16))
                           for a, ins in rows.items()
                           for m in [re.match(r'^(b\w*)\s+(0x[0-9a-f]+)', ins)]
                           if m and m.group(1) not in ('bl', 'blx')}
        expected_branches = {(a, mn, d) for a, mn, d in spec['branches']}
        if listed_branches != expected_branches:
            raise ValueError(f"{spec['name']}: branch set drifted: "
                             f"{sorted(listed_branches ^ expected_branches)}")

        for address, expected_text in spec['instructions']:
            if rows.get(address) != expected_text:
                raise ValueError(f"{spec['name']}: instruction drifted at "
                                 f"{address:#x}: {rows.get(address)!r} != "
                                 f"{expected_text!r}")

        methods.append({
            'name': spec['name'],
            'method': spec['method'],
            'types': spec['types'],
            'imp': f"0x{spec['start']:08x}",
            'boundary_end': f"0x{spec['end']:08x}",
            'boundary': spec['boundary'],
            'verified_words': words,
            'pic_base': f'0x{base:08x}',
            'selectors': selectors,
            'classrefs': classrefs,
            'calls': calls,
            'branches': [{'address': f'0x{a:08x}', 'mnemonic': mn,
                          'destination': f'0x{d:08x}'}
                         for a, mn, d in spec['branches']],
            'semantics': spec['semantics'],
        })

    return {
        'schema': 1,
        'elf_sha256': sha,
        'batch': 'WorldHelper per-tile sunlight update pair',
        'claim': ('static bounded-body maps with per-instruction anchors; the '
                  'recursive sunlight engines, World/WorldHelper internals and '
                  'runtime values are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'worldhelper_sunlight.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale worldhelper_sunlight.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
