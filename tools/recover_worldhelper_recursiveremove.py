#!/usr/bin/env python3
"""Hash-gated recovery of WorldHelper +[recursivelyRemoveAllSunLightWithList:…].

One class body from the pinned original libApplication.so (1.7.6,
armeabi-v7a, SHA-256 733d8210…b94c7):

  +[WorldHelper recursivelyRemoveAllSunLightWithList:openIndices:
    lightWasRemovedList:removeIndices:world:minx:maxX:]
    0x00a1bd10 .. 0x00a1c680 (604 words)

The single-step removal engine of the sunlight system: it pops one work item,
clears the tile's sunlight byte, re-records the removal, and re-enqueues lit
neighbours. The caller (+[updateSunLightRemovedForTile:atPos:world:], already
mapped) drives it in a drain loop; the updater twin
(recursivelyUpdateSunLightWithList:…) and the broader algorithm are NOT
mapped here.

Every instruction word is re-verified against the pinned ELF; PIC base,
selector cells, the NSNumber class relocation, the objc_msgSend import, all
40 call sites (16 direct bl with pinned targets), all 51 branches and key
instructions are anchored; the tool refuses to emit on any drift.
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
GET_WORLD_POS = 0x00A15518       # _Z24getWorldPosForWorldIndexiPiS_P5World
TILE_AT = 0x00A12F24             # _Z25tileAtWorldPositionLoadediiP5World
AIR_OR_SNOW = 0x00A12760         # _Z15tileIsAirOrSnowP4Tile
RECALC_DRAW = 0x00A18F68         # _Z35recalculateDrawBlockLightingForTileiiP9MacroTileP5World
WORLD_INDEX = 0x00A156A8         # _Z25worldIndexAtWorldPositioniiP5World

SPEC = dict(
    name='recursivelyRemoveAllSunLightWithList',
    method=('WorldHelper +[recursivelyRemoveAllSunLightWithList:openIndices:'
            'lightWasRemovedList:removeIndices:world:minx:maxX:]'),
    types='v36@0:4@8@12@16@20@24i28i32',
    start=0x00A1BD10, end=0x00A1C680,
    disasm='disasm_worldhelper_recursiveremovesunlight.txt',
    base_add=0x00A1BD20, base_literal=0x00A1C67C,
    boundary=('no own ARM.exidx entry; closed by the next method IMP '
              '0x00a1c680 (+[updateSunLightRemovedForTile:atPos:world:])'),
    selectors={
        0x00A1C654: (0x00E84C88, 'removeIndex:'),
        0x00A1C658: (0x00E84C84, 'removeObjectAtIndex:'),
        0x00A1C65C: (0x00E84C80, 'intValue'),
        0x00A1C660: (0x00E84C7C, 'objectAtIndex:'),
        0x00A1C664: (0x00E84C9C, 'addIndex:'),
        0x00A1C668: (0x00E84C98, 'addObject:'),
        0x00A1C66C: (0x00E84C94, 'numberWithInt:'),
        0x00A1C674: (0x00E84C70, 'macroTiles'),
        0x00A1C678: (0x00E84C90, 'containsIndex:'),
    },
    classrefs={0x00A1C670: (0x00E8AE74, 'OBJC_CLASS_$_NSNumber')},
    imports={0x00A1C650: (MSGSEND_GOT_SLOT, 'objc_msgSend')},
    calls=[
        (0x00A1BDEC, 'blx r3', None, "objc_msgSend: [list objectAtIndex:0]"),
        (0x00A1BDFC, 'blx r2', None, "objc_msgSend: [obj intValue] -> idx"),
        (0x00A1BE18, 'blx r3', None, "objc_msgSend: [list removeObjectAtIndex:0]"),
        (0x00A1BE30, 'blx r3', None, "objc_msgSend: [openIndices removeIndex:idx]"),
        (0x00A1BE50, 'bl sym.getWorldPosForWorldIndex_int__int__int__World_', GET_WORLD_POS,
         'getWorldPosForWorldIndex(idx, &x, &y, world)'),
        (0x00A1BE60, 'bl sym.tileAtWorldPositionLoaded_int__int__World_', TILE_AT,
         'tileAtWorldPositionLoaded(x, y, world) -> tile'),
        (0x00A1BE7C, 'bl sym.tileIsAirOrSnow_Tile_', AIR_OR_SNOW,
         'tileIsAirOrSnow(tile)'),
        (0x00A1BF0C, 'blx r2', None, "objc_msgSend: [world macroTiles]"),
        (0x00A1BF28, 'bl sym.recalculateDrawBlockLightingForTile_int__int__MacroTile__World_',
         RECALC_DRAW, 'recalculateDrawBlockLightingForTile(x, y, macroTile, world)'),
        (0x00A1BF94, 'blx r4', None,
         "objc_msgSend: [NSNumber numberWithInt:idx] (lightWasRemovedList)"),
        (0x00A1BFB4, 'blx r3', None, "objc_msgSend: [lightWasRemovedList addObject:N]"),
        (0x00A1BFCC, 'blx r3', None, "objc_msgSend: [removeIndices addIndex:idx]"),
        (0x00A1BFE0, 'bl sym.tileAtWorldPositionLoaded_int__int__World_', TILE_AT,
         'y+1 neighbour tile'),
        (0x00A1C020, 'bl sym.tileIsAirOrSnow_Tile_', AIR_OR_SNOW, 'y+1 neighbour air/snow'),
        (0x00A1C060, 'bl sym.worldIndexAtWorldPosition_int__int__World_', WORLD_INDEX,
         'y+1 neighbour index'),
        (0x00A1C0A4, 'blx r3', None, 'y+1: [openIndices containsIndex:nidx]'),
        (0x00A1C11C, 'blx r4', None, 'y+1: [NSNumber numberWithInt:nidx]'),
        (0x00A1C13C, 'blx r3', None, 'y+1: [list addObject:N]'),
        (0x00A1C154, 'blx r3', None, 'y+1: [openIndices addIndex:nidx]'),
        (0x00A1C170, 'bl sym.tileAtWorldPositionLoaded_int__int__World_', TILE_AT,
         'y-1 neighbour tile'),
        (0x00A1C1B0, 'bl sym.tileIsAirOrSnow_Tile_', AIR_OR_SNOW, 'y-1 neighbour air/snow'),
        (0x00A1C1F0, 'bl sym.worldIndexAtWorldPosition_int__int__World_', WORLD_INDEX,
         'y-1 neighbour index'),
        (0x00A1C234, 'blx r3', None, 'y-1: [openIndices containsIndex:nidx]'),
        (0x00A1C2AC, 'blx r4', None, 'y-1: [NSNumber numberWithInt:nidx]'),
        (0x00A1C2CC, 'blx r3', None, 'y-1: [list addObject:N]'),
        (0x00A1C2E4, 'blx r3', None, 'y-1: [openIndices addIndex:nidx]'),
        (0x00A1C314, 'bl sym.tileAtWorldPositionLoaded_int__int__World_', TILE_AT,
         'x+1 neighbour tile (guarded x+1 < maxX)'),
        (0x00A1C354, 'bl sym.tileIsAirOrSnow_Tile_', AIR_OR_SNOW, 'x+1 neighbour air/snow'),
        (0x00A1C394, 'bl sym.worldIndexAtWorldPosition_int__int__World_', WORLD_INDEX,
         'x+1 neighbour index'),
        (0x00A1C3D8, 'blx r3', None, 'x+1: [openIndices containsIndex:nidx]'),
        (0x00A1C450, 'blx r4', None, 'x+1: [NSNumber numberWithInt:nidx]'),
        (0x00A1C470, 'blx r3', None, 'x+1: [list addObject:N]'),
        (0x00A1C488, 'blx r3', None, 'x+1: [openIndices addIndex:nidx]'),
        (0x00A1C4BC, 'bl sym.tileAtWorldPositionLoaded_int__int__World_', TILE_AT,
         'x-1 neighbour tile (guarded x-1 >= minx)'),
        (0x00A1C4FC, 'bl sym.tileIsAirOrSnow_Tile_', AIR_OR_SNOW, 'x-1 neighbour air/snow'),
        (0x00A1C53C, 'bl sym.worldIndexAtWorldPosition_int__int__World_', WORLD_INDEX,
         'x-1 neighbour index'),
        (0x00A1C580, 'blx r3', None, 'x-1: [openIndices containsIndex:nidx]'),
        (0x00A1C5F8, 'blx r4', None, 'x-1: [NSNumber numberWithInt:nidx]'),
        (0x00A1C618, 'blx r3', None, 'x-1: [list addObject:N]'),
        (0x00A1C630, 'blx r3', None, 'x-1: [openIndices addIndex:nidx]'),
    ],
    branches=[
        (0x00A1BE74, 'beq', 0x00A1C648),
        (0x00A1BE88, 'beq', 0x00A1BEAC),
        (0x00A1BE98, 'beq', 0x00A1C648),
        (0x00A1BEA8, 'beq', 0x00A1C648),
        (0x00A1BEC0, 'beq', 0x00A1C644),
        (0x00A1BFF4, 'beq', 0x00A1C160),
        (0x00A1C004, 'beq', 0x00A1C15C),
        (0x00A1C018, 'bgt', 0x00A1C15C),
        (0x00A1C02C, 'beq', 0x00A1C050),
        (0x00A1C03C, 'beq', 0x00A1C15C),
        (0x00A1C04C, 'beq', 0x00A1C15C),
        (0x00A1C070, 'blt', 0x00A1C158),
        (0x00A1C0B0, 'bne', 0x00A1C158),
        (0x00A1C158, 'b', 0x00A1C15C),
        (0x00A1C15C, 'b', 0x00A1C160),
        (0x00A1C184, 'beq', 0x00A1C2F0),
        (0x00A1C194, 'beq', 0x00A1C2EC),
        (0x00A1C1A8, 'bgt', 0x00A1C2EC),
        (0x00A1C1BC, 'beq', 0x00A1C1E0),
        (0x00A1C1CC, 'beq', 0x00A1C2EC),
        (0x00A1C1DC, 'beq', 0x00A1C2EC),
        (0x00A1C200, 'blt', 0x00A1C2E8),
        (0x00A1C240, 'bne', 0x00A1C2E8),
        (0x00A1C2E8, 'b', 0x00A1C2EC),
        (0x00A1C2EC, 'b', 0x00A1C2F0),
        (0x00A1C300, 'bge', 0x00A1C498),
        (0x00A1C328, 'beq', 0x00A1C494),
        (0x00A1C338, 'beq', 0x00A1C490),
        (0x00A1C34C, 'bgt', 0x00A1C490),
        (0x00A1C360, 'beq', 0x00A1C384),
        (0x00A1C370, 'beq', 0x00A1C490),
        (0x00A1C380, 'beq', 0x00A1C490),
        (0x00A1C3A4, 'blt', 0x00A1C48C),
        (0x00A1C3E4, 'bne', 0x00A1C48C),
        (0x00A1C48C, 'b', 0x00A1C490),
        (0x00A1C490, 'b', 0x00A1C494),
        (0x00A1C494, 'b', 0x00A1C498),
        (0x00A1C4A8, 'blt', 0x00A1C640),
        (0x00A1C4D0, 'beq', 0x00A1C63C),
        (0x00A1C4E0, 'beq', 0x00A1C638),
        (0x00A1C4F4, 'bgt', 0x00A1C638),
        (0x00A1C508, 'beq', 0x00A1C52C),
        (0x00A1C518, 'beq', 0x00A1C638),
        (0x00A1C528, 'beq', 0x00A1C638),
        (0x00A1C54C, 'blt', 0x00A1C634),
        (0x00A1C58C, 'bne', 0x00A1C634),
        (0x00A1C634, 'b', 0x00A1C638),
        (0x00A1C638, 'b', 0x00A1C63C),
        (0x00A1C63C, 'b', 0x00A1C640),
        (0x00A1C640, 'b', 0x00A1C644),
        (0x00A1C644, 'b', 0x00A1C648),
    ],
    instructions=[
        (0x00A1BE00, 'str r0, [fp, -0x44]'),
        (0x00A1BED8, 'movw r3, 0'),
        (0x00A1BEE0, 'strb r3, [ip, 7]'),
        (0x00A1BFD8, 'add r1, r1, 1'),
        (0x00A1C014, 'cmp r0, r1'),
        (0x00A1C168, 'sub r1, r1, 1'),
        (0x00A1C2F4, 'add r0, r0, 1'),
        (0x00A1C49C, 'sub r0, r0, 1'),
    ],
    semantics=(
        'Single-step work item: obj = [list objectAtIndex:0]; idx = [obj intValue]; '
        '[list removeObjectAtIndex:0]; [openIndices removeIndex:idx]; '
        'x = 0; y = 0; getWorldPosForWorldIndex(idx, &x, &y, world); '
        'tile = tileAtWorldPositionLoaded(x, y, world); '
        'if (tile == 0) return; '
        'if (tileIsAirOrSnow(tile) && (tile[1] == 2 || tile[1] == 3)) return; '
        'lvl = tile[7]; if (lvl == 0) return; '
        'tile[7] = 0; mt = [world macroTiles]; '
        'recalculateDrawBlockLightingForTile(x, y, mt, world); '
        '[lightWasRemovedList addObject:[NSNumber numberWithInt:idx]]; '
        '[removeIndices addIndex:idx]; '
        'then four neighbour passes in the order y+1, y-1, x+1, x-1; for each '
        '(dx, dy): (x-neighbours only) skip when x+1 >= maxX (dx=+1) or '
        'x-1 < minx (dx=-1); tn = tileAtWorldPositionLoaded(x+dx, y+dy, world); '
        'skip if !tn; skip if tn[7] == 0 or tn[7] > lvl (level monotonicity: '
        'only tiles lit at or below the removed level are swept); skip if '
        'tileIsAirOrSnow(tn) && tn[1] in {2,3}; nidx = '
        'worldIndexAtWorldPosition(x+dx, y+dy, world); skip if nidx < 0 or '
        '[openIndices containsIndex:nidx]; else [list addObject:'
        '[NSNumber numberWithInt:nidx]] and [openIndices addIndex:nidx]. '
        'Current-tile aborts (tile == nil, air/snow with solid walls, lvl == 0) '
        'return immediately without examining neighbours; neighbour aborts '
        'fall through to the next neighbour. Exactly one work item per call — '
        'the caller drain loop re-invokes until the list empties.'),
)


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

    spec = SPEC
    text = (NATIVE / spec['disasm']).read_text()
    words = verify_disassembly(memory, text, spec['start'], spec['end'])
    rows = {}
    for m in re.finditer(r'\b(0x[0-9a-f]{8})\s+[0-9a-f]{8}\s+(.*)', text):
        rows[int(m.group(1), 16)] = m.group(2).split(';')[0].strip()

    base = (spec['base_add'] + 8 + signed(memory.word(spec['base_literal']))) & 0xffffffff
    if base != EXPECTED_BASE:
        raise ValueError(f'PIC base drift {base:#x}')

    selectors = {}
    for cell, (expected_slot, expected_name) in spec['selectors'].items():
        slot = (base + signed(memory.word(cell))) & 0xffffffff
        if slot != expected_slot:
            raise ValueError(f'selector cell {cell:#x} -> {slot:#x}, expected {expected_slot:#x}')
        got = cstr(memory.word(slot))
        if got != expected_name:
            raise ValueError(f'selector cell drifted at {cell:#x}: {got!r} != {expected_name!r}')
        selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'selector': got}

    classrefs = {}
    for cell, (expected_slot, expected_symbol) in spec['classrefs'].items():
        slot = (base + signed(memory.word(cell))) & 0xffffffff
        if slot != expected_slot:
            raise ValueError(f'classref cell {cell:#x} -> {slot:#x}')
        got = relocs.get(slot)
        if got != expected_symbol:
            raise ValueError(f'classref drifted at {cell:#x}: {got!r}')
        classrefs[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'class': got}

    for cell, (expected_slot, expected_name) in spec['imports'].items():
        slot = (base + signed(memory.word(cell))) & 0xffffffff
        if slot != expected_slot:
            raise ValueError(f'import cell {cell:#x} -> {slot:#x}')
        got = memory.imports.get(slot)
        if got != expected_name:
            raise ValueError(f'import drifted at {cell:#x}: {got!r}')
        selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'import': got}

    listed = {a for a, ins in rows.items() if re.match(r'^blx?\s', ins)}
    expected_sites = {site for site, *_ in spec['calls']}
    if listed != expected_sites:
        raise ValueError(f'call site set drifted: {sorted(listed ^ expected_sites)}')
    calls = []
    for site, route, target, note in spec['calls']:
        if rows[site] != route:
            raise ValueError(f'call route drifted at {site:#x}: {rows[site]!r} != {route!r}')
        got_target = None
        if route.startswith('bl '):
            got_target = bl_target(site, memory.word(site))
            if got_target != target:
                raise ValueError(f'bl target drifted at {site:#x}: {got_target:#x} != {target:#x}')
        calls.append({'site': f'0x{site:08x}', 'route': route,
                      'callee': f'0x{got_target:08x}' if got_target else None,
                      'note': note})

    listed_branches = {(a, m.group(1), int(m.group(2), 16))
                       for a, ins in rows.items()
                       for m in [re.match(r'^(b\w*)\s+(0x[0-9a-f]+)', ins)]
                       if m and m.group(1) not in ('bl', 'blx')}
    expected_branches = {(a, mn, d) for a, mn, d in spec['branches']}
    if listed_branches != expected_branches:
        raise ValueError(f'branch set drifted: {sorted(listed_branches ^ expected_branches)}')

    for address, expected_text in spec['instructions']:
        if rows.get(address) != expected_text:
            raise ValueError(f'instruction drifted at {address:#x}: '
                             f'{rows.get(address)!r} != {expected_text!r}')

    method = {
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
    }
    return {
        'schema': 1,
        'elf_sha256': sha,
        'batch': 'WorldHelper recursivelyRemoveAllSunLightWithList: (single-step removal engine)',
        'claim': ('static bounded-body map with per-instruction anchors; the '
                  'updater twin, Tile/MacroTile internals and runtime values '
                  'are outside this body'),
        'classes': [method],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'worldhelper_recursiveremove.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale worldhelper_recursiveremove.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
