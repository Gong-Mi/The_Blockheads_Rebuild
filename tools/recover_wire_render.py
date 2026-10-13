#!/usr/bin/env python3
"""Hash-gated recovery of the Wire render trio.

3 bodies, 2861 instruction words total, from the pinned original libApplication.so (1.7.6, armeabi-v7a):
draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld: (138w, frame canonicaliser),
staticGeometryDrawCubeCount (529w, config/solid group counting), addDrawCubeData:fromIndex: (2194w, fillBuffer: draw-cube builder).
Every instruction word is re-verified; tool refuses to emit on drift.
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

ROUTE_TARGETS = {
    'bl 0x9549b8': 0X009549B8,
    'bl loc.imp.objc_msgSend': 0X001C281C,
    'bl method.Vector2.operator_float__': 0X004BDAAC,
    'bl sym.texCoordsForImageIndex_int_': 0X004D6820,
}

SPECS = [
    dict(
        name='w_draw',
        method='Wire -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        types='v156@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76i140i144i148i152',
        start=9769208,
        end=9769760,
        disasm='disasm_wire_draw.txt',
        base_add=None,
        base_literal=None,
        boundary='consecutive IMPs: [freeblockCreationItemType] follows at 0x00951320',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9769208, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9769220, 'bic sp, sp, 0xf'), (9769224, 'vmov s0, r2'), (9769756, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('Argument-frame canonicaliser only: repacks the full incoming argument layout - self/selector, float pinchScale, the camera ints and both _GLKMatrix4 16-float blocks - into a fixed local frame layout and returns. No call sites, no branches, no ivar/selector cells in this bounded body; the GL submission path is not inside it.'),
        calls=[],
        branches=[],
    ),
    dict(
        name='w_sgcdc',
        method='Wire -[staticGeometryDrawCubeCount]',
        types='i8@0:4',
        start=9772844,
        end=9774960,
        disasm='disasm_wire_staticgeometrydrawcubecount.txt',
        base_add=9772852,
        base_literal=9774956,
        boundary='consecutive IMPs: [addDrawCubeData:fromIndex:] follows at 0x00952770',
        selectors={},
        imports={},
        ivars={9774948: (17163000, 'OBJC_IVAR_$_Wire.currentConfiguration', 60), 9774952: (17163004, 'OBJC_IVAR_$_Wire.currentSolidConfiguration', 64)},
        classes={},
        instructions=[(9772844, 'sub sp, sp, 0x10'), (9773044, 'cmp r0, 5'), (9773056, 'add r0, r0, 1'), (9774944, 'bx lr')],
        semantics=('Counts the static draw cubes this wire needs: +1 for each of 6 orientation groups hit by currentConfiguration@60 - {1,2,3,4,5}, {1,2,6,7,8}, {7,10,12}, {8,9,11}, {4,9,10}, {5,11,12}; then +1 for each of 4 solid groups hit by currentSolidConfiguration@64 - {2,4,5,6,9,12,14,16}, {2,4,5,6,10,11,13,17}, {2,5,7,8,9,10,11,12}, {2,6,7,9,10,13,14,15}; returns the total (0..10) - the exact number of fillBuffer: records addDrawCubeData:fromIndex: appends.'),
        calls=[],
        branches=[(9772904, 'beq', 9773052), (9772940, 'beq', 9773052), (9772976, 'beq', 9773052), (9773012, 'beq', 9773052), (9773048, 'bne', 9773064), (9773096, 'beq', 9773244), (9773132, 'beq', 9773244), (9773168, 'beq', 9773244), (9773204, 'beq', 9773244), (9773240, 'bne', 9773256), (9773288, 'beq', 9773364), (9773324, 'beq', 9773364), (9773360, 'bne', 9773376), (9773408, 'beq', 9773484), (9773444, 'beq', 9773484), (9773480, 'bne', 9773496), (9773528, 'beq', 9773604), (9773564, 'beq', 9773604), (9773600, 'bne', 9773616), (9773648, 'beq', 9773724), (9773684, 'beq', 9773724), (9773720, 'bne', 9773736), (9773768, 'beq', 9774024), (9773804, 'beq', 9774024), (9773840, 'beq', 9774024), (9773876, 'beq', 9774024), (9773912, 'beq', 9774024), (9773948, 'beq', 9774024), (9773984, 'beq', 9774024), (9774020, 'bne', 9774036), (9774068, 'beq', 9774324), (9774104, 'beq', 9774324), (9774140, 'beq', 9774324), (9774176, 'beq', 9774324), (9774212, 'beq', 9774324), (9774248, 'beq', 9774324), (9774284, 'beq', 9774324), (9774320, 'bne', 9774336), (9774368, 'beq', 9774624), (9774404, 'beq', 9774624), (9774440, 'beq', 9774624), (9774476, 'beq', 9774624), (9774512, 'beq', 9774624), (9774548, 'beq', 9774624), (9774584, 'beq', 9774624), (9774620, 'bne', 9774636), (9774668, 'beq', 9774924), (9774704, 'beq', 9774924), (9774740, 'beq', 9774924), (9774776, 'beq', 9774924), (9774812, 'beq', 9774924), (9774848, 'beq', 9774924), (9774884, 'beq', 9774924), (9774920, 'bne', 9774936)],
    ),
    dict(
        name='w_addcube',
        method='Wire -[addDrawCubeData:fromIndex:]',
        types='i16@0:4^f8i12',
        start=9774960,
        end=9783736,
        disasm='disasm_wire_adddrawcubedata.txt',
        base_add=9774988,
        base_literal=9775068,
        boundary='body 0x00952770..0x009549b8; vector-builder helper 0x009549b8..0x00954a2c (IMP gap) excluded; trailing pool 0x0095498c.. onward inside bound)',
        selectors={9775108: (15219308, 'fillBuffer:fromIndex:matrix:width:height:depth:centerX:centerY:centerZ:topMinS:topMaxS:topMinT:topMaxT:sideMinS:sideMaxS:sideMinT:sideMaxT:macroWorldX:macroWorldY:'), 9783688: (15219308, 'fillBuffer:fromIndex:matrix:width:height:depth:centerX:centerY:centerZ:topMinS:topMaxS:topMinT:topMaxT:sideMinS:sideMaxS:sideMinT:sideMaxT:macroWorldX:macroWorldY:'), 9783716: (15219308, 'fillBuffer:fromIndex:matrix:width:height:depth:centerX:centerY:centerZ:topMinS:topMaxS:topMinT:topMaxT:sideMinS:sideMaxS:sideMinT:sideMaxT:macroWorldX:macroWorldY:')},
        imports={},
        ivars={9775072: (17163004, 'OBJC_IVAR_$_Wire.currentSolidConfiguration', 64), 9775080: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24), 9775084: (17163000, 'OBJC_IVAR_$_Wire.currentConfiguration', 60), 9775104: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12), 9778444: (17163000, 'OBJC_IVAR_$_Wire.currentConfiguration', 60), 9779960: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12), 9783704: (17163004, 'OBJC_IVAR_$_Wire.currentSolidConfiguration', 64), 9783712: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12)},
        classes={9775088: (15248308, 'OBJC_CLASS_$_DrawCube'), 9778448: (15248308, 'OBJC_CLASS_$_DrawCube'), 9783708: (15248308, 'OBJC_CLASS_$_DrawCube')},
        instructions=[(9774960, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9774968, 'vpush {d8}'), (9775276, 'bl 0x9549b8'), (9775288, 'bl sym.texCoordsForImageIndex_int_'), (9775952, 'movt ip, 0x3d4c'), (9783684, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('Draw-cube builder: position = floatPos@24 (Vector2, via Vector2::operator float*()) with +5.0 y-lift and a z fold (-1.0f default; 0.0f when currentSolidConfiguration@64 == 0); vertex variants scale z by f64 constants 0.05 / 0.45 / 0.525; per-variant record float table 0.4f/0.5f/0.05f/1.0f/0.525f/1.525f; texture = texCoordsForImageIndex(0x70) (the wire texture); helper 0x9549b8 (IMP gap, out of body) builds the Vertex Vector; per matched configuration group (the same 6 config + 4 solid groups as staticGeometryDrawCubeCount) one record is staged (index = fromIndex + running count) and appended via [macroTileOwner fillBuffer:fromIndex:matrix:width:height:depth:centerX:centerY:centerZ:topMinS:topMaxS:topMinT:topMaxT:sideMinS:sideMaxS:sideMinT:sideMaxT:macroWorldX:macroWorldY:]; returns the i16 count of appended cubes.'),
        calls=[(9775196, 'bl method.Vector2.operator_float__'), (9775232, 'bl method.Vector2.operator_float__'), (9775276, 'bl 0x9549b8'), (9775288, 'bl sym.texCoordsForImageIndex_int_'), (9776080, 'bl loc.imp.objc_msgSend'), (9776868, 'bl loc.imp.objc_msgSend'), (9777648, 'bl loc.imp.objc_msgSend'), (9778400, 'bl loc.imp.objc_msgSend'), (9779180, 'bl loc.imp.objc_msgSend'), (9779920, 'bl loc.imp.objc_msgSend'), (9780872, 'bl loc.imp.objc_msgSend'), (9781796, 'bl loc.imp.objc_msgSend'), (9782732, 'bl loc.imp.objc_msgSend'), (9783656, 'bl loc.imp.objc_msgSend')],
        branches=[(9775060, 'beq', 9775172), (9775064, 'b', 9775116), (9775148, 'beq', 9775172), (9775324, 'beq', 9775472), (9775360, 'beq', 9775472), (9775396, 'beq', 9775472), (9775432, 'beq', 9775472), (9775468, 'bne', 9776096), (9776128, 'beq', 9776276), (9776164, 'beq', 9776276), (9776200, 'beq', 9776276), (9776236, 'beq', 9776276), (9776272, 'bne', 9776916), (9776884, 'b', 9776916), (9776948, 'beq', 9777024), (9776984, 'beq', 9777024), (9777020, 'bne', 9777664), (9777696, 'beq', 9777772), (9777732, 'beq', 9777772), (9777768, 'bne', 9778456), (9778416, 'b', 9778456), (9778488, 'beq', 9778564), (9778524, 'beq', 9778564), (9778560, 'bne', 9779196), (9779228, 'beq', 9779304), (9779264, 'beq', 9779304), (9779300, 'bne', 9779964), (9779936, 'b', 9779964), (9779996, 'beq', 9780252), (9780032, 'beq', 9780252), (9780068, 'beq', 9780252), (9780104, 'beq', 9780252), (9780140, 'beq', 9780252), (9780176, 'beq', 9780252), (9780212, 'beq', 9780252), (9780248, 'bne', 9780888), (9780920, 'beq', 9781176), (9780956, 'beq', 9781176), (9780992, 'beq', 9781176), (9781028, 'beq', 9781176), (9781064, 'beq', 9781176), (9781100, 'beq', 9781176), (9781136, 'beq', 9781176), (9781172, 'bne', 9781824), (9781812, 'b', 9781824), (9781856, 'beq', 9782112), (9781892, 'beq', 9782112), (9781928, 'beq', 9782112), (9781964, 'beq', 9782112), (9782000, 'beq', 9782112), (9782036, 'beq', 9782112), (9782072, 'beq', 9782112), (9782108, 'bne', 9782748), (9782780, 'beq', 9783036), (9782816, 'beq', 9783036), (9782852, 'beq', 9783036), (9782888, 'beq', 9783036), (9782924, 'beq', 9783036), (9782960, 'beq', 9783036), (9782996, 'beq', 9783036), (9783032, 'bne', 9783672)],
    ),]

def signed(v: int) -> int:
    return v - (1 << 32) if v & 0x80000000 else v


def bl_target(site: int, word: int) -> int:
    if word >> 24 != 0xEB:
        raise ValueError(f'{site:#x} is not ARM bl')
    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 1 << 24
    return (site + 8 + (imm << 2)) & 0xffffffff


def recover(path: Path) -> dict:
    data = path.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    if sha != EXPECTED_SHA:
        raise ValueError('unsupported ELF SHA-256; fixed-IMP analysis requires pinned original')
    memory = ELFMemory(path)

    def cstr(addr):
        off = memory.offset(addr, 1)
        if off is None:
            return None
        end = data.find(b'\0', off, off + 256)
        return data[off:end].decode('utf-8', 'replace') if end >= 0 else None

    dynsym = {}
    for sec in ELFFile(io.BytesIO(data)).iter_sections():
        if sec.name == '.dynsym':
            for s in sec.iter_symbols():
                if s['st_value']:
                    dynsym.setdefault(s['st_value'], s.name)

    methods = []
    for spec in SPECS:
        text = (NATIVE / spec['disasm']).read_text()
        words = verify_disassembly(memory, text, spec['start'], spec['end'])
        rows = {}
        for mm in re.finditer(r'\b(0x[0-9a-f]{8})\s+[0-9a-f]{8}\s+(.*)', text):
            rows[int(mm.group(1), 16)] = mm.group(2).split(';')[0].strip()

        base = None
        if spec['base_add'] is not None:
            base = (spec['base_add'] + 8 + signed(memory.word(spec['base_literal']))) & 0xffffffff
            if base != EXPECTED_BASE:
                raise ValueError(f"{spec['name']}: PIC base drift {base:#x}")

        selectors = {}
        for cell, (expected_slot, expected_name) in spec['selectors'].items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: selector cell {cell:#x} -> {slot:#x}")
            got = cstr(memory.word(slot))
            if got != expected_name:
                raise ValueError(f"{spec['name']}: selector drifted at {cell:#x}: {got!r}")
            selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'selector': got}

        ivars = {}
        for cell, (expected_slot, expected_symbol, expected_offset) in spec['ivars'].items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: ivar cell {cell:#x} -> {slot:#x}")
            entry = memory.word(slot)
            symbol = dynsym.get(entry, '')
            offset = memory.word(entry)
            if symbol != expected_symbol or offset != expected_offset:
                raise ValueError(f"{spec['name']}: ivar {cell:#x} drifted: {symbol!r}@{offset}")
            ivars[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'symbol': symbol, 'offset': offset}

        for cell, (expected_slot, expected_symbol) in spec.get('classes', {}).items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: class cell {cell:#x} -> {slot:#x}")
            entry = memory.word(slot)
            got = dynsym.get(entry, '')
            if got != expected_symbol:
                raise ValueError(f"{spec['name']}: class drifted at {cell:#x}: {got!r}")
            selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'class': got}

        for cell, (expected_slot, expected_name) in spec['imports'].items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: import cell {cell:#x} -> {slot:#x}")
            got = memory.imports.get(slot)
            if got != expected_name:
                raise ValueError(f"{spec['name']}: import drifted at {cell:#x}: {got!r}")
            selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'import': got}

        inrange = {a: ins for a, ins in rows.items() if spec['start'] <= a < spec['end']}
        listed = {a for a, ins in inrange.items() if re.match(r'^blx?\s', ins)}
        expected_sites = {site for site, _ in spec['calls']}
        if listed != expected_sites:
            raise ValueError(f"{spec['name']}: call set drifted: {sorted(listed ^ expected_sites)}")
        calls = []
        for site, route in spec['calls']:
            if rows[site] != route:
                raise ValueError(f"{spec['name']}: route drifted at {site:#x}: {rows[site]!r}")
            target = None
            if route.startswith('bl '):
                target = bl_target(site, memory.word(site))
                expected = ROUTE_TARGETS.get(route)
                if expected is None or target != expected:
                    raise ValueError(f"{spec['name']}: bl target drifted at {site:#x}: {target:#x}")
            calls.append({'site': f'0x{site:08x}', 'route': route,
                          'callee': f'0x{target:08x}' if target else None})

        listed_branches = {(a, m.group(1), int(m.group(2), 16))
                           for a, ins in inrange.items()
                           for m in [re.match(r'^(b\w*)\s+(0x[0-9a-f]+)', ins)]
                           if m and m.group(1) not in ('bl', 'blx')}
        expected_branches = {(a, mn, dest) for a, mn, dest in spec['branches']}
        if listed_branches != expected_branches:
            raise ValueError(f"{spec['name']}: branch set drifted: {sorted(listed_branches ^ expected_branches)}")

        for address, expected_text in spec['instructions']:
            if rows.get(address) != expected_text:
                raise ValueError(f"{spec['name']}: instruction drifted at {address:#x}: "
                                 f"{rows.get(address)!r} != {expected_text!r}")

        methods.append({
            'name': spec['name'],
            'method': spec['method'],
            'types': spec['types'],
            'imp': f"0x{spec['start']:08x}",
            'boundary_end': f"0x{spec['end']:08x}",
            'boundary': spec['boundary'],
            'verified_words': words,
            'pic_base': f'0x{base:08x}' if base else None,
            'selectors': selectors,
            'ivars': ivars,
            'calls': calls,
            'branches': [{'address': f'0x{a:08x}', 'mnemonic': mn,
                          'destination': f'0x{d:08x}'}
                         for a, mn, d in spec['branches']],
            'semantics': spec['semantics'],
        })

    return {
        'schema': 1,
        'elf_sha256': sha,
        'batch': 'Wire render trio: draw: (frame canonicaliser), staticGeometryDrawCubeCount (config/solid group counting), addDrawCubeData:fromIndex: (fillBuffer: draw-cube builder, 2194w)',
        'claim': ('static bounded-body maps with per-instruction anchors; '
                  'runtime values and the render consumers are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'wire_render.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale wire_render.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
