#!/usr/bin/env python3
"""Hash-gated recovery of the WorldTileLoader terrain column-height helpers.

Four bounded bodies from the pinned original libApplication.so (1.7.6,
armeabi-v7a, SHA-256 733d8210…b94c7):

  -[unmodifiedGroundLevelForX:]     0x00857a2c .. 0x00857bf8  (115 words)
  -[maxOfRockAndDirtHeightForX:]    0x00857bf8 .. 0x00857dc8  (116 words)
  -[lakeHeightForX:]                0x00857dc8 .. 0x00857f48  ( 96 words)
  -[getCloudHeightForX:]            0x00857340 .. 0x00857684  (209 words)

These are the per-column height queries the terrain pipeline consumes:
the height-array accessors (rock/dirt/lake) and the cloud-layer noise
composition.  They sit next to the already-recovered generator
(`getInitialRockAndDirtHeightforX:`, `faultOffsetForX:y:`,
`isCaveForX:y:faultOffset:`, `refineTerrain`).

Every instruction word is re-verified against the pinned ELF; PIC base,
selector cells, ivar cells, literal-pool constants, call sites and every
branch destination are anchored, and the tool refuses to emit on any drift.
Static bounded-body maps only — noise internals and runtime values are
outside these bodies.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import struct
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
MSGSEND_GOT_SLOT = 0x0105B7A0        # objc_msgSend import
MSGSEND_STUB = 0x001C281C            # loc.imp.objc_msgSend thunk
CLAMP = 0x004BE068                   # _Z5clampfff
LINEAR = 0x00582A14                  # _Z17linearInterpolatefff

# Anchor vocabulary: selector cells resolve to a slot holding the SEL string;
# ivar cells resolve to a slot holding an ivar-descriptor pointer; import
# cells to a GOT slot. All keyed by the pool cell, value = (slot, ...).

SPECS = [
    dict(
        name='unmodifiedGroundLevelForX',
        method='WorldTileLoader -[unmodifiedGroundLevelForX:]',
        types='i12@0:4i8',
        start=0x00857A2C, end=0x00857BF8,
        disasm='disasm_worldtileloader_unmodifiedgroundlevel.txt',
        base_add=0x00857A3C, base_literal=0x00857BF4,
        boundary=('no own ARM.exidx entry; closed by the next method IMP '
                  '0x00857bf8 (-[maxOfRockAndDirtHeightForX:])'),
        selectors={
            0x00857BE8: (0x00E82438, 'getRockAndDirtHeightforX:rockHeight:dirtHeight:'),
            0x00857BEC: (0x00E82404, 'faultOffsetForX:y:'),
            0x00857BF0: (0x00E82408, 'isCaveForX:y:faultOffset:'),
        },
        imports={0x00857BE4: (MSGSEND_GOT_SLOT, 'objc_msgSend')},
        ivars={},
        constants=[],
        instructions=[
            (0x00857A40, 'sub ip, fp, 0x1c'),
            (0x00857A44, 'sub lr, fp, 0x20'),
            (0x00857A78, 'str lr, [sp]'),
            (0x00857A98, 'cmp r0, r1'),
            (0x00857B20, 'cmp r0, r1'),
            (0x00857B78, 'sxtb r0, r0'),
            (0x00857B94, 'movw r2, 0'),
            (0x00857B98, 'movne r2, 1'),
            (0x00857BA0, 'moveq r0, 0'),
            (0x00857BA4, 'add r0, r1, r0'),
            (0x00857BC8, 'strb r0, [sp, 0x1f]'),
        ],
        calls=[
            (0x00857A7C, 'blx r4',
             'objc_msgSend: [self getRockAndDirtHeightforX:x rockHeight:&fp-0x1c '
             'dirtHeight:&fp-0x20] (r3=fp-0x1c arg3, [sp]=fp-0x20 arg4)'),
            (0x00857B10, 'blx ip',
             'objc_msgSend: [self faultOffsetForX:x y:i] (r2=x arg1, r3=i arg2)'),
            (0x00857B74, 'blx ip',
             'objc_msgSend: [self isCaveForX:x y:i faultOffset:off] '
             '(r2=x, r3=i, [sp]=off)'),
        ],
        branches=[
            (0x00857A9C, 'bge', 0x00857AAC),
            (0x00857AA8, 'b', 0x00857AB4),
            (0x00857AD4, 'ble', 0x00857BD0),
            (0x00857B24, 'ble', 0x00857B34),
            (0x00857B30, 'b', 0x00857BD8),
            (0x00857B80, 'bne', 0x00857BB0),
            (0x00857BAC, 'b', 0x00857BD8),
            (0x00857BB0, 'b', 0x00857BB4),
            (0x00857BCC, 'b', 0x00857ACC),
        ],
        semantics=(
            'i0 = max(rock, dirt) from [self getRockAndDirtHeightforX:x ...]; '
            'flag = 0; while (i > 0) { off = [self faultOffsetForX:x y:i]; '
            'if (i > rock) return i; '
            'if ([self isCaveForX:x y:i faultOffset:off]) { flag = 1; i--; continue; } '
            'return i + (flag != 0 ? 1 : 0); } return 0. '
            'Both out-parameters are ints (array lookups upstream); when '
            'dirt > rock the first iteration returns immediately with dirt; '
            'otherwise the loop scans downward from the rock line while '
            'isCave stays true and returns the first non-cave level, +1 when '
            'it entered a cave at least once, else the plain level.'),
    ),
    dict(
        name='maxOfRockAndDirtHeightForX',
        method='WorldTileLoader -[maxOfRockAndDirtHeightForX:]',
        types='i12@0:4i8',
        start=0x00857BF8, end=0x00857DC8,
        disasm='disasm_worldtileloader_maxofrockanddirt.txt',
        base_add=0x00857C2C, base_literal=0x00857DB8,
        boundary=('no own ARM.exidx entry; closed by the next method IMP '
                  '0x00857dc8 (-[lakeHeightForX:])'),
        selectors={
            0x00857DB0: (0x00E823A8, 'worldWidthMacro'),
        },
        imports={},
        ivars={
            0x00857DA8: (0x0105DD4C, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
            0x00857DBC: (0x0105DD60, 'OBJC_IVAR_$_WorldTileLoader.rockHeights', 96),
            0x00857DC4: (0x0105DD5C, 'OBJC_IVAR_$_WorldTileLoader.dirtHeights', 92),
        },
        constants=[],
        instructions=[
            (0x00857C14, 'cmp r0, 0'),
            (0x00857C58, 'lsl r0, r0, 5'),
            (0x00857C60, 'add r0, r2, r0'),
            (0x00857CBC, 'cmp r2, r0'),
            (0x00857D04, 'lsl r0, r0, 5'),
            (0x00857D0C, 'sub r0, r2, r0'),
            (0x00857D40, 'ldr r1, [r2, r1, lsl 2]'),
            (0x00857D64, 'ldr r1, [r1]'),
            (0x00857D74, 'cmp r1, r2'),
        ],
        calls=[
            (0x00857C50, 'bl loc.imp.objc_msgSend',
             'objc_msgSend: [world worldWidthMacro] (x < 0 path)'),
            (0x00857CAC, 'bl loc.imp.objc_msgSend',
             'objc_msgSend: [world worldWidthMacro] (x >= 0 path, compare)'),
            (0x00857CFC, 'bl loc.imp.objc_msgSend',
             'objc_msgSend: [world worldWidthMacro] (x > W path, subtract)'),
        ],
        branches=[
            (0x00857C18, 'bge', 0x00857C70),
            (0x00857C6C, 'b', 0x00857D1C),
            (0x00857CC4, 'ble', 0x00857D18),
            (0x00857D18, 'b', 0x00857D1C),
            (0x00857D7C, 'bge', 0x00857D8C),
            (0x00857D88, 'b', 0x00857D94),
        ],
        semantics=(
            'W = worldWidthMacro * 32 (lsl #5). if (x < 0) x += W; '
            'else if (x > W) x -= W (x == W is kept). '
            'rock = rockHeights[x]; dirt = dirtHeights[x]; '
            'return rock >= dirt ? rock : dirt (max, strict >= keeps rock '
            'on ties).'),
    ),
    dict(
        name='lakeHeightForX',
        method='WorldTileLoader -[lakeHeightForX:]',
        types='i12@0:4i8',
        start=0x00857DC8, end=0x00857F48,
        disasm='disasm_worldtileloader_lakeheight.txt',
        base_add=0x00857DFC, base_literal=0x00857F38,
        boundary=('no own ARM.exidx entry; closed by the next method IMP '
                  '0x00857f48 (-[isCaveForX:y:faultOffset:])'),
        selectors={
            0x00857F30: (0x00E823A8, 'worldWidthMacro'),
        },
        imports={},
        ivars={
            0x00857F28: (0x0105DD4C, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
            0x00857F3C: (0x0105DD64, 'OBJC_IVAR_$_WorldTileLoader.lakeHeights', 100),
        },
        constants=[],
        instructions=[
            (0x00857DE4, 'cmp r0, 0'),
            (0x00857E28, 'lsl r0, r0, 5'),
            (0x00857E30, 'add r0, r2, r0'),
            (0x00857E8C, 'cmp r2, r0'),
            (0x00857ED4, 'lsl r0, r0, 5'),
            (0x00857EDC, 'sub r0, r2, r0'),
            (0x00857F10, 'add r1, r2, r1, lsl 2'),
            (0x00857F14, 'ldr r1, [r1]'),
        ],
        calls=[
            (0x00857E20, 'bl loc.imp.objc_msgSend',
             'objc_msgSend: [world worldWidthMacro] (x < 0 path)'),
            (0x00857E7C, 'bl loc.imp.objc_msgSend',
             'objc_msgSend: [world worldWidthMacro] (x >= 0 path, compare)'),
            (0x00857ECC, 'bl loc.imp.objc_msgSend',
             'objc_msgSend: [world worldWidthMacro] (x > W path, subtract)'),
        ],
        branches=[
            (0x00857DE8, 'bge', 0x00857E40),
            (0x00857E3C, 'b', 0x00857EEC),
            (0x00857E94, 'ble', 0x00857EE8),
            (0x00857EE8, 'b', 0x00857EEC),
        ],
        semantics=(
            'W = worldWidthMacro * 32. if (x < 0) x += W; '
            'else if (x > W) x -= W (x == W is kept). '
            'return lakeHeights[x] (int array, lsl #2 index). '
            'Same wrap shape as maxOfRockAndDirtHeightForX:.'),
    ),
    dict(
        name='getCloudHeightForX',
        method='WorldTileLoader -[getCloudHeightForX:]',
        types='i12@0:4i8',
        start=0x00857340, end=0x00857684,
        disasm='disasm_worldtileloader_getcloudheight.txt',
        base_add=0x00857354, base_literal=0x00857680,
        boundary=('no own ARM.exidx entry; closed by the next method IMP '
                  '0x00857684 (-[limestoneFractionForX:y:faultOffset:])'),
        selectors={
            0x00857660: (0x00E82420, 'getX:Y:octaves:'),
            0x00857678: (0x00E823A8, 'worldWidthMacro'),
        },
        imports={0x0085765C: (MSGSEND_GOT_SLOT, 'objc_msgSend')},
        ivars={
            0x00857674: (0x0105DD88, 'OBJC_IVAR_$_WorldTileLoader.heightNoiseFunctionA', 16),
            0x00857668: (0x0105DD84, 'OBJC_IVAR_$_WorldTileLoader.heightNoiseFunctionB', 20),
            0x0085767C: (0x0105DD4C, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
        },
        constants=[
            (0x00857650, 'float', '42200000'),        # 40.0f
            (0x00857654, 'float', '42000000'),        # 32.0f
            (0x00857658, 'float', '00000000'),        # 0.0f
            (0x00857664, 'float', '3d4ccccd'),        # 0.05f
            (0x0085766C, 'float', '3d8f5c29'),        # 0.07f
            (0x00857670, 'float', '3dcccccd'),        # 0.1f
            (0x00857638, 'double', '3fc99999a0000000'),  # (double)0.2f
            (0x00857640, 'double', '3fe99999a0000000'),  # (double)0.8f
            (0x00857648, 'double', '3fd3333340000000'),  # (double)0.3f
        ],
        instructions=[
            (0x00857370, 'vmov.f64 d4, 7'),
            (0x00857398, 'vmov.f64 d6, 5'),
            (0x008573f8, 'vdiv.f32 s3, s11, s3'),
            (0x00857474, 'vdiv.f32 s0, s2, s0'),
            (0x00857498, 'vadd.f32 s0, s0, s2'),
            (0x008574cc, 'vmul.f64 d2, d2, d3'),
            (0x008574d4, 'vadd.f64 d2, d2, d4'),
            (0x008574fc, 'vadd.f32 s0, s0, s2'),
            (0x0085752c, 'vmul.f64 d2, d2, d3'),
            (0x00857530, 'vadd.f64 d2, d2, d3'),
            (0x00857558, 'vadd.f32 s0, s0, s2'),
            (0x0085758c, 'vmul.f64 d2, d2, d3'),
            (0x00857594, 'vadd.f64 d2, d2, d4'),
            (0x008575C4, 'vldr s0, [fp, -0x34]'),
            (0x008575DC, 'bl sym.linearInterpolate_float__float__float_'),
            (0x008575f8, 'vmov.f32 s14, 3'),
            (0x00857604, 'vmul.f32 s0, s0, s14'),
            (0x00857608, 'vmul.f32 s0, s0, s10'),
            (0x0085760c, 'vadd.f32 s0, s2, s0'),
            (0x00857610, 'vcvt.s32.f32 s0, s0'),
        ],
        calls=[
            (0x00857464, 'blx r5',
             'objc_msgSend: [world worldWidthMacro] -> q = x / 32.0f / W'),
            (0x008574C0, 'blx lr',
             'objc_msgSend: [heightNoiseFunctionA getX:q+0.1 Y:5.0 octaves:3]'),
            (0x00857520, 'blx lr',
             'objc_msgSend: [heightNoiseFunctionB getX:q+0.07 Y:5.0 octaves:3]'),
            (0x00857580, 'blx lr',
             'objc_msgSend: [heightNoiseFunctionB getX:q+0.05 Y:7.0 octaves:9]'),
            (0x008575B8, 'bl sym.clamp_float__float__float_',
             'clamp(w3, 0.0, 1.0)'),
            (0x008575DC, 'bl sym.linearInterpolate_float__float__float_',
             'linearInterpolate(w1, w2, clamp(w3,0,1))'),
        ],
        branches=[],
        semantics=(
            'q = (float)x / 32.0f / (float)[world worldWidthMacro]; '
            'n1 = [heightNoiseFunctionA getX:q+0.1 Y:5.0 octaves:3]; '
            'n2 = [heightNoiseFunctionB getX:q+0.07 Y:5.0 octaves:3]; '
            'n3 = [heightNoiseFunctionB getX:q+0.05 Y:7.0 octaves:9]; '
            'w1 = n1*0.3+5.0; w2 = n2*5.0+5.0; w3 = n3*0.8+0.2; '
            't = clamp(w3, 0.0, 1.0); '
            'return (int)(40.0f + linearInterpolate(w1, w2, t) * 3.0f * 32.0f). '
            'The 0.2/0.8/0.3 doubles are float-precision constants widened to '
            'double ((double)0.2f bit patterns), as in the recovered '
            'getInitialRockAndDirt constants family.'),
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


def load_rows(text: str) -> dict[int, str]:
    rows = {}
    for line in text.splitlines():
        m = re.search(r'\b(0x[0-9a-f]{8})\s+([0-9a-f]{8})\s+(.*)', line)
        if m:
            ins = m.group(3).split(';')[0].strip()
            rows[int(m.group(1), 16)] = ins
    return rows


def recover(path: Path) -> dict:
    data = path.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    if sha != EXPECTED_SHA:
        raise ValueError('unsupported ELF SHA-256; fixed-IMP analysis requires pinned original')
    memory = ELFMemory(path)
    elf = ELFFile(io.BytesIO(data))
    symbols = {}
    for section in elf.iter_sections():
        if section.name == '.dynsym':
            for s in section.iter_symbols():
                if s['st_value']:
                    symbols.setdefault(s['st_value'], s.name)

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
        rows = load_rows(text)

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

        for cell, (expected_slot, expected_name) in spec['imports'].items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: import cell {cell:#x} -> {slot:#x}")
            got = memory.imports.get(slot)
            if got != expected_name:
                raise ValueError(f"{spec['name']}: import drifted at {cell:#x}: {got!r}")
            selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'import': got}

        ivars = {}
        for cell, (expected_slot, expected_symbol, expected_offset) in spec['ivars'].items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: ivar cell {cell:#x} -> "
                                 f"{slot:#x}, expected {expected_slot:#x}")
            entry = memory.word(slot)
            symbol = symbols.get(entry, '')
            offset = memory.word(entry)
            if symbol != expected_symbol or offset != expected_offset:
                raise ValueError(f"{spec['name']}: ivar slot {slot:#x} drifted: "
                                 f"{symbol!r}@{offset}")
            ivars[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}',
                                      'descriptor': f'0x{entry:08x}',
                                      'symbol': symbol, 'offset': offset}

        constants = {}
        for address, kind, expected_hex in spec['constants']:
            off = memory.offset(address, 8)
            if kind == 'float':
                raw = memory.data[off:off + 4]
                got = raw[::-1].hex()
                value = struct.unpack('<f', raw)[0]
            else:
                raw = memory.data[off:off + 8]
                got = raw[::-1].hex()
                value = struct.unpack('<d', raw)[0]
            if got != expected_hex:
                raise ValueError(f"{spec['name']}: pool {kind} at {address:#x} "
                                 f"drifted: 0x{got}")
            constants[f'0x{address:08x}'] = {'kind': kind, 'bits': f'0x{got}',
                                             'value': value}

        # full call-site set equality + route text + (for bl) target
        listed = {a for a, ins in rows.items() if re.match(r'^blx?\s', ins)}
        expected_sites = {site for site, *_ in spec['calls']}
        if listed != expected_sites:
            raise ValueError(f"{spec['name']}: call site set drifted: "
                             f"{sorted(a for a in listed ^ expected_sites)}")
        calls = []
        for site, route, note in spec['calls']:
            if rows[site] != route:
                raise ValueError(f"{spec['name']}: call route drifted at "
                                 f"{site:#x}: {rows[site]!r} != {route!r}")
            target = None
            if route.startswith('bl '):
                target = bl_target(site, memory.word(site))
                expect = {'bl loc.imp.objc_msgSend': MSGSEND_STUB,
                          'bl sym.clamp_float__float__float_': CLAMP,
                          'bl sym.linearInterpolate_float__float__float_': LINEAR}[route]
                if target != expect:
                    raise ValueError(f"{spec['name']}: bl target drifted at "
                                     f"{site:#x}: {target:#x} != {expect:#x}")
            calls.append({'site': f'0x{site:08x}', 'route': route,
                          'callee': f'0x{target:08x}' if target else None,
                          'note': note})

        # full branch set equality
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
            'ivars': ivars,
            'constants': constants,
            'calls': calls,
            'branches': [{'address': f'0x{a:08x}', 'mnemonic': mn,
                          'destination': f'0x{d:08x}'}
                         for a, mn, d in spec['branches']],
            'semantics': spec['semantics'],
        })

    return {
        'schema': 1,
        'elf_sha256': sha,
        'batch': 'WorldTileLoader column-height helpers',
        'scope': ('WorldTileLoader column-height helpers: height-array '
                  'accessors and the cloud-noise composition'),
        'claim': ('static bounded-body maps with per-instruction anchors; '
                  'NoiseFunction internals, customRules layout and runtime '
                  'values are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'worldtileloader_column_heights.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale worldtileloader_column_heights.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
