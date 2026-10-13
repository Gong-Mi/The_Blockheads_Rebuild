#!/usr/bin/env python3
"""Hash-gated recovery of WorldHelper +[recalculateLightingForPhysicalBlockIfNeeded:…].

One class body from the pinned original libApplication.so (1.7.6,
armeabi-v7a, SHA-256 733d8210…b94c7):

  +[WorldHelper recalculateLightingForPhysicalBlockIfNeeded:world:
    clientLightBlockIndex:forBlockhead:]
    0x00a1ca64 .. 0x00a1d730 (819 words)

The per-macro-block lighting orchestrator: server-only, blockhead-view centered,
culls far blocks, then walks the 32x32 tile grid computing a radial light field
(light = (int)(255*(4 - 2*((sqrt(d2)+margin)/2)))) and writing tile[9] /
tile[6] (or the per-client light-block extraData), calling the per-tile
updateSunLightForTile:atPos:world: (WORLDHELPER_SUNLIGHT.md) on eligible tiles,
freezing tiles at content type 3 below zero temperature via
fillTile:atPos:withType: and reporting through lightChangedAtMacroPos: /
exploreLightChangedAtMacroPos:.

Every instruction word is re-verified against the pinned ELF; PIC base,
selector cells, the objc_msgSend import, all 40 call sites (with pinned
direct-call targets), all 62 branches and key instructions are anchored.
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

ROUTE_TARGETS = {
    'bl loc.imp.objc_msgSend': 0x001C281C,
    'bl loc.imp.objc_msgSend_stret': 0x001C2918,
    'bl sym.imp.memset': 0x001C2924,
    'bl sym.imp.__aeabi_idiv': 0x001C3728,
    'bl sym.imp.sqrtf': 0x001C2B28,
    'bl sym.backWallIsMutable_Tile_': 0x00A1234C,
    'bl sym.tileIsSolid_Tile_': 0x00A1179C,
    'bl sym.makeIntpair_int__int_': 0x004B49FC,
    'bl sym.seasonForWorldX_int__double__World_': 0x00A14A48,
    'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_': 0x00A15404,
}

SEMANTICS = (
    'Gates: if (clientLightBlockIndex == 0) return; dw = [world dynamicWorld]; '
    'if ([dw isClient]) return; if ([blockhead '
    'isClientBlockheadBeingControlledByServer]) return. '
    'bx32 = physicalBlock->blockX << 5; by32 = physicalBlock->blockY << 5; '
    'extra = (clientLightBlockIndex != -1) ? physicalBlock[0x20 + idx*4] : 0; '
    'when extra != 0 it is first loaded via [world '
    'loadLightBlockForClientLightBlockIndex:idx intoPhysicalBlock:pb]. '
    'center = blockhead ? [blockhead pos] : [world startPortalPos] (nil world -> '
    '{0,0}); vr = blockhead ? [blockhead viewRadius] : 4; margin = max(22 - vr, 0). '
    'Wrap center.x into the macro width: if (center.x - bx32 < -(w<<4)) center.x += w<<5; '
    'if (center.x - bx32 > (w<<4)) center.x -= w<<5 (w = [world worldWidthMacro]); same for '
    'center.y. Cull: return unless center.x in (bx32-vr, bx32+32+vr) and center.y in '
    '(by32-vr, by32+32+vr). '
    'Per tile loop (i = 0..31 rows, j = 0..31 cols): tile = '
    'physicalBlock->tiles + (i*32+j)*64; worldPos = (bx32+j, by32+i); '
    'srcByte = extra ? extra[i*32+j] : tile[6]; dx = center.x - (bx32+j), '
    'if (dx < 0) dx += 1, then wrapped by the same +-w<<4 / w<<5 rule; dy analog; '
    'd2 = dx*dx + dy*dy; if (d2 >= 0x1e4) continue; '
    't = ((float)sqrtf(d2) + (float)margin) / 2.0f; u = 4.0f - t * 4.0f; '
    'lightI = (int)(255.0f * u); newLight = (lightI > srcByte) ? min(lightI, 0xff) : srcByte; '
    'if (tile[9] == 0) { if (newLight > 0) { tile[9] = newLight; flag36 = 1; '
    'if (backWallIsMutable(tile) && !tileIsSolid(tile) && tile[3] == 0 && tile[0] != 3) '
    '[WorldHelper updateSunLightForTile:tile atPos:worldPos world:world]; } } '
    'else if (newLight > tile[9]) { tile[9] = newLight; flag36 = 1; } '
    'if (tile[0] == 3) { weather = [world getWeatherFractionForPos:worldPos]; '
    'dayNight = [world getDayNightFractionForX:(float)worldPos.x '
    'atWorldTime:(double)[world worldTime]]; season = seasonForWorldX(worldPos.x, '
    '(double)[world worldTime], world); temp = currentTemperatureForTileAtWorldPos(tile, '
    'worldPos, weather, dayNight, season, world); '
    'if (temp < 0) [world fillTile:tile atPos:worldPos withType:0x422]; } '
    'if (newLight != srcByte) { if (extra) extra[i*32+j] = newLight; else tile[6] = newLight; '
    'flag35 = 1; } '
    'After the loops: if (flag36) [dw lightChangedAtMacroPos:makeIntpair(pb.blockX, '
    'pb.blockY) sendReliably:0 sendAtAll:0]; if (flag35) [dw '
    'exploreLightChangedAtMacroPos:makeIntpair(pb.blockX, pb.blockY) '
    'clientLightBlockIndex:idx]. '
    'The light falloff is the exact arithmetic: light = (int)(255.0f * (4.0f - 2.0f*'
    '(((float)sqrtf(dx*dx+dy*dy) + (float)margin) / 2.0f)) as the ARM computes it '
    '(margins max(22-vr,0)); tiles at d2 >= 0x1e4 are skipped.'
)

SPEC = dict(
    name='recalculateLightingForPhysicalBlockIfNeeded',
    method=('WorldHelper +[recalculateLightingForPhysicalBlockIfNeeded:world:'
            'clientLightBlockIndex:forBlockhead:]'),
    types='v24@0:4^{PhysicalBlock=ii^{Tile}cCdII[32*][32C]}8@12i16@20',
    start=0x00A1CA64, end=0x00A1D730,
    disasm='disasm_worldhelper_recalculatelighting.txt',
    base_add=0x00A1CA74, base_literal=0x00A1D728,
    boundary=('no own ARM.exidx entry; closed by the next method IMP '
              '0x00a1d730 (-[reloadDrawBlock:world:waterAnimationIndex:...])'),
    selectors={
        0x00A1D6B4: (0x00E84C8C, 'isClient'),
        0x00A1D6B8: (0x00E84C2C, 'dynamicWorld'),
        0x00A1D6BC: (0x00E84CC4, 'isClientBlockheadBeingControlledByServer'),
        0x00A1D6C0: (0x00E84CC8, 'loadLightBlockForClientLightBlockIndex:intoPhysicalBlock:'),
        0x00A1D6C8: (0x00E84CCC, 'startPortalPos'),
        0x00A1D6CC: (0x00E84C58, 'pos'),
        0x00A1D6D0: (0x00E84CD0, 'viewRadius'),
        0x00A1D6D4: (0x00E84C68, 'worldWidthMacro'),
        0x00A1D708: (0x00E84CD4, 'updateSunLightForTile:atPos:world:'),
        0x00A1D710: (0x00E84CD8, 'getWeatherFractionForPos:'),
        0x00A1D718: (0x00E84CDC, 'worldTime'),
        0x00A1D71C: (0x00E84CE0, 'getDayNightFractionForX:atWorldTime:'),
        0x00A1D720: (0x00E84CE4, 'fillTile:atPos:withType:'),
        0x00A1D6EC: (0x00E84CE8, 'lightChangedAtMacroPos:sendReliably:sendAtAll:'),
        0x00A1D6F4: (0x00E84CEC, 'exploreLightChangedAtMacroPos:clientLightBlockIndex:'),
    },
    classrefs={},
    imports={0x00A1D6B0: (MSGSEND_GOT_SLOT, 'objc_msgSend')},
    instructions=[
        (0x00A1D1A0, 'cmp r0, 0x1e4'),
        (0x00A1D1B4, 'vmov.f32 s2, 4'),
        (0x00A1D1BC, 'vmov.f32 s4, 2'),
        (0x00A1D1D8, 'vstr s4, [sp, 0x58]'),
        (0x00A1D1E4, 'vstr s2, [sp, 0x4c]'),
        (0x00A1D2A0, 'strb r1, [r2, 9]'),
        (0x00A1D2A4, 'strb r0, [fp, -0x36]'),
        (0x00A1D4E4, 'movw r4, 0x422'),
        (0x00A1D520, 'strb r1, [r2, 9]'),
        (0x00A1D560, 'strb r0, [r1]'),
        (0x00A1D570, 'strb r0, [r1, 6]'),
        (0x00A1D578, 'strb r0, [fp, -0x35]'),
    ],
    calls=[

        (0x00a1cae8, 'blx ip'),
        (0x00a1caf8, 'blx r2'),
        (0x00a1cb30, 'blx r2'),
        (0x00a1cbdc, 'bl loc.imp.objc_msgSend'),
        (0x00a1cc3c, 'bl loc.imp.objc_msgSend_stret'),
        (0x00a1cc60, 'bl sym.imp.memset'),
        (0x00a1ccd0, 'blx r3'),
        (0x00a1cd04, 'bl loc.imp.objc_msgSend_stret'),
        (0x00a1cd28, 'bl sym.imp.memset'),
        (0x00a1cdc0, 'bl loc.imp.objc_msgSend'),
        (0x00a1cdd0, 'bl sym.imp.__aeabi_idiv'),
        (0x00a1ce04, 'bl loc.imp.objc_msgSend'),
        (0x00a1ce60, 'bl loc.imp.objc_msgSend'),
        (0x00a1ce78, 'bl sym.imp.__aeabi_idiv'),
        (0x00a1ceac, 'bl loc.imp.objc_msgSend'),
        (0x00a1d050, 'bl loc.imp.objc_msgSend'),
        (0x00a1d068, 'bl sym.imp.__aeabi_idiv'),
        (0x00a1d09c, 'bl loc.imp.objc_msgSend'),
        (0x00a1d0f0, 'bl loc.imp.objc_msgSend'),
        (0x00a1d100, 'bl sym.imp.__aeabi_idiv'),
        (0x00a1d134, 'bl loc.imp.objc_msgSend'),
        (0x00a1d1ec, 'bl sym.imp.sqrtf'),
        (0x00a1d2ac, 'bl sym.backWallIsMutable_Tile_'),
        (0x00a1d2c0, 'bl sym.tileIsSolid_Tile_'),
        (0x00a1d314, 'bl sym.makeIntpair_int__int_'),
        (0x00a1d348, 'bl loc.imp.objc_msgSend'),
        (0x00a1d368, 'bl sym.makeIntpair_int__int_'),
        (0x00a1d3a4, 'bl loc.imp.objc_msgSend'),
        (0x00a1d3d4, 'bl loc.imp.objc_msgSend'),
        (0x00a1d3fc, 'bl loc.imp.objc_msgSend'),
        (0x00a1d43c, 'bl loc.imp.objc_msgSend'),
        (0x00a1d460, 'bl sym.seasonForWorldX_int__double__World_'),
        (0x00a1d494, 'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_'),
        (0x00a1d4f0, 'bl loc.imp.objc_msgSend'),
        (0x00a1d5d0, 'bl loc.imp.objc_msgSend'),
        (0x00a1d5f8, 'bl sym.makeIntpair_int__int_'),
        (0x00a1d624, 'bl loc.imp.objc_msgSend'),
        (0x00a1d64c, 'bl loc.imp.objc_msgSend'),
        (0x00a1d674, 'bl sym.makeIntpair_int__int_'),
        (0x00a1d6a4, 'bl loc.imp.objc_msgSend'),
    ],
    branches=[
        (0x00a1caa8, 'beq', 0x00a1cb40),
        (0x00a1cb04, 'bne', 0x00a1cb40),
        (0x00a1cb3c, 'beq', 0x00a1cb44),
        (0x00a1cb40, 'b', 0x00a1d6a8),
        (0x00a1cb7c, 'beq', 0x00a1cbfc),
        (0x00a1cbac, 'bne', 0x00a1cbf8),
        (0x00a1cbf8, 'b', 0x00a1cbfc),
        (0x00a1cc2c, 'beq', 0x00a1cc44),
        (0x00a1cc40, 'b', 0x00a1cc64),
        (0x00a1cc78, 'bne', 0x00a1cc98),
        (0x00a1cc94, 'b', 0x00a1cd3c),
        (0x00a1ccf4, 'beq', 0x00a1cd0c),
        (0x00a1cd08, 'b', 0x00a1cd2c),
        (0x00a1cd60, 'bge', 0x00a1cd70),
        (0x00a1cd6c, 'b', 0x00a1cd78),
        (0x00a1cddc, 'bge', 0x00a1ce24),
        (0x00a1ce20, 'b', 0x00a1cecc),
        (0x00a1ce84, 'ble', 0x00a1cec8),
        (0x00a1cec8, 'b', 0x00a1cecc),
        (0x00a1cee4, 'bge', 0x00a1d5ac),
        (0x00a1cefc, 'ble', 0x00a1d5ac),
        (0x00a1cf18, 'bge', 0x00a1d5ac),
        (0x00a1cf30, 'ble', 0x00a1d5ac),
        (0x00a1cf48, 'bge', 0x00a1d5a8),
        (0x00a1cf60, 'bge', 0x00a1d590),
        (0x00a1cfc4, 'beq', 0x00a1cfe0),
        (0x00a1cfdc, 'b', 0x00a1cfec),
        (0x00a1d00c, 'bge', 0x00a1d01c),
        (0x00a1d074, 'blt', 0x00a1d0bc),
        (0x00a1d0b8, 'b', 0x00a1d154),
        (0x00a1d10c, 'bgt', 0x00a1d150),
        (0x00a1d150, 'b', 0x00a1d154),
        (0x00a1d16c, 'bge', 0x00a1d17c),
        (0x00a1d1a4, 'bge', 0x00a1d530),
        (0x00a1d248, 'ble', 0x00a1d270),
        (0x00a1d254, 'ble', 0x00a1d264),
        (0x00a1d260, 'b', 0x00a1d26c),
        (0x00a1d26c, 'b', 0x00a1d270),
        (0x00a1d284, 'bne', 0x00a1d500),
        (0x00a1d290, 'ble', 0x00a1d4fc),
        (0x00a1d2b8, 'beq', 0x00a1d2f0),
        (0x00a1d2cc, 'bne', 0x00a1d2f0),
        (0x00a1d2dc, 'bne', 0x00a1d2f0),
        (0x00a1d2ec, 'bne', 0x00a1d34c),
        (0x00a1d358, 'bne', 0x00a1d4f8),
        (0x00a1d4ac, 'bpl', 0x00a1d4f4),
        (0x00a1d4f4, 'b', 0x00a1d4f8),
        (0x00a1d4f8, 'b', 0x00a1d4fc),
        (0x00a1d4fc, 'b', 0x00a1d52c),
        (0x00a1d510, 'ble', 0x00a1d528),
        (0x00a1d528, 'b', 0x00a1d52c),
        (0x00a1d52c, 'b', 0x00a1d530),
        (0x00a1d53c, 'beq', 0x00a1d57c),
        (0x00a1d54c, 'beq', 0x00a1d568),
        (0x00a1d564, 'b', 0x00a1d574),
        (0x00a1d57c, 'b', 0x00a1d580),
        (0x00a1d58c, 'b', 0x00a1cf58),
        (0x00a1d590, 'b', 0x00a1d594),
        (0x00a1d5a0, 'b', 0x00a1cf40),
        (0x00a1d5a8, 'b', 0x00a1d5ac),
        (0x00a1d5b4, 'beq', 0x00a1d628),
        (0x00a1d630, 'beq', 0x00a1d6a8),
    ],
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

    for cell, (expected_slot, expected_name) in spec['imports'].items():
        slot = (base + signed(memory.word(cell))) & 0xffffffff
        if slot != expected_slot:
            raise ValueError(f'import cell {cell:#x} -> {slot:#x}')
        got = memory.imports.get(slot)
        if got != expected_name:
            raise ValueError(f'import drifted at {cell:#x}: {got!r}')
        selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'import': got}

    listed = {a for a, ins in rows.items() if re.match(r'^blx?\s', ins)}
    expected_sites = {site for site, _ in spec['calls']}
    if listed != expected_sites:
        raise ValueError(f'call site set drifted: {sorted(listed ^ expected_sites)}')
    calls = []
    for site, route in spec['calls']:
        if rows[site] != route:
            raise ValueError(f'call route drifted at {site:#x}: {rows[site]!r} != {route!r}')
        target = None
        if route.startswith('bl '):
            target = bl_target(site, memory.word(site))
            expected = ROUTE_TARGETS.get(route)
            if expected is None:
                raise ValueError(f'no pinned target for route {route!r}')
            if target != expected:
                raise ValueError(f'bl target drifted at {site:#x}: {target:#x} != {expected:#x}')
        calls.append({'site': f'0x{site:08x}', 'route': route,
                      'callee': f'0x{target:08x}' if target else None})

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
        'calls': calls,
        'branches': [{'address': f'0x{a:08x}', 'mnemonic': mn,
                      'destination': f'0x{d:08x}'}
                     for a, mn, d in spec['branches']],
        'semantics': SEMANTICS,
    }
    return {
        'schema': 1,
        'elf_sha256': sha,
        'batch': 'WorldHelper recalculateLightingForPhysicalBlockIfNeeded: (per-block lighting orchestrator)',
        'claim': ('static bounded-body map with per-instruction anchors; the '
                  'temperature model behind currentTemperatureForTileAtWorldPos, '
                  'fillTile:atPos:withType: effects and runtime values are '
                  'outside this body'),
        'classes': [method],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'worldhelper_recalculatelighting.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale worldhelper_recalculatelighting.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
