#!/usr/bin/env python3
"""Hash-gated recovery of the physical-block-load re-registration hook.

-[ArtificialLight addContributionForPhysicalBlockLoadedAtXPos:yPos:]
0x00a95248 .. 0x00a958bc (413 words) from the pinned original
libApplication.so (1.7.6, armeabi-v7a). Culls the block (with x half-wrap,
y plain) against radius, then retracts ([self removeFromTiles]), clears the
contribution grid (memset dia^2*10) and re-adds ([self addToTiles] through
the saved objc_msgSend pointer). Every instruction word is re-verified
against the pinned ELF; tool refuses to emit on drift.
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
    'bl loc.imp.objc_msgSend': 0x001C281C,
    'bl sym.makeIntpair_int__int_': 0x004B49FC,
    'bl sym.imp.__aeabi_idiv': 0x001C3728,
    'bl sym.imp.memset': 0x001C2924,
}

SEMANTICS = (
'Cull-and-reregister hook run when a physical (client light) block loads. pair1 = makeIntpair(xPos << 5, yPos << 5); pair2 = makeIntpair((xPos+1) << 5, (yPos+1) << 5). With h = ([self.world worldWidthMacro] << 5) / 2 (via __aeabi_idiv): dx1 = self.pos.x - xPos*32 wrapped by the world width (dx1 >= h -> dx1 -= w*32; dx1 < -h -> dx1 += w*32); dx2 = self.pos.x - (xPos+1)*32 wrapped the same way. Culls (all return): dx1 < -radius; dx2 >= radius; dy1 = self.pos.y - yPos*32 < -radius; dy2 = self.pos.y - (yPos+1)*32 >= radius (y never wraps - the world is x-cylindrical). Otherwise the light re-registers itself: objc_msgSend(self, @selector(removeFromTiles)) retracts the old contributions - the call site carries an additional staged argument block (r2 = &addToTiles selector slot, r3 = 0, stack = &diameter-descr, 5, 0, &addToTiles selector slot, PIC base, 1, objc_msgSend function pointer) recorded as observed, the method consumes none of it; then memset(self.contributionGrid, 0, diameter*diameter*2*5) clears the whole 5-int16-per-cell grid (count = (diameter<<1) * diameter * 5); then objc_msgSend(self, @selector(addToTiles)) is issued through the saved objc_msgSend function pointer (blx r2). Net effect: stale contributions are retracted, the grid is reset, and addToTiles re-runs the engine + contribution walk against the newly loaded block data.'
)

SPECS = [
    dict(
        name='addContributionForPhysicalBlockLoadedAtXPos:yPos:',
        method='ArtificialLight -[addContributionForPhysicalBlockLoadedAtXPos:yPos:]',
        types='v16@0:4i8i12',
        start=0x00A95248, end=0x00A958BC,
        disasm='disasm_artificiallight_addcontribution.txt',
        base_add=0x00A95258, base_literal=0x00A958B8,
        boundary='own ARM.exidx bound 0x00a958bc (end of the region; next method IMP 0x00a958bc = -[ArtificialLight .cxx_construct])',
        selectors={
            0x00A9587C: (0x00E854D0, 'worldWidthMacro'),
            0x00A958A4: (0x00E854F8, 'addToTiles'),
            0x00A958AC: (0x00E85518, 'removeFromTiles'),
        },
        ivars={
            0x00A95870: (0x0105C390, 'OBJC_IVAR_$_DynamicObject.pos', 16),
            0x00A95878: (0x0105C394, 'OBJC_IVAR_$_DynamicObject.world', 4),
            0x00A9588C: (0x0105EA20, 'OBJC_IVAR_$_ArtificialLight.radius', 80),
            0x00A958A8: (0x0105EA18, 'OBJC_IVAR_$_ArtificialLight.diameter', 92),
            0x00A958B4: (0x0105EA1C, 'OBJC_IVAR_$_ArtificialLight.contributionGrid', 56),
        },
        imports={0x00A958A0: (0x0105B7A0, 'objc_msgSend')},
        instructions=[
            (0x00A95278, 'lsl r1, r0, 5'),
            (0x00A95280, 'sub r0, fp, 0x28'),
            (0x00A953EC, 'rsb r0, r0, 0'),
            (0x00A954CC, 'sub r1, r1, r2'),
            (0x00A95624, 'rsb r0, r0, 0'),
            (0x00A957AC, 'movw r3, 0'),
            (0x00A957B0, 'movw ip, 5'),
            (0x00A957BC, 'movw r4, 1'),
            (0x00A95820, 'lsl r0, r0, 1'),
            (0x00A95838, 'mul r0, r0, r3'),
            (0x00A95840, 'mul r2, r0, r3'),
            (0x00A9584C, 'and r1, r1, 0xff'),
            (0x00A95864, 'blx r2'),
        ],
        semantics=SEMANTICS,
        calls=[
        (0x00a95290, 'bl sym.makeIntpair_int__int_'),
        (0x00a952b0, 'bl sym.makeIntpair_int__int_'),
        (0x00a952f8, 'bl loc.imp.objc_msgSend'),
        (0x00a95310, 'bl sym.imp.__aeabi_idiv'),
        (0x00a95370, 'bl loc.imp.objc_msgSend'),
        (0x00a953e8, 'bl loc.imp.objc_msgSend'),
        (0x00a953f8, 'bl sym.imp.__aeabi_idiv'),
        (0x00a95458, 'bl loc.imp.objc_msgSend'),
        (0x00a95530, 'bl loc.imp.objc_msgSend'),
        (0x00a95548, 'bl sym.imp.__aeabi_idiv'),
        (0x00a955a8, 'bl loc.imp.objc_msgSend'),
        (0x00a95620, 'bl loc.imp.objc_msgSend'),
        (0x00a95630, 'bl sym.imp.__aeabi_idiv'),
        (0x00a95690, 'bl loc.imp.objc_msgSend'),
        (0x00a957f4, 'bl loc.imp.objc_msgSend'),
        (0x00a95850, 'bl sym.imp.memset'),
        (0x00a95864, 'blx r2'),
        ],
        branches=[
        (0x00a9531c, 'blt', 0x00a95390),
        (0x00a9538c, 'b', 0x00a954a8),
        (0x00a95404, 'bge', 0x00a95478),
        (0x00a95474, 'b', 0x00a954a0),
        (0x00a954d4, 'blt', 0x00a95868),
        (0x00a95554, 'blt', 0x00a955c8),
        (0x00a955c4, 'b', 0x00a956e0),
        (0x00a9563c, 'bge', 0x00a956b0),
        (0x00a956ac, 'b', 0x00a956d8),
        (0x00a95704, 'bge', 0x00a95868),
        (0x00a95750, 'blt', 0x00a95868),
        (0x00a95794, 'bge', 0x00a95868),
        ],
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

    from elftools.elf.elffile import ELFFile as _ELF
    dynsym = {}
    for sec in _ELF(io.BytesIO(data)).iter_sections():
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

        for cell, (expected_slot, expected_name) in spec['imports'].items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: import cell {cell:#x} -> {slot:#x}")
            got = memory.imports.get(slot)
            if got != expected_name:
                raise ValueError(f"{spec['name']}: import drifted at {cell:#x}: {got!r}")
            selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'import': got}

        listed = {a for a, ins in rows.items() if re.match(r'^blx?\s', ins)}
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
                           for a, ins in rows.items()
                           for m in [re.match(r'^(b\w*)\s+(0x[0-9a-f]+)', ins)]
                           if m and m.group(1) not in ('bl', 'blx')}
        expected_branches = {(a, mn, d) for a, mn, d in spec['branches']}
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
            'pic_base': f'0x{base:08x}',
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
        'batch': 'ArtificialLight physical-block-load re-registration hook',
        'claim': ('static bounded-body map with per-instruction anchors; the '
                  'removeFromTiles/addToTiles bodies it dispatches into are '
                  'mapped in the tiles pair batch; runtime values are outside '
                  'this body'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'artificiallight_blockload.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale artificiallight_blockload.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
