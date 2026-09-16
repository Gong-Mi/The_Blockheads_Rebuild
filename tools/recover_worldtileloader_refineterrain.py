#!/usr/bin/env python3
"""Byte-gated, hand-reviewed WorldTileLoader -[refineTerrain] evidence map.

IMP 0x00854c54 .. ARM.exidx end 0x00855ad0 (927 words including literal pool),
PIC base 0x0105faf4 materialised TWICE (r2 at 0x00854c60..0x00854c64, r8 at
0x00854ca8..0x00854cac) and re-materialised per site via pc-relative pairs;
all resolutions below use 0x0105faf4. The checked-in listing is re-verified
word-by-word against the SHA-256-pinned ELF; every cell, call site and branch
below is anchored and the tool refuses to emit on any drift.

Reviewed semantics (static):
  pool = [[NSAutoreleasePool alloc] init]            (fp-0x28, entry 0x00854d04..0x00854d34)
  w4   = [self->world worldWidthMacro] / 4           ((w<<5)/0x80 via __aeabi_idiv, fp-0x24)
  for (i = self->refineTerrainCount;                 (ivar 232; loop var fp-0x2c)
       i < self->refineTerrainCount + w4;             (bge 0x00854d90 -> exit 0x00855948)
       i++) {
      [pool release];
      pool = [[NSAutoreleasePool alloc] init];        (loop tail 0x008558ac..0x00855934)
      colRock = self->rockHeights[i];                 (ivar 96)
      colDirt = self->dirtHeights[i];                 (ivar 92)
      byte = (colRock < colDirt);                     (fp-0x2d)
      modX1 = (colRock + w*32 - 1) % (w*32);          (fp-0x34, __modsi3)
      modX2 = (colDirt + w*32 - 1) % (w*32);          (fp-0x38)
      if (rand() % 8 == 0) {                          (rand = local f(n) @0x008540cc, no symbol)
          randX = rand() % (colRock - 1);             (fp-0x48)
          faultOffset = [self faultOffsetForX:i y:randX];      (fp-0x4c)
          if ([self isCaveForX:i y:randX faultOffset:faultOffset]) {   (sxtb gate)
              punch(i, randX);
          }
      }
      column fill loops (3 more blocks): same faultOffset/isCave gate per
      scanline yy, punch(i, yy) for yy descending through the column range;
  }
  punch(x, y):                                       (4 identical bodies)
      tile = tileAtWorldPositionLoaded(x, y, self->world);
      if (tile->byte0 != 0x1f) {
          tile->byte0 = 3; tile->byte4 = 0xff; tile->byte7 = 0;
          [self recursivelyFlowOutWaterFromTile:tile
           atPos:makeIntpair(x, y)];
      }
  exit:
      self->refineTerrainCount += w4;                 (0x00855954..0x00855970)
      [world decommisionAllBlocksBlockToSavePhyscialBlock:1];  (0x00855988..0x008559b0)
      if (w*32 - 1 == <world-queried value>) self->hasRefinedTerrain = 1;  (ivar 104 byte)

Static map only: column-range data flow between modX1/modX2/fp-0x44/fp-0x6c
is census-level; no runtime claim.
"""
import argparse
import hashlib
import io
import json
import re
from pathlib import Path

from elftools.elf.elffile import ELFFile
from trace_objc_dispatch import ELFMemory
from recover_drawframe_slices import verify_disassembly
from recover_worldtileloader_faultoffset import plt_slot

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
START, END = 0x00854C54, 0x00855AD0
BASE2_ADD, BASE2_LITERAL = 0x00854C64, 0x00855AC8   # r2 = 0x0105faf4
BASE8_ADD, BASE8_LITERAL = 0x00854CAC, 0x00855A54   # r8 = 0x0105faf4
EXPECTED_BASE = 0x0105FAF4
DISPATCH_SLOT = 0x0105B7A0                          # objc_msgSend
IDIV_PLT, IDIV_SLOT = 0x001C3728, 0x106001C
MODSI3_PLT, MODSI3_SLOT = 0x001C3020, 0x105FDC4
RAND_FUNC = 0x008540CC
TILEAT = 0x00A12F24                 # _Z25tileAtWorldPositionLoadediiP5World
MAKEPAIR = 0x004B49FC               # _Z11makeIntpairii

# (cell, expected_slot, kind, expected_name[, expected_ivar_offset])
CELLS = (
    (0x00855A3C, 0x0105DDBC, 'IVAR', 'OBJC_IVAR_$_WorldTileLoader.refineTerrainCount', 232),
    (0x00855A40, 0x0105B7A0, 'IMP', 'objc_msgSend'),
    (0x00855A44, 0x00E823A4, 'SEL', 'init'),
    (0x00855A48, 0x00E823BC, 'SEL', 'alloc'),
    (0x00855A4C, 0x00E8A8A0, 'REF', 'OBJC_CLASS_$_NSAutoreleasePool'),
    (0x00855A50, 0x0105DD4C, 'IVAR', 'OBJC_IVAR_$_WorldTileLoader.world', 4),
    (0x00855A58, 0x00E823A8, 'SEL', 'worldWidthMacro'),
    (0x00855A60, 0x00E82434, 'SEL', 'decommisionAllBlocksBlockToSavePhyscialBlock:'),
    (0x00855A64, 0x00E82414, 'SEL', 'release'),
    (0x00855A68, 0x0105DDC0, 'IVAR', 'OBJC_IVAR_$_WorldTileLoader.hasRefinedTerrain', 104),
    (0x00855A6C, 0x0105DD60, 'IVAR', 'OBJC_IVAR_$_WorldTileLoader.rockHeights', 96),
    (0x00855A74, 0x0105DD5C, 'IVAR', 'OBJC_IVAR_$_WorldTileLoader.dirtHeights', 92),
    (0x00855A78, 0x00E82408, 'SEL', 'isCaveForX:y:faultOffset:'),
    (0x00855A7C, 0x00E82404, 'SEL', 'faultOffsetForX:y:'),
)
PAIR_CELLS = {
    0x00855A80: (0x00855A84, 0x00855060),   # -> 0x00e82430 recursivelyFlowOutWater...
}

BRANCHES = (
    (0x00854D90, 0x00855948), (0x00854F0C, 0x0085508C), (0x00854F20, 0x0085508C),
    (0x00854FC0, 0x00855088), (0x00855008, 0x00855084), (0x00855084, 0x00855088),
    (0x00855088, 0x0085508C), (0x00855094, 0x0085509C), (0x00855098, 0x008558AC),
    (0x008550A4, 0x00855204), (0x008550E0, 0x00855204), (0x0085511C, 0x00855204),
    (0x00855170, 0x00855204), (0x008551AC, 0x00855204), (0x00855200, 0x008558A8),
    (0x0085524C, 0x0085528C), (0x00855288, 0x008553A0), (0x008552D8, 0x008553A0),
    (0x00855320, 0x0085539C), (0x0085539C, 0x008558A4), (0x008553D8, 0x00855430),
    (0x0085542C, 0x00855620), (0x00855478, 0x00855488), (0x00855484, 0x00855490),
    (0x008554AC, 0x0085561C), (0x0085553C, 0x00855604), (0x00855584, 0x00855600),
    (0x00855600, 0x00855604), (0x00855604, 0x00855608), (0x00855618, 0x008554A0),
    (0x0085561C, 0x00855620), (0x00855658, 0x008556B0), (0x008556AC, 0x008558A0),
    (0x008556F8, 0x00855708), (0x00855704, 0x00855710), (0x0085572C, 0x0085589C),
    (0x008557BC, 0x00855884), (0x00855804, 0x00855880), (0x00855880, 0x00855884),
    (0x00855884, 0x00855888), (0x00855898, 0x00855720), (0x0085589C, 0x008558A0),
    (0x008558A0, 0x008558A4), (0x008558A4, 0x008558A8), (0x008558A8, 0x008558AC),
    (0x00855944, 0x00854D64), (0x00855A10, 0x00855A34),
)

CALLS = (
    (0x00854CE4, 'stub'), (0x00854CFC, 'plt-idiv'), (0x00854D20, 'got'),
    (0x00854D30, 'got'), (0x00854E20, 'stub'), (0x00854E58, 'stub'),
    (0x00854E64, 'plt-modsi3'), (0x00854E9C, 'stub'), (0x00854EA8, 'plt-modsi3'),
    (0x00854F10, 'rand'), (0x00854F18, 'plt-modsi3'), (0x00854F24, 'rand'),
    (0x00854F60, 'plt-modsi3'), (0x00854F80, 'got'), (0x00854FB4, 'got'),
    (0x00854FF4, 'tileat'), (0x00855054, 'makepair'), (0x00855080, 'stub'),
    (0x0085523C, 'got'), (0x008552CC, 'got'), (0x0085530C, 'tileat'),
    (0x0085536C, 'makepair'), (0x00855398, 'stub'), (0x008554FC, 'got'),
    (0x00855530, 'got'), (0x00855570, 'tileat'), (0x008555D0, 'makepair'),
    (0x008555FC, 'stub'), (0x0085577C, 'got'), (0x008557B0, 'got'),
    (0x008557F0, 'tileat'), (0x00855850, 'makepair'), (0x0085587C, 'stub'),
    (0x00855900, 'got'), (0x00855920, 'got'), (0x00855930, 'got'),
    (0x008559B0, 'stub'), (0x008559C4, 'stub'), (0x008559F4, 'stub'),
)


def signed(v):
    return v - (1 << 32) if v & 0x80000000 else v


def bl_target(site, word):
    if word >> 24 != 0xEB:
        raise ValueError(f'{site:#x} is not a bl immediate form: {word:#x}')
    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 1 << 24
    return (site + 8 + (imm << 2)) & 0xFFFFFFFF


def b_target(site, word):
    if (word >> 25) & 0b111 != 0b101:
        raise ValueError(f'{site:#x} is not a B/BL encoding: {word:#x}')
    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 1 << 24
    return (site + 8 + (imm << 2)) & 0xFFFFFFFF


def recover(path: Path) -> dict:
    memory = ELFMemory(path)
    text = (NATIVE / 'disasm_worldtileloader_refineterrain.txt').read_text()
    words = verify_disassembly(memory, text, START, END)

    base2 = (BASE2_ADD + 8 + signed(memory.word(BASE2_LITERAL))) & 0xffffffff
    base8 = (BASE8_ADD + 8 + signed(memory.word(BASE8_LITERAL))) & 0xffffffff
    if base2 != EXPECTED_BASE or base8 != EXPECTED_BASE:
        raise ValueError(f'PIC base drift {base2:#x} {base8:#x}')

    def cstr(addr):
        if addr is None:
            return None
        off = memory.offset(addr, 1)
        if off is None:
            return None
        end = memory.data.find(b'\0', off, off + 256)
        return memory.data[off:end].decode('utf-8', 'replace') if end >= 0 else None

    elf = ELFFile(io.BytesIO(path.read_bytes()))
    symbols = {s['st_value']: s.name
               for s in elf.get_section_by_name('.dynsym').iter_symbols()}

    if memory.imports.get(DISPATCH_SLOT) != 'objc_msgSend':
        raise ValueError('dispatch slot evidence changed')
    if plt_slot(memory, IDIV_PLT) != IDIV_SLOT or \
            memory.imports.get(IDIV_SLOT) != '__aeabi_idiv':
        raise ValueError('idiv PLT/JUMP_SLOT evidence changed')
    if plt_slot(memory, MODSI3_PLT) != MODSI3_SLOT or \
            memory.imports.get(MODSI3_SLOT) != '__modsi3':
        raise ValueError('modsi3 PLT/JUMP_SLOT evidence changed')
    if symbols.get(TILEAT) != '_Z25tileAtWorldPositionLoadediiP5World':
        raise ValueError('tileAtWorldPositionLoaded symbol drifted')
    if symbols.get(MAKEPAIR) != '_Z11makeIntpairii':
        raise ValueError('makeIntpair symbol drifted')

    cells = {}
    for cell, expected_slot, kind, name, *rest in CELLS:
        slot = (EXPECTED_BASE + signed(memory.word(cell))) & 0xffffffff
        if slot != expected_slot:
            raise ValueError(f'cell {cell:#x} -> {slot:#x}, expected {expected_slot:#x}')
        val = memory.word(slot)
        if kind == 'SEL':
            if cstr(val) != name:
                raise ValueError(f'selector cell {cell:#x} drifted: {cstr(val)}')
        elif kind == 'IVAR':
            if symbols.get(val) != name:
                raise ValueError(f'ivar cell {cell:#x} drifted: {symbols.get(val)}')
            if memory.word(val) != rest[0]:
                raise ValueError(f'ivar offset drifted for {name}')
        elif kind == 'IMP':
            if memory.imports.get(slot) != name:
                raise ValueError(f'import slot {slot:#x} drifted')
        elif kind == 'REF':
            found = False
            for sec in elf.iter_sections():
                if sec.header.sh_type in ('SHT_REL', 'SHT_RELA'):
                    symtab = elf.get_section(sec.header.sh_link)
                    for rel in sec.iter_relocations():
                        if rel['r_offset'] == slot and \
                                symtab.get_symbol(rel['r_info_sym']).name == name:
                            found = True
            if not found:
                raise ValueError(f'classref reloc for {name} at {slot:#x} missing')
        cells[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'kind': kind, 'name': name}
    for cellA, (cellB, add_addr) in PAIR_CELLS.items():
        slot = (signed(memory.word(cellA)) + signed(memory.word(cellB))
                + add_addr + 8) & 0xffffffff
        if slot != 0x00E82430:
            raise ValueError(f'pair cell {cellA:#x} -> {slot:#x}')
        if cstr(memory.word(slot)) != 'recursivelyFlowOutWaterFromTile:atPos:':
            raise ValueError(f'pair selector drifted at {cellA:#x}')

    rows = {}
    for line in text.splitlines():
        m = re.search(r'\b(0x[0-9a-f]{8})\s+[0-9a-f]{8}\s+(.*)', line)
        if m:
            rows[int(m[1], 16)] = m[2].strip().replace('#', '')
    call_sites = {a for a, _ in CALLS}
    listed = {a for a, ins in rows.items()
              if re.match(r'^bl(x?)\s', ins) and a in rows}
    if listed != call_sites:
        raise ValueError(f'bl/blx site set drifted: {sorted(listed ^ call_sites)}')
    for site, flavour in CALLS:
        ins = rows[site]
        if flavour == 'stub':
            if not re.match(r'^bl\s+loc\.imp\.objc_msgSend$', ins):
                raise ValueError(f'{site:#x} route drifted: {ins}')
        elif flavour == 'got':
            if not re.match(r'^blx\s+', ins):
                raise ValueError(f'{site:#x} route drifted: {ins}')
        elif flavour == 'rand':
            if bl_target(site, memory.word(site)) != RAND_FUNC:
                raise ValueError(f'{site:#x} rand target drifted')
        elif flavour == 'plt-idiv':
            if bl_target(site, memory.word(site)) != IDIV_PLT:
                raise ValueError(f'{site:#x} idiv PLT drifted')
        elif flavour == 'plt-modsi3':
            if bl_target(site, memory.word(site)) != MODSI3_PLT:
                raise ValueError(f'{site:#x} modsi3 PLT drifted')
        elif flavour == 'tileat':
            if bl_target(site, memory.word(site)) != TILEAT:
                raise ValueError(f'{site:#x} tileAt target drifted')
        elif flavour == 'makepair':
            if bl_target(site, memory.word(site)) != MAKEPAIR:
                raise ValueError(f'{site:#x} makeIntpair target drifted')
    for addr, dest in BRANCHES:
        got = b_target(addr, memory.word(addr))
        if got != dest:
            raise ValueError(f'branch {addr:#x} -> {got:#x}, expected {dest:#x}')

    return {
        'method': 'WorldTileLoader -[refineTerrain]',
        'types': 'v8@0:4',
        'elf_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        'imp': f'0x{START:08x}',
        'arm_exidx_end': f'0x{END:08x}',
        'verified_words': words,
        'pic_base_r2': f'0x{base2:08x}',
        'pic_base_r8': f'0x{base8:08x}',
        'dispatch_slot': f'0x{DISPATCH_SLOT:08x}',
        'dispatch_slot_import': 'objc_msgSend',
        'cells': cells,
        'call_sites': [{'site': f'0x{a:08x}', 'flavour': f} for a, f in CALLS],
        'call_site_count': len(CALLS),
        'branches': [{'address': f'0x{a:08x}', 'destination': f'0x{d:08x}'}
                     for a, d in BRANCHES],
        'branch_count': len(BRANCHES),
        'direct_functions': {
            'rand': {'address': f'0x{RAND_FUNC:08x}',
                     'note': 'no symbol; inside initWithWorld IMP range'},
            'tileAtWorldPositionLoaded': {'address': f'0x{TILEAT:08x}',
                                          'symbol': '_Z25tileAtWorldPositionLoadediiP5World'},
            'makeIntpair': {'address': f'0x{MAKEPAIR:08x}',
                            'symbol': '_Z11makeIntpairii'},
        },
        'decision': (
            'pool = [[NSAutoreleasePool alloc] init]; w4 = [world '
            'worldWidthMacro]/4; loop i in [self->refineTerrainCount, '
            'self->refineTerrainCount + w4): pool recycle per iteration '
            '([pool release] + fresh pool); colRock = rockHeights[i]; colDirt '
            '= dirtHeights[i]; 1/8 rand sampling; faultOffset = [self '
            'faultOffsetForX:i y:randX]; carve iff [self isCaveForX:i y:randX '
            'faultOffset:faultOffset] (sxtb); punch(x4 blocks): tile = '
            'tileAtWorldPositionLoaded(x, y, world); if (tile->byte0 != 0x1f) '
            '{ byte0=3; byte4=0xff; byte7=0; [self '
            'recursivelyFlowOutWaterFromTile:tile atPos:makeIntpair(x,y)]; }. '
            'Exit: refineTerrainCount += w4; [world '
            'decommisionAllBlocksBlockToSavePhyscialBlock:1]; if (w*32-1 == '
            'queried value) hasRefinedTerrain = 1 (byte, ivar 104).'),
        'claim': ('static bounded-body map; column-range data flow '
                  '(modX1/modX2/fp-0x44/fp-0x6c interrelations) is census-level; '
                  'no runtime claim'),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'worldtileloader_refineterrain.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale worldtileloader_refineterrain.json')
    else:
        args.output.write_text(payload)
    print(f"words={report['verified_words']} calls={report['call_site_count']} "
          f"branches={report['branch_count']} cells={len(report['cells'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
