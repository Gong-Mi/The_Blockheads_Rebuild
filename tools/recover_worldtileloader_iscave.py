#!/usr/bin/env python3
"""Byte-gated, hand-reviewed WorldTileLoader -[isCaveForX:y:faultOffset:] map.

IMP 0x00857f48 .. ARM.exidx end 0x00858320 (246 words including literal pool),
PIC/GOT base 0x0105faf4 (same GOT family). The checked-in listing is
re-verified word-by-word against the SHA-256-pinned ELF; every
selector/ivar literal, call site, branch target and constant below is
anchored to a verified address and the tool refuses to emit on any drift.

Reviewed semantics (static):
  Rules r1;                                     // 64-byte struct (stret)
  if (self->world) objc_msgSend_stret(&r1, self->world, @selector(customRules));
  else memset(&r1, 0, 0x40);
  if (r1.byte[0xc] == 0) return 0;              // cave gate
  xq   = (x / 32.0f) / (float)[self->world worldWidthMacro];
  yq   = (float)(y - faultOffset) / 32.0f / self->yHeightDivider;  // float ivar
  cave = (float)([self->caveNoiseFunctionA getX:(double)xq Y:(double)yq octaves:2]
                 + 0.05 * [self->caveNoiseFunctionB getX:(double)xq
                            Y:(double)yq octaves:1]);
  cave = fabsf(cave);
  Rules r2;                                     // SECOND identical query
  if (self->world) objc_msgSend_stret(&r2, self->world, @selector(customRules));
  else memset(&r2, 0, 0x40);
  threshold = (r2.byte[0xc] == 2) ? 0.2 : 0.04;
  return cave < threshold;                      // sxtb of the compare result

Static map only: customRules struct layout beyond byte 0xc, NoiseFunction
internals, and all runtime values are outside this body.
"""
import argparse
import hashlib
import io
import json
import re
import struct
from pathlib import Path

from elftools.elf.elffile import ELFFile
from trace_objc_dispatch import ELFMemory
from recover_drawframe_slices import verify_disassembly
from recover_worldtileloader_faultoffset import bl_target, plt_slot

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
START, END = 0x00857F48, 0x00858320
EXPECTED_BASE = 0x0105FAF4
BASE_ADD = 0x00857F58
BASE_LITERAL = 0x00858318
MSGSEND_GOT_SLOT = 0x0105B7A0
STRET_PLT, STRET_SLOT = 0x001C2918, 0x105FB6C
MEMSET_PLT, MEMSET_SLOT = 0x001C2924, 0x105FB70
CHKFAIL_PLT, CHKFAIL_SLOT = 0x001C28B8, 0x105FB4C
GUARD_SLOT = 0x0105B7E0

SELECTOR_CELLS = {
    'customRules': (0x008582F0, 0x00E823F4),
    'getX:Y:octaves:': (0x00858300, 0x00E82420),
    'worldWidthMacro': (0x00858314, 0x00E823A8),
}
IVAR_CELLS = {
    'world': (0x008582F4, 0x0105DD4C),
    'caveNoiseFunctionA': (0x00858308, 0x0105DD78),
    'caveNoiseFunctionB': (0x00858304, 0x0105DD74),
    'yHeightDivider': (0x0085830C, 0x0105DD48),
}
DOUBLE_CELLS = {
    0x008582D8: 0.04,
    0x008582E0: 0.05,
    0x008582E8: 0.2,
}
FLOAT_CELLS = {0x00858310: 32.0}

MSGSENDS = (
    (0x008580DC, 'blx lr', 'worldWidthMacro',
     'world (self+ivar 4): loaded 0x0085808c..0x0085809c; float arg s0 = '
     'x/32.0f ([sp+0x50]); result int -> float, xq = (x/32)/w -> [sp+0x94]'),
    (0x0085816C, 'blx lr', 'getX:Y:octaves:',
     'caveNoiseFunctionA (self+ivar 4 via slot 0x0105dd78): loaded '
     '0x0085812c..0x0085813c; X=(double)xq r2:r3, Y=(double)yq at [sp], '
     'octaves=2 at [sp+8] (movw r7,2 0x0085804c); result double -> [sp+0x8c]'),
    (0x008581BC, 'blx lr', 'getX:Y:octaves:',
     'caveNoiseFunctionB (self+ivar 8 via slot 0x0105dd74): loaded '
     '0x0085817c..0x0085818c; X=(double)xq, Y=(double)yq at [sp], octaves=1 '
     'at [sp+8] (movw ip,1 0x0085802c); result double * 0.05 -> [sp+0x88]'),
)
STRET_CALLS = (
    (0x00857FCC, 'objc_msgSend_stret', 'customRules',
     'sret dst &fp-0x60 (sub r0,fp,0x60 0x00857fc0), receiver self->world '
     '(loaded 0x00857f98..0x00857fa4 via slot 0x0105dd4c), nil-guarded '
     '(beq 0x00857fbc -> memset 0x00857fd4..0x00857ff0); 64-byte struct '
     '(movw r2,0x40); gate byte read ldrsb [fp,-0x54] = struct offset 0xc'),
    (0x00858234, 'objc_msgSend_stret', 'customRules',
     'SECOND identical query: sret dst &fp-0xa0, receiver self->world '
     '(reloaded 0x00858200..0x00858208), nil-guarded (beq 0x00858224 -> '
     'memset); selector byte read ldrsb [fp,-0x94] = struct offset 0xc; '
     'value 2 selects threshold 0.2 over 0.04 (bne 0x00858264)'),
)
PLT_CALLS = (
    (0x00857FF0, MEMSET_PLT, MEMSET_SLOT, 'memset',
     'nil path: memset(&fp-0x60, 0, 0x40)'),
    (0x00858258, MEMSET_PLT, MEMSET_SLOT, 'memset',
     'nil path 2: memset(&fp-0xa0, 0, 0x40)'),
    (0x008582D0, CHKFAIL_PLT, CHKFAIL_SLOT, '__stack_chk_fail',
     'canary mismatch path: guard slot 0x0105b7e0 loaded at 0x00857f74, '
     'compared at 0x008582ac..0x008582bc'),
)
BRANCHES = (
    (0x00857FBC, 0x00857FD4, 'beq: self->world == nil -> memset struct path'),
    (0x00857FD0, 0x00857FF4, 'b: stret done -> join'),
    (0x00857FFC, 0x0085800C, 'bne: r1.byte[0xc] != 0 -> cave computation'),
    (0x00858008, 0x0085829C, 'b: gate byte == 0 -> return 0'),
    (0x00858224, 0x0085823C, 'beq: self->world == nil -> memset struct 2'),
    (0x00858238, 0x0085825C, 'b: stret 2 done -> join'),
    (0x00858264, 0x00858270, 'bne: r2.byte[0xc] != 2 -> keep threshold 0.04'),
    (0x00858284, 0x00858294, 'bpl: cave >= threshold -> return 0'),
    (0x00858290, 0x0085829C, 'b: return 1 join'),
    (0x008582BC, 0x008582D0, 'bne: canary mismatch -> __stack_chk_fail'),
)


def signed(v):
    return v - (1 << 32) if v & 0x80000000 else v


def recover(path: Path) -> dict:
    memory = ELFMemory(path)
    text = (NATIVE / 'disasm_worldtileloader_iscave.txt').read_text()
    words = verify_disassembly(memory, text, START, END)

    base = (BASE_ADD + 8 + signed(memory.word(BASE_LITERAL))) & 0xffffffff
    if base != EXPECTED_BASE:
        raise ValueError(f'PIC base drift {base:#x}')

    def cstr(addr):
        off = memory.offset(addr, 1)
        if off is None:
            return None
        end = memory.data.find(b'\0', off, off + 256)
        return memory.data[off:end].decode('utf-8', 'replace') if end >= 0 else None

    elf = ELFFile(io.BytesIO(path.read_bytes()))
    symbols = {s['st_value']: s.name
               for s in elf.get_section_by_name('.dynsym').iter_symbols()}

    if memory.imports.get(MSGSEND_GOT_SLOT) != 'objc_msgSend':
        raise ValueError('msgSend GOT slot evidence changed')
    if memory.imports.get(GUARD_SLOT) != '__stack_chk_guard':
        raise ValueError('stack guard slot evidence changed')
    for plt, slot, name in ((STRET_PLT, STRET_SLOT, 'objc_msgSend_stret'),
                            (MEMSET_PLT, MEMSET_SLOT, 'memset'),
                            (CHKFAIL_PLT, CHKFAIL_SLOT, '__stack_chk_fail')):
        if plt_slot(memory, plt) != slot or memory.imports.get(slot) != name:
            raise ValueError(f'{name} PLT/JUMP_SLOT evidence changed')

    selectors = {}
    for name, (cell, expected_slot) in SELECTOR_CELLS.items():
        slot = (base + signed(memory.word(cell))) & 0xffffffff
        if slot != expected_slot:
            raise ValueError(f'selector cell {cell:#x} -> {slot:#x}, '
                             f'expected {expected_slot:#x}')
        got = cstr(memory.word(slot))
        if got != name:
            raise ValueError(f'selector cell drifted at {cell:#x}: {got}')
        selectors[name] = {'cell': f'0x{cell:08x}', 'slot': f'0x{slot:08x}'}

    ivars = {}
    for name, (cell, expected_slot) in IVAR_CELLS.items():
        slot = (base + signed(memory.word(cell))) & 0xffffffff
        if slot != expected_slot:
            raise ValueError(f'ivar cell {cell:#x} -> {slot:#x}, '
                             f'expected {expected_slot:#x}')
        entry = memory.word(slot)
        symbol = symbols.get(entry, '')
        if not symbol.startswith('OBJC_IVAR_$_WorldTileLoader.'):
            raise ValueError(f'ivar cell drifted at {cell:#x}: {symbol}')
        ivars[name] = {'cell': f'0x{cell:08x}', 'slot': f'0x{slot:08x}',
                       'symbol': symbol, 'offset': memory.word(entry)}

    constants = {}
    for cell, expected in DOUBLE_CELLS.items():
        off = memory.offset(cell, 1)
        got = struct.unpack('<d', memory.data[off:off + 8])[0]
        if got != expected:
            raise ValueError(f'pool double drifted at {cell:#x}: {got!r}')
        constants[f'0x{cell:08x}'] = {'kind': 'double', 'value': got}
    for cell, expected in FLOAT_CELLS.items():
        got = struct.unpack('<f', struct.pack('<I', memory.word(cell)))[0]
        if got != expected:
            raise ValueError(f'pool float drifted at {cell:#x}: {got!r}')
        constants[f'0x{cell:08x}'] = {'kind': 'float', 'value': got}

    rows = {}
    for line in text.splitlines():
        m = re.search(r'\b(0x[0-9a-f]{8})\s+[0-9a-f]{8}\s+(.*)', line)
        if m:
            rows[int(m[1], 16)] = m[2].strip().replace('#', '')
    call_sites = {s for s, _, _, _ in MSGSENDS} | {s for s, _, _, _ in STRET_CALLS} | {s for s, *_ in PLT_CALLS}
    listed = {a for a, ins in rows.items()
              if re.match(r'^bl(x?)\s', ins) and a in rows}
    if listed != call_sites:
        raise ValueError(f'bl/blx site set drifted: {sorted(listed ^ call_sites)}')
    for site, route, _sel, _recv in MSGSENDS:
        if not re.match(rf'^{route}$', rows[site]):
            raise ValueError(f'{site:#x} route drifted: {rows[site]}')
    for site, _name, _sel, _note in STRET_CALLS:
        got = bl_target(site, memory.word(site))
        if got != STRET_PLT:
            raise ValueError(f'{site:#x} no longer targets stret PLT: {got:#x}')
    for site, plt, _slot, _name, _note in PLT_CALLS:
        got = bl_target(site, memory.word(site))
        if got != plt:
            raise ValueError(f'{site:#x} bl targets {got:#x}, expected {plt:#x}')
    for addr, dest, _cond in BRANCHES:
        ins = rows.get(addr, '')
        m = re.match(r'^(b\w*)\s+(0x[0-9a-f]+)', ins)
        if not m or int(m[2], 16) != dest:
            raise ValueError(f'branch {addr:#x} drifted: {ins!r} -> {dest:#x}')

    calls = [{'site': f'0x{s:08x}', 'route': r, 'selector': sel,
              'receiver_route': recv} for s, r, sel, recv in MSGSENDS]
    calls += [{'site': f'0x{s:08x}', 'route': 'bl PLT', 'callee': n,
               'selector': sel, 'note': note} for s, n, sel, note in STRET_CALLS]
    calls += [{'site': f'0x{s:08x}', 'route': 'bl PLT', 'callee': n,
               'note': note} for s, _p, _sl, n, note in PLT_CALLS]
    return {
        'method': 'WorldTileLoader -[isCaveForX:y:faultOffset:]',
        'types': 'c20@0:4i8i12i16',
        'elf_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        'imp': f'0x{START:08x}',
        'arm_exidx_end': f'0x{END:08x}',
        'verified_words': words,
        'pic_base': f'0x{base:08x}',
        'msgsend_got_slot': f'0x{MSGSEND_GOT_SLOT:08x}',
        'selectors': selectors,
        'ivars': ivars,
        'constants': constants,
        'calls': calls,
        'branches': [{'address': f'0x{a:08x}', 'destination': f'0x{d:08x}',
                      'condition': c} for a, d, c in BRANCHES],
        'decision': (
            'Rules r1 = [self->world customRules] (stret, 64 bytes, memset-0 '
            'nil path); if r1.byte[0xc] == 0 return 0. xq = (x/32.0f)/'
            '(float)[world worldWidthMacro]; yq = (float)(y-faultOffset)/32.0f/'
            'self->yHeightDivider (float ivar). cave = fabsf((float)('
            '[caveNoiseFunctionA getX:xq Y:yq octaves:2] + 0.05*'
            '[caveNoiseFunctionB getX:xq Y:yq octaves:1])). Rules r2 = SECOND '
            'identical [world customRules] query; threshold = (r2.byte[0xc]==2)'
            ' ? 0.2 : 0.04. return cave < threshold (sxtb).'),
        'claim': ('static bounded-body map with per-instruction anchors; '
                  'customRules struct layout beyond byte 0xc, NoiseFunction '
                  'internals and runtime values are outside this body'),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'worldtileloader_iscave.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale worldtileloader_iscave.json')
    else:
        args.output.write_text(payload)
    print(f"words={report['verified_words']} calls={len(report['calls'])} "
          f"branches={len(report['branches'])} ivars={len(report['ivars'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
