#!/usr/bin/env python3
"""Byte-gated map for WorldTileLoader -[getInitialRockAndDirtHeightforX:rockHeight:dirtHeight:] and
its ClientTileLoader sibling at 0x00947af8.

IMP 0x00855ad0 .. next-IMP boundary 0x00856d18 (1170 words including literal pools).
No ARM.exidx entry: the bounded region is pinned by the next method IMP
(-[faultOffsetForX:y:] at 0x00856d18, whose own exidx end is 0x00857188).
PIC/GOT base 0x0105faf4 (same GOT as the GameView family). The checked-in
listing is re-verified word-by-word against the SHA-256-pinned ELF.

Reviewed semantics (static, evidence per block below):
  self+0x04 world; out params rockHeight=[r2], dirtHeight=[r3]
  w = [self->world worldWidthMacro]                       (blx 0x00855d24)
  xq = (x / 32.0f) / (float)w
  A = heightNoiseFunctionA  (self+16)  getX:Y:octaves: with
      X=(double)(xq + 0.05f), Y=7.0, octaves=1            (blx 0x00855da0)
  B = heightNoiseFunctionB  (self+20)  getX:Y:octaves: with
      X=(double)(xq + 0.07f), Y=7.0, octaves=(w>=3?w+2:3)  (blx 0x00855e20)
  C = caveNoiseFunctionA    (self+16? see json) getX with
      X=(double)(xq + 0.05f), Y=(double)(cave+0.05f), octaves=(w>=3?w+2:3)  (blx 0x00855e8c)
  A' = linearInterpolate(clamp(0.2*n + 0.8, 0, 1), base+3, caveY) * (2.0f/5.0f)
  ... (full per-phase formula in emitted JSON; conservative per-block notes)

Claim boundary: static bounded-body map. NoiseFunction::getX:Y:octaves:
internals, worldWidthMacro units, runtime values, and the semantics of the
64-byte customRules struct returned by objc_msgSend_stret are outside this
body.
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

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
START, END = 0x00855AD0, 0x00856D18
BASE = 0x0105FAF4
BASE_ADD, BASE_LITERAL = 0x00855AE8, 0x00856A6C  # lr = 0x0105faf4

STRET_PLT, STRET_GOT = 0x001C2918, 0x0105FB6C
MEMSET_PLT, MEMSET_GOT = 0x001C2924, 0x0105FB70
MSGSEND_PLT, MSGSEND_GOT = 0x001C281C, 0x0105B7A0
CLAMP = 0x004BE068
LINERP = 0x00582A14
POWF_PLT, POWF_JUMP_SLOT = 0x001C3F98, 0x10602EC
STACKCHK_GOT = 0x0105B7E0

# literal cell -> (resolved GOT slot, meaning)
CELLS = {
    0x00856A70: (0x00E823F4, 'selector customRules (name unverified: slot points at data)'),
    0x00856A74: (0x0105DD4C, 'OBJC_IVAR_$_WorldTileLoader.world offset 4'),
    0x00856A78: (0x0105B7E0, '__stack_chk_guard'),
    0x00856B44: (0x0105DD4C, 'OBJC_IVAR_$_WorldTileLoader.world offset 4'),
    0x00856C10: (0x0105B7A0, 'objc_msgSend GOT'),
    0x00856C14: (0x00E82420, 'selector getX:Y:octaves:'),
    0x00856C18: (0x0105DD84, 'OBJC_IVAR_$_WorldTileLoader.heightNoiseFunctionB offset 20'),
    0x00856C1C: (0x0105DD88, 'OBJC_IVAR_$_WorldTileLoader.heightNoiseFunctionA offset 16'),
    0x00856C20: (0x00E823A8, 'selector worldWidthMacro'),
    0x00856CE8: (0x00E823F4, 'selector customRules'),
    0x00856CEC: (0x0105DD4C, 'OBJC_IVAR_$_WorldTileLoader.world offset 4'),
    0x00856CF0: (0x0105B7E0, '__stack_chk_guard'),
    0x00856CF4: (0x0105B7A0, 'objc_msgSend GOT'),
    0x00856CF8: (0x00E82420, 'selector getX:Y:octaves:'),
    0x00856CFC: (0x0105DD84, 'heightNoiseFunctionB offset 20'),
    0x00856D00: (0x0105DD88, 'heightNoiseFunctionA offset 16'),
}
FLOAT_CELLS = {
    0x00856008: ('float', 0.0),
    0x00856010: ('double', 0.20000000298023224),
    0x00856018: ('double', 0.800000011920929),
    0x00856020: ('float', 0.05000000074505806),
    0x00856024: ('float', 0.07000000029802322),
    0x00856028: ('double', 0.30000001192092896),
    0x00856030: ('float', 0.10000000149011612),
    0x00856034: ('float', 32.0),
    0x00856288: ('float', 0.05999999865889549),
    0x00856A64: ('float', 0.05999999865889549),
    0x00856A68: ('float', 0.10000000149011612),
    0x00856CE0: ('double', 512.0),
    0x00856D04: ('float', 32.0),
    0x00856D08: ('float', 512.0),
    0x00856D0C: ('float', 511.25),
    0x00856D10: ('float', 512.25),
}
# All 15 objc_msgSend_stret sites (customRules fetch) in body order.
STRET_SITES = (
    0x00855B68, 0x00855BF0, 0x00855F68, 0x00856000, 0x00856108,
    0x008561DC, 0x00856280, 0x008565E0, 0x00856678, 0x00856750,
    0x00856824, 0x008568C8, 0x00856990, 0x00856A5C, 0x00856C08,
)
MEMSET_SITES = (
    0x00855B8C, 0x00855C14, 0x00855F8C, 0x00856054, 0x0085612C,
    0x00856200, 0x008562A8, 0x00856604, 0x0085669C, 0x00856774,
    0x00856848, 0x008568EC, 0x008569B4, 0x00856A98, 0x00856C40,
)
# Getter blx sites (indirect via GOT-loaded stubs) with reviewed receiver/args.
GETTER_CALLS = (
    (0x00855D24, 'blx r3', 'worldWidthMacro',
     'world (self+ivar 4): loaded 0x00855cb8..0x00855cc4; result int; '
     'xq = (x/32.0f)/w stored [rule+0x38]'),
    (0x00855DA0, 'blx r4', 'getX:Y:octaves:',
     'heightNoiseFunctionA (self+ivar 16): loaded 0x00855d48..0x00855d58; '
     'X=(double)(xq+0.05f), Y=7.0, octaves=[sp+0x228] (3 default)'),
    (0x00855E20, 'blx r4', 'getX:Y:octaves:',
     'heightNoiseFunctionB: X=(double)(xq+0.07f), Y=7.0, '
     'octaves=[sp+0x228]+2 (w>=3 gate at 0x00855b98)'),
    (0x00855E8C, 'blx lr', 'getX:Y:octaves:',
     'caveNoiseFunctionA: X=(double)(xq+0.05f), Y=(double)(cave+0.05f), '
     'octaves from [sp+0x228] chain'),
    (0x0085641C, 'blx r5', 'getX:Y:octaves:',
     'second A-family call: X=(double)(xq+0.05f) recomputed from [rule+0x38], '
     'Y=7.0, octaves=[sp+0x228]'),
    (0x00856498, 'blx r4', 'getX:Y:octaves:',
     'second B-family call: X=(double)(xq+0.07f), Y=7.0, '
     'octaves=[sp+0x228]+2'),
    (0x00856504, 'blx lr', 'getX:Y:octaves:',
     'cave B call: X=(double)(xq+0.05f), Y=(double)(cave+0.07f), '
     'octaves chain'),
)
DIRECT_CALLS = (
    (0x00855EC8, 'bl', CLAMP, '_Z5clampfff', 'clamp(0.2*n+0.8, lo, hi)'),
    (0x00855EF0, 'bl', LINERP, '_Z17linearInterpolatefff', 'interp rock base'),
    (0x00856540, 'bl', CLAMP, '_Z5clampfff', 'clamp dirt side'),
    (0x00856568, 'bl', LINERP, '_Z17linearInterpolatefff', 'interp dirt base'),
    (0x00856174, 'bl', POWF_PLT, '__wrap_powf', 'powf(2, n) ridge'),
    (0x008567BC, 'bl', POWF_PLT, '__wrap_powf', 'powf(2, n) dirt ridge'),
    (0x00856CDC, 'bl', 0x001C28B8, '__stack_chk_fail', 'stack guard fail'),
)
# Core conditional branches (reviewed subset, each anchored).
BRANCHES = (
    (0x00855B58, 0x00855B70, 'beq: nil customRules (world ivar chain) -> zero struct'),
    (0x00855B98, 0x00855BA8, 'bne: skip w>=3 octaves write'),
    (0x00855BE0, 0x00855BF8, 'beq: nil gate -> memset 0x40'),
    (0x00855C20, 0x00855C2C, 'bne: rule byte fp-0xcd == 3 -> rock=4 preset'),
    (0x008560BC, 0x00856194, 'bpl: |n| >= 0.1 -> ridge family'),
    (0x0085613C, 0x00856194, 'beq: rule byte == 4 -> skip powf'),
    (0x00856210, 0x00856228, 'bne: rule byte fp-0xd6 != 4 -> inline negate gate'),
    (0x00856234, 0x008562CC, 'beq: mirror-rule byte sp+0x20f == 0 -> skip negate'),
    (0x008562B8, 0x008562CC, 'beq: skip negate'),
    (0x00856704, 0x008567DC, 'bpl: dirt |n| >= 0.1 -> ridge'),
    (0x00856784, 0x008567DC, 'beq: skip dirt ridge rule'),
    (0x00856AA8, 0x00856BC0, 'bne: rule byte sp+0x28b != 0 -> skip final clamp pair'),
    (0x00856AC4, 0x00856B48, 'ble: rock <= dirt -> rock-dirt delta path'),
    (0x00856B00, 0x00856B14, 'ble: rock > 512 -> clamp rock to 512.25'),
    (0x00856B80, 0x00856B94, 'ble: dirt > 512 -> clamp dirt'),
    (0x00856C50, 0x00856CB0, 'bne: rule byte sp+0x24b != 1 -> skip +/-2.5 shift'),
)


def signed(v):
    return v - (1 << 32) if v & 0x80000000 else v


def bl_target(site, word):
    if word >> 24 != 0xEB:
        raise ValueError(f'{site:#x} is not ARM bl: {word:#x}')
    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 1 << 24
    return (site + 8 + (imm << 2)) & 0xFFFFFFFF


def ror(v, n):
    n &= 31
    return ((v >> n) | (v << (32 - n))) & 0xFFFFFFFF


def imm12(word):
    return ror(word & 0xFF, 2 * ((word >> 8) & 0xF))


def plt_slot(memory, plt):
    def fields(w):
        return {'ls': (w >> 20) & 0xFF, 'rn': (w >> 16) & 0xF,
                'rd': (w >> 12) & 0xF, 'off': w & 0xFFF}
    w0, w1, w2 = fields(memory.word(plt)), fields(memory.word(plt + 4)), fields(memory.word(plt + 8))
    if not (w0['ls'] == 0x28 and w0['rn'] == 0xF and w0['rd'] == 0xC):
        raise ValueError(f'{plt:#x} is not add ip, pc, #imm')
    if not (w1['ls'] == 0x28 and w1['rn'] == 0xC and w1['rd'] == 0xC):
        raise ValueError(f'{plt+4:#x} is not add ip, ip, #imm')
    if not (w2['ls'] == 0x5B and w2['rn'] == 0xC and w2['rd'] == 0xF):
        raise ValueError(f'{plt+8:#x} is not ldr pc, [ip, #off]!')
    ip = (plt + 8 + imm12(memory.word(plt)) + imm12(memory.word(plt + 4))) & 0xFFFFFFFF
    return (ip + w2['off']) & 0xFFFFFFFF


def recover(path: Path) -> dict:
    memory = ELFMemory(path)
    text = (NATIVE / 'disasm_worldtileloader_getinitialrockdirt.txt').read_text()
    words = verify_disassembly(memory, text, START, END)

    base = (BASE_ADD + 8 + signed(memory.word(BASE_LITERAL))) & 0xffffffff
    if base != BASE:
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

    if memory.imports.get(STRET_GOT) != 'objc_msgSend_stret':
        raise ValueError('stret GOT evidence changed')
    if memory.imports.get(MEMSET_GOT) != 'memset':
        raise ValueError('memset GOT evidence changed')
    if memory.imports.get(MSGSEND_GOT) != 'objc_msgSend':
        raise ValueError('msgSend GOT evidence changed')
    if memory.imports.get(POWF_JUMP_SLOT) != '__wrap_powf':
        raise ValueError('powf JUMP_SLOT evidence changed')
    for plt, slot in ((STRET_PLT, STRET_GOT), (MEMSET_PLT, MEMSET_GOT), (POWF_PLT, POWF_JUMP_SLOT)):
        got = plt_slot(memory, plt)
        if got != slot:
            raise ValueError(f'{plt:#x} PLT resolves {got:#x}, expected {slot:#x}')

    cells = {}
    for cell, (slot, meaning) in CELLS.items():
        got = (base + signed(memory.word(cell))) & 0xffffffff
        if got != slot:
            raise ValueError(f'cell {cell:#x} -> {got:#x}, expected {slot:#x}')
        entry = memory.word(slot)
        symbol = symbols.get(entry, '')
        sel = None
        if 'selector' in meaning:
            sel = cstr(memory.word(slot)) or cstr(entry)
        cells[f'0x{cell:08x}'] = {
            'slot': f'0x{slot:08x}', 'meaning': meaning,
            'symbol': symbol or None, 'selector_string': sel,
        }

    constants = {}
    for cell, (kind, expected) in FLOAT_CELLS.items():
        if kind == 'float':
            got = struct.unpack('<f', struct.pack('<I', memory.word(cell)))[0]
        else:
            off = memory.offset(cell, 8)
            got = struct.unpack('<d', memory.data[off:off + 8])[0]
        if got != expected:
            raise ValueError(f'pool constant drifted at {cell:#x}: {got!r}')
        constants[f'0x{cell:08x}'] = {'kind': kind, 'value': got}

    rows = {}
    for line in text.splitlines():
        m = re.search(r'\b(0x[0-9a-f]{8})\s+[0-9a-f]{8}\s+(.*)', line)
        if m:
            rows[int(m[1], 16)] = m[2].strip().replace('#', '')

    listed_stret = {a for a in rows if 'objc_msgSend_stret' in rows[a]}
    if listed_stret != set(STRET_SITES):
        raise ValueError(f'stret site set drifted: {sorted(listed_stret ^ set(STRET_SITES))}')
    listed_memset = {a for a in rows if rows[a].startswith('bl sym.imp.memset')}
    if listed_memset != set(MEMSET_SITES):
        raise ValueError(f'memset site set drifted: {sorted(listed_memset ^ set(MEMSET_SITES))}')
    for site, route, sel, note in GETTER_CALLS:
        ins = rows[site]
        if not re.match(rf'^{route}$', ins):
            raise ValueError(f'{site:#x} no longer {route}: {ins}')
    for site, kind, target, sym, note in DIRECT_CALLS:
        if kind != 'bl':
            continue
        got = bl_target(site, memory.word(site))
        if got != target:
            raise ValueError(f'{site:#x} bl targets {got:#x}, expected {target:#x}')
        if symbols.get(target) and symbols[target] != sym and target != POWF_PLT:
            raise ValueError(f'{site:#x} target symbol drifted: {symbols.get(target)}')
    for addr, dest, cond in BRANCHES:
        ins = rows.get(addr, '')
        m = re.match(r'^(b\w*)\s+(0x[0-9a-f]+)', ins)
        if not m or int(m[2], 16) != dest:
            raise ValueError(f'branch {addr:#x} drifted: {ins!r} -> {dest:#x}')

    return {
        'method': 'WorldTileLoader -[getInitialRockAndDirtHeightforX:rockHeight:dirtHeight:]',
        'sibling_imp': '0x00947af8 ClientTileLoader (same selector, separate body)',
        'types': 'v20@0:4i8^f12^f16',
        'elf_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        'imp': f'0x{START:08x}',
        'boundary_end': f'0x{END:08x}',
        'boundary_note': ('no ARM.exidx entry; region closed by next IMP '
                          '-[faultOffsetForX:y:] 0x00856d18'),
        'verified_words': words,
        'pic_base': f'0x{base:08x}',
        'cells': cells,
        'constants': constants,
        'stret_sites': [f'0x{s:08x}' for s in STRET_SITES],
        'memset_sites': [f'0x{s:08x}' for s in MEMSET_SITES],
        'getter_calls': [{'site': f'0x{s:08x}', 'route': r, 'selector': sel,
                          'note': n} for s, r, sel, n in GETTER_CALLS],
        'direct_calls': [{'site': f'0x{s:08x}', 'target': f'0x{t:08x}',
                          'symbol': sym, 'note': n} for s, k, t, sym, n in DIRECT_CALLS],
        'branches': [{'address': f'0x{a:08x}', 'destination': f'0x{d:08x}',
                      'condition': c} for a, d, c in BRANCHES],
        'reviewed_semantics': (
            'w = worldWidthMacro; xq = (x/32)/w. '
            'A = hNFA.getX(xq+0.05, 7, oct=w>=3?w+2:3); '
            'B = hNFB.getX(xq+0.07, 7, same oct); '
            'caveA = cNFA.getX(xq+0.05, cave+0.05, oct); '
            'caveB = cNFB.getX(xq+0.05, cave+0.07, oct). '
            'rock = clamp(0.2*A+0.8, 0, 1) interp base; ridge powf(2, n) '
            'gated by |n| >= 0.1 and customRules bytes; dirt mirrors '
            'with own offsets; final pair clamp to [511.25, 512.25] with '
            'delta preserved; optional +/-2.5 shift gated by rule byte.'),
        'claim': ('static bounded-body map; 15 customRules struct fetches '
                  '(objc_msgSend_stret, 0x40-byte results) gate the formula '
                  'phases; NoiseFunction internals, customRules struct field '
                  'semantics beyond byte equality, and runtime values are '
                  'outside this body'),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'worldtileloader_getinitialrockdirt.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale worldtileloader_getinitialrockdirt.json')
    else:
        args.output.write_text(payload)
    print(f"words={report['verified_words']} stret=15 memset=15 getters=7 "
          f"direct={len(report['direct_calls'])} branches={len(report['branches'])} "
          f"constants={len(report['constants'])} cells={len(report['cells'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
