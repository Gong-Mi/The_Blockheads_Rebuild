#!/usr/bin/env python3
"""Byte-gated, hand-reviewed WorldTileLoader -[faultOffsetForX:y:] evidence map.

IMP 0x00856d18 .. ARM.exidx end 0x00857188 (284 words including literal pool),
PIC/GOT base 0x0105faf4 (same GOT as the GameView family). The checked-in
listing is re-verified word-by-word against the SHA-256-pinned ELF; every
selector/ivar literal, call site, branch target and float constant below is
anchored to a verified address and the tool refuses to emit on any drift.

Reviewed semantics (static): normalized-coordinate fault-profile computation.
  w    = [self->world worldWidthMacro]            (queried 3x, 3 msgSends)
  xq   = (x / 32.0f) / (float)w
  yq   = (y / 64.0f) / (float)w                   (y / 2.0f / 32.0f)
  if (w >= 512) yq = (y / 64.0f) / 512.0f
  band = clamp(0.8 * [self->heightNoiseFunctionB getX:(double)(xq + 0.05f)
                     Y:7.0 octaves:1] + 0.2, 0.0f, 1.0f)
  a    = | (float)[self->faultNoiseFunction getX:(double)xq Y:(double)yq
                   octaves:1] |
  shaped = 0                        if a <= 0
           powf(2a, 2)              if 0 < a < 0.2
           powf(max(2(a-0.2),0),2) + 5*band   if a >= 0.2
  return (int)(512.0f * shaped * band)          (vcvt.s32.f32 truncation)

Static map only: NOT a proof of NoiseFunction::getX:Y:octaves: internals,
worldWidthMacro units, or any runtime value.
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
START, END = 0x00856D18, 0x00857188
EXPECTED_BASE = 0x0105FAF4
BASE_ADD = 0x00856D2C
BASE_LITERAL = 0x00857184
MSGSEND_GOT_SLOT = 0x0105B7A0   # import slot reloaded for all five msgSends
POWF_PLT = 0x001C3F98
POWF_JUMP_SLOT = 0x10602EC      # R_ARM_JUMP_SLOT __wrap_powf
CLAMP_TARGET = 0x004BE068       # _Z5clampfff

SELECTOR_CELLS = {
    'worldWidthMacro': (0x0085715C, 0x00E823A8),
    'getX:Y:octaves:': (0x0085716C, 0x00E82420),
}
IVAR_CELLS = {
    'world': (0x00857160, 0x0105DD4C),
    'faultNoiseFunction': (0x00857170, 0x0105DD7C),
    'heightNoiseFunctionB': (0x0085717C, 0x0105DD84),
}
FLOAT_CELLS = {
    0x00857144: ('float', 32.0),
    0x00857164: ('float', 32.0),
    0x00857168: ('float', 512.0),
    0x00857174: ('float', 0.0),
    0x00857178: ('float', 0.05000000074505806),
    0x00857180: ('float', 0.20000000298023224),
    0x00857148: ('double', 0.20000000298023224),
    0x00857150: ('double', 0.800000011920929),
}

# Reviewed dispatch sites: exactly the eight bl/blx instructions in this body.
MSGSENDS = (
    (0x00856DB0, 'blx lr', 'worldWidthMacro',
     'world (self+ivar 4): loaded 0x00856d78..0x00856d84; x/32.0f in s0; '
     'result int -> float, xq = (x/32)/w stored fp-0x2c'),
    (0x00856E08, 'blx r3', 'worldWidthMacro',
     'world reloaded 0x00856de4..0x00856df4; (y/64.0f) in s0; '
     'yq = (y/64)/w stored fp-0x30'),
    (0x00856E40, 'blx r3', 'worldWidthMacro',
     'world reloaded 0x00856e20..0x00856e30, s0 still yq (unused arg slot); '
     'result compared >= 0x200 (bge 0x00856e48): if w >= 512, yq recomputed '
     'as (y/64)/512.0f in the 0x00856e4c..0x00856e88 block'),
    (0x00856F30, 'blx r4', 'getX:Y:octaves:',
     'heightNoiseFunctionB (self+ivar 0x14): loaded 0x00856ec8..0x00856edc; '
     'args: X=(double)(xq+0.05f) in r2:r3, Y=7.0 at [sp], octaves=1 at '
     '[sp+8]; result double; band source = 0.8*n + 0.2 (d3=0.8, d2=0.2)'),
    (0x00856FDC, 'blx lr', 'getX:Y:octaves:',
     'faultNoiseFunction (self+ivar 0x18): loaded 0x00856f88..0x00856fa0; '
     'args: X=(double)xq in r2:r3, Y=(double)yq at [sp], octaves=1 at '
     '[sp+8]; result double -> fabsf'),
)
DIRECT_CALLS = (
    (0x00856F68, 'bl', CLAMP_TARGET, '_Z5clampfff',
     'clamp(value, 0.0f, 1.0f): r0 = 0.8*n+0.2 (s0), r1 = 0.0f ([sp+0x48]), '
     'r2 = 1.0f ([sp+0x3c]); result stored fp-0x34'),
    (0x00857044, 'bl', POWF_PLT, '__wrap_powf',
     'powf(2a, 2.0f): taken when 0 < a < 0.2 (bpl 0x00857018 not taken); '
     'args r0 = 2a (s2), r1 = 2.0f (s0); result becomes shaped'),
    (0x008570E0, 'bl', POWF_PLT, '__wrap_powf',
     'powf(max(2(a-0.2), 0), 2.0f): taken when a >= 0.2; r0 = t ([fp-0x48] '
     'via fp-0x3c), r1 = 2.0f (s2); shaped = result + 5.0f*band'),
)
BRANCHES = (
    (0x00856E48, 0x00856E8C, 'bge: worldWidthMacro >= 512 -> yq recompute '
                           '(y/64)/512.0f with stack consts 512/2/32'),
    (0x00857004, 0x00857108, 'ble: |fault| <= 0.0 -> shaped stays 0 '
                            '(falls into final scale)'),
    (0x00857018, 0x00857054, 'bpl: |fault| >= 0.2 -> ridge block '
                            '(t = max(2(a-0.2), 0), +5*band)'),
    (0x00857050, 0x00857104, 'b: join after powf(2a,2) block'),
    (0x0085709C, 0x008570AC, 'bpl: 2(a-0.2) >= 0 -> t = 2(a-0.2) else t = 0'),
    (0x008570A8, 0x008570B4, 'b: join into t^2'),
    (0x00857104, 0x00857108, 'b: join into final scale'),
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


def ror(v, n):
    n &= 31
    return ((v >> n) | (v << (32 - n))) & 0xFFFFFFFF


def imm12(word):
    """ARM modified immediate: imm8 rotated right by 2*rot."""
    return ror(word & 0xFF, 2 * ((word >> 8) & 0xF))


def plt_slot(memory, plt):
    """Resolve `ldr pc, [ip, #off]!` target of a 3-instruction ARM PLT."""
    def fields(w):
        return {'dp': (w >> 26) & 3 == 0, 'imm': (w >> 25) & 1 == 1,
                'op': (w >> 21) & 0xF, 's': (w >> 20) & 1,
                'rn': (w >> 16) & 0xF, 'rd': (w >> 12) & 0xF,
                'ls': (w >> 20) & 0xFF, 'off': w & 0xFFF}
    w0, w1, w2 = (fields(memory.word(plt)), fields(memory.word(plt + 4)),
                  fields(memory.word(plt + 8)))
    if not (w0['dp'] and w0['imm'] and w0['op'] == 4 and w0['s'] == 0
            and w0['rn'] == 0xF and w0['rd'] == 0xC):
        raise ValueError(f'{plt:#x} is not add ip, pc, #imm')
    if not (w1['dp'] and w1['imm'] and w1['op'] == 4 and w1['s'] == 0
            and w1['rn'] == 0xC and w1['rd'] == 0xC):
        raise ValueError(f'{plt+4:#x} is not add ip, ip, #imm')
    if not ((memory.word(plt + 8) >> 26) & 3 == 1 and w2['ls'] == 0x5B
            and w2['rn'] == 0xC and w2['rd'] == 0xF):
        raise ValueError(f'{plt+8:#x} is not ldr pc, [ip, #off]!')
    w0r, w1r = memory.word(plt), memory.word(plt + 4)
    ip = (plt + 8 + imm12(w0r) + imm12(w1r)) & 0xFFFFFFFF
    return (ip + w2['off']) & 0xFFFFFFFF


def recover(path: Path) -> dict:
    memory = ELFMemory(path)
    text = (NATIVE / 'disasm_worldtileloader_faultoffset.txt').read_text()
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
    for cell, (kind, expected) in FLOAT_CELLS.items():
        if kind == 'float':
            got = struct.unpack('<f', struct.pack('<I', memory.word(cell)))[0]
        else:
            off = memory.offset(cell, 1)
            got = struct.unpack('<d', memory.data[off:off + 8])[0]
        if got != expected:
            raise ValueError(f'pool constant drifted at {cell:#x}: {got!r}')
        constants[f'0x{cell:08x}'] = {'kind': kind, 'value': got}

    # Instruction-level cross-check against the verified listing.
    rows = {}
    for line in text.splitlines():
        m = re.search(r'\b(0x[0-9a-f]{8})\s+[0-9a-f]{8}\s+(.*)', line)
        if m:
            rows[int(m[1], 16)] = m[2].strip().replace('#', '')
    dispatch_sites = {s for s, _, _, _ in MSGSENDS} | {s for s, _, _, _, _ in DIRECT_CALLS}
    listed = {a for a, ins in rows.items()
              if re.match(r'^bl(x?)\s', ins) and a in rows}
    if listed != dispatch_sites:
        raise ValueError(f'bl/blx site set drifted: {sorted(listed ^ dispatch_sites)}')
    for site, route, _sel, _recv in MSGSENDS:
        ins = rows[site]
        if not re.match(rf'^{route}$', ins):
            raise ValueError(f'{site:#x} no longer {route}: {ins}')
    for site, kind, target, sym, _note in DIRECT_CALLS:
        got = bl_target(site, memory.word(site))
        if got != target:
            raise ValueError(f'{site:#x} bl targets {got:#x}, expected {target:#x}')
        if target == POWF_PLT:
            slot = plt_slot(memory, POWF_PLT)
            if slot != POWF_JUMP_SLOT:
                raise ValueError(f'powf PLT resolves to {slot:#x}, '
                                 f'expected {POWF_JUMP_SLOT:#x}')
        elif symbols.get(target) != sym:
            raise ValueError(f'{site:#x} target symbol drifted: '
                             f'{symbols.get(target)}')
    if memory.imports.get(POWF_JUMP_SLOT) != '__wrap_powf':
        raise ValueError('powf JUMP_SLOT evidence changed')
    for addr, dest, _cond in BRANCHES:
        ins = rows.get(addr, '')
        m = re.match(r'^(b\w*)\s+(0x[0-9a-f]+)', ins)
        if not m or int(m[2], 16) != dest:
            raise ValueError(f'branch {addr:#x} drifted: {ins!r} -> {dest:#x}')

    calls = [{'site': f'0x{s:08x}', 'route': r, 'selector': sel,
              'receiver_route': recv} for s, r, sel, recv in MSGSENDS]
    calls += [{'site': f'0x{s:08x}', 'route': k, 'target': f'0x{t:08x}',
               'symbol': sym, 'note': note} for s, k, t, sym, note in DIRECT_CALLS]
    return {
        'method': 'WorldTileLoader -[faultOffsetForX:y:]',
        'types': 'i16@0:4i8i12',
        'elf_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        'imp': f'0x{START:08x}',
        'arm_exidx_end': f'0x{END:08x}',
        'verified_words': words,
        'pic_base': f'0x{base:08x}',
        'msgsend_got_slot': f'0x{MSGSEND_GOT_SLOT:08x}',
        'powf_plt': f'0x{POWF_PLT:08x}',
        'powf_jump_slot': f'0x{POWF_JUMP_SLOT:08x}',
        'selectors': selectors,
        'ivars': ivars,
        'constants': constants,
        'calls': calls,
        'branches': [{'address': f'0x{a:08x}', 'destination': f'0x{d:08x}',
                      'condition': c} for a, d, c in BRANCHES],
        'decision': (
            'w = [self->world worldWidthMacro] (3 separate queries); '
            'xq = (x/32.0f)/(float)w; yq = (y/64.0f)/(float)w; if w >= 512: '
            'yq = (y/64.0f)/512.0f. band = clamp(0.8*[heightNoiseFunctionB '
            'getX:(double)(xq+0.05f) Y:7.0 octaves:1] + 0.2, 0.0f, 1.0f). '
            'a = fabsf((float)[faultNoiseFunction getX:(double)xq Y:(double)yq '
            'octaves:1]); shaped = 0 if a<=0; powf(2a,2) if a<0.2; else '
            'powf(max(2(a-0.2),0),2) + 5*band. return (int)(512.0f*shaped*band), '
            'vcvt.s32.f32 truncation toward zero.'),
        'claim': ('static bounded-body map with per-instruction anchors; '
                  'NoiseFunction internals, worldWidthMacro units and runtime '
                  'values are outside this body'),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'worldtileloader_faultoffset.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale worldtileloader_faultoffset.json')
    else:
        args.output.write_text(payload)
    print(f"words={report['verified_words']} msgSends=5 directCalls=3 "
          f"branches={len(report['branches'])} constants={len(report['constants'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
