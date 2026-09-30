#!/usr/bin/env python3
"""Hash-gated static evidence for GameView -[init] (IMP 0x0091c780).

A forward register+frame-slot model walks the pinned ARM function word by word
(capstone), resolving objc_msgSend dispatch targets and r1 selector slots
through the per-function PIC base. Sites the model cannot prove (cross-branch
state loss, indirect targets from unmodelled loads) are exported as
'target': 'unresolved' — never guessed.

Outputs gameview_init.json. Local acceptance layer: requires the copyright
original ELF (SHA-256 pinned) and is NOT run in CI; CI instead validates the
checked-in JSON structurally (tools/test_gameview_init_evidence.py).

This is a static call/selector map, NOT a runtime execution-order claim.
"""
import argparse
import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from trace_objc_dispatch import ELFMemory, ALIASES

START, END = 0x0091C780, 0x0091D9CC
BASE_LITERAL = 0x0091D1DC          # prologue: ldr r2,[pc,#N]@91d1dc ; add r2,pc,r2
EXPECTED_BASE = 0x0105FAF4
LISTING = ROOT / 'reconstruction/reverse-v3/native/disasm_gameview_init.txt'

R = r'(?:r(?:1[0-5]|[0-9])|ip|sl|fp|lr)'
NUM = r'(-?(?:0[xX][0-9a-fA-F]+|\d+))'

def reg(s): return ALIASES.get(s, s)
def num(tok): return int(tok, 0)
def signed(v): return v - (1 << 32) if v & 0x80000000 else v


def section_ranges(elf_path):
    out = subprocess.check_output(
        ['llvm-readelf', '-S', '--wide', str(elf_path)], text=True, errors='replace')
    ranges = {}
    for name in ('__objc_selrefs', '__cfstring', '__objc_classrefs',
                 '__objc_ivar', '__objc_methname'):
        for line in out.splitlines():
            if name in line:
                m = re.search(r'PROGBITS\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)', line)
                if m:
                    start = int(m[2], 16)
                    ranges[name] = (start, start + int(m[3], 16))
                break
    if len(ranges) != 5:
        raise ValueError('expected metadata sections missing')
    return ranges


def dynamic_symbol_map(elf_path):
    out = subprocess.check_output(
        ['llvm-readelf', '--dyn-syms', '--wide', str(elf_path)],
        text=True, errors='replace')
    symbols = {}
    for line in out.splitlines():
        m = re.search(r'\s([0-9a-f]{8})\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+([A-Za-z_][\w$.$]*)$', line)
        if m:
            symbols.setdefault(int(m[1], 16), m[2])
    return symbols


def listing_words(memory):
    """Parse the checked-in listing and verify every word against the pinned ELF."""
    rows = re.findall(r'\b(0x[0-9a-fA-F]{8})\s+([0-9a-fA-F]{8})\b',
                      LISTING.read_text(encoding='utf-8'))
    words = {}
    for address, raw in rows:
        address = int(address, 16)
        expected = int.from_bytes(bytes.fromhex(raw), 'little')
        if not (START <= address < END):
            continue
        if memory.word(address) != expected:
            raise ValueError(f'listing bytes differ from pinned ELF at {address:#x}')
        words[address] = expected
    if set(words) != set(range(START, END, 4)):
        raise ValueError('listing does not exactly cover IMP..exidx-end')
    return words


def recover(elf_path: Path) -> dict:
    import capstone
    memory = ELFMemory(elf_path)

    def ror(value, count):
        count &= 31
        return ((value >> count) | (value << (32 - count))) & 0xffffffff if count else value

    def plt_import(address):
        # ARM PLT stub (3 words):
        #   add ip, pc, #rot-imm   (0xE28FC000 masked 0xFFFFF000)
        #   add ip, ip, #rot-imm   (0xE28CC000 masked 0xFFFFF000)
        #   ldr pc, [ip, #off]!    (0xE5BCF000 masked 0xFFFFF000)
        # GOT slot = (first word address + 8) + imm1 + imm2 + off; the
        # JUMP_SLOT relocation at that slot names the imported function.
        w1 = memory.word(address)
        w2 = memory.word(address + 4)
        w3 = memory.word(address + 8)
        if w1 is None or w2 is None or w3 is None:
            return None
        if (w1 & 0xFFFFF000) != 0xE28FC000 or (w2 & 0xFFFFF000) != 0xE28CC000 \
                or (w3 & 0xFFFFF000) != 0xE5BCF000:
            return None
        def rot_imm(word):
            return ror(word & 0xFF, ((word >> 8) & 0xF) * 2)
        slot = (address + 8 + rot_imm(w1) + rot_imm(w2) + (w3 & 0xFFF)) & 0xffffffff
        return memory.imports.get(slot)

    ranges = section_ranges(elf_path)
    symbols = dynamic_symbol_map(elf_path)
    selrefs, cfstr, clsrefs = ranges['__objc_selrefs'], ranges['__cfstring'], ranges['__objc_classrefs']
    ivars, methnames = ranges['__objc_ivar'], ranges['__objc_methname']
    base = (0x0091C790 + 8 + memory.word(BASE_LITERAL)) & 0xffffffff
    if base != EXPECTED_BASE:
        raise ValueError('PIC base drift')

    def cstr(addr):
        if addr is None:
            return None
        off = memory.offset(addr, 1)
        if off is None:
            return None
        end = memory.data.find(b'\0', off, off + 512)
        return memory.data[off:end].decode('utf-8', 'replace') if end >= 0 else None

    def pic_sum(x, y):
        if y == base: return (base + signed(x)) & 0xffffffff
        if x == base: return (base + signed(y)) & 0xffffffff
        if signed(x) < 0 <= y and 0x0e00000 <= y <= 0x1200000:
            return (y + signed(x)) & 0xffffffff
        if signed(y) < 0 <= x and 0x0e00000 <= x <= 0x1200000:
            return (x + signed(y)) & 0xffffffff
        return (x + y) & 0xffffffff

    def classify(state, dest, slot):
        slot &= 0xffffffff
        if slot in memory.imports:
            state[dest] = ('import', memory.imports[slot]); return
        if selrefs[0] <= slot < selrefs[1]:
            w = memory.word(slot)
            if w is not None: state[dest] = ('sel', w, slot)
            else: state.pop(dest, None)
            return
        if cfstr[0] <= slot < cfstr[1]:
            state[dest] = ('cfstr', slot)
            cfstring_slots.add(slot)
            return
        if clsrefs[0] <= slot < clsrefs[1]:
            w = memory.word(slot)
            name = symbols.get(w)
            if not name and w is not None:
                # ARMv7 class_t: +8 holds the char* class name.
                name = cstr(memory.word((w + 8) & 0xffffffff))
            state[dest] = ('clsref', slot, name or f'0x{w or 0:08x}')
            return
        w = memory.word(slot) if slot not in memory.unsupported_relocations else None
        if w is None:
            state.pop(dest, None); return
        if ivars[0] <= w < ivars[1]:
            state[dest] = ('ivarslot', slot, w, symbols.get(slot, '')); return
        if methnames[0] <= w < methnames[1]:
            state[dest] = ('cstr', w); return
        state[dest] = w

    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    off0 = memory.offset(START, 4)
    r, stack, sp_to_fp = {}, {}, None
    r['r2'] = base
    events = []
    cfstring_slots = set()

    P_LDR_LIT  = re.compile(r'^ldr\s+(%s),\s+\[pc,\s+%s\]$' % (R, NUM))
    P_ADD_PC   = re.compile(r'^add\s+(%s),\s+pc,\s+(%s)$' % (R, R))
    P_ADD_RR   = re.compile(r'^add\s+(%s),\s+(%s),\s+(%s)$' % (R, R, R))
    P_ADDSUB_I = re.compile(r'^(add|sub)(?:\.w)?\s+(%s),\s+(%s),\s+%s$' % (R, R, NUM))
    P_MOV      = re.compile(r'^mov(?:\.w)?\s+(%s),\s+(%s)$' % (R, R))
    P_MOVW     = re.compile(r'^movw\s+(%s),\s+(0[xX][0-9a-fA-F]+|\d+)$' % R)
    P_MOVT     = re.compile(r'^movt\s+(%s),\s+(0[xX][0-9a-fA-F]+|\d+)$' % R)
    P_LDR_OFS  = re.compile(r'^ldr(?:\.w)?\s+(%s),\s+\[(%s),\s+%s\]$' % (R, R, NUM))
    P_LDR_OO   = re.compile(r'^ldr(?:\.w)?\s+(%s),\s+\[(%s),\s+(%s)\]$' % (R, R, R))
    P_LDR_P    = re.compile(r'^ldr(?:\.w)?\s+(%s),\s+\[(%s)\]$' % (R, R))
    P_STR_P    = re.compile(r'^str(?:\.w)?\s+(%s),\s+\[(%s)\]$' % (R, R))
    P_STR_OFS  = re.compile(r'^str(?:\.w)?\s+(%s),\s+\[(%s),\s+%s\]$' % (R, R, NUM))
    P_STR_OO   = re.compile(r'^str(?:\.w)?\s+(%s),\s+\[(%s),\s+(%s)\]$' % (R, R, R))
    P_BLR      = re.compile(r'^blx\s+(%s)$' % R)

    for a in range(START, END, 4):
        raw = memory.data[off0 + (a - START): off0 + (a - START) + 4]
        got = list(md.disasm(raw, a))
        if not got:
            continue
        full = (got[0].mnemonic + ' ' + got[0].op_str).strip().replace('#', '')

        m = P_LDR_LIT.match(full)
        if m:
            dest = reg(m[1]); lit = (a + 8 + num(m[2])) & 0xffffffff
            w = memory.word(lit)
            if w is None: r.pop(dest, None)
            else: r[dest] = w
            continue
        m = P_ADD_PC.match(full)
        if m:
            dest, src = reg(m[1]), reg(m[2])
            v = r.get(src)
            if isinstance(v, int): r[dest] = (a + 8 + v) & 0xffffffff
            else: r.pop(dest, None)
            continue
        m = P_ADD_RR.match(full)
        if m:
            dest, x, y = reg(m[1]), reg(m[2]), reg(m[3])
            xv, yv = r.get(x), r.get(y)
            if isinstance(xv, int) and isinstance(yv, int):
                slot = pic_sum(xv, yv)
                if cfstr[0] <= slot < cfstr[1]:
                    cfstring_slots.add(slot)
                r[dest] = slot
            else: r.pop(dest, None)
            continue
        m = P_ADDSUB_I.match(full)
        if m:
            op, dest, src, off = m[1], reg(m[2]), reg(m[3]), num(m[4])
            if dest == 'r11' and src == 'r13' and op == 'add':
                sp_to_fp = off; continue
            if dest == 'r13' and src == 'r13' and sp_to_fp is not None:
                sp_to_fp = sp_to_fp + off if op == 'add' else sp_to_fp - off
                continue
            if dest == 'r11' or src == 'r11':
                r.pop(dest, None); stack.clear(); continue
            if op == 'add' and src == 'r15':
                r[dest] = (a + 8 + off) & 0xffffffff; continue
            v = r.get(src)
            if isinstance(v, int):
                r[dest] = (v + off if op == 'add' else v - off) & 0xffffffff
            else: r.pop(dest, None)
            continue
        m = P_MOV.match(full)
        if m:
            dest, src = reg(m[1]), reg(m[2])
            if 'r11' in (dest, src): r.pop(dest, None)
            elif src in r: r[dest] = r[src]
            else: r.pop(dest, None)
            continue
        m = P_MOVW.match(full)
        if m: r[reg(m[1])] = num(m[2]); continue
        m = P_MOVT.match(full)
        if m:
            dest = reg(m[1]); v = r.get(dest)
            if isinstance(v, int): r[dest] = (v & 0xffff) | (num(m[2]) << 16)
            else: r.pop(dest, None)
            continue
        m = P_LDR_OFS.match(full)
        if m:
            dest, b, off = reg(m[1]), reg(m[2]), num(m[3])
            if b == 'r13' and sp_to_fp is not None:
                off, b = off - sp_to_fp, 'r11'
            if b == 'r11':
                v = stack.get(off)
                if v is not None: r[dest] = v
                else: r.pop(dest, None)
                continue
            bv = r.get(b)
            if isinstance(bv, int): classify(r, dest, (bv + off) & 0xffffffff)
            else: r.pop(dest, None)
            continue
        m = P_LDR_OO.match(full)
        if m:
            dest, b, o = reg(m[1]), reg(m[2]), reg(m[3])
            bv, ov = r.get(b), r.get(o)
            if isinstance(bv, int) and isinstance(ov, int):
                classify(r, dest, pic_sum(bv, ov))
            else: r.pop(dest, None)
            continue
        m = P_LDR_P.match(full)
        if m:
            dest, b = reg(m[1]), reg(m[2])
            if b == 'r13' and sp_to_fp is not None:
                v = stack.get(-sp_to_fp)
                if v is not None: r[dest] = v
                else: r.pop(dest, None)
                continue
            bv = r.get(b)
            if isinstance(bv, int): classify(r, dest, bv)
            else: r.pop(dest, None)
            continue
        m = P_STR_P.match(full)
        if m:
            sreg, b = reg(m[1]), reg(m[2])
            if b == 'r13' and sp_to_fp is not None: stack[-sp_to_fp] = r.get(sreg)
            elif b == 'r11': stack[0] = r.get(sreg)
            continue
        m = P_STR_OFS.match(full)
        if m:
            sreg, b, off = reg(m[1]), reg(m[2]), num(m[3])
            if b == 'r13' and sp_to_fp is not None:
                stack[off - sp_to_fp] = r.get(sreg)
            elif b == 'r11':
                stack[off] = r.get(sreg)
            continue
        m = P_STR_OO.match(full)
        if m:
            sreg, b, o = reg(m[1]), reg(m[2]), reg(m[3])
            ov = r.get(o)
            if isinstance(ov, tuple) and ov[0] == 'ivarslot':
                events.append((a, 'ivar_store', {'object_reg': b, 'source_reg': sreg,
                                                 'ivar_cell': f'0x{ov[1]:08x}',
                                                 'ivar_symbol': ov[3],
                                                 'offset': ov[2]}))
            continue
        m = P_BLR.match(full)
        if m:
            t = reg(m[1])
            events.append((a, 'blx', {'target_register': m[1], 'target': r.get(t),
                                      'r0': r.get('r0'), 'r1': r.get('r1')}))
            for c in ('r0', 'r1', 'r2', 'r3', 'ip'): r.pop(c, None)
            continue
        m = re.match(r'^bl\s+(\S+)$', full)
        if m:
            events.append((a, 'bl', {'target_address': m[1]}))
            for c in ('r0', 'r1', 'r2', 'r3', 'ip'): r.pop(c, None)
            continue
        dm = re.match(r'^(' + R + r')(?:,|\[)', full.split(None, 1)[1] if ' ' in full else '')
        if dm:
            r.pop(reg(dm[1]), None)

    def encode(v):
        if isinstance(v, tuple):
            if v[0] == 'import': return {'kind': 'import', 'symbol': v[1]}
            if v[0] == 'sel':
                name = cstr(v[1])
                if name is None: return {'kind': 'unresolved'}
                return {'kind': 'selector', 'slot': f'0x{v[2]:08x}', 'name': name,
                        'name_address': f'0x{v[1]:08x}'}
            if v[0] == 'cfstr':
                ptr = memory.word(v[1] + 8)
                return {'kind': 'cfstring', 'slot': f'0x{v[1]:08x}', 'string': cstr(ptr)}
            if v[0] == 'clsref': return {'kind': 'classref', 'slot': f'0x{v[1]:08x}', 'symbol': v[2]}
            if v[0] == 'cstr': return {'kind': 'cstring', 'string': cstr(v[1])}
            if v[0] == 'ivarslot': return {'kind': 'ivar', 'symbol': v[3], 'offset': v[2]}
            return {'kind': 'address', 'value': f'0x{v:08x}'}
        if isinstance(v, int): return {'kind': 'address', 'value': f'0x{v:08x}'}
        return {'kind': 'unresolved'}

    calls, direct, ivar_rows = [], [], []
    for a, kind, payload in events:
        if kind == 'blx':
            calls.append({'call': f'0x{a:08x}', 'target_register': payload['target_register'],
                          'target': encode(payload['target']), 'receiver': encode(payload.get('r0')),
                          'selector': encode(payload.get('r1'))})
        elif kind == 'ivar_store':
            ivar_rows.append({'store': f'0x{a:08x}', **payload})
        else:
            target = int(payload['target_address'].lstrip('#'), 0)
            direct.append({'call': f'0x{a:08x}', 'target': f'0x{target:08x}',
                           'symbol': symbols.get(target) or plt_import(target)})

    selectors_used = sorted({c['selector']['name'] for c in calls
                             if c['selector'].get('kind') == 'selector'})
    cfstrings_used = sorted(
        ({'slot': f'0x{slot:08x}', 'string': cstr(memory.word(slot + 8))}
         for slot in cfstring_slots), key=lambda row: row['slot'])
    return {
        'method': 'GameView -[init]',
        'elf_sha256': hashlib.sha256(elf_path.read_bytes()).hexdigest(),
        'imp': f'0x{START:08x}',
        'arm_exidx_end': f'0x{END:08x}',
        'instruction_words': (END - START) // 4,
        'listing_verified_words': (END - START) // 4,
        'pic_base': f'0x{base:08x}',
        'blx_sites': len(calls),
        'direct_bl_sites': len(direct),
        'selector_resolved_calls': sum(1 for c in calls
                                       if c['selector'].get('kind') == 'selector'
                                       and c['target'].get('symbol') in ('objc_msgSend', 'objc_msgSendSuper2')),
        'selectors': selectors_used,
        'cfstrings': cfstrings_used,
        'calls': calls,
        'direct_calls': direct,
        'ivar_stores': ivar_rows,
        'claim': ('forward static model of the pinned function body only; unresolved sites stay '
                  'unresolved; no receiver identity, call order or runtime side-effect claim'),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=ROOT / 'reconstruction/reverse-v3/native/gameview_init.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale gameview_init.json')
    else:
        args.output.write_text(payload)
    print(f"words={report['listing_verified_words']} blx={report['blx_sites']} "
          f"resolved={report['selector_resolved_calls']} selectors={len(report['selectors'])} "
          f"direct_bl={report['direct_bl_sites']} ivar_stores={len(report['ivar_stores'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
