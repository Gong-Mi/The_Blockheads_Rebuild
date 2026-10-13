#!/usr/bin/env python3
"""Hash-gated key->conversion->writeback pairing for NPC -[loadValuesFromSaveDict:].

Bounded forward simulator over 0x00643b20..0x0064448c. Cell literals resolve
eagerly against the pinned ELF:

  ldr rD,[pc,#lit]          rD = ('cell', lit)
  add rD,rB,cell / add rD,cell,rB (rB==PIC base) rD = resolved cell value
  GOT slot                  ('func', import name)
  OBJC_IVAR_$_* slot        ('ivaroff', symbol, value)
  CFString data ptr at +8   ('key', string)   (len field must equal strlen)
  __objc_selrefs-known      ('sel', selector)
  stack slots               fp/sp-relative str/ldr modelled by symbolic slot id

Every blx dispatch site records r0/r1/r2/r3 in resolved form; each writeback
(str/strh/strb/vstr to [r0|r1]) records the target ('ivaroff',...) and the
value operand, letting key->conversion->writeback chains be read off directly.
Unresolved operands stay None; nothing is promoted by proximity.
"""
import argparse, hashlib, io, json
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from trace_objc_dispatch import ELFMemory

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
BASE = 0x0105FAF4
START, END = 0x00643B20, 0x0064448C


def signed(v):
    return v - (1 << 32) if v & 0x80000000 else v


def run(elf_path, dump_json):
    raw = Path(elf_path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHA:
        raise ValueError('original ELF SHA mismatch')
    m = ELFMemory(Path(elf_path))
    elf = ELFFile(io.BytesIO(raw))

    def rw(a):
        if not isinstance(a, int) or a < 0 or a >= 0x1060488:
            return None
        off = m.offset(a, 4)
        return None if off is None else int.from_bytes(m.data[off:off + 4], 'little')

    def cstr(a):
        if a is None or a >= 0x1060488:
            return None
        off = m.offset(a, 1)
        if off is None:
            return None
        end = m.data.find(b'\0', off, off + 96)
        try:
            return m.data[off:end].decode('ascii') if end > off else None
        except UnicodeDecodeError:
            return None

    abs32 = {}
    for section in elf.iter_sections():
        if isinstance(section, RelocationSection):
            syms = elf.get_section(section['sh_link'])
            for rel in section.iter_relocations():
                if rel['r_info_type'] == 2 and rel['r_info_sym']:
                    abs32[rel['r_offset']] = syms.get_symbol(rel['r_info_sym']).name
    dynsym = elf.get_section_by_name('.dynsym')
    ivar_addr = {s['st_value']: s.name for s in dynsym.iter_symbols()
                 if s['st_value'] and s.name.startswith('OBJC_IVAR_$_')}

    def resolve_slot(t):
        imp = m.imports.get(t)
        if imp:
            return ('func', imp)
        sym = abs32.get(t)
        if sym and sym.startswith('OBJC_IVAR_$_'):
            return ('ivaroff', sym, rw(t))
        sym2 = ivar_addr.get(t)
        if sym2:
            return ('ivaroff', sym2, rw(t))
        if sym == '__CFConstantStringClassReference':
            da = rw(t + 8)
            key = cstr(da) if da is not None else None
            ln = rw(t + 12)
            if key is not None and ln is not None and ln == len(key.encode()):
                return ('key', key)
        tw = rw(t)
        if tw:
            sel = m.selectors.get(tw)
            if sel:
                return ('sel', sel)
        return ('slot', t)

    def resolve_cell(wordv):
        return resolve_slot((BASE + signed(wordv)) & 0xFFFFFFFF)

    NAME = {13: 'sp', 14: 'lr', 12: 'ip', 11: 'fp', 10: 'sl'}
    def rn(r):
        r = r.strip()
        if r in ('pc',):
            return 'r15'
        d = {'ip': 12, 'lr': 14, 'fp': 11, 'sp': 13, 'sl': 10}.get(r)
        return f'r{d}' if d is not None else r

    regs = {}
    slots = {}   # (base,id) or ('sp',off) -> tagged value
    base_site = {}
    calls, writes, fills = [], [], []

    def tag_of(r):
        return regs.get(rn(r))

    def setv(r, v):
        regs[rn(r)] = v

    def spill_store(r, base, ident):
        slots[ident] = tag_of(r)
        fills.append({'site': hex(a), 'kind': 'spill', 'reg': rn(r), 'slot': ident})

    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    off0 = m.offset(START, END - START)
    for ins in md.disasm(m.data[off0:off0 + (END - START)], START):
        a = ins.address
        mn, ops = ins.mnemonic, ins.op_str
        parts = [p.strip() for p in ops.split(',')]
        if mn.startswith('bl'):
            calls.append({'site': f'0x{a:08x}', 'mn': mn,
                          'r0': tag_of('r0'), 'r1': tag_of('r1'),
                          'r2': tag_of('r2'), 'r3': tag_of('r3')})
            for c in ('r0', 'r1', 'r2', 'r3', 'ip', 'lr'):
                regs[c] = None
            continue
        if mn == 'ldr' and '[' in ops:
            dst = parts[0]
            rest = ops[ops.index('[') + 1:ops.rindex(']')]
            rp = [p.strip() for p in rest.split(',')]
            if rp[0] == 'pc':
                lit = (a + 8 + (int(rp[1], 0) if len(rp) > 1 else 0)) & 0xFFFFFFFF
                w = rw(lit)
                setv(dst, ('lit', w) if w is not None else None)
                base_site[a] = lit
                continue
            if len(rp) == 1:
                b = tag_of(rp[0])
                ident = ('mem',) if b is None else None
                if b and b[0] in ('slot', 'ivaroff', 'func', 'sel', 'key'):
                    # ldr rD,[regWithResolvedCell]: value at slot
                    addr = b[1] if b[0] == 'slot' else None
                    setv(dst, ('val', rw(addr)) if addr is not None else None)
                elif b and b[0] == 'ivaroff':
                    setv(dst, ('val', rw(b[1] if len(b) > 1 else 0) if False else None))
                else:
                    setv(dst, None)
                continue
            b = tag_of(rp[0]); o = tag_of(rp[1])
            if rp[0] in ('fp', 'sp'):
                offv = int(rp[1].lstrip('#'), 0) if rp[1].startswith('#') else None
                ident = (rp[0], offv) if offv is not None else None
                setv(dst, slots.get(ident) if ident else None)
                continue
            if o and o[0] == 'lit' and b and b[0] == 'val' and b[1] == BASE:
                setv(dst, resolve_cell(o[1]))
                continue
            if b and b[0] == 'lit' and o and o[0] == 'val' and o[1] == BASE:
                setv(dst, resolve_cell(b[1]))
                continue
            setv(dst, None)
            continue
        if mn == 'str':
            dst_reg = parts[0]
            rest = ops[ops.index('[') + 1:ops.rindex(']')]
            rp = [p.strip() for p in rest.split(',')]
            if rp[0] in ('fp', 'sp'):
                offv = int(rp[1].lstrip('#'), 0) if len(rp) > 1 else 0
                spill_store(dst_reg, rp[0], (rp[0], offv))
                continue
            b = tag_of(rp[0])
            if b and b[0] in ('ivaroff', 'slot', 'key'):
                writes.append({'site': f'0x{a:08x}', 'mn': 'str',
                               'target': b, 'value': tag_of(dst_reg)})
            continue
        if mn in ('strh', 'strb'):
            dst_reg = parts[0]
            rest = ops[ops.index('[') + 1:ops.rindex(']')]
            rp = [p.strip() for p in rest.split(',')]
            b = tag_of(rp[0])
            writes.append({'site': f'0x{a:08x}', 'mn': mn,
                           'target': b, 'value': tag_of(dst_reg)})
            continue
        if mn == 'vstr':
            rest = ops[ops.index('[') + 1:ops.rindex(']')]
            b = tag_of(rest)
            writes.append({'site': f'0x{a:08x}', 'mn': 'vstr',
                           'target': b, 'value': ('float', ops.split(',')[0].strip())})
            continue
        if mn == 'add':
            if len(parts) == 3:
                d, a1, a2 = parts[0], parts[1], parts[2]
                if a2 == 'pc' or a1 == 'pc':
                    other = tag_of(a1 if a2 == 'pc' else a2)
                    if other and other[0] == 'lit':
                        setv(d, ('val', BASE))
                    else:
                        setv(d, None)
                    continue
                t1, t2 = tag_of(a1), tag_of(a2)
                if t1 and t1[0] == 'lit' and t2 and t2[0] == 'val' and t2[1] == BASE:
                    setv(d, resolve_cell(t1[1]))
                    continue
                if t2 and t2[0] == 'lit' and t1 and t1[0] == 'val' and t1[1] == BASE:
                    setv(d, resolve_cell(t2[1]))
                    continue
                # self + ivaroff -> ('addr', ivar-tag)
                if t1 and t2:
                    if t1[0] == 'val' and t1[1] == START and t2[0] == 'ivaroff':
                        setv(d, ('selfplus', t2)); continue
                    if t2[0] == 'val' and t2[1] == START and t1[0] == 'ivaroff':
                        setv(d, ('selfplus', t1)); continue
                setv(d, None)
                continue
            setv(parts[0], None)
            continue
        if mn == 'mov' and len(parts) == 2:
            regs[rn(parts[0])] = tag_of(parts[1])
            continue
        if mn == 'cmp':
            continue
        if mn.startswith('v') or mn == 'sxtb':
            continue
        # generic dest clobber
        if parts and re.match(r'^(r\d{1,2}|ip|lr|fp|sl)$', parts[0]):
            regs[rn(parts[0])] = None

    return calls, writes, fills


import re


def main():
    p = argparse.ArgumentParser()
    p.add_argument('elf', type=Path)
    p.add_argument('--output', type=Path, default=NATIVE / 'npc_loadvalues_traced.json')
    a = p.parse_args()
    calls, writes, fills = run(a.elf, None)
    data = {'schema': 1, 'elf_sha256': SHA, 'imp': f'0x{START:08x}',
            'boundary': f'0x{END:08x}', 'pic_base': f'0x{BASE:08x}',
            'calls': [{'site': c['site'], 'mn': c['mn'],
                       'r0': c['r0'], 'r1': c['r1'], 'r2': c['r2'], 'r3': c['r3']} for c in calls],
            'writebacks': [{'site': w['site'], 'mn': w['mn'],
                            'target': w['target'], 'value': w['value']} for w in writes],
            'note': 'raw forward-trace dump; tags are (kind,...) tuples, None = unresolved'}
    text = json.dumps(data, indent=2, sort_keys=True) + '\n'
    a.output.write_text(text)
    print(f'traced calls={len(calls)} writebacks={len(writes)}')


if __name__ == '__main__':
    main()
