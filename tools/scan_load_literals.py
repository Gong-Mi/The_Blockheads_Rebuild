#!/usr/bin/env python3
"""Scan the PC-relative literal cells of a (IMP, boundary) method body and
classify every cell: GOT imports, CFString keys, selrefs, ivar-offset
storages, classrefs, superrefs (__objc_superrefs -> OBJC_CLASS_$_X), and
unresolved slots. Used to build the exact POOL lists a load-side recovery
batch must gate. Read-only probe (no JSON output)."""
import argparse
import hashlib
import io
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
from trace_objc_dispatch import ELFMemory  # noqa: E402

ELF_DEFAULT = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
BASE = 0x0105FAF4


def signed(v):
    return v - (1 << 32) if v & 0x80000000 else v


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('start')
    ap.add_argument('end')
    ap.add_argument('--elf', type=Path, default=ELF_DEFAULT)
    a = ap.parse_args()
    start, end = int(a.start, 16), int(a.end, 16)
    raw = a.elf.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHA:
        raise SystemExit('ELF SHA mismatch')
    m = ELFMemory(a.elf)
    elf = ELFFile(io.BytesIO(raw))

    def rw(addr, n=4):
        off = m.offset(addr, n)
        return None if off is None else int.from_bytes(m.data[off:off + n], 'little')

    def cstr(addr):
        off = m.offset(addr, 1)
        if off is None:
            return None
        e = m.data.find(b'\0', off, off + 128)
        return m.data[off:e].decode('ascii', 'replace') if e > 0 else None

    # relocation tables by kind
    rel = {}
    for s in elf.iter_sections():
        if isinstance(s, RelocationSection):
            syms = elf.get_section(s['sh_link'])
            for r in s.iter_relocations():
                rel.setdefault(r['r_offset'], []).append(
                    (r['r_info_type'],
                     syms.get_symbol(r['r_info_sym']).name if r['r_info_sym'] else ''))
    dynsym = elf.get_section_by_name('.dynsym')
    ivar_slots = {}
    classes = {}
    for s in dynsym.iter_symbols():
        if not s['st_value']:
            continue
        if s.name.startswith('OBJC_IVAR_$_'):
            ivar_slots[s['st_value']] = (s.name, rw(s['st_value']))
        elif s.name.startswith('OBJC_CLASS_$_'):
            classes[s['st_value']] = s.name

    keys, selrefs, ivars, clas, got, other = [], [], [], [], [], []
    for addr in range(start, end, 4):
        w = rw(addr)
        if w is None:
            continue
        if w & 0x0FFF0000 == 0x059F0000 and (w >> 12) & 0xF != 15:
            lit = (addr + 8 + (w & 0xFFF)) & 0xFFFFFFFF
            t = (BASE + signed(rw(lit) or 0)) & 0xFFFFFFFF
            imp = m.imports.get(t)
            if imp:
                got.append((lit, t, imp))
                continue
            r = rel.get(t)
            if r and any(ty == 2 and n.startswith('OBJC_IVAR_$_') for ty, n in r):
                nm = [n for ty, n in r if ty == 2][0]
                ivars.append((lit, t, nm, rw(t)))
                continue
            if r and any(ty == 21 for ty, n in r):
                got.append((lit, t, [n for ty, n in r if ty == 21][0]))
                continue
            if r and any(ty == 23 and n and 'superrefs' not in n for ty, n in r):
                pass
            rw_t = rw(t)
            if rw_t is None:
                other.append((lit, t, 'unmapped'))
                continue
            # CFString?
            if any(n == '__CFConstantStringClassReference' for ty, n in rel.get(t, [])):
                data = rw(t + 8)
                ln = rw(t + 12)
                k = cstr(data) if data else None
                keys.append((lit, t, k, ln))
                continue
            if ivar_slots.get(rw_t):
                ivars.append((lit, t, ivar_slots[rw_t][0], ivar_slots[rw_t][1]))
                continue
            if rw_t in classes:
                clas.append((lit, t, classes[rw_t]))
                continue
            sel = m.selectors.get(rw_t)
            if sel:
                selrefs.append((lit, t, sel))
                continue
            other.append((lit, t, f'word 0x{rw_t:08x} rel={rel.get(t)}'))

    def dump(title, rows):
        print(f'-- {title} ({len(rows)})')
        seen = set()
        for row in rows:
            if row[1] in seen:
                continue
            seen.add(row[1])
            print('   ', ' | '.join(str(x) for x in row))

    dump('GOT', got)
    dump('CFString keys', keys)
    dump('selrefs', selrefs)
    dump('ivar-offset storages', ivars)
    dump('classrefs/classes', clas)
    dump('other/unresolved', other)
    print('-- key set:', sorted({k[2] for k in keys if k[2]}))


if __name__ == '__main__':
    main()
