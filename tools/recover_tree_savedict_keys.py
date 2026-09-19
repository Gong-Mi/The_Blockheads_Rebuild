#!/usr/bin/env python3
"""Hash-gated key pairings for the three minimal tree -[getSaveDict] overrides.

AppleTree (78w) and PineTree (79w): [super getSaveDict] then ONE float key
`availableFood` from <Class>.availableFood @136 (vldr s0,[self+off] ->
numberWithFloat: -> setObject:forKey:).
GemTree (112w): [super getSaveDict] then int keys `gemTreeType` @136 and
`fruitYear` @140 (ldr -> numberWithInt: -> setObject:forKey:).

Gates per class on the pinned ELF only (no proximity promotion):
  1. method-map row (class, getSaveDict, types @8@0:4) and boundary==next IMP;
  2. super triple: GOT cell -> objc_msgSendSuper2 import (file word 0),
     selref cell -> 'getSaveDict' cstring, classref cell -> __objc_classrefs
     slot whose materialised file word is the class struct and whose name walk
     (word(class+0x10) ro, word(ro+0x10) cstr) equals the class itself — the
     ARM32 objc_msgSendSuper2 super_data class pointer;
  3. per key: CFString object (ABS32 -> __CFConstantStringClassReference,
     +8 cstr == key, +12 == strlen), key literal cell re-bases to the object;
  4. per key: ivar cell -> RELATIVE slot -> dynsym OBJC_IVAR_$_<Class>.<ivar>,
     and the storage word equals the claimed byte offset; NSNumber classref
     cell ABS32-gated with zero file word;
  5. raw little-endian words at super/conversion/setObject dispatch sites.
"""
import argparse, hashlib, io, json, re
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from trace_objc_dispatch import ELFMemory

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
BASE = 0x0105FAF4
MSGSEND_SUPER2 = 0x0105B79C

# class, imp, boundary, super2_got_cell, getSaveDict_selref_cell,
# super_classref_cell, super_site, super_word
CLASSES = [
 ('AppleTree', 0x009BD548, 0x009BD680, 0x009BD658, 0x009BD65C, 0x009BD660, 0x009BD59C, '3cff2fe1'),
 ('PineTree',  0x00B651BC, 0x00B652F8, 0x00B652CC, 0x00B652D0, 0x00B652D4, 0x00B65210, '3cff2fe1'),
 ('GemTree',   0x0052922C, 0x005293EC, 0x005293BC, 0x005293C0, 0x005293C4, 0x00529280, '3cff2fe1'),
]
# class, key, cfstring_obj, key_cell, number_classref_cell, ivar_cell,
# ivar_name, ivar_off, conv_word_selector_site, conv_word, set_site, set_word
KEYS = [
 ('AppleTree', 'availableFood', 0x00F96178, 0x009BD664, 0x009BD678, 0x009BD674, 'availableFood', 136,
  'numberWithFloat:', 0x009BD624, '3eff2fe1', 0x009BD648, '3cff2fe1'),
 ('PineTree',  'availableFood', 0x00F9DE08, 0x00B652D8, 0x00B652EC, 0x00B652E8, 'availableFood', 136,
  'numberWithFloat:', 0x00B65298, '3eff2fe1', 0x00B652BC, '3cff2fe1'),
 ('GemTree',   'gemTreeType',   0x00F79468, 0x005293E0, 0x005293DC, 0x005293E4, 'gemTreeType', 136,
  'numberWithInt:', 0x00529328, '37ff2fe1', 0x0052934C, '3cff2fe1'),
 ('GemTree',   'fruitYear',     0x00F79478, 0x005293C8, 0x005293DC, 0x005293D8, 'fruitYear', 140,
  'numberWithInt:', 0x00529388, '33ff2fe1', 0x005293AC, '3cff2fe1'),
]


def signed(v):
    return v - (1 << 32) if v & 0x80000000 else v


def recover(path):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHA:
        raise ValueError('original ELF SHA mismatch')
    m = ELFMemory(path)

    def rw(a):
        off = m.offset(a, 4)
        if off is None:
            raise ValueError(f'unmapped {a:#x}')
        return int.from_bytes(m.data[off:off + 4], 'little')

    def cstr(a):
        off = m.offset(a, 1)
        end = m.data.find(b'\0', off, off + 96)
        return m.data[off:end].decode('ascii')

    def rebase(cell_addr):
        return (BASE + signed(rw(cell_addr))) & 0xFFFFFFFF

    elf = ELFFile(io.BytesIO(raw))
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

    tsv = (NATIVE / 'libApplication_objc_methods.tsv').read_text().splitlines()[1:]
    rows = sorted((l.split('\t') for l in tsv), key=lambda l: int(l[0], 16))
    imps = [int(r[0], 16) for r in rows]
    by_imp = {int(r[0], 16): r for r in rows}

    def class_name(struct):
        ro = rw(struct + 0x10)
        return cstr(rw(ro + 0x10))

    results = {}
    for cls, imp, boundary, got_cell, sel_cell, cr_cell, site, word in CLASSES:
        row = by_imp.get(imp)
        if row is None or row[1] != cls or row[3] != 'getSaveDict':
            raise ValueError(f'{cls}: method-map drift')
        nxt = min(i for i in imps if i > imp)
        if nxt != boundary:
            raise ValueError(f'{cls}: boundary drift {nxt:#x}')
        if rw(site).to_bytes(4, 'little').hex() != word:
            raise ValueError(f'{cls}: super site word drift')
        if rebase(got_cell) != MSGSEND_SUPER2 or m.imports.get(MSGSEND_SUPER2) != 'objc_msgSendSuper2' or rw(MSGSEND_SUPER2) != 0:
            raise ValueError(f'{cls}: super2 GOT drift')
        if cstr(rw(rebase(sel_cell))) != 'getSaveDict':
            raise ValueError(f'{cls}: getSaveDict selref drift')
        cr_slot = rebase(cr_cell)
        struct = rw(cr_slot)
        if class_name(struct) != cls:
            raise ValueError(f'{cls}: super classref name-walk drift')
        results[cls] = {'class': cls, 'imp': f'0x{imp:08x}',
                        'boundary': f'0x{boundary:08x}',
                        'code_words': (boundary - imp) // 4,
                        'style': 'super_plus_own_keys',
                        'super_site': f'0x{site:08x}',
                        'super_class_struct': f'0x{struct:08x}',
                        'keys': []}
    for (cls, key, obj, kcell, ncell, icell, ivar, off, conv_sel,
         conv_site, conv_word, set_site, set_word) in KEYS:
        if abs32.get(obj) != '__CFConstantStringClassReference':
            raise ValueError(f'{cls}.{key}: CFString isa drift')
        da = rw(obj + 8)
        if cstr(da) != key or rw(obj + 12) != len(key.encode()):
            raise ValueError(f'{cls}.{key}: CFString payload drift')
        if rebase(kcell) != obj:
            raise ValueError(f'{cls}.{key}: key cell drift')
        nslot = rebase(ncell)
        if abs32.get(nslot) != 'OBJC_CLASS_$_NSNumber' or rw(nslot) != 0:
            raise ValueError(f'{cls}.{key}: NSNumber classref drift')
        islot = rebase(icell)
        isym = ivar_addr.get(rw(islot))
        if isym != f'OBJC_IVAR_$_{cls}.{ivar}' or rw(rw(islot)) != off:
            raise ValueError(f'{cls}.{key}: ivar drift ({isym})')
        for site, wh, tag in ((conv_site, conv_word, 'conversion'), (set_site, set_word, 'set')):
            if rw(site).to_bytes(4, 'little').hex() != wh:
                raise ValueError(f'{cls}.{key}: {tag} word drift')
        conv_selres = cstr(rw(_conv_sel_cell(cls, key) and rebase(_conv_sel_cell(cls, key))))
        if conv_selres != conv_sel:
            raise ValueError(f'{cls}.{key}: conversion selref cstring drift')
        set_selres = cstr(rw(rebase(_set_sel_cell(cls, key))))
        if set_selres != 'setObject:forKey:':
            raise ValueError(f'{cls}.{key}: setObject selref drift')
        results[cls]['keys'].append({
            'key': key, 'cfstring_object': f'0x{obj:08x}',
            'ivar': f'OBJC_IVAR_$_{cls}.{ivar}', 'ivar_offset': off,
            'conversion': conv_sel, 'conversion_site': f'0x{conv_site:08x}',
            'set_object_site': f'0x{set_site:08x}',
            'number_classref_slot': f'0x{nslot:08x}',
        })
    return {
        'schema': 1, 'elf_sha256': SHA, 'pic_base': f'0x{BASE:08x}',
        'method': 'tree subclass getSaveDict own-key pairings (batch 2a)',
        'classes': [results[c] for c, *_ in CLASSES],
        'claim': ('AppleTree/PineTree add exactly one float availableFood @136 after '
                  '[super getSaveDict]; GemTree adds numberWithInt: gemTreeType @136 '
                  'and fruitYear @140; super classref name-walk proves the ARM32 '
                  'objc_msgSendSuper2 receiver identity; raw words gate every dispatch '
                  'site; remaining 43 overrides, the read-back side of these keys and '
                  'any save/roundtrip behavior stay unresolved'),
    }


_CONV = {('AppleTree', 'availableFood'): 0x009BD670, ('PineTree', 'availableFood'): 0x00B652E4,
         ('GemTree', 'gemTreeType'): 0x005293D4, ('GemTree', 'fruitYear'): 0x005293D4}
_SET = {('AppleTree', 'availableFood'): 0x009BD66C, ('PineTree', 'availableFood'): 0x00B652E0,
        ('GemTree', 'gemTreeType'): 0x005293D0, ('GemTree', 'fruitYear'): 0x005293D0}


def _conv_sel_cell(cls, key):
    return _CONV[(cls, key)]


def _set_sel_cell(cls, key):
    return _SET[(cls, key)]


def main():
    p = argparse.ArgumentParser()
    p.add_argument('elf', type=Path)
    p.add_argument('--check', action='store_true')
    p.add_argument('--output', type=Path, default=NATIVE / 'tree_savedict_keys.json')
    a = p.parse_args()
    text = json.dumps(recover(a.elf), indent=2, sort_keys=True) + '\n'
    if a.check:
        if a.output.read_text() != text:
            raise SystemExit('stale tree_savedict_keys.json')
    else:
        a.output.write_text(text)
    print('tree-savedict classes=3 own_keys=4')


if __name__ == '__main__':
    main()
