#!/usr/bin/env python3
"""Hash-gated getSaveDict key pairings for batch 2f: Column, Stairs, Door, Wire.

A template family: [super getSaveDict] + itemType/configuration-style int
keys + direct-object inherited ownerID. Every dispatch word, CFString cell,
ivar cell, classref cell and selector cell in this table was extracted
MECHANICALLY from the annotated listings + the freeblock forward simulator
(tools/gen_b2f_table.py), then gated independently against the pinned ELF.

Chain order comes from the simulator (execution order), not pool position.

Shapes:
  Column 0x00835094: numberWithInt: itemType @56 (0x8351d4/0x8351f8),
    numberWithInt: configuration <- currentConfiguration @64 (0x835234/
    0x835258), numberWithUnsignedInt: paintColor @60 (0x835294/0x8352b8),
    direct-object INHERITED ownerID @36 (set 0x835330).
  Stairs 0x006ccd98: same template; itemType @56 (0x6cced8/0x6ccefc),
    configuration <- currentConfiguration @60 (0x6ccf38/0x6ccf5c),
    paintColor @64 UNSIGNED (0x6ccf98/0x6ccfbc), ownerID (0x6cd034).
  Door 0x00769dc8: itemType @64 (0x769ee0/0x769f04), blocked @68 int
    (0x769f40/0x769f64), direct-object ironPlaceClientID @72 (0x769fdc),
    ownerID (0x76a05c).
  Wire 0x00950770: itemType @56 (0x9508b8/0x9508dc), configuration <-
    currentConfiguration @60 (0x950918/0x95093c), solidConfiguration <-
    currentSolidConfiguration @64 (0x950978/0x95099c), ownerID (0x950a14).
"""
import argparse, hashlib, io, json
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from trace_objc_dispatch import ELFMemory

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
BASE = 0x0105FAF4
MSGSEND_SUPER2 = 0x0105B79C

SUPER = {  # class: imp, boundary, got_cell, selref_cell, classref_cell, super_site
 'Column': (0x00835094, 0x00835384, 0x00835340, 0x00835344, 0x00835348, 0x008350E8),
 'Stairs': (0x006CCD98, 0x006CD088, 0x006CD044, 0x006CD048, 0x006CD04C, 0x006CCDEC),
 'Door':   (0x00769DC8, 0x0076A0AC, 0x0076A06C, 0x0076A070, 0x0076A074, 0x00769E1C),
 'Wire':   (0x00950770, 0x00950A64, 0x00950A24, 0x00950A28, 0x00950A2C, 0x009507C4),
}
# key cell, cfstring obj, ivar sym, ivar off, conv sel, conv site, conv word,
# NSNumber classref cell, conv selref cell, set site, set word, set selref cell
KEYS = [
 ('Column','itemType',0x00835374,0x00F92098,'OBJC_IVAR_$_Column.itemType',56,
  'numberWithInt:',0x008351D4,'3cff2fe1',0x00835364,0x0083536C,0x008351F8,'3cff2fe1',0x00835358),
 ('Column','configuration',0x00835368,0x00F920A8,'OBJC_IVAR_$_Column.currentConfiguration',64,
  'numberWithInt:',0x00835234,'33ff2fe1',0x00835364,0x0083536C,0x00835258,'3cff2fe1',0x00835358),
 ('Column','paintColor',0x00835350,0x00F92088,'OBJC_IVAR_$_Column.paintColor',60,
  'numberWithUnsignedInt:',0x00835294,'33ff2fe1',0x00835364,0x0083535C,0x008352B8,'3cff2fe1',0x00835358),
 ('Column','ownerID',0x0083537C,0x00F92078,'OBJC_IVAR_$_DynamicObject.ownerID',36,
  None,None,None,None,None,0x00835330,'3cff2fe1',0x00835358),
 ('Stairs','itemType',0x006CD078,0x00F863D8,'OBJC_IVAR_$_Stairs.itemType',56,
  'numberWithInt:',0x006CCED8,'3cff2fe1',0x006CD068,0x006CD070,0x006CCEFC,'3cff2fe1',0x006CD05C),
 ('Stairs','configuration',0x006CD06C,0x00F863E8,'OBJC_IVAR_$_Stairs.currentConfiguration',60,
  'numberWithInt:',0x006CCF38,'33ff2fe1',0x006CD068,0x006CD070,0x006CCF5C,'3cff2fe1',0x006CD05C),
 ('Stairs','paintColor',0x006CD054,0x00F863C8,'OBJC_IVAR_$_Stairs.paintColor',64,
  'numberWithUnsignedInt:',0x006CCF98,'33ff2fe1',0x006CD068,0x006CD060,0x006CCFBC,'3cff2fe1',0x006CD05C),
 ('Stairs','ownerID',0x006CD080,0x00F863B8,'OBJC_IVAR_$_DynamicObject.ownerID',36,
  None,None,None,None,None,0x006CD034,'3cff2fe1',0x006CD05C),
 ('Door','itemType',0x0076A094,0x00F8FD88,'OBJC_IVAR_$_Door.itemType',64,
  'numberWithInt:',0x00769EE0,'3cff2fe1',0x0076A090,0x0076A088,0x00769F04,'3cff2fe1',0x0076A084),
 ('Door','blocked',0x0076A07C,0x00F8FD98,'OBJC_IVAR_$_Door.blocked',68,
  'numberWithInt:',0x00769F40,'33ff2fe1',0x0076A090,0x0076A088,0x00769F64,'3cff2fe1',0x0076A084),
 ('Door','ironPlaceClientID',0x0076A09C,0x00F8FD68,'OBJC_IVAR_$_Door.ironPlaceClientID',72,
  None,None,None,None,None,0x00769FDC,'3cff2fe1',0x0076A084),
 ('Door','ownerID',0x0076A0A4,0x00F8FD78,'OBJC_IVAR_$_DynamicObject.ownerID',36,
  None,None,None,None,None,0x0076A05C,'3cff2fe1',0x0076A084),
 ('Wire','itemType',0x00950A54,0x00F954A8,'OBJC_IVAR_$_Wire.itemType',56,
  'numberWithInt:',0x009508B8,'3cff2fe1',0x00950A48,0x00950A40,0x009508DC,'3cff2fe1',0x00950A3C),
 ('Wire','configuration',0x00950A4C,0x00F954B8,'OBJC_IVAR_$_Wire.currentConfiguration',60,
  'numberWithInt:',0x00950918,'33ff2fe1',0x00950A48,0x00950A40,0x0095093C,'3cff2fe1',0x00950A3C),
 ('Wire','solidConfiguration',0x00950A34,0x00F954C8,'OBJC_IVAR_$_Wire.currentSolidConfiguration',64,
  'numberWithInt:',0x00950978,'33ff2fe1',0x00950A48,0x00950A40,0x0095099C,'3cff2fe1',0x00950A3C),
 ('Wire','ownerID',0x00950A5C,0x00F95498,'OBJC_IVAR_$_DynamicObject.ownerID',36,
  None,None,None,None,None,0x00950A14,'3cff2fe1',0x00950A3C),
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

    def rebase(c):
        return (BASE + signed(rw(c))) & 0xFFFFFFFF

    def word_eq(a, wh):
        return rw(a).to_bytes(4, 'little').hex() == wh

    elf = ELFFile(io.BytesIO(raw))
    abs32 = {}
    for section in elf.iter_sections():
        if isinstance(section, RelocationSection):
            syms = elf.get_section(section['sh_link'])
            for rel in section.iter_relocations():
                if rel['r_info_type'] == 2 and rel['r_info_sym']:
                    abs32[rel['r_offset']] = syms.get_symbol(rel['r_info_sym']).name
    dynsym = elf.get_section_by_name('.dynsym')
    ivar_by_name = {s.name: s['st_value'] for s in dynsym.iter_symbols()
                    if s['st_value'] and s.name.startswith('OBJC_IVAR_$_')}

    tsv = (NATIVE / 'libApplication_objc_methods.tsv').read_text().splitlines()[1:]
    rows = sorted((l.split('\t') for l in tsv), key=lambda l: int(l[0], 16))
    imps = [int(r[0], 16) for r in rows]
    by_imp = {int(r[0], 16): r for r in rows}

    def class_name(struct):
        return cstr(rw(rw(struct + 0x10) + 0x10))

    results = {}
    for cls, (imp, boundary, gotc, selc, crc, site) in SUPER.items():
        row = by_imp.get(imp)
        if row is None or row[1] != cls or row[3] != 'getSaveDict':
            raise ValueError(f'{cls}: method-map drift')
        if min(i for i in imps if i > imp) != boundary:
            raise ValueError(f'{cls}: boundary drift')
        if not word_eq(site, '3cff2fe1'):
            raise ValueError(f'{cls}: super site word drift')
        if rebase(gotc) != MSGSEND_SUPER2 or rw(MSGSEND_SUPER2) != 0:
            raise ValueError(f'{cls}: super2 GOT drift')
        if cstr(rw(rebase(selc))) != 'getSaveDict':
            raise ValueError(f'{cls}: super selref drift')
        struct = rw(rebase(crc))
        if class_name(struct) != cls:
            raise ValueError(f'{cls}: super classref name-walk drift')
        results[cls] = {'class': cls, 'imp': f'0x{imp:08x}',
                        'boundary': f'0x{boundary:08x}',
                        'code_words': (boundary - imp) // 4,
                        'style': 'super_plus_own_keys',
                        'super_site': f'0x{site:08x}',
                        'super_class_struct': f'0x{struct:08x}', 'keys': []}

    for cls, key, kcell, obj, isym, off, conv, cs, cw, ncell, csr, ss, sw, ssc in KEYS:
        if abs32.get(obj) != '__CFConstantStringClassReference':
            raise ValueError(f'{cls}.{key}: CFString isa drift')
        if cstr(rw(obj + 8)) != key or rw(obj + 12) != len(key.encode()):
            raise ValueError(f'{cls}.{key}: CFString payload drift')
        if rebase(kcell) != obj:
            raise ValueError(f'{cls}.{key}: key cell drift')
        stor = ivar_by_name.get(isym)
        if stor is None or rw(stor) != off:
            raise ValueError(f'{cls}.{key}: ivar drift')
        if not word_eq(ss, sw):
            raise ValueError(f'{cls}.{key}: set word drift')
        if cstr(rw(rebase(ssc))) != 'setObject:forKey:':
            raise ValueError(f'{cls}.{key}: setObject selref drift')
        entry = {'key': key, 'cfstring_object': f'0x{obj:08x}', 'ivar': isym,
                 'ivar_offset': off, 'set_object_site': f'0x{ss:08x}'}
        if conv is None:
            entry['conversion'] = 'direct_object'
        else:
            entry['conversion'] = conv
            entry['conversion_site'] = f'0x{cs:08x}'
            if not word_eq(cs, cw):
                raise ValueError(f'{cls}.{key}: conv word drift')
            if cstr(rw(rebase(csr))) != conv:
                raise ValueError(f'{cls}.{key}: conv selref drift')
            if abs32.get(rebase(ncell)) != 'OBJC_CLASS_$_NSNumber' or rw(rebase(ncell)) != 0:
                raise ValueError(f'{cls}.{key}: NSNumber classref drift')
        results[cls]['keys'].append(entry)

    return {
        'schema': 1, 'elf_sha256': SHA, 'pic_base': f'0x{BASE:08x}',
        'method': 'getSaveDict key pairings (batch 2f)',
        'classes': [results[c] for c in ('Column', 'Stairs', 'Door', 'Wire')],
        'claim': ('Column/Stairs/Wire share the itemType+configuration(s)+paint '
                  'template (currentConfiguration/currentSolidConfiguration '
                  'ivars under plain key names; Column paintColor @60, Stairs '
                  '@64), Door adds blocked @68 int and direct-object '
                  'ironPlaceClientID @72; all four insert INHERITED '
                  'DynamicObject.ownerID @36 directly; paintColor uses '
                  'numberWithUnsignedInt:, the rest numberWithInt:; every '
                  'address here was extracted mechanically via '
                  'tools/gen_b2f_table.py before gating; 25 overrides remain, '
                  'read-back/roundtrip unresolved'),
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument('elf', type=Path)
    p.add_argument('--check', action='store_true')
    p.add_argument('--output', type=Path, default=NATIVE / 'subclass_savedict_keys_b2f.json')
    a = p.parse_args()
    text = json.dumps(recover(a.elf), indent=2, sort_keys=True) + '\n'
    if a.check:
        if a.output.read_text() != text:
            raise SystemExit('stale subclass_savedict_keys_b2f.json')
    else:
        a.output.write_text(text)
    print('b2f classes=4 keys=16')


if __name__ == '__main__':
    main()
