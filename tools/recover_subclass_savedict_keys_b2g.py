#!/usr/bin/env python3
"""Hash-gated getSaveDict key pairings for batch 2g: Rail, KelpPlant,
VinePlant, Egg. Addresses/words extracted mechanically from the annotated
listings + freeblock simulator, then gated against the pinned ELF.

Shapes:
  Rail 0x0077b034: [super] + itemType @56 int (0x77b180/0x77b1a4),
    configuration <- currentConfiguration @60 int (0x77b1e0/0x77b204),
    ownedByStation @65 BOOL (0x77b240/0x77b264). No ownerID key (7 blx =
    super + 3 conv + 3 set exactly).
  KelpPlant 0x008166e0: [super] + numberOfOccupiedTilesAbove @200 int
    (0x816830/0x816854), growthTimer @176 FLOAT (0x816890/0x8168b4),
    availableFood @180 FLOAT (0x8168f0/0x816914).
  VinePlant 0x004f74c4: mirror template with BELOW @180 int
    (0x4f7614/0x4f7638), growthTimer @176 float (0x4f7674/0x4f7698),
    availableFood @100 float (0x4f76d4/0x4f76f8).
  Egg 0x00d4e8d8: [super] + hatchTimer @64 float (0xd4ea18/0xd4ea3c),
    saveTime via [self.world @4 worldTime] (selector site 0xd4ea78, boxing
    0xd4ea9c, set 0xd4eac0), genesDict @56 direct object (set 0xd4eb38).
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

SUPER = {
 'Rail':      (0x0077B034, 0x0077B2B0, 0x0077B274, 0x0077B278, 0x0077B27C, 0x0077B088),
 'KelpPlant': (0x008166E0, 0x00816960, 0x00816924, 0x00816928, 0x0081692C, 0x00816734),
 'VinePlant': (0x004F74C4, 0x004F7744, 0x004F7708, 0x004F770C, 0x004F7710, 0x004F7518),
 'Egg':       (0x00D4E8D8, 0x00D4EB84, 0x00D4EB48, 0x00D4EB4C, 0x00D4EB50, 0x00D4E92C),
}
KEYS = [
 ('Rail','itemType',0x0077B2A4,0x00F8FFA8,'OBJC_IVAR_$_Rail.itemType',56,
  'numberWithInt:',0x0077B180,'33ff2fe1',0x0077B294,0x0077B29C,0x0077B1A4,'3cff2fe1',0x0077B288),
 ('Rail','configuration',0x0077B298,0x00F8FFC8,'OBJC_IVAR_$_Rail.currentConfiguration',60,
  'numberWithInt:',0x0077B1E0,'33ff2fe1',0x0077B294,0x0077B29C,0x0077B204,'3cff2fe1',0x0077B288),
 ('Rail','ownedByStation',0x0077B280,0x00F8FFB8,'OBJC_IVAR_$_Rail.ownedByStation',65,
  'numberWithBool:',0x0077B240,'33ff2fe1',0x0077B294,0x0077B28C,0x0077B264,'3cff2fe1',0x0077B288),
 ('KelpPlant','numberOfOccupiedTilesAbove',0x00816950,0x00F91E88,'OBJC_IVAR_$_KelpPlant.numberOfOccupiedTilesAbove',200,
  'numberWithInt:',0x00816830,'33ff2fe1',0x00816944,0x00816954,0x00816854,'3cff2fe1',0x00816938),
 ('KelpPlant','growthTimer',0x00816948,0x00F91E98,'OBJC_IVAR_$_KelpPlant.growthTimer',176,
  'numberWithFloat:',0x00816890,'3eff2fe1',0x00816944,0x0081693C,0x008168B4,'3cff2fe1',0x00816938),
 ('KelpPlant','availableFood',0x00816930,0x00F91EA8,'OBJC_IVAR_$_KelpPlant.availableFood',180,
  'numberWithFloat:',0x008168F0,'3eff2fe1',0x00816944,0x0081693C,0x00816914,'3cff2fe1',0x00816938),
 ('VinePlant','numberOfOccupiedTilesBelow',0x004F7734,0x00F79128,'OBJC_IVAR_$_VinePlant.numberOfOccupiedTilesBelow',180,
  'numberWithInt:',0x004F7614,'33ff2fe1',0x004F7728,0x004F7738,0x004F7638,'3cff2fe1',0x004F771C),
 ('VinePlant','growthTimer',0x004F772C,0x00F79138,'OBJC_IVAR_$_VinePlant.growthTimer',176,
  'numberWithFloat:',0x004F7674,'3eff2fe1',0x004F7728,0x004F7720,0x004F7698,'3cff2fe1',0x004F771C),
 ('VinePlant','availableFood',0x004F7714,0x00F79148,'OBJC_IVAR_$_VinePlant.availableFood',100,
  'numberWithFloat:',0x004F76D4,'3eff2fe1',0x004F7728,0x004F7720,0x004F76F8,'3cff2fe1',0x004F771C),
 ('Egg','hatchTimer',0x00D4EB74,0x00FAE518,'OBJC_IVAR_$_Egg.hatchTimer',64,
  'numberWithFloat:',0x00D4EA18,'35ff2fe1',0x00D4EB70,0x00D4EB64,0x00D4EA3C,'3cff2fe1',0x00D4EB60),
 ('Egg','genesDict',0x00D4EB7C,0x00FAE508,'OBJC_IVAR_$_Egg.genesDict',56,
  None,None,None,None,None,0x00D4EB38,'3cff2fe1',0x00D4EB60),
]
# Egg saveTime: derived [world worldTime] key, no ivar source
EGG_SAVETIME = {'key': 'saveTime', 'cfstring_obj': 0x00FAE538, 'key_cell': 0x00D4EB58,
                'world_ivar': 'OBJC_IVAR_$_DynamicObject.world', 'world_off': 4,
                'world_ivar_cell': 0x00D4EB6C, 'worldtime_sel_cell': 0x00D4EB68,
                'worldtime_site': 0x00D4EA78, 'worldtime_word': '33ff2fe1',
                'boxing_site': 0x00D4EA9C, 'boxing_word': '33ff2fe1',
                'set_site': 0x00D4EAC0, 'set_word': '3cff2fe1', 'set_sel_cell': 0x00D4EB60}


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

    st = EGG_SAVETIME
    obj = st['cfstring_obj']
    if abs32.get(obj) != '__CFConstantStringClassReference':
        raise ValueError('Egg.saveTime: CFString isa drift')
    if cstr(rw(obj + 8)) != st['key'] or rw(obj + 12) != len(st['key'].encode()):
        raise ValueError('Egg.saveTime: CFString payload drift')
    if rebase(st['key_cell']) != obj:
        raise ValueError('Egg.saveTime: key cell drift')
    wstor = ivar_by_name.get(st['world_ivar'])
    if wstor is None or rw(wstor) != st['world_off']:
        raise ValueError('Egg.saveTime: world ivar drift')
    if rw(rebase(st['world_ivar_cell'])) != wstor:
        raise ValueError('Egg.saveTime: world ivar cell drift')
    if cstr(rw(rebase(st['worldtime_sel_cell']))) != 'worldTime':
        raise ValueError('Egg.saveTime: worldTime selref drift')
    if not word_eq(st['worldtime_site'], st['worldtime_word']):
        raise ValueError('Egg.saveTime: worldTime site word drift')
    if not word_eq(st['boxing_site'], st['boxing_word']):
        raise ValueError('Egg.saveTime: boxing word drift')
    if not word_eq(st['set_site'], st['set_word']):
        raise ValueError('Egg.saveTime: set word drift')
    if cstr(rw(rebase(st['set_sel_cell']))) != 'setObject:forKey:':
        raise ValueError('Egg.saveTime: setObject selref drift')
    # insertion order: hatchTimer < saveTime < genesDict by set sites
    sites = [k['set_object_site'] for k in results['Egg']['keys']]
    order = [int(x, 16) for x in sites]
    assert order[0] < st['set_site'] < order[1], 'Egg saveTime must slot between'
    results['Egg']['keys'].insert(1, {'key': st['key'],
                                      'cfstring_object': f'0x{obj:08x}',
                                      'conversion': 'world_time_derived',
                                      'value_ivar': st['world_ivar'],
                                      'value_ivar_offset': st['world_off'],
                                      'worldtime_site': f'0x{st["worldtime_site"]:08x}',
                                      'conversion_site': f'0x{st["boxing_site"]:08x}',
                                      'set_object_site': f'0x{st["set_site"]:08x}'})

    return {
        'schema': 1, 'elf_sha256': SHA, 'pic_base': f'0x{BASE:08x}',
        'method': 'getSaveDict key pairings (batch 2g)',
        'classes': [results[c] for c in ('Rail', 'KelpPlant', 'VinePlant', 'Egg')],
        'claim': ('Rail: itemType@56 int, configuration<-currentConfiguration@60, '
                  'ownedByStation@65 numberWithBool: (no ownerID: exactly 7 '
                  'dispatch sites). KelpPlant/VinePlant share the plant growth '
                  'template with ABOVE@200/Below@180 divergence and KelpPlant '
                  'availableFood@180 vs VinePlant@100 — same keys, different '
                  'layouts. Egg adds hatchTimer@64 float, worldTime-derived '
                  'saveTime (same formula as NPC) and direct genesDict@56; 21 '
                  'overrides remain, read-back/roundtrip unresolved'),
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument('elf', type=Path)
    p.add_argument('--check', action='store_true')
    p.add_argument('--output', type=Path, default=NATIVE / 'subclass_savedict_keys_b2g.json')
    a = p.parse_args()
    text = json.dumps(recover(a.elf), indent=2, sort_keys=True) + '\n'
    if a.check:
        if a.output.read_text() != text:
            raise SystemExit('stale subclass_savedict_keys_b2g.json')
    else:
        a.output.write_text(text)
    print('b2g classes=4 keys=12')


if __name__ == '__main__':
    main()
