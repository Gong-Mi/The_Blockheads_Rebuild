#!/usr/bin/env python3
"""Hash-gated getSaveDict key pairings for batch 2h: TulipPlant, SteamTrain,
OwnershipSign, CactusTree. Addresses/words extracted mechanically from the
annotated listings + freeblock simulator, then gated against the pinned ELF.

Shapes:
  TulipPlant 0x009a1854: [super] + availableFood@100 float (0x9a19c0/
    0x9a19e4), colorGenes@112 int (0x9a1a20/0x9a1a44), mixGenes@114 int
    (0x9a1a80/0x9a1aa4), mateColorGenes@116 int (0x9a1ae0/0x9a1b04).
  SteamTrain 0x00d18e84: [super] + fuelFraction@260 float (0xd18ff0/
    0xd19014), hasFuel@268 bool (0xd19050/0xd19074), goingRight@252 bool
    (0xd190b0/0xd190d4), stopped@325 bool (0xd19110/0xd19134).
  OwnershipSign 0x00a358e4: [super] + DIRECT-OBJECT landOwnerID@124
    (set 0xa35a04) and landOwnerName@128 (set 0xa35a3c) — the ID is stored
    as an object, NOT boxed numberWithInt: — then w<-widthRadius@132 int
    (0xa35ad8/0xa35afc), h<-heightRadius@136 int (0xa35b98/0xa35bbc).
  CactusTree 0x00b53728: [super] + splitHeightA@136 int (0xb538b4/
    0xb538d8), splitHeightB@140 int (0xb53914/0xb53938), splitDirection@144
    bool (0xb53974/0xb53998), availableFood@148 float (0xb539d4/0xb539f8).
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
 'TulipPlant':  (0x009A1854, 0x009A1B58, 0x009A1B14, 0x009A1B18, 0x009A1B1C, 0x009A18A8),
 'SteamTrain':  (0x00D18E84, 0x00D19188, 0x00D19144, 0x00D19148, 0x00D1914C, 0x00D18ED8),
 'OwnershipSign':(0x00A358E4, 0x00A35C0C, 0x00A35BCC, 0x00A35BD0, 0x00A35BD4, 0x00A35938),
 'CactusTree':  (0x00B53728, 0x00B53A50, 0x00B53A08, 0x00B53A0C, 0x00B53A10, 0x00B5377C),
}

CALL_MANIFESTS = {
 'TulipPlant': [0x009A18A8, 0x009A19C0, 0x009A19E4, 0x009A1A20, 0x009A1A44, 0x009A1A80, 0x009A1AA4, 0x009A1AE0, 0x009A1B04],
 'SteamTrain': [0x00D18ED8, 0x00D18FF0, 0x00D19014, 0x00D19050, 0x00D19074, 0x00D190B0, 0x00D190D4, 0x00D19110, 0x00D19134],
 'OwnershipSign': [0x00A35938, 0x00A35A04, 0x00A35A3C, 0x00A35AD8, 0x00A35AFC, 0x00A35B98, 0x00A35BBC],
 'CactusTree': [0x00B5377C, 0x00B538B4, 0x00B538D8, 0x00B53914, 0x00B53938, 0x00B53974, 0x00B53998, 0x00B539D4, 0x00B539F8],
}

BRANCH_MANIFESTS = {
 'TulipPlant': [],
 'SteamTrain': [],
 'OwnershipSign': [0x00A3596C, 0x00A35994, 0x00A35A60, 0x00A35B20],
 'CactusTree': [],
}

BODY_SHA256 = {
 'TulipPlant': '02751712c22382848a87ae8d4a3abbd518d7ef6479a11d4b4244b81a4bccff29',
 'SteamTrain': 'b53882a4019a9d5d50321ad77be4ee058c9b79de6bc60811ca316fd6ece4fc19',
 'OwnershipSign': '03db3baafaf27aa82b07bd32b69c6a69c78512e3dff6f3846c83efdd4e066ee7',
 'CactusTree': '93892c30515e781b0ee30aa3706574ba102cab11347ee0f86692a8440e95e00b',
}
# class, key, key_cell, cfstring_obj, ivar, off, conv, conv_site, conv_word,
# ncell, conv_sel_cell, set_site, set_word, set_sel_cell
KEYS = [
 ('TulipPlant','availableFood',0x009A1B48,0x00F95D78,'OBJC_IVAR_$_TulipPlant.availableFood',100,
  'numberWithFloat:',0x009A19C0,'33ff2fe1',0x009A1B34,0x009A1B4C,0x009A19E4,'3cff2fe1',0x009A1B28),
 ('TulipPlant','colorGenes',0x009A1B40,0x00F95D88,'OBJC_IVAR_$_TulipPlant.colorGenes',112,
  'numberWithInt:',0x009A1A20,'33ff2fe1',0x009A1B34,0x009A1B2C,0x009A1A44,'3cff2fe1',0x009A1B28),
 ('TulipPlant','mixGenes',0x009A1B38,0x00F95DA8,'OBJC_IVAR_$_TulipPlant.mixGenes',114,
  'numberWithInt:',0x009A1A80,'33ff2fe1',0x009A1B34,0x009A1B2C,0x009A1AA4,'3cff2fe1',0x009A1B28),
 ('TulipPlant','mateColorGenes',0x009A1B20,0x00F95D98,'OBJC_IVAR_$_TulipPlant.mateColorGenes',116,
  'numberWithInt:',0x009A1AE0,'33ff2fe1',0x009A1B34,0x009A1B2C,0x009A1B04,'3cff2fe1',0x009A1B28),
 ('SteamTrain','fuelFraction',0x00D19178,0x00FADED8,'OBJC_IVAR_$_SteamTrain.fuelFraction',260,
  'numberWithFloat:',0x00D18FF0,'33ff2fe1',0x00D19164,0x00D1917C,0x00D19014,'3cff2fe1',0x00D19158),
 ('SteamTrain','hasFuel',0x00D19170,0x00FADEE8,'OBJC_IVAR_$_SteamTrain.hasFuel',268,
  'numberWithBool:',0x00D19050,'33ff2fe1',0x00D19164,0x00D1915C,0x00D19074,'3cff2fe1',0x00D19158),
 ('SteamTrain','goingRight',0x00D19168,0x00FADEF8,'OBJC_IVAR_$_SteamTrain.goingRight',252,
  'numberWithBool:',0x00D190B0,'33ff2fe1',0x00D19164,0x00D1915C,0x00D190D4,'3cff2fe1',0x00D19158),
 ('SteamTrain','stopped',0x00D19150,0x00FADF08,'OBJC_IVAR_$_SteamTrain.stopped',325,
  'numberWithBool:',0x00D19110,'33ff2fe1',0x00D19164,0x00D1915C,0x00D19134,'3cff2fe1',0x00D19158),
 ('OwnershipSign','landOwnerID',0x00A35BEC,0x00F97128,'OBJC_IVAR_$_OwnershipSign.landOwnerID',124,
  None,None,None,None,None,0x00A35A04,'3eff2fe1',0x00A35BE8),
 ('OwnershipSign','landOwnerName',0x00A35BE0,0x00F97138,'OBJC_IVAR_$_OwnershipSign.landOwnerName',128,
  None,None,None,None,None,0x00A35A3C,'3cff2fe1',0x00A35BE8),
 ('OwnershipSign','w',0x00A35BF4,0x00F97148,'OBJC_IVAR_$_OwnershipSign.widthRadius',132,
  'numberWithInt:',0x00A35AD8,'3eff2fe1',0x00A35BFC,0x00A35BF8,0x00A35AFC,'3cff2fe1',0x00A35BE8),
 ('OwnershipSign','h',0x00A35C04,0x00F97158,'OBJC_IVAR_$_OwnershipSign.heightRadius',136,
  'numberWithInt:',0x00A35B98,'3eff2fe1',0x00A35BFC,0x00A35BF8,0x00A35BBC,'3cff2fe1',0x00A35BE8),
 ('CactusTree','splitHeightA',0x00B53A44,0x00F9D988,'OBJC_IVAR_$_CactusTree.splitHeightA',136,
  'numberWithInt:',0x00B538B4,'33ff2fe1',0x00B53A28,0x00B53A3C,0x00B538D8,'3cff2fe1',0x00B53A1C),
 ('CactusTree','splitHeightB',0x00B53A38,0x00F9D998,'OBJC_IVAR_$_CactusTree.splitHeightB',140,
  'numberWithInt:',0x00B53914,'33ff2fe1',0x00B53A28,0x00B53A3C,0x00B53938,'3cff2fe1',0x00B53A1C),
 ('CactusTree','splitDirection',0x00B53A2C,0x00F9D9A8,'OBJC_IVAR_$_CactusTree.splitDirection',144,
  'numberWithBool:',0x00B53974,'33ff2fe1',0x00B53A28,0x00B53A30,0x00B53998,'3cff2fe1',0x00B53A1C),
 ('CactusTree','availableFood',0x00B53A14,0x00F9D9B8,'OBJC_IVAR_$_CactusTree.availableFood',148,
  'numberWithFloat:',0x00B539D4,'3eff2fe1',0x00B53A28,0x00B53A20,0x00B539F8,'3cff2fe1',0x00B53A1C),
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
        off_body = m.offset(imp, boundary - imp)
        if off_body is None:
            raise ValueError(f'{cls}: unmapped body')
        body_bytes = m.data[off_body:off_body + (boundary - imp)]
        actual_sha = hashlib.sha256(body_bytes).hexdigest()
        if actual_sha != BODY_SHA256[cls]:
            raise ValueError(f'{cls}: body sha256 drift')
        results[cls] = {'class': cls, 'imp': f'0x{imp:08x}',
                        'boundary': f'0x{boundary:08x}',
                        'code_words': (boundary - imp) // 4,
                        'body_sha256': actual_sha,
                        'style': 'super_plus_own_keys',
                        'super_site': f'0x{site:08x}',
                        'super_class_struct': f'0x{struct:08x}',
                        'call_sites': [f'0x{c:08x}' for c in CALL_MANIFESTS[cls]],
                        'branch_sites': [f'0x{b:08x}' for b in BRANCH_MANIFESTS[cls]],
                        'keys': []}

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
        'method': 'getSaveDict key pairings (batch 2h)',
        'classes': [results[c] for c in ('TulipPlant', 'SteamTrain',
                                          'OwnershipSign', 'CactusTree')],
        'claim': ('TulipPlant gene trio at tight @112/114/116 + availableFood@100; '
                  'SteamTrain four train-state keys incl stopped@325 (deep struct); '
                  'OwnershipSign stores landOwnerID/landOwnerName as RAW OBJECTS '
                  '(no numberWithInt: boxing) under short keys w/h for '
                  'widthRadius/heightRadius; CactusTree split geometry trio + '
                  'availableFood@148; 17 overrides remain, read-back/roundtrip '
                  'unresolved'),
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument('elf', type=Path)
    p.add_argument('--check', action='store_true')
    p.add_argument('--output', type=Path, default=NATIVE / 'subclass_savedict_keys_b2h.json')
    a = p.parse_args()
    text = json.dumps(recover(a.elf), indent=2, sort_keys=True) + '\n'
    if a.check:
        if a.output.read_text() != text:
            raise SystemExit('stale subclass_savedict_keys_b2h.json')
    else:
        a.output.write_text(text)
    print('b2h classes=4 keys=16')


if __name__ == '__main__':
    main()
