#!/usr/bin/env python3
"""Hash-gated getSaveDict key pairings for batch 2i: Sign, ElevatorMotor,
ElevatorShaft, Painting. Addresses/words extracted mechanically from the
annotated listings + freeblock simulator (tools/gen_b2i_table.py), then
gated against the pinned ELF.

Shapes:
  Sign 0x005FAEB4: [super] + nil-guarded DIRECT text@100 (0x5faf94),
    ownerID@36 (0x5fb014), ownerName via InteractionObject@84 (0x5fb094),
    then connectionType@112 numberWithInt: (0x5fb138/0x5fb15c),
    offsetType@116 numberWithInt: (0x5fb198/0x5fb1bc).
  ElevatorMotor 0x00700B5C: [super] + itemType@56 numberWithInt: (0x700cc0/
    0x700ce4), availableElectricity@60 / minY@64 / maxY@68
    numberWithUnsignedInt: (0x700d20/0x700d44, 0x700d80/0x700da4,
    0x700de0/0x700e04), ownerID@36 direct.
  ElevatorShaft 0x00CAD998: [super] + itemType@56 numberWithInt: (0xcadb00/
    0xcadb24), lastKnownMotorPos.x@60 (0xcadb60/0xcadb84) and
    lastKnownMotorPos.y@+4 (0xcadbc0/0xcadbe4) DOTTED keys, paintColor@84
    numberWithUnsignedInt: (0xcadc20/0xcadc44), ownerID@36 direct.
  Painting 0x00AA8FC8: [super] + itemType@56 numberWithInt: (0xaa90ac/
    0xaa90d0), outputImageData DIRECT from Painting.imageData@60 gated by
    [imageData length]>0 (length call 0xaa9130, set 0xaa9190), ownerID@36
    direct, ownerName@64 direct, hasVerifiedImageData@79 numberWithBool:
    from ldrb+sxtb (0xaa930c/0xaa9330).
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
 'Sign':          (0x005FAEB4, 0x005FB214, 0x005FB1CC, 0x005FB1D0, 0x005FB1D4, 0x005FAF08),
 'ElevatorMotor': (0x00700B5C, 0x00700ED8, 0x00700E8C, 0x00700E90, 0x00700E94, 0x00700BB0),
 'ElevatorShaft': (0x00CAD998, 0x00CADD14, 0x00CADCCC, 0x00CADCD0, 0x00CADCD4, 0x00CAD9EC),
 'Painting':      (0x00AA8FC8, 0x00AA9390, 0x00AA9340, 0x00AA9344, 0x00AA9348, 0x00AA901C),
}
# class, key, key_cell, cfstring_obj, ivar, off, conv, conv_site, conv_word,
# ncell, conv_sel_cell, set_site, set_word, set_sel_cell
KEYS = [
 ('Sign','text',0x005FB1DC,0x00F7E388,'OBJC_IVAR_$_Sign.text',100,
  None,None,None,None,None,0x005FAF94,'3cff2fe1',0x005FB1E4),
 ('Sign','ownerID',0x005FB1EC,0x00F7E3B8,'OBJC_IVAR_$_DynamicObject.ownerID',36,
  None,None,None,None,None,0x005FB014,'3cff2fe1',0x005FB1E4),
 ('Sign','ownerName',0x005FB1F4,0x00F7E3C8,'OBJC_IVAR_$_InteractionObject.ownerName',84,
  None,None,None,None,None,0x005FB094,'3cff2fe1',0x005FB1E4),
 ('Sign','connectionType',0x005FB208,0x00F7E398,'OBJC_IVAR_$_Sign.connectionType',112,
  'numberWithInt:',0x005FB138,'3aff2fe1',0x005FB204,0x005FB1FC,0x005FB15C,'3cff2fe1',0x005FB1E4),
 ('Sign','offsetType',0x005FB1F8,0x00F7E3A8,'OBJC_IVAR_$_Sign.offsetType',116,
  'numberWithInt:',0x005FB198,'33ff2fe1',0x005FB204,0x005FB1FC,0x005FB1BC,'3cff2fe1',0x005FB1E4),
 ('ElevatorMotor','itemType',0x00700EC4,0x00F86E48,'OBJC_IVAR_$_ElevatorMotor.itemType',56,
  'numberWithInt:',0x00700CC0,'3cff2fe1',0x00700EB0,0x00700EC8,0x00700CE4,'3cff2fe1',0x00700EA4),
 ('ElevatorMotor','availableElectricity',0x00700EBC,0x00F86E58,'OBJC_IVAR_$_ElevatorMotor.availableElectricity',60,
  'numberWithUnsignedInt:',0x00700D20,'33ff2fe1',0x00700EB0,0x00700EA8,0x00700D44,'3cff2fe1',0x00700EA4),
 ('ElevatorMotor','minY',0x00700EB4,0x00F86E68,'OBJC_IVAR_$_ElevatorMotor.minY',64,
  'numberWithUnsignedInt:',0x00700D80,'33ff2fe1',0x00700EB0,0x00700EA8,0x00700DA4,'3cff2fe1',0x00700EA4),
 ('ElevatorMotor','maxY',0x00700E9C,0x00F86E78,'OBJC_IVAR_$_ElevatorMotor.maxY',68,
  'numberWithUnsignedInt:',0x00700DE0,'33ff2fe1',0x00700EB0,0x00700EA8,0x00700E04,'3cff2fe1',0x00700EA4),
 ('ElevatorMotor','ownerID',0x00700ED0,0x00F86E38,'OBJC_IVAR_$_DynamicObject.ownerID',36,
  None,None,None,None,None,0x00700E7C,'3cff2fe1',0x00700EA4),
 ('ElevatorShaft','itemType',0x00CADD04,0x00FA31C8,'OBJC_IVAR_$_ElevatorShaft.itemType',56,
  'numberWithInt:',0x00CADB00,'3cff2fe1',0x00CADCF0,0x00CADCF8,0x00CADB24,'3cff2fe1',0x00CADCE4),
 ('ElevatorShaft','lastKnownMotorPos.x',0x00CADD00,0x00FA31D8,'OBJC_IVAR_$_ElevatorShaft.lastKnownMotorPos',60,
  'numberWithInt:',0x00CADB60,'33ff2fe1',0x00CADCF0,0x00CADCF8,0x00CADB84,'3cff2fe1',0x00CADCE4),
 ('ElevatorShaft','lastKnownMotorPos.y',0x00CADCF4,0x00FA31E8,'OBJC_IVAR_$_ElevatorShaft.lastKnownMotorPos',60,
  'numberWithInt:',0x00CADBC0,'33ff2fe1',0x00CADCF0,0x00CADCF8,0x00CADBE4,'3cff2fe1',0x00CADCE4),
 ('ElevatorShaft','paintColor',0x00CADCDC,0x00FA31B8,'OBJC_IVAR_$_ElevatorShaft.paintColor',84,
  'numberWithUnsignedInt:',0x00CADC20,'33ff2fe1',0x00CADCF0,0x00CADCE8,0x00CADC44,'3cff2fe1',0x00CADCE4),
 ('ElevatorShaft','ownerID',0x00CADD0C,0x00FA31A8,'OBJC_IVAR_$_DynamicObject.ownerID',36,
  None,None,None,None,None,0x00CADCBC,'3cff2fe1',0x00CADCE4),
 ('Painting','itemType',0x00AA9350,0x00F9B5E8,'OBJC_IVAR_$_Painting.itemType',56,
  'numberWithInt:',0x00AA90AC,'3cff2fe1',0x00AA9364,0x00AA935C,0x00AA90D0,'3cff2fe1',0x00AA9358),
 ('Painting','outputImageData',0x00AA936C,0x00F9B5B8,'OBJC_IVAR_$_Painting.imageData',60,
  None,None,None,None,None,0x00AA9190,'3cff2fe1',0x00AA9358),
 ('Painting','ownerID',0x00AA9374,0x00F9B5C8,'OBJC_IVAR_$_DynamicObject.ownerID',36,
  None,None,None,None,None,0x00AA9210,'3cff2fe1',0x00AA9358),
 ('Painting','ownerName',0x00AA937C,0x00F9B5D8,'OBJC_IVAR_$_Painting.ownerName',64,
  None,None,None,None,None,0x00AA9290,'3cff2fe1',0x00AA9358),
 ('Painting','hasVerifiedImageData',0x00AA9380,0x00F9B5F8,'OBJC_IVAR_$_Painting.hasVerifiedImageData',79,
  'numberWithBool:',0x00AA930C,'3eff2fe1',0x00AA9364,0x00AA9384,0x00AA9330,'3cff2fe1',0x00AA9358),
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
        'method': 'getSaveDict key pairings (batch 2i)',
        'classes': [results[c] for c in ('Sign', 'ElevatorMotor',
                                          'ElevatorShaft', 'Painting')],
        'claim': ('Sign stores text/ownerID/ownerName as nil-or-zero-guarded RAW '
                  'OBJECTS then two numberWithInt: geometry keys; ElevatorMotor '
                  'and ElevatorShaft are the first numberWithUnsignedInt: boxes '
                  '(minY/maxY/paintColor) and ElevatorShaft introduces DOTTED '
                  'wire keys lastKnownMotorPos.x/.y from one struct ivar '
                  '(@60: x=word+0, y=word+4); Painting re-keys imageData as '
                  'outputImageData behind a [imageData length]>0 gate and '
                  'hasVerifiedImageData@79 is a signed byte (ldrb+sxtb); '
                  '13 overrides remain, read-back/roundtrip unresolved'),
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument('elf', type=Path)
    p.add_argument('--check', action='store_true')
    p.add_argument('--output', type=Path, default=NATIVE / 'subclass_savedict_keys_b2i.json')
    a = p.parse_args()
    text = json.dumps(recover(a.elf), indent=2, sort_keys=True) + '\n'
    if a.check:
        if a.output.read_text() != text:
            raise SystemExit('stale subclass_savedict_keys_b2i.json')
    else:
        a.output.write_text(text)
    print('b2i classes=4 keys=20')


if __name__ == '__main__':
    main()
