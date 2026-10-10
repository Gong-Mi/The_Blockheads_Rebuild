#!/usr/bin/env python3
"""Hash-gated getSaveDict shapes for SnowSurfaceBlock, Window, Yak (batch 2c).

SnowSurfaceBlock 0x00d8da7c (15w): NO super, NO dict reassembly — it returns
the pre-built ivar `SnowSurfaceBlock.saveDictCached` (self + 64):
    ldr r2,[ivar cell]; add r0=self, r2; ldr r0,[r0]; bx lr
i.e. a cached-dictionary accessor (a new style, distinct from the trees).

Window (112w): [super getSaveDict] + numberWithInt: itemType @56, then a
SECOND setObject:forKey: inserting the INHERITED ivar
`DynamicObject.ownerID` @36 (loaded via ldr from [self+36]) under the
'ownerID' key — an inherited-ivar key, not a same-class one.

Yak (113w): [super getSaveDict] + milk (numberWithFloat: @1136, key cell
@0x0095e09c) and hair (numberWithFloat: @1140) — both Yak ivars.

Gates: method-map row + next-IMP boundary; super triple (GOT import
file-word-zero, getSaveDict selref cstr, classref name-walk == class) for
Window/Yak; CFString ABS32+payload+length; ivar double-deref to the exact
OBJC_IVAR_$_ symbol (class-qualified) with storage word == offset; NSNumber
classref ABS32; raw dispatch words; set-selref == setObject:forKey:.
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
 'Window': (0x00C98E80, 0x00C99040, 0x00C99010, 0x00C99014, 0x00C99018, 0x00C98ED4, '3cff2fe1'),
 'Yak':    (0x0095DEE4, 0x0095E0A8, 0x0095E078, 0x0095E07C, 0x0095E080, 0x0095DF38, '3cff2fe1'),
}
# class, key, cfstring_obj, key_cell, ivar_SYM(full), ivar_off, conv_sel,
# conv_site, conv_word, number_classref_cell, set_site, set_word, set_sel_cell
KEYS = [
 ('Window','itemType',0x00FA2F68,0x00C99020,'OBJC_IVAR_$_Window.itemType',56,
  'numberWithInt:',0x00C98F64,'3cff2fe1',0x00C99034,0x00C98F88,'3cff2fe1',0x00C99028),
 ('Window','ownerID',0x00FA2F58,0x00C99038,'OBJC_IVAR_$_DynamicObject.ownerID',36,
  None,None,None,None,0x00C99000,'3cff2fe1',0x00C99028),
 ('Yak','milk',0x00F95718,0x0095E09C,'OBJC_IVAR_$_Yak.milk',1136,
  'numberWithFloat:',0x0095DFE4,'37ff2fe1',0x0095E098,0x0095E008,'3cff2fe1',0x0095E08C),
 ('Yak','hair',0x00F95728,0x0095E084,'OBJC_IVAR_$_Yak.hair',1140,
  'numberWithFloat:',0x0095E044,'3eff2fe1',0x0095E098,0x0095E068,'3cff2fe1',0x0095E08C),
]
SSB = {'imp': 0x00D8DA7C, 'boundary': 0x00D8DAB8,
       'ivar': 'OBJC_IVAR_$_SnowSurfaceBlock.saveDictCached', 'ivar_off': 64,
       'ivar_cell': 0x00D8DAB0, 'ret_site': 0x00D8DAA4, 'ret_word': '000090e5',
       'bx_site': 0x00D8DAAC, 'bx_word': '1eff2fe1'}


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
    ivar_by_name = {v: k for k, v in ivar_addr.items()}

    tsv = (NATIVE / 'libApplication_objc_methods.tsv').read_text().splitlines()[1:]
    rows = sorted((l.split('\t') for l in tsv), key=lambda l: int(l[0], 16))
    imps = [int(r[0], 16) for r in rows]
    by_imp = {int(r[0], 16): r for r in rows}

    def class_name(struct):
        return cstr(rw(rw(struct + 0x10) + 0x10))

    def check_ivar(sym, off):
        stor = ivar_by_name.get(sym)
        if stor is None or rw(stor) != off:
            raise ValueError(f'{sym}: ivar drift')

    def check_cfstring(key, obj):
        if abs32.get(obj) != '__CFConstantStringClassReference':
            raise ValueError(f'{key}: CFString isa drift')
        if cstr(rw(obj + 8)) != key or rw(obj + 12) != len(key.encode()):
            raise ValueError(f'{key}: CFString payload drift')

    # super classes
    results = {}
    for cls, (imp, boundary, gotc, selc, crc, site, word) in SUPER.items():
        row = by_imp.get(imp)
        if row is None or row[1] != cls or row[3] != 'getSaveDict':
            raise ValueError(f'{cls}: method-map drift')
        if min(i for i in imps if i > imp) != boundary:
            raise ValueError(f'{cls}: boundary drift')
        if rw(site).to_bytes(4, 'little').hex() != word:
            raise ValueError(f'{cls}: super site word drift')
        if rebase(gotc) != MSGSEND_SUPER2 or rw(MSGSEND_SUPER2) != 0 \
                or m.imports.get(MSGSEND_SUPER2) != 'objc_msgSendSuper2':
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

    for cls, key, obj, kcell, isym, off, conv, cs, cw, ncell, ss, sw, ssc in KEYS:
        check_cfstring(key, obj)
        if rebase(kcell) != obj:
            raise ValueError(f'{cls}.{key}: key cell drift')
        check_ivar(isym, off)
        if rw(ss).to_bytes(4, 'little').hex() != sw:
            raise ValueError(f'{cls}.{key}: setObject word drift')
        if cstr(rw(rebase(ssc))) != 'setObject:forKey:':
            raise ValueError(f'{cls}.{key}: setObject selref drift')
        entry = {'key': key, 'cfstring_object': f'0x{obj:08x}', 'ivar': isym,
                 'ivar_offset': off, 'set_object_site': f'0x{ss:08x}'}
        if conv is None:
            entry['conversion'] = 'direct_object'
        else:
            entry['conversion'] = conv
            entry['conversion_site'] = f'0x{cs:08x}'
            if rw(cs).to_bytes(4, 'little').hex() != cw:
                raise ValueError(f'{cls}.{key}: conv word drift')
            if abs32.get(rebase(ncell)) != 'OBJC_CLASS_$_NSNumber' or rw(rebase(ncell)) != 0:
                raise ValueError(f'{cls}.{key}: NSNumber classref drift')
        results[cls]['keys'].append(entry)

    # SnowSurfaceBlock cached-dict accessor
    imp = SSB['imp']
    row = by_imp.get(imp)
    if row is None or row[1] != 'SnowSurfaceBlock' or row[3] != 'getSaveDict':
        raise ValueError('SSB: method-map drift')
    if min(i for i in imps if i > imp) != SSB['boundary']:
        raise ValueError('SSB: boundary drift')
    check_ivar(SSB['ivar'], SSB['ivar_off'])
    if rw(SSB['ret_site']).to_bytes(4, 'little').hex() != SSB['ret_word'] \
            or rw(SSB['bx_site']).to_bytes(4, 'little').hex() != SSB['bx_word']:
        raise ValueError('SSB: return/bx word drift')
    results['SnowSurfaceBlock'] = {
        'class': 'SnowSurfaceBlock', 'imp': f'0x{imp:08x}',
        'boundary': f'0x{SSB["boundary"]:08x}',
        'code_words': (SSB['boundary'] - imp) // 4,
        'style': 'cached_dict_accessor',
        'cached_ivar': SSB['ivar'], 'cached_ivar_offset': SSB['ivar_off'],
        'return_site': f'0x{SSB["ret_site"]:08x}', 'keys': []}

    return {
        'schema': 1, 'elf_sha256': SHA, 'pic_base': f'0x{BASE:08x}',
        'method': 'getSaveDict shapes (batch 2c)',
        'classes': [results['SnowSurfaceBlock'], results['Window'], results['Yak']],
        'claim': ('SnowSurfaceBlock is a cached-dict accessor returning '
                  'saveDictCached @64 with no message send; Window adds '
                  'numberWithInt: itemType @56 then a SECOND setObject '
                  'inserting the INHERITED DynamicObject.ownerID @36 under '
                  'ownerID; Yak adds numberWithFloat: milk @1136 (executed '
                  'first) and hair @1140 despite pool order; 37 overrides, '
                  'read-back sides and save/roundtrip behavior unresolved'),
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument('elf', type=Path)
    p.add_argument('--check', action='store_true')
    p.add_argument('--output', type=Path, default=NATIVE / 'subclass_savedict_keys_b2c.json')
    a = p.parse_args()
    text = json.dumps(recover(a.elf), indent=2, sort_keys=True) + '\n'
    if a.check:
        if a.output.read_text() != text:
            raise SystemExit('stale subclass_savedict_keys_b2c.json')
    else:
        a.output.write_text(text)
    print('b2c classes=3 (SSB cached accessor, Window 2-key incl inherited ownerID, Yak 2 float)')


if __name__ == '__main__':
    main()
