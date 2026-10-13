#!/usr/bin/env python3
"""Hash-gated key pairings for TrainStation/Bed/CraftableItemObject getSaveDict.

Three more of the 43 reassembling overrides, smallest bodies first:

Bed (112w): [super getSaveDict] + two numberWithInt: keys, itemType @100
    (conv 0x00d411c8 -> set 0x00d411ec) and beddingColor @104
    (conv 0x00d41228 -> set 0x00d4124c).
TrainStation (68w): [super getSaveDict] + direct object key `text` @128
    (NSString stored without conversion, set at 0x00b39560).
CraftableItemObject (78w): NO super — allocates [NSMutableDictionary
    dictionary] (blx 0x00ac7af4), boxes the object's own 124-byte POD region
    with [NSData dataWithBytes:self+4 length:0x7c] (blx 0x00ac7b34, movw
    0x7c at 0x00ac7a84) and inserts it under `craftableItem` (0x00ac7b58).
    This is the save-format evidence that craftable item state is a fixed
    124-byte inline struct at ivar offset 4.

Gates (pinned ELF, no proximity promotion): method-map row and next-IMP
boundary; super triple where applicable (GOT import file-word-zero,
getSaveDict selref cstr, classref slot whose materialised struct name-walks
to the class itself); per key: CFString ABS32 isa + payload + length, key
cell rebase, ivar double-deref to OBJC_IVAR_$_<Class>.<ivar> with storage
word == offset; NSNumber/NSData/NSMutableDictionary classref ABS32 gates;
raw words at every dispatch site; conversion/set selector names cross-checked
against the freeblock forward simulator output embedded in the listing
annotations.
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
MSGSEND = 0x0105B7A0

# (class, imp, boundary, super got cell, super selref cell, super classref
#  cell, super site, super word)
SUPER = {
 'Bed':           (0x00D410CC, 0x00D4128C, 0x00D4125C, 0x00D41260, 0x00D41264, 0x00D41120, '3cff2fe1'),
 'TrainStation':  (0x00B39480, 0x00B39590, 0x00B39570, 0x00B39574, 0x00B39578, 0x00B394D4, '3cff2fe1'),
}
# (class, key, cfstring_obj, key_cell, ivar_cell, ivar_off, conv_sel,
#  conv_site, conv_word, number_classref_cell or None (direct object),
#  set_site, set_word)
KEYS = [
 ('Bed', 'itemType', 0x00FAE468, 0x00D41280, 0x00D41284, 100, 'numberWithInt:',
  0x00D411C8, '37ff2fe1', 0x00D4127C, 0x00D411EC, '3cff2fe1'),
 ('Bed', 'beddingColor', 0x00FAE478, 0x00D41268, 0x00D41278, 104, 'numberWithInt:',
  0x00D41228, '33ff2fe1', 0x00D4127C, 0x00D4124C, '3cff2fe1'),
 ('TrainStation', 'text', 0x00F9D608, 0x00B39580, 0x00B3957C, 128, None,
  None, None, None, 0x00B39560, '3cff2fe1'),
]
CICO = {
 'imp': 0x00AC7A54, 'boundary': 0x00AC7B8C,
 'key': 'craftableItem', 'cfstring_obj': 0x00F9B7B8, 'key_cell': 0x00AC7B68,
 'ivar_cell': 0x00AC7B78, 'ivar': 'OBJC_IVAR_$_CraftableItemObject.craftableItem',
 'ivar_off': 4, 'struct_length': 0x7C,
 'dict_site': 0x00AC7AF4, 'dict_word': '3cff2fe1',
 'dict_classref_cell': 0x00AC7B84, 'dict_sel_cell': 0x00AC7B80,
 'data_site': 0x00AC7B34, 'data_word': '34ff2fe1',
 'data_classref_cell': 0x00AC7B7C, 'data_sel_cell': 0x00AC7B74,
 'set_site': 0x00AC7B58, 'set_word': '3cff2fe1', 'set_sel_cell': 0x00AC7B70,
 'length_word_site': 0x00AC7A84, 'length_word': '7c5000e3',  # movw r5,#0x7c
}


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

    def check_cfstring(key, obj):
        if abs32.get(obj) != '__CFConstantStringClassReference':
            raise ValueError(f'{key}: CFString isa drift')
        da = rw(obj + 8)
        if cstr(da) != key or rw(obj + 12) != len(key.encode()):
            raise ValueError(f'{key}: CFString payload drift')

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
        return cstr(rw(rw(struct + 0x10) + 0x10))

    def check_ivar_cell(cls, key, icell, off):
        slot = rebase(icell)
        stor = rw(slot)
        if ivar_addr.get(stor) != f'OBJC_IVAR_$_{cls}.{key}' or rw(stor) != off:
            raise ValueError(f'{cls}.{key}: ivar drift')

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

    for cls, key, obj, kcell, icell, off, conv, conv_site, conv_word, \
            ncell, set_site, set_word in KEYS:
        check_cfstring(key, obj)
        if rebase(kcell) != obj:
            raise ValueError(f'{cls}.{key}: key cell drift')
        check_ivar_cell(cls, key, icell, off)
        if rw(set_site).to_bytes(4, 'little').hex() != set_word:
            raise ValueError(f'{cls}.{key}: setObject word drift')
        if cstr(rw(rebase(_SET_SEL[cls]))) != 'setObject:forKey:':
            raise ValueError(f'{cls}.{key}: setObject selref drift')
        if conv is None:
            style = 'direct_object'
        else:
            style = conv
            if rw(conv_site).to_bytes(4, 'little').hex() != conv_word:
                raise ValueError(f'{cls}.{key}: conv word drift')
            if abs32.get(rebase(ncell)) != 'OBJC_CLASS_$_NSNumber' \
                    or rw(rebase(ncell)) != 0:
                raise ValueError(f'{cls}.{key}: NSNumber classref drift')
        results[cls]['keys'].append({
            'key': key, 'cfstring_object': f'0x{obj:08x}',
            'ivar': f'OBJC_IVAR_$_{cls}.{key}',
            'ivar_offset': off, 'conversion': style,
            'set_object_site': f'0x{set_site:08x}',
            **({'conversion_site': f'0x{conv_site:08x}'} if conv else {})})

    ci = CICO
    row = by_imp.get(ci['imp'])
    if row is None or row[1] != 'CraftableItemObject' or row[3] != 'getSaveDict':
        raise ValueError('CICO: method-map drift')
    if min(i for i in imps if i > ci['imp']) != ci['boundary']:
        raise ValueError('CICO: boundary drift')
    check_cfstring(ci['key'], ci['cfstring_obj'])
    if rebase(ci['key_cell']) != ci['cfstring_obj']:
        raise ValueError('CICO: key cell drift')
    slot = rebase(ci['ivar_cell'])
    stor = rw(slot)
    if ivar_addr.get(stor) != ci['ivar'] or rw(stor) != ci['ivar_off']:
        raise ValueError('CICO: ivar drift')
    for site, word, tag in ((ci['dict_site'], ci['dict_word'], 'dict'),
                            (ci['data_site'], ci['data_word'], 'data'),
                            (ci['set_site'], ci['set_word'], 'set')):
        if rw(site).to_bytes(4, 'little').hex() != word:
            raise ValueError(f'CICO: {tag} word drift')
    if rw(ci['length_word_site']).to_bytes(4, 'little').hex() != ci['length_word']:
        raise ValueError('CICO: length movw drift')
    for cell, klass in ((ci['dict_classref_cell'], 'OBJC_CLASS_$_NSMutableDictionary'),
                        (ci['data_classref_cell'], 'OBJC_CLASS_$_NSData')):
        t = rebase(cell)
        if abs32.get(t) != klass or rw(t) != 0:
            raise ValueError(f'CICO: {klass} classref drift')
    for cell, selname in ((ci['dict_sel_cell'], 'dictionary'),
                          (ci['data_sel_cell'], 'dataWithBytes:length:'),
                          (ci['set_sel_cell'], 'setObject:forKey:')):
        if cstr(rw(rebase(cell))) != selname:
            raise ValueError(f'CICO: {selname} selref drift')
    results['CraftableItemObject'] = {
        'class': 'CraftableItemObject', 'imp': f"0x{ci['imp']:08x}",
        'boundary': f"0x{ci['boundary']:08x}",
        'code_words': (ci['boundary'] - ci['imp']) // 4,
        'style': 'fresh_dictionary_pod_blob',
        'keys': [{'key': ci['key'], 'cfstring_object': f"0x{ci['cfstring_obj']:08x}",
                  'ivar': ci['ivar'], 'ivar_offset': ci['ivar_off'],
                  'conversion': 'dataWithBytes:length:',
                  'struct_length': ci['struct_length'],
                  'conversion_site': f"0x{ci['data_site']:08x}",
                  'set_object_site': f"0x{ci['set_site']:08x}"}]}

    return {
        'schema': 1, 'elf_sha256': SHA, 'pic_base': f'0x{BASE:08x}',
        'method': 'subclass getSaveDict own-key pairings (batch 2b)',
        'classes': [results[c] for c in ('Bed', 'TrainStation', 'CraftableItemObject')],
        'claim': ('Bed stores two numberWithInt: ints (itemType @100 first, beddingColor '
                  '@104 second, order from the simulator); TrainStation stores its text '
                  'NSString directly (no conversion); CraftableItemObject builds a fresh '
                  'NSMutableDictionary and stores a 124-byte NSData copy of the POD at '
                  'self+4 — no parent dictionary at all in that body; remaining 40 '
                  'overrides, the read-back sides of these keys, and save/roundtrip '
                  'behavior unresolved'),
    }


_SET_SEL = {'Bed': 0x00D41270, 'TrainStation': 0x00B39588}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('elf', type=Path)
    p.add_argument('--check', action='store_true')
    p.add_argument('--output', type=Path, default=NATIVE / 'item_savedict_keys.json')
    a = p.parse_args()
    text = json.dumps(recover(a.elf), indent=2, sort_keys=True) + '\n'
    if a.check:
        if a.output.read_text() != text:
            raise SystemExit('stale item_savedict_keys.json')
    else:
        a.output.write_text(text)
    print('item-savedict classes=3 keys=4')


if __name__ == '__main__':
    main()
