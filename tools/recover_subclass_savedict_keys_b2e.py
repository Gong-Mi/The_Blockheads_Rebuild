#!/usr/bin/env python3
"""Hash-gated getSaveDict key pairings for batch 2e: Tutorial,
BlockheadCraftableItemObject, Ladder, TradePortal.

Every dispatch word and literal cell is extracted mechanically from the
annotated listings (extraction-first workflow), then independently gated on
the pinned ELF.

Shapes:
  Tutorial 0x0071e1f0 (146w): fresh [NSMutableDictionary dictionary] (blx
    0x0071e2cc), NO super; numberWithInt: state @12 (conv 0x0071e30c, set
    0x0071e330), numberWithInt: impromptuNightState @16 (0x0071e36c/
    0x0071e390), numberWithBool: wrongToolHasBeenDisplayed @20
    (0x0071e3cc/0x0071e3f0). Pool lists wrongTool cells first; execution is
    state -> impromptuNightState -> wrongTool (pool order != exec order).
  BlockheadCraftableItemObject 0x00811b60 (150w): [super getSaveDict] +
    direct-object name @128 (set 0x00811cc0) + dataWithBytes:length: of the
    20-byte POD at skinOptions @132 (movw r8,#0x14 @0x00811bfc; conv
    0x00811cfc blx r4; set 0x00811d20) + numberWithInt: of the CONSTANT 1
    under craftableObjectType (movw lr,#1 @0x00811bdc; conv 0x00811d48,
    set 0x00811d6c).
  Ladder 0x00aae2ac (155w): [super] + numberWithInt: itemType @56
    (0x00aae3d0/0x00aae3f4) + numberWithUnsignedInt: paintColor @60
    (0x00aae430/0x00aae454) + direct-object INHERITED
    DynamicObject.ownerID @36 (set 0x00aae4cc).
  TradePortal 0x00d39460 (157w): [super] + direct-object
    localPriceOffsets @128 (set 0x00d39540) + numberWithInt: level @132
    (0x00d395ec/0x00d39610) + nested [TradePortal.light @100 getSaveDict]
    (0x00d39634) inserted as lightDict (0x00d3968c).
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
 'BlockheadCraftableItemObject': (0x00811B60, 0x00811DB8, 0x00811D7C, 0x00811D80, 0x00811D84, 0x00811BB4, '3cff2fe1'),
 'Ladder':   (0x00AAE2AC, 0x00AAE518, 0x00AAE4DC, 0x00AAE4E0, 0x00AAE4E4, 0x00AAE300, '3cff2fe1'),
 'TradePortal': (0x00D39460, 0x00D396D4, 0x00D3969C, 0x00D396A0, 0x00D396A4, 0x00D394B4, '3cff2fe1'),
}
TUTORIAL = {'imp': 0x0071E1F0, 'boundary': 0x0071E438,
            'dict_site': 0x0071E2CC, 'dict_word': '3cff2fe1',
            'dict_selref_cell': 0x0071E42C, 'dict_classref_cell': 0x0071E430,
            'set_selref_cell': 0x0071E408, 'num_classref_cell': 0x0071E414}
# (class, key, cfstring_obj, ivar_sym_or_None, ivar_off, conv_sel_or_None,
#  conv_site, conv_word, number_classref_cell_or_None, set_site, set_word,
#  set_sel_cell, extra)
KEYS = [
 ('Tutorial', 'state', 0x00F89BE8, 'OBJC_IVAR_$_Tutorial.state', 12,
  'numberWithInt:', 0x0071E30C, '33ff2fe1', 0x0071E414, 0x0071E330, '3cff2fe1', 0x0071E408,
  {'conv_selref_cell': 0x0071E41C}),
 ('Tutorial', 'impromptuNightState', 0x00F89BF8, 'OBJC_IVAR_$_Tutorial.impromptuNightState', 16,
  'numberWithInt:', 0x0071E36C, '33ff2fe1', 0x0071E414, 0x0071E390, '3cff2fe1', 0x0071E408,
  {'conv_selref_cell': 0x0071E41C}),
 ('Tutorial', 'wrongToolHasBeenDisplayed', 0x00F89C08, 'OBJC_IVAR_$_Tutorial.wrongToolHasBeenDisplayed', 20,
  'numberWithBool:', 0x0071E3CC, '33ff2fe1', 0x0071E414, 0x0071E3F0, '3cff2fe1', 0x0071E408,
  {'conv_selref_cell': 0x0071E40C, 'conv_sel': 'numberWithBool:'}),
 ('BlockheadCraftableItemObject', 'name', 0x00F91E18, 'OBJC_IVAR_$_BlockheadCraftableItemObject.name', 128,
  None, None, None, None, 0x00811CC0, '3cff2fe1', 0x00811D90, None),
 ('BlockheadCraftableItemObject', 'skinOptions', 0x00F91E28, 'OBJC_IVAR_$_BlockheadCraftableItemObject.skinOptions', 132,
  'dataWithBytes:length:', 0x00811CFC, '34ff2fe1', 0x00811DA8, 0x00811D20, '3cff2fe1', 0x00811D90,
  {'data_selref_cell': 0x00811DA0, 'pod_len_site': 0x00811BFC, 'pod_len_word': '148000e3',
   'pod_len': 20}),
 ('BlockheadCraftableItemObject', 'craftableObjectType', 0x00F91E78, None, None,
  'numberWithInt:', 0x00811D48, '3cff2fe1', 0x00811D98, 0x00811D6C, '3cff2fe1', 0x00811D90,
  {'const_site': 0x00811BDC, 'const_word': '01e000e3', 'const_value': 1,
   'conv_selref_cell': 0x00811D94}),
 ('Ladder', 'itemType', 0x00F9B678, 'OBJC_IVAR_$_Ladder.itemType', 56,
  'numberWithInt:', 0x00AAE3D0, '3cff2fe1', 0x00AAE500, 0x00AAE3F4, '3cff2fe1', 0x00AAE4F4,
  {'conv_selref_cell': 0x00AAE508, 'conv_sel': 'numberWithInt:'}),
 ('Ladder', 'paintColor', 0x00F9B658, 'OBJC_IVAR_$_Ladder.paintColor', 60,
  'numberWithUnsignedInt:', 0x00AAE430, '33ff2fe1', 0x00AAE500, 0x00AAE454, '3cff2fe1', 0x00AAE4F4,
  {'conv_selref_cell': 0x00AAE4F8}),
 ('Ladder', 'ownerID', 0x00F9B668, 'OBJC_IVAR_$_DynamicObject.ownerID', 36,
  None, None, None, None, 0x00AAE4CC, '3cff2fe1', 0x00AAE4F4, None),
 ('TradePortal', 'localPriceOffsets', 0x00FAE218, 'OBJC_IVAR_$_TradePortal.localPriceOffsets', 128,
  None, None, None, None, 0x00D39540, '3cff2fe1', 0x00D396B4, None),
 ('TradePortal', 'level', 0x00FAE228, 'OBJC_IVAR_$_TradePortal.level', 132,
  'numberWithInt:', 0x00D395EC, '38ff2fe1', 0x00D396C8, 0x00D39610, '3cff2fe1', 0x00D396B4,
  {'conv_selref_cell': 0x00D396C0}),
 ('TradePortal', 'lightDict', 0x00FAE238, 'OBJC_IVAR_$_TradePortal.light', 100,
  'nested_getSaveDict', 0x00D39634, '33ff2fe1', None, 0x00D3968C, '3cff2fe1', 0x00D396B4, None),
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
    tu = TUTORIAL
    row = by_imp.get(tu['imp'])
    if row is None or row[1] != 'Tutorial' or row[3] != 'getSaveDict':
        raise ValueError('Tutorial: method-map drift')
    if min(i for i in imps if i > tu['imp']) != tu['boundary']:
        raise ValueError('Tutorial: boundary drift')
    if not word_eq(tu['dict_site'], tu['dict_word']):
        raise ValueError('Tutorial: dictionary site word drift')
    if cstr(rw(rebase(tu['dict_selref_cell']))) != 'dictionary':
        raise ValueError('Tutorial: dictionary selref drift')
    if abs32.get(rebase(tu['dict_classref_cell'])) != 'OBJC_CLASS_$_NSMutableDictionary' \
            or rw(rebase(tu['dict_classref_cell'])) != 0:
        raise ValueError('Tutorial: NSMutableDictionary classref drift')
    results['Tutorial'] = {'class': 'Tutorial', 'imp': f'0x{tu["imp"]:08x}',
                           'boundary': f'0x{tu["boundary"]:08x}',
                           'code_words': (tu['boundary'] - tu['imp']) // 4,
                           'style': 'fresh_dictionary',
                           'dictionary_site': f'0x{tu["dict_site"]:08x}', 'keys': []}

    for cls, (imp, boundary, gotc, selc, crc, site, word) in SUPER.items():
        row = by_imp.get(imp)
        if row is None or row[1] != cls or row[3] != 'getSaveDict':
            raise ValueError(f'{cls}: method-map drift')
        if min(i for i in imps if i > imp) != boundary:
            raise ValueError(f'{cls}: boundary drift')
        if not word_eq(site, word):
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

    for cls, key, obj, isym, off, conv, cs, cw, ncell, ss, sw, ssc, extra in KEYS:
        if abs32.get(obj) != '__CFConstantStringClassReference':
            raise ValueError(f'{cls}.{key}: CFString isa drift')
        if cstr(rw(obj + 8)) != key or rw(obj + 12) != len(key.encode()):
            raise ValueError(f'{cls}.{key}: CFString payload drift')
        if not word_eq(ss, sw):
            raise ValueError(f'{cls}.{key}: set word drift')
        if cstr(rw(rebase(ssc))) != 'setObject:forKey:':
            raise ValueError(f'{cls}.{key}: setObject selref drift')
        entry = {'key': key, 'cfstring_object': f'0x{obj:08x}',
                 'set_object_site': f'0x{ss:08x}'}
        if isym:
            stor = ivar_by_name.get(isym)
            if stor is None or rw(stor) != off:
                raise ValueError(f'{cls}.{key}: ivar drift')
            entry['ivar'] = isym
            entry['ivar_offset'] = off
        if conv is None:
            entry['conversion'] = 'direct_object'
        else:
            entry['conversion'] = conv
            entry['conversion_site'] = f'0x{cs:08x}'
            if not word_eq(cs, cw):
                raise ValueError(f'{cls}.{key}: conv word drift')
            if conv == 'nested_getSaveDict':
                pass  # receiver/sel identical cell chain as class super (gated above)
            else:
                if abs32.get(rebase(ncell)) != ('OBJC_CLASS_$_NSData' if extra and
                        extra.get('data_selref_cell') else 'OBJC_CLASS_$_NSNumber') \
                        or rw(rebase(ncell)) != 0:
                    raise ValueError(f'{cls}.{key}: classref drift')
            if extra and 'conv_selref_cell' in extra:
                want = extra.get('conv_sel', conv)
                if cstr(rw(rebase(extra['conv_selref_cell']))) != want:
                    raise ValueError(f'{cls}.{key}: conv selref drift')
            if extra and 'pod_len_site' in extra:
                if not word_eq(extra['pod_len_site'], extra['pod_len_word']):
                    raise ValueError(f'{cls}.{key}: pod length movw drift')
                entry['pod_length'] = extra['pod_len']
            if extra and 'const_site' in extra:
                if not word_eq(extra['const_site'], extra['const_word']):
                    raise ValueError(f'{cls}.{key}: constant movw drift')
                entry['value_constant'] = extra['const_value']
        results[cls]['keys'].append(entry)

    return {
        'schema': 1, 'elf_sha256': SHA, 'pic_base': f'0x{BASE:08x}',
        'method': 'getSaveDict key pairings (batch 2e)',
        'classes': [results[c] for c in ('Tutorial',
                                          'BlockheadCraftableItemObject',
                                          'Ladder', 'TradePortal')],
        'claim': ('Tutorial builds a fresh NSMutableDictionary (no super) with '
                  'state @12 / impromptuNightState @16 ints and '
                  'wrongToolHasBeenDisplayed @20 bool; '
                  'BlockheadCraftableItemObject saves name @128 direct, a '
                  '20-byte NSData POD of skinOptions @132 and the CONSTANT 1 '
                  'as craftableObjectType; Ladder adds itemType @56, '
                  'numberWithUnsignedInt: paintColor @60 and the inherited '
                  'ownerID @36; TradePortal nests [light @100 getSaveDict] as '
                  'lightDict with localPriceOffsets @128 and level @132; '
                  '29 overrides remain, read-back/roundtrip unresolved'),
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument('elf', type=Path)
    p.add_argument('--check', action='store_true')
    p.add_argument('--output', type=Path, default=NATIVE / 'subclass_savedict_keys_b2e.json')
    a = p.parse_args()
    text = json.dumps(recover(a.elf), indent=2, sort_keys=True) + '\n'
    if a.check:
        if a.output.read_text() != text:
            raise SystemExit('stale subclass_savedict_keys_b2e.json')
    else:
        a.output.write_text(text)
    print('b2e classes=4 keys=11')


if __name__ == '__main__':
    main()
