#!/usr/bin/env python3
"""Hash-gated getSaveDict key pairings for batch 2d: PaintingCraftableItemObject,
NormalPlant, GlowBlock, GatherBlock.

All dispatch-site words and CFString/ivar/classref cells were extracted
mechanically from the annotated listings (no hand transcription), then each
pairing is re-gated independently against the pinned ELF.

Shapes:
  PaintingCraftableItemObject 0x00742008 [super] + direct-object imageData
    (NSData ivar @128, set 0x742074) + direct-object outputImageData (@132,
    set 0x7420ec) + numberWithInt: craftableObjectType (conv 0x742150,
    set 0x742174; VALUE-CELL pending, deliberately ungated).
  NormalPlant 0x00a66e68 [super] + numberWithFloat: availableFood @120
    (conv 0xa66f04, set 0xa66f28); then [self emitsLight] guard (0xa66f3c,
    cmp r0,#0 beq 0xa66ff4) around nested [self.light @124 getSaveDict]
    (0xa66f94) inserted directly as `lightDict` (set 0xa66fec).
  GlowBlock 0x00ca8ccc [super] + numberWithInt: tileType @60 (conv 0xca8d84,
    set 0xca8da8); nested [self.light @56 getSaveDict] (0xca8dcc) with
    cmp/beq-nil-skip 0xca8ddc/0xca8de0 inserted as `lightDict` (0xca8e24).
  GatherBlock 0x008697f4 [super] + numberWithFloat: timer @56 (conv
    0x8698c0, set 0x8698e4) BEFORE numberWithInt: lastKnownGatherValue @60
    (conv 0x869920, set 0x869944) — again pool order != execution order.
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
 'PaintingCraftableItemObject': (0x00741FB4, 0x007421B8, 0x00742184, 0x00742188, 0x0074218C, 0x00742008),
 'NormalPlant': (0x00A66E14, 0x00A67034, 0x00A67000, 0x00A67004, 0x00A67008, 0x00A66E68),
 'GlowBlock':   (0x00CA8C78, 0x00CA8E64, 0x00CA8E34, 0x00CA8E38, 0x00CA8E3C, 0x00CA8CCC),
 'GatherBlock': (0x008697A0, 0x00869988, 0x00869954, 0x00869958, 0x0086995C, 0x008697F4),
}
# (class, key, cfstring_obj, ivar_sym_or_None, ivar_off, conv_sel_or_None,
#  conv_site, conv_word, number_classref_cell_or_None, set_site, set_word,
#  set_sel_cell)
KEYS = [
 ('PaintingCraftableItemObject','imageData',0x00F8CEB8,'OBJC_IVAR_$_PaintingCraftableItemObject.imageData',128,
  None,None,None,None,0x00742074,'3cff2fe1',0x0074219C),
 ('PaintingCraftableItemObject','outputImageData',0x00F8CEC8,'OBJC_IVAR_$_PaintingCraftableItemObject.outputImageData',132,
  None,None,None,None,0x007420EC,'3cff2fe1',0x0074219C),
 ('PaintingCraftableItemObject','craftableObjectType',0x00F8CED8,None,None,
  'numberWithInt:',0x00742150,'3eff2fe1',0x007421B0,0x00742174,'3cff2fe1',0x0074219C),
 ('NormalPlant','availableFood',0x00F97418,'OBJC_IVAR_$_NormalPlant.availableFood',120,
  'numberWithFloat:',0x00A66F04,'35ff2fe1',0x00A67024,0x00A66F28,'3cff2fe1',0x00A67018),
 ('NormalPlant','lightDict',0x00F97428,'OBJC_IVAR_$_NormalPlant.light',124,
  'nested_getSaveDict',0x00A66F94,'33ff2fe1',None,0x00A66FEC,'3cff2fe1',0x00A67018),
 ('GlowBlock','tileType',0x00FA30D8,'OBJC_IVAR_$_GlowBlock.tileType',60,
  'numberWithInt:',0x00CA8D84,'38ff2fe1',0x00CA8E58,0x00CA8DA8,'3cff2fe1',0x00CA8E4C),
 ('GlowBlock','lightDict',0x00FA30E8,'OBJC_IVAR_$_GlowBlock.light',56,
  'nested_getSaveDict',0x00CA8DCC,'33ff2fe1',None,0x00CA8E24,'3cff2fe1',0x00CA8E4C),
 ('GatherBlock','timer',0x00F925F8,'OBJC_IVAR_$_GatherBlock.timer',56,
  'numberWithFloat:',0x008698C0,'3aff2fe1',0x00869974,0x008698E4,'3cff2fe1',0x00869968),
 ('GatherBlock','lastKnownGatherValue',0x00F92608,'OBJC_IVAR_$_GatherBlock.lastKnownGatherValue',60,
  'numberWithInt:',0x00869920,'33ff2fe1',0x00869974,0x00869944,'3cff2fe1',0x00869968),
]
GUARDS = {
 'NormalPlant': {'emits_light_site': 0x00A66F3C, 'emits_light_word': '32ff2fe1',
                 'emits_selref_cell': 0x00A67010, 'cmp_site': 0x00A66F44,
                 'beq_site': 0x00A66F48, 'skip_target': 0x00A66FF4},
 'GlowBlock':   {'cmp_site': 0x00CA8DDC, 'beq_site': 0x00CA8DE0,
                 'skip_target': 0x00CA8E28},
}
SUPER_WORDS = {c: '3cff2fe1' for c in SUPER}


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
        if not word_eq(site, SUPER_WORDS[cls]):
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
                        'super_site': f'0x{site:08x}',
                        'super_class_struct': f'0x{struct:08x}',
                        'keys': []}

    for cls, key, obj, isym, off, conv, cs, cw, ncell, ss, sw, ssc in KEYS:
        if abs32.get(obj) != '__CFConstantStringClassReference':
            raise ValueError(f'{cls}.{key}: CFString isa drift')
        if cstr(rw(obj + 8)) != key or rw(obj + 12) != len(key.encode()):
            raise ValueError(f'{cls}.{key}: CFString payload drift')
        if not word_eq(ss, sw):
            raise ValueError(f'{cls}.{key}: set word drift')
        if cstr(rw(rebase(ssc))) != 'setObject:forKey:':
            raise ValueError(f'{cls}.{key}: set selref drift')
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
                if cstr(rw(rebase(SUPER[cls][3]))) != 'getSaveDict':
                    raise ValueError(f'{cls}.{key}: nested selref (shared cell) drift')
            elif ncell:
                if abs32.get(rebase(ncell)) != 'OBJC_CLASS_$_NSNumber' \
                        or rw(rebase(ncell)) != 0:
                    raise ValueError(f'{cls}.{key}: NSNumber classref drift')
        if isym is None:
            entry['value_source'] = 'pending (value cell not gated)'
        results[cls]['keys'].append(entry)

    for cls, g in GUARDS.items():
        if 'emits_light_site' in g:
            if not word_eq(g['emits_light_site'], g['emits_light_word']):
                raise ValueError(f'{cls}: emits guard word drift')
        b = rw(g['beq_site'])
        if b & 0x0F000000 != 0x0A000000:
            raise ValueError(f'{cls}: beq gate drift')
        imm = (b & 0x00FFFFFF) * 4
        if b & 0x00800000:
            imm -= 0x01000000
        if ((g['beq_site'] + 8 + imm) & 0xFFFFFFFF) != g['skip_target']:
            raise ValueError(f'{cls}: beq target drift')
        results[cls]['guard'] = {k: (f'0x{v:08x}' if isinstance(v, int) and v > 0xFFFF else v)
                                 for k, v in g.items()}
        if 'emits_light_site' in g:
            results[cls]['guard']['emits_light_selref'] = 'emitsLight'
            if cstr(rw(rebase(g['emits_selref_cell']))) != 'emitsLight':
                raise ValueError(f'{cls}: emitsLight selref drift')

    return {
        'schema': 1, 'elf_sha256': SHA, 'pic_base': f'0x{BASE:08x}',
        'method': 'getSaveDict key pairings (batch 2d)',
        'classes': [results[c] for c in ('PaintingCraftableItemObject',
                                          'NormalPlant', 'GlowBlock',
                                          'GatherBlock')],
        'claim': ('PaintingCraftableItemObject: two direct-object NSData ivars '
                  '(imageData@128, outputImageData@132) plus numberWithInt: '
                  'craftableObjectType whose value cell stays pending; '
                  'NormalPlant/GlowBlock add a NESTED [child getSaveDict] '
                  '(child ivar NormalPlant.light@124 / GlowBlock.light@56) '
                  'inserted as lightDict, NormalPlant gated by an emitsLight '
                  'bool test; GatherBlock saves timer@56 float BEFORE '
                  'lastKnownGatherValue@60 int despite pool order; every '
                  'dispatch word here was extracted mechanically from the '
                  'annotated listing before gating; 33 overrides and the '
                  'read-back/roundtrip behavior remain unresolved'),
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument('elf', type=Path)
    p.add_argument('--check', action='store_true')
    p.add_argument('--output', type=Path, default=NATIVE / 'subclass_savedict_keys_b2d.json')
    a = p.parse_args()
    text = json.dumps(recover(a.elf), indent=2, sort_keys=True) + '\n'
    if a.check:
        if a.output.read_text() != text:
            raise SystemExit('stale subclass_savedict_keys_b2d.json')
    else:
        a.output.write_text(text)
    print('b2d classes=4 keys=9')


if __name__ == '__main__':
    main()
