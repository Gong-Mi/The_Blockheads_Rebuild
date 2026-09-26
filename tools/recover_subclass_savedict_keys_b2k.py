#!/usr/bin/env python3
"""Hash-gated getSaveDict key pairings for batch 2k: Boat, ArtificialLight,
DropBear. Addresses/words extracted mechanically from the annotated
listings + freeblock simulator (tools/gen_b2k_table.py), then gated against
the pinned ELF.

Shapes:
  Boat 0x0096C238: [super getSaveDict] @0x96c28c, nil-guard on
    Boat.rider@116 (cmp/beq 0x96c2bc/0x96c2c0); when the rider exists it
    fast-enumerates [self.dynamicWorld blockheads]
    (countByEnumeratingWithState @0x96c340) searching for the blockhead
    equal to the rider (cmp/bne 0x96c438/0x96c440), skipping riders whose
    [needsRemoved] is set (msgSend @0x96c46c + sxtb + bne 0x96c478); when
    found, setObject:numberWithInt(index) forKey:'currentBlockheadIndex'
    (conv 0x96c57c blx lr, set 0x96c5a0) — the value is the ENUMERATION
    INDEX in [dynamicWorld blockheads], not an ivar. Finally nil-guarded
    ownerID DIRECT (cmp/beq 0x96c5c8/0x96c5cc, set 0x96c624).
  ArtificialLight 0x00A942D4: [super getSaveDict] @0xa94328, then eight
    numberWithInt: boxes: maxRed@64, maxGreen@68, maxBlue@72, maxHeat@76,
    radius@80, contributionGridOrigin.x@84 (word+0, ldr @0xa94640),
    contributionGridOrigin.y@84 (word+4, ldr @0xa946a0),
    lightDirection@96 — all plain word loads, NSNumber numberWithInt:,
    setObject:forKey:.
  DropBear 0x0079DDC0: [super getSaveDict] @0x79de14, then a spilled-key
    cascade saving 8 own keys: provokeMeter@300 and courageMeter@304 via
    numberWithFloat: (vldr s0 @0x79df44/@0x79dfc8), dropping@308 and
    onGround@344 via numberWithBool: (ldrb+sxtb @0x79e028/@0x79e0e8),
    dropSpeed@312 via numberWithFloat: (vldr @0x79e088), dropPos.x@348
    and dropPos.y@348+4 via numberWithBool: of a WORD load then sxtb
    (ldr @0x79e148 / ldr #4 @0x79e1a8 — only the low byte survives the
    sxtb), goalTreeDirection@356 via numberWithBool: (word load
    @0x79e208 + sxtb @0x79e21c).

Facts:
- DropBear.dropPos is a struct of two SIGNED BYTES stored in word slots:
  the word is loaded then sxtb narrows to the low byte before
  numberWithBool: — a replacement encoder must reproduce the
  byte-narrowing, not copy the raw word.
- goalTreeDirection@356 is likewise a word-load-then-sxtb signed byte.
- Boat.currentBlockheadIndex is the only key so far whose value is a
  LOOP INDEX (position of the rider in [dynamicWorld blockheads]) rather
  than an ivar read; rider itself and needsRemoved are guards/selectors
  and are NOT saved under any key.
- ArtificialLight contributesGridOrigin.x/.y are the second DOTTED-key
  struct pair (word+0/word+4 of one ivar @84) after ElevatorShaft.
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

# cls, imp, boundary, super_site, super_got_cell, super_sel_cell, super_class_cell
SUPER = {
 'Boat':           (0x0096C238, 0x0096C674, 0x0096C28C, 0x0096C634, 0x0096C638, 0x0096C63C),
 'ArtificialLight': (0x00A942D4, 0x00A947AC, 0x00A94328, 0x00A94750, 0x00A94754, 0x00A94758),
 'DropBear':       (0x0079DDC0, 0x0079E2B8, 0x0079DE14, 0x0079E258, 0x0079E25C, 0x0079E260),
}

# cls, key, key_cell, cfstring_obj, ivar, off, conv, conv_site, conv_word,
# ncell, conv_sel_cell, set_site, set_word, set_sel_cell
KEYS = [
 ('Boat','currentBlockheadIndex',0x0096C658,0x00F95838,None,0,
  'numberWithInt:',0x0096C57C,'3eff2fe1',0x0096C664,0x0096C660,0x0096C5A0,'3cff2fe1',0x0096C65C),
 ('Boat','ownerID',0x0096C66C,0x00F95828,'OBJC_IVAR_$_DynamicObject.ownerID',36,
  None,None,None,None,None,0x0096C624,'3cff2fe1',0x0096C65C),
 ('ArtificialLight','maxRed',0x00A947A0,0x00F9B238,'OBJC_IVAR_$_ArtificialLight.maxRed',64,
  'numberWithInt:',0x00A9447C,'33ff2fe1',0x00A94770,0x00A94768,0x00A944A0,'3cff2fe1',0x00A94764),
 ('ArtificialLight','maxGreen',0x00A94798,0x00F9B248,'OBJC_IVAR_$_ArtificialLight.maxGreen',68,
  'numberWithInt:',0x00A944DC,'33ff2fe1',0x00A94770,0x00A94768,0x00A94500,'3cff2fe1',0x00A94764),
 ('ArtificialLight','maxBlue',0x00A94790,0x00F9B258,'OBJC_IVAR_$_ArtificialLight.maxBlue',72,
  'numberWithInt:',0x00A9453C,'33ff2fe1',0x00A94770,0x00A94768,0x00A94560,'3cff2fe1',0x00A94764),
 ('ArtificialLight','maxHeat',0x00A94788,0x00F9B268,'OBJC_IVAR_$_ArtificialLight.maxHeat',76,
  'numberWithInt:',0x00A9459C,'33ff2fe1',0x00A94770,0x00A94768,0x00A945C0,'3cff2fe1',0x00A94764),
 ('ArtificialLight','radius',0x00A94780,0x00F9B278,'OBJC_IVAR_$_ArtificialLight.radius',80,
  'numberWithInt:',0x00A945FC,'33ff2fe1',0x00A94770,0x00A94768,0x00A94620,'3cff2fe1',0x00A94764),
 ('ArtificialLight','contributionGridOrigin.x',0x00A9477C,0x00F9B288,'OBJC_IVAR_$_ArtificialLight.contributionGridOrigin',84,
  'numberWithInt:',0x00A9465C,'33ff2fe1',0x00A94770,0x00A94768,0x00A94680,'3cff2fe1',0x00A94764),
 ('ArtificialLight','contributionGridOrigin.y',0x00A94774,0x00F9B298,'OBJC_IVAR_$_ArtificialLight.contributionGridOrigin',84,
  'numberWithInt:',0x00A946BC,'33ff2fe1',0x00A94770,0x00A94768,0x00A946E0,'3cff2fe1',0x00A94764),
 ('ArtificialLight','lightDirection',0x00A9475C,0x00F9B2A8,'OBJC_IVAR_$_ArtificialLight.lightDirection',96,
  'numberWithInt:',0x00A9471C,'33ff2fe1',0x00A94770,0x00A94768,0x00A94740,'3cff2fe1',0x00A94764),
 ('DropBear','provokeMeter',0x0079E2AC,0x00F908D8,'OBJC_IVAR_$_DropBear.provokeMeter',300,
  'numberWithFloat:',0x0079DF84,'33ff2fe1',0x0079E278,0x0079E294,0x0079DFA8,'3cff2fe1',0x0079E26C),
 ('DropBear','courageMeter',0x0079E2A4,0x00F908E8,'OBJC_IVAR_$_DropBear.courageMeter',304,
  'numberWithFloat:',0x0079DFE4,'3eff2fe1',0x0079E278,0x0079E294,0x0079E008,'3cff2fe1',0x0079E26C),
 ('DropBear','dropping',0x0079E29C,0x00F908F8,'OBJC_IVAR_$_DropBear.dropping',308,
  'numberWithBool:',0x0079E044,'33ff2fe1',0x0079E278,0x0079E270,0x0079E068,'3cff2fe1',0x0079E26C),
 ('DropBear','dropSpeed',0x0079E290,0x00F90908,'OBJC_IVAR_$_DropBear.dropSpeed',312,
  'numberWithFloat:',0x0079E0A4,'3eff2fe1',0x0079E278,0x0079E294,0x0079E0C8,'3cff2fe1',0x0079E26C),
 ('DropBear','onGround',0x0079E288,0x00F90918,'OBJC_IVAR_$_DropBear.onGround',344,
  'numberWithBool:',0x0079E104,'33ff2fe1',0x0079E278,0x0079E270,0x0079E128,'3cff2fe1',0x0079E26C),
 ('DropBear','dropPos.x',0x0079E284,0x00F90928,'OBJC_IVAR_$_DropBear.dropPos',348,
  'numberWithBool:',0x0079E164,'33ff2fe1',0x0079E278,0x0079E270,0x0079E188,'3cff2fe1',0x0079E26C),
 ('DropBear','dropPos.y',0x0079E27C,0x00F90938,'OBJC_IVAR_$_DropBear.dropPos',348,
  'numberWithBool:',0x0079E1C4,'33ff2fe1',0x0079E278,0x0079E270,0x0079E1E8,'3cff2fe1',0x0079E26C),
 ('DropBear','goalTreeDirection',0x0079E264,0x00F90948,'OBJC_IVAR_$_DropBear.goalTreeDirection',356,
  'numberWithBool:',0x0079E224,'33ff2fe1',0x0079E278,0x0079E270,0x0079E248,'3cff2fe1',0x0079E26C),
]

# site gates that are not per-key: guards, loop machinery, value loads.
EXTRA_GATES = [
 ('Boat', 'rider_guard_cmp', 0x0096C2BC, '000051e1'),
 ('Boat', 'rider_guard_beq', 0x0096C2C0, 'b800000a'),
 ('Boat', 'enumerate_site', 0x0096C340, '32ff2fe1'),
 ('Boat', 'rider_cmp', 0x0096C438, '000053e1'),
 ('Boat', 'rider_bne', 0x0096C440, '1000001a'),
 ('Boat', 'needsremoved_msg_site', 0x0096C46C, '32ff2fe1'),
 ('Boat', 'needsremoved_sxtb', 0x0096C470, '7000afe6'),
 ('Boat', 'needsremoved_bne', 0x0096C478, '0200001a'),
 ('Boat', 'found_ldrsb', 0x0096C510, 'd9035be1'),
 ('Boat', 'found_beq', 0x0096C518, '2100000a'),
 ('Boat', 'ownerid_guard_beq', 0x0096C5CC, '1500000a'),
 ('ArtificialLight', 'cgo_x_word_ldr', 0x00A94640, '003093e5'),
 ('ArtificialLight', 'cgo_y_word_ldr4', 0x00A946A0, '043093e5'),
 ('DropBear', 'provoke_vldr', 0x0079DF44, '000a90ed'),
 ('DropBear', 'courage_vldr', 0x0079DFC8, '000a93ed'),
 ('DropBear', 'dropping_ldrb', 0x0079E028, '0030d3e5'),
 ('DropBear', 'dropping_sxtb', 0x0079E03C, '7320afe6'),
 ('DropBear', 'dropSpeed_vldr', 0x0079E088, '000a93ed'),
 ('DropBear', 'onGround_ldrb', 0x0079E0E8, '0030d3e5'),
 ('DropBear', 'onGround_sxtb', 0x0079E0FC, '7320afe6'),
 ('DropBear', 'dropPos_x_ldr', 0x0079E148, '003093e5'),
 ('DropBear', 'dropPos_x_sxtb', 0x0079E15C, '7320afe6'),
 ('DropBear', 'dropPos_y_ldr4', 0x0079E1A8, '043093e5'),
 ('DropBear', 'dropPos_y_sxtb', 0x0079E1BC, '7320afe6'),
 ('DropBear', 'goalTree_ldr', 0x0079E208, '003093e5'),
 ('DropBear', 'goalTree_sxtb', 0x0079E21C, '7320afe6'),
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
    for cls, (imp, boundary, site, gotc, selc, crc) in SUPER.items():
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
        if isym is None:
            entry = {'key': key, 'cfstring_object': f'0x{obj:08x}',
                     'ivar': None, 'set_object_site': f'0x{ss:08x}'}
            if conv is None:
                entry['conversion'] = 'direct_object'
            else:
                entry['conversion'] = conv
                entry['conversion_site'] = f'0x{cs:08x}'
                entry['value_source'] = 'loop_index'
                if not word_eq(cs, cw):
                    raise ValueError(f'{cls}.{key}: conv word drift')
                if cstr(rw(rebase(csr))) != conv:
                    raise ValueError(f'{cls}.{key}: conv selref drift')
                if abs32.get(rebase(ncell)) != 'OBJC_CLASS_$_NSNumber' or rw(rebase(ncell)) != 0:
                    raise ValueError(f'{cls}.{key}: NSNumber classref drift')
            if not word_eq(ss, sw):
                raise ValueError(f'{cls}.{key}: set word drift')
            if cstr(rw(rebase(ssc))) != 'setObject:forKey:':
                raise ValueError(f'{cls}.{key}: setObject selref drift')
            results[cls]['keys'].append(entry)
            continue
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
            if cw is not None:
                if not word_eq(cs, cw):
                    raise ValueError(f'{cls}.{key}: conv word drift')
            if cstr(rw(rebase(csr))) != conv:
                raise ValueError(f'{cls}.{key}: conv selref drift')
            if abs32.get(rebase(ncell)) != 'OBJC_CLASS_$_NSNumber' or rw(rebase(ncell)) != 0:
                raise ValueError(f'{cls}.{key}: NSNumber classref drift')
        results[cls]['keys'].append(entry)

    gate_notes = {}
    for cls, name, site, wh in EXTRA_GATES:
        if not word_eq(site, wh):
            raise ValueError(f'{cls}.{name}: gate word drift @0x{site:08x}')
        gate_notes.setdefault(cls, []).append(f'{name}@0x{site:08x}')
    for cls, notes in gate_notes.items():
        results[cls]['site_gates'] = notes

    return {
        'schema': 1, 'elf_sha256': SHA, 'pic_base': f'0x{BASE:08x}',
        'method': 'getSaveDict key pairings (batch 2k)',
        'classes': [results[c] for c in ('Boat', 'ArtificialLight', 'DropBear')],
        'claim': ('Boat saves currentBlockheadIndex as the numberWithInt '
                  'of the LOOP INDEX of its rider inside '
                  '[dynamicWorld blockheads] (rider nil-guarded, '
                  'needsRemoved-entries skipped; rider itself is NOT '
                  'saved) plus a nil-guarded DIRECT ownerID; '
                  'ArtificialLight saves eight plain-int keys '
                  'maxRed/maxGreen/maxBlue/maxHeat/radius/lightDirection '
                  'and the DOTTED contributionGridOrigin.x/.y word pair '
                  '(@84 +0/+4) all via numberWithInt:; DropBear saves '
                  'provokeMeter@300/courageMeter@304/dropSpeed@312 as '
                  'numberWithFloat (vldr), dropping@308/onGround@344 as '
                  'numberWithBool of ldrb+sxtb signed bytes, and '
                  'dropPos.x/.y@348 + goalTreeDirection@356 as '
                  'numberWithBool of WORD loads narrowed by sxtb to '
                  'their low byte; 7 overrides remain (Action, Plant, '
                  'Tree, CaveTroll, InteractionObject, TrainCar, '
                  'Workbench), read-back/roundtrip unresolved'),
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument('elf', type=Path)
    p.add_argument('--check', action='store_true')
    p.add_argument('--output', type=Path, default=NATIVE / 'subclass_savedict_keys_b2k.json')
    a = p.parse_args()
    text = json.dumps(recover(a.elf), indent=2, sort_keys=True) + '\n'
    if a.check:
        if a.output.read_text() != text:
            raise SystemExit('stale subclass_savedict_keys_b2k.json')
    else:
        a.output.write_text(text)
    print('b2k classes=3 keys=18')


if __name__ == '__main__':
    main()
