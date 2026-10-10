#!/usr/bin/env python3
"""Hash-gated getSaveDict key pairings for batch 2m: InteractionObject.
Addresses/words extracted mechanically from the annotated listing +
freeblock simulator (tools/gen_b2m_table.py), then gated against the
pinned ELF.

Shapes:
  InteractionObject 0x005F50B8: [super getSaveDict] @0x5f510c, then:
    saveTime = numberWithDouble:([self.world worldTime]) — same
      world-clock double contract as Plant (msgSend worldTime @0x5f5298,
      vmov d0 @0x5f529c, conv 0x5f52b8, set 0x5f52dc);
    isInUse@68 = numberWithBool: (ldrb @0x5f52fc + sxtb @0x5f5310,
      conv 0x5f5318, set 0x5f533c);
    flipped@69 = numberWithBool: (ldrb @0x5f535c + sxtb @0x5f5370,
      conv 0x5f5378, set 0x5f539c) — ADJACENT BYTE to isInUse@68;
    interactionObjectType = numberWithInt: of msgSend(self,
      'interactionObjectType') — a computed SELECTOR value, not an
      ivar (selref cell 0x5f5874, conv 0x5f53e4, set 0x5f5408);
    paintColor@88 = numberWithUnsignedInt: (conv 0x5f5444, set
      0x5f5468);
    currentBlockheadIndex = the LOOP INDEX of
      InteractionObject.currentBlockhead@56 inside
      [dynamicWorld blockheads] (nil-guard on the ivar cmp/beq
      0x5f5484/0x5f5488; enumeration @0x5f5508; equality cmp/bne
      0x5f5600/0x5f5608 — NO needsRemoved check, unlike Boat;
      found ldrsb @0x5f56a0; conv 0x5f570c, set 0x5f5730);
    ownerID@36 = nil-guarded DIRECT (cmp/beq 0x5f5758/0x5f575c, set
      0x5f57b4);
    ownerName@84 = nil-guarded DIRECT (cmp/beq 0x5f57d8/0x5f57dc, set
      0x5f5834).

Facts:
- InteractionObject is the PARENT of Sign/OwnershipSign/Painting's
  ownerName@84 — the base class itself saves ownerName, so subclasses
  with their own ownerName keys (Sign b2i, Painting b2i) OVERWRITE or
  re-save the same key.
- saveTime (worldTime double) appears in BOTH Plant (b2l) and
  InteractionObject — a shared timestamp contract across unrelated
  subtrees; Egg (b2g) previously noted a worldTime stamp.
- interactionObjectType is the second computed-selector value (after
  TradingPost's per-item saveData); the wire key equals the selector
  name.
- currentBlockheadIndex matches Boat's rider search but WITHOUT the
  needsRemoved skip — InteractionObject only checks identity.
- isInUse@68 / flipped@69 are the third adjacent-byte bool pair (after
  Plant 84/85, Torch 80/82 are halfword-strided not adjacent).
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
 'InteractionObject': (0x005F50B8, 0x005F58C0, 0x005F510C, 0x005F5844, 0x005F5848, 0x005F584C),
}

# cls, key, key_cell, cfstring_obj, ivar, off, conv, conv_site, conv_word,
# ncell, conv_sel_cell, set_site, set_word, set_sel_cell
KEYS = [
 ('InteractionObject','saveTime',0x005F588C,0x00F7E228,None,0,
  'numberWithDouble:',0x005F52B8,'3cff2fe1',0x005F5868,0x005F5890,0x005F52DC,'3cff2fe1',0x005F585C),
 ('InteractionObject','isInUse',0x005F5884,0x00F7E1F8,'OBJC_IVAR_$_InteractionObject.isInUse',68,
  'numberWithBool:',0x005F5318,'33ff2fe1',0x005F5868,0x005F587C,0x005F533C,'3cff2fe1',0x005F585C),
 ('InteractionObject','flipped',0x005F5878,0x00F7E208,'OBJC_IVAR_$_InteractionObject.flipped',69,
  'numberWithBool:',0x005F5378,'33ff2fe1',0x005F5868,0x005F587C,0x005F539C,'3cff2fe1',0x005F585C),
 ('InteractionObject','interactionObjectType',0x005F586C,0x00F7E238,None,0,
  'numberWithInt:',0x005F53E4,'33ff2fe1',0x005F5868,0x005F5870,0x005F5408,'3cff2fe1',0x005F585C),
 ('InteractionObject','paintColor',0x005F5854,0x00F7E1E8,'OBJC_IVAR_$_InteractionObject.paintColor',88,
  'numberWithUnsignedInt:',0x005F5444,'33ff2fe1',0x005F5868,0x005F5860,0x005F5468,'3cff2fe1',0x005F585C),
 ('InteractionObject','currentBlockheadIndex',0x005F58A8,0x00F7E218,None,0,
  'numberWithInt:',0x005F570C,'3eff2fe1',0x005F5868,0x005F5870,0x005F5730,'3cff2fe1',0x005F585C),
 ('InteractionObject','ownerID',0x005F58B0,0x00F7E1D8,'OBJC_IVAR_$_DynamicObject.ownerID',36,
  None,None,None,None,None,0x005F57B4,'3cff2fe1',0x005F585C),
 ('InteractionObject','ownerName',0x005F58B8,0x00F7E1C8,'OBJC_IVAR_$_InteractionObject.ownerName',84,
  None,None,None,None,None,0x005F5834,'3cff2fe1',0x005F585C),
]

# site gates: guards, loop machinery, value loads, computed selectors.
EXTRA_GATES = [
 ('InteractionObject', 'currentblockhead_guard_cmp', 0x005F5484, '020050e1'),
 ('InteractionObject', 'currentblockhead_guard_beq', 0x005F5488, 'aa00000a'),
 ('InteractionObject', 'enumerate_site', 0x005F5508, '32ff2fe1'),
 ('InteractionObject', 'identity_cmp', 0x005F5600, '000053e1'),
 ('InteractionObject', 'identity_bne', 0x005F5608, '0200001a'),
 ('InteractionObject', 'found_ldrsb', 0x005F56A0, 'd9035be1'),
 ('InteractionObject', 'found_beq', 0x005F56A8, '2100000a'),
 ('InteractionObject', 'isInUse_ldrb', 0x005F52FC, '0030d3e5'),
 ('InteractionObject', 'isInUse_sxtb', 0x005F5310, '7320afe6'),
 ('InteractionObject', 'flipped_ldrb', 0x005F535C, '0030d3e5'),
 ('InteractionObject', 'flipped_sxtb', 0x005F5370, '7320afe6'),
 ('InteractionObject', 'worldtime_msg_site', 0x005F5298, '3cff2fe1'),
 ('InteractionObject', 'worldtime_vmov_d0', 0x005F529C, '100b41ec'),
 ('InteractionObject', 'ownerid_guard_beq', 0x005F575C, '1500000a'),
 ('InteractionObject', 'ownername_guard_beq', 0x005F57DC, '1500000a'),
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
        entry = {'key': key, 'cfstring_object': f'0x{obj:08x}',
                 'set_object_site': f'0x{ss:08x}'}
        if isym is not None:
            stor = ivar_by_name.get(isym)
            if stor is None or rw(stor) != off:
                raise ValueError(f'{cls}.{key}: ivar drift')
            entry['ivar'] = isym
            entry['ivar_offset'] = off
        else:
            entry['ivar'] = None
        if not word_eq(ss, sw):
            raise ValueError(f'{cls}.{key}: set word drift')
        if cstr(rw(rebase(ssc))) != 'setObject:forKey:':
            raise ValueError(f'{cls}.{key}: setObject selref drift')
        if conv is None:
            entry['conversion'] = 'direct_object'
        else:
            entry['conversion'] = conv
            entry['conversion_site'] = f'0x{cs:08x}'
            if isym is None:
                if key == 'saveTime':
                    entry['value_source'] = 'world_selector'
                elif key == 'currentBlockheadIndex':
                    entry['value_source'] = 'loop_index'
                else:
                    entry['value_source'] = 'computed_selector'
            if cw is not None:
                if not word_eq(cs, cw):
                    raise ValueError(f'{cls}.{key}: conv word drift')
            if cstr(rw(rebase(csr))) != conv:
                raise ValueError(f'{cls}.{key}: conv selref drift')
            if abs32.get(rebase(ncell)) != 'OBJC_CLASS_$_NSNumber' or rw(rebase(ncell)) != 0:
                raise ValueError(f'{cls}.{key}: NSNumber classref drift')
        results[cls]['keys'].append(entry)

    # interactionObjectType selector gate: selref cell 0x5f5874 must
    # resolve to the 'interactionObjectType' selector (the value source).
    if cstr(rw(rebase(0x005F5874))) != 'interactionObjectType':
        raise ValueError('interactionObjectType selector drift')

    gate_notes = {}
    for cls, name, site, wh in EXTRA_GATES:
        if not word_eq(site, wh):
            raise ValueError(f'{cls}.{name}: gate word drift @0x{site:08x}')
        gate_notes.setdefault(cls, []).append(f'{name}@0x{site:08x}')
    for cls, notes in gate_notes.items():
        results[cls]['site_gates'] = notes

    return {
        'schema': 1, 'elf_sha256': SHA, 'pic_base': f'0x{BASE:08x}',
        'method': 'getSaveDict key pairings (batch 2m)',
        'classes': [results[c] for c in ('InteractionObject',)],
        'claim': ('InteractionObject saves the world-clock double '
                  'saveTime=[world worldTime] (shared contract with '
                  'Plant), adjacent-byte bools isInUse@68/flipped@69, '
                  'the COMPUTED interactionObjectType selector value '
                  'as numberWithInt, paintColor@88 '
                  'numberWithUnsignedInt, currentBlockheadIndex as the '
                  'loop index of currentBlockhead@56 inside '
                  '[dynamicWorld blockheads] (identity only, no '
                  'needsRemoved skip unlike Boat), and nil-guarded '
                  'DIRECT ownerID@36/ownerName@84 (the parent that '
                  'Sign/Painting ownerName keys override); 4 overrides '
                  'remain (Action, Tree, TrainCar, Workbench), '
                  'read-back/roundtrip unresolved'),
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument('elf', type=Path)
    p.add_argument('--check', action='store_true')
    p.add_argument('--output', type=Path, default=NATIVE / 'subclass_savedict_keys_b2m.json')
    a = p.parse_args()
    text = json.dumps(recover(a.elf), indent=2, sort_keys=True) + '\n'
    if a.check:
        if a.output.read_text() != text:
            raise SystemExit('stale subclass_savedict_keys_b2m.json')
    else:
        a.output.write_text(text)
    print('b2m classes=1 keys=8')


if __name__ == '__main__':
    main()
