#!/usr/bin/env python3
"""Hash-gated getSaveDict key pairings for batch 2n: TrainCar.
Addresses/words extracted mechanically from the annotated listing +
freeblock simulator (tools/gen_b2n_table.py), then gated against the
pinned ELF, with the dynamic format-string key handled as a special
entry (the simulator cannot resolve stringWithFormat: keys).

Shapes:
  TrainCar 0x00A394B0: [super getSaveDict] @0xa39504, then:
    rider slots: for i in 0..[self maxNumberOfRiders] (msgSend
      @0xa39550, cmp/bge 0xa39558/0xa3955c): slot value =
      TrainCar.riders@76 C-array element at +i*4 (ldr @0xa3958c);
      nil slots skip (cmp/beq 0xa39590/0xa39598); occupied slots
      fast-enumerate [dynamicWorld blockheads] (@0xa39618) skipping
      [needsRemoved] entries (@0xa39748); when the slot's blockhead is
      found, the key is BUILT DYNAMICALLY:
      [NSString stringWithFormat:'currentBlockheadIndex_%d', i]
      (CFString 'currentBlockheadIndex_%d' cell 0xa39d54,
      stringWithFormat: selref 0xa39d58, NSString classref 0xa39d5c,
      format call @0xa398a0) and the value is the blockhead's index
      (numberWithInt conv @0xa39878, set @0xa398c4) — the FIRST
      format-string wire key in the save path;
    rightCarID = numberWithInt([rightCar uniqueID]) with nil-guard on
      TrainCar.rightCar@168 (cmp/beq 0xa39900/0xa39904, uniqueID via
      import thunk bl #0x1c281c @0xa39980, conv 0xa399a8, set
      0xa399cc);
    leftCarID = same shape via TrainCar.leftCar@172 (conv 0xa39a98,
      set 0xa39abc);
    engineCarID = same shape via TrainCar.engineCar@176 (conv 0xa39b88,
      set 0xa39bac);
    ownerID = nil-guarded DIRECT (DynamicObject.ownerID@36, set
      0xa39c2c);
    engineIsRight = numberWithBool of TrainCar.engineIsRight@180
      signed byte (ldrb @0xa39c7c + sxtb @0xa39c8c, conv 0xa39ca8,
      set 0xa39ccc) — NOT nil-guarded, saved unconditionally.

Facts:
- 'currentBlockheadIndex_%d' is the first DYNAMIC format-string key:
  one saved entry PER OCCUPIED RIDER SLOT, keyed by slot index; a
  replacement encoder must emit currentBlockheadIndex_0, _1, ... for
  each occupied slot (not a fixed key set).
- TrainCar.riders@76 is a C array of object pointers indexed by raw
  arithmetic (base + i*4), NOT an NSArray subscript — the only raw
  C-array traversal in the save path so far.
- rightCarID/leftCarID/engineCarID are CROSS-ENTITY references: they
  serialize the NEIGHBOR car's uniqueID (a selector call on another
  object), each behind a nil-guard so missing neighbors save nothing.
- The nested loop (slots × blockheads) means the save cost is
  O(riders × blockheads) — same double-loop family as Boat/
  InteractionObject but with the needsRemoved skip.
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
 'TrainCar': (0x00A394B0, 0x00A39D64, 0x00A39504, 0x00A39CDC, 0x00A39CE0, 0x00A39CE4),
}

# cls, key, key_cell, cfstring_obj, ivar, off, conv, conv_site, conv_word,
# ncell, conv_sel_cell, set_site, set_word, set_sel_cell
KEYS = [
 ('TrainCar','rightCarID',0x00A39CF4,0x00F972B8,'OBJC_IVAR_$_TrainCar.rightCar',168,
  'numberWithInt:',0x00A399A8,'33ff2fe1',0x00A39D00,0x00A39CFC,0x00A399CC,'3cff2fe1',0x00A39CF8),
 ('TrainCar','leftCarID',0x00A39D10,0x00F972C8,'OBJC_IVAR_$_TrainCar.leftCar',172,
  'numberWithInt:',0x00A39A98,'33ff2fe1',0x00A39D00,0x00A39CFC,0x00A39ABC,'3cff2fe1',0x00A39CF8),
 ('TrainCar','engineCarID',0x00A39D1C,0x00F972D8,'OBJC_IVAR_$_TrainCar.engineCar',176,
  'numberWithInt:',0x00A39B88,'33ff2fe1',0x00A39D00,0x00A39CFC,0x00A39BAC,'3cff2fe1',0x00A39CF8),
 ('TrainCar','ownerID',0x00A39D28,0x00F97298,'OBJC_IVAR_$_DynamicObject.ownerID',36,
  None,None,None,None,None,0x00A39C2C,'3cff2fe1',0x00A39CF8),
 ('TrainCar','engineIsRight',0x00A39D2C,0x00F972E8,'OBJC_IVAR_$_TrainCar.engineIsRight',180,
  'numberWithBool:',0x00A39CA8,'3eff2fe1',0x00A39D00,0x00A39D30,0x00A39CCC,'3cff2fe1',0x00A39CF8),
]

# dynamic format-string key: the CFString 'currentBlockheadIndex_%d'
# payload, format/conv/set sites and the uniqueID thunk are gated here.
DYNAMIC_KEY = {
 'TrainCar': {
   'format_cfstring': 0x00F972A8,
   'format_cfstring_cell': 0x00A39D54,
   'stringWithFormat_sel_cell': 0x00A39D58,
   'nsstring_classref_cell': 0x00A39D5C,
   'format_call_site': 0x00A398A0,
   'format_call_word': '3eff2fe1',
   'conv_site': 0x00A39878,
   'conv_word': '36ff2fe1',
   'set_site': 0x00A398C4,
   'set_word': '3cff2fe1',
 },
}

# site gates: guards, loop machinery, value loads.
EXTRA_GATES = [
 ('TrainCar', 'maxriders_msg_site', 0x00A39550, '32ff2fe1'),
 ('TrainCar', 'maxriders_bge', 0x00A3955C, 'df0000aa'),
 ('TrainCar', 'riders_slot_ldr', 0x00A3958C, '002092e5'),
 ('TrainCar', 'riders_slot_nil_beq', 0x00A39598, 'cb00000a'),
 ('TrainCar', 'rider_enumerate_site', 0x00A39618, '32ff2fe1'),
 ('TrainCar', 'needsremoved_msg_site', 0x00A39748, '32ff2fe1'),
 ('TrainCar', 'found_ldrsb', 0x00A397EC, 'dd035be1'),
 ('TrainCar', 'found_beq', 0x00A397F4, '3300000a'),
 ('TrainCar', 'rightcar_guard_beq', 0x00A39904, '3100000a'),
 ('TrainCar', 'leftcar_guard_beq', 0x00A399F4, '3100000a'),
 ('TrainCar', 'enginecar_guard_beq', 0x00A39AE4, '3100000a'),
 ('TrainCar', 'uniqueid_thunk_right', 0x00A39980, 'a523deeb'),
 ('TrainCar', 'uniqueid_thunk_left', 0x00A39A70, '6923deeb'),
 ('TrainCar', 'uniqueid_thunk_engine', 0x00A39B60, '2d23deeb'),
 ('TrainCar', 'engineisright_ldrb', 0x00A39C7C, '0040d4e5'),
 ('TrainCar', 'engineisright_sxtb', 0x00A39C8C, '74e0afe6'),
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

    # dynamic format-string key entry (first in the method's emission order)
    for cls, dyn in DYNAMIC_KEY.items():
        obj = dyn['format_cfstring']
        if abs32.get(obj) != '__CFConstantStringClassReference':
            raise ValueError(f'{cls}.dynamic: CFString isa drift')
        if cstr(rw(obj + 8)) != 'currentBlockheadIndex_%d':
            raise ValueError(f'{cls}.dynamic: CFString payload drift')
        if rebase(dyn['format_cfstring_cell']) != obj:
            raise ValueError(f'{cls}.dynamic: format cell drift')
        if cstr(rw(rebase(dyn['stringWithFormat_sel_cell']))) != 'stringWithFormat:':
            raise ValueError(f'{cls}.dynamic: stringWithFormat selref drift')
        if abs32.get(rebase(dyn['nsstring_classref_cell'])) != 'OBJC_CLASS_$_NSString' \
                or rw(rebase(dyn['nsstring_classref_cell'])) != 0:
            raise ValueError(f'{cls}.dynamic: NSString classref drift')
        if not word_eq(dyn['format_call_site'], dyn['format_call_word']):
            raise ValueError(f'{cls}.dynamic: format call word drift')
        if not word_eq(dyn['conv_site'], dyn['conv_word']):
            raise ValueError(f'{cls}.dynamic: conv word drift')
        if not word_eq(dyn['set_site'], dyn['set_word']):
            raise ValueError(f'{cls}.dynamic: set word drift')
        results[cls]['keys'].append({
            'key': 'currentBlockheadIndex_%d',
            'key_kind': 'format_string',
            'cfstring_object': f"0x{obj:08x}",
            'value_source': 'blockhead_index_per_occupied_slot',
            'conversion': 'numberWithInt:',
            'conversion_site': f"0x{dyn['conv_site']:08x}",
            'set_object_site': f"0x{dyn['set_site']:08x}",
        })

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
        entry = {'key': key, 'cfstring_object': f'0x{obj:08x}', 'ivar': isym,
                 'ivar_offset': off, 'set_object_site': f'0x{ss:08x}'}
        if not word_eq(ss, sw):
            raise ValueError(f'{cls}.{key}: set word drift')
        if cstr(rw(rebase(ssc))) != 'setObject:forKey:':
            raise ValueError(f'{cls}.{key}: setObject selref drift')
        if conv is None:
            entry['conversion'] = 'direct_object'
            if key in ('rightCarID', 'leftCarID', 'engineCarID'):
                raise ValueError(f'{cls}.{key}: carID must be boxed')
        else:
            entry['conversion'] = conv
            entry['conversion_site'] = f'0x{cs:08x}'
            if key in ('rightCarID', 'leftCarID', 'engineCarID'):
                entry['value_source'] = 'neighbor_uniqueID'
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
        'method': 'getSaveDict key pairings (batch 2n)',
        'classes': [results[c] for c in ('TrainCar',)],
        'claim': ('TrainCar saves one DYNAMIC format-string key per '
                  'occupied rider slot — [NSString '
                  "stringWithFormat:'currentBlockheadIndex_%d', i] "
                  'gating the blockhead-index numberWithInt (first '
                  'format-string wire key; riders@76 is a raw C array '
                  'indexed base+i*4; needsRemoved entries skipped); '
                  'rightCarID/leftCarID/engineCarID serialize the '
                  'NEIGHBOR car uniqueID behind nil-guards (cross-'
                  'entity references), ownerID@36 nil-guarded DIRECT, '
                  'and engineIsRight@180 signed-byte bool saved '
                  'unconditionally; 3 overrides remain (Action, Tree, '
                  'Workbench), read-back/roundtrip unresolved'),
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument('elf', type=Path)
    p.add_argument('--check', action='store_true')
    p.add_argument('--output', type=Path, default=NATIVE / 'subclass_savedict_keys_b2n.json')
    a = p.parse_args()
    text = json.dumps(recover(a.elf), indent=2, sort_keys=True) + '\n'
    if a.check:
        if a.output.read_text() != text:
            raise SystemExit('stale subclass_savedict_keys_b2n.json')
    else:
        a.output.write_text(text)
    print('b2n classes=1 keys=6')


if __name__ == '__main__':
    main()
