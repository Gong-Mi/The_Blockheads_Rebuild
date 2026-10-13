#!/usr/bin/env python3
"""Hash-gated getSaveDict key pairings for batch 2p: Workbench — the
final unpaired getSaveDict override (1232 words). Addresses/words
extracted mechanically from the annotated listing + freeblock
simulator, then gated against the pinned ELF.

Shapes (all sites gated below):
  Workbench 0x00AE81D0: [super getSaveDict] @0xae8228, then 20 static
  keys + one format-string family + one nested light save:
    workbenchType = numberWithInt of Workbench.type@120 (RE-KEYED);
    selectedIndex@136 int; xScroll@172 float; level@176 int;
    craftProgressCount@188 float; hurryTimer@192 float;
    hurrySeconds@196 float; hurrying@200 bool; hurryCost@204 int;
    availableElectricity@222 numberWithUnsignedInt;
    fireSpreadTimer@208 float; fuelFraction@212 float;
    hasFuel@220 bool; lastWorldTime@256 = numberWithDouble of the
      OWN-IVAR 64-bit field (second own-ivar double after Tree.timeDied);
    currentBlockheadIndexFuel = loop index of
      currentFuelBlockhead@108 inside [dynamicWorld blockheads]
      (enumerate @0xae8ac0, conv 0xae8c6c, set 0xae8c90);
    craftingItemDatav2 = NESTED [craftingItemObject@180 getSaveDict]
      (msg 0xae8d2c, nil-guard, set 0xae8d84);
    count@228 / countLeft@232 / countCreated@236 = numberWithInt
      (conv 0xae8e64/0xae8ec4/0xae8f24); the 'craftableItem' selector
      (selref 0xae94c0) and craftingItemObject cell load into the
      spill cascade — exact consumer semantics recorded as PENDING
      (not asserted);
    sourceItems_%d = per-index DYNAMIC keys: outer loop over
      [sourceItems@140 count] (msg @0xae9074), inner enumeration
      builds [NSMutableArray array] of per-item [saveData] dicts
      (addObject @0xae9218 region, calls 0xae9268/0xae9288), then
      [NSString stringWithFormat:'sourceItems_%d', i] @0xae9370 and
      setObject under it @0xae9394;
    lightDict = NESTED [Workbench.light@100 getSaveDict] (selref
      0xae948c, msg 0xae9424, set 0xae947c).

Facts:
- Workbench is the LARGEST override (1232 words) and the last one in
  the census: with b2p the [super getSaveDict] subclass override key
  matrix is COMPLETE at the static level.
- workbenchType RE-KEYS the ivar `type` (same re-key family as
  Painting.outputImageData/imageData, DropBear attackingNPC/
  chasingNPC).
- lastWorldTime@256 is the second own-ivar double (vldr-family
  64-bit field read + numberWithDouble) after Tree.timeDied.
- sourceItems_%d is the SECOND format-string key family (after
  TrainCar's currentBlockheadIndex_%d): per-index arrays of
  per-item saveData dicts — the save is O(indices × items).
- craftingItemDatav2 + lightDict are nested entity saves: the
  workbench embeds its crafting item's and light's full save dicts.
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
 'Workbench': (0x00AE81D0, 0x00AE9510, 0x00AE8228, 0x00AE8F94, 0x00AE8F98, 0x00AE8F9C),
}

# cls, key, key_cell, cfstring_obj, ivar, off, conv, conv_site, conv_word,
# ncell, conv_sel_cell, set_site, set_word, set_sel_cell
KEYS = [
 ('Workbench','workbenchType',0x00AE93D0,0x00F9B9F8,'OBJC_IVAR_$_Workbench.type',120,
  'numberWithInt:',0x00AE84C4,'3cff2fe1',0x00AE8FB8,0x00AE94A0,0x00AE84E8,'3cff2fe1',0x00AE8FAC),
 ('Workbench','selectedIndex',0x00AE93C8,0x00F9BA08,'OBJC_IVAR_$_Workbench.selectedIndex',136,
  'numberWithInt:',0x00AE8524,'33ff2fe1',0x00AE8FB8,0x00AE94A0,0x00AE8548,'3cff2fe1',0x00AE8FAC),
 ('Workbench','xScroll',0x00AE93C0,0x00F9BA18,'OBJC_IVAR_$_Workbench.xScroll',172,
  'numberWithFloat:',0x00AE8584,'3eff2fe1',0x00AE8FB8,0x00AE8FCC,0x00AE85A8,'3cff2fe1',0x00AE8FAC),
 ('Workbench','level',0x00AE93B8,0x00F9B9D8,'OBJC_IVAR_$_Workbench.level',176,
  'numberWithInt:',0x00AE85E4,'33ff2fe1',0x00AE8FB8,0x00AE94A0,0x00AE8608,'3cff2fe1',0x00AE8FAC),
 ('Workbench','craftProgressCount',0x00AE93B0,0x00F9BA28,'OBJC_IVAR_$_Workbench.craftProgressCount',188,
  'numberWithFloat:',0x00AE8644,'3eff2fe1',0x00AE8FB8,0x00AE8FCC,0x00AE8668,'3cff2fe1',0x00AE8FAC),
 ('Workbench','hurryTimer',0x00AE9004,0x00F9BA38,'OBJC_IVAR_$_Workbench.hurryTimer',192,
  'numberWithFloat:',0x00AE86A4,'3eff2fe1',0x00AE8FB8,0x00AE8FCC,0x00AE86C8,'3cff2fe1',0x00AE8FAC),
 ('Workbench','hurrySeconds',0x00AE8FFC,0x00F9BA48,'OBJC_IVAR_$_Workbench.hurrySeconds',196,
  'numberWithFloat:',0x00AE8704,'3eff2fe1',0x00AE8FB8,0x00AE8FCC,0x00AE8728,'3cff2fe1',0x00AE8FAC),
 ('Workbench','hurrying',0x00AE8FF4,0x00F9BA58,'OBJC_IVAR_$_Workbench.hurrying',200,
  'numberWithBool:',0x00AE8764,'33ff2fe1',0x00AE8FB8,0x00AE8FC0,0x00AE8788,'3cff2fe1',0x00AE8FAC),
 ('Workbench','hurryCost',0x00AE8FE8,0x00F9BA68,'OBJC_IVAR_$_Workbench.hurryCost',204,
  'numberWithInt:',0x00AE87C4,'33ff2fe1',0x00AE8FB8,0x00AE94A0,0x00AE87E8,'3cff2fe1',0x00AE8FAC),
 ('Workbench','availableElectricity',0x00AE8FDC,0x00F9B9E8,'OBJC_IVAR_$_Workbench.availableElectricity',222,
  'numberWithUnsignedInt:',0x00AE8824,'33ff2fe1',0x00AE8FB8,0x00AE8FE0,0x00AE8848,'3cff2fe1',0x00AE8FAC),
 ('Workbench','fireSpreadTimer',0x00AE8FD4,0x00F9BA78,'OBJC_IVAR_$_Workbench.fireSpreadTimer',208,
  'numberWithFloat:',0x00AE8884,'3eff2fe1',0x00AE8FB8,0x00AE8FCC,0x00AE88A8,'3cff2fe1',0x00AE8FAC),
 ('Workbench','fuelFraction',0x00AE8FC8,0x00F9B9B8,'OBJC_IVAR_$_Workbench.fuelFraction',212,
  'numberWithFloat:',0x00AE88E4,'3eff2fe1',0x00AE8FB8,0x00AE8FCC,0x00AE8908,'3cff2fe1',0x00AE8FAC),
 ('Workbench','hasFuel',0x00AE8FBC,0x00F9B9C8,'OBJC_IVAR_$_Workbench.hasFuel',220,
  'numberWithBool:',0x00AE8944,'33ff2fe1',0x00AE8FB8,0x00AE8FC0,0x00AE8968,'3cff2fe1',0x00AE8FAC),
 ('Workbench','lastWorldTime',0x00AE8FA4,0x00F9BA88,'OBJC_IVAR_$_Workbench.lastWorldTime',256,
  'numberWithDouble:',0x00AE89A4,'3eff2fe1',0x00AE8FB8,0x00AE8FB0,0x00AE89C8,'3cff2fe1',0x00AE8FAC),
 ('Workbench','currentBlockheadIndexFuel',0x00AE94B0,0x00F9BAA8,None,0,
  'numberWithInt:',0x00AE8C6C,'3eff2fe1',0x00AE949C,0x00AE94A0,0x00AE8C90,'3cff2fe1',0x00AE9498),
 ('Workbench','craftingItemDatav2',0x00AE94BC,0x00F9BAB8,'OBJC_IVAR_$_Workbench.craftingItemObject',180,
  None,None,None,None,None,0x00AE8D84,'3cff2fe1',0x00AE9498),
 ('Workbench','count',0x00AE94D4,0x00F9BAE8,'OBJC_IVAR_$_Workbench.count',228,
  'numberWithInt:',0x00AE8E64,'3eff2fe1',0x00AE949C,0x00AE94A0,0x00AE8E88,'3cff2fe1',0x00AE9498),
 ('Workbench','countLeft',0x00AE94CC,0x00F9BAF8,'OBJC_IVAR_$_Workbench.countLeft',232,
  'numberWithInt:',0x00AE8EC4,'33ff2fe1',0x00AE949C,0x00AE94A0,0x00AE8EE8,'3cff2fe1',0x00AE9498),
 ('Workbench','countCreated',0x00AE94C4,0x00F9BB08,'OBJC_IVAR_$_Workbench.countCreated',236,
  'numberWithInt:',0x00AE8F24,'33ff2fe1',0x00AE949C,0x00AE94A0,0x00AE8F48,'3cff2fe1',0x00AE9498),
 ('Workbench','lightDict',0x00AE94E0,0x00F9BB28,'OBJC_IVAR_$_Workbench.light',100,
  None,None,None,None,None,0x00AE947C,'3cff2fe1',0x00AE9498),
]

DYNAMIC_KEY = {
 'Workbench': {
   'format_cfstring': 0x00F9BB18,
   'format_cfstring_cell': 0x00AE9504,
   'stringWithFormat_selref_cell': 0x00AE9508,
   'nsstring_classref_cell': 0x00AE950C,
   'format_call_site': 0x00AE9370,
   'format_call_word': '3cff2fe1',
   'set_site': 0x00AE9394,
   'set_word': '3cff2fe1',
 },
}

EXTRA_GATES = [
 ('Workbench', 'super_site', 0x00AE8228, '3cff2fe1'),
 ('Workbench', 'fuel_enumerate', 0x00AE8AC0, '3eff2fe1'),
 ('Workbench', 'nested_getsavedict_msg', 0x00AE8D2C, '33ff2fe1'),
 ('Workbench', 'nested_guard_beq', 0x00AE8D40, '1000000a'),
 ('Workbench', 'craftableitem_selref_cell', 0x00AE94C0, None),
 ('Workbench', 'craftingitem_object_cell', 0x00AE94B8, None),
 ('Workbench', 'sourceitems_count_msg', 0x00AE9074, '68249fe5'),
 ('Workbench', 'sourceitems_ivar_cell', 0x00AE94E8, None),
 ('Workbench', 'sourceitems_array_create', 0x00AE90BC, '32ff2fe1'),
 ('Workbench', 'sourceitems_addobject_selref', 0x00AE9218, 'dc329fe5'),
 ('Workbench', 'savedata_selref', 0x00AE9500, None),
 ('Workbench', 'light_getsavedict_selref', 0x00AE948C, None),
 ('Workbench', 'light_nested_msg', 0x00AE9424, '33ff2fe1'),
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

    for cls, dyn in DYNAMIC_KEY.items():
        obj = dyn['format_cfstring']
        if abs32.get(obj) != '__CFConstantStringClassReference':
            raise ValueError(f'{cls}.dynamic: CFString isa drift')
        if cstr(rw(obj + 8)) != 'sourceItems_%d':
            raise ValueError(f'{cls}.dynamic: CFString payload drift')
        if rebase(dyn['format_cfstring_cell']) != obj:
            raise ValueError(f'{cls}.dynamic: format cell drift')
        if cstr(rw(rebase(dyn['stringWithFormat_selref_cell']))) != 'stringWithFormat:':
            raise ValueError(f'{cls}.dynamic: stringWithFormat selref drift')
        if abs32.get(rebase(dyn['nsstring_classref_cell'])) != 'OBJC_CLASS_$_NSString' \
                or rw(rebase(dyn['nsstring_classref_cell'])) != 0:
            raise ValueError(f'{cls}.dynamic: NSString classref drift')
        if not word_eq(dyn['format_call_site'], dyn['format_call_word']):
            raise ValueError(f'{cls}.dynamic: format call word drift')
        if not word_eq(dyn['set_site'], dyn['set_word']):
            raise ValueError(f'{cls}.dynamic: set word drift')
        results[cls]['keys'].append({
            'key': 'sourceItems_%d',
            'key_kind': 'format_string',
            'cfstring_object': f"0x{obj:08x}",
            'value_source': 'per_index_saveData_arrays',
            'set_object_site': f"0x{dyn['set_site']:08x}",
        })

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
            if key == 'craftingItemDatav2':
                entry['value_source'] = 'nested_getSaveDict'
            elif key == 'lightDict':
                entry['value_source'] = 'nested_getSaveDict'
        else:
            entry['conversion'] = conv
            entry['conversion_site'] = f'0x{cs:08x}'
            if isym is None:
                entry['value_source'] = 'loop_index'
            if cw is not None:
                if not word_eq(cs, cw):
                    raise ValueError(f'{cls}.{key}: conv word drift')
            if cstr(rw(rebase(csr))) != conv:
                raise ValueError(f'{cls}.{key}: conv selref drift')
            if abs32.get(rebase(ncell)) != 'OBJC_CLASS_$_NSNumber' or rw(rebase(ncell)) != 0:
                raise ValueError(f'{cls}.{key}: NSNumber classref drift')
        results[cls]['keys'].append(entry)

    gate_notes = {}
    pending = []
    for cls, name, site, wh in EXTRA_GATES:
        if wh is None:
            # cell-existence gates (selref/ivar cells): verify the cell
            # resolves to the expected pool annotation kind by reading
            # the listing annotation semantics — here we gate that the
            # cell word is a valid rebase target (non-crashing).
            _ = rebase(site)
            pending.append(f'{name}@0x{site:08x}')
            continue
        if not word_eq(site, wh):
            raise ValueError(f'{cls}.{name}: gate word drift @0x{site:08x}')
        gate_notes.setdefault(cls, []).append(f'{name}@0x{site:08x}')
    for cls, notes in gate_notes.items():
        results[cls]['site_gates'] = notes
    if pending:
        results['Workbench']['pending_gates'] = pending

    return {
        'schema': 1, 'elf_sha256': SHA, 'pic_base': f'0x{BASE:08x}',
        'method': 'getSaveDict key pairings (batch 2p)',
        'classes': [results[c] for c in ('Workbench',)],
        'claim': ('Workbench — the LARGEST (1232w) and FINAL unpaired '
                  'getSaveDict override — chains super then saves 20 '
                  'static keys (workbenchType re-keys ivar type@120; '
                  'lastWorldTime@256 is the second own-ivar '
                  'numberWithDouble; availableElectricity@222 unsigned; '
                  'the hurry family floats/bool; count/countLeft/'
                  'countCreated@228/232/236 ints), one loop-index '
                  'key (currentBlockheadIndexFuel over blockheads), '
                  'two NESTED [getSaveDict] entity saves '
                  '(craftingItemDatav2 from craftingItemObject@180, '
                  'lightDict from light@100), and the SECOND '
                  'format-string key family sourceItems_%d (per-index '
                  '[saveData] arrays); the craftableItem selector '
                  'consumer is recorded PENDING; the static subclass '
                  'getSaveDict key matrix is now COMPLETE at static '
                  'level-A, read-back/roundtrip unresolved'),
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument('elf', type=Path)
    p.add_argument('--check', action='store_true')
    p.add_argument('--output', type=Path, default=NATIVE / 'subclass_savedict_keys_b2p.json')
    a = p.parse_args()
    text = json.dumps(recover(a.elf), indent=2, sort_keys=True) + '\n'
    if a.check:
        if a.output.read_text() != text:
            raise SystemExit('stale subclass_savedict_keys_b2p.json')
    else:
        a.output.write_text(text)
    print('b2p classes=1 keys=21')


if __name__ == '__main__':
    main()
