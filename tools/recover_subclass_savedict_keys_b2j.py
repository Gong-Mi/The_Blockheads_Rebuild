#!/usr/bin/env python3
"""Hash-gated getSaveDict key pairings for batch 2j: Torch, TradingPost,
FireObject. Addresses/words extracted mechanically from the annotated
listings + freeblock simulator (tools/gen_b2j_table.py), then gated against
the pinned ELF.

Shapes:
  Torch 0x004B65B8: [super getSaveDict] (objc_msgSendSuper2 @0x4b660c), then
    a second objc_msgSend(self, getSaveDict) to fetch the light object's own
    dict (r5 = objc_msgSend ptr @0x4b6618-0x4b6620, call @0x4b660c), then a
    spilled-key cascade boxing Torch.itemType@64, dataA@80, dataB@82,
    connectionType@60 via numberWithInt: (each: ldrh zero-extended halfword
    load of the ivar slot, NSNumber numberWithInt:, then setObject:forKey:),
    a nil-guarded lightDict DIRECT from Torch.light@56 (guard cmp r0, #0 +
    beq at 0x4b68b8/0x4b68bc; load objc_msgSend(self, getSaveDict) result,
    setObject:forKey: 'lightDict' @0x4b6900), and a nil-guarded ownerID
    DIRECT from DynamicObject.ownerID@36 (cmp r1, r0(=0) + beq at
    0x4b6924/0x4b6928, setObject @0x4b6980).
  TradingPost 0x005E6B08: [super getSaveDict] @0x5e6b5c, nil-guarded
    sellerClientName@112 DIRECT (@0x5e6b8c cmp + beq, set @0x5e6be8); then
    fast-enumerates TradingPost.sellSlot@100 (countByEnumeratingWithState:
    @0x5e6cb8, [NSMutableArray array] @0x5e6c60), skipping entries whose
    itemType == 0xb (objc_msgSend(item, itemType) @0x5e6d64, cmp r0, #0xb +
    beq 0x5e6d68/0x5e6d6c), else [saveData addObject: item] (@0x5e6db4
    objc_msgSend(item, saveData) -> r0, then objc_msgSend(array, addObject:,
    r0) @0x5e6dd4) - saveData is a SELECTOR on each iterated item, not an
    ivar of TradingPost; finally priceTier@108 and coinCount@104 via
    numberWithInt: boxed sets (@0x5e6efc priceTier, @0x5e6f38 coinCount),
    and sellSlot@100 stored DIRECT (the NSMutableArray object itself, set
    @0x5e6fbc).
  FireObject 0x0067501C: [super getSaveDict] @0x675070, then a second
    objc_msgSend(self, getSaveDict) for the light dict (@0x67507c-0x675084,
    r3 = msgSend ptr), then burnTimer@56 numberWithFloat: from vldr s0
    [r0] @0x67513c (float32), spreadTimers@60 array float32 elements at
    word +0/+4/+8/+0xc (vldr @0x6751bc/0x67521c/0x67527c/0x6752dc) boxed
    with numberWithFloat: as spreadTimer_0/1/2/3, then a nil-guarded
    lightDict DIRECT from FireObject.light@76 (guard cmp r0, r1(=0) + beq
    0x675350/0x675354, setObject @0x675398).

Facts:
- Torch.dataA@80 / dataB@82 are halfword loads (ldrh 0x4b6784/0x4b67e4);
  zero-extended 16-bit values into numberWithInt:. Torch introduces the
  same-key ivar-offset-storage reuse as Sign (ownerID shared from
  DynamicObject).
- FireObject is the first numberWithFloat: batch: float32 values read by
  VFP vldr s0 and boxed via numberWithFloat:. spreadTimer_0..3 are the
  four float32 lanes of ONE array ivar FireObject.spreadTimers@60.
- TradingPost.saveData is a message to each iterated item, not an ivar;
  items with itemType == 11 are EXCLUDED from the saved array.
- TradingPost.sellSlot is saved DIRECT (the live array object), while the
  filtered array-of-saveData is NOT stored under any key in this method;
  the constructed array is local only.
- Torch.ownerID and FireObject.lightDict / Torch.lightDict are all
  nil-or-zero guarded before setObject:forKey:.
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

# cls, imp, boundary, super_site, super_got_cell, super_sel_cell, super_class_cell
SUPER = {
 'Torch':       (0x004B65B8, 0x004B69E0, 0x004B660C, 0x004B6990, 0x004B6994, 0x004B6998),
 'TradingPost': (0x005E6B08, 0x005E7024, 0x005E6B5C, 0x005E6FCC, 0x005E6FD0, 0x005E6FD4),
 'FireObject':  (0x0067501C, 0x006753EC, 0x00675070, 0x006753A8, 0x006753AC, 0x006753B0),
}

# cls, key, key_cell, cfstring_obj, ivar, off, conv, conv_site, conv_word,
# ncell, conv_sel_cell, set_site, set_word, set_sel_cell
KEYS = [
 ('Torch','itemType',0x004B69C8,0x00F73498,'OBJC_IVAR_$_Torch.itemType',64,
  'numberWithInt:',0x004B6740,'33ff2fe1',0x004B69B4,0x004B69AC,0x004B6764,'3cff2fe1',0x004B69A8),
 ('Torch','dataA',0x004B69C0,0x00F734A8,'OBJC_IVAR_$_Torch.dataA',80,
  'numberWithInt:',0x004B67A0,'33ff2fe1',0x004B69B4,0x004B69AC,0x004B67C4,'3cff2fe1',0x004B69A8),
 ('Torch','dataB',0x004B69B8,0x00F734B8,'OBJC_IVAR_$_Torch.dataB',82,
  'numberWithInt:',0x004B6800,'33ff2fe1',0x004B69B4,0x004B69AC,0x004B6824,'3cff2fe1',0x004B69A8),
 ('Torch','connectionType',0x004B69A4,0x00F73488,'OBJC_IVAR_$_Torch.connectionType',60,
  'numberWithInt:',0x004B6860,'33ff2fe1',0x004B69B4,0x004B69AC,0x004B6884,'3cff2fe1',0x004B69A8),
 ('Torch','lightDict',0x004B69D0,0x00F734C8,'OBJC_IVAR_$_Torch.light',56,
  None,None,None,None,None,0x004B6900,'3cff2fe1',0x004B69A8),
 ('Torch','ownerID',0x004B69D8,0x00F73478,'OBJC_IVAR_$_DynamicObject.ownerID',36,
  None,None,None,None,None,0x004B6980,'3cff2fe1',0x004B69A8),
 ('TradingPost','sellerClientName',0x005E6FDC,0x00F7E0B8,'OBJC_IVAR_$_TradingPost.sellerClientName',112,
  None,None,None,None,None,0x005E6BE8,'3cff2fe1',0x005E6FE4),
 ('TradingPost','coinCount',0x005E7014,0x00F7E098,'OBJC_IVAR_$_TradingPost.coinCount',104,
  'numberWithInt:',0x005E6F38,'33ff2fe1',0x005E7010,0x005E7008,0x005E6F5C,'3cff2fe1',0x005E6FE4),
 ('TradingPost','priceTier',0x005E7004,0x00F7E0A8,'OBJC_IVAR_$_TradingPost.priceTier',108,
  'numberWithInt:',0x005E6F98,'33ff2fe1',0x005E7010,0x005E7008,0x005E6FBC,'3cff2fe1',0x005E6FE4),
 ('TradingPost','sellSlot',0x005E701C,0x00F7DFF8,'OBJC_IVAR_$_TradingPost.sellSlot',100,
  None,None,None,None,None,0x005E6EFC,'38ff2fe1',0x005E6FE4),
 ('FireObject','burnTimer',0x006753DC,0x00F82558,'OBJC_IVAR_$_FireObject.burnTimer',56,
  'numberWithFloat:',0x00675178,'33ff2fe1',0x006753CC,0x006753C4,0x0067519C,'3cff2fe1',0x006753C0),
 ('FireObject','spreadTimer_0',0x006753D8,0x00F82568,'OBJC_IVAR_$_FireObject.spreadTimers',60,
  'numberWithFloat:',0x006751D8,'3eff2fe1',0x006753CC,0x006753C4,0x006751FC,'3cff2fe1',0x006753C0),
 ('FireObject','spreadTimer_1',0x006753D4,0x00F82578,'OBJC_IVAR_$_FireObject.spreadTimers',60,
  'numberWithFloat:',0x00675238,'3eff2fe1',0x006753CC,0x006753C4,0x0067525C,'3cff2fe1',0x006753C0),
 ('FireObject','spreadTimer_2',0x006753D0,0x00F82588,'OBJC_IVAR_$_FireObject.spreadTimers',60,
  'numberWithFloat:',0x00675298,'3eff2fe1',0x006753CC,0x006753C4,0x006752BC,'3cff2fe1',0x006753C0),
 ('FireObject','spreadTimer_3',0x006753BC,0x00F82598,'OBJC_IVAR_$_FireObject.spreadTimers',60,
  'numberWithFloat:',0x006752F8,'3eff2fe1',0x006753CC,0x006753C4,0x0067531C,'3cff2fe1',0x006753C0),
 ('FireObject','lightDict',0x006753E4,0x00F825A8,'OBJC_IVAR_$_FireObject.light',76,
  None,None,None,None,None,0x00675398,'3cff2fe1',0x006753C0),
]

# site-based gates that are not per-key: second getSaveDict dispatch,
# guards, enumeration, itemType==0xb exclusion, saveData selector.
EXTRA_GATES = [
 ('Torch', 'second_getsavedict_site', 0x004B660C, '3cff2fe1'),
 ('Torch', 'ownerID_guard_cmp', 0x004B6924, '000051e1'),
 ('Torch', 'ownerID_guard_beq', 0x004B6928, '1500000a'),
 ('Torch', 'light_guard_cmp', 0x004B68B8, '010050e1'),
 ('Torch', 'light_guard_beq', 0x004B68BC, '1000000a'),
 ('Torch', 'dataA_ldrh', 0x004B6784, 'b030d3e1'),
 ('Torch', 'dataB_ldrh', 0x004B67E4, 'b030d3e1'),
 ('TradingPost', 'seller_guard_cmp', 0x005E6B8C, '000051e1'),
 ('TradingPost', 'seller_guard_beq', 0x005E6B90, '1500000a'),
 ('TradingPost', 'enumerate_site', 0x005E6CB8, '3eff2fe1'),
 ('TradingPost', 'itemtype_msg_site', 0x005E6D64, '32ff2fe1'),
 ('TradingPost', 'itemtype_cmp_0xb', 0x005E6D68, '0b0050e3'),
 ('TradingPost', 'itemtype_beq', 0x005E6D6C, '1900000a'),
 ('TradingPost', 'savedata_msg_site', 0x005E6DB4, '3cff2fe1'),
 ('TradingPost', 'addobject_site', 0x005E6DD4, '33ff2fe1'),
 ('FireObject', 'second_getsavedict_site', 0x00675070, '3cff2fe1'),
 ('FireObject', 'burn_vldr', 0x0067513C, '000a90ed'),
 ('FireObject', 'spread_vldr_0', 0x006751BC, '000a93ed'),
 ('FireObject', 'spread_vldr_1', 0x0067521C, '010a93ed'),
 ('FireObject', 'spread_vldr_2', 0x0067527C, '020a93ed'),
 ('FireObject', 'spread_vldr_3', 0x006752DC, '030a93ed'),
 ('FireObject', 'light_guard_cmp', 0x00675350, '010050e1'),
 ('FireObject', 'light_guard_beq', 0x00675354, '1000000a'),
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
        'method': 'getSaveDict key pairings (batch 2j)',
        'classes': [results[c] for c in ('Torch', 'TradingPost', 'FireObject')],
        'claim': ('Torch saves itemType/dataA/dataB/connectionType as '
                  'numberWithInt: boxes (dataA@80/dataB@82 are ldrh '
                  'zero-extended halfwords) plus nil-guarded DIRECT '
                  'lightDict (Torch.light@56) and ownerID (shared '
                  'DynamicObject.ownerID@36); TradingPost stores a '
                  'nil-guarded DIRECT sellerClientName@112, builds a '
                  'local NSMutableArray of per-item [saveData] dicts '
                  'EXCLUDING itemType==11 entries (saveData is a selector '
                  'on each item of sellSlot@100, not an ivar), and saves '
                  'priceTier@108/coinCount@104 numberWithInt: plus the '
                  'LIVE sellSlot array DIRECT; FireObject is the first '
                  'numberWithFloat: batch - burnTimer@56 and the four '
                  'float32 lanes of spreadTimers@60 (spreadTimer_0..3, '
                  'vldr s0 [r3, #0/4/8/0xc]) are float-boxed, lightDict '
                  'DIRECT from FireObject.light@76 nil-guarded; 10 '
                  'overrides remain, read-back/roundtrip unresolved'),
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument('elf', type=Path)
    p.add_argument('--check', action='store_true')
    p.add_argument('--output', type=Path, default=NATIVE / 'subclass_savedict_keys_b2j.json')
    a = p.parse_args()
    text = json.dumps(recover(a.elf), indent=2, sort_keys=True) + '\n'
    if a.check:
        if a.output.read_text() != text:
            raise SystemExit('stale subclass_savedict_keys_b2j.json')
    else:
        a.output.write_text(text)
    print('b2j classes=3 keys=16')


if __name__ == '__main__':
    main()
