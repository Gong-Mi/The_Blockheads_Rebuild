#!/usr/bin/env python3
"""Hash-gated key->objectForKey->conversion->writeback chains for
NPC -[loadValuesFromSaveDict:].

Boundaries from the pinned method map: IMP 0x00643b20, next IMP 0x0064448c.
Per chain, four gates on the pinned ELF (no proximity promotion):
  1. CFString key object: R_ARM_ABS32 -> __CFConstantStringClassReference at
     the object word, data ptr at +8 cstr == key, length field +12 == strlen;
  2. key-load site is `ldr rN,[pc,#lit]` whose literal cell re-bases to the
     object address;
  3. raw words at objectForKey/conversion/writeback sites;
  4. write-side agreement: the same CFString object constant and ivar byte
     offset recorded in npc_save_keys.json (documented asymmetries excepted).

Conversion selector names come from the checked-in annotated listing
(disasm_npc_loadvaluesfromsavedict.txt) and are cross-checked to exist in
the __objc_selrefs table.
"""
import argparse, hashlib, io, json
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from trace_objc_dispatch import ELFMemory

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
START, BOUNDARY = 0x00643B20, 0x0064448C
BASE = 0x0105FAF4

# key, cfstring_obj, key_load_site, ok_site, ok_word, conv_selector,
# conv_site, conv_word, wb_kind, wb_site, wb_word, ivar_name, ivar_offset
CHAIN = [
 ('fullness',                    0x00F80568, 0x00643BF4, 0x00643C4C, '34ff2fe1', 'floatValue',            0x00643C5C, '32ff2fe1', 'vstr', 0x00643C74, '000a80ed', 'fullness', 68),
 ('layTimer',                    0x00F80578, 0x00643BD4, 0x00643C8C, '33ff2fe1', 'floatValue',            0x00643C9C, '32ff2fe1', 'vstr', 0x00643CB4, '000a80ed', 'layTimer', 80),
 ('damage',                      0x00F80588, 0x00643BC4, 0x00643CCC, '33ff2fe1', 'intValue',              0x00643CDC, '32ff2fe1', 'strh', 0x00643CF0, 'b000c1e1', 'damage', 54),
 ('age',                         0x00F80598, 0x00643BA0, 0x00643D08, '33ff2fe1', 'floatValue',            0x00643D18, '32ff2fe1', 'vstr', 0x00643D30, '000a80ed', 'age', 88),
 ('layCooldownTimer',            0x00F805A8, 0x00643E50, 0x00643EA8, '34ff2fe1', 'floatValue',            0x00643EB8, '32ff2fe1', 'vstr', 0x00643ED0, '000a80ed', 'layCooldownTimer', 84),
 ('tameCooldownTimer',           0x00F805B8, 0x00643E30, 0x00643EE8, '33ff2fe1', 'floatValue',            0x00643EF8, '32ff2fe1', 'vstr', 0x00643F10, '000a80ed', 'tameCooldownTimer', 72),
 ('mateCooldownTimer',           0x00F805C8, 0x00643E10, 0x00643F28, '33ff2fe1', 'floatValue',            0x00643F38, '32ff2fe1', 'vstr', 0x00643F50, '000a80ed', 'mateCooldownTimer', 76),
 ('hasBred',                     0x00F805D8, 0x00643DE0, 0x00643F68, '33ff2fe1', 'boolValue',             0x00643F78, '32ff2fe1', 'strb', 0x00643F8C, '0000c1e5', 'hasBred', 100),
 ('hasBeenFedByBlockheadOrChest',0x00F805E8, 0x00643DC8, 0x00643FA4, '33ff2fe1', 'boolValue',             0x00643FB4, '32ff2fe1', 'strb', 0x00643FC8, '0000c1e5', 'hasBeenFedByBlockheadOrChest', 101),
 ('mateBreed',                   0x00F805F8, 0x00643DA0, 0x00643FE0, '33ff2fe1', 'intValue',              0x00643FF0, '32ff2fe1', 'strh', 0x00644004, 'b000c1e1', 'mateBreed', 98),
 ('breed',                       0x00F80608, 0x00644074, 0x006440A8, '3eff2fe1', 'unsignedIntegerValue',  0x006440B8, '32ff2fe1', 'strh', 0x006440CC, 'b000c1e1', 'breed', 96),
 ('tamedClientID',               0x00F80618, 0x00644124, 0x00644174, '3cff2fe1', 'retain',                0x00644184, '32ff2fe1', 'str',  0x00644198, '000081e5', 'tamedClientID', 108),
 ('name',                        0x00F80628, 0x00644114, 0x006441E0, '33ff2fe1', 'retain',                0x006441F0, '32ff2fe1', 'str',  0x00644204, '000081e5', 'name', 92),
 ('tameCountsByClientID',        0x00F80638, 0x006440D4, 0x00644264, '3eff2fe1', 'retain',                0x006442E4, '32ff2fe1', 'str',  0x006442F8, '000081e5', 'tameCountsByClientID', 104),
 ('currentBlockheadIndex',       0x00F80648, 0x00644384, 0x006443B8, '3eff2fe1', 'intValue',              0x006443C8, '32ff2fe1', 'str',  0x006443DC, '000081e5', 'savedBlockheadIndex', 136),
]
# first (guard/nil-check) probes of the twice-read keys:
GUARD_PROBES = {'fullness': 0x00643B70, 'layCooldownTimer': 0x00643D70,
                'breed': 0x00644044, 'currentBlockheadIndex': 0x00644354}
# tameCountsByClientID is installed as a mutable copy: dictionaryWithDictionary:
# at 0x006442d4 (blx lr) feeds the retain above.
DICTIONARY_COPY_SITE = 0x006442D4


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

    elf = ELFFile(io.BytesIO(raw))
    abs32 = {}
    for section in elf.iter_sections():
        if isinstance(section, RelocationSection):
            syms = elf.get_section(section['sh_link'])
            for rel in section.iter_relocations():
                if rel['r_info_type'] == 2 and rel['r_info_sym']:
                    abs32[rel['r_offset']] = syms.get_symbol(rel['r_info_sym']).name
    dynsym = elf.get_section_by_name('.dynsym')
    ivars = {s.name[len('OBJC_IVAR_$_NPC.'):]: s['st_value']
             for s in dynsym.iter_symbols()
             if s['st_value'] and s.name.startswith('OBJC_IVAR_$_NPC.')}

    write_side = json.loads((NATIVE / 'npc_save_keys.json').read_text())
    ws = {p['key']: p for p in write_side['pairings']}
    listing = (NATIVE / 'disasm_npc_loadvaluesfromsavedict.txt').read_text()

    pairings = []
    for (key, obj, kload, oksite, okword, conv_sel, conv_site, conv_word,
         wb_kind, wb_site, wb_word, ivar, off) in CHAIN:
        if not (START <= kload <= BOUNDARY and START <= wb_site <= BOUNDARY):
            raise ValueError(f'{key}: site outside boundary')
        if abs32.get(obj) != '__CFConstantStringClassReference':
            raise ValueError(f'{key}: CFString isa reloc drift')
        da = rw(obj + 8)
        if da is None or cstr(da) != key or rw(obj + 12) != len(key.encode()):
            raise ValueError(f'{key}: CFString payload drift')
        kw = rw(kload)
        if kw & 0x051F0000 != 0x051F0000:
            raise ValueError(f'{key}: key-load not ldr rN,[pc,#imm]')
        lit = (kload + 8 + (kw & 0xFFF)) & 0xFFFFFFFF
        if (BASE + signed(rw(lit))) & 0xFFFFFFFF != obj:
            raise ValueError(f'{key}: key-load cell does not resolve to object')
        for site, wh, label in ((oksite, okword, 'objectForKey'),
                                (conv_site, conv_word, conv_sel),
                                (wb_site, wb_word, wb_kind)):
            if rw(site).to_bytes(4, 'little').hex() != wh:
                raise ValueError(f'{key}: {label} word drift at {site:#x}')
        stor = ivars.get(ivar)
        if stor is None or rw(stor) != off:
            raise ValueError(f'{key}: ivar offset drift {ivar}')
        if conv_sel not in m.selectors.values():
            raise ValueError(f'{key}: conversion selector not in selrefs table')
        if f'{conv_site:#010x}' not in listing:
            raise ValueError(f'{key}: conv site missing from annotated listing')
        w = ws.get(key)
        if w is None:
            raise ValueError(f'{key}: no write-side pairing to compare')
        if w['constant_string_object'] != f'0x{obj:08x}':
            raise ValueError(f'{key}: CFString object differs from write side')
        wsrc = w.get('value_source') or {}
        woff = wsrc.get('ivar_offset')
        if wsrc.get('ivar', '').startswith('OBJC_IVAR_$_NPC.') and woff != off:
            raise ValueError(f'{key}: ivar offset disagrees with write side')
        pairings.append({
            'key': key, 'cfstring_object': f'0x{obj:08x}',
            'key_load_site': f'0x{kload:08x}',
            'object_for_key_site': f'0x{oksite:08x}',
            'conversion': conv_sel, 'conversion_site': f'0x{conv_site:08x}',
            'writeback': wb_kind, 'writeback_site': f'0x{wb_site:08x}',
            'ivar': f'OBJC_IVAR_$_NPC.{ivar}', 'ivar_offset': off,
        })
    return {
        'schema': 1, 'elf_sha256': SHA, 'method': 'NPC -[loadValuesFromSaveDict:]',
        'imp': f'0x{START:08x}', 'boundary': f'0x{BOUNDARY:08x}',
        'pairing_count': len(pairings),
        'guard_probes': {k: f'0x{v:08x}' for k, v in sorted(GUARD_PROBES.items())},
        'dictionary_copy_site': f'0x{DICTIONARY_COPY_SITE:08x}',
        'asymmetries': {
            'currentBlockheadIndex': 'read back into NPC.savedBlockheadIndex @136; '
                                     'write side derives the key from the rider loop',
            'saveTime': 'no read-back: derived from world time on save only',
        },
        'pairings': pairings,
        'claim': ('15 key->objectForKey->conversion->self+ivar writeback chains pinned '
                  'with CFString reloc/length, key-load cell, raw-word, dynsym-ivar and '
                  'write-side agreement gates; no objc_msgSendSuper2 in this body, so '
                  'inherited DynamicObject fields load elsewhere; retain/release '
                  'ordering and all runtime behavior unresolved'),
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument('elf', type=Path)
    p.add_argument('--check', action='store_true')
    p.add_argument('--output', type=Path, default=NATIVE / 'npc_loadvalues_keys.json')
    a = p.parse_args()
    text = json.dumps(recover(a.elf), indent=2, sort_keys=True) + '\n'
    if a.check:
        if a.output.read_text() != text:
            raise SystemExit('stale npc_loadvalues_keys.json')
    else:
        a.output.write_text(text)
    print('npc-loadvalues pairings=15 guard_probes=4')


if __name__ == '__main__':
    main()
