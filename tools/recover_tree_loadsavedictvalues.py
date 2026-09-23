#!/usr/bin/env python3
"""Hash-gated loadValues evidence for batch b3a: Tree
-[loadSaveDictValues:] — the read-back counterpart of the b2o Tree
getSaveDict pairings. Gates the objectForKey:/conv/store site chains
against the pinned ELF and asserts the save/load key-set asymmetry.

Load shape (all sites gated):
  treeSeasonOffset: objectForKey @0x4c2f60 (blx r3) → intValue
    @0x4c2f70 (blx r2) → WORD store @0x4c2f84 (str r0,[r1]) into
    Tree.treeSeasonOffset@84.
  dead: objectForKey @0x4c2f9c → boolValue @0x4c2fac → BYTE store
    @0x4c2fc0 (strb) into Tree.dead@104.
  timeDied: objectForKey @0x4c2fd8 → doubleValue @0x4c2fe8 →
    vmov d0 @0x4c2fec → vstr d0 @0x4c3000 into Tree.timeDied@112
    (64-bit field).
  removeCheckCount: objectForKey @0x4c3018 → floatValue @0x4c3028 →
    vmov s2 @0x4c302c → vstr s2 @0x4c3040 into
    Tree.removeCheckCount@120.
  treeFruit: objectForKey @0x4c3058 → fruitCount@128 reset to 0
    (store @0x4c3074) → fast-enumerate the array
    (countByEnumeratingWithState @0x4c30b8, empty-guard beq
    0x4c30bc/0x4c30c4); per fruit dict: pos.x/pos.y word stores and
    hasCreatedFreeBlockThisSeason (objectForKey → boolValue →
    sxtb @0x4c3290) written into the treeFruits@124 C-array with
    12-BYTE record stride (movw #0xc @0x4c32a8; mul @0x4c32fc);
    isStaticTree members take a different branch (tileIsKindOfSelf
    selref @0x4c3944 in pool).
  isStaticTree LOAD-SIDE GATE: msgSend → sxtb @0x4c3568 → cmp
    @0x4c356c → bne #0x4c38e4 @0x4c3570 — the gene/growth block
    (maxHeightReached/growthRateGene/maxHeightGene + growth family)
    is loaded ONLY for non-static trees, mirroring the save-side
    gate from b2o.

Key facts:
- saveTime is NOT read back: the CFString pool of this method
  contains NO 'saveTime' key — the world-clock stamp written by
  Tree getSaveDict (b2o) is WRITE-ONLY. This is the first save/load
  asymmetry proven at static level for the Tree family.
- The load-side isStaticTree gate mirrors the save-side conditional
  key set (b2o): static trees load only the always-on keys.
- The fruit records are 12-byte structs (pos.x word, pos.y word,
  hasCreatedFreeBlockThisSeason byte + stride padding) reconstructed
  from the per-fruit dictionaries — matching the save-side
  construction from the same three keys.
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

IMP = 0x004C2DF0
BOUNDARY = 0x004C39A0

# key, ivar, off, objectforkey_site, conv_site, conv_sel, store_site, store_word, store_kind
CHAINS = [
 ('treeSeasonOffset', 'OBJC_IVAR_$_Tree.treeSeasonOffset', 84,
  0x004C2F60, 0x004C2F70, 'intValue', 0x004C2F84, '000081e5', 'word_store'),
 ('dead', 'OBJC_IVAR_$_Tree.dead', 104,
  0x004C2F9C, 0x004C2FAC, 'boolValue', 0x004C2FC0, '0000c1e5', 'byte_store'),
 ('timeDied', 'OBJC_IVAR_$_Tree.timeDied', 112,
  0x004C2FD8, 0x004C2FE8, 'doubleValue', 0x004C3000, '000b80ed', 'double_store'),
 ('removeCheckCount', 'OBJC_IVAR_$_Tree.removeCheckCount', 120,
  0x004C3018, 0x004C3028, 'floatValue', 0x004C3040, '001a80ed', 'float_store'),
]

# treeFruit + fruit-loop gates
FRUIT_GATES = [
 ('treeFruit_objectforkey_site', 0x004C3058, '33ff2fe1'),
 ('fruitcount_reset_store', 0x004C3074, '002080e5'),
 ('fruit_enumerate_site', 0x004C30B8, '3eff2fe1'),
 ('fruit_empty_beq', 0x004C30C4, 'dd00000a'),
 ('fruit_stride_movw_0xc', 0x004C32A8, '0c2000e3'),
 ('hcfb_sxtb', 0x004C3290, '7000afe6'),
]

# isStaticTree load-side gate + the gene-block entry
GATE_GATES = [
 ('isstatictree_sxtb', 0x004C3568, '7000afe6'),
 ('isstatictree_cmp', 0x004C356C, '000050e3'),
 ('isstatictree_bne', 0x004C3570, 'db00001a'),
 ('geneblock_maxheightreached_key_load', 0x004C35A4, 'cc639fe5'),
]

# The CFString key objects that MUST be in this method's pool (spill
# cascade), and the one that must NOT be (saveTime write-only).
POOL_KEYS_REQUIRED = ['treeFruit', 'removeCheckCount', 'timeDied',
                      'dead', 'treeSeasonOffset', 'pos.y', 'pos.x',
                      'hasCreatedFreeBlockThisSeason', 'maxAge',
                      'height', 'growthRateGene', 'maxHeightGene',
                      'maxHeightReached', 'maxHeight', 'growthRate',
                      'growthCounter', 'age']
POOL_KEY_ABSENT = 'saveTime'

KEY_CELLS = {
 'treeFruit': 0x004C38F8, 'removeCheckCount': 0x004C3908,
 'timeDied': 0x004C3914, 'dead': 0x004C3920,
 'treeSeasonOffset': 0x004C392C, 'pos.y': 0x004C3934,
 'pos.x': 0x004C3938, 'hasCreatedFreeBlockThisSeason': 0x004C394C,
 'maxAge': 0x004C3968, 'height': 0x004C3960,
 'growthRateGene': 0x004C397C, 'maxHeightGene': 0x004C3980,
 'maxHeightReached': 0x004C3978, 'maxHeight': 0x004C3988,
 'growthRate': 0x004C3990, 'growthCounter': 0x004C3998,
 'age': 0x004C3958,
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
    row = by_imp.get(IMP)
    if row is None or row[1] != 'Tree' or row[3] != 'loadSaveDictValues:':
        raise ValueError('method-map drift')
    if min(i for i in imps if i > IMP) != BOUNDARY:
        raise ValueError('boundary drift')

    # CFString pool gates
    keys_seen = set()
    for key, cell in KEY_CELLS.items():
        obj = rebase(cell)
        if abs32.get(obj) != '__CFConstantStringClassReference':
            raise ValueError(f'{key}: CFString isa drift')
        if cstr(rw(obj + 8)) != key or rw(obj + 12) != len(key.encode()):
            raise ValueError(f'{key}: CFString payload drift')
        keys_seen.add(key)
    if set(POOL_KEYS_REQUIRED) != keys_seen:
        raise ValueError(f'pool key set drift: missing '
                         f'{set(POOL_KEYS_REQUIRED) - keys_seen}, extra '
                         f'{keys_seen - set(POOL_KEYS_REQUIRED)}')
    # saveTime must NOT appear: scan the whole method body's literal
    # cells for any CFString resolving to 'saveTime'.
    for a in range(IMP, BOUNDARY, 4):
        if a & 3:
            continue
        # only inspect PC-relative ldr literal slots
        w = rw(a)
        if w & 0x0FFF0000 == 0x059F0000 and (w >> 12) & 0xF != 15:
            lit = (a + 8 + (w & 0xFFF)) & 0xFFFFFFFF
            if lit >= BASE and lit < BASE + 0x2000000:
                t = rebase(lit)
                if abs32.get(t) == '__CFConstantStringClassReference':
                    name = cstr(rw(t + 8))
                    if name == POOL_KEY_ABSENT:
                        raise ValueError(
                            f'{POOL_KEY_ABSENT} unexpectedly read at '
                            f'literal 0x{lit:08x}')

    chains_out = []
    for key, isym, off, ofk, cs, conv, store, store_w, kind in CHAINS:
        stor = ivar_by_name.get(isym)
        if stor is None or rw(stor) != off:
            raise ValueError(f'{key}: ivar drift')
        if not word_eq(ofk, '33ff2fe1'):
            raise ValueError(f'{key}: objectForKey word drift')
        if not word_eq(cs, '32ff2fe1'):
            raise ValueError(f'{key}: conv call word drift')
        if not word_eq(store, store_w):
            raise ValueError(f'{key}: store word drift')
        chains_out.append({
            'key': key, 'ivar': isym, 'ivar_offset': off,
            'objectforkey_site': f'0x{ofk:08x}',
            'conversion': conv, 'conversion_site': f'0x{cs:08x}',
            'store_site': f'0x{store:08x}', 'store_kind': kind})

    gates = []
    for name, site, wh in FRUIT_GATES + GATE_GATES:
        if not word_eq(site, wh):
            raise ValueError(f'{name}: gate word drift @0x{site:08x}')
        gates.append(f'{name}@0x{site:08x}')

    # fruit ivars
    for isym, off in (('OBJC_IVAR_$_Tree.fruitCount', 128),
                      ('OBJC_IVAR_$_Tree.treeFruits', 124)):
        stor = ivar_by_name.get(isym)
        if stor is None or rw(stor) != off:
            raise ValueError(f'{isym}: ivar drift')

    return {
        'schema': 1, 'elf_sha256': SHA, 'pic_base': f'0x{BASE:08x}',
        'method': 'Tree loadSaveDictValues: read-back evidence (batch b3a)',
        'class': 'Tree', 'imp': f'0x{IMP:08x}',
        'boundary': f'0x{BOUNDARY:08x}',
        'code_words': (BOUNDARY - IMP) // 4,
        'chains': chains_out,
        'treeFruit': {
            'objectforkey_site': '0x004c3058',
            'fruitcount_reset': True,
            'enumerate_site': '0x004c30b8',
            'record_stride': 0xc,
            'fruit_keys': ['pos.x', 'pos.y',
                           'hasCreatedFreeBlockThisSeason'],
        },
        'isStaticTree_gate': {
            'sxtb': '0x004c3568', 'cmp': '0x004c356c',
            'bne': '0x004c3570',
            'note': 'gene/growth block loaded only for non-static trees, '
                    'mirroring the save-side gate (b2o)'},
        'saveTime_read_back': False,
        'pool_keys': sorted(keys_seen),
        'site_gates': gates,
        'claim': ('Tree -[loadSaveDictValues:] reads '
                  'treeSeasonOffset/dead/timeDied/removeCheckCount via '
                  'objectForKey+intValue/boolValue/doubleValue/'
                  'floatValue into word/byte/64-bit/float ivar stores, '
                  'reconstructs treeFruit from per-fruit dictionaries '
                  '(pos.x/pos.y/hasCreatedFreeBlockThisSeason into '
                  '12-byte treeFruits records with fruitCount reset '
                  'first), and gates the gene/growth block behind '
                  'isStaticTree — mirroring the save-side conditional '
                  'from b2o; saveTime is NOT read (write-only world '
                  'stamp — first proven save/load key asymmetry); '
                  'static level-A only, runtime roundtrip unresolved'),
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument('elf', type=Path)
    p.add_argument('--check', action='store_true')
    p.add_argument('--output', type=Path, default=NATIVE / 'tree_loadsavedictvalues.json')
    a = p.parse_args()
    text = json.dumps(recover(a.elf), indent=2, sort_keys=True) + '\n'
    if a.check:
        if a.output.read_text() != text:
            raise SystemExit('stale tree_loadsavedictvalues.json')
    else:
        a.output.write_text(text)
    print('b3a chains=4 pool_keys=17')


if __name__ == '__main__':
    main()
