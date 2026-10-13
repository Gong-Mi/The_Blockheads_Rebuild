#!/usr/bin/env python3
"""Hash-gated getSaveDict key pairings for batch 2o: Action, Tree.
Addresses/words extracted mechanically from the annotated listings +
freeblock simulator (tools/gen_b2o_table.py pipeline), then gated
against the pinned ELF.

Shapes:
  Action 0x00735E54: NO [super getSaveDict] — the method builds its own
    [NSMutableDictionary dictionary] (@0x735ee0, classref 0x7365b8,
    'dictionary' selref 0x7365c0) and saves 15 own keys directly into
    it (first self-built-dictionary override in the census):
      inProgress@4 = numberWithBool of ldrsb byte (conv 0x735f28);
      isAI@6 = numberWithBool (conv 0x735f98);
      goalTilePos.x/.y@8 = numberWithInt word pair (conv 0x736004/
        0x736068);
      interactionItemIndex@20 / interactionItemSubIndex@22 =
        numberWithInt (conv 0x7360d0/0x736138);
      interactionItemType = numberWithInt of msgSend(interactionItem,
        itemType) — computed cross-entity selector (msg @0x73619c,
        conv 0x7361bc);
      goalInteraction@24 / pathType@28 = numberWithInt (conv 0x736220/
        0x736284);
      interactionObjectID@32 = numberWithUnsignedLong (conv 0x7362e8);
      inventoryChange@64 = nil-guarded DIRECT dict object (cmp/beq
        0x736328/0x73632c, set 0x736384);
      craftableItemObject@40 = NESTED [getSaveDict] of the ivar object
        (msg @0x7363d0, nil-guard cmp/beq 0x7363e0/0x7363e4, set
        0x736428);
      craftCountOrExtraData@44 = numberWithUnsignedInt of a ldrsh
        SIGNED HALFWORD load @0x7364cc — signed source boxed unsigned;
      interactionTestResult@52 = [NSData dataWithBytes:length:0xc] —
        12 raw bytes (movw #0xc @0x73644c, msg @0x736570), stored
        UNGUARDED.
  Tree 0x004C3CAC: [super getSaveDict] @0x4c3d00, then 16 own keys:
      height@60 int (conv 0x4c3eec); saveTime = world-fed
        numberWithDouble([world worldTime]) (msg 0x4c3f4c, conv
        0x4c3f6c); treeSeasonOffset@84 int (conv 0x4c3fcc);
        age@96 float (vldr s2 @0x4c4010, conv 0x4c402c); dead@104
        bool (ldrb @0x4c4070 + sxtb, conv 0x4c408c); timeDied@112 =
        numberWithDouble of a vldr d0 OWN-IVAR double (first own-ivar
        double; @0x4c40d0, conv 0x4c40ec); removeCheckCount@120 float
        (conv 0x4c414c); treeFruit = NSMutableArray built by looping
        fruitCount@128 times over treeFruits@124 C-array elements,
        each fruit saved as its own [NSMutableDictionary dictionary]
        with keys pos.x (word @0x4c42f4), pos.y (word+4 @0x4c4368),
        hasCreatedFreeBlockThisSeason (ldrb [r3,#8] @0x4c43dc + sxtb),
        then addObject: @0x4c4440; the finished array is set under
        'treeFruit' @0x4c44a4. THEN an isStaticTree gate (msg
        @0x4c44b8, sxtb, cmp/bne 0x4c44c0/0x4c44c4 → skip to epilogue):
        only NON-STATIC trees additionally save maxHeightGene@54
        (ldrh @0x4c45f0, conv 0x4c4630), growthRateGene@56 (ldrh
        @0x4c4674, conv 0x4c4690), maxHeightReached@64 (word @0x4c46d4,
        conv 0x4c46f0), growthCounter@68 float (vldr s0 @0x4c4734,
        conv 0x4c4750), growthRate@72 float (vldr s0 @0x4c4794, conv
        0x4c47b0), maxHeight@88 int (conv 0x4c4810), maxAge@92 float
        (vldr s0 @0x4c4854, conv 0x4c4870).

Facts:
- Action is the FIRST override that builds its own dictionary instead
  of chaining [super getSaveDict] — Action entities do not inherit
  DynamicObject's base keys in their save dict.
- Action.craftCountOrExtraData loads a SIGNED halfword (ldrsh) but
  boxes it numberWithUnsignedInt — the sign bit survives into the
  unsigned domain; a replacement encoder must reproduce the
  sign-extended-then-unsigned value, not the raw halfword bits.
- Action.interactionTestResult is the second raw-buffer key
  (12 bytes, after CaveTroll.state's 36) and is saved UNGUARDED — an
  all-zero result still produces an NSData entry.
- Action.craftableItemObject is the first NESTED entity save via
  [ivar getSaveDict] (dynamic object graph inside a save).
- Tree.timeDied is the first OWN-IVAR double (vldr d0): saveTime is
  world-fed in every class so far, but timeDied reads a stored 64-bit
  timestamp field.
- Tree's fruit sub-dictionaries REUSE the keys pos.x/pos.y/
  hasCreatedFreeBlockThisSeason per fruit — key names collide with the
  parent's own pos keys in other classes; the treeFruit array entries
  are independently keyed dictionaries.
- The isStaticTree gate means STATIC trees save a SMALLER key set:
  height/saveTime/treeSeasonOffset/age/dead/timeDied/
  removeCheckCount/treeFruit only; the eight growth keys are
  non-static-only.
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

# Tree: cls, imp, boundary, super_site, super_got_cell, super_sel_cell, super_class_cell
SUPER = {
 'Tree': (0x004C3CAC, 0x004C4974, 0x004C3D00, 0x004C48A4, 0x004C48A8, 0x004C48AC),
}

# Action: own-dictionary creation gates (no super).
OWN_DICT = {
 'Action': {
   'imp': 0x00735E54, 'boundary': 0x0073664C,
   'dictionary_call_site': 0x00735EE0, 'dictionary_call_word': '4d32eaeb',
   'mutable_dict_classref_cell': 0x007365B8,
   'dictionary_selref_cell': 0x007365C0,
 },
}

# cls, key, key_cell, cfstring_obj, ivar, off, conv, conv_site, conv_word,
# ncell, conv_sel_cell, set_site, set_word, set_sel_cell
KEYS = [
 ('Action','inProgress',0x007365D0,0x00F8CC98,'OBJC_IVAR_$_Action.inProgress',4,
  'numberWithBool:',0x00735F28,'3b32eaeb',0x007365C4,0x007365CC,0x00735F5C,'2e32eaeb',0x007365B0),
 ('Action','isAI',0x007365D8,0x00F8CCA8,'OBJC_IVAR_$_Action.isAI',6,
  'numberWithBool:',0x00735F98,'1f32eaeb',0x007365C4,0x007365CC,0x00735FC0,'1532eaeb',0x007365B0),
 ('Action','goalTilePos.x',0x007365E4,0x00F8CCB8,'OBJC_IVAR_$_Action.goalTilePos',8,
  'numberWithInt:',0x00736004,'0432eaeb',0x007365C4,0x007365E0,0x0073602C,'fa31eaeb',0x007365B0),
 ('Action','goalTilePos.y',0x007365E8,0x00F8CCC8,'OBJC_IVAR_$_Action.goalTilePos',8,
  'numberWithInt:',0x00736068,'eb31eaeb',0x007365C4,0x007365E0,0x00736090,'e131eaeb',0x007365B0),
 ('Action','interactionItemIndex',0x007365F0,0x00F8CCD8,'OBJC_IVAR_$_Action.interactionItemIndex',20,
  'numberWithInt:',0x007360D0,'d131eaeb',0x007365C4,0x007365E0,0x007360F8,'c731eaeb',0x007365B0),
 ('Action','interactionItemSubIndex',0x007365F8,0x00F8CCE8,'OBJC_IVAR_$_Action.interactionItemSubIndex',22,
  'numberWithInt:',0x00736138,'b731eaeb',0x007365C4,0x007365E0,0x00736160,'ad31eaeb',0x007365B0),
 ('Action','interactionItemType',0x00736604,0x00F8CCF8,'OBJC_IVAR_$_Action.interactionItem',16,
  'numberWithInt:',0x007361BC,'9631eaeb',0x007365C4,0x007365E0,0x007361E4,'8c31eaeb',0x007365B0),
 ('Action','goalInteraction',0x0073660C,0x00F8CD08,'OBJC_IVAR_$_Action.goalInteraction',24,
  'numberWithInt:',0x00736220,'7d31eaeb',0x007365C4,0x007365E0,0x00736248,'7331eaeb',0x007365B0),
 ('Action','pathType',0x00736614,0x00F8CD18,'OBJC_IVAR_$_Action.pathType',28,
  'numberWithInt:',0x00736284,'6431eaeb',0x007365C4,0x007365E0,0x007362AC,'5a31eaeb',0x007365B0),
 ('Action','interactionObjectID',0x007365A8,0x00F8CD28,'OBJC_IVAR_$_Action.interactionObjectID',32,
  'numberWithUnsignedLong:',0x007362E8,'33ff2fe1',0x007365C4,0x007365B4,0x0073630C,'3cff2fe1',0x007365B0),
 ('Action','inventoryChange',0x0073661C,0x00F8CD68,'OBJC_IVAR_$_Action.inventoryChange',64,
  None,None,None,None,None,0x00736384,'3cff2fe1',0x007365B0),
 ('Action','craftableItemObject',0x00736628,0x00F8CD38,'OBJC_IVAR_$_Action.craftableItemObject',40,
  None,None,None,None,None,0x00736428,'3cff2fe1',0x007365B0),
 ('Action','craftCountOrExtraData',0x0073663C,0x00F8CD58,'OBJC_IVAR_$_Action.craftCountOrExtraData',44,
  'numberWithUnsignedInt:',0x00736510,'3aff2fe1',0x007365C4,0x00736640,0x00736534,'3cff2fe1',0x007365B0),
 ('Action','interactionTestResult',0x0073662C,0x00F8CD78,'OBJC_IVAR_$_Action.interactionTestResult',52,
  'dataWithBytes:length:',0x00736570,'34ff2fe1',0x00736638,0x00736630,0x00736594,'3cff2fe1',0x007365B0),
 ('Tree','height',0x004C4908,0x00F73588,'OBJC_IVAR_$_Tree.height',60,
  'numberWithInt:',0x004C3EEC,'33ff2fe1',0x004C48CC,0x004C48F4,0x004C3F10,'3cff2fe1',0x004C48C0),
 ('Tree','saveTime',0x004C48FC,0x00F73618,None,0,
  'numberWithDouble:',0x004C3F6C,'3cff2fe1',0x004C48CC,0x004C48D4,0x004C3F90,'3cff2fe1',0x004C48C0),
 ('Tree','treeSeasonOffset',0x004C48F0,0x00F73508,'OBJC_IVAR_$_Tree.treeSeasonOffset',84,
  'numberWithInt:',0x004C3FCC,'33ff2fe1',0x004C48CC,0x004C48F4,0x004C3FF0,'3cff2fe1',0x004C48C0),
 ('Tree','age',0x004C48E8,0x00F73598,'OBJC_IVAR_$_Tree.age',96,
  'numberWithFloat:',0x004C402C,'3eff2fe1',0x004C48CC,0x004C48C4,0x004C4050,'3cff2fe1',0x004C48C0),
 ('Tree','dead',0x004C48DC,0x00F73518,'OBJC_IVAR_$_Tree.dead',104,
  'numberWithBool:',0x004C408C,'33ff2fe1',0x004C48CC,0x004C48E0,0x004C40B0,'3cff2fe1',0x004C48C0),
 ('Tree','timeDied',0x004C48D0,0x00F73528,'OBJC_IVAR_$_Tree.timeDied',112,
  'numberWithDouble:',0x004C40EC,'3eff2fe1',0x004C48CC,0x004C48D4,0x004C4110,'3cff2fe1',0x004C48C0),
 ('Tree','removeCheckCount',0x004C48BC,0x00F73538,'OBJC_IVAR_$_Tree.removeCheckCount',120,
  'numberWithFloat:',0x004C414C,'3eff2fe1',0x004C48CC,0x004C48C4,0x004C4170,'3cff2fe1',0x004C48C0),
 ('Tree','treeFruit',0x004C4918,0x00F73548,None,0,
  None,None,None,None,None,0x004C44A4,'3cff2fe1',0x004C48C0),
 ('Tree','maxHeightGene',0x004C494C,0x00F735D8,'OBJC_IVAR_$_Tree.maxHeightGene',54,
  'numberWithInt:',0x004C4630,'33ff2fe1',0x004C48CC,0x004C48F4,0x004C4654,'3cff2fe1',0x004C48C0),
 ('Tree','growthRateGene',0x004C4944,0x00F735E8,'OBJC_IVAR_$_Tree.growthRateGene',56,
  'numberWithInt:',0x004C4690,'33ff2fe1',0x004C48CC,0x004C48F4,0x004C46B4,'3cff2fe1',0x004C48C0),
 ('Tree','maxHeightReached',0x004C493C,0x00F735F8,'OBJC_IVAR_$_Tree.maxHeightReached',64,
  'numberWithInt:',0x004C46F0,'33ff2fe1',0x004C48CC,0x004C48F4,0x004C4714,'3cff2fe1',0x004C48C0),
 ('Tree','growthCounter',0x004C4934,0x00F735A8,'OBJC_IVAR_$_Tree.growthCounter',68,
  'numberWithFloat:',0x004C4750,'3eff2fe1',0x004C48CC,0x004C48C4,0x004C4774,'3cff2fe1',0x004C48C0),
 ('Tree','growthRate',0x004C492C,0x00F735B8,'OBJC_IVAR_$_Tree.growthRate',72,
  'numberWithFloat:',0x004C47B0,'3eff2fe1',0x004C48CC,0x004C48C4,0x004C47D4,'3cff2fe1',0x004C48C0),
 ('Tree','maxHeight',0x004C4924,0x00F735C8,'OBJC_IVAR_$_Tree.maxHeight',88,
  'numberWithInt:',0x004C4810,'33ff2fe1',0x004C48CC,0x004C48F4,0x004C4834,'3cff2fe1',0x004C48C0),
 ('Tree','maxAge',0x004C491C,0x00F73608,'OBJC_IVAR_$_Tree.maxAge',92,
  'numberWithFloat:',0x004C4870,'3eff2fe1',0x004C48CC,0x004C48C4,0x004C4894,'3cff2fe1',0x004C48C0),
]

# which Tree keys are behind the isStaticTree gate (non-static only)
NON_STATIC_ONLY = {'maxHeightGene', 'growthRateGene', 'maxHeightReached',
                   'growthCounter', 'growthRate', 'maxHeight', 'maxAge'}

EXTRA_GATES = [
 ('Action', 'dictionary_call', 0x00735EE0, '4d32eaeb'),
 ('Action', 'inprogress_ldrsb', 0x00735F10, 'd020dce1'),
 ('Action', 'itemtype_msg', 0x0073619C, '9e31eaeb'),
 ('Action', 'inventory_guard_cmp', 0x00736328, '020050e1'),
 ('Action', 'inventory_guard_beq', 0x0073632C, '1500000a'),
 ('Action', 'nested_getsavedict_msg', 0x007363D0, '33ff2fe1'),
 ('Action', 'nested_guard_beq', 0x007363E4, '1000000a'),
 ('Action', 'craftraw_len_movw_0xc', 0x0073644C, '0ce000e3'),
 ('Action', 'craftcount_ldrsh', 0x007364CC, 'f000d0e1'),
 ('Tree', 'super_site', 0x004C3D00, '3cff2fe1'),
 ('Tree', 'age_vldr_s2', 0x004C4010, '001a93ed'),
 ('Tree', 'dead_ldrb', 0x004C4070, '0030d3e5'),
 ('Tree', 'dead_sxtb', 0x004C4084, '7320afe6'),
 ('Tree', 'timedied_vldr_d0', 0x004C40D0, '000b93ed'),
 ('Tree', 'worldtime_msg', 0x004C3F4C, '33ff2fe1'),
 ('Tree', 'fruit_array_create', 0x004C4190, '33ff2fe1'),
 ('Tree', 'fruit_dict_create', 0x004C42BC, '32ff2fe1'),
 ('Tree', 'fruit_pos_x_ldr', 0x004C42F4, '003093e5'),
 ('Tree', 'fruit_pos_y_ldr4', 0x004C4368, '043093e5'),
 ('Tree', 'fruit_hcfb_ldrb8', 0x004C43DC, '0830d3e5'),
 ('Tree', 'fruit_hcfb_sxtb', 0x004C43F0, '7320afe6'),
 ('Tree', 'fruit_addobject', 0x004C4440, '33ff2fe1'),
 ('Tree', 'isstatictree_msg', 0x004C44B8, '32ff2fe1'),
 ('Tree', 'isstatictree_sxtb', 0x004C44BC, '7000afe6'),
 ('Tree', 'isstatictree_bne', 0x004C44C4, 'f300001a'),
 ('Tree', 'gene_maxheight_ldrh', 0x004C45F0, 'b000d0e1'),
 ('Tree', 'gene_growthrate_ldrh', 0x004C4674, 'b030d3e1'),
 ('Tree', 'mhr_word_ldr', 0x004C46D4, '003093e5'),
 ('Tree', 'growthcounter_vldr', 0x004C4734, '000a93ed'),
 ('Tree', 'growthrate_vldr', 0x004C4794, '000a93ed'),
 ('Tree', 'maxage_vldr', 0x004C4854, '000a93ed'),
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
    # Tree super handling
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

    # Action own-dictionary handling (no super)
    for cls, od in OWN_DICT.items():
        imp, boundary = od['imp'], od['boundary']
        row = by_imp.get(imp)
        if row is None or row[1] != cls or row[3] != 'getSaveDict':
            raise ValueError(f'{cls}: method-map drift')
        if min(i for i in imps if i > imp) != boundary:
            raise ValueError(f'{cls}: boundary drift')
        if not word_eq(od['dictionary_call_site'], od['dictionary_call_word']):
            raise ValueError(f'{cls}: dictionary call word drift')
        if abs32.get(rebase(od['mutable_dict_classref_cell'])) != 'OBJC_CLASS_$_NSMutableDictionary' \
                or rw(rebase(od['mutable_dict_classref_cell'])) != 0:
            raise ValueError(f'{cls}: NSMutableDictionary classref drift')
        if cstr(rw(rebase(od['dictionary_selref_cell']))) != 'dictionary':
            raise ValueError(f'{cls}: dictionary selref drift')
        results[cls] = {'class': cls, 'imp': f'0x{imp:08x}',
                        'boundary': f'0x{boundary:08x}',
                        'code_words': (boundary - imp) // 4,
                        'style': 'own_dictionary_no_super',
                        'keys': []}

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
            if cls == 'Action' and key == 'inventoryChange':
                pass
            elif cls == 'Action' and key == 'craftableItemObject':
                entry['value_source'] = 'nested_getSaveDict'
            elif cls == 'Tree' and key == 'treeFruit':
                entry['value_source'] = 'fruit_dict_array'
        else:
            entry['conversion'] = conv
            entry['conversion_site'] = f'0x{cs:08x}'
            if isym is None:
                if key == 'saveTime':
                    entry['value_source'] = 'world_selector'
                elif cls == 'Action' and key == 'interactionItemType':
                    entry['value_source'] = 'computed_selector'
            if cls == 'Action' and key == 'craftCountOrExtraData':
                entry['value_source'] = 'signed_halfword'
            if cls == 'Action' and key == 'interactionItemType':
                entry['value_source'] = 'computed_selector'
            if cls == 'Action' and key == 'interactionTestResult':
                entry['value_source'] = 'raw_buffer'
                entry['raw_length'] = 0xc
            if cw is not None:
                if not word_eq(cs, cw):
                    raise ValueError(f'{cls}.{key}: conv word drift')
            if cstr(rw(rebase(csr))) != conv:
                raise ValueError(f'{cls}.{key}: conv selref drift')
            if abs32.get(rebase(ncell)) != 'OBJC_CLASS_$_NSNumber' or rw(rebase(ncell)) != 0:
                if conv != 'dataWithBytes:length:':
                    raise ValueError(f'{cls}.{key}: NSNumber classref drift')
        if cls == 'Tree' and key in NON_STATIC_ONLY:
            entry['gated_by'] = 'isStaticTree==false'
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
        'method': 'getSaveDict key pairings (batch 2o)',
        'classes': [results[c] for c in ('Action', 'Tree')],
        'claim': ('Action is the first override that builds its OWN '
                  '[NSMutableDictionary dictionary] with no super chain, '
                  'saving 15 keys including the ldrsh-signed-halfword '
                  'boxed unsigned craftCountOrExtraData, the 12-byte '
                  'UNGUARDED NSData raw buffer interactionTestResult, '
                  'the computed interactionItemType selector value, and '
                  'the first NESTED [ivar getSaveDict] entity save '
                  '(craftableItemObject); Tree chains super then saves '
                  'height/saveTime(worldTime double)/treeSeasonOffset/'
                  'age/dead/timeDied(first OWN-IVAR double via vldr d0)/'
                  'removeCheckCount/treeFruit (per-fruit dictionaries '
                  'pos.x/pos.y/hasCreatedFreeBlockThisSeason built from '
                  'the treeFruits@124 C-array loop), and gates the '
                  'seven growth keys behind isStaticTree==false '
                  '(maxHeightGene/growthRateGene halfwords, '
                  'maxHeightReached/growthCounter/growthRate/maxHeight/'
                  'maxAge); 1 override remains (Workbench 1232w), '
                  'read-back/roundtrip unresolved'),
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument('elf', type=Path)
    p.add_argument('--check', action='store_true')
    p.add_argument('--output', type=Path, default=NATIVE / 'subclass_savedict_keys_b2o.json')
    a = p.parse_args()
    text = json.dumps(recover(a.elf), indent=2, sort_keys=True) + '\n'
    if a.check:
        if a.output.read_text() != text:
            raise SystemExit('stale subclass_savedict_keys_b2o.json')
    else:
        a.output.write_text(text)
    print('b2o classes=2 keys=29')


if __name__ == '__main__':
    main()
