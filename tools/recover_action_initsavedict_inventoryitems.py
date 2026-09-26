#!/usr/bin/env python3
"""Hash-gated read-back evidence for batch b3d: `-[Action
initWithSaveDict:inventoryItems:]` 0x00735198 (815 w, boundary 0x00735e54)
— the action/command deserialiser that consumes the inventory array, the
nested craftable-item dictionary and the interaction target records.

Shape decoded from the instruction stream:

  self = [super init]; if (!self) return nil;            (super2 → Action)
  inProgress@4          objectForKey → boolValue  → strb
  isAI@6                objectForKey → boolValue  → strb
  goalTilePos.x@8/y@12  objectForKey → intValue   → str / str [r1,#4]
  interactionItemIndex@20      objectForKey → intValue → strh
  interactionItemSubIndex@22   objectForKey → intValue → strh
  interactionItemType          objectForKey → intValue → local (compare only)
  animationTimer@68      CONSTANT 1.0f (vldr/vstr from a literal), not a key
  interactionItem@16     explicit nil reset

  INVENTORY WALK (only when interactionItemIndex@20 > 0):
    item = [inventoryItems objectAtIndex:interactionItemIndex]   (arg 3)
    if ([item count] == 0) skip
    element = [item objectAtIndex:([item count] - 1)]
    interactionItem@16 = element
    if ([element count] == 0) skip
    if (interactionItemSubIndex@22 == -1) skip
    sub = [element subItems]                                     (selector subItems)
    subElement = [sub objectAtIndex:interactionItemSubIndex@22]
    interactionItem@16 = subElement
    element2 = [subElement objectAtIndex:([subElement count] - 1)]
    interactionItem@16 = element2
    if ([element2 itemType] != interactionItemType-from-dict):
        interactionItem@16 = nil; interactionItemIndex@20 = -1;
        interactionItemSubIndex@22 = -1        (type-mismatch reset)

  [self->interactionItem retain]                          (0x7358ec)
  goalInteraction@24         objectForKey → intValue  → str
  pathType@28                objectForKey → intValue  → str
  interactionObjectID@32     objectForKey → unsignedLongValue → 64-bit store
                             (str r0,[r1,r2]! + str #0,[r1,#4] high word)
  craftableItemObject        objectForKey (nested dictionary)
    if nil → skip construction
    craftableObjectType = [[saveDict objectForKey:@"craftableObjectType"] intValue]
      1 → [[BlockheadCraftableItemObject alloc] initWithSaveDict:dict] → @40
      2 → [[PaintingCraftableItemObject alloc] initWithSaveDict:dict] → @40
      else → [[CraftableItemObject alloc] initWithSaveDict:dict]     → @40
      (links to batch b3c: the b3c initialisers consume exactly this dict)
  craftCountOrExtraData@44   objectForKey → intValue → strh
  inventoryChange@64         objectForKey → retain   → str
  interactionTestResult@52   objectForKey → getBytes:length: 12 (0xc) inline record

Static level-A evidence only: no runtime roundtrip, and the interaction
record layout inside the walked arrays is established by the ivar stores
above, not by executing the game.
"""
import argparse
import copy
import hashlib
import io
import json
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
from trace_objc_dispatch import ELFMemory  # noqa: E402

ROOT = TOOLS.parent
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
BASE = 0x0105FAF4
GOT_MSGSEND = 0x0105B7A0
GOT_SUPER2 = 0x0105B79C
MSGSEND_VENEER = 0x001C281C

CLASS = 'Action'
IMP = 0x00735198
BOUNDARY = 0x00735E54
SUPERREF_SLOT = 0x00E8BD04
SUPER_CLASS_OBJECT = 0x00E90DA0

# key -> CFString object slot
KEY_CELLS = {
    'inProgress': 0x00F8CC98, 'isAI': 0x00F8CCA8,
    'goalTilePos.x': 0x00F8CCB8, 'goalTilePos.y': 0x00F8CCC8,
    'interactionItemIndex': 0x00F8CCD8,
    'interactionItemSubIndex': 0x00F8CCE8,
    'interactionItemType': 0x00F8CCF8, 'goalInteraction': 0x00F8CD08,
    'pathType': 0x00F8CD18, 'interactionObjectID': 0x00F8CD28,
    'craftableItemObject': 0x00F8CD38, 'craftableObjectType': 0x00F8CD48,
    'craftCountOrExtraData': 0x00F8CD58, 'inventoryChange': 0x00F8CD68,
    'interactionTestResult': 0x00F8CD78,
}

IVAR_OFFSETS = {
    'inProgress': 4, 'isAI': 6, 'goalTilePos': 8,
    'interactionItem': 16, 'interactionItemIndex': 20,
    'interactionItemSubIndex': 22, 'goalInteraction': 24, 'pathType': 28,
    'interactionObjectID': 32, 'craftableItemObject': 40,
    'craftCountOrExtraData': 44, 'interactionTestResult': 52,
    'inventoryChange': 64, 'animationTimer': 68,
}

# key -> (conv, ofk, ofk_w, conv_site, conv_w, store, store_w, kind, ivar, offset)
CHAINS = [
    ('inProgress', 'boolValue', 0x73536C, 'e12fff38', 0x73537C, 'e12fff32',
     0x735390, 'e5c10000', 'byte_store', 'inProgress', 4),
    ('isAI', 'boolValue', 0x7353A8, 'e12fff33', 0x7353B8, 'e12fff32',
     0x7353CC, 'e5c10000', 'byte_store', 'isAI', 6),
    ('goalTilePos.x', 'intValue', 0x7353E4, 'e12fff33', 0x7353F4, 'e12fff32',
     0x735408, 'e5810000', 'word_store', 'goalTilePos', 8),
    ('goalTilePos.y', 'intValue', 0x735420, 'e12fff33', 0x735430, 'e12fff32',
     0x735444, 'e5810004', 'word_store_pair', 'goalTilePos', 12),
    ('interactionItemIndex', 'intValue', 0x73545C, 'e12fff33', 0x73546C,
     'e12fff32', 0x735480, 'e1c100b0', 'halfword_store',
     'interactionItemIndex', 20),
    ('interactionItemSubIndex', 'intValue', 0x735498, 'e12fff33', 0x7354A8,
     'e12fff32', 0x7354BC, 'e1c100b0', 'halfword_store',
     'interactionItemSubIndex', 22),
    ('goalInteraction', 'intValue', 0x73591C, 'ebea33be', 0x735934,
     'ebea33b8', 0x73594C, 'e7810002', 'word_store', 'goalInteraction', 24),
    ('pathType', 'intValue', 0x735964, 'ebea33ac', 0x735974, 'ebea33a8',
     0x73598C, 'e7810002', 'word_store', 'pathType', 28),
    ('interactionObjectID', 'unsignedLongValue', 0x7359A4, 'ebea339c',
     0x7359B4, 'ebea3398', 0x7359CC, 'e7a10002', 'word_store_hi_zero',
     'interactionObjectID', 32),
    ('craftCountOrExtraData', 'intValue', 0x735CC4, 'e12fff35', 0x735CD4,
     'e12fff32', 0x735CE8, 'e1c100b0', 'halfword_store',
     'craftCountOrExtraData', 44),
    ('inventoryChange', 'retain', 0x735D00, 'e12fff33', 0x735D10, 'e12fff32',
     0x735D24, 'e5810000', 'word_store', 'inventoryChange', 64),
    ('interactionTestResult', 'getBytes:length:', 0x735D3C, 'e12fff33',
     0x735D74, 'e12fff3c', 0x735D74, 'e12fff3c', 'blob_store',
     'interactionTestResult', 52),
]
# keys captured into a local instead of an ivar (compared later)
LOCAL_KEYS = {
    'interactionItemType': (0x7354D4, 'e12fff33', 0x7354E4, 'e12fff32',
                            0x7354E8, 'e50b003c'),
    'craftableObjectType': (0x735A4C, 'e12fff3c', 0x735A5C, 'e12fff32',
                            0x735A60, 'e50b004c'),
}
# keys consumed as objects (no conversion)
OBJECT_KEYS = {
    'craftableItemObject': (0x7359EC, 'e12fff3c', 0x7359FC, 'e1500001'),
}

GATES = [
    ('super_call', 0x7351F4, 'e12fff34'),
    ('nil_cmp', 0x73520C, 'e1510000'),
    ('nil_bne', 0x735210, '1a000002'),
    ('nil_return_branch', 0x73521C, 'ea0002d7'),
    ('animation_const_vmov', 0x73523C, 'eeb70a00'),
    ('animation_store', 0x735500, 'ed800a00'),
    ('interactionitem_nil_reset', 0x735518, 'e5803000'),
    ('index_positive_cmp', 0x735530, 'e3500000'),
    ('index_positive_ble_skip', 0x735534, 'da0000d4'),
    ('walk_objectatindex_call', 0x735590, 'e12fff3c'),
    ('walk_count_call', 0x7355A8, 'e12fff32'),
    ('walk_count_zero_bls', 0x7355B0, '9a0000b4'),
    ('walk_count_minus_one', 0x73561C, 'e2402001'),
    ('walk_last_element_call', 0x735618, 'e12fff32'),
    ('walk_store_interactionitem', 0x735648, 'e5810000'),
    ('element_count_call', 0x735668, 'e12fff33'),
    ('element_count_zero_bls', 0x735680, '9a00007f'),
    ('subindex_cmn_m1', 0x7356A0, 'e3700001'),
    ('subindex_m1_beq_skip', 0x7356A4, '0a000076'),
    ('subitems_call', 0x735718, 'e12fff35'),
    ('subitems_objectatindex_call', 0x73573C, 'e12fff33'),
    ('subitem_count_zero_cmp', 0x735758, 'e3500000'),
    ('subitem_count_call', 0x7357B8, 'e12fff32'),
    ('subitem_count_minus_one', 0x7357BC, 'e2402001'),
    ('subitem_last_call', 0x7357D4, 'e12fff33'),
    ('subitem_last_store', 0x7357E8, 'e5810000'),
    ('itemtype_call', 0x735818, 'e12fff3c'),
    ('itemtype_cmp', 0x735820, 'e1510000'),
    ('itemtype_match_beq', 0x735824, '0a000014'),
    ('mismatch_movw_ffff', 0x735828, 'e30f0fff'),
    ('mismatch_item_nil', 0x735858, 'e58ec000'),
    ('mismatch_subindex_store', 0x735868, 'e1c300b0'),
    ('mismatch_index_store', 0x735878, 'e1c100b0'),
    ('retain_interactionitem_veneer', 0x7358EC, 'ebea33ca'),
    ('interactionobjectid_highword_zero', 0x7359D4, 'e5810004'),
    ('craftable_nil_cmp', 0x7359FC, 'e1500001'),
    ('craftable_nil_beq_skip', 0x735A00, '0a000078'),
    ('type_eq1_cmp', 0x735A68, 'e3500001'),
    ('type_eq1_bne', 0x735A6C, '1a00001d'),
    ('alloc_call_class1', 0x735AB8, 'e12fff32'),
    ('init_call_class1', 0x735ACC, 'e12fff33'),
    ('store_class1', 0x735AE0, 'e5810000'),
    ('type_eq2_cmp', 0x735AEC, 'e3500002'),
    ('type_eq2_bne', 0x735AF0, '1a00001d'),
    ('alloc_call_class2', 0x735B3C, 'e12fff32'),
    ('init_call_class2', 0x735B50, 'e12fff33'),
    ('store_class2', 0x735B64, 'e5810000'),
    ('alloc_call_default', 0x735BB4, 'e12fff32'),
    ('init_call_default', 0x735BC8, 'e12fff33'),
    ('store_default', 0x735BDC, 'e5810000'),
    ('interactiontestresult_len_movw_12', 0x735BE8, 'e300300c'),
    ('interactiontestresult_getbytes', 0x735D74, 'e12fff3c'),
    ('return_self_load', 0x735D78, 'e51b0024'),
]
CRAFT_DISPATCH = [
    (1, 0x00E8A544, 0x00E91228, 'OBJC_CLASS_$_BlockheadCraftableItemObject'),
    (2, 0x00E8A548, 0x00E90E18, 'OBJC_CLASS_$_PaintingCraftableItemObject'),
    (None, 0x00E8A54C, 0x00E91CC8, 'OBJC_CLASS_$_CraftableItemObject'),
]

EXPECTED_SELREFS = {
    'init', 'objectForKey:', 'boolValue', 'intValue', 'count',
    'objectAtIndex:', 'subItems', 'itemType', 'unsignedLongValue', 'retain',
    'initWithSaveDict:', 'alloc', 'getBytes:length:',
}

FORBIDDEN_KEYS = {'craftableItem', 'imageData', 'outputImageData',
                  'skinOptions', 'name', 'saveTime'}


def signed(v):
    return v - (1 << 32) if v & 0x80000000 else v


class ELF:
    def __init__(self, path):
        self.raw = path.read_bytes()
        if hashlib.sha256(self.raw).hexdigest() != SHA:
            raise ValueError('original ELF SHA mismatch')
        self.m = ELFMemory(path)
        self.elf = ELFFile(io.BytesIO(self.raw))
        self.rel = {}
        for s in self.elf.iter_sections():
            if isinstance(s, RelocationSection):
                syms = self.elf.get_section(s['sh_link'])
                for r in s.iter_relocations():
                    self.rel.setdefault(r['r_offset'], []).append(
                        (r['r_info_type'],
                         syms.get_symbol(r['r_info_sym']).name
                         if r['r_info_sym'] else ''))
        self.ivar_slots, self.classes = {}, {}
        for s in self.elf.get_section_by_name('.dynsym').iter_symbols():
            if not s['st_value']:
                continue
            if s.name.startswith('OBJC_IVAR_$_'):
                self.ivar_slots[s['st_value']] = (s.name, self.rw(s['st_value']))
            elif s.name.startswith('OBJC_CLASS_$_'):
                self.classes[s['st_value']] = s.name
        tsv = (NATIVE / 'libApplication_objc_methods.tsv').read_text().splitlines()[1:]
        self.imps = sorted(int(l.split('\t')[0], 16) for l in tsv)
        self.rows = {int(l.split('\t')[0], 16): l.split('\t') for l in tsv}

    def rw(self, a, n=4):
        off = self.m.offset(a, n)
        return None if off is None else int.from_bytes(self.m.data[off:off + n],
                                                       'little')

    def cstr(self, a):
        off = self.m.offset(a, 1)
        if off is None:
            return None
        e = self.m.data.find(b'\0', off, off + 128)
        return self.m.data[off:e].decode('ascii', 'replace') if e > 0 else None

    def word_eq(self, a, wh):
        return f'{(self.rw(a) or 0):08x}' == wh

    def offset_of(self, vaddr):
        off = self.m.offset(vaddr, 1)
        if off is None:
            raise ValueError(f'unmapped vaddr 0x{vaddr:08x}')
        return off

    def mutate(self, vaddr, new_bytes):
        clone = copy.copy(self)
        clone.m = copy.copy(self.m)
        data = bytearray(self.m.data)
        off = self.offset_of(vaddr)
        data[off:off + len(new_bytes)] = new_bytes
        clone.m.data = bytes(data)
        return clone

    def slot_of_ivar(self, name):
        for a, v in self.ivar_slots.items():
            if v[0] == name:
                return a
        raise ValueError(f'ivar symbol missing: {name}')

    def literal_cells(self, lo, hi):
        keys, selrefs, ivars, classes, got = {}, {}, {}, {}, {}
        for a in range(lo, hi, 4):
            w = self.rw(a) or 0
            if w & 0x0FFF0000 != 0x059F0000 or (w >> 12) & 0xF == 15:
                continue
            lit = (a + 8 + (w & 0xFFF)) & 0xFFFFFFFF
            t = (BASE + signed(self.rw(lit) or 0)) & 0xFFFFFFFF
            imp = self.m.imports.get(t)
            if imp:
                got[lit] = (t, imp)
                continue
            rel_t = self.rel.get(t, [])
            owned = [n for ty, n in rel_t
                     if ty == 2 and n.startswith('OBJC_IVAR_$_')]
            if owned:
                ivars[lit] = (t, owned[0], self.rw(t))
                continue
            if any(ty == 21 for ty, _ in rel_t):
                got[lit] = (t, [n for ty, n in rel_t if ty == 21][0])
                continue
            if any(n == '__CFConstantStringClassReference' for _, n in rel_t):
                data = self.rw(t + 8)
                keys[lit] = (t, self.cstr(data) if data else None,
                             self.rw(t + 12))
                continue
            wv = self.rw(t)
            if wv is not None and wv in self.ivar_slots:
                ivars[lit] = (t, self.ivar_slots[wv][0], self.rw(wv))
                continue
            if wv is not None and wv in self.classes:
                classes[lit] = (t, self.classes[wv])
                continue
            if wv is not None and self.m.selectors.get(wv):
                selrefs[lit] = (t, self.m.selectors[wv])
        return {'keys': keys, 'selrefs': selrefs, 'ivars': ivars,
                'classes': classes, 'got': got}


def arm_imm(w):
    imm12 = w & 0xFFF
    rot = (imm12 >> 8) * 2
    v = imm12 & 0xFF
    if rot:
        v = ((v >> rot) | (v << (32 - rot))) & 0xFFFFFFFF
    return v


def veneer_ok(elf):
    """0x1c281c is the objc_msgSend PIC veneer:
       add ip, pc, #imm1 / add ip, ip, #imm2 / ldr pc, [ip, #imm3]!
    The final slot must be an imported objc_msgSend GOT word."""
    w0 = elf.rw(MSGSEND_VENEER) or 0
    w1 = elf.rw(MSGSEND_VENEER + 4) or 0
    w2 = elf.rw(MSGSEND_VENEER + 8) or 0
    if w0 & 0x0FFF0000 != 0x028F0000 or (w0 >> 12) & 0xF != 12:
        raise ValueError('msgSend veneer prologue drift')
    if w1 & 0x0FFF0000 != 0x028C0000 or (w1 >> 12) & 0xF != 12:
        raise ValueError('msgSend veneer body drift')
    if w2 & 0x0FFF0000 != 0x05BC0000 or (w2 >> 12) & 0xF != 15:
        raise ValueError('msgSend veneer jump drift')
    ip = (MSGSEND_VENEER + 8 + arm_imm(w0) + arm_imm(w1)) & 0xFFFFFFFF
    # ldr/str immediates are plain 12-bit offsets (no rotated-immediate form)
    slot = (ip + (w2 & 0xFFF)) & 0xFFFFFFFF
    if elf.m.imports.get(slot) != 'objc_msgSend':
        raise ValueError(f'msgSend veneer target drift 0x{slot:08x}')
    return {'veneer': f'0x{MSGSEND_VENEER:08x}',
            'veneer_slot': f'0x{slot:08x}',
            'veneer_target': 'objc_msgSend'}


def recover(elf):
    row = elf.rows.get(IMP)
    if row is None or row[1] != CLASS or row[3] != 'initWithSaveDict:inventoryItems:':
        raise ValueError('Action: method-map drift')
    if min(i for i in elf.imps if i > IMP) != BOUNDARY:
        raise ValueError('Action: boundary drift')
    cells = elf.literal_cells(IMP, BOUNDARY)

    # ---- CFString pool: exact set equality (+ forbidden keys)
    found = {k: lit for lit, (t, k, ln) in cells['keys'].items() if k}
    if set(found) != set(KEY_CELLS):
        raise ValueError(f'Action: key set drift {set(found) ^ set(KEY_CELLS)}')
    for lit, (t, k, ln) in cells['keys'].items():
        if k is None or ln != len(k.encode()):
            raise ValueError(f'Action: CFString payload drift at 0x{lit:08x}')
    pools = {}
    for k, want in KEY_CELLS.items():
        t = cells['keys'][found[k]][0]
        if t != want:
            raise ValueError(f'Action: {k} cell drift 0x{t:08x} != 0x{want:08x}')
        pools[k] = f'0x{t:08x}'
    for forbidden in FORBIDDEN_KEYS & set(found):
        raise ValueError(f'Action: forbidden key read back: {forbidden}')

    # ---- super init + nil guard
    rel_cell = elf.rel.get(SUPERREF_SLOT, [])
    if not any(ty == 23 for ty, _ in rel_cell):
        raise ValueError('Action: superref slot lacks R_ARM_RELATIVE')
    target = elf.rw(SUPERREF_SLOT) or 0
    if target != SUPER_CLASS_OBJECT or elf.classes.get(target) != 'OBJC_CLASS_$_Action':
        raise ValueError('Action: superref target drift')
    if elf.m.imports.get(GOT_SUPER2) != 'objc_msgSendSuper2':
        raise ValueError('Action: msgSendSuper2 GOT drift')

    # ---- key chains
    chains = []
    for (key, conv, ofk, ofk_w, cs, cs_w, store, store_w, kind, ivar,
         off) in CHAINS:
        for site, want, what in ((ofk, ofk_w, 'objectForKey'),
                                 (cs, cs_w, 'conversion'),
                                 (store, store_w, 'store')):
            if not elf.word_eq(site, want):
                raise ValueError(f'Action.{key}: {what} word drift @0x{site:08x}')
        if not (IMP <= ofk < cs <= store < BOUNDARY):
            raise ValueError(f'Action.{key}: site order drift')
        if (elf.rw(elf.slot_of_ivar(f'OBJC_IVAR_$_{CLASS}.{ivar}')) or -1) != \
                IVAR_OFFSETS[ivar]:
            raise ValueError(f'Action.{key}: ivar offset drift')
        chains.append({'key': key, 'conversion': conv,
                       'cfstring_object': pools[key],
                       'objectforkey_site': f'0x{ofk:08x}',
                       'conversion_site': f'0x{cs:08x}',
                       'ivar': f'OBJC_IVAR_$_{CLASS}.{ivar}',
                       'ivar_offset': IVAR_OFFSETS[ivar],
                       'store_offset': off,
                       'store_site': f'0x{store:08x}', 'store_kind': kind})
    locals_out = []
    for key, (ofk, ofk_w, cs, cs_w, store, store_w) in LOCAL_KEYS.items():
        for site, want, what in ((ofk, ofk_w, 'objectForKey'),
                                 (cs, cs_w, 'conversion'),
                                 (store, store_w, 'local store')):
            if not elf.word_eq(site, want):
                raise ValueError(f'Action.{key}: {what} word drift @0x{site:08x}')
        locals_out.append({'key': key, 'objectforkey_site': f'0x{ofk:08x}',
                           'conversion_site': f'0x{cs:08x}',
                           'cfstring_object': pools[key],
                           'stored_to': f'0x{store:08x}',
                           'note': 'captured into a stack local, compared later '
                                   '(interactionItemType: item type match; '
                                   'craftableObjectType: class dispatch)'})
    objects_out = []
    for key, (ofk, ofk_w, cmp_site, cmp_w) in OBJECT_KEYS.items():
        if not elf.word_eq(ofk, ofk_w) or not elf.word_eq(cmp_site, cmp_w):
            raise ValueError(f'Action.{key}: site word drift')
        objects_out.append({'key': key, 'objectforkey_site': f'0x{ofk:08x}',
                            'nil_cmp_site': f'0x{cmp_site:08x}',
                            'cfstring_object': pools[key],
                            'consumed_by': 'alloc + initWithSaveDict: of the '
                                           'class selected by craftableObjectType'})

    # ---- structural gates
    for name, site, wh in GATES:
        if not elf.word_eq(site, wh):
            raise ValueError(f'Action gate {name} drift @0x{site:08x}')

    # ---- craftable-class dispatch
    dispatch = []
    for tag, slot, obj, name in CRAFT_DISPATCH:
        rel_slot = elf.rel.get(slot, [])
        if not any(ty == 23 for ty, _ in rel_slot):
            raise ValueError(f'Action: dispatch slot 0x{slot:08x} lacks '
                             'R_ARM_RELATIVE')
        got_obj = elf.rw(slot) or 0
        if got_obj != obj or elf.classes.get(got_obj) != name:
            raise ValueError(f'Action: dispatch slot 0x{slot:08x} drift '
                             f'{elf.classes.get(got_obj)}')
        dispatch.append({'craftableObjectType': tag, 'classref_slot':
                         f'0x{slot:08x}', 'class_object': name,
                         'instance_size':
                         elf.rw((elf.rw(got_obj + 16) or 0) + 8) or 0})

    # ---- ivar slot census
    ivar_found = {n.split('.', 1)[1]: off
                  for _, (t, n, off) in cells['ivars'].items()}
    for name, want in IVAR_OFFSETS.items():
        if (elf.rw(elf.slot_of_ivar(f'OBJC_IVAR_$_{CLASS}.{name}')) or -1) != want:
            raise ValueError(f'Action: {name} offset drift')
    if ivar_found != IVAR_OFFSETS:
        raise ValueError(f'Action: ivar-slot drift {ivar_found}')
    sels = {n for _, n in cells['selrefs'].values()}
    if sels != EXPECTED_SELREFS:
        raise ValueError(f'Action: selref drift {sels ^ EXPECTED_SELREFS}')

    ven = veneer_ok(elf)

    # ---- save-side cross reference
    save_src = 'subclass_savedict_keys_b2o.json'
    b2o = json.loads((NATIVE / save_src).read_text())
    action_save = []
    def walk(o):
        if isinstance(o, dict):
            if o.get('class') == 'Action':
                yield o
            for v in o.values():
                yield from walk(v)
        elif isinstance(o, list):
            for v in o:
                yield from walk(v)
    for e in walk(b2o):
        action_save = e.get('keys') or []
    write_set = {k['key'] for k in action_save}
    read_set = set(pools)

    return {
        'schema': 1, 'batch': 'b3d', 'elf_sha256': SHA,
        'pic_base': f'0x{BASE:08x}',
        'method': 'Action initWithSaveDict:inventoryItems: read-back evidence '
                  '(batch b3d)',
        'class': CLASS, 'imp': f'0x{IMP:08x}', 'boundary': f'0x{BOUNDARY:08x}',
        'code_words': (BOUNDARY - IMP) // 4,
        'selector': 'initWithSaveDict:inventoryItems:',
        'super_init': {'selector': 'init',
                       'superref_slot': f'0x{SUPERREF_SLOT:08x}',
                       'class_object': 'OBJC_CLASS_$_Action',
                       'got_slot': f'0x{GOT_SUPER2:08x}',
                       'call_site': '0x007351f4'},
        'keys': chains, 'local_keys': locals_out, 'object_keys': objects_out,
        'inventory_walk': {
            'entry_gate': 'interactionItemIndex@20 > 0 (cmp/ble 0x735534)',
            'array_argument': 'arg3 inventoryItems',
            'call_sites': ['0x735590 objectAtIndex: (index)',
                           '0x7355a8 count', '0x735618 objectAtIndex:(count-1)',
                           '0x735668 count', '0x735718 subItems',
                           '0x73573c objectAtIndex:(subIndex)',
                           '0x7357b8 count', '0x7357d4 objectAtIndex:(count-1)',
                           '0x735818 itemType'],
            'stores_to_interactionItem': ['0x735648', '0x735758', '0x7357e8'],
            'type_mismatch_reset': {
                'compare': '0x735820 (itemType vs dict interactionItemType)',
                'equal_branch': '0x735824 (keep)',
                'mismatch_sets': {'interactionItem@16': 'nil (0x735858)',
                                  'interactionItemIndex@20': '-1 (0x735878)',
                                  'interactionItemSubIndex@22': '-1 (0x735868)'},
            },
        },
        'constants': {
            'animationTimer@68': '1.0f literal (vmov.f32 0x73523c → vstr 0x735500)',
            'interactionItem@16': 'explicit nil reset (0x735518)',
            'interactionObjectID@32': '64-bit store, high word zeroed (0x7359cc + 0x7359d4)',
            'interactionTestResult@52': 'inline record, getBytes:length: 12 (0x735be8)',
        },
        'craftable_dispatch': dispatch,
        'retain_sites': {'interactionItem@16': '0x7358ec',
                         'inventoryChange@64': '0x735d10'},
        'msgSend_veneer': ven,
        'pool_keys': sorted(pools), 'pool_key_cells': pools,
        'selrefs': sorted(sels),
        'save_side': {'source': save_src,
                      'keys': sorted(write_set),
                      'write_only': sorted(write_set - read_set),
                      'read_only': sorted(read_set - write_set)},
        'claim': (
            'Action -[initWithSaveDict:inventoryItems:] (815 w) calls '
            '[super init] through its own-class superref, returns nil when '
            'that fails, restores 12 scalar/object keys through '
            'objectForKey: + boolValue/intValue/unsignedLongValue/retain/'
            'getBytes:length:, keeps interactionItemType and '
            'craftableObjectType in locals, and when '
            'interactionItemIndex > 0 walks the inventoryItems argument '
            '(objectAtIndex: → count-1 last element → subItems → '
            'subItemIndex → last element → itemType) storing the found '
            'record into interactionItem@16, resetting '
            'interactionItem/interactionItemIndex/interactionItemSubIndex to '
            'nil/-1/-1 on a type mismatch, then builds craftableItemObject@40 '
            'by dispatching craftableObjectType 1/2/other to '
            'BlockheadCraftableItemObject / PaintingCraftableItemObject / '
            'CraftableItemObject alloc + initWithSaveDict: (the b3c '
            'initialisers consume exactly that nested dictionary); '
            'animationTimer@68 is a 1.0f constant and '
            'interactionTestResult@52 a 12-byte inline record; static '
            'level-A only, no runtime roundtrip'),
    }


MUTATIONS = [
    ('action_goal_y_store_offset', 0x735444, bytes.fromhex('e5810000'),
     'goalTilePos.y: store word drift'),
    ('action_index_halfword_store', 0x735480, bytes.fromhex('e5810000'),
     'interactionItemIndex: store word drift'),
    ('action_interactionobjectid_high_zero', 0x7359D4,
     bytes.fromhex('e5810008'), 'interactionobjectid_highword_zero drift'),
    ('action_itemtype_cmp_site', 0x735820, bytes.fromhex('e1510001'),
     'itemtype_cmp drift'),
    ('action_mismatch_movw', 0x735828, bytes.fromhex('e30f0ffe'),
     'mismatch_movw_ffff drift'),
    ('action_dispatch_slot1_target', 0x00E8A544, bytes.fromhex('18 0e e9 00'.replace(' ', '')),
     'dispatch slot 0x00e8a544 drift'),
    ('action_dispatch_eq2_cmp', 0x735AEC, bytes.fromhex('e3500003'),
     'type_eq2_cmp drift'),
    ('action_testresult_length', 0x735BE8, bytes.fromhex('e300300d'),
     'interactiontestresult_len_movw_12 drift'),
    ('action_veneer_immediate', 0x001C2820, bytes.fromhex('9dca8de2'),
     'msgSend veneer body drift'),
    ('action_inventorychange_ivar', 'ivar:OBJC_IVAR_$_Action.inventoryChange',
     bytes.fromhex('48000000'), 'offset drift'),
    ('action_craftable_key_cell', 0x735DF0, bytes.fromhex('40d2f2ff'),
     'key set drift'),
    ('action_superref_target', 0x00E8BD04, bytes.fromhex('00000000'),
     'superref target drift'),
]


def resolve_target(elf, target):
    if isinstance(target, int):
        return target
    if isinstance(target, str) and target.startswith('ivar:'):
        return elf.slot_of_ivar(target[len('ivar:'):])
    raise ValueError(f'unresolvable mutation target {target!r}')


def self_test(elf):
    failures = []
    for name, target, patch, expect in MUTATIONS:
        try:
            recover(elf.mutate(resolve_target(elf, target), patch))
        except ValueError as exc:
            if expect not in str(exc):
                failures.append(f'{name}: wrong failure: {exc}')
        except Exception as exc:  # noqa: BLE001
            failures.append(f'{name}: unexpected {type(exc).__name__}: {exc}')
        else:
            failures.append(f'{name}: mutation was NOT detected')
    if failures:
        for f in failures:
            print('MUTATION FAIL:', f)
        raise SystemExit(f'{len(failures)}/{len(MUTATIONS)} negative controls failed')
    print(f'b3d self-test: {len(MUTATIONS)}/{len(MUTATIONS)} mutations detected')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--output', type=Path,
                    default=NATIVE / 'action_initsavedict_inventoryitems.json')
    a = ap.parse_args()
    elf = ELF(a.elf)
    if a.self_test:
        self_test(elf)
        return
    text = json.dumps(recover(elf), indent=2, sort_keys=True) + '\n'
    if a.check:
        if a.output.read_text() != text:
            raise SystemExit(f'stale {a.output.name}')
    else:
        a.output.write_text(text)
    print('b3d Action chains=12 locals=2 objects=1 dispatch=3')


if __name__ == '__main__':
    main()
