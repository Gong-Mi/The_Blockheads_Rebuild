#!/usr/bin/env python3
"""Hash-gated read-back evidence for batch b3m-2: the CHEST loader
`-[Chest initWithWorld:dynamicWorld:saveDict:cache:]` 0x00cb627c (760
words, exact variant) — the save-system centerpiece, closeout series part
2 of 3.

Decoded structure (pool + branch skeleton + helper disasm):

  * super-forward to InteractionObject (nil guard → nil), then own reads:
      chestType        → intValue  → Chest.chestType
      safeClientID     → (retain)  → DynamicObject.ownerID
      saveItemSlots    → NSNumber; count → per-slot enumeration
      shelfItemDataBs_%d  (formatted, via stringWithFormat:)
      shelfRenderItems_%d (formatted)
  * SLOT CAPACITY RULE (decoded from the private helper at 0x00cb623c,
    called 4x inside the body BEFORE the loops):
        numberOfSlots = (chestType == 2 || chestType == 5) ? 4 : 16
    — i.e. chest types 2 and 5 are 4-slot chests, everything else 16 slots.
  * per-slot loop: for each slot index, read shelfItemDataBs_%d /
      shelfRenderItems_%d from the save dict; construct InventoryItem
      children via alloc + [InventoryItem initWithSaveData:] (classrefs:
      InventoryItem, NSMutableArray, NSString) and addObject: into
      Chest.inventoryItems / shelfItemDataBs / shelfRenderItems arrays
      (initWithCapacity: driven by the capacity rule above).
  * the only front method with __stack_chk_guard (stack canary) — its
    loops write through local buffers.
  * hooks: initSubDerivedItems, then
      [dynamicWorld dynamicWorldChangedAtPos:objectType:],
      [world customRules] (on the world object),
      [self itemType] / [self objectType].
  * one NSFastEnumeration (countByEnumeratingWithState:objects:count:)
    over the saveItemSlots array, with the 0x1c2e28 mutation veneer
    present in the body.

Gates: pool-exact (keys/ivars/selectors/classrefs/GOT incl.
__stack_chk_guard) + prologue/epilogue word gates + the helper's four
cmp/movw words pinned (the capacity rule is the batch's semantic
payload).
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
SEL_EXACT = 'initWithWorld:dynamicWorld:saveDict:cache:'

PUSH = 'e92d4df0'
ADD_FP = 'e28db018'
RET_SUB = 'e24bd018'
POP = 'e8bd8df0'

OWN_KEYS = ['chestType', 'safeClientID', 'saveItemSlots',
            'shelfItemDataBs_%d', 'shelfRenderItems_%d']
OWN_IVARS = ['OBJC_IVAR_$_Chest.chestType',
             'OBJC_IVAR_$_Chest.inventoryItems',
             'OBJC_IVAR_$_Chest.shelfItemDataBs',
             'OBJC_IVAR_$_Chest.shelfRenderItems',
             'OBJC_IVAR_$_DynamicObject.dynamicWorld',
             'OBJC_IVAR_$_DynamicObject.ownerID',
             'OBJC_IVAR_$_DynamicObject.pos',
             'OBJC_IVAR_$_DynamicObject.world']
OWN_SELS = ['addObject:', 'alloc', 'array', 'autorelease', 'count',
            'countByEnumeratingWithState:objects:count:', 'customRules',
            'dynamicWorldChangedAtPos:objectType:', 'initSubDerivedItems',
            'initWithCapacity:', 'initWithSaveData:', 'intValue',
            'itemType', 'objectAtIndex:', 'objectForKey:', 'objectType',
            'retain', 'stringWithFormat:']
OWN_CLASSREFS = ['OBJC_CLASS_$_Chest', 'OBJC_CLASS_$_InventoryItem',
                 'OBJC_CLASS_$_NSMutableArray', 'OBJC_CLASS_$_NSString']
OWN_GOT = {'objc_msgSend', 'objc_msgSendSuper2', '__stack_chk_guard'}

# the private capacity helper 0x00cb623c (16 words): pin its decision words
# (words read from the binary: e3500002 = cmp r0,#2; e3500005 = cmp r0,#5;
#  e3000004 = movw r0,#4; e3000010 = movw r0,#0x10)
HELPER = 0x00CB623C
HELPER_GATES = [
    (3, 'e3500002', 'cmp r0,#2 (chestType 2?)'),
    (4, '0a000002', 'beq small'),
    (6, 'e3500005', 'cmp r0,#5 (chestType 5?)'),
    (7, '1a000002', 'bne big'),
    (8, 'e3000004', 'movw r0,#4 (4 slots)'),
    (11, 'e3000010', 'movw r0,#0x10 (16 slots)'),
]
# body gates: super call at w42 (blx r6), nil guard at w48 (cmp) + w49 (bne)
BODY_GATES = [
    (42, 'e12fff36', 'blx r6 = objc_msgSendSuper2 (4-arg forward)'),
    (48, 'e1510000', 'cmp r1,r0 nil guard'),
    (49, '1a000002', 'bne <continue>'),
]


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

    def words(self, imp, boundary):
        return [self.rw(a) or 0 for a in range(imp, boundary, 4)]

    def super_class_of(self, class_object):
        ptr = self.rw(class_object + 4)
        name = self.classes.get(ptr)
        return name.replace('OBJC_CLASS_$_', '') if name else None

    def literal_cells(self, lo, hi):
        keys, selrefs, ivars, classes, got, other = {}, {}, {}, {}, {}, {}
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
            cls_rel = [n for ty, n in rel_t
                       if ty == 2 and n.startswith('OBJC_CLASS_$_')]
            if cls_rel:
                classes[lit] = (t, cls_rel[0])
                continue
            wv = self.rw(t)
            if wv is not None and wv in self.ivar_slots:
                ivars[lit] = (t, self.ivar_slots[wv][0], self.rw(wv))
                continue
            wv2 = self.rw(t)
            if wv2 is not None and wv2 in self.classes:
                classes[lit] = (t, self.classes[wv2])
                continue
            sel = self.m.selectors.get(wv2) if wv2 is not None else None
            if sel and sel.isprintable() and '\x7f' not in sel:
                selrefs[lit] = (t, sel)
                continue
            other[lit] = (t, wv2)
        return {'keys': keys, 'selrefs': selrefs, 'ivars': ivars,
                'classes': classes, 'got': got, 'other': other}


def recover(elf):
    imp = 0x00CB627C
    row = elf.rows.get(imp)
    if row is None or row[1] != 'Chest' or row[3] != SEL_EXACT:
        raise ValueError('Chest: method-map drift')
    boundary = min(i for i in elf.imps if i > imp)
    words = elf.words(imp, boundary)
    if len(words) != 760:
        raise ValueError(f'Chest: body length drift {len(words)}')
    if f'{words[0]:08x}' != PUSH or f'{words[1]:08x}' != ADD_FP:
        raise ValueError('Chest: prologue drift')
    frame = [f'{w:08x}' for w in words]
    try:
        epi = frame.index(RET_SUB)
    except ValueError:
        raise ValueError('Chest: epilogue drift (no RET_SUB)')  # noqa: B904
    if frame[epi + 1] != POP:
        raise ValueError('Chest: epilogue drift (no POP)')
    for idx, want, meaning in BODY_GATES:
        if frame[idx] != want:
            raise ValueError(f'Chest: word {idx} drift ({meaning})')
    # the capacity helper: pin its decision words
    helper_words = elf.words(HELPER, HELPER + 16 * 4)
    if len(helper_words) != 16:
        raise ValueError('Chest: helper length drift')
    for idx, want, meaning in HELPER_GATES:
        if f'{helper_words[idx]:08x}' != want:
            raise ValueError(f'Chest: helper word {idx} drift ({meaning})')
    cells = elf.literal_cells(imp, boundary)
    found_keys = {v[1] for v in cells['keys'].values()}
    if found_keys != set(OWN_KEYS):
        raise ValueError(f'Chest: CFString key set drift '
                         f'{sorted(found_keys)} != {sorted(OWN_KEYS)}')
    found_ivars = {v[1] for v in cells['ivars'].values()}
    if found_ivars != set(OWN_IVARS):
        raise ValueError(f'Chest: ivar slot set drift '
                         f'{sorted(found_ivars)} != {sorted(OWN_IVARS)}')
    sels = {n for _, n in cells['selrefs'].values()}
    want_sels = set(OWN_SELS) | {SEL_EXACT}
    if sels != want_sels:
        raise ValueError(f'Chest: selref set drift {sorted(sels)} != '
                         f'{sorted(want_sels)}')
    got = {n for _, n in cells['got'].values()}
    if got != OWN_GOT:
        raise ValueError(f'Chest: GOT drift {sorted(got)}')
    cls_names = {n for _, n in cells['classes'].values()}
    if cls_names != set(OWN_CLASSREFS):
        raise ValueError(f'Chest: classref drift {sorted(cls_names)}')
    sup_slot = next(iter(cells['classes'].values()))[0]
    runtime_super = elf.super_class_of(elf.rw(sup_slot) or 0)
    if runtime_super != 'InteractionObject':
        raise ValueError(f'Chest: runtime super drift {runtime_super}')
    if not cells['other']:
        raise ValueError('Chest: PIC-base cell missing')
    got_cells = {n: f'0x{t:08x}' for t, n in cells['got'].values()}
    return {
        'schema': 1, 'batch': 'b3m2', 'elf_sha256': SHA,
        'pic_base': f'0x{BASE:08x}',
        'method': ('the Chest loader — save-system centerpiece '
                   '(batch b3m-2, closeout series part 2)'),
        'census': {'front_methods': 60, 'front_words': 13820,
                   'covered_after_b3m2': 58,
                   'covered_words_after_b3m2': 10326 + 760,
                   'remaining_methods': 2, 'remaining_words': 2734},
        'classes': [{
            'class': 'Chest', 'imp': f'0x{imp:08x}',
            'boundary': f'0x{boundary:08x}',
            'code_words': len(words), 'selector': SEL_EXACT,
            'runtime_superclass': runtime_super,
            'literal_cells': {
                'super2_got': got_cells['objc_msgSendSuper2'],
                'msgsend_got': got_cells['objc_msgSend'],
                'stack_chk_guard_got': got_cells['__stack_chk_guard'],
                'superref_slot': f'0x{sup_slot:08x}',
                'class_object': 'OBJC_CLASS_$_Chest',
                'pic_cells': len(cells['other']),
            },
            'own_keys': sorted(OWN_KEYS),
            'capacity_helper': {
                'imp': f'0x{HELPER:08x}', 'code_words': 16,
                'rule': 'numberOfSlots = (chestType == 2 || chestType == 5) '
                        '? 4 : 16',
            },
            'claim': ('super-forwards to InteractionObject (nil guard → nil), '
                      'then reads chestType/safeClientID and enumerates '
                      'saveItemSlots, reading FORMATTED keys '
                      'shelfItemDataBs_%d / shelfRenderItems_%d per slot; '
                      'constructs InventoryItem children via alloc + '
                      'initWithSaveData: into inventoryItems/shelf arrays '
                      'sized by the private capacity helper 0x00cb623c: '
                      'chestType 2 or 5 → 4 slots, else 16 slots; the only '
                      'front method with a stack canary; exact '
                      'key/ivar/selector/classref/GOT sets gated'),
        }],
        'claim': (
            'Chest 0x00cb627c (760w, exact variant, super=InteractionObject) '
            'is the save-system centerpiece: five own keys including two '
            'FORMATTED per-slot key families, InventoryItem child '
            'construction (alloc + initWithSaveData:), and a decoded SLOT '
            'CAPACITY RULE from its private helper 0x00cb623c (chestType '
            '2/5 → 4 slots, else 16). Only front method with '
            '__stack_chk_guard. Static level-A evidence only'),
    }


MUTATIONS = [
    ('b3m2_chest_push', 0x00CB627C + 0 * 4,
     bytes.fromhex('e92d4df1'), 'Chest: prologue drift'),
    ('b3m2_chest_super', 0x00CB627C + 42 * 4,
     bytes.fromhex('e12fff37'), 'Chest: word 42 drift'),
    ('b3m2_chest_nil', 0x00CB627C + 48 * 4,
     bytes.fromhex('e1510001'), 'Chest: word 48 drift'),
    ('b3m2_capacity_small', 0x00CB623C + 8 * 4,
     bytes.fromhex('050000e3'), 'Chest: helper word 8 drift'),
    ('b3m2_capacity_big', 0x00CB623C + 11 * 4,
     bytes.fromhex('110000e3'), 'Chest: helper word 11 drift'),
    ('b3m2_capacity_cmp2', 0x00CB623C + 3 * 4,
     bytes.fromhex('030050e3'), 'Chest: helper word 3 drift'),
]


def self_test(elf):
    failures = []
    for name, vaddr, patch, expect in MUTATIONS:
        try:
            recover(elf.mutate(vaddr, patch))
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
    print(f'b3m2 self-test: {len(MUTATIONS)}/{len(MUTATIONS)} mutations detected')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--output', type=Path,
                    default=NATIVE / 'chest_big_initwithworld.json')
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
    print('b3m-2 Chest loader gated')


if __name__ == '__main__':
    main()
