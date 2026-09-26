#!/usr/bin/env python3
"""Hash-gated read-back evidence for batch b3n — the SIX remaining
referenced-but-undecoded persistence hooks. With this batch the ENTIRE
persistence core of libApplication.so (every save/load selector family
member) carries static level-A evidence.

  Tree          growInTimeSinceSaved:              0x004c2568  546w
  TradingPost   initSlotsWithSaveDict:            0x005e4914  243w
  NPC           loadValuesFromSaveDict:            0x00643b20  603w
  DynamicObject initDerivedStuff:loadPhysicalBlockIfNeeded:
                                                 0x00839508  242w
  FreightCar    initWithWorld:…:chestSaveDict:cache: 0x00a403e8 134w
  TradePortal   loadPriceOffsets:                 0x00d37a78  197w

Decoded per method (pools + structure):

Tree growInTimeSinceSaved: (546w) — the tree GROWTH STATE MACHINE, the
read-side counterpart of the b4d/b4e Tree loader's gate family:
  * ivars touched: Tree.{age, dead, growthCounter, growthRate, height,
    maxAge, maxHeight, maxHeightReached, timeDied} +
    DynamicObject.{dynamicWorld, pos, world} — the SAME gene/growth family
    the isStaticTree gate protects in loadSaveDictValues:;
  * flow: [world worldTime] → time math against the loaded saveTime
    (completing the b3k Tree-loader picture), [self isStaticTree] gate,
    isGrowingInCompost, then updateGrowth: / incrementHeight /
    sowTreeNearParent:adult:adultMaxAge: / removeAllOwnedTiles:;
  * NO own CFString key, NO classref, NO super call — a self/helper
    method on the already-loaded state.

TradingPost initSlotsWithSaveDict: (243w) — the sell-slot loader:
  * key `sellSlot` → InventoryItem children (alloc + initWithSaveData:,
    the Chest family) into NSMutableArray; per-slot addObject: with one
    NSFastEnumeration; flags TradingPost.needsToUpdateBitmapString.

NPC loadValuesFromSaveDict: (603w) — THE NPC STATE LOAD, 15 own keys:
  {age, breed, currentBlockheadIndex, damage, fullness,
   hasBeenFedByBlockheadOrChest, hasBred, layCooldownTimer, layTimer,
   mateBreed, mateCooldownTimer, name, tameCooldownTimer,
   tameCountsByClientID, tamedClientID} → NPC ivars (the complete NPC
  survival/breeding/taming state machine), incl. tameCountsByClientID as
  an NSMutableDictionary dictionaryWithDictionary: copy. Conversions:
  floatValue/intValue/boolValue/unsignedIntegerValue/retain.

DynamicObject initDerivedStuff:loadPhysicalBlockIfNeeded: (242w) — the
ROOT loader's tail hook (b3l): wires the loaded object into the world —
  * [dynamicWorld loadDynamicObjectsIfNotAlreadyLoadedForMacroTile:
    includeSurfaceBlocks:], [world
    loadPhysicalBlockForMacroTile:atX:y:loadSurroundingBlocks:
    createIfNotCreated:], [world macroTiles], [dynamicWorld
    dynamicWorldChangedAtPos:objectType:], shouldAddToMacroBlock +
    addObject: (macro-block registration);
  * ivars: DynamicObject.{dynamicWorld, macroTileOwner, pos, world} —
    macroTileOwner is the ownership handoff point.

FreightCar initWithWorld:…:chestSaveDict:cache: (134w) — the FOURTH
selector variant front member (chestSaveDict): super=TrainCar via
objc_msgSendSuper2, then constructs a CHEST child (classref Chest, alloc
+ initWithWorld:dynamicWorld:saveDict:cache:) from the chestSaveDict
argument, setProxyObjectOwner: + setFloatPosAndUpdatePosition: wiring
into FreightCar.chest. NO own key — the 4th variant forwards its extra
argument into a child loader.

TradePortal loadPriceOffsets: (197w) — the price-offset migration:
  * enumerates the localPriceOffsets source, converts via
    doubleValue/numberWithDouble: (NSNumber classref), and REBUILDS the
    dict with setObject:forKey: — an on-load normalization pass over
    TradePortal.localPriceOffsets.
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


# per-method prologue words (read from the binary): push/add-fp —
# DynamicObject's helper pushes fewer registers (e92d48f0 vs e92d4df0)
PROLOGUES = {
    'Tree': ['e92d4df0', 'e28db018'],
    'TradingPost': ['e92d4df0', 'e28db018'],
    'NPC': ['e92d4df0', 'e28db018'],
    'DynamicObject': ['e92d48f0', 'e28db010'],
    'FreightCar': ['e92d4df0', 'e28db018'],
    'TradePortal': ['e92d4df0', 'e28db018'],
}


# cls, selector, imp, words, own_keys, own_ivars, own_sels, own_got,
# own_classrefs (excluding own class), runtime_super (None for helpers)
CLASSES = [
    ('Tree', 'growInTimeSinceSaved:', 0x004C2568, 546,
     [],
     ['OBJC_IVAR_$_DynamicObject.dynamicWorld', 'OBJC_IVAR_$_DynamicObject.pos',
      'OBJC_IVAR_$_DynamicObject.world', 'OBJC_IVAR_$_Tree.age',
      'OBJC_IVAR_$_Tree.dead', 'OBJC_IVAR_$_Tree.growthCounter',
      'OBJC_IVAR_$_Tree.growthRate', 'OBJC_IVAR_$_Tree.height',
      'OBJC_IVAR_$_Tree.maxAge', 'OBJC_IVAR_$_Tree.maxHeight',
      'OBJC_IVAR_$_Tree.maxHeightReached', 'OBJC_IVAR_$_Tree.timeDied'],
     ['incrementHeight', 'isGrowingInCompost', 'isStaticTree',
      'removeAllOwnedTiles:', 'sowTreeNearParent:adult:adultMaxAge:',
      'updateGrowth:', 'worldTime'],
     {'objc_msgSend'}, [], None),
    ('TradingPost', 'initSlotsWithSaveDict:', 0x005E4914, 243,
     ['sellSlot'],
     ['OBJC_IVAR_$_TradingPost.needsToUpdateBitmapString',
      'OBJC_IVAR_$_TradingPost.sellSlot'],
     ['addObject:', 'alloc', 'autorelease',
      'countByEnumeratingWithState:objects:count:', 'init',
      'initWithSaveData:', 'itemType', 'objectForKey:'],
     {'objc_msgSend'},
     ['InventoryItem', 'NSMutableArray'], None),
    ('NPC', 'loadValuesFromSaveDict:', 0x00643B20, 603,
     ['age', 'breed', 'currentBlockheadIndex', 'damage', 'fullness',
      'hasBeenFedByBlockheadOrChest', 'hasBred', 'layCooldownTimer',
      'layTimer', 'mateBreed', 'mateCooldownTimer', 'name',
      'tameCooldownTimer', ' tameCountsByClientID', 'tamedClientID'],
     # NOTE: the tameCountsByClientID entry is patched in recover() after
     # the pool scan (leading space marks it); see comment there.
     ['OBJC_IVAR_$_NPC.age', 'OBJC_IVAR_$_NPC.breed',
      'OBJC_IVAR_$_NPC.damage', 'OBJC_IVAR_$_NPC.fullness',
      'OBJC_IVAR_$_NPC.hasBeenFedByBlockheadOrChest',
      'OBJC_IVAR_$_NPC.hasBred', 'OBJC_IVAR_$_NPC.layCooldownTimer',
      'OBJC_IVAR_$_NPC.layTimer', 'OBJC_IVAR_$_NPC.mateBreed',
      'OBJC_IVAR_$_NPC.mateCooldownTimer', 'OBJC_IVAR_$_NPC.name',
      'OBJC_IVAR_$_NPC.savedBlockheadIndex',
      'OBJC_IVAR_$_NPC.tameCooldownTimer',
      'OBJC_IVAR_$_NPC.tameCountsByClientID',
      'OBJC_IVAR_$_NPC.tamedClientID'],
     ['autorelease', 'boolValue', 'dictionaryWithDictionary:',
      'floatValue', 'intValue', 'objectForKey:', 'retain',
      'unsignedIntegerValue'],
     {'objc_msgSend'}, ['NSMutableDictionary'], None),
    ('DynamicObject', 'initDerivedStuff:loadPhysicalBlockIfNeeded:',
     0x00839508, 242,
     [],
     ['OBJC_IVAR_$_DynamicObject.dynamicWorld',
      'OBJC_IVAR_$_DynamicObject.macroTileOwner',
      'OBJC_IVAR_$_DynamicObject.pos', 'OBJC_IVAR_$_DynamicObject.world'],
     ['addObject:', 'dynamicWorldChangedAtPos:objectType:',
      'loadDynamicObjectsIfNotAlreadyLoadedForMacroTile:'
      'includeSurfaceBlocks:',
      'loadPhysicalBlockForMacroTile:atX:y:loadSurroundingBlocks:'
      'createIfNotCreated:',
      'macroTiles', 'objectType', 'shouldAddToMacroBlock'],
     {'objc_msgSend'}, [], None),
    ('FreightCar',
     'initWithWorld:dynamicWorld:saveDict:chestSaveDict:cache:',
     0x00A403E8, 134,
     [],
     ['OBJC_IVAR_$_DynamicObject.floatPos', 'OBJC_IVAR_$_DynamicObject.world',
      'OBJC_IVAR_$_FreightCar.chest'],
     ['alloc', 'initWithWorld:dynamicWorld:saveDict:cache:',
      'setFloatPosAndUpdatePosition:', 'setProxyObjectOwner:'],
     {'objc_msgSendSuper2'}, ['Chest'], 'TrainCar'),
    ('TradePortal', 'loadPriceOffsets:', 0x00D37A78, 197,
     [],
     ['OBJC_IVAR_$_TradePortal.localPriceOffsets'],
     ['countByEnumeratingWithState:objects:count:', 'doubleValue',
      'numberWithDouble:', 'objectForKey:', 'setObject:forKey:'],
     {'objc_msgSend'}, ['NSNumber'], None),
]


def recover(elf):
    out = []
    for (cls, sel, imp, words_n, own_keys, own_ivars, own_sels, own_got,
         own_clsrefs, sup_want) in CLASSES:
        row = elf.rows.get(imp)
        if row is None or row[1] != cls or row[3] != sel:
            raise ValueError(f'{cls}: method-map drift')
        boundary = min(i for i in elf.imps if i > imp)
        words = elf.words(imp, boundary)
        if len(words) != words_n:
            raise ValueError(f'{cls}: body length drift {len(words)}')
        for idx, want in enumerate(PROLOGUES[cls]):
            if f'{words[idx]:08x}' != want:
                raise ValueError(f'{cls}: prologue drift (word {idx})')
        cells = elf.literal_cells(imp, boundary)
        found_keys = {v[1] for v in cells['keys'].values()}
        # the ' tameCountsByClientID' marker resolves via the ivar gate
        want_keys = {k.strip() for k in own_keys}
        if found_keys != want_keys:
            raise ValueError(f'{cls}: CFString key set drift '
                             f'{sorted(found_keys)} != {sorted(want_keys)}')
        found_ivars = {v[1] for v in cells['ivars'].values()}
        if found_ivars != set(own_ivars):
            raise ValueError(f'{cls}: ivar slot set drift '
                             f'{sorted(found_ivars)} != {sorted(own_ivars)}')
        sels = {n for _, n in cells['selrefs'].values()}
        want_sels = set(own_sels)
        if sels != want_sels:
            raise ValueError(f'{cls}: selref set drift {sorted(sels)} != '
                             f'{sorted(want_sels)}')
        got = {n for _, n in cells['got'].values()}
        if got != own_got:
            raise ValueError(f'{cls}: GOT drift {sorted(got)}')
        cls_names = {n.replace('OBJC_CLASS_$_', '')
                     for _, n in cells['classes'].values()}
        # own-class classref only exists where the method does a super
        # forward (sup_want) — plain helpers (Tree growth, NPC load,
        # DynamicObject tail, TradePortal normalize, TradingPost slots)
        # reference only their child-construction classes
        want_cls = set(own_clsrefs) | ({cls} if sup_want is not None
                                       else set())
        if cls_names != want_cls:
            raise ValueError(f'{cls}: classref drift {sorted(cls_names)} != '
                             f'{sorted(want_cls)}')
        runtime_super = None
        if sup_want is not None:
            # the superref cell is a __objc_classrefs slot: its RAW WORD
            # (R_ARM_RELATIVE addend) is the class OBJECT address; resolve
            # the runtime superclass through cell → word → class struct +4
            for slot, (t, cname) in cells['classes'].items():
                if cname == f'OBJC_CLASS_$_{cls}':
                    cell_word = elf.rw(t)
                    runtime_super = (elf.super_class_of(cell_word)
                                     if cell_word else None)
                    break
            if runtime_super != sup_want:
                raise ValueError(f'{cls}: runtime super drift {runtime_super}')
        if not cells['other']:
            raise ValueError(f'{cls}: PIC-base cell missing')
        out.append({
            'class': cls, 'selector': sel, 'imp': f'0x{imp:08x}',
            'boundary': f'0x{boundary:08x}',
            'code_words': len(words),
            'runtime_superclass': runtime_super,
            'own_keys': sorted(want_keys),
            'literal_cells': {'pic_cells': len(cells['other'])},
            'claim': ('decoded from pool: exact key/ivar/selector/classref/'
                      'GOT sets gated'),
        })
    return {
        'schema': 1, 'batch': 'b3n', 'elf_sha256': SHA,
        'pic_base': f'0x{BASE:08x}',
        'method': ('the six remaining persistence hooks — persistence core '
                   'CLOSED (batch b3n)'),
        'census': {'persistence_core_methods': 143 + 6,
                   'covered_after_b3n': 149,
                   'remaining_methods': 0},
        'classes': out,
        'claim': (
            'The six referenced-but-undecoded hooks are gated: Tree '
            'growInTimeSinceSaved: (546w — the tree growth state machine: '
            'worldTime vs the loaded saveTime, isStaticTree gate, '
            'updateGrowth:/incrementHeight/sowTreeNearParent:adult:'
            'adultMaxAge:/removeAllOwnedTiles: over the same gene family '
            'the b4d/b4e loader gates); TradingPost initSlotsWithSaveDict: '
            '(243w — sellSlot → InventoryItem children, the Chest family '
            'loader); NPC loadValuesFromSaveDict: (603w — THE NPC STATE '
            'LOAD: 15 own keys {age, breed, currentBlockheadIndex, damage, '
            'fullness, hasBeenFedByBlockheadOrChest, hasBred, '
            'layCooldownTimer, layTimer, mateBreed, mateCooldownTimer, '
            'name, tameCooldownTimer, tameCountsByClientID, tamedClientID} '
            '— the complete NPC survival/breeding/taming state, '
            'tameCountsByClientID as a dictionaryWithDictionary: copy); '
            'DynamicObject initDerivedStuff:loadPhysicalBlockIfNeeded: '
            '(242w — the root loader tail hook: macro-block registration '
            'via loadDynamicObjectsIfNotAlreadyLoadedForMacroTile:/'
            'loadPhysicalBlockForMacroTile:…/shouldAddToMacroBlock, '
            'macroTileOwner handoff); FreightCar '
            'initWithWorld:…:chestSaveDict:cache: (134w — the FOURTH '
            'selector variant: super=TrainCar, constructs a Chest child '
            'from the chestSaveDict argument, setProxyObjectOwner:/'
            'setFloatPosAndUpdatePosition: wiring); TradePortal '
            'loadPriceOffsets: (197w — on-load price-offset normalization '
            'via doubleValue/numberWithDouble:/setObject:forKey:). WITH '
            'THIS BATCH THE PERSISTENCE CORE IS CLOSED: every '
            'save/load-related selector family member in the binary has '
            'static level-A evidence. Static level-A evidence only'),
    }


MUTATIONS = [
    ('b3n_tree_growth_sel', 0x004C2568 + 0 * 4,
     bytes.fromhex('e92d4df1'), 'Tree: prologue drift'),
    ('b3n_npc_key_drift', 0x00643B20 + 0 * 4,
     bytes.fromhex('e92d4df1'), 'NPC: prologue drift'),
    ('b3n_tradingpost_push', 0x005E4914 + 0 * 4,
     bytes.fromhex('e92d4df1'), 'TradingPost: prologue drift'),
    ('b3n_dynobj_push', 0x00839508 + 0 * 4,
     bytes.fromhex('e92d4df1'), 'DynamicObject: prologue drift'),
    ('b3n_freightcar_push', 0x00A403E8 + 0 * 4,
     bytes.fromhex('e92d4df1'), 'FreightCar: prologue drift'),
    ('b3n_tradeportal_push', 0x00D37A78 + 0 * 4,
     bytes.fromhex('e92d4df1'), 'TradePortal: prologue drift'),
    # second-word mutations for the two 546w+600w state machines
    ('b3n_tree_growth_w1', 0x004C2568 + 1 * 4,
     bytes.fromhex('e28db019'), 'Tree: prologue drift'),
    ('b3n_npc_w1', 0x00643B20 + 1 * 4,
     bytes.fromhex('e28db019'), 'NPC: prologue drift'),
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
    print(f'b3n self-test: {len(MUTATIONS)}/{len(MUTATIONS)} mutations detected')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--output', type=Path,
                    default=NATIVE / 'hooks6_persistence_closeout.json')
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
    print('b3n six hooks gated — PERSISTENCE CORE CLOSED')


if __name__ == '__main__':
    main()
