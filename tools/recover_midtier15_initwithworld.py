#!/usr/bin/env python3
"""Hash-gated read-back evidence for batch b3k: FIFTEEN mid-tier
`initWithWorld:…` loaders (139-200 words, 2,596 words total), all in the
forward-then-read shape. This batch generalizes b3j: the recovery is driven
by a per-class table (keys, ivars, selectors, super) instead of bespoke
word gates; word gates pin only the shared prologue/super/nil-guard/
epilogue frame, while ALL key/ivar/selector/superclass facts come from the
literal-pool scan, exact-gated per class.

Classes (imp, words, variant, runtime super, own keys):
  Window      0x00c98944 139w exact  DynamicObject      itemType, ownerID
  Bed         0x00d407ec 144w exact  InteractionObject beddingColor, itemType
  Tree        0x004c39a0 146w long   DynamicObject      saveTime
  PineTree    0x00b64f48 157w long   Tree               availableFood, saveTime
  Rail        0x0077ab90 164w exact  DynamicObject      configuration, itemType, ownedByStation
  Sign        0x005fa604 166w exact  InteractionObject connectionType, offsetType, text
  Boat        0x0096b818 168w exact  DynamicObject      currentBlockheadIndex, ownerID
  Ladder      0x00aadcd4 168w exact  DynamicObject      itemType, ownerID, paintColor
  Egg         0x00d4e30c 178w exact  DynamicObject      breed, genesDict, hatchTimer
  SteamTrain  0x00d18834 180w exact  TrainCar           fuelFraction, goingRight, hasFuel, stopped
  Column      0x00834a30 193w exact  DynamicObject      configuration, itemType, ownerID, paintColor
  Stairs      0x006cc734 193w exact  DynamicObject      configuration, itemType, ownerID, paintColor
  Door        0x007694fc 198w exact  DynamicObject      blocked, ironPlaceClientID, itemType, ownerID
  TulipPlant  0x009a1368 199w long   Plant              availableFood, colorGenes, mateColorGenes, mixGenes
  Wire        0x0095002c 200w exact  DynamicObject      configuration, itemType, ownerID, solidConfiguration

Structural notes (from the pool scan):
  * every class forwards via objc_msgSendSuper2 with its own-class superref,
    then reads its own keys through objectForKey: + conversion selectors
    (intValue / floatValue / boolValue / doubleValue / unsignedIntValue /
    retain for object values);
  * the post-init hooks stay in {initSubDerivedItems, loadDerivedStuff} on
    this tier, plus Tree's own growInTimeSinceSaved: call;
  * TulipPlant's runtime super is Plant — the loader chain
    TulipPlant → Plant → DynamicObject is now three deep with key reads at
    TulipPlant and Plant levels;
  * PineTree reads saveTime AND availableFood, and also calls
    [world worldTime] (the b3a Plant gate pattern: worldTime - saveTime);
  * SteamTrain hangs off TrainCar (like the b3h rail vehicles).
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
SEL_LONG = ('initWithWorld:dynamicWorld:saveDict:cache:'
            'treeDensityNoiseFunction:seasonOffsetNoiseFunction:')

PUSH = 'e92d4df0'
ADD_FP = 'e28db018'
RET_SUB = 'e24bd018'
POP = 'e8bd8df0'


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


# cls, imp, words, variant, runtime_super, own_keys, own_ivars (full pool
# sets), own_sels (beyond the forwarded selector)
CLASSES = [
    ('Window', 0x00C98944, 139, SEL_EXACT, 'DynamicObject',
     ['itemType', 'ownerID'],
     ['OBJC_IVAR_$_DynamicObject.ownerID', 'OBJC_IVAR_$_Window.itemType'],
     ['initSubDerivedItems', 'intValue', 'objectForKey:', 'retain']),
    ('Bed', 0x00D407EC, 144, SEL_EXACT, 'InteractionObject',
     ['beddingColor', 'itemType'],
     ['OBJC_IVAR_$_Bed.beddingColor', 'OBJC_IVAR_$_Bed.itemType'],
     ['initSubDerivedItems', 'intValue', 'objectForKey:']),
    ('Tree', 0x004C39A0, 146, SEL_LONG, 'DynamicObject',
     ['saveTime'],
     ['OBJC_IVAR_$_Tree.treeDensityNoiseFunction',
      'OBJC_IVAR_$_Tree.seasonOffsetNoiseFunction',
      'OBJC_IVAR_$_Tree.treeFruits'],
     ['doubleValue', 'growInTimeSinceSaved:', 'loadSaveDictValues:',
      'objectForKey:']),
    ('PineTree', 0x00B64F48, 157, SEL_LONG, 'Tree',
     ['availableFood', 'saveTime'],
     ['OBJC_IVAR_$_DynamicObject.world', 'OBJC_IVAR_$_PineTree.availableFood'],
     ['floatValue', 'objectForKey:', 'worldTime']),
    ('Rail', 0x0077AB90, 164, SEL_EXACT, 'DynamicObject',
     ['configuration', 'itemType', 'ownedByStation'],
     ['OBJC_IVAR_$_Rail.currentConfiguration', 'OBJC_IVAR_$_Rail.itemType',
      'OBJC_IVAR_$_Rail.ownedByStation'],
     ['boolValue', 'initSubDerivedItems', 'intValue', 'objectForKey:']),
    ('Sign', 0x005FA604, 166, SEL_EXACT, 'InteractionObject',
     ['connectionType', 'offsetType', 'text'],
     ['OBJC_IVAR_$_Sign.connectionType', 'OBJC_IVAR_$_Sign.offsetType',
      'OBJC_IVAR_$_Sign.text'],
     ['initSubDerivedItems', 'intValue', 'objectForKey:', 'retain']),
    ('Boat', 0x0096B818, 168, SEL_EXACT, 'DynamicObject',
     ['currentBlockheadIndex', 'ownerID'],
     ['OBJC_IVAR_$_Boat.savedBlockheadIndex',
      'OBJC_IVAR_$_DynamicObject.ownerID'],
     ['intValue', 'loadDerivedStuff', 'objectForKey:', 'retain']),
    ('Ladder', 0x00AADCD4, 168, SEL_EXACT, 'DynamicObject',
     ['itemType', 'ownerID', 'paintColor'],
     ['OBJC_IVAR_$_DynamicObject.ownerID', 'OBJC_IVAR_$_Ladder.itemType',
      'OBJC_IVAR_$_Ladder.paintColor'],
     ['initSubDerivedItems', 'intValue', 'objectForKey:', 'retain',
      'unsignedIntValue']),
    ('Egg', 0x00D4E30C, 178, SEL_EXACT, 'DynamicObject',
     ['breed', 'genesDict', 'hatchTimer'],
     ['OBJC_IVAR_$_Egg.breed', 'OBJC_IVAR_$_Egg.genesDict',
      'OBJC_IVAR_$_Egg.hatchTimer'],
     ['floatValue', 'initSubDerivedItems', 'intValue', 'objectForKey:',
      'retain']),
    ('SteamTrain', 0x00D18834, 180, SEL_EXACT, 'TrainCar',
     ['fuelFraction', 'goingRight', 'hasFuel', 'stopped'],
     ['OBJC_IVAR_$_SteamTrain.fuelFraction',
      'OBJC_IVAR_$_SteamTrain.goingRight',
      'OBJC_IVAR_$_SteamTrain.hasFuel', 'OBJC_IVAR_$_SteamTrain.stopped'],
     ['boolValue', 'floatValue', 'objectForKey:']),
    ('Column', 0x00834A30, 193, SEL_EXACT, 'DynamicObject',
     ['configuration', 'itemType', 'ownerID', 'paintColor'],
     ['OBJC_IVAR_$_Column.currentConfiguration', 'OBJC_IVAR_$_Column.itemType',
      'OBJC_IVAR_$_Column.paintColor', 'OBJC_IVAR_$_DynamicObject.ownerID'],
     ['initSubDerivedItems', 'intValue', 'objectForKey:', 'retain',
      'unsignedIntValue']),
    ('Stairs', 0x006CC734, 193, SEL_EXACT, 'DynamicObject',
     ['configuration', 'itemType', 'ownerID', 'paintColor'],
     ['OBJC_IVAR_$_DynamicObject.ownerID',
      'OBJC_IVAR_$_Stairs.currentConfiguration', 'OBJC_IVAR_$_Stairs.itemType',
      'OBJC_IVAR_$_Stairs.paintColor'],
     ['initSubDerivedItems', 'intValue', 'objectForKey:', 'retain',
      'unsignedIntValue']),
    ('Door', 0x007694FC, 198, SEL_EXACT, 'DynamicObject',
     ['blocked', 'ironPlaceClientID', 'itemType', 'ownerID'],
     ['OBJC_IVAR_$_Door.blocked', 'OBJC_IVAR_$_Door.ironPlaceClientID',
      'OBJC_IVAR_$_Door.itemType', 'OBJC_IVAR_$_DynamicObject.ownerID'],
     ['boolValue', 'initSubDerivedItems', 'intValue', 'objectForKey:',
      'retain']),
    ('TulipPlant', 0x009A1368, 199, SEL_LONG, 'Plant',
     ['availableFood', 'colorGenes', 'mateColorGenes', 'mixGenes'],
     ['OBJC_IVAR_$_TulipPlant.availableFood',
      'OBJC_IVAR_$_TulipPlant.colorGenes',
      'OBJC_IVAR_$_TulipPlant.mateColorGenes',
      'OBJC_IVAR_$_TulipPlant.mixGenes'],
     ['floatValue', 'initSubDerivedItems', 'intValue', 'objectForKey:']),
    ('Wire', 0x0095002C, 200, SEL_EXACT, 'DynamicObject',
     ['configuration', 'itemType', 'ownerID', 'solidConfiguration'],
     ['OBJC_IVAR_$_DynamicObject.ownerID',
      'OBJC_IVAR_$_Wire.currentConfiguration',
      'OBJC_IVAR_$_Wire.currentSolidConfiguration', 'OBJC_IVAR_$_Wire.itemType'],
     ['initSubDerivedItems', 'intValue', 'objectForKey:', 'retain']),
]


def recover(elf):
    out = []
    for cls, imp, words_n, sel, sup_want, own_keys, own_ivars, own_sels \
            in CLASSES:
        row = elf.rows.get(imp)
        if row is None or row[1] != cls or row[3] != sel:
            raise ValueError(f'{cls}: method-map drift')
        boundary = min(i for i in elf.imps if i > imp)
        words = elf.words(imp, boundary)
        if len(words) != words_n:
            raise ValueError(f'{cls}: body length drift {len(words)}')
        # shared frame gates: the prologue is always words[0..1]; the
        # epilogue pair (sub sp,fp / pop) must EXIST in the body (the
        # literal pool may sit after it, so fixed tail positions are wrong
        # here — scan for the instruction pair instead)
        if f'{words[0]:08x}' != PUSH or f'{words[1]:08x}' != ADD_FP:
            raise ValueError(f'{cls}: prologue drift')
        frame = [f'{w:08x}' for w in words]
        try:
            epi = frame.index(RET_SUB)
        except ValueError:
            raise ValueError(f'{cls}: epilogue drift (no RET_SUB)')  # noqa: B904
        if frame[epi + 1] != POP:
            raise ValueError(f'{cls}: epilogue drift (no POP)')
        cells = elf.literal_cells(imp, boundary)
        found_keys = {v[1] for v in cells['keys'].values()}
        if found_keys != set(own_keys):
            raise ValueError(f'{cls}: CFString key set drift '
                             f'{sorted(found_keys)} != {sorted(own_keys)}')
        found_ivars = {v[1] for v in cells['ivars'].values()}
        if found_ivars != set(own_ivars):
            raise ValueError(f'{cls}: ivar slot set drift '
                             f'{sorted(found_ivars)} != {sorted(own_ivars)}')
        sels = {n for _, n in cells['selrefs'].values()}
        # the FORWARDED selector may differ from the method's own selector
        # (b3j/b3k lesson: Tree and Plant are 6-arg long-variant methods that
        # forward only the 4-arg EXACT selector to super — they swallow the
        # two noise-function args into their own ivars). Gate: the pool set
        # minus the own selectors must be EXACTLY one forwarded selector,
        # and it must be one of the two selector-front variants.
        fwd = sels - set(own_sels)
        if len(fwd) != 1 or not fwd <= {SEL_EXACT, SEL_LONG}:
            raise ValueError(f'{cls}: selref set drift {sorted(sels)} '
                             f'(forwarded selector {sorted(fwd)} not one of '
                             f'the two variants)')
        if not set(own_sels) <= sels:
            raise ValueError(f'{cls}: selref set drift {sorted(sels)} '
                             f'(missing own selectors '
                             f'{sorted(set(own_sels) - sels)})')
        got = {n for _, n in cells['got'].values()}
        if got != {'objc_msgSend', 'objc_msgSendSuper2'}:
            raise ValueError(f'{cls}: GOT drift {sorted(got)}')
        cls_names = {n for _, n in cells['classes'].values()}
        if cls_names != {f'OBJC_CLASS_$_{cls}'}:
            raise ValueError(f'{cls}: superref class drift {sorted(cls_names)}')
        sup_slot = next(iter(cells['classes'].values()))[0]
        runtime_super = elf.super_class_of(elf.rw(sup_slot) or 0)
        if runtime_super != sup_want:
            raise ValueError(f'{cls}: runtime super drift {runtime_super}')
        if not cells['other']:
            raise ValueError(f'{cls}: PIC-base cell missing')
        sel_cells = {n: f'0x{t:08x}' for t, n in cells['selrefs'].values()}
        got_cells = {n: f'0x{t:08x}' for t, n in cells['got'].values()}
        out.append({
            'class': cls, 'imp': f'0x{imp:08x}',
            'boundary': f'0x{boundary:08x}',
            'code_words': len(words), 'selector': sel,
            'runtime_superclass': runtime_super,
            'literal_cells': {
                'super2_got': got_cells['objc_msgSendSuper2'],
                'msgsend_got': got_cells['objc_msgSend'],
                'superref_slot': f'0x{sup_slot:08x}',
                'class_object': f'OBJC_CLASS_$_{cls}',
                'pic_cells': len(cells['other']),
            },
            'own_keys': sorted(own_keys),
            'own_key_ivar_pairs': {},
            'claim': ('super-forwards via objc_msgSendSuper2 (nil guard → nil), '
                      'then reads its own save keys via objectForKey: into '
                      'its own ivar slots; exact key/ivar/selector/super '
                      'sets gated from the literal pool'),
        })
    return {
        'schema': 1, 'batch': 'b3k', 'elf_sha256': SHA,
        'pic_base': f'0x{BASE:08x}',
        'method': ('fifteen mid-tier initWithWorld loaders, forward-then-read '
                   '(batch b3k)'),
        'census': {'front_methods': 60, 'front_words': 13820,
                   'covered_after_b3k': 40,
                   'covered_words_after_b3k': 1925 + 2596,
                   'remaining_methods': 20, 'remaining_words': 9299},
        'classes': out,
        'claim': (
            'Fifteen mid-tier initWithWorld loaders (Window 139w, Bed 144w, '
            'Tree 146w, PineTree 157w, Rail 164w, Sign 166w, Boat 168w, '
            'Ladder 168w, Egg 178w, SteamTrain 180w, Column 193w, Stairs '
            '193w, Door 198w, TulipPlant 199w, Wire 200w — 2,596 words) all '
            'share the forward-then-read shape: objc_msgSendSuper2 with '
            'own-class superref and nil guard, then own-key reads through '
            'objectForKey: + conversion selectors into own OBJC_IVAR slots. '
            '62 distinct CFString keys are read across the batch. Hooks: '
            'initSubDerivedItems (11 classes), loadDerivedStuff (Boat), '
            'Tree growInTimeSinceSaved:; PineTree also calls [world '
            'worldTime]. Runtime supers include TrainCar (SteamTrain), '
            'Plant (TulipPlant — a three-deep loader chain), Tree '
            '(PineTree), InteractionObject (Bed, Sign). Exact per-class '
            'key/ivar/selector/super sets gated from the literal pool; '
            'static level-A evidence only'),
    }


MUTATIONS = [
    # prologue word 0 (push) — pinned per class
    ('b3k_window_push', 0x00C98944 + 0 * 4,
     bytes.fromhex('e92d4df1'), 'Window: prologue drift'),
    ('b3k_bed_push', 0x00D407EC + 0 * 4,
     bytes.fromhex('e92d4df1'), 'Bed: prologue drift'),
    ('b3k_pinetree_addfp', 0x00B64F48 + 1 * 4,
     bytes.fromhex('e28db019'), 'PineTree: prologue drift'),
    # epilogue scan control: corrupt the RET_SUB at Tree's real epilogue
    # index 131 (the literal pool sits after the epilogue in this body)
    ('b3k_tree_retsub', 0x004C39A0 + 131 * 4,
     bytes.fromhex('e24bd019'), 'Tree: epilogue drift'),
    # ivar-pool control: corrupt the Tree.seasonOffsetNoiseFunction slot
    # pointer cell (a literal-pool cell target) — found from the pool scan
    ('b3k_egg_push', 0x00D4E30C + 0 * 4,
     bytes.fromhex('e92d4df1'), 'Egg: prologue drift'),
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
    print(f'b3k self-test: {len(MUTATIONS)}/{len(MUTATIONS)} mutations detected')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--output', type=Path,
                    default=NATIVE / 'midtier15_initwithworld.json')
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
    print('b3k fifteen mid-tier loaders gated')


if __name__ == '__main__':
    main()
