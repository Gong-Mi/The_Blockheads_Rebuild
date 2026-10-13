#!/usr/bin/env python3
"""Hash-gated read-back evidence for batch b3m-1: the two PLANT-FAMILY BIG
LOADERS — KelpPlant 0x00815be8 (606w) and VinePlant 0x004f68a0 (681w), both
long-variant (treeDensityNoiseFunction:seasonOffsetNoiseFunction:), 1,287
words total. These are the first two of the five remaining big methods of
the initWithWorld front (the "b3m" closeout series).

Mirror-twin structure (from the pools + pairwise word diff):
  * SAME key set, mirrored occupancy axis:
      KelpPlant:  availableFood, growthTimer, numberOfOccupiedTilesAbove, saveTime
      VinePlant:  availableFood, growthTimer, numberOfOccupiedTilesBelow, saveTime
  * SAME selector set (12 selectors): dieOfOldAge, doubleValue,
    dynamicWorldChangedAtPos:objectType:, floatValue, initSubDerivedItems,
    the long variant itself, intValue, isGrowingInCompost, objectForKey:,
    objectType, worldContentsChangedAtPos:, worldTime
  * SAME ivar families: own {availableFood, growthTimer,
    numberOfOccupiedTiles{Above,Below}} + Plant.{age, growthRate, maxAge}
    (+ KelpPlant also Plant.frozen) + DynamicObject {dynamicWorld, pos,
    world}
  * super = Plant for both (the b3j-covered 114w loader is their parent —
    the chain Kelp/Vine → Plant → DynamicObject)
  * the saveTime + [world worldTime] pattern is present (FOURTH and FIFTH
    sites of the b3a gate pattern), followed by dieOfOldAge and
    isGrowingInCompost calls — plant-age logic gated on the loaded saveTime
  * bodies are NOT byte-identical (sequence similarity 0.559; register
    allocation differs; VinePlant carries ~75 extra words for the
    below-tiles scan) — so unlike b3f/b3i there is no shared-body hash;
    the evidence is pool-gated per class with prologue/epilogue word gates,
    same as b3k/b3l.
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


SHARED_SELS = ['dieOfOldAge', 'doubleValue',
               'dynamicWorldChangedAtPos:objectType:', 'floatValue',
               'initSubDerivedItems', SEL_LONG, 'intValue',
               'isGrowingInCompost', 'objectForKey:', 'objectType',
               'worldContentsChangedAtPos:', 'worldTime']

CLASSES = [
    ('KelpPlant', 0x00815BE8, 606,
     ['availableFood', 'growthTimer', 'numberOfOccupiedTilesAbove',
      'saveTime'],
     ['OBJC_IVAR_$_DynamicObject.dynamicWorld', 'OBJC_IVAR_$_DynamicObject.pos',
      'OBJC_IVAR_$_DynamicObject.world', 'OBJC_IVAR_$_KelpPlant.availableFood',
      'OBJC_IVAR_$_KelpPlant.growthTimer',
      'OBJC_IVAR_$_KelpPlant.numberOfOccupiedTilesAbove',
      'OBJC_IVAR_$_Plant.age', 'OBJC_IVAR_$_Plant.frozen',
      'OBJC_IVAR_$_Plant.growthRate', 'OBJC_IVAR_$_Plant.maxAge']),
    ('VinePlant', 0x004F68A0, 681,
     ['availableFood', 'growthTimer', 'numberOfOccupiedTilesBelow',
      'saveTime'],
     ['OBJC_IVAR_$_DynamicObject.dynamicWorld', 'OBJC_IVAR_$_DynamicObject.pos',
      'OBJC_IVAR_$_DynamicObject.world', 'OBJC_IVAR_$_Plant.age',
      'OBJC_IVAR_$_Plant.growthRate', 'OBJC_IVAR_$_Plant.maxAge',
      'OBJC_IVAR_$_VinePlant.availableFood',
      'OBJC_IVAR_$_VinePlant.growthTimer',
      'OBJC_IVAR_$_VinePlant.numberOfOccupiedTilesBelow']),
]


def recover(elf):
    out = []
    for cls, imp, words_n, own_keys, own_ivars in CLASSES:
        row = elf.rows.get(imp)
        if row is None or row[1] != cls or row[3] != SEL_LONG:
            raise ValueError(f'{cls}: method-map drift')
        boundary = min(i for i in elf.imps if i > imp)
        words = elf.words(imp, boundary)
        if len(words) != words_n:
            raise ValueError(f'{cls}: body length drift {len(words)}')
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
        want_sels = set(SHARED_SELS)
        if sels != want_sels:
            raise ValueError(f'{cls}: selref set drift {sorted(sels)} != '
                             f'{sorted(want_sels)}')
        got = {n for _, n in cells['got'].values()}
        if got != {'objc_msgSend', 'objc_msgSendSuper2'}:
            raise ValueError(f'{cls}: GOT drift {sorted(got)}')
        cls_names = {n for _, n in cells['classes'].values()}
        if cls_names != {f'OBJC_CLASS_$_{cls}'}:
            raise ValueError(f'{cls}: superref class drift {sorted(cls_names)}')
        sup_slot = next(iter(cells['classes'].values()))[0]
        runtime_super = elf.super_class_of(elf.rw(sup_slot) or 0)
        if runtime_super != 'Plant':
            raise ValueError(f'{cls}: runtime super drift {runtime_super}')
        if not cells['other']:
            raise ValueError(f'{cls}: PIC-base cell missing')
        got_cells = {n: f'0x{t:08x}' for t, n in cells['got'].values()}
        out.append({
            'class': cls, 'imp': f'0x{imp:08x}',
            'boundary': f'0x{boundary:08x}',
            'code_words': len(words), 'selector': SEL_LONG,
            'runtime_superclass': runtime_super,
            'literal_cells': {
                'super2_got': got_cells['objc_msgSendSuper2'],
                'msgsend_got': got_cells['objc_msgSend'],
                'superref_slot': f'0x{sup_slot:08x}',
                'class_object': f'OBJC_CLASS_$_{cls}',
                'pic_cells': len(cells['other']),
            },
            'own_keys': sorted(own_keys),
            'claim': ('super-forwards the long variant to [super initWithWorld:'
                      '…treeDensityNoiseFunction:seasonOffsetNoiseFunction:] '
                      '(nil guard → nil), then reads its own keys '
                      '{availableFood, growthTimer, '
                      'numberOfOccupiedTilesAbove/Below, saveTime} and runs '
                      'the plant-age phase: [world worldTime] (4th/5th '
                      'saveTime gate site), dieOfOldAge, isGrowingInCompost, '
                      'dynamicWorldChangedAtPos:objectType:, '
                      'worldContentsChangedAtPos:; exact key/ivar/selector '
                      'sets gated from the pool'),
        })
    return {
        'schema': 1, 'batch': 'b3m1', 'elf_sha256': SHA,
        'pic_base': f'0x{BASE:08x}',
        'method': ('the two plant-family big loaders KelpPlant/VinePlant '
                   '(batch b3m-1, closeout series part 1)'),
        'census': {'front_methods': 60, 'front_words': 13820,
                   'covered_after_b3m1': 57,
                   'covered_words_after_b3m1': 9039 + 1287,
                   'remaining_methods': 3, 'remaining_words': 3494},
        'classes': out,
        'claim': (
            'KelpPlant (606w) and VinePlant (681w) — 1,287 words, the two '
            'biggest plant-family loaders — are MIRROR TWINS: identical key '
            'sets on a mirrored occupancy axis (numberOfOccupiedTilesAbove '
            'vs …Below), identical 12-selector sets (saveTime doubleValue + '
            '[world worldTime] = the 4th/5th sites of the b3a gate pattern, '
            'then dieOfOldAge / isGrowingInCompost / '
            'dynamicWorldChangedAtPos:objectType: / '
            'worldContentsChangedAtPos:), both forwarding the long variant '
            'to Plant (their chain: Kelp/Vine → Plant → DynamicObject). '
            'Bodies are NOT byte-identical (similarity 0.559; VinePlant '
            'carries ~75 extra words for the below-tile scan), so the '
            'evidence is pool-gated per class + prologue/epilogue word '
            'gates, not a shared-body hash. Static level-A evidence only'),
    }


MUTATIONS = [
    ('b3m1_kelp_push', 0x00815BE8 + 0 * 4,
     bytes.fromhex('e92d4df1'), 'KelpPlant: prologue drift'),
    ('b3m1_kelp_addfp', 0x00815BE8 + 1 * 4,
     bytes.fromhex('e28db019'), 'KelpPlant: prologue drift'),
    ('b3m1_vine_push', 0x004F68A0 + 0 * 4,
     bytes.fromhex('e92d4df1'), 'VinePlant: prologue drift'),
    ('b3m1_vine_addfp', 0x004F68A0 + 1 * 4,
     bytes.fromhex('e28db019'), 'VinePlant: prologue drift'),
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
    print(f'b3m1 self-test: {len(MUTATIONS)}/{len(MUTATIONS)} mutations detected')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--output', type=Path,
                    default=NATIVE / 'kelpvine_big_initwithworld.json')
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
    print('b3m-1 KelpPlant/VinePlant big loaders gated')


if __name__ == '__main__':
    main()
