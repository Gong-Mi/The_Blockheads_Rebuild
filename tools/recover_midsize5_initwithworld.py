#!/usr/bin/env python3
"""Hash-gated read-back evidence for batch b3j: the five MID-SIZE
`initWithWorld:…` loaders that do MORE than forward (AppleTree, TrainStation,
Plant, GatherBlock, Yak — 102/105/114/128/134 words, 583 total).

Shared shape (from the listings):
  1. prologue spills the incoming args into the outgoing super-call frame;
  2. objc_msgSendSuper2 forwards the SAME selector (exact 4-arg variant) with
     the own-class superref — the long variant forwards all six;
  3. nil guard: nil super result → return nil;
  4. OWNd-state phase: 1-3 objc_msgSend calls whose receivers are the
     returned super result (self) or an init argument, with VFP float
     conversions (vmov/vcvt/vstr) and ivar stores via OBJC_IVAR slots;
  5. return self.

Per-class decode (word indices into each body; keys/ivars resolved from the
literal pool — these ARE save-dict readers, 4 of 5):

AppleTree 0x009bd3b0 (102w, long variant, super = Tree):
  w45 super call; w52 nil guard; reads key `availableFood`
  (objectForKey: → floatValue, w77/w81 the two msgSends, w82 vmov s0,r0,
  w87 vstr s0) into ivar OBJC_IVAR_$_AppleTree.availableFood; return self.

TrainStation 0x00b38f88 (105w, exact variant, super = DynamicObject):
  w38 super; w45 nil guard; reads key `text` (objectForKey: w75, result
  retained w79 and stored word into OBJC_IVAR_$_TrainStation.text at w84);
  then [self initSubDerivedItems] (w89, result discarded); return self.

Plant 0x009559d0 (114w, long variant, super = Tree):
  w38 super; w45 nil guard; NO CFString key — it stores the two noise
  function ARGS into Plant ivars (w56 OBJC_IVAR_$_Plant.seasonOffsetNoise-
  Function via the PIC ivar-slot chain, w62 treeDensityNoiseFunction, both
  `str r0,[r1,r2]`), reads DynamicObject.pos/dynamicWorld through slots,
  then calls [self loadSaveDictValues:] (w68 veneer) — i.e. Plant's
  save-dict reading is DELEGATED to the already-covered b3a method —
  plus [dynamicWorld dynamicWorldChangedAtPos:objectType:] (w96) and
  reads [self objectType] (w87-96 region); return self.

GatherBlock 0x008695a0 (128w, exact variant, super = DynamicObject):
  w38 super; w45 nil guard; reads key `lastKnownGatherValue`
  (objectForKey: w81 → floatValue, then the FLOAT->UINT->FLOAT round trip
  w87 vcvt.u32.f32 / w90 vcvt.f32.u32 — i.e. (float)(uint)value — stored
  vstr s0 w95 into OBJC_IVAR_$_GatherBlock.lastKnownGatherValue); reads
  key `timer` (objectForKey: w101 → intValue, stored word w110 into
  OBJC_IVAR_$_GatherBlock.timer); return self.

Yak 0x0095dae4 (134w, exact variant, super = DynamicObject):
  w41 super; w48 nil guard; reads key `hair` (objectForKey: w85 →
  floatValue → vstr s0 w95 into OBJC_IVAR_$_Yak.hair) and key `milk`
  (objectForKey: w101 → floatValue → vstr s0 w111 into
  OBJC_IVAR_$_Yak.milk); then [self updateTextures] (w116, side-effect
  call, result discarded); return self.

So the batch claim: these five constructors each forward to super, then
read their OWN save keys (except Plant, which delegates to its own
loadSaveDictValues: already covered in b3a). Key/ivar pairing is proven by
the literal-pool decode: each key CFString, its conversion selector
(floatValue/intValue), and its target ivar slot all appear as gated literal
cells in the same body.

Gates: per-class body word gates (from the listings, never from memory) +
CFString-pool emptiness (negative control: a planted key must fail) +
mutation --self-test naming the first firing gate.
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
NIL_CMP = 'e1510000'
NIL_BNE = '1a000002'
MOVW0 = 'e3000000'
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


# cls, imp, boundary, words, variant, runtime_super, gates[(idx, word, meaning)],
# own_keys {key: ivar}, own_selectors (beyond the forwarded selector)
CLASSES = [
    ('AppleTree', 0x009BD3B0, 0x009BD548, 102, SEL_LONG, 'Tree', [
        (0, PUSH, 'push'), (1, ADD_FP, 'add fp,sp,#0x18'),
        (2, 'e24dd060', 'sub sp,#0x60'),
        (45, 'e12fff38', 'blx r8 = objc_msgSendSuper2 (6-arg forward)'),
        (51, NIL_CMP, 'cmp r1,r0 nil guard'), (52, NIL_BNE, 'bne <continue>'),
        (53, MOVW0, 'movw r0,#0'), (55, 'ea000021', 'b <epilogue>'),
        (77, 'e12fff3e', 'blx lr = objc_msgSend #1 (own call, self receiver)'),
        (81, 'e12fff32', 'blx r2 = objc_msgSend #2 (own call)'),
        (82, 'ee000a10', 'vmov s0,r0 (float result)'),
        (87, 'ed800a00', 'vstr s0,[r0] (ivar float store)'),
        (91, RET_SUB, 'sub sp,fp,#0x18'), (92, POP, 'pop')],
     {'availableFood': 'OBJC_IVAR_$_AppleTree.availableFood'},
     ['objectForKey:', 'floatValue']),
    ('TrainStation', 0x00B38F88, 0x00B3912C, 105, SEL_EXACT, 'InteractionObject', [
        (0, PUSH, 'push'), (1, ADD_FP, 'add fp,sp,#0x18'),
        (2, 'e24dd058', 'sub sp,#0x58'),
        (38, 'e12fff36', 'blx r6 = objc_msgSendSuper2 (4-arg forward)'),
        (44, NIL_CMP, 'cmp r1,r0 nil guard'), (45, NIL_BNE, 'bne <continue>'),
        (46, MOVW0, 'movw r0,#0'), (48, 'ea00002a', 'b <epilogue>'),
        (75, 'e12fff35', 'blx r5 = objc_msgSend #1 (own call)'),
        (79, 'e12fff32', 'blx r2 = objc_msgSend #2 (own call)'),
        (84, 'e5810000', 'str r0,[r1] (word ivar store)'),
        (89, 'e12fff33', 'blx r3 = objc_msgSend #3 (own call, result discarded)'),
        (93, RET_SUB, 'sub sp,fp,#0x18'), (94, POP, 'pop')],
     {'text': 'OBJC_IVAR_$_TrainStation.text'},
     ['objectForKey:', 'retain', 'initSubDerivedItems']),
    ('Plant', 0x009559D0, 0x00955B98, 114, SEL_LONG, 'DynamicObject', [
        (0, PUSH, 'push'), (1, ADD_FP, 'add fp,sp,#0x18'),
        (2, 'e24dd050', 'sub sp,#0x50'),
        (38, 'e12fff38', 'blx r8 = objc_msgSendSuper2 (6-arg forward)'),
        (44, NIL_CMP, 'cmp r1,r0 nil guard'), (45, NIL_BNE, 'bne <continue>'),
        (46, MOVW0, 'movw r0,#0'), (48, 'ea000031', 'b <epilogue>'),
        (56, 'e7810002', 'str r0,[r1,r2] (ivar store #1, season noise arg)'),
        (62, 'e7810002', 'str r0,[r1,r2] (ivar store #2, density noise arg)'),
        (68, 'ebe1b34d', 'bl #0x1c281c veneer (msgSend bridge)'),
        (96, 'ebe1b331', 'bl #0x1c281c veneer #3'),
        (100, RET_SUB, 'sub sp,fp,#0x18'), (101, POP, 'pop')],
     {},
     ['loadSaveDictValues:', 'dynamicWorldChangedAtPos:objectType:', 'objectType']),
    ('GatherBlock', 0x008695A0, 0x008697A0, 128, SEL_EXACT, 'DynamicObject', [
        (0, PUSH, 'push'), (1, ADD_FP, 'add fp,sp,#0x18'),
        (2, 'e24dd068', 'sub sp,#0x68'),
        (38, 'e12fff36', 'blx r6 = objc_msgSendSuper2 (4-arg forward)'),
        (44, NIL_CMP, 'cmp r1,r0 nil guard'), (45, NIL_BNE, 'bne <continue>'),
        (46, MOVW0, 'movw r0,#0'), (48, 'ea00003f', 'b <epilogue>'),
        (87, 'eebc0ac0', 'vcvt.u32.f32 s0,s0 (float->uint round-trip)'),
        (90, 'eeb80a40', 'vcvt.f32.u32 s0,s0 (uint->float)'),
        (95, 'ed800a00', 'vstr s0,[r0] (ivar float store)'),
        (101, 'e12fff33', 'blx r3 = objc_msgSend (own call)'),
        (110, 'e5810000', 'str r0,[r1] (word ivar store)'),
        (114, RET_SUB, 'sub sp,fp,#0x18'), (115, POP, 'pop')],
     {'lastKnownGatherValue': 'OBJC_IVAR_$_GatherBlock.lastKnownGatherValue',
      'timer': 'OBJC_IVAR_$_GatherBlock.timer'},
     ['objectForKey:', 'floatValue', 'intValue']),
    ('Yak', 0x0095DAE4, 0x0095DCFC, 134, SEL_EXACT, 'DonkeyLike', [
        (0, PUSH, 'push'), (1, ADD_FP, 'add fp,sp,#0x18'),
        (2, 'e24dd068', 'sub sp,#0x68'),
        (41, 'e12fff36', 'blx r6 = objc_msgSendSuper2 (4-arg forward)'),
        (47, NIL_CMP, 'cmp r1,r0 nil guard'), (48, NIL_BNE, 'bne <continue>'),
        (49, MOVW0, 'movw r0,#0'), (51, 'ea000042', 'b <epilogue>'),
        (85, 'e12fff38', 'blx r8 = objc_msgSend #1 (own call)'),
        (90, 'ee000a10', 'vmov s0,r0'), (95, 'ed800a00', 'vstr s0 (store #1)'),
        (101, 'e12fff33', 'blx r3 = objc_msgSend #2 (own call)'),
        (106, 'ee000a10', 'vmov s0,r0'), (111, 'ed800a00', 'vstr s0 (store #2)'),
        (116, 'e12fff33', 'blx r3 = objc_msgSend #3 (side-effect call)'),
        (120, RET_SUB, 'sub sp,fp,#0x18'), (121, POP, 'pop')],
     {'hair': 'OBJC_IVAR_$_Yak.hair', 'milk': 'OBJC_IVAR_$_Yak.milk'},
     ['objectForKey:', 'floatValue', 'updateTextures']),
]


def recover(elf):
    out = []
    for cls, imp, boundary, words_n, sel, sup_want, gates, own_keys, \
            own_sels in CLASSES:
        row = elf.rows.get(imp)
        if row is None or row[1] != cls or row[3] != sel:
            raise ValueError(f'{cls}: method-map drift')
        if min(i for i in elf.imps if i > imp) != boundary:
            raise ValueError(f'{cls}: boundary drift')
        words = elf.words(imp, boundary)
        if len(words) != words_n:
            raise ValueError(f'{cls}: body length drift {len(words)}')
        for idx, want, meaning in gates:
            if f'{words[idx]:08x}' != want:
                raise ValueError(f'{cls}: word {idx} drift ({meaning})')
        cells = elf.literal_cells(imp, boundary)
        found_keys = {v[1] for v in cells['keys'].values()}
        if found_keys != set(own_keys):
            raise ValueError(f'{cls}: CFString key set drift '
                             f'{sorted(found_keys)} != {sorted(own_keys)}')
        found_ivars = {v[1] for v in cells['ivars'].values()}
        want_ivars = {v for v in own_keys.values()}
        if not want_ivars <= found_ivars:
            raise ValueError(f'{cls}: target ivar slot missing '
                             f'{sorted(want_ivars - found_ivars)}')
        sels = {n for _, n in cells['selrefs'].values()}
        # the FORWARDED selector may differ from the method's own selector:
        # Plant is a 6-arg long-variant method but forwards only the 4-arg
        # exact selector to super (it swallows the two noise-function args
        # into its own ivars instead of passing them on)
        fwd_sel = SEL_EXACT if cls == 'Plant' else sel
        if fwd_sel not in sels:
            raise ValueError(f'{cls}: super selector missing')
        want_sels = set(own_sels) | {fwd_sel}
        if sels != want_sels:
            raise ValueError(f'{cls}: selref set drift {sorted(sels)} != '
                             f'{sorted(want_sels)}')
        got = {n for _, n in cells['got'].values()}
        if not {'objc_msgSendSuper2'} <= got:
            raise ValueError(f'{cls}: super2 GOT missing {sorted(got)}')
        if 'objc_msgSend' not in got and cls != 'Plant':
            # Plant routes own calls through the 0x1c281c local veneer,
            # not the imported GOT cell
            raise ValueError(f'{cls}: msgSend GOT missing {sorted(got)}')
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
            'class': cls, 'imp': f'0x{imp:08x}', 'boundary': f'0x{boundary:08x}',
            'code_words': len(words), 'selector': sel,
            'runtime_superclass': runtime_super,
            'literal_cells': {
                'super2_got': got_cells['objc_msgSendSuper2'],
                'msgsend_got': got_cells.get('objc_msgSend'),
                'superref_slot': f'0x{sup_slot:08x}',
                'class_object': f'OBJC_CLASS_$_{cls}',
                'own_selectors': sorted(n for n in sel_cells
                                        if n not in (SEL_EXACT, SEL_LONG)),
                'pic_cells': len(cells['other']),
            },
            'own_keys': sorted(own_keys),
            'own_key_ivar_pairs': {k: v for k, v in own_keys.items()},
            'claim': ('super-forwards via objc_msgSendSuper2 (nil guard → nil), '
                      'then reads its own save keys into its own ivars '
                      '(exact key/ivar/selector sets gated); not a pure '
                      'constructor: own save-dict keys are read directly'),
        })
    return {
        'schema': 1, 'batch': 'b3j', 'elf_sha256': SHA,
        'pic_base': f'0x{BASE:08x}',
        'method': ('five mid-size initWithWorld loaders with own post-init '
                   'messages (batch b3j)'),
        'census': {'covered_after_b3j': 25,
                   'remaining_methods': 18, 'remaining_words': 9051},
        'classes': out,
        'claim': (
            'AppleTree (102w, long variant, super=Tree), TrainStation (105w, '
            'exact, super=DynamicObject), Plant (114w, long, super=Tree), '
            'GatherBlock (128w, exact, super=DynamicObject), Yak (134w, '
            'exact, super=DynamicObject) — 583 words total — share the '
            'forward-then-read shape: objc_msgSendSuper2 forwards the SAME '
            'selector with own-class superref, nil guard returns nil, then '
            'the method reads its OWN save keys via objectForKey:/'
            'floatValue/intValue into its OWN ivar slots (key/ivar pairs: '
            'AppleTree availableFood→AppleTree.availableFood; TrainStation '
            'text→TrainStation.text then [self initSubDerivedItems]; '
            'GatherBlock lastKnownGatherValue→.lastKnownGatherValue with a '
            'float→uint→float round trip and timer→.timer; Yak hair→.hair, '
            'milk→.milk then [self updateTextures]). Plant reads NO key: it '
            'stores the two noise-function ARGS into its ivars and DELEGATES '
            'save-dict reading to its own already-covered '
            'loadSaveDictValues: (b3a). Key/ivar/conversion-selector sets '
            'are exact-gated per class. Static level-A evidence only'),
    }


MUTATIONS = [
    ('b3j_appletree_super', 0x009BD3B0 + 45 * 4, bytes.fromhex('e12fff37'),
     'AppleTree: word 45 drift'),
    ('b3j_trainstation_nil', 0x00B38F88 + 44 * 4, bytes.fromhex('e1510001'),
     'TrainStation: word 44 drift'),
    ('b3j_plant_store1', 0x009559D0 + 56 * 4, bytes.fromhex('e7810003'),
     'Plant: word 56 drift'),
    ('b3j_gatherblock_cvt', 0x008695A0 + 87 * 4, bytes.fromhex('eebc0ac1'),
     'GatherBlock: word 87 drift'),
    ('b3j_yak_store1', 0x0095DAE4 + 95 * 4, bytes.fromhex('ed800a01'),
     'Yak: word 95 drift'),
    # key-set negative control: corrupt the availableFood CFString's DATA
    # POINTER (cell at 0x00f96178+8) so the decoded key name drifts
    ('b3j_appletree_key_drift', 0x00F96178 + 8,
     bytes.fromhex('00000001'), 'AppleTree: CFString key set drift'),
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
    print(f'b3j self-test: {len(MUTATIONS)}/{len(MUTATIONS)} mutations detected')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--output', type=Path,
                    default=NATIVE / 'midsize5_initwithworld.json')
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
    print('b3j five mid-size loaders gated')


if __name__ == '__main__':
    main()
