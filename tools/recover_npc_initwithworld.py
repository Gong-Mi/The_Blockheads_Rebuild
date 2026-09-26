#!/usr/bin/env python3
"""Hash-gated read-back evidence for batch b3g: `-[NPC
initWithWorld:dynamicWorld:saveDict:cache:]` 0x00644b24 (95 w, boundary
0x00644ca0) — the superclass initialiser that the b3f five (ClownFish, Shark,
Scorpion, Dodo, DonkeyLike) forward into.

Shape decoded from the instruction stream:

  [super initWithWorld:dynamicWorld:saveDict:cache:]      objc_msgSendSuper2,
        struct {self, OBJC_CLASS_$_NPC} at sp+0x28, own superref
        0x00e8bc84 → 0x00e90828; blx at word 38
  if (super result == nil) return nil                     words 44/45 and the
        return-zero block 46-48
  [self loadValuesFromSaveDict:saveDict]                  word 61
  r0 = helper_0x6445d8()                                  word 62
  randomHarmFromHungerTimer@144 = 1.0f + 20.0f * (r0 / 2^31f)
        movw #1 / vmov.f32 s0,#1.0 / movw #0x14 / vmov.f32 s2,#20.0 /
        vldr s4 = 0x4f000000 (2^31) / vmov s6,r0 / vcvt.f32.s32 /
        vdiv / vmul / vadd / vstr (words 66-79)

The helper is a local 4-word wrapper (`push {fp,lr} / mov fp,sp /
bl 0x1c2804 / pop {fp,pc}`) around the ABI veneer 0x001c2804, whose slot
0x0105fb10 is the imported **lrand48** — so the hunger timer is seeded from a
random draw in [1, 21) and this loader is NOT deterministic. Any differential
roundtrip must control lrand48's sequence.

Save-side cross reference: NPC `getSaveDict` / `loadValuesFromSaveDict:` were
paired in the earlier save-line batches (b2/super-forward work), so the key
side of this class is inherited; this batch adds the *initialiser* half.
"""
import argparse
import copy
import hashlib
import io
import json
import re
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
CLASS = 'NPC'
IMP = 0x00644B24
BOUNDARY = 0x00644CA0
WORDS = 95
SUPER_SELECTOR = 'initWithWorld:dynamicWorld:saveDict:cache:'
HELPER = 0x006445D8          # local wrapper → veneer
HELPER_VENEER = 0x001C2804   # ABI veneer → imported lrand48 (slot 0x0105fb10)
HELPER_SLOT = 0x0105FB10
FLOAT_2P31 = 0x4F000000
TIMER_IVAR = 'OBJC_IVAR_$_NPC.randomHarmFromHungerTimer'
TIMER_OFFSET = 144
SUPERREF_SLOT = 0x00E8BC84
SUPER_CLASS_OBJECT = 0x00E90828
GOT_SUPER2 = 0x0105B79C
GOT_MSGSEND = 0x0105B7A0

# word index -> (word, meaning)
GATES = [
    (0, 'e92d4df0', 'push {r4,r5,r6,r7,r8,sl,fp,lr}'),
    (38, 'e12fff36', 'blx r6 = objc_msgSendSuper2'),
    (44, 'e1510000', 'cmp r1,r0'),
    (45, '1a000002', 'bne <continue>'),
    (46, 'e3000000', 'movw r0,#0 (return nil)'),
    (47, 'e50b001c', 'str r0,[fp,#-0x1c]'),
    (48, 'ea000022', 'b <epilogue>'),
    (61, 'e12fff33', 'blx r3 = objc_msgSend (loadValuesFromSaveDict:)'),
    (62, 'ebfffe6d', 'bl 0x006445d8 (lrand48 wrapper)'),
    (66, 'e3003001', 'movw r3,#1'),
    (67, 'eeb70a00', 'vmov.f32 s0,#1.0'),
    (68, 'e300c014', 'movw ip,#0x14'),
    (69, 'eeb31a04', 'vmov.f32 s2,#20.0'),
    (70, 'ed9f2a13', 'vldr s4,[pc,#0x4c] (= 2^31f)'),
    (71, 'ee030a10', 'vmov s6,r0'),
    (72, 'eeb83ac3', 'vcvt.f32.s32 s6,s6'),
    (73, 'ee832a02', 'vdiv.f32 s4,s6,s4'),
    (74, 'ee221a01', 'vmul.f32 s2,s4,s2'),
    (75, 'ee310a00', 'vadd.f32 s0,s2,s0'),
    (79, 'ed800a00', 'vstr s0,[r0] (randomHarmFromHungerTimer@144)'),
    (84, 'e51b001c', 'ldr r0,[fp,#-0x1c] (return value)'),
    (86, 'e8bd8df0', 'pop {r4,r5,r6,r7,r8,sl,fp,pc}'),
]
EXPECTED_SELREFS = {SUPER_SELECTOR, 'loadValuesFromSaveDict:'}
EXPECTED_GOT = {'objc_msgSend', 'objc_msgSendSuper2'}
HELPER_WORDS = ['e92d4800', 'e1a0b00d', 'ebedf887', 'e8bd8800']  # push/mov/bl 0x1c2804/pop
# bl target inside the helper: pc = 0x6445e0, target 0x1c2804 → imm24
HELPER_BL_TARGET = HELPER_VENEER


def signed(v):
    return v - (1 << 32) if v & 0x80000000 else v


def arm_imm(w):
    imm12 = w & 0xFFF
    rot = (imm12 >> 8) * 2
    v = imm12 & 0xFF
    return v if not rot else ((v >> rot) | (v << (32 - rot))) & 0xFFFFFFFF


def bl_target(word, addr):
    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 0x1000000
    return (addr + 8 + (imm << 2)) & 0xFFFFFFFF


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

    def words(self, imp, boundary):
        return [self.rw(a) or 0 for a in range(imp, boundary, 4)]

    def super_class_of(self, class_object):
        ptr = self.rw(class_object + 4)
        name = self.classes.get(ptr)
        return name.replace('OBJC_CLASS_$_', '') if name else None

    def slot_of_ivar(self, name):
        for a, v in self.ivar_slots.items():
            if v[0] == name:
                return a
        raise ValueError(f'ivar symbol missing: {name}')

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
            if wv is not None and wv in self.classes:
                classes[lit] = (t, self.classes[wv])
                continue
            sel = self.m.selectors.get(wv) if wv is not None else None
            if sel and sel.isprintable() and '\x7f' not in sel:
                selrefs[lit] = (t, sel)
                continue
            other[lit] = (t, wv)
        return {'keys': keys, 'selrefs': selrefs, 'ivars': ivars,
                'classes': classes, 'got': got, 'other': other}


def helper_chain(elf):
    """0x6445d8 wrapper → 0x1c2804 veneer → imported symbol."""
    words = [f'{(elf.rw(HELPER + 4 * i) or 0):08x}' for i in range(4)]
    if words != HELPER_WORDS:
        raise ValueError(f'NPC: lrand48 wrapper drift {words}')
    target = bl_target(elf.rw(HELPER + 8) or 0, HELPER + 8)
    if target != HELPER_VENEER:
        raise ValueError(f'NPC: wrapper veneer target drift 0x{target:08x}')
    w0 = elf.rw(HELPER_VENEER) or 0
    w1 = elf.rw(HELPER_VENEER + 4) or 0
    w2 = elf.rw(HELPER_VENEER + 8) or 0
    if w0 & 0x0FFF0000 != 0x028F0000 or w1 & 0x0FFF0000 != 0x028C0000:
        raise ValueError('NPC: veneer prologue drift')
    if w2 & 0x0FFF0000 != 0x05BC0000:
        raise ValueError('NPC: veneer jump drift')
    ip = (HELPER_VENEER + 8 + arm_imm(w0) + arm_imm(w1)) & 0xFFFFFFFF
    slot = (ip + (w2 & 0xFFF)) & 0xFFFFFFFF
    if slot != HELPER_SLOT:
        raise ValueError(f'NPC: veneer slot drift 0x{slot:08x}')
    sym = elf.m.imports.get(slot)
    if sym != 'lrand48':
        raise ValueError(f'NPC: veneer import drift {sym}')
    return {'wrapper': f'0x{HELPER:08x}', 'veneer': f'0x{HELPER_VENEER:08x}',
            'slot': f'0x{slot:08x}', 'import': sym,
            'wrapper_words': words}


def recover(elf):
    row = elf.rows.get(IMP)
    if row is None or row[1] != CLASS or row[3] != SUPER_SELECTOR:
        raise ValueError('NPC: method-map drift')
    if min(i for i in elf.imps if i > IMP) != BOUNDARY:
        raise ValueError('NPC: boundary drift')
    words = elf.words(IMP, BOUNDARY)
    if len(words) != WORDS:
        raise ValueError(f'NPC: body length drift {len(words)}')
    for idx, want, meaning in GATES:
        if f'{words[idx]:08x}' != want:
            raise ValueError(f'NPC: word {idx} drift ({meaning})')

    cells = elf.literal_cells(IMP, BOUNDARY)
    if cells['keys']:
        raise ValueError('NPC: unexpected CFString keys')
    sels = {n for _, n in cells['selrefs'].values()}
    if sels != EXPECTED_SELREFS:
        raise ValueError(f'NPC: selref drift {sorted(sels)}')
    got = {n for _, n in cells['got'].values()}
    if got != EXPECTED_GOT:
        raise ValueError(f'NPC: GOT drift {sorted(got)}')
    cls_names = {n for _, n in cells['classes'].values()}
    if cls_names != {f'OBJC_CLASS_$_{CLASS}'}:
        raise ValueError(f'NPC: superref class drift {sorted(cls_names)}')
    if (elf.rw(SUPERREF_SLOT) or 0) != SUPER_CLASS_OBJECT:
        raise ValueError('NPC: superref slot target drift')
    ivar_found = {n: off for _, (t, n, off) in cells['ivars'].items()}
    if ivar_found != {TIMER_IVAR: TIMER_OFFSET}:
        raise ValueError(f'NPC: ivar census drift {ivar_found}')
    if (elf.rw(elf.slot_of_ivar(TIMER_IVAR)) or -1) != TIMER_OFFSET:
        raise ValueError('NPC: timer ivar offset drift')
    float_lits = [w for w in words[87:] if w == FLOAT_2P31]
    if float_lits != [FLOAT_2P31]:
        raise ValueError('NPC: 2^31 float literal drift in pool')
    helper = helper_chain(elf)
    sel_cells = {n: f'0x{t:08x}' for t, n in cells['selrefs'].values()}
    got_cells = {n: f'0x{t:08x}' for t, n in cells['got'].values()}

    return {
        'schema': 1, 'batch': 'b3g', 'elf_sha256': SHA,
        'pic_base': f'0x{BASE:08x}',
        'method': 'NPC initWithWorld:dynamicWorld:saveDict:cache: read-back '
                  'evidence (batch b3g)',
        'class': CLASS, 'imp': f'0x{IMP:08x}', 'boundary': f'0x{BOUNDARY:08x}',
        'code_words': len(words), 'selector': SUPER_SELECTOR,
        'super_init': {'selector': SUPER_SELECTOR,
                       'superref_slot': f'0x{SUPERREF_SLOT:08x}',
                       'class_object': f'OBJC_CLASS_$_{CLASS}',
                       'runtime_superclass': elf.super_class_of(SUPER_CLASS_OBJECT),
                       'got_slot': got_cells['objc_msgSendSuper2'],
                       'call_word_index': 38},
        'post_load': {'selector': 'loadValuesFromSaveDict:',
                      'selector_cell': sel_cells['loadValuesFromSaveDict:'],
                      'call_word_index': 61,
                      'argument': 'saveDict (5th argument)'},
        'hunger_timer_seed': {
            'ivar': TIMER_IVAR, 'ivar_offset': TIMER_OFFSET,
            'formula': 'randomHarmFromHungerTimer@144 = 1.0f + 20.0f * '
                       '(float(lrand48()) / 2^31f)',
            'words': 'vmov s0=1.0f (67) / vmov s2=20.0f (69) / vldr s4=2^31f '
                     '(70) / vmov s6,r0 (71) / vcvt.f32.s32 (72) / vdiv (73) / '
                     'vmul (74) / vadd (75) / vstr (79)',
            'range': '[1.0, 21.0] (float32 rounds the largest lrand48 '
                     'values up: v >= 2^31-2^7 lands on exactly 21.0f)',
            'determinism': 'NON-deterministic: seeded from lrand48()',
        },
        'lrand48_chain': helper,
        'shape': {'super_call_word_index': 38, 'nil_guard_word_indices': [44, 45],
                  'return_nil_word_indices': [46, 47, 48],
                  'loadValues_call_word_index': 61,
                  'lrand48_wrapper_call_word_index': 62,
                  'timer_store_word_index': 79},
        'pool_keys': [], 'selrefs': sorted(sels),
        'claim': (
            'NPC -[initWithWorld:dynamicWorld:saveDict:cache:] (95 w) forwards '
            'to [super initWithWorld:dynamicWorld:saveDict:cache:] through '
            'objc_msgSendSuper2 with its own-class superref '
            '(OBJC_CLASS_$_NPC → runtime super resolved in-file), returns nil '
            'when that fails, then calls [self loadValuesFromSaveDict:saveDict] '
            'and finally seeds randomHarmFromHungerTimer@144 with '
            '1.0f + 20.0f * (float(lrand48()) / 2^31f) — a random draw in '
            '[1, 21) coming from the local wrapper 0x006445d8 → ABI veneer '
            '0x001c2804 → imported lrand48 (slot 0x0105fb10), so this loader '
            'is NOT deterministic and any differential roundtrip must control '
            'lrand48; static level-A evidence only'),
    }


MUTATIONS = [
    ('b3g_super_call_word', IMP + 38 * 4, bytes.fromhex('37ff2fe1'),
     'word 38 drift'),
    ('b3g_loadvalues_call_word', IMP + 61 * 4, bytes.fromhex('34ff2fe1'),
     'word 61 drift'),
    ('b3g_wrapper_call_word', IMP + 62 * 4, bytes.fromhex('ebfffe6e'),
     'word 62 drift'),
    ('b3g_timer_formula_mul', IMP + 74 * 4, bytes.fromhex('013a22ee'),
     'word 74 drift'),
    ('b3g_timer_store_word', IMP + 79 * 4, bytes.fromhex('ed800a01'),
     'word 79 drift'),
    ('b3g_float_2p31_literal', 0x00644C90, bytes.fromhex('0100004f'),
     '2^31 float literal drift'),
    ('b3g_timer_ivar_offset', 'ivar:OBJC_IVAR_$_NPC.randomHarmFromHungerTimer',
     bytes.fromhex('98000000'), 'ivar'),
    ('b3g_superref_slot', SUPERREF_SLOT, bytes.fromhex('00000000'),
     'superref class drift'),
    ('b3g_wrapper_bl', HELPER + 8, bytes.fromhex('88f8edeb'),
     'lrand48 wrapper drift'),
    ('b3g_veneer_slot', HELPER_VENEER + 8, bytes.fromhex('05f3bce5'),
     'veneer slot drift'),
    ('b3g_loadvalues_selector_cell', 0x00E7F104, bytes.fromhex('00000000'),
     'selref drift'),
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
    print(f'b3g self-test: {len(MUTATIONS)}/{len(MUTATIONS)} mutations detected')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--output', type=Path, default=NATIVE / 'npc_initwithworld.json')
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
    print('b3g NPC: super forward + loadValuesFromSaveDict + lrand48 hunger '
          'timer seed gated')


if __name__ == '__main__':
    main()
