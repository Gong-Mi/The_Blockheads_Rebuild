#!/usr/bin/env python3
"""Hash-gated read-back evidence for batch b3f: the five 74-word
`- [initWithWorld:dynamicWorld:saveDict:cache:]` forwarders

  ClownFish  0x0078e420   Shark       0x007c8918   Scorpion  0x00893d58
  Dodo       0x00a6b7dc   DonkeyLike  0x00ab0c3c

Census (43 methods share this selector, 10,976 words total) put these five at
exactly 74 words each. They turn out to be the SAME 69-word skeleton with only
their five literal-pool cells differing per class:

  [super initWithWorld:dynamicWorld:saveDict:cache:]   (objc_msgSendSuper2,
        struct at sp+0x20 = {self, OBJC_CLASS_$_<own class>} via superref,
        blx at word 41)
  if (result == nil) return nil                        (movw/cmp/bne at
        words 43/47/48, return-zero at 49-51)
  [self loadDerivedStuff]                              (msgSend through the
        GOT + selref, blx at word 62)
  return self

No CFString keys and no ivar offsets are touched by any of the five: their
own state lives in the superclass initialiser, they only add the
`loadDerivedStuff` post-init hook. The skeleton is pinned by sha256 over its
69 little-endian words, so a single altered instruction in ANY of the five
bodies fails the run.
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
SELECTOR = 'initWithWorld:dynamicWorld:saveDict:cache:'

CLASSES = [
    ('ClownFish', 0x0078E420, 0x0078E548),
    ('Shark', 0x007C8918, 0x007C8A40),
    ('Scorpion', 0x00893D58, 0x00893E80),
    ('Dodo', 0x00A6B7DC, 0x00A6B904),
    ('DonkeyLike', 0x00AB0C3C, 0x00AB0D64),
]
WORDS = 74
SKELETON_WORDS = 69
SKELETON_SHA256 = ('bbd0bc16ac1ca4e3776bafe9153a60672'
                   'ca15a66b68d4efffad33581d804f1c8')
SKELETON_GATES = {                       # word index -> (word, meaning)
    0: ('e92d4df0', 'push {r4,r5,r6,r7,r8,sl,fp,lr}'),
    41: ('e12fff36', 'blx r6 = objc_msgSendSuper2'),
    43: ('e3000000', 'movw r0,#0 (nil compare)'),
    47: ('e1510000', 'cmp r1,r0'),
    48: ('1a000002', 'bne <continue>'),
    49: ('e3000000', 'movw r0,#0 (return nil)'),
    51: ('ea00000c', 'b <epilogue>'),
    62: ('e12fff32', 'blx r2 = objc_msgSend (loadDerivedStuff)'),
    67: ('e8bd8df0', 'pop {r4,r5,r6,r7,r8,sl,fp,pc}'),
}
EXPECTED_SELREFS = {SELECTOR, 'loadDerivedStuff'}
EXPECTED_GOT = {'objc_msgSend', 'objc_msgSendSuper2'}


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
            if wv is not None and wv in self.classes:
                classes[lit] = (t, self.classes[wv])
                continue
            sel = self.m.selectors.get(wv) if wv is not None else None
            if sel:
                selrefs[lit] = (t, sel)
                continue
            other[lit] = (t, wv)
        return {'keys': keys, 'selrefs': selrefs, 'ivars': ivars,
                'classes': classes, 'got': got, 'other': other}


def recover(elf):
    out = []
    skeletons = {}
    for cls, imp, boundary in CLASSES:
        row = elf.rows.get(imp)
        if row is None or row[1] != cls or row[3] != SELECTOR:
            raise ValueError(f'{cls}: method-map drift')
        if min(i for i in elf.imps if i > imp) != boundary:
            raise ValueError(f'{cls}: boundary drift')
        words = elf.words(imp, boundary)
        if len(words) != WORDS:
            raise ValueError(f'{cls}: body length drift {len(words)}')
        # index gates first so a flipped instruction names its site
        for idx, (want, meaning) in sorted(SKELETON_GATES.items()):
            if f'{words[idx]:08x}' != want:
                raise ValueError(f'{cls}: skeleton word {idx} drift '
                                 f'({meaning})')
        skeleton = b''.join(w.to_bytes(4, 'little') for w in words[:SKELETON_WORDS])
        digest = hashlib.sha256(skeleton).hexdigest()
        if digest != SKELETON_SHA256:
            raise ValueError(f'{cls}: skeleton sha256 drift {digest}')
        skeletons[cls] = digest
        cells = elf.literal_cells(imp, boundary)
        if cells['keys']:
            raise ValueError(f'{cls}: unexpected CFString keys')
        if cells['ivars']:
            raise ValueError(f'{cls}: unexpected ivar cells')
        cls_names = {n for _, n in cells['classes'].values()}
        if cls_names != {f'OBJC_CLASS_$_{cls}'}:
            raise ValueError(f'{cls}: superref class drift {sorted(cls_names)}')
        sup_slot = next(iter(cells['classes'].values()))[0]
        if len(cells['other']) != 1:
            raise ValueError(f'{cls}: unexpected extra literal cells '
                             f'{sorted(cells["other"])}')
        pic_word = next(iter(cells['other'].values()))[1]
        sels = {n for _, n in cells['selrefs'].values()}
        if sels != EXPECTED_SELREFS:
            raise ValueError(f'{cls}: selref drift {sels ^ EXPECTED_SELREFS}')
        got = {n for _, n in cells['got'].values()}
        if got != EXPECTED_GOT:
            raise ValueError(f'{cls}: GOT drift {got}')
        sel_cells = {n: f'0x{t:08x}' for t, n in cells['selrefs'].values()}
        got_cells = {n: f'0x{t:08x}' for t, n in cells['got'].values()}
        sup_name = elf.super_class_of(elf.rw(sup_slot) or 0)
        out.append({
            'class': cls, 'imp': f'0x{imp:08x}', 'boundary': f'0x{boundary:08x}',
            'code_words': len(words), 'selector': SELECTOR,
            'runtime_superclass': sup_name,
            'skeleton_sha256': digest, 'skeleton_words': SKELETON_WORDS,
            'literal_cells': {
                'super2_got': got_cells.get('objc_msgSendSuper2'),
                'msgsend_got': got_cells.get('objc_msgSend'),
                'super_selector_cell': sel_cells.get(SELECTOR),
                'loadDerivedStuff_selector_cell': sel_cells.get('loadDerivedStuff'),
                'superref_slot': f'0x{sup_slot:08x}',
                'class_object': f'OBJC_CLASS_$_{cls}',
                'pic_base_cell_word': (f'0x{pic_word:08x}'
                                       if pic_word is not None else 'unmapped'),
            },
            'shape': {'super_call_word_index': 41,
                      'nil_guard_word_indices': [43, 47, 48],
                      'return_nil_indices': [49, 51],
                      'loadDerivedStuff_call_word_index': 62},
            'own_keys': [], 'own_ivars': [],
            'claim': ('forwards to [super initWithWorld:dynamicWorld:saveDict:'
                      'cache:] with objc_msgSendSuper2 (own-class superref), '
                      'returns nil when the super result is nil, then calls '
                      '[self loadDerivedStuff] and returns self; touches no '
                      'CFString key and no own ivar'),
        })
    if len(set(skeletons.values())) != 1:
        raise ValueError('skeleton divergence across the five classes')
    return {
        'schema': 1, 'batch': 'b3f', 'elf_sha256': SHA,
        'pic_base': f'0x{BASE:08x}',
        'method': 'five 74-word initWithWorld:dynamicWorld:saveDict:cache: '
                  'forwarders — shared skeleton + loadDerivedStuff hook '
                  '(batch b3f)',
        'selector': SELECTOR,
        'shared_skeleton_sha256': SKELETON_SHA256,
        'shared_skeleton_words': SKELETON_WORDS,
        'census': {'selector_methods': 43, 'selector_words': 10976,
                   'covered_by_this_batch': 5},
        'classes': out,
        'claim': (
            'The five smallest implementations of '
            'initWithWorld:dynamicWorld:saveDict:cache: (ClownFish, Shark, '
            'Scorpion, Dodo, DonkeyLike; 74 words each) are the SAME 69-word '
            'body — pinned by sha256 — differing only in five literal-pool '
            'cells (objc_msgSendSuper2 GOT slot, the selector cell, the '
            'own-class __objc_superrefs slot, the loadDerivedStuff selector '
            'cell and the PIC base cell). Each forwards to its superclass '
            'initialiser, returns nil on a nil super result, then invokes '
            '[self loadDerivedStuff] and returns self, contributing no keys '
            'and no ivars of its own; static level-A evidence only, the '
            'loadDerivedStuff body and the runtime roundtrip are unresolved'),
    }


MUTATIONS = [
    ('b3f_skeleton_word_41', 0x0078E420 + 41 * 4, bytes.fromhex('37ff2fe1'),
     'skeleton word 41 drift'),
    ('b3f_skeleton_word_62_shark', 0x007C8918 + 62 * 4,
     bytes.fromhex('33ff2fe1'), 'skeleton word 62 drift'),
    ('b3f_skeleton_nil_branch', 0x00893D58 + 48 * 4,
     bytes.fromhex('1a000003'), 'skeleton word 48 drift'),
    ('b3f_skeleton_hash_dodo', 0x00A6B7DC + 20 * 4,
     bytes.fromhex('00001be5'), 'skeleton sha256 drift'),
    ('b3f_donkeylike_epilogue_word', 0x00AB0D48,
     bytes.fromhex('f08dbde9'), 'skeleton word 67 drift'),
    ('b3f_superref_slot_target', 0x00E8BD38, bytes.fromhex('00000000'),
     'superref class drift'),
    ('b3f_loadderived_selector_cell', 0x00E81310, bytes.fromhex('00000000'),
     'selref drift'),
    ('b3f_scorpion_loadderived_cell', 0x00E82B88,
     bytes.fromhex('00000000'), 'selref drift'),
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
    print(f'b3f self-test: {len(MUTATIONS)}/{len(MUTATIONS)} mutations detected')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--output', type=Path,
                    default=NATIVE / 'forwarder5_initwithworld.json')
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
    print('b3f classes=5 shared skeleton, loadDerivedStuff hook gated')


if __name__ == '__main__':
    main()
