#!/usr/bin/env python3
"""Hash-gated read-back evidence for batch b3i: the NINE tree-family
`-[initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:
seasonOffsetNoiseFunction:]` forwarders (the long 6-arg variant), 62 words each:

    CactusTree   0x00b533bc    CherryTree  0x00d0df2c    CoconutTree 0x00a99948
    CoffeeTree   0x007deb28    GemTree     0x00529134    LimeTree    0x00809c3c
    MangoTree    0x00d4b4f4    MapleTree   0x00db5fb4    OrangeTree  0x00a96604

All nine share ONE byte-identical code body for words 0..58 (verified by
pairwise word comparison — 59/62 words identical, diffs only at the tail
literal-pool words 59, 60, 61 which hold the per-class superref/selector cells
and the pc-relative base). Semantics (from the CactusTree listing):

  * prologue spills the 6 incoming arguments (self, _cmd, world, dynamicWorld,
    saveDict, cache, treeDensityNoiseFunction, seasonOffsetNoiseFunction —
    the last two on the stack per the @32@0:4@8@12@16@20@24@28 type encoding)
    into the outgoing call frame;
  * `blx r8` = objc_msgSendSuper2 with the own-class superref, forwarding ALL
    SIX arguments to [super initWithWorld:dynamicWorld:saveDict:cache:
    treeDensityNoiseFunction:seasonOffsetNoiseFunction:];
  * nil guard: if the super result is nil, return nil;
  * otherwise return the super result (return self);
  * no CFString key is read, no ivar is written, no post-init hook is called.

Because words 0..58 are byte-identical across the nine, the batch gates the
shared body by sha256 over words 0..58 (with a handful of word-INDEX gates in
front so a flipped instruction reports its site) and gates each per-class tail
triple (words 59, 60, 61) individually.
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
SELECTOR = ('initWithWorld:dynamicWorld:saveDict:cache:'
            'treeDensityNoiseFunction:seasonOffsetNoiseFunction:')

# Shared-skeleton word gates (indices into the 62-word body; identical across
# all nine classes). Hex words verified against the CactusTree listing.
SHARED_GATES = [
    (0, 'e92d4df0', 'push {r4-r8,sl,fp,lr}'),
    (1, 'e28db018', 'add fp,sp,#0x18'),
    (2, 'e24dd048', 'sub sp,sp,#0x48'),
    (10, 'e59f80b8', 'ldr r8,[pc,#0xb8] (super2 GOT literal)'),
    (11, 'e798800c', 'ldr r8,[r8,ip] = objc_msgSendSuper2'),
    (37, 'e1a00007', 'mov r0,r7 (objc_super receiver = self)'),
    (42, 'e12fff38', 'blx r8 = objc_msgSendSuper2 (6-arg forward)'),
    (43, 'e58d0010', 'str r0,[sp,#0x10] (spill super result)'),
    (44, 'e3000000', 'movw r0,#0 (nil constant)'),
    (45, 'e59d1010', 'ldr r1,[sp,#0x10]'),
    (48, 'e1510000', 'cmp r1,r0 (nil guard)'),
    (49, '1a000002', 'bne <continue>'),
    (55, 'e51b001c', 'ldr r0,[fp,#-0x1c] (return value)'),
    (56, 'e24bd018', 'sub sp,fp,#0x18'),
    (57, 'e8bd8df0', 'pop {r4-r8,sl,fp,pc}'),
]

# cls, imp, boundary, tail words (59,60,61) little-endian hex — read from the
# binary, never extrapolated: the tail words are signed pc-relative offsets.
CLASSES = [
    ('CactusTree', 0x00B533BC, 0x00B534B4, ['ffe26f1c', 'ffe2c3b4', '0050c720']),
    ('CherryTree', 0x00D0DF2C, 0x00D0E024, ['ffe28994', 'ffe2c414', '00351bb0']),
    ('CoconutTree', 0x00A99948, 0x00A99A40, ['ffe25aa0', 'ffe2c35c', '005c6194']),
    ('CoffeeTree', 0x007DEB28, 0x007DEC20, ['ffe21e00', 'ffe2c264', '00880fb4']),
    ('GemTree', 0x00529134, 0x0052922C, ['ffe1de7c', 'ffe2c160', '00b369a8']),
    ('LimeTree', 0x00809C3C, 0x00809D34, ['ffe22164', 'ffe2c270', '00855ea0']),
    ('MangoTree', 0x00D4B4F4, 0x00D4B5EC, ['ffe28f44', 'ffe2c42c', '003145e8']),
    ('MapleTree', 0x00DB5FB4, 0x00DB60AC, ['ffe2947c', 'ffe2c45c', '002a9b28']),
    ('OrangeTree', 0x00A96604, 0x00A966FC, ['ffe25a44', 'ffe2c358', '005c94d8']),
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


def recover(elf):
    out = []
    body_hashes = {}
    first_body_hash = None
    for cls, imp, boundary, tail in CLASSES:
        row = elf.rows.get(imp)
        if row is None or row[1] != cls or row[3] != SELECTOR:
            raise ValueError(f'{cls}: method-map drift')
        if min(i for i in elf.imps if i > imp) != boundary:
            raise ValueError(f'{cls}: boundary drift')
        words = elf.words(imp, boundary)
        if len(words) != 62:
            raise ValueError(f'{cls}: body length drift {len(words)}')
        # per-class tail gate (words 59, 60, 61 — the literal pool)
        for idx, want in zip((59, 60, 61), tail):
            if f'{words[idx]:08x}' != want:
                raise ValueError(f'{cls}: tail word {idx} drift')
        # word gates FIRST (site-specific messages), then the shared-skeleton
        # sha256 equality check — a checksum must never swallow the site info
        for idx, want, meaning in SHARED_GATES:
            if f'{words[idx]:08x}' != want:
                raise ValueError(f'{cls}: word {idx} drift ({meaning})')
        body = b''.join(struct_pack(w) for w in words[:59])
        digest = hashlib.sha256(body).hexdigest()
        if first_body_hash is not None and digest != first_body_hash:
            raise ValueError(f'{cls}: shared-body word drift '
                             f'(sha256 {digest[:12]} != {first_body_hash[:12]})')
        if first_body_hash is None:
            first_body_hash = digest
        body_hashes[cls] = digest
        cells = elf.literal_cells(imp, boundary)
        if cells['keys']:
            raise ValueError(f'{cls}: unexpected CFString keys')
        if cells['ivars']:
            raise ValueError(f'{cls}: unexpected ivar cells')
        sels = {n for _, n in cells['selrefs'].values()}
        if sels != {SELECTOR}:
            raise ValueError(f'{cls}: selref drift {sorted(sels)}')
        got = {n for _, n in cells['got'].values()}
        if got != {'objc_msgSendSuper2'}:
            raise ValueError(f'{cls}: GOT drift {sorted(got)}')
        cls_names = {n for _, n in cells['classes'].values()}
        if cls_names != {f'OBJC_CLASS_$_{cls}'}:
            raise ValueError(f'{cls}: superref class drift {sorted(cls_names)}')
        sup_slot = next(iter(cells['classes'].values()))[0]
        runtime_super = elf.super_class_of(elf.rw(sup_slot) or 0)
        if runtime_super != 'Tree':
            raise ValueError(f'{cls}: runtime super drift {runtime_super}')
        if not cells['other']:
            raise ValueError(f'{cls}: PIC-base cell missing')
        sel_cells = {n: f'0x{t:08x}' for t, n in cells['selrefs'].values()}
        got_cells = {n: f'0x{t:08x}' for t, n in cells['got'].values()}
        out.append({
            'class': cls, 'imp': f'0x{imp:08x}', 'boundary': f'0x{boundary:08x}',
            'code_words': len(words), 'selector': SELECTOR,
            'runtime_superclass': runtime_super,
            'super_call_word_index': 42,
            'shared_body_sha256': digest,
            'literal_cells': {
                'super2_got': got_cells['objc_msgSendSuper2'],
                'super_selector_cell': sel_cells[SELECTOR],
                'superref_slot': f'0x{sup_slot:08x}',
                'class_object': f'OBJC_CLASS_$_{cls}',
                'pic_cells': len(cells['other']),
            },
            'own_keys': [], 'own_ivars': [],
            'claim': ('forwards all six arguments to [super initWithWorld:'
                      'dynamicWorld:saveDict:cache:treeDensityNoiseFunction:'
                      'seasonOffsetNoiseFunction:] through objc_msgSendSuper2 '
                      'with its own-class superref, returns nil on a nil super '
                      'result, returns self otherwise; reads no CFString key '
                      'and writes no own ivar'),
        })
    # one body hash across all nine
    if len(set(body_hashes.values())) != 1:
        raise ValueError('shared-skeleton hash drift across classes')
    return {
        'schema': 1, 'batch': 'b3i', 'elf_sha256': SHA,
        'pic_base': f'0x{BASE:08x}',
        'method': ('nine tree-family initWithWorld:dynamicWorld:saveDict:cache:'
                   'treeDensityNoiseFunction:seasonOffsetNoiseFunction: '
                   'forwarders (batch b3i)'),
        'selector': SELECTOR,
        'census': {'selector_methods': 43, 'selector_words': 10976,
                   'exact_variant_methods': 43,
                   'long_variant_methods': 17,
                   'covered_after_b3i': 20, 'words_covered_after_b3i': 784 + 558,
                   'remaining_methods': 23, 'remaining_words': 10192 - 558},
        'classes': out,
        'claim': (
            'Nine implementations of the LONG initWithWorld variant '
            '(treeDensityNoiseFunction:seasonOffsetNoiseFunction:) — CactusTree, '
            'CherryTree, CoconutTree, CoffeeTree, GemTree, LimeTree, MangoTree, '
            'MapleTree, OrangeTree, 62 words each, 558 words total — share ONE '
            'byte-identical body (words 0..58, sha256-gated) and forward all six '
            'arguments to [super …] via objc_msgSendSuper2 with their own-class '
            'superref; all nine runtime superclasses resolve in-file to Tree; '
            'nil guard returns nil; return self; no CFString key is read, no '
            'ivar is written, no post-init hook exists. The per-class tail '
            'words 59-61 only select their own superref/selector cells. Static '
            'level-A evidence only'),
    }


def struct_pack(w):
    import struct as _s
    return _s.pack('<I', w)


MUTATIONS = [
    ('b3i_cactus_super_call', 0x00B533BC + 42 * 4, bytes.fromhex('e12fff37'),
     'CactusTree: word 42 drift'),
    ('b3i_cherry_nil_guard', 0x00D0DF2C + 48 * 4, bytes.fromhex('e1510001'),
     'CherryTree: word 48 drift'),
    ('b3i_coconut_tail', 0x00A99948 + 60 * 4, bytes.fromhex('ffe2c35d'),
     'CoconutTree: tail word 60 drift'),
    ('b3i_gemtree_push', 0x00529134 + 0 * 4, bytes.fromhex('e92d4df1'),
     'GemTree: word 0 drift'),
    ('b3i_limetree_pop', 0x00809C3C + 57 * 4, bytes.fromhex('e8bd8df1'),
     'LimeTree: word 57 drift'),
    ('b3i_mangotree_body_hash', 0x00D4B4F4 + 30 * 4, bytes.fromhex('00000000'),
     'MangoTree: shared-body word drift'),
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
    print(f'b3i self-test: {len(MUTATIONS)}/{len(MUTATIONS)} mutations detected')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--output', type=Path,
                    default=NATIVE / 'treefamily9_long_initwithworld.json')
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
    print('b3i nine tree-family long-variant forwarders gated')


if __name__ == '__main__':
    main()
