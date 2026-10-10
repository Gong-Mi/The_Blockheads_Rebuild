#!/usr/bin/env python3
"""Hash-gated read-back evidence for batch b3h: five more
`- [initWithWorld:dynamicWorld:saveDict:cache:]` forwarders, in two shapes —

  super-only (no post-init hook):
    SurfaceBlock      0x00812e64 (57 w)  super → DynamicObject
    PassengerCar      0x0081bcc8 (60 w)  super → TrainCar
    HandCar           0x00a4f564 (60 w)  super → TrainCar
  super + initSubDerivedItems hook:
    Mirror            0x00a9f434 (71 w)  super → InteractionObject
    SnowSurfaceBlock  0x00d8d89c (71 w)  super → DynamicObject

Unlike the b3f five (which shared one byte-identical body), these five have
per-class bodies, so each one is gated at its own word indices; what they do
share is the *shape*: objc_msgSendSuper2 with the own-class superref, a nil
guard that returns nil, an optional post-init hook, and `return self`. None of
them reads a CFString key or writes an ivar — the second hook name of the line
(`initSubDerivedItems`, alongside b3f's `loadDerivedStuff`) appears here.

The runtime superclasses are resolved from the class structs in-file:
`TrainCar` for both rail vehicles and `InteractionObject` for Mirror, i.e.
these loaders forward into three different parents, not one.
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
SELECTOR = 'initWithWorld:dynamicWorld:saveDict:cache:'
HOOK = 'initSubDerivedItems'

PUSH = 'e92d4df0'
POP = 'e8bd8df0'
SUPER_CALL = 'e12fff36'
CMP_NIL = 'e1510000'
BNE = '1a000002'
MOVW0 = 'e3000000'
STR_RET = 'e50b001c'
RET_SUB = 'e24bd018'

# cls, imp, boundary, words, shape, runtime_super, gates[(idx, word, meaning)]
CLASSES = [
    ('SurfaceBlock', 0x00812E64, 0x00812F48, 57, 'super_only', 'DynamicObject', [
        (0, PUSH, 'push'), (2, 'e24dd040', 'sub sp,#0x40'),
        (37, SUPER_CALL, 'blx r6 = objc_msgSendSuper2'),
        (43, CMP_NIL, 'cmp r1,r0'), (44, BNE, 'bne <continue>'),
        (45, MOVW0, 'movw r0,#0 (return nil)'), (46, STR_RET, 'str r0,[fp,#-0x1c]'),
        (47, 'ea000001', 'b <epilogue>'), (49, STR_RET, 'str r0,[fp,#-0x1c]'),
        (51, RET_SUB, 'sub sp,fp,#0x18'), (52, POP, 'pop')]),
    ('PassengerCar', 0x0081BCC8, 0x0081BDB8, 60, 'super_only', 'TrainCar', [
        (0, PUSH, 'push'), (2, 'e24dd040', 'sub sp,#0x40'),
        (40, SUPER_CALL, 'blx r6 = objc_msgSendSuper2'),
        (46, CMP_NIL, 'cmp r1,r0'), (47, BNE, 'bne <continue>'),
        (48, MOVW0, 'movw r0,#0 (return nil)'), (49, STR_RET, 'str r0,[fp,#-0x1c]'),
        (50, 'ea000001', 'b <epilogue>'), (52, STR_RET, 'str r0,[fp,#-0x1c]'),
        (54, RET_SUB, 'sub sp,fp,#0x18'), (55, POP, 'pop')]),
    ('HandCar', 0x00A4F564, 0x00A4F654, 60, 'super_only', 'TrainCar', [
        (0, PUSH, 'push'), (2, 'e24dd040', 'sub sp,#0x40'),
        (40, SUPER_CALL, 'blx r6 = objc_msgSendSuper2'),
        (46, CMP_NIL, 'cmp r1,r0'), (47, BNE, 'bne <continue>'),
        (48, MOVW0, 'movw r0,#0 (return nil)'), (49, STR_RET, 'str r0,[fp,#-0x1c]'),
        (50, 'ea000001', 'b <epilogue>'), (52, STR_RET, 'str r0,[fp,#-0x1c]'),
        (54, RET_SUB, 'sub sp,fp,#0x18'), (55, POP, 'pop')]),
    ('Mirror', 0x00A9F434, 0x00A9F550, 71, 'super_plus_initSubDerivedItems',
     'InteractionObject', [
        (0, PUSH, 'push'), (2, 'e24dd048', 'sub sp,#0x48'),
        (38, SUPER_CALL, 'blx r6 = objc_msgSendSuper2'),
        (44, CMP_NIL, 'cmp r1,r0'), (45, BNE, 'bne <continue>'),
        (46, MOVW0, 'movw r0,#0 (return nil)'), (47, STR_RET, 'str r0,[fp,#-0x1c]'),
        (48, 'ea00000c', 'b <epilogue>'),
        (49, 'e59f0044', 'ldr r0,[pc,#0x44] (msgSend GOT)'),
        (56, 'e58d000c', 'str r0,[sp,#0xc]'),
        (59, 'e12fff32', 'blx r2 = objc_msgSend (initSubDerivedItems)'),
        (61, STR_RET, 'str r0,[fp,#-0x1c]'),
        (63, RET_SUB, 'sub sp,fp,#0x18'), (64, POP, 'pop')]),
    ('SnowSurfaceBlock', 0x00D8D89C, 0x00D8D9B8, 71,
     'super_plus_initSubDerivedItems', 'DynamicObject', [
        (0, PUSH, 'push'), (2, 'e24dd048', 'sub sp,#0x48'),
        (38, SUPER_CALL, 'blx r6 = objc_msgSendSuper2'),
        (44, CMP_NIL, 'cmp r1,r0'), (45, BNE, 'bne <continue>'),
        (46, MOVW0, 'movw r0,#0 (return nil)'), (47, STR_RET, 'str r0,[fp,#-0x1c]'),
        (48, 'ea00000c', 'b <epilogue>'),
        (49, 'e59f0044', 'ldr r0,[pc,#0x44] (msgSend GOT)'),
        (56, 'e58d000c', 'str r0,[sp,#0xc]'),
        (59, 'e12fff32', 'blx r2 = objc_msgSend (initSubDerivedItems)'),
        (61, STR_RET, 'str r0,[fp,#-0x1c]'),
        (63, RET_SUB, 'sub sp,fp,#0x18'), (64, POP, 'pop')]),
]
EXPECTED_SUPER_SEL = SELECTOR


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
    for cls, imp, boundary, words_n, shape, sup_want, gates in CLASSES:
        row = elf.rows.get(imp)
        if row is None or row[1] != cls or row[3] != SELECTOR:
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
        if cells['keys']:
            raise ValueError(f'{cls}: unexpected CFString keys')
        if cells['ivars']:
            raise ValueError(f'{cls}: unexpected ivar cells')
        sels = {n for _, n in cells['selrefs'].values()}
        want_sels = ({SELECTOR} if shape == 'super_only'
                     else {SELECTOR, HOOK})
        if sels != want_sels:
            raise ValueError(f'{cls}: selref drift {sorted(sels)}')
        got = {n for _, n in cells['got'].values()}
        want_got = ({'objc_msgSendSuper2'} if shape == 'super_only'
                    else {'objc_msgSendSuper2', 'objc_msgSend'})
        if got != want_got:
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
            'class': cls, 'imp': f'0x{imp:08x}', 'boundary': f'0x{boundary:08x}',
            'code_words': len(words), 'selector': SELECTOR, 'shape': shape,
            'runtime_superclass': runtime_super,
            'super_call_word_index': next(i for i, w, m in gates
                                          if 'objc_msgSendSuper2' in m),
            'hook': (None if shape == 'super_only' else {
                'selector': HOOK,
                'selector_cell': sel_cells[HOOK],
                'call_word_index': next(i for i, w, m in gates
                                        if 'initSubDerivedItems' in m)}),
            'literal_cells': {
                'super2_got': got_cells['objc_msgSendSuper2'],
                'super_selector_cell': sel_cells[SELECTOR],
                'msgsend_got': got_cells.get('objc_msgSend'),
                'superref_slot': f'0x{sup_slot:08x}',
                'class_object': f'OBJC_CLASS_$_{cls}',
                'pic_cells': len(cells['other']),
            },
            'own_keys': [], 'own_ivars': [],
            'claim': ('forwards to [super initWithWorld:dynamicWorld:saveDict:'
                      'cache:] through objc_msgSendSuper2 with its own-class '
                      'superref and returns nil on a nil super result' +
                      ('' if shape == 'super_only' else
                       ', then calls [self initSubDerivedItems]') +
                      ' before returning self; reads no CFString key and '
                      'writes no own ivar'),
        })
    return {
        'schema': 1, 'batch': 'b3h', 'elf_sha256': SHA,
        'pic_base': f'0x{BASE:08x}',
        'method': 'five more initWithWorld:dynamicWorld:saveDict:cache: '
                  'forwarders — super-only and initSubDerivedItems shapes '
                  '(batch b3h)',
        'selector': SELECTOR,
        'census': {'selector_methods': 43, 'selector_words': 10976,
                   'covered_after_b3h': 11, 'words_covered_after_b3h': 784,
                   'remaining_methods': 32, 'remaining_words': 10192},
        'shapes': {'super_only': ['SurfaceBlock', 'PassengerCar', 'HandCar'],
                   'super_plus_initSubDerivedItems': ['Mirror',
                                                      'SnowSurfaceBlock']},
        'classes': out,
        'claim': (
            'Five more implementations of '
            'initWithWorld:dynamicWorld:saveDict:cache: (SurfaceBlock 57w, '
            'PassengerCar 60w, HandCar 60w, Mirror 71w, SnowSurfaceBlock 71w; '
            '319 words total) share one behavioural shape — objc_msgSendSuper2 '
            'to [super initWithWorld:dynamicWorld:saveDict:cache:] with the '
            'own-class superref, nil guard returning nil, then return self — '
            'with three of them being super-only and two (Mirror, '
            'SnowSurfaceBlock) additionally calling [self '
            'initSubDerivedItems] (the second post-init hook name of the line, '
            'alongside b3f\'s loadDerivedStuff). Their runtime superclasses '
            'resolve in-file to DynamicObject / TrainCar / TrainCar / '
            'InteractionObject / DynamicObject, i.e. the selector is a pure '
            'forwarding convention across unrelated hierarchies rather than '
            'one shared body; none reads a CFString key or writes an ivar; '
            'static level-A evidence only'),
    }


MUTATIONS = [
    ('b3h_surface_super_call', 0x00812E64 + 37 * 4, bytes.fromhex('37ff2fe1'),
     'SurfaceBlock: word 37 drift'),
    ('b3h_passenger_cmp', 0x0081BCC8 + 46 * 4, bytes.fromhex('e1510001'),
     'PassengerCar: word 46 drift'),
    ('b3h_handcar_return_branch', 0x00A4F564 + 50 * 4, bytes.fromhex('ea000002'),
     'HandCar: word 50 drift'),
    ('b3h_mirror_hook_call', 0x00A9F434 + 59 * 4, bytes.fromhex('33ff2fe1'),
     'Mirror: word 59 drift'),
    ('b3h_snow_hook_store', 0x00D8D89C + 56 * 4, bytes.fromhex('e58d000d'),
     'SnowSurfaceBlock: word 56 drift'),
    ('b3h_snow_superref', 0x00e8bf38, bytes.fromhex('00000000'),
     'superref'),
    ('b3h_mirror_selector_cell', 0x00e856c0, bytes.fromhex('00000000'),
     'selref drift'),
    ('b3h_passenger_hook_absence', 0x0081BCC8 + 47 * 4,
     bytes.fromhex('1a000003'), 'PassengerCar: word 47 drift'),
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
    print(f'b3h self-test: {len(MUTATIONS)}/{len(MUTATIONS)} mutations detected')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--output', type=Path,
                    default=NATIVE / 'forwarder5b_initwithworld.json')
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
    print('b3h five forwarders (3 super-only, 2 with initSubDerivedItems) gated')


if __name__ == '__main__':
    main()
