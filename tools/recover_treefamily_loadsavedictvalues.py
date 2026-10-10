#!/usr/bin/env python3
"""Hash-gated read-back evidence for batch b3b: the remaining tree-family
`- [loadSaveDictValues:]` methods that b3a left open —

  Plant      0x009554a0 (332 w)
  GemTree    0x005293ec ( 99 w)
  CactusTree 0x00b534b4 (157 w)
  CoconutTree 0x00a99a40 ( 29 w)

Every claim is gated on the SHA-256-pinned ELF: method-map rows and
boundaries, per-key objectForKey:/conversion/store site words, the CFString
pool of each method body (exact set equality = negative control), the
ivar-offset storage slots, the objc_msgSendSuper2 cells, the class hierarchy
resolved from the class structs, and the save-side key sets of the matching
b2* batches (read/write asymmetry computed, not asserted from memory).

Shapes decoded from the instruction stream:

Plant -[loadSaveDictValues:] (own keys only, NO super call):
  seasonOffset@68        objectForKey → intValue   → str  r0,[r1]
  age@72                 objectForKey → floatValue → vstr s0,[r0]
  gatherProgress@80      objectForKey → intValue   → str
  hasFloweredThisSeason@84 objectForKey → boolValue → strb
  flowering@85           objectForKey → boolValue  → strb
  frozen@76              objectForKey → boolValue  → strb
  maxAgeGene@54          objectForKey → intValue   → strh, then
                         clamp(gene, 1, 255) via local helper 0x004c0b70
                         (movw #1 / movw #0xff staged at 0x009554b4/b8)
  growthRateGene@56      objectForKey → intValue   → strh, then same clamp
  saveTime               objectForKey → doubleValue → NO ivar store; the
                         value feeds  [self.world worldTime] - saveTime
                         > 1800.0  (vsub/vcmpe/ble) and on that branch
                         hasFloweredThisSeason@84 is RESET to 0.
  save-only stamps growthRate/maxAge are NOT read (pool negative control).

GemTree: own keys FIRST (gemTreeType@136 str, fruitYear@140 str), then
  [super loadSaveDictValues:] via objc_msgSendSuper2 whose class field is
  the __objc_superrefs slot for OBJC_CLASS_$_GemTree (runtime super = Tree).
CactusTree: [super loadSaveDictValues:] FIRST, then own keys splitHeightA@136
  (str), splitHeightB@140 (str), splitDirection@144 (strb), availableFood@148
  (vstr s0).
CoconutTree: pure super forwarder — no own keys at all (0 CFString cells).

Read-side asymmetry established for the family (computed from the b2*/b3a
JSONs in the same run): Tree write-only {saveTime}; Plant write-only
{maxAge, growthRate} (derived caches re-derived from the genes).
Bounded claim: static level-A read chains; no runtime roundtrip.
"""
import argparse
import hashlib
import io
import json
import struct
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

# (Imp, boundary, class, selector) rows this batch owns; boundary = next IMP
# in the pinned method map.
METHODS = [
    ('Plant', 0x009554A0, 0x009559D0, 'own_keys_no_super'),
    ('GemTree', 0x005293EC, 0x00529578, 'own_keys_then_super'),
    ('CactusTree', 0x00B534B4, 0x00B53728, 'super_then_own_keys'),
    ('CoconutTree', 0x00A99A40, 0x00A99AB4, 'super_forward_only'),
]

# class -> resolved superclass name from the class struct (word at +4)
EXPECTED_SUPER = {
    'Plant': 'DynamicObject', 'Tree': 'DynamicObject',
    'GemTree': 'Tree', 'CactusTree': 'Tree', 'CoconutTree': 'Tree',
}

# key -> (conv, ofk_site, ofk_word, conv_site, conv_word, store_site,
#         store_word, store_kind, ivar_offset)
CHAINS = {
    'Plant': [
        ('seasonOffset', 'intValue', 0x00955610, 'e12fff33', 0x00955620,
         'e12fff32', 0x00955634, 'e5810000', 'word_store', 68),
        ('age', 'floatValue', 0x0095564C, 'e12fff33', 0x0095565C,
         'e12fff32', 0x00955674, 'ed800a00', 'float_store', 72),
        ('gatherProgress', 'intValue', 0x0095568C, 'e12fff33', 0x0095569C,
         'e12fff32', 0x009556B0, 'e5810000', 'word_store', 80),
        ('hasFloweredThisSeason', 'boolValue', 0x009556C8, 'e12fff33',
         0x009556D8, 'e12fff32', 0x009556EC, 'e5c10000', 'byte_store', 84),
        ('flowering', 'boolValue', 0x00955704, 'e12fff33', 0x00955714,
         'e12fff32', 0x00955728, 'e5c10000', 'byte_store', 85),
        ('frozen', 'boolValue', 0x00955740, 'e12fff33', 0x00955750,
         'e12fff32', 0x00955764, 'e5c10000', 'byte_store', 76),
        ('maxAgeGene', 'intValue', 0x0095577C, 'e12fff33', 0x0095578C,
         'e12fff32', 0x009557A0, 'e1c100b0', 'halfword_store', 54),
        ('growthRateGene', 'intValue', 0x009557B8, 'e12fff33', 0x009557C8,
         'e12fff32', 0x009557DC, 'e1c100b0', 'halfword_store', 56),
    ],
    'GemTree': [
        ('gemTreeType', 'intValue', 0x005294B4, 'e12fff37', 0x005294C4,
         'e12fff32', 0x005294D8, 'e5810000', 'word_store', 136),
        ('fruitYear', 'intValue', 0x005294F0, 'e12fff33', 0x00529500,
         'e12fff32', 0x00529514, 'e5810000', 'word_store', 140),
    ],
    'CactusTree': [
        ('splitHeightA', 'intValue', 0x00B535FC, 'e12fff34', 0x00B5360C,
         'e12fff32', 0x00B53620, 'e5810000', 'word_store', 136),
        ('splitHeightB', 'intValue', 0x00B53638, 'e12fff33', 0x00B53648,
         'e12fff32', 0x00B5365C, 'e5810000', 'word_store', 140),
        ('splitDirection', 'boolValue', 0x00B53674, 'e12fff33', 0x00B53684,
         'e12fff32', 0x00B53698, 'e5c10000', 'byte_store', 144),
        ('availableFood', 'floatValue', 0x00B536B0, 'e12fff33', 0x00B536C0,
         'e12fff32', 0x00B536D8, 'ed800a00', 'float_store', 148),
    ],
    'CoconutTree': [],
}

# key -> CFString object slot address (from the literal-pool census of the
# method body; the tool re-derives these cells and asserts equality)
KEY_CELLS = {
    'Plant': {
        'seasonOffset': 0x00F954F8, 'age': 0x00F95508,
        'gatherProgress': 0x00F95518, 'hasFloweredThisSeason': 0x00F95528,
        'flowering': 0x00F95538, 'frozen': 0x00F95548,
        'maxAgeGene': 0x00F95558, 'growthRateGene': 0x00F95568,
        'saveTime': 0x00F95578,
    },
    'GemTree': {'gemTreeType': 0x00F79468, 'fruitYear': 0x00F79478},
    'CactusTree': {
        'splitHeightA': 0x00F9D988, 'splitHeightB': 0x00F9D998,
        'splitDirection': 0x00F9D9A8, 'availableFood': 0x00F9D9B8,
    },
    'CoconutTree': {},
}

# Plant-only literal: the world-clock key read but never stored into an ivar
PLANT_SAVE_TIME_KEY = 'saveTime'

SUPER_FORWARD = {
    'GemTree': {
        'class_slot': 0x00E8BC54, 'class_object': 'OBJC_CLASS_$_GemTree',
        'selector_cell': 0x00E7D988, 'got_slot': 0x0105B79C,
        'receiver_site': '0x00529520', 'receiver_word': 'e50b0030',
        'class_store_site': '0x0052952c', 'class_store_word': 'e50b102c',
        'call_site': '0x00529540', 'call_word': 'e12fff33',
    },
    'CactusTree': {
        'class_slot': 0x00E8BEA8, 'class_object': 'OBJC_CLASS_$_CactusTree',
        'selector_cell': 0x00E86A14, 'got_slot': 0x0105B79C,
        'receiver_site': '0x00b534f8', 'receiver_word': 'e50b0030',
        'class_store_site': '0x00b53500', 'class_store_word': 'e50b002c',
        'call_site': '0x00b53510', 'call_word': 'e12fff3e',
    },
    'CoconutTree': {
        'class_slot': 0x00E8BE50, 'class_object': 'OBJC_CLASS_$_CoconutTree',
        'selector_cell': 0x00E85598, 'got_slot': 0x0105B79C,
        'receiver_site': '0x00a99a84', 'receiver_word': 'e58d0000',
        'class_store_site': '0x00a99a8c', 'class_store_word': 'e58d0004',
        'call_site': '0x00a99a98', 'call_word': 'e12fff3e',
    },
}

# Plant-only gates: gene clamp helper, bound staging, saveTime comparison,
# conditional reset of hasFloweredThisSeason.
PLANT_GATES = [
    ('bound_lo_movw_1', 0x009554B4, 'e300c001'),
    ('bound_hi_movw_ff', 0x009554B8, 'e300e0ff'),
    ('clamp_maxagegene_call', 0x009557FC, 'ebedacdb'),
    ('clamp_maxagegene_store', 0x00955828, 'e1ce00b0'),
    ('clamp_growthrategene_call', 0x0095583C, 'ebedaccb'),
    ('clamp_growthrategene_store', 0x00955894, 'e1c800b0'),
    ('savetime_objectforkey', 0x009558C8, 'e12fff36'),
    ('savetime_conv', 0x009558D8, 'e12fff32'),
    ('world_receiver_add', 0x009558F0, 'e0800002'),
    ('worldtime_call', 0x00955904, 'e12fff33'),
    ('vsub_f64', 0x00955918, 'ee311b42'),
    ('vcmpe_f64', 0x00955928, 'eeb41bc2'),
    ('ble_gate', 0x00955930, 'da000007'),
    ('reset_hfts_store', 0x00955950, 'e5c10000'),
]
# clamp helper 0x004c0b70 (leaf): out=v; if v>b out=b; if v<a out=a; bx lr
CLAMP_HELPER = {
    'imp': 0x004C0B70,
    'gates': [('out_store', 0x004C0B84, 'e58d0000'),
              ('cmp_upper', 0x004C0B90, 'e1500001'),
              ('ble_upper', 0x004C0B94, 'da000001'),
              ('cmp_lower', 0x004C0BA8, 'e1500001'),
              ('bge_lower', 0x004C0BAC, 'aa000001'),
              ('bx_lr', 0x004C0BC0, 'e12fff1e')],
    'bounds_arg_order': 'arg1=low, arg2=high (call sites pass movw #1 / movw #0xff)',
}
SAVE_TIME_RESET = {
    'key': 'saveTime', 'conversion': 'doubleValue',
    'objectforkey_site': '0x009558c8', 'conversion_site': '0x009558d8',
    'world_ivar': 'OBJC_IVAR_$_DynamicObject.world', 'world_ivar_offset': 4,
    'world_time_selector': 'worldTime', 'world_time_call_site': '0x00955904',
    'subtract_site': '0x00955918', 'compare_site': '0x00955928',
    'branch_site': '0x00955930', 'skip_branch_target': '0x00955954',
    'threshold_double': 1800.0,
    'threshold_words': ['0x00955960:0x00000000', '0x00955964:0x409c2000'],
    'reset_ivar': 'OBJC_IVAR_$_Plant.hasFloweredThisSeason',
    'reset_store_site': '0x00955950', 'reset_value': 0,
    'semantics': 'if (world.worldTime - saveTime > 1800.0) '
                 'hasFloweredThisSeason = 0',
}

EXPECTED_SELREFS = {
    'Plant': {'objectForKey:', 'intValue', 'floatValue', 'boolValue',
              'doubleValue', 'worldTime'},
    'GemTree': {'loadSaveDictValues:', 'objectForKey:', 'intValue'},
    'CactusTree': {'loadSaveDictValues:', 'objectForKey:', 'intValue',
                   'boolValue', 'floatValue'},
    'CoconutTree': {'loadSaveDictValues:'},
}

EXPECTED_IVAR_SLOTS = {
    'Plant': {'OBJC_IVAR_$_Plant.seasonOffset': 68, 'OBJC_IVAR_$_Plant.age': 72,
              'OBJC_IVAR_$_Plant.gatherProgress': 80,
              'OBJC_IVAR_$_Plant.hasFloweredThisSeason': 84,
              'OBJC_IVAR_$_Plant.flowering': 85, 'OBJC_IVAR_$_Plant.frozen': 76,
              'OBJC_IVAR_$_Plant.maxAgeGene': 54,
              'OBJC_IVAR_$_Plant.growthRateGene': 56,
              'OBJC_IVAR_$_DynamicObject.world': 4},
    'GemTree': {'OBJC_IVAR_$_GemTree.gemTreeType': 136,
                'OBJC_IVAR_$_GemTree.fruitYear': 140},
    'CactusTree': {'OBJC_IVAR_$_CactusTree.splitHeightA': 136,
                   'OBJC_IVAR_$_CactusTree.splitHeightB': 140,
                   'OBJC_IVAR_$_CactusTree.splitDirection': 144,
                   'OBJC_IVAR_$_CactusTree.availableFood': 148},
    'CoconutTree': {},
}

# method body -> CFString keys that must NOT appear (negative controls)
FORBIDDEN_KEYS = {
    'Plant': {'maxAge', 'growthRate'},            # save-only derived stamps
    'GemTree': {'saveTime', 'pos.x', 'pos.y'},    # Tree-side stamps
    'CactusTree': {'saveTime', 'treeFruit'},
    'CoconutTree': {'saveTime'},
}

# save-side cross-reference (write sets come from the closed b2* batches)
SAVE_SIDE = {
    'Plant': [('subclass_savedict_keys_b2l.json', 'Plant')],
    'GemTree': [('tree_savedict_keys.json', 'GemTree')],
    'CactusTree': [('subclass_savedict_keys_b2h.json', 'CactusTree')],
    'CoconutTree': [('subclass_savedict_inventory.json', 'CoconutTree')],
    'Tree': [('subclass_savedict_keys_b2o.json', 'Tree')],
}
TREE_READ_SOURCE = 'tree_loadsavedictvalues.json'      # b3a
TREE_READ_SUBKEYS = {'pos.x', 'pos.y', 'hasCreatedFreeBlockThisSeason'}


def signed(v):
    return v - (1 << 32) if v & 0x80000000 else v


def find_class_entry(obj, cls):
    if isinstance(obj, dict):
        if obj.get('class') == cls:
            yield obj
        for v in obj.values():
            yield from find_class_entry(v, cls)
    elif isinstance(obj, list):
        for v in obj:
            yield from find_class_entry(v, cls)


def save_side_keys(fname, cls):
    return save_side_entry(fname, cls).get('keys') or []


def save_side_entry(fname, cls):
    data = json.loads((NATIVE / fname).read_text())
    for e in find_class_entry(data, cls):
        return e
    raise ValueError(f'{cls} not found in {fname}')


class ELF:
    def __init__(self, path):
        self.path = path
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
        self.rows = {}
        tsv = (NATIVE / 'libApplication_objc_methods.tsv').read_text().splitlines()[1:]
        self.imps = sorted(int(l.split('\t')[0], 16) for l in tsv)
        for l in tsv:
            f = l.split('\t')
            self.rows[int(f[0], 16)] = f

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
        """Shallow copy with `new_bytes` written at `vaddr` (in-memory only).
        Used by --self-test to prove the gates fail on altered input."""
        import copy
        clone = copy.copy(self)
        clone.m = copy.copy(self.m)
        clone.m.data = bytearray(self.m.data)
        off = self.offset_of(vaddr)
        clone.m.data[off:off + len(new_bytes)] = new_bytes
        clone.m.data = bytes(clone.m.data)
        return clone

    def rebase(self, cell):
        return (BASE + signed(self.rw(cell) or 0)) & 0xFFFFFFFF

    def literal_cells(self, lo, hi):
        """Classify every PC-relative literal cell in a method body."""
        keys, selrefs, ivars, classes, got, other = {}, {}, {}, {}, {}, {}
        for a in range(lo, hi, 4):
            w = self.rw(a) or 0
            if w & 0x0FFF0000 != 0x059F0000 or (w >> 12) & 0xF == 15:
                continue
            lit = (a + 8 + (w & 0xFFF)) & 0xFFFFFFFF
            t = self.rebase(lit)
            imp = self.m.imports.get(t)
            if imp:
                got[lit] = (t, imp)
                continue
            rel_t = self.rel.get(t, [])
            owned = [n for ty, n in rel_t if ty == 2 and n.startswith('OBJC_IVAR_$_')]
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
                ivars[lit] = (t, self.ivar_slots[wv][0], self.ivar_slots[wv][1])
                continue
            if wv is not None and wv in self.classes:
                classes[lit] = (t, self.classes[wv])
                continue
            if wv is not None and self.m.selectors.get(wv):
                selrefs[lit] = (t, self.m.selectors[wv])
                continue
            other[lit] = (t, wv)
        return {'keys': keys, 'selrefs': selrefs, 'ivars': ivars,
                'classes': classes, 'got': got, 'other': other}

    def super_class_of(self, class_object):
        ptr = self.rw(class_object + 4)
        name = self.classes.get(ptr)
        if not name:
            return f'?0x{(ptr or 0):08x}'
        return name.replace('OBJC_CLASS_$_', '')

    def slot_of_ivar(self, name):
        for a, v in self.ivar_slots.items():
            if v[0] == name:
                return a
        raise ValueError(f'ivar symbol missing: {name}')


def recover(elf):
    classes_out = []
    for cls, imp, boundary, style in METHODS:
        row = elf.rows.get(imp)
        if row is None or row[1] != cls or row[3] != 'loadSaveDictValues:':
            raise ValueError(f'{cls}: method-map drift')
        if min(i for i in elf.imps if i > imp) != boundary:
            raise ValueError(f'{cls}: boundary drift')
        cells = elf.literal_cells(imp, boundary)

        # ---- CFString pool: exact set equality (positive + negative control)
        expected_cells = KEY_CELLS[cls]
        found = {k: lit for lit, (t, k, ln) in cells['keys'].items() if k}
        if set(found) != set(expected_cells):
            raise ValueError(f'{cls}: key set drift {set(found) ^ set(expected_cells)}')
        for lit, (t, k, ln) in cells['keys'].items():
            if k is None:
                raise ValueError(f'{cls}: unresolved CFString payload at 0x{lit:08x}')
            if ln != len(k.encode()):
                raise ValueError(f'{cls}: CFString length drift for {k!r}')
        pools = {}
        for k, want in expected_cells.items():
            lit = found[k]
            t = cells['keys'][lit][0]
            if t != want:
                raise ValueError(f'{cls}: {k} cell drift 0x{t:08x} != 0x{want:08x}')
            pools[k] = f'0x{t:08x}'
        for forbidden in FORBIDDEN_KEYS[cls]:
            if forbidden in found:
                raise ValueError(f'{cls}: forbidden key read back: {forbidden}')
        # duplicate-cell sanity: a key must not share a pool cell with another
        if len(set(pools.values())) != len(pools):
            raise ValueError(f'{cls}: duplicate CFString cells')

        # ---- key chains
        chains = []
        for (key, conv, ofk, ofk_w, cs, cs_w, store, store_w, kind,
             off) in CHAINS[cls]:
            if not elf.word_eq(ofk, ofk_w):
                raise ValueError(f'{cls}.{key}: objectForKey word drift @0x{ofk:08x}')
            if not elf.word_eq(cs, cs_w):
                raise ValueError(f'{cls}.{key}: conversion word drift @0x{cs:08x}')
            if not elf.word_eq(store, store_w):
                raise ValueError(f'{cls}.{key}: store word drift @0x{store:08x}')
            if not (imp <= ofk < cs < store < boundary):
                raise ValueError(f'{cls}.{key}: site order drift')
            ivar = f'OBJC_IVAR_$_{cls}.{key}'
            if (elf.rw(elf.slot_of_ivar(ivar)) or -1) != off:
                raise ValueError(f'{cls}.{key}: ivar offset drift')
            chains.append({
                'key': key, 'conversion': conv,
                'cfstring_object': pools[key],
                'objectforkey_site': f'0x{ofk:08x}',
                'conversion_site': f'0x{cs:08x}',
                'ivar': ivar, 'ivar_offset': off,
                'store_site': f'0x{store:08x}', 'store_kind': kind,
            })

        # ---- super forward
        sup = None
        if cls in SUPER_FORWARD:
            s = SUPER_FORWARD[cls]
            rel_cell = elf.rel.get(s['class_slot'], [])
            if not any(ty == 23 for ty, _ in rel_cell):
                raise ValueError(f'{cls}: superref slot lacks R_ARM_RELATIVE')
            if (elf.rw(s['class_slot']) or 0) != next(
                    a for a, n in elf.classes.items() if n == s['class_object']):
                raise ValueError(f'{cls}: superref target drift')
            if elf.m.imports.get(s['got_slot']) != 'objc_msgSendSuper2':
                raise ValueError(f'{cls}: msgSendSuper2 GOT drift')
            if elf.m.selectors.get(elf.rw(s['selector_cell']) or 0) != 'loadSaveDictValues:':
                raise ValueError(f'{cls}: super selector cell drift')
            for name in ('receiver_site', 'class_store_site', 'call_site'):
                if not elf.word_eq(int(s[name], 16), s[name.replace('_site', '_word')]):
                    raise ValueError(f'{cls}: {name} word drift')
            runtime_super = elf.super_class_of(elf.rw(s['class_slot']))
            if runtime_super != EXPECTED_SUPER[cls]:
                raise ValueError(f'{cls}: runtime super drift {runtime_super}')
            sup = {
                'dispatch': 'objc_msgSendSuper2',
                'selector': 'loadSaveDictValues:',
                'selector_cell': f"0x{s['selector_cell']:08x}",
                'got_slot': f"0x{s['got_slot']:08x}",
                'superref_slot': f"0x{s['class_slot']:08x}",
                'class_object': s['class_object'],
                'runtime_superclass': runtime_super,
                'receiver_store_site': s['receiver_site'],
                'class_store_site': s['class_store_site'],
                'call_site': s['call_site'],
            }
        # own-key / super call ordering, derived from the site addresses
        if not CHAINS[cls]:
            order = SUP_ORDER[cls]
        elif sup is None:
            order = 'own_keys_no_super'
        else:
            own_sites = [c[2] for c in CHAINS[cls]] + [c[4] for c in CHAINS[cls]]
            order = ('own_then_super'
                     if max(own_sites) < int(sup['call_site'], 16)
                     else 'super_then_own')
        if order != SUP_ORDER[cls]:
            raise ValueError(f'{cls}: super/own order drift {order}')

        # ---- structural census: selrefs / ivar slots / GOT cells
        sels = {name for _, name in cells['selrefs'].values()}
        if sels != EXPECTED_SELREFS[cls]:
            raise ValueError(f'{cls}: selref drift {sels ^ EXPECTED_SELREFS[cls]}')
        ivar_found = {}
        for _, (t, name, off) in cells['ivars'].items():
            ivar_found[name] = off
        # live check first: gives the precise message on an altered offset
        for name, want in EXPECTED_IVAR_SLOTS[cls].items():
            if (elf.rw(elf.slot_of_ivar(name)) or -1) != want:
                raise ValueError(f'{cls}: {name} offset drift')
        if ivar_found != EXPECTED_IVAR_SLOTS[cls]:
            raise ValueError(f'{cls}: ivar-slot drift {ivar_found}')
        got_names = {name for _, name in cells['got'].values()}
        if CHAINS[cls] and 'objc_msgSend' not in got_names:
            raise ValueError(f'{cls}: objc_msgSend GOT cell missing')

        # ---- Plant-only structural gates
        extra = {}
        if cls == 'Plant':
            for name, site, wh in PLANT_GATES:
                if not elf.word_eq(site, wh):
                    raise ValueError(f'Plant gate {name} drift @0x{site:08x}')
            for name, site, wh in CLAMP_HELPER['gates']:
                if not elf.word_eq(site, wh):
                    raise ValueError(f'clamp helper gate {name} drift')
            lo_w = elf.rw(0x00955960) or 0
            hi_w = elf.rw(0x00955964) or 0
            dbl = struct.unpack('<d', struct.pack('<II', lo_w, hi_w))[0]
            if dbl != SAVE_TIME_RESET['threshold_double']:
                raise ValueError(f'threshold drift {dbl}')
            if elf.word_eq(0x00955934, 'e3000000') is False:
                raise ValueError('reset immediate drift')
            extra = {
                'save_time_read_back': True,
                'save_time_reset': dict(SAVE_TIME_RESET),
                'gene_clamp': {
                    'helper': f"0x{CLAMP_HELPER['imp']:08x}",
                    'bounds': [1, 255],
                    'bounds_arg_order': CLAMP_HELPER['bounds_arg_order'],
                    'applied': [
                        {'ivar': 'OBJC_IVAR_$_Plant.maxAgeGene',
                         'call_site': '0x009557fc',
                         'store_site': '0x00955828'},
                        {'ivar': 'OBJC_IVAR_$_Plant.growthRateGene',
                         'call_site': '0x0095583c',
                         'store_site': '0x00955894'},
                    ],
                },
            }
        if cls == 'Plant':
            # hasFloweredThisSeason is written twice: unsigned load + reset
            stores = [c['store_site'] for c in chains]
            if '0x009556ec' not in stores:
                raise ValueError('hfts load store missing')

        # ---- save-side cross reference
        src, _ = SAVE_SIDE[cls][0]
        save_entry = save_side_entry(src, cls)
        save_keys = save_entry.get('keys') or []
        write_set = {k['key'] for k in save_keys} if save_keys else set()
        read_set = set(pools)
        write_only = sorted(write_set - read_set)
        read_only = sorted(read_set - write_set)
        shared_cf = sorted({k['key'] for k in save_keys if k.get('cfstring_object')
                            and k['key'] in pools
                            and k['cfstring_object'] == pools[k['key']]})
        save_offsets = {k['key']: k.get('ivar_offset') for k in save_keys
                        if k.get('ivar_offset') is not None}
        offset_mismatch = {c['key']: (c['ivar_offset'], save_offsets[c['key']])
                           for c in chains
                           if c['key'] in save_offsets
                           and save_offsets[c['key']] != c['ivar_offset']}
        if offset_mismatch:
            raise ValueError(f'{cls}: save/load ivar offset mismatch {offset_mismatch}')
        classes_out.append({
            'class': cls, 'imp': f'0x{imp:08x}', 'boundary': f'0x{boundary:08x}',
            'code_words': (boundary - imp) // 4, 'style': style,
            'super_class': EXPECTED_SUPER[cls],
            'selector': 'loadSaveDictValues:',
            'keys': chains,
            'pool_keys': sorted(pools),
            'pool_key_cells': pools,
            'super_forward': sup,
            'own_keys_order': order,
            'site_gates': [f'{n}@0x{s:08x}' for n, s, _ in
                           (PLANT_GATES if cls == 'Plant' else [])],
            'save_side': {
                'source': src, 'style': save_entry.get('style'),
                'keys': sorted(write_set), 'write_only': write_only,
                'read_only': read_only,
                'shared_cfstring_objects': shared_cf,
            },
            **extra,
        })

    # ---- family cross reference incl. b3a Tree read set
    tree_write = {k['key'] for k in save_side_keys('subclass_savedict_keys_b2o.json', 'Tree')}
    b3a = json.loads((NATIVE / TREE_READ_SOURCE).read_text())
    tree_read = set(b3a['pool_keys']) - TREE_READ_SUBKEYS
    family = {
        'class_hierarchy': dict(EXPECTED_SUPER),
        'per_class_read_write': {},
        'asymmetries': [],
    }
    for c in ('Plant', 'Tree', 'GemTree', 'CactusTree', 'CoconutTree'):
        entry = next((e for e in classes_out if e['class'] == c), None)
        if c == 'Tree':
            r, w = tree_read, tree_write
        else:
            r = set(entry['pool_keys'])
            w = {k['key'] for k in save_side_keys(*SAVE_SIDE[c][0])}
        family['per_class_read_write'][c] = {
            'write': sorted(w), 'read': sorted(r),
            'write_only': sorted(w - r), 'read_only': sorted(r - w),
            'symmetric': sorted(w - r) == [] and sorted(r - w) == [],
        }
        if w - r:
            family['asymmetries'].append(
                {'class': c, 'write_only': sorted(w - r)})
    family['asymmetries'].append(
        {'class': 'Tree', 'read_source': TREE_READ_SOURCE,
         'note': 'b3a read set; saveTime is the write-only world-clock stamp'})
    return {
        'schema': 1, 'batch': 'b3b', 'elf_sha256': SHA,
        'pic_base': f'0x{BASE:08x}',
        'method': 'tree-family loadSaveDictValues: read-back evidence (batch b3b)',
        'classes': classes_out,
        'family': family,
        'claim': (
            'Plant/GemTree/CactusTree/CoconutTree -[loadSaveDictValues:] read '
            'their save keys back through objectForKey: + int/float/bool/'
            'doubleValue into word/byte/halfword/float ivar stores; the two '
            'Tree subclasses and CoconutTree forward to Tree through '
            'objc_msgSendSuper2 (GemTree: own keys then super; CactusTree: '
            'super then own keys; CoconutTree: super only); Plant reads '
            'saveTime (doubleValue) purely to reset hasFloweredThisSeason '
            'when worldTime - saveTime > 1800.0 and clamps both gene '
            'halfwords through local helper 0x004c0b70 to [1,255]; '
            'save-only stamps (Plant maxAge/growthRate, Tree saveTime) are '
            'proven absent by exact CFString pool set equality; static '
            'level-A only, runtime roundtrip unresolved'),
    }


SUP_ORDER = {'Plant': 'own_keys_no_super', 'GemTree': 'own_then_super',
             'CactusTree': 'super_then_own', 'CoconutTree': 'super_only'}

# Negative controls: each mutation must make recover() raise (a gate that
# cannot fail would prove nothing). vaddr -> replacement bytes.
MUTATIONS = [
    ('plant_hfts_store_opcode_flip', 0x009556EC, bytes.fromhex('e5c10001'),
     'Plant.hasFloweredThisSeason: store word drift'),
    ('plant_clamp_bound_immediate', 0x009554B8, bytes.fromhex('e300e0fe'),
     'Plant gate bound_hi_movw_ff drift'),
    ('plant_savetime_threshold_double', 0x00955964, bytes.fromhex('409c2001'),
     'threshold drift'),
    ('plant_seasonoffset_ivar_offset', 'ivar:OBJC_IVAR_$_Plant.seasonOffset',
     bytes.fromhex('4c000000'), 'offset drift'),
    ('plant_seasonoffset_pointer_cell', 0x0105C5A8, bytes.fromhex('4c000000'),
     'Plant: ivar-slot drift'),
    ('plant_reader_add_site', 0x009558F0, bytes.fromhex('e0800003'),
     'Plant gate world_receiver_add drift'),
    ('gemtree_superref_slot_target', 0x00E8BC54, bytes.fromhex('b804e900'),
     'GemTree: superref target drift'),
    ('gemtree_fruityear_key_cell_payload', 0x00529564,
     bytes.fromhex('6495f1ff'), 'GemTree: key set drift'),
    ('cactustree_conv_site_register', 0x00B53648, bytes.fromhex('e12fff33'),
     'CactusTree.splitHeightB: conversion word drift'),
    ('cactustree_splitdirection_ivar_offset',
     'ivar:OBJC_IVAR_$_CactusTree.splitDirection', bytes.fromhex('94000000'),
     'offset drift'),
    ('coconuttree_super_selector_cell', 0x00E85598, bytes.fromhex('00000000'),
     'CoconutTree: super selector cell drift'),
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
    print(f'b3b self-test: {len(MUTATIONS)}/{len(MUTATIONS)} mutations detected')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--self-test', action='store_true',
                    help='negative controls: every mutation must be caught')
    ap.add_argument('--output', type=Path,
                    default=NATIVE / 'treefamily_loadsavedictvalues.json')
    a = ap.parse_args()
    if a.self_test:
        self_test(ELF(a.elf))
        return
    text = json.dumps(recover(ELF(a.elf)), indent=2, sort_keys=True) + '\n'
    if a.check:
        if a.output.read_text() != text:
            raise SystemExit(f'stale {a.output.name}')
    else:
        a.output.write_text(text)
    print('b3b classes=4 keys=14 (Plant 8 + saveTime, GemTree 2, '
          'CactusTree 4, CoconutTree 0)')


if __name__ == '__main__':
    main()
