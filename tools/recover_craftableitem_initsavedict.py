#!/usr/bin/env python3
"""Hash-gated read-back evidence for batch b3c: the craftable-item family
`- [initWithSaveDict:]` (deserialisation side of the b2* save batches) —

  CraftableItemObject          0x00ac7900 ( 85 w)
  PaintingCraftableItemObject  0x00741e18 (103 w)
  BlockheadCraftableItemObject 0x00810f10 (788 w, incl. local helper 0x8112d8)

Shapes decoded from the instruction stream:

CraftableItemObject (super @selector(init), then blob):
  self = [super init]; if (!self) return nil;
  [[saveDict objectForKey:@"craftableItem"] getBytes:&self->craftableItem
   length:124]   (0x7c)  → 124-byte inline struct at craftableItem@4.
PaintingCraftableItemObject (super @selector(initWithSaveDict:), then):
  self->imageData@128        = [[saveDict objectForKey:@"imageData"] retain]
  self->outputImageData@132  = [[saveDict objectForKey:@"outputImageData"]
                                 retain]
BlockheadCraftableItemObject (super @selector(initWithSaveDict:), then):
  self->name@128 = [[saveDict objectForKey:@"name"] retain]
  skinOptions@132 is a 20-byte (0x14) inline struct with a DUAL source:
    - blob present: [data getBytes:&self->skinOptions length:20]
    - blob absent (beq 0x8110ec): four scalar keys are converted —
      isMale → boolValue → sxtb, headIndex/skinIndex/hairStyleIndex →
      intValue — and passed to local helper 0x8112d8(&local, isMale,
      headIndex, skinIndex, stack=hairStyleIndex); the helper's 20-byte
      result is memcpy'd (0x1c2894) into self+132. The helper's internal
      packing is listed but NOT decoded in this batch.

Every gate is word-gated against the SHA-256-pinned ELF; the CFString pool of
each method is asserted by exact set equality (positive + negative control),
super calls resolve through the __objc_superrefs slot of the own class, and
--self-test mutates eleven sites that must each fail the run.
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

METHODS = [
    ('CraftableItemObject', 0x00AC7900, 0x00AC7A54, 'super_init_then_blob'),
    ('PaintingCraftableItemObject', 0x00741E18, 0x00741FB4, 'super_init_then_retain'),
    ('BlockheadCraftableItemObject', 0x00810F10, 0x00811B60, 'dual_source_skinoptions'),
]

EXPECTED_SUPER = {
    'CraftableItemObject': None,           # root class: superclass word is NIL
    'PaintingCraftableItemObject': 'CraftableItemObject',
    'BlockheadCraftableItemObject': 'CraftableItemObject',
}

# class-struct facts from the pinned ELF (class_ro_t): start/size must agree
# with the ivar offsets this batch restores
CLASS_META = {
    'CraftableItemObject': {'instance_start': 4, 'instance_size': 128,
                            'root': True},
    'PaintingCraftableItemObject': {'instance_start': 128, 'instance_size': 136,
                                    'root': False},
    'BlockheadCraftableItemObject': {'instance_start': 128, 'instance_size': 152,
                                     'root': False},
}
# restored record end must equal the class instance size
RECORD_FIT = {
    'CraftableItemObject': (4, 124),          # craftableItem@4 + 124 bytes
    'PaintingCraftableItemObject': (128, 8),  # imageData@128 + output@132
    'BlockheadCraftableItemObject': (132, 20),  # skinOptions@132 + 20 bytes
}

KEY_CELLS = {
    'CraftableItemObject': {'craftableItem': 0x00F9B7B8},
    'PaintingCraftableItemObject': {'imageData': 0x00F8CEB8,
                                    'outputImageData': 0x00F8CEC8},
    'BlockheadCraftableItemObject': {'isMale': 0x00F91E38,
                                     'headIndex': 0x00F91E48,
                                     'skinIndex': 0x00F91E58,
                                     'hairStyleIndex': 0x00F91E68,
                                     'name': 0x00F91E18,
                                     'skinOptions': 0x00F91E28},
}

EXPECTED_IVAR_SLOTS = {
    'CraftableItemObject': {'OBJC_IVAR_$_CraftableItemObject.craftableItem': 4},
    'PaintingCraftableItemObject': {
        'OBJC_IVAR_$_PaintingCraftableItemObject.imageData': 128,
        'OBJC_IVAR_$_PaintingCraftableItemObject.outputImageData': 132},
    'BlockheadCraftableItemObject': {
        'OBJC_IVAR_$_BlockheadCraftableItemObject.name': 128,
        'OBJC_IVAR_$_BlockheadCraftableItemObject.skinOptions': 132},
}

# super-init dispatch: (selector, superref_slot, call_site, call_word)
SUPER_INIT = {
    'CraftableItemObject': ('init', 0x00E8BE74, 0x00AC7958, 'e12fff3e'),
    'PaintingCraftableItemObject': ('initWithSaveDict:', 0x00E8BD0C,
                                    0x00741E74, 'e12fff3e'),
    'BlockheadCraftableItemObject': ('initWithSaveDict:', 0x00E8BD6C,
                                     0x00810F6C, 'e12fff3e'),
}
GOT_SUPER2 = 0x0105B79C

# nil guard: (cmp_site, cmp_word, bne_site, bne_word, target)
NIL_GUARD = {
    'CraftableItemObject': (0x00AC7970, 'e1510000', 0x00AC7974, '1a000002',
                            0x00ac7984),
    'PaintingCraftableItemObject': (0x00741E8C, 'e1510000', 0x00741E90,
                                    '1a000002', 0x00741ea0),
    'BlockheadCraftableItemObject': (0x00810F84, 'e1510000', 0x00810F88,
                                     '1a000002', 0x00810f98),
}

# key chains for the simple paths:
# (key, form, conv, ofk_site, ofk_word, conv_site, conv_word, store_site,
#  store_word, store_kind, ivar_offset, extra)
CHAINS = {
    'CraftableItemObject': [
        ('craftableItem', 'blob_getbytes', 'getBytes:length:',
         0x00AC79E0, 'e12fff34', 0x00AC7A18, 'e12fff3c', 0x00AC7A18,
         'e12fff3c', 'blob_store', 4, {'length': 124,
                                       'length_movw_site': '0x00ac7984'}),
    ],
    'PaintingCraftableItemObject': [
        ('imageData', 'retain_object', 'retain', 0x00741F10, 'e12fff36',
         0x00741F20, 'e12fff32', 0x00741F34, 'e5810000', 'word_store', 128,
         {}),
        ('outputImageData', 'retain_object', 'retain', 0x00741F4C, 'e12fff33',
         0x00741F5C, 'e12fff32', 0x00741F70, 'e5810000', 'word_store', 132,
         {}),
    ],
    'BlockheadCraftableItemObject': [
        ('name', 'retain_object', 'retain', 0x00811004, 'e12fff3c',
         0x00811014, 'e12fff32', 0x00811028, 'e5810000', 'word_store', 128,
         {}),
    ],
}

# BlockheadCraftableItemObject skinOptions dual-source gates
SKIN_GATES = [
    ('data_objectforkey', 0x00811040, 'e12fff33'),
    ('data_nil_cmp', 0x00811048, 'e1500001'),
    ('blob_absent_beq', 0x0081104C, '0a000026'),
    ('blob_len_movw_20', 0x00811050, 'e3003014'),
    ('blob_objectforkey', 0x008110AC, 'e12fff34'),
    ('blob_getbytes_call', 0x008110E4, 'e12fff3c'),
    ('blob_path_exit_branch', 0x008110E8, 'ea000063'),
    ('scalar_ofk_ismale', 0x00811180, 'e12fff34'),
    ('scalar_conv_ismale_boolvalue', 0x00811190, 'e12fff32'),
    ('scalar_store_ismale_local', 0x00811194, 'e54b0035'),
    ('scalar_ofk_headindex', 0x008111AC, 'e12fff33'),
    ('scalar_conv_headindex_intvalue', 0x008111BC, 'e12fff32'),
    ('scalar_ofk_skinindex', 0x008111D8, 'e12fff33'),
    ('scalar_conv_skinindex_intvalue', 0x008111E8, 'e12fff32'),
    ('scalar_ofk_hairstyleindex', 0x00811204, 'e12fff33'),
    ('scalar_conv_hairstyleindex_intvalue', 0x00811214, 'e12fff32'),
    ('scaler_dest_add', 0x00811228, 'e0800002'),
    ('scalar_sxtb_ismale', 0x00811244, 'e6af1072'),
    ('pack_helper_call', 0x0081125C, 'eb00001d'),
    ('memcpy_len_movw_20', 0x00811260, 'e3002014'),
    ('memcpy_call', 0x00811278, 'ebe6c585'),
]
PACK_HELPER = {'imp': 0x008112D8, 'code_words': 353,
               'args': 'r0=&local struct, r1=isMale(sxtb), r2=headIndex, '
                       'r3=skinIndex, [sp]=hairStyleIndex',
               'result_bytes': 20, 'memcpy': '0x001c2894',
               'decoded_in_batch': False,
               'gates': [('helper_prologue', 0x008112D8, 'e92d4830'),
                         ('helper_movw_r5_2', 0x008112F8, 'e3005002')]}

FORBIDDEN_KEYS = {
    'CraftableItemObject': {'skinOptions', 'name', 'imageData'},
    'PaintingCraftableItemObject': {'craftableItem', 'skinOptions'},
    'BlockheadCraftableItemObject': {'craftableItem', 'imageData',
                                     'outputImageData'},
}

SAVE_SIDE_CANDIDATES = [
    'item_savedict_keys.json',
    'subclass_savedict_keys_b2c.json', 'subclass_savedict_keys_b2d.json',
    'subclass_savedict_keys_b2e.json', 'subclass_savedict_keys_b2f.json',
    'subclass_savedict_keys_b2g.json', 'subclass_savedict_keys_b2h.json',
    'subclass_savedict_keys_b2i.json', 'subclass_savedict_keys_b2j.json',
    'subclass_savedict_keys_b2k.json', 'subclass_savedict_keys_b2l.json',
    'subclass_savedict_keys_b2m.json', 'subclass_savedict_keys_b2n.json',
    'subclass_savedict_keys_b2o.json', 'subclass_savedict_keys_b2p.json',
    'subclass_savedict_inventory.json', 'tree_savedict_keys.json',
]


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


def save_side_entry(cls):
    for fname in SAVE_SIDE_CANDIDATES:
        p = NATIVE / fname
        if not p.exists():
            continue
        for e in find_class_entry(json.loads(p.read_text()), cls):
            return fname, e
    return None, None


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

    def slot_of_ivar(self, name):
        for a, v in self.ivar_slots.items():
            if v[0] == name:
                return a
        raise ValueError(f'ivar symbol missing: {name}')

    def super_class_of(self, class_object):
        ptr = self.rw(class_object + 4)
        name = self.classes.get(ptr)
        return name.replace('OBJC_CLASS_$_', '') if name else f'?0x{(ptr or 0):08x}'

    def literal_cells(self, lo, hi):
        keys, selrefs, ivars, classes, got = {}, {}, {}, {}, {}
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
            wv = self.rw(t)
            if wv is not None and wv in self.ivar_slots:
                ivars[lit] = (t, self.ivar_slots[wv][0], self.rw(wv))
                continue
            if wv is not None and wv in self.classes:
                classes[lit] = (t, self.classes[wv])
                continue
            if wv is not None and self.m.selectors.get(wv):
                selrefs[lit] = (t, self.m.selectors[wv])
        return {'keys': keys, 'selrefs': selrefs, 'ivars': ivars,
                'classes': classes, 'got': got}


def recover(elf):
    classes_out = []
    for cls, imp, boundary, style in METHODS:
        row = elf.rows.get(imp)
        if row is None or row[1] != cls or row[3] != 'initWithSaveDict:':
            raise ValueError(f'{cls}: method-map drift')
        if min(i for i in elf.imps if i > imp) != boundary:
            raise ValueError(f'{cls}: boundary drift')
        cells = elf.literal_cells(imp, boundary)

        # ---- CFString pool: exact set equality
        expected_cells = KEY_CELLS[cls]
        found = {k: lit for lit, (t, k, ln) in cells['keys'].items() if k}
        if set(found) != set(expected_cells):
            raise ValueError(f'{cls}: key set drift {set(found) ^ set(expected_cells)}')
        for lit, (t, k, ln) in cells['keys'].items():
            if k is None or ln != len(k.encode()):
                raise ValueError(f'{cls}: CFString payload drift at 0x{lit:08x}')
        pools = {}
        for k, want in expected_cells.items():
            t = cells['keys'][found[k]][0]
            if t != want:
                raise ValueError(f'{cls}: {k} cell drift 0x{t:08x} != 0x{want:08x}')
            pools[k] = f'0x{t:08x}'
        for forbidden in FORBIDDEN_KEYS[cls]:
            if forbidden in found:
                raise ValueError(f'{cls}: forbidden key read back: {forbidden}')

        # ---- super init dispatch (own-class superref)
        sel_name, slot, call_site, call_word = SUPER_INIT[cls]
        rel_cell = elf.rel.get(slot, [])
        if not any(ty == 23 for ty, _ in rel_cell):
            raise ValueError(f'{cls}: superref slot lacks R_ARM_RELATIVE')
        target = elf.rw(slot) or 0
        cls_name = elf.classes.get(target, '')
        if cls_name != f'OBJC_CLASS_$_{cls}':
            raise ValueError(f'{cls}: superref target drift {cls_name}')
        if elf.m.imports.get(GOT_SUPER2) != 'objc_msgSendSuper2':
            raise ValueError(f'{cls}: msgSendSuper2 GOT drift')
        if not elf.word_eq(call_site, call_word):
            raise ValueError(f'{cls}: super call word drift')
        runtime_super = elf.super_class_of(target)
        meta = CLASS_META[cls]
        sup_word = elf.rw(target + 4) or 0
        if meta['root']:
            if sup_word != 0 or runtime_super != '?0x00000000':
                raise ValueError(f'{cls}: root-class superclass word drift')
            runtime_super = None
        elif runtime_super != EXPECTED_SUPER[cls]:
            raise ValueError(f'{cls}: runtime super drift {runtime_super}')
        ro = elf.rw(target + 16) or 0
        i_start, i_size = elf.rw(ro + 4) or 0, elf.rw(ro + 8) or 0
        if (i_start, i_size) != (meta['instance_start'], meta['instance_size']):
            raise ValueError(f'{cls}: class instance layout drift '
                             f'{i_start}/{i_size}')
        off, size = RECORD_FIT[cls]
        if off + size != i_size:
            raise ValueError(f'{cls}: restored record does not fill instance')
        class_facts = {'superref_slot': f'0x{slot:08x}',
                       'class_object': cls_name,
                       'class_struct': f'0x{target:08x}',
                       'runtime_superclass': runtime_super,
                       'root_class': meta['root'],
                       'instance_start': i_start, 'instance_size': i_size,
                       'record_fit': [off, size]}

        # ---- nil guard
        cmp_site, cmp_w, bne_site, bne_w, target_pc = NIL_GUARD[cls]
        if not elf.word_eq(cmp_site, cmp_w):
            raise ValueError(f'{cls}: nil cmp drift')
        if not elf.word_eq(bne_site, bne_w):
            raise ValueError(f'{cls}: nil bne drift')
        # bne must branch past the return-zero block
        delta = (int.from_bytes((elf.rw(bne_site) or 0).to_bytes(4, 'little')[0:3],
                                'little') << 2) + 8
        if bne_site + delta - 0x800000 + 0x800000 != target_pc:
            raise ValueError(f'{cls}: nil bne target drift')

        # ---- key chains
        chains = []
        for (key, form, conv, ofk, ofk_w, cs, cs_w, store, store_w, kind,
             off, extra) in CHAINS[cls]:
            for site, want, what in ((ofk, ofk_w, 'objectForKey'),
                                     (cs, cs_w, 'conversion'),
                                     (store, store_w, 'store')):
                if not elf.word_eq(site, want):
                    raise ValueError(f'{cls}.{key}: {what} word drift @0x{site:08x}')
            ivar = f'OBJC_IVAR_$_{cls}.{key}'
            if (elf.rw(elf.slot_of_ivar(ivar)) or -1) != off:
                raise ValueError(f'{cls}.{key}: ivar offset drift')
            entry = {'key': key, 'form': form, 'conversion': conv,
                     'cfstring_object': pools[key],
                     'objectforkey_site': f'0x{ofk:08x}',
                     'conversion_site': f'0x{cs:08x}',
                     'ivar': ivar, 'ivar_offset': off,
                     'store_site': f'0x{store:08x}', 'store_kind': kind}
            entry.update(extra)
            chains.append(entry)

        extra_out = {}
        if cls == 'CraftableItemObject':
            if not elf.word_eq(0x00AC7984, 'e300307c'):
                raise ValueError('CraftableItemObject: blob length drift')
            if not elf.word_eq(0x00AC79F8, 'e0811003'):
                raise ValueError('CraftableItemObject: dest add drift')
            extra_out['blob'] = {'key': 'craftableItem', 'length': 124,
                                 'length_word': 'e300307c',
                                 'dest_site': '0x00ac79f8'}
        if cls == 'BlockheadCraftableItemObject':
            for name, site, wh in SKIN_GATES:
                if not elf.word_eq(site, wh):
                    raise ValueError(f'BlockheadCraftableItemObject gate {name} drift')
            for name, site, wh in PACK_HELPER['gates']:
                if not elf.word_eq(site, wh):
                    raise ValueError(f'pack helper gate {name} drift')
            extra_out['skin_options'] = {
                'ivar': 'OBJC_IVAR_$_BlockheadCraftableItemObject.skinOptions',
                'ivar_offset': 132, 'record_bytes': 20,
                'dual_source': True,
                'blob_path': {'objectforkey_site': '0x00811040',
                              'nil_cmp_site': '0x00811048',
                              'blob_absent_branch': '0x0081104c',
                              'length_movw_site': '0x00811050',
                              'getbytes_site': '0x008110e4'},
                'scalar_path': {'entry_branch_target': '0x008110ec',
                                'scalars': [
                                    {'key': 'isMale', 'conversion': 'boolValue',
                                     'objectforkey_site': '0x00811180',
                                     'conversion_site': '0x00811190',
                                     'local_byte_store': '0x00811194',
                                     'sxtb_site': '0x00811244'},
                                    {'key': 'headIndex', 'conversion': 'intValue',
                                     'objectforkey_site': '0x008111ac',
                                     'conversion_site': '0x008111bc'},
                                    {'key': 'skinIndex', 'conversion': 'intValue',
                                     'objectforkey_site': '0x008111d8',
                                     'conversion_site': '0x008111e8'},
                                    {'key': 'hairStyleIndex',
                                     'conversion': 'intValue',
                                     'objectforkey_site': '0x00811204',
                                     'conversion_site': '0x00811214'}],
                                'dest_add_site': '0x00811228',
                                'helper_call_site': '0x0081125c',
                                'memcpy_site': '0x00811278',
                                'memcpy_len_movw_site': '0x00811260'},
                'pack_helper': {**PACK_HELPER,
                                'imp': f"0x{PACK_HELPER['imp']:08x}"},
            }

        # ---- structural census
        sels = {name for _, name in cells['selrefs'].values()}
        ivar_found = {name: off for _, (t, name, off) in cells['ivars'].items()}
        for name, want in EXPECTED_IVAR_SLOTS[cls].items():
            if (elf.rw(elf.slot_of_ivar(name)) or -1) != want:
                raise ValueError(f'{cls}: {name} offset drift')
        if ivar_found != EXPECTED_IVAR_SLOTS[cls]:
            raise ValueError(f'{cls}: ivar-slot drift {ivar_found}')
        if 'objc_msgSendSuper2' not in {n for _, n in cells['got'].values()}:
            raise ValueError(f'{cls}: super2 GOT cell missing')

        # ---- save-side cross reference
        src, save_entry = save_side_entry(cls)
        save_keys = (save_entry or {}).get('keys') or []
        write_set = {k['key'] for k in save_keys}
        read_set = set(pools)
        classes_out.append({
            'class': cls, 'imp': f'0x{imp:08x}', 'boundary': f'0x{boundary:08x}',
            'code_words': (boundary - imp) // 4, 'style': style,
            'selector': 'initWithSaveDict:',
            'super_class': runtime_super,
            'super_init': {'selector': sel_name,
                           'superref_slot': f'0x{slot:08x}',
                           'class_object': cls_name,
                           'runtime_superclass': runtime_super,
                           'got_slot': f'0x{GOT_SUPER2:08x}',
                           'call_site': f'0x{call_site:08x}',
                           **class_facts},
            'nil_guard': {'cmp_site': f'0x{cmp_site:08x}',
                          'bne_site': f'0x{bne_site:08x}',
                          'continue_target': f'0x{target_pc:08x}'},
            'keys': chains,
            'pool_keys': sorted(pools), 'pool_key_cells': pools,
            'selrefs': sorted(sels),
            'save_side': {'source': src, 'style': (save_entry or {}).get('style'),
                          'keys': sorted(write_set),
                          'write_only': sorted(write_set - read_set),
                          'read_only': sorted(read_set - write_set)},
            **extra_out,
        })
    return {
        'schema': 1, 'batch': 'b3c', 'elf_sha256': SHA,
        'pic_base': f'0x{BASE:08x}',
        'method': 'craftable-item family initWithSaveDict: read-back evidence '
                  '(batch b3c)',
        'classes': classes_out,
        'claim': (
            'The three craftable-item deserialisers call their own-class '
            'super init through objc_msgSendSuper2 (CraftableItemObject via '
            'selector(init), the two subclasses via '
            'selector(initWithSaveDict:)), return nil when that init returns '
            'nil, then restore their state: CraftableItemObject copies a '
            '124-byte inline struct out of the craftableItem NSData blob via '
            'getBytes:length:, PaintingCraftableItemObject retains the '
            'imageData/outputImageData objects into ivars 128/132, and '
            'BlockheadCraftableItemObject retains name@128 then fills its '
            '20-byte skinOptions@132 record from either the skinOptions blob '
            '(getBytes:length: 20) or, when that blob is absent, from the '
            'scalar keys isMale/headIndex/skinIndex/hairStyleIndex converted '
            'and packed by local helper 0x008112d8 whose 20-byte result is '
            'memcpy-ed into the ivar (helper internals not decoded in this '
            'batch); static level-A evidence only, no runtime roundtrip'),
    }


MUTATIONS = [
    ('cio_blob_length_immediate', 0x00AC7984, bytes.fromhex('e3003080'),
     'blob length drift'),
    ('cio_getbytes_site_register', 0x00AC7A18, bytes.fromhex('e12fff3d'),
     'craftableItem: conversion word drift'),
    ('cio_nil_branch_target', 0x00AC7974, bytes.fromhex('1a000003'),
     'nil bne drift'),
    ('cio_superref_target', 0x00E8BE74, bytes.fromhex('1004e900'),
     'superref target drift'),
    ('ptg_imagedata_ivar_offset', 'ivar:OBJC_IVAR_$_PaintingCraftableItemObject.imageData',
     bytes.fromhex('84000000'), 'offset drift'),
    ('ptg_retain_site', 0x00741F20, bytes.fromhex('e12fff33'),
     'imageData: conversion word drift'),
    ('bhc_skinoptions_branch', 0x0081104C, bytes.fromhex('0a000027'),
     'blob_absent_beq drift'),
    ('bhc_scalar_sxtb', 0x00811244, bytes.fromhex('e6af1073'),
     'scalar_sxtb_ismale drift'),
    ('bhc_memcpy_call', 0x00811278, bytes.fromhex('ebe6c584'),
     'memcpy_call drift'),
    ('bhc_name_key_cell', 0x008112B0, bytes.fromhex('2023f3ff'),
     'key set drift'),
    ('bhc_skinoptions_ivar_offset',
     'ivar:OBJC_IVAR_$_BlockheadCraftableItemObject.skinOptions',
     bytes.fromhex('88000000'), 'offset drift'),
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
    print(f'b3c self-test: {len(MUTATIONS)}/{len(MUTATIONS)} mutations detected')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--output', type=Path,
                    default=NATIVE / 'craftableitem_initsavedict.json')
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
    print('b3c classes=3 keys=4 (craftableItem blob / imageData+outputImageData '
          'retain / name retain + skinOptions dual source)')


if __name__ == '__main__':
    main()
