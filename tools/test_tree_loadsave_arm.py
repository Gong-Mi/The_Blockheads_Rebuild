#!/usr/bin/env python3
"""Execute the ORIGINAL ARM `-[Tree loadSaveDictValues:]` (0x004c2df0, 748
words) under Unicorn — STAGE 1: empty treeFruit array plus the isStaticTree
gate — and compare the planted fields against the recovered C++
(reconstruction/recovered/tree_load_save_dict.cpp at -O0 and -O2).

Executed from the original binary: the four scalar chains (treeSeasonOffset@84
word, dead@104 byte, timeDied@112 64-bit, removeCheckCount@120 float), the
treeFruit fetch, the fruitCount@128 reset, the real `bl 0x1c2924` memset veneer
(patched to a stub that records its arguments) and
`countByEnumeratingWithState:objects:count:`, which returns 0 for the empty
array so the record loop is skipped, then the isStaticTree gate.

Stubbed messages: objectForKey: (fake dictionary), intValue / floatValue /
boolValue / doubleValue (per-key boxes), isStaticTree on self, the enumeration
call, and the memset/objc_enumerationMutation veneer slots. Deferred to the
next stage: the gene/growth block for non-static trees and the per-fruit
12-byte records (needs the local helper 0x00a12f24, `tileIsKindOfSelf:` and the
64-bit uniqueID@40 identity check).
"""
import argparse
import ctypes
import hashlib
import json
import struct
import subprocess
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR,
                               UC_ARM_REG_PC, UC_ARM_REG_C1_C0_2,
                               UC_ARM_REG_FPEXC)

SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
IMP = 0x004C2DF0
BOUNDARY = 0x004C39A0
GOT_MSGSEND = 0x0105B7A0
MEMSET_SLOT = 0x0105FB70           # 0x1c2924 veneer → memset
MUTATION_SLOT = 0x0105FD1C         # 0x1c2e28 veneer → objc_enumerationMutation
TREE_INSTANCE_SIZE = 136
FIELDS = {'treeSeasonOffset': (84, 'word'), 'dead': (104, 'byte'),
          'timeDied': (112, 'double'), 'removeCheckCount': (120, 'float'),
          'height': (60, 'word'), 'age': (96, 'float'),
          'fruitCount': (128, 'word')}
# Always-on key order observed by execution (batch b4d): the four scalars, the
# fruit array, then height and age — the isStaticTree gate only guards the
# *remaining* gene/growth family.
DICT_KEYS = ['treeSeasonOffset', 'dead', 'timeDied', 'removeCheckCount',
             'treeFruit', 'height', 'age']
# Gene/growth keys belong to the non-static branch. They are registered with
# zero values so a mis-gated run still completes and reports the key order
# instead of dying on an unknown key (TREE_DEBUG=1 prints that order).
GENE_KEYS = ['maxHeightReached', 'growthRateGene', 'maxHeightGene', 'maxHeight',
             'growthRate', 'growthCounter', 'height', 'age', 'maxAge']
DEBUG = bool(__import__('os').environ.get('TREE_DEBUG'))

# Same inputs as the C++ contract test (empty fruit array, static trees).
CASES = [
    {'treeSeasonOffset': 0, 'dead': 0, 'timeDied': 0.0, 'removeCheckCount': 0.0,
     'height': 0, 'age': 0.0},
    {'treeSeasonOffset': 1, 'dead': 1, 'timeDied': 1.5, 'removeCheckCount': 2.5,
     'height': 12, 'age': 3.5},
    {'treeSeasonOffset': -7, 'dead': 0, 'timeDied': -0.25, 'removeCheckCount': 1234.5,
     'height': -9, 'age': -2.5},
    {'treeSeasonOffset': 2147483647, 'dead': 1, 'timeDied': 1.0e9,
     'removeCheckCount': -1.5, 'height': 2147483647, 'age': 1.5},
    {'treeSeasonOffset': -2147483648, 'dead': 0,
     'timeDied': 1.7976931348623157e308,
     'removeCheckCount': 3.4028234663852886e38,
     'height': -2147483648, 'age': 7.25},
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    ap.add_argument('--output-dir', type=Path, required=True)
    a = ap.parse_args()
    if hashlib.sha256(a.elf.read_bytes()).hexdigest() != SHA:
        raise SystemExit('ELF SHA mismatch')
    a.output_dir.mkdir(parents=True, exist_ok=True)

    with a.elf.open('rb') as f:
        elf = ELFFile(f)
        assert elf['e_machine'] == 'EM_ARM' and elf.elfclass == 32
        loads = [(s['p_vaddr'], s['p_memsz'], s.data())
                 for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']

    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.reg_write(UC_ARM_REG_C1_C0_2, uc.reg_read(UC_ARM_REG_C1_C0_2) | (0xF << 20))
    uc.reg_write(UC_ARM_REG_FPEXC, 0x40000000)
    pages = set()
    for base, size, _ in loads:
        pages.update(range(base & ~4095, (base + size + 4095) & ~4095, 4096))
    for page in sorted(pages):
        uc.mem_map(page, 4096)
    for base, _, data in loads:
        uc.mem_write(base, data)

    graph, stack, stop = 0x60000000, 0x70000000, 0x71000000
    stub_msg, stub_memset, stub_mutation = 0x72000000, 0x72100000, 0x72200000
    for base, size in ((graph, 0x20000), (stack, 0x10000), (stop, 0x1000),
                       (stub_msg, 0x1000), (stub_memset, 0x1000),
                       (stub_mutation, 0x1000)):
        uc.mem_map(base, size)
    sel_region = 0x73000000
    uc.mem_map(sel_region, 0x1000)

    def word(at, value):
        uc.mem_write(at, struct.pack('<I', value & 0xffffffff))

    def read_word(at):
        return int.from_bytes(bytes(uc.mem_read(at, 4)), 'little')

    word(GOT_MSGSEND, stub_msg)
    word(MEMSET_SLOT, stub_memset)
    word(MUTATION_SLOT, stub_mutation)

    self_ptr = graph
    save_dict = graph + 0x8000
    array_box = graph + 0x9000
    items_page = graph + 0x10000
    boxes = {key: graph + 0x4000 + i * 0x100
             for i, key in enumerate(DICT_KEYS + GENE_KEYS)}
    selectors = {}
    for i, name in enumerate(DICT_KEYS + GENE_KEYS + ['objectForKey:', 'intValue',
                                          'floatValue', 'boolValue',
                                          'doubleValue', 'isStaticTree',
                                          'countByEnumeratingWithState:objects:count:']):
        addr = sel_region + i * 0x60
        selectors[name] = addr
        uc.mem_write(addr, name.encode() + b'\0')
    context = {}
    calls = {'memset': [], 'enumerate': 0, 'keys': [], 'messages': []}

    def hook(uc_, address, size, data):
        if address == stub_memset:
            dest = uc_.reg_read(UC_ARM_REG_R0)
            byte = uc_.reg_read(UC_ARM_REG_R1) & 0xff
            length = uc_.reg_read(UC_ARM_REG_R2)
            calls['memset'].append({'dest': f'0x{dest:08x}', 'byte': byte,
                                    'length': length})
            uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))
            return
        if address == stub_mutation:
            raise AssertionError('objc_enumerationMutation called unexpectedly')
        recv = uc_.reg_read(UC_ARM_REG_R0)
        sel_ptr = uc_.reg_read(UC_ARM_REG_R1)
        sel = bytes(uc_.mem_read(sel_ptr, 96)).split(b'\0')[0].decode()
        calls['messages'].append(sel)
        if sel == 'objectForKey:':
            arg = uc_.reg_read(UC_ARM_REG_R2)
            key = bytes(uc_.mem_read(arg, 32)).split(b'\0')[0].decode('latin-1')
            if key not in boxes:
                data_ptr = read_word(arg + 8)
                key = bytes(uc_.mem_read(data_ptr, 32)).split(b'\0')[0].decode()
            assert recv in (save_dict,), ('objectForKey receiver', hex(recv))
            assert key in boxes, key
            calls['keys'].append(key)
            uc_.reg_write(UC_ARM_REG_R0, boxes[key])
        elif sel in ('intValue', 'floatValue', 'boolValue', 'doubleValue'):
            key = next((k for k, v in boxes.items() if v == recv), None)
            if key is None and recv == array_box:
                key = 'treeFruit'
            assert key is not None, ('box receiver', hex(recv))
            value = context.get(key, 0) if key != 'treeFruit' else array_box
            if sel == 'intValue':
                uc_.reg_write(UC_ARM_REG_R0, int(value) & 0xffffffff)
            elif sel == 'boolValue':
                uc_.reg_write(UC_ARM_REG_R0, 1 if value else 0)
            elif sel == 'floatValue':
                uc_.reg_write(UC_ARM_REG_R0,
                              struct.unpack('<I', struct.pack('<f', value))[0])
            else:
                lo, hi = struct.unpack('<II', struct.pack('<d', float(value)))
                uc_.reg_write(UC_ARM_REG_R0, lo)
                uc_.reg_write(UC_ARM_REG_R1, hi)
        elif sel == 'isStaticTree':
            assert recv == self_ptr, ('isStaticTree receiver', hex(recv))
            uc_.reg_write(UC_ARM_REG_R0, context['isStaticTree'])
        elif sel == 'countByEnumeratingWithState:objects:count:':
            state = uc_.reg_read(UC_ARM_REG_R2)
            calls['enumerate'] += 1
            # NSFastEnumerationState on ARM32: {state@0, itemsPtr@4,
            # mutationsPtr@8, extra[5]@12}. Empty array → return 0.
            word(state + 0, 0)
            word(state + 4, items_page)
            word(state + 8, items_page + 0x100)
            uc_.reg_write(UC_ARM_REG_R0, 0)
        else:
            raise AssertionError(('unimplemented message', hex(recv), sel))
        uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

    for addr in (stub_msg, stub_memset, stub_mutation):
        uc.hook_add(UC_HOOK_CODE, hook, begin=addr, end=addr + 4)

    repo = Path(__file__).resolve().parents[1]
    fns = []
    for opt in (0, 2):
        lib = a.output_dir / f'tree_load-O{opt}.so'
        subprocess.run(['clang++', '-std=c++17', f'-O{opt}', '-UNDEBUG',
                        '-fno-fast-math', '-ffp-contract=off', '-fPIC', '-shared',
                        '-I' + str(repo / 'reconstruction/recovered'),
                        str(repo / 'tools/tree_load_save_dict_arm_bridge.cpp'),
                        str(repo / 'reconstruction/recovered/tree_load_save_dict.cpp'),
                        '-o', str(lib)], check=True)
        cdll = ctypes.CDLL(str(lib))
        cdll.recovered_tree_load_stage1.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        fns.append(cdll.recovered_tree_load_stage1)

    class In(ctypes.Structure):
        _fields_ = [('season_offset', ctypes.c_int32), ('dead', ctypes.c_int32),
                    ('time_died', ctypes.c_double),
                    ('remove_check_count', ctypes.c_float),
                    ('height', ctypes.c_int32), ('age', ctypes.c_float),
                    ('fruit_array_count', ctypes.c_int32),
                    ('is_static_tree', ctypes.c_int32)]

    class Out(ctypes.Structure):
        _fields_ = [('tree_season_offset', ctypes.c_int32),
                    ('dead', ctypes.c_uint8), ('time_died', ctypes.c_double),
                    ('remove_check_count', ctypes.c_float),
                    ('height', ctypes.c_int32), ('age', ctypes.c_float),
                    ('fruit_count', ctypes.c_int32),
                    ('gene_block_skipped', ctypes.c_int32)]

    def read_field(name):
        addr, kind = FIELDS[name]
        if kind == 'word':
            return struct.unpack('<i', bytes(uc.mem_read(self_ptr + addr, 4)))[0]
        if kind == 'float':
            return struct.unpack('<f', bytes(uc.mem_read(self_ptr + addr, 4)))[0]
        if kind == 'double':
            return struct.unpack('<d', bytes(uc.mem_read(self_ptr + addr, 8)))[0]
        return struct.unpack('<B', bytes(uc.mem_read(self_ptr + addr, 1)))[0]

    rows = []
    for case in CASES:
        context.clear()
        context.update(case)
        context['isStaticTree'] = 1
        calls['memset'].clear()
        calls['keys'].clear()
        calls['messages'].clear()
        calls['enumerate'] = 0
        uc.mem_write(self_ptr, b'\x00' * TREE_INSTANCE_SIZE)
        sp = stack + 0x8000
        uc.reg_write(UC_ARM_REG_R0, self_ptr)
        uc.reg_write(UC_ARM_REG_R1, selectors['objectForKey:'])
        uc.reg_write(UC_ARM_REG_R2, save_dict)
        uc.reg_write(UC_ARM_REG_SP, sp)
        uc.reg_write(UC_ARM_REG_LR, stop)
        uc.emu_start(IMP, stop, count=500000)
        assert uc.reg_read(UC_ARM_REG_PC) == stop, 'method did not return'
        arm = {name: read_field(name) for name in FIELDS}
        if DEBUG:
            print('keys:', calls['keys'])
            print('messages:', calls['messages'])
        # The gate: a static tree must never ask for the gene/growth keys.
        extra = set(calls['keys']) - set(DICT_KEYS)
        if extra:
            raise AssertionError(('gene keys requested for a static tree',
                                  sorted(extra), calls['keys']))
        assert 'isStaticTree' in calls['messages'], calls['messages']
        arm['gene_block_skipped'] = 1
        arm['memset_calls'] = list(calls['memset'])
        arm['enumerate_calls'] = calls['enumerate']
        inp = In(season_offset=case['treeSeasonOffset'], dead=case['dead'],
                 time_died=case['timeDied'],
                 remove_check_count=case['removeCheckCount'],
                 height=case['height'], age=case['age'],
                 fruit_array_count=0, is_static_tree=1)
        cpp_results = []
        for fn in fns:
            out = Out()
            fn(ctypes.byref(inp), ctypes.byref(out))
            cpp_results.append({'treeSeasonOffset': out.tree_season_offset,
                                'dead': out.dead, 'timeDied': out.time_died,
                                'removeCheckCount': out.remove_check_count,
                                'height': out.height, 'age': out.age,
                                'fruitCount': out.fruit_count,
                                'gene_block_skipped': out.gene_block_skipped})
        for cpp in cpp_results:
            for name in FIELDS:
                assert arm[name] == cpp[name], (case, name, arm[name], cpp[name])
            assert cpp['treeSeasonOffset'] == case['treeSeasonOffset']
            assert cpp['dead'] == case['dead']
            assert cpp['fruitCount'] == 0
            assert cpp['gene_block_skipped'] == 1
        rows.append({'inputs': case, 'arm': {k: arm[k] for k in FIELDS},
                     'memset_calls': arm['memset_calls'],
                     'enumerate_calls': arm['enumerate_calls'],
                     'keys_requested': sorted(set(calls['keys'])),
                     'cpp': cpp_results[0]})

    report = {
        'sha256': SHA, 'class': 'Tree', 'method': 'loadSaveDictValues:',
        'stage': 1, 'entry': f'0x{IMP:08x}', 'boundary': f'0x{BOUNDARY:08x}',
        'cases': len(rows), 'match': True,
        'covered': ('scalar chains (@84 word, @104 byte, @112 64-bit, @120 float), '
                    'treeFruit fetch, fruitCount@128 reset, real 0x1c2924 memset '
                    'veneer, countByEnumeratingWithState:objects:count: with an '
                    'empty array, isStaticTree gate (gene block skipped — the '
                    'requested key set is asserted to contain no gene keys)'),
        'deferred': ('gene/growth block for non-static trees; per-fruit 12-byte '
                     'records (needs helper 0x00a12f24, tileIsKindOfSelf: and the '
                     '64-bit uniqueID@40 identity check)'),
        'boundary': ('Unicorn execution of the original 748-word method with a '
                     'synthetic save dictionary and an empty fruit array. Not '
                     'Foundation, not the original-app runtime, not device '
                     'gameplay; the dictionary, boxes and array are stubs.'),
        'rows': rows,
    }
    (a.output_dir / 'tree-loadsave-arm-result.json').write_text(
        json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('sha256', 'stage', 'cases',
                                             'match')}, indent=2))


if __name__ == '__main__':
    main()
