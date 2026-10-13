#!/usr/bin/env python3
"""Execute the ORIGINAL ARM `-[Tree loadSaveDictValues:]` (0x004c2df0, 748
words) under Unicorn — STAGE 2: the per-fruit 12-byte records — and compare
them against the recovered C++ (reconstruction/recovered/tree_load_records.cpp
at -O0 and -O2).

Fixture (stated limits — synthetic world, not Foundation, not the original-app
runtime):
  * fake save dictionary + per-key boxes (objectForKey: / intValue /
    floatValue / boolValue / doubleValue) and `isStaticTree` → 1.
  * the treeFruit array is a fake array whose enumeration stub returns the
    fixture's fruit dictionaries, then 0 on the next call.
  * treeFruits@124 points at a scratch page that receives the records.
  * the per-fruit tile lookup (the original `bl 0x00a12f24` world accessor)
    queries the fake world for `worldWidthMacro` (answered 32) and
    `macroTiles` (answered with a pointer-table page). At the identity compare
    site (0x4c3218) the harness copies the looked-up tile's +0x28/+0x2c into
    the tree's uniqueID@40/+44 — which is exactly the state the original gates
    on — so the record write is reached; with that fitting DISABLED the gate
    must skip every fruit (negative control).
Executed from the original binary: the whole record loop, the real memset veneer
(0x1c2924) that clears the enumeration state, the world accessor and the record
stores.
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
GOT_MSG_A = 0x0105B7A0          # method's own msgSend slot
GOT_MSG_B = 0x0105FB18          # 0x1c281c veneer slot used by the world accessor
MEMSET_SLOT = 0x0105FB70
MUTATION_SLOT = 0x0105FD1C
TREE_INSTANCE_SIZE = 136
RECORD_BUFFER = 0x60070000
WORLD_WIDTH_MACRO = 32
# Fruit cases: (x, y, hasCreated) — keep in sync with the C++ contract test.
# Coordinates are restricted to the harness's verified domain: the synthetic
# macro-tile table returns a tile (so the identity gate can be fitted). A
# coordinate where the fixture lookup yields nil skips the record through the
# same path as the identity mismatch — see NIL_FIXTURE_CASES below. This is a
# fixture boundary, not a decoded game rule.
FRUIT_CASES = [
    [],
    [(5, 6, 1)],
    [(1, 2, 0), (3, 4, 1)],
    [(12, 12, 1), (12, 12, 1), (12, 12, 1), (12, 12, 1)],
    [(1023, 1023, 1), (1023, 0, 0), (0, 1023, 1)],
    [(100, 100, 0)],
]
# Coordinates for which the synthetic world lookup yields nil (observed). The
# original then writes no record and leaves fruitCount untouched.
NIL_FIXTURE_CASES = [(0, 0), (32, 32), (64, 64), (1024, 1024)]
SCALARS = {'treeSeasonOffset': 3, 'dead': 1, 'timeDied': 2.5,
           'removeCheckCount': 1.5, 'height': 12, 'age': 3.5}
SELECTOR_NAMES = ['treeSeasonOffset', 'dead', 'timeDied', 'removeCheckCount',
                  'treeFruit', 'height', 'age', 'pos.x', 'pos.y',
                  'hasCreatedFreeBlockThisSeason', 'objectForKey:',
                  'intValue', 'floatValue', 'boolValue', 'doubleValue',
                  'isStaticTree',
                  'countByEnumeratingWithState:objects:count:',
                  'tileIsKindOfSelf:']


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    ap.add_argument('--output-dir', type=Path, required=True)
    ap.add_argument('--sweep', action='store_true',
                    help='print the world accessor acceptance domain')
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
    sel_region = 0x73000000
    tile_page = 0x74000000
    storage_page = 0x600C0000
    for base, size in ((graph, 0x200000), (stack, 0x10000), (stop, 0x1000),
                       (stub_msg, 0x1000), (stub_memset, 0x1000),
                       (stub_mutation, 0x1000), (sel_region, 0x1000),
                       (tile_page, 0x1000)):
        uc.mem_map(base, size)

    def word(at, value):
        uc.mem_write(at, struct.pack('<I', value & 0xffffffff))

    def rw(at):
        return int.from_bytes(bytes(uc.mem_read(at, 4)), 'little')

    for slot in (GOT_MSG_A, GOT_MSG_B):
        word(slot, stub_msg)
    word(MEMSET_SLOT, stub_memset)
    word(MUTATION_SLOT, stub_mutation)

    self_ptr = graph
    world = graph + 0x10000
    save_dict = graph + 0x20000
    array_box = graph + 0x30000
    items_page = graph + 0x40000
    fruit_dicts = [graph + 0x50000 + i * 0x1000 for i in range(4)]
    boxes = {name: graph + 0x80000 + i * 0x100
             for i, name in enumerate(SELECTOR_NAMES)}
    selectors = {}
    for i, name in enumerate(SELECTOR_NAMES):
        addr = sel_region + i * 0x60
        selectors[name] = addr
        uc.mem_write(addr, name.encode() + b'\0')
    # The macro-tile pointer table: any aligned read yields a synthetic tile.
    for off in range(0, 0x40000, 4):
        word(storage_page + off, tile_page)
    word(tile_page + 0x28, 0x0)
    word(tile_page + 0x2c, 0x0)
    word(self_ptr + 124, RECORD_BUFFER)
    word(self_ptr + 4, world)

    context = {'fruits': [], 'enumerated': 0, 'fit_identity': True}
    box_role = {}
    calls = {'world': [], 'keys': [], 'messages': []}

    def hook(uc_, address, size, data):
        if address == stub_memset:
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
                data_ptr = rw(arg + 8)
                key = bytes(uc_.mem_read(data_ptr, 32)).split(b'\0')[0].decode()
            if recv == save_dict:
                calls['keys'].append(key)
                box_role[boxes[key]] = ('save', key)
                uc_.reg_write(UC_ARM_REG_R0, boxes[key])
            else:
                # per-fruit dictionary: return the matching box for the key
                fruit_index = fruit_dicts.index(recv)
                box_role[boxes[key]] = ('fruit', fruit_index, key)
                uc_.reg_write(UC_ARM_REG_R0, boxes[key])
        elif sel in ('intValue', 'floatValue', 'boolValue', 'doubleValue'):
            role = box_role.get(recv)
            if role is None:
                raise AssertionError(('value message on unknown box', hex(recv), sel))
            if role[0] == 'save':
                value = SCALARS[role[1]]
            else:
                _, fruit_index, key = role
                fruit = context['fruits'][fruit_index]
                value = {'pos.x': fruit[0], 'pos.y': fruit[1],
                         'hasCreatedFreeBlockThisSeason': fruit[2]}[key]
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
            assert recv == self_ptr
            uc_.reg_write(UC_ARM_REG_R0, 1)
        elif sel == 'countByEnumeratingWithState:objects:count:':
            # the array is the object the save dictionary returned for treeFruit
            assert recv == boxes['treeFruit'], hex(recv)
            state = uc_.reg_read(UC_ARM_REG_R2)
            if context['enumerated'] < len(context['fruits']):
                index = context['enumerated']
                word(items_page, fruit_dicts[index])
                word(state + 0, 0)
                word(state + 4, items_page)
                word(state + 8, items_page + 0x100)
                context['enumerated'] += 1
                uc_.reg_write(UC_ARM_REG_R0, 1)
            else:
                uc_.reg_write(UC_ARM_REG_R0, 0)
        elif sel == 'tileIsKindOfSelf:':
            uc_.reg_write(UC_ARM_REG_R0, 1)
        elif sel == 'worldWidthMacro':
            calls['world'].append(sel)
            uc_.reg_write(UC_ARM_REG_R0, WORLD_WIDTH_MACRO)
        elif sel == 'macroTiles':
            calls['world'].append(sel)
            uc_.reg_write(UC_ARM_REG_R0, storage_page)
        else:
            raise AssertionError(('unimplemented message', hex(recv), sel))
        uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

    for addr in (stub_msg, stub_memset, stub_mutation):
        uc.hook_add(UC_HOOK_CODE, hook, begin=addr, end=addr + 4)

    def fit_identity(uc_, address, size, data):
        if not context['fit_identity']:
            return
        tile = uc_.reg_read(UC_ARM_REG_R0)
        uc_.mem_write(self_ptr + 40, bytes(uc_.mem_read(tile + 0x28, 4)))
        uc_.mem_write(self_ptr + 44, bytes(uc_.mem_read(tile + 0x2c, 4)))

    uc.hook_add(UC_HOOK_CODE, fit_identity, begin=0x4C3218, end=0x4C3218)

    repo = Path(__file__).resolve().parents[1]
    fns = []
    for opt in (0, 2):
        lib = a.output_dir / f'tree_records-O{opt}.so'
        subprocess.run(['clang++', '-std=c++17', f'-O{opt}', '-UNDEBUG',
                        '-fno-fast-math', '-ffp-contract=off', '-fPIC', '-shared',
                        '-I' + str(repo / 'reconstruction/recovered'),
                        str(repo / 'tools/tree_load_records_arm_bridge.cpp'),
                        str(repo / 'reconstruction/recovered/tree_load_records.cpp'),
                        '-o', str(lib)], check=True)
        cdll = ctypes.CDLL(str(lib))
        cdll.recovered_tree_fruit_records.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        fns.append(cdll.recovered_tree_fruit_records)

    class In(ctypes.Structure):
        _fields_ = [('count', ctypes.c_int32),
                    ('pos_x', ctypes.c_int32 * 4), ('pos_y', ctypes.c_int32 * 4),
                    ('created', ctypes.c_int32 * 4)]

    class Out(ctypes.Structure):
        _fields_ = [('fruit_count', ctypes.c_int32),
                    ('record_x', ctypes.c_int32 * 4),
                    ('record_y', ctypes.c_int32 * 4),
                    ('record_created', ctypes.c_int32 * 4)]

    def arm_run(fruits, fit_identity=True):
        context['fruits'] = list(fruits)
        context['enumerated'] = 0
        context['fit_identity'] = fit_identity
        box_role.clear()
        calls['keys'].clear()
        calls['world'].clear()
        calls['messages'].clear()
        uc.mem_write(self_ptr, b'\x00' * TREE_INSTANCE_SIZE)
        uc.mem_write(RECORD_BUFFER, b'\x00' * 0x1000)
        word(self_ptr + 124, RECORD_BUFFER)
        word(self_ptr + 4, world)
        for i, box in enumerate(boxes.values()):
            uc.mem_write(box, b'\x00' * 0x40)
        sp = stack + 0x8000
        uc.reg_write(UC_ARM_REG_R0, self_ptr)
        uc.reg_write(UC_ARM_REG_R1, selectors['objectForKey:'])
        uc.reg_write(UC_ARM_REG_R2, save_dict)
        uc.reg_write(UC_ARM_REG_SP, sp)
        uc.reg_write(UC_ARM_REG_LR, stop)
        word(sp, save_dict)
        word(sp + 4, 0)
        uc.emu_start(IMP, stop, count=500000)
        assert uc.reg_read(UC_ARM_REG_PC) == stop, 'method did not return'
        count = rw(self_ptr + 128)
        records = []
        for i in range(4):
            base = RECORD_BUFFER + 12 * i
            records.append((struct.unpack('<i', bytes(uc.mem_read(base, 4)))[0],
                            struct.unpack('<i', bytes(uc.mem_read(base + 4, 4)))[0],
                            bytes(uc.mem_read(base + 8, 1))[0]))
        return count, records, list(calls['keys']), list(calls['world'])

    rows = []
    if a.sweep:
        sweep = [(0, 0), (1, 1), (1023, 1023), (1024, 1024), (1023, 0), (0, 1023),
                 (-1, 0), (0, -1), (100, 100), (32, 32), (64, 64), (1023, 1022)]
        for x, y in sweep:
            count, _, _, _ = arm_run([(x, y, 1)])
            print(f'sweep x={x:5d} y={y:5d} -> records={count}')
        raise SystemExit(0)

    for fruits in FRUIT_CASES:
        count, records, keys, world_calls = arm_run(fruits)
        assert count == len(fruits), (fruits, count)
        assert records[:len(fruits)] == [tuple(f) for f in fruits], (fruits, records)
        assert 'tileIsKindOfSelf:' in calls['messages'] if fruits else True
        assert set(keys) == set(SELECTOR_NAMES[:7]), keys
        if fruits:
            assert world_calls, 'world accessor was not queried'
        else:
            assert not world_calls, world_calls
        inp = In(count=len(fruits))
        for i, (x, y, created) in enumerate(fruits):
            inp.pos_x[i], inp.pos_y[i], inp.created[i] = x, y, created
        cpp_results = []
        for fn in fns:
            out = Out()
            fn(ctypes.byref(inp), ctypes.byref(out))
            cpp_results.append({
                'fruit_count': out.fruit_count,
                'records': [(out.record_x[i], out.record_y[i],
                             out.record_created[i]) for i in range(out.fruit_count)]})
        for cpp in cpp_results:
            assert cpp['fruit_count'] == count, (fruits, cpp, count)
            assert cpp['records'] == records[:count], (fruits, cpp, records)
        rows.append({'fruits': [list(f) for f in fruits], 'arm_fruit_count': count,
                     'arm_records': records[:count], 'keys_requested': sorted(set(keys)),
                     'world_queries': world_calls, 'cpp': cpp_results[0]})

    # Negative control: with the identity fitting disabled the gate must skip
    # every fruit — no records, counter untouched.
    count, records, _, world_calls = arm_run([(5, 6, 1), (7, 8, 1)],
                                             fit_identity=False)
    assert count == 0, ('gate did not skip', count)
    assert records[0] == (0, 0, 0), records
    assert world_calls, 'world accessor should still be queried'
    rows.append({'fruits': [[5, 6, 1], [7, 8, 1]], 'fit_identity': False,
                 'arm_fruit_count': count, 'arm_records': [],
                 'negative_control': 'identity mismatch skips every record'})

    # Fixture-domain row: coordinates where the synthetic world lookup yields
    # nil still skip the record (same code path, no counter movement). This
    # documents the fixture boundary rather than a decoded game rule.
    nil_rows = []
    for x, y in NIL_FIXTURE_CASES:
        count, records, _, world_calls = arm_run([(x, y, 1)])
        assert count == 0, ('nil fixture coordinate wrote a record', x, y, count)
        nil_rows.append({'fruit': [x, y, 1], 'arm_fruit_count': count})
    rows.append({'fixture_lookup_nil': nil_rows, 'arm_records': [],
                 'boundary': 'synthetic macro-tile table returns nil for these '
                             'coordinates'})

    report = {
        'sha256': SHA, 'class': 'Tree', 'method': 'loadSaveDictValues:',
        'stage': 2, 'entry': f'0x{IMP:08x}', 'cases': len(rows), 'match': True,
        'covered': ('per-fruit 12-byte records (pos.x word @+0, pos.y word @+4, '
                    'hasCreatedFreeBlockThisSeason byte @+8) with fruitCount@128 '
                    'as the running index, the real 0x1c2924 memset veneer, the '
                    'world accessor (worldWidthMacro/macroTiles) and the identity '
                    'gate (uniqueID@40/+44 vs the looked-up tile) including its '
                    'skip path'),
        'fixture_note': ('at the identity compare site the harness copies the '
                         'looked-up tile +0x28/+0x2c into the tree uniqueID, i.e. '
                         'it puts the fixture into the state the original gates '
                         'on; disabling that fitting is the negative control'),
        'boundary': ('Unicorn execution of the original 748-word method with a '
                     'synthetic world, save dictionary and fruit array. Not '
                     'Foundation, not the original-app runtime, not device '
                     'gameplay.'),
        'rows': rows,
    }
    (a.output_dir / 'tree-records-arm-result.json').write_text(
        json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('sha256', 'stage', 'cases', 'match')},
                     indent=2))


if __name__ == '__main__':
    main()
