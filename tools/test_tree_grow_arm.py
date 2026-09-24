#!/usr/bin/env python3
"""Execute the ORIGINAL ARM `-[Tree growInTimeSinceSaved:]`
(0x004c2568, 546 words, stage 1: nil-tile path) under Unicorn with
synthetic world/dynamicWorld objects and compare the resulting instance
image and message trace against the recovered C++ contract
(reconstruction/recovered/tree_grow_in_time.cpp, built at -O0 and -O2).

Synthetic graph (stated limits — not Foundation, not the original-app
runtime):
  * `objc_msgSend` (GOT slot 0x0105b7a0) is stubbed; the body loads every
    selector from its own selref cells, so the stub dispatches on the real
    selector strings. Stubs answer isStaticTree / worldTime /
    isGrowingInCompost, script incrementHeight's height/maxHeightReached
    mutations, and record updateGrowth:'s adult flag (+ the spilled 1.0f
    the body parks at sp+0x44 = the next iteration's timeToGrow),
    sowTreeNearParent:adult:adultMaxAge:'s [sp] float, and
    removeAllOwnedTiles:.
  * The tile lookup `bl 0xa12f24` is hooked at its first instruction and
    returns nil (STAGE 1 FIXTURE): the tile-record/PRNG block and the
    0x1c3728 chain are a stage-2 slice. The hook asserts the lookup asks
    for (pos.x, pos.y + current height) — proving the body really reads
    those ivars.
  * Everything else executes for real: the isStaticTree gate, the dead
    checks, the f64 elapsed math, the maxAge comparison, the growth loop
    (growthTime formula with the pinned 0.005 constant, the increment and
    partial branches, the spilled timeToGrow), the compost/death paths and
    the timeDied f64 store.
Checked per case: the (code, arg) trace, the 120-byte instance image, and
expectations computed independently of the C++ pair (timeDied value,
sowTree adultMaxAge bits, scripted maxHeightReached, boundary branches).
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
IMP = 0x004C2568
GOT_MSGSEND = 0x0105B7A0
TILE_ACCESSOR = 0x00A12F24
IMAGE_SIZE = 120

# Trace codes — must match the C++ enum TreeGrowCall.
IS_STATIC_TREE, WORLD_TIME, INCREMENT_HEIGHT = 0, 1, 2
UPDATE_GROWTH_ADULT, UPDATE_GROWTH_NO = 3, 4
IS_GROWING_IN_COMPOST, SOW_TREE, REMOVE_ALL = 5, 6, 7

BASE = {
    'world_token': 0x51CE0004, 'dynamic_world_token': 0x51CE0005,
    'pos_x': 7, 'pos_y': 11,
    'max_age': 100.0, 'age': 10.0, 'growth_counter': 0.2,
    'growth_rate': 1.0, 'max_height': 10, 'height': 5,
    'max_height_reached': 5, 'dead': 0,
    'world_time': 0.0, 'time_since_saved': 0.0,
}
CASES = [
    {'name': 'static', 'is_static_tree': 1},
    {'name': 'dead_entry', 'dead': 1},
    {'name': 'partial', 'world_time': 50.0, 'time_since_saved': 10.0},
    {'name': 'double_increment', 'max_age': 1000.0, 'growth_counter': 0.9,
     'growth_rate': 10.0, 'height': 3, 'max_height_reached': 3,
     'world_time': 100.0, 'time_since_saved': 0.0},
    {'name': 'scripted_height_exit', 'max_age': 1000.0, 'growth_rate': 10.0,
     'height_after_increment': 10, 'max_height_reached_after_increment': 6,
     'world_time': 100.0, 'time_since_saved': 0.0},
    {'name': 'compost', 'age': 95.0, 'world_time': 200.0,
     'time_since_saved': 110.0, 'is_growing_in_compost': 1},
    {'name': 'death', 'age': 95.0, 'world_time': 200.0,
     'time_since_saved': 110.0},
    {'name': 'nan_worldtime', 'world_time': float('nan'),
     'is_growing_in_compost': 1},
    {'name': 'negative_elapsed', 'world_time': 5.0, 'time_since_saved': 10.0},
    {'name': 'boundary', 'age': 50.0, 'world_time': 60.0,
     'time_since_saved': 10.0, 'is_growing_in_compost': 1},
]


def f32bits(value):
    return struct.unpack('<I', struct.pack('<f', value))[0]


def f64bits(value):
    return struct.unpack('<Q', struct.pack('<d', value))[0]


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
    uc.reg_write(UC_ARM_REG_C1_C0_2,
                 uc.reg_read(UC_ARM_REG_C1_C0_2) | (0xF << 20))
    uc.reg_write(UC_ARM_REG_FPEXC, 0x40000000)
    pages = set()
    for base, size, _ in loads:
        pages.update(range(base & ~4095, (base + size + 4095) & ~4095, 4096))
    for page in sorted(pages):
        uc.mem_map(page, 4096)
    for base, _, data in loads:
        uc.mem_write(base, data)

    graph, stack, stop, stub = (0x60000000, 0x70000000, 0x71000000, 0x72000000)
    for base in (graph, stack, stop, stub):
        uc.mem_map(base, 0x10000 if base in (graph, stack) else 0x1000)
    cmd_region = 0x73000000
    uc.mem_map(cmd_region, 0x1000)

    def word(at, value):
        uc.mem_write(at, struct.pack('<I', value & 0xffffffff))

    self_ptr = graph
    world = graph + 0x1000
    dynamic_world = graph + 0x1100
    word(GOT_MSGSEND, stub)
    uc.mem_write(cmd_region, b'growInTimeSinceSaved:\0')

    state = {'calls': [], 'accessor': [], 'case': None}

    def hook(uc_, address, size, data):
        if address == TILE_ACCESSOR:
            # Stage-1 fixture: the tile lookup returns nil. Record the
            # requested coordinates to prove pos/height are really read.
            x = uc_.reg_read(UC_ARM_REG_R0)
            y = uc_.reg_read(UC_ARM_REG_R1)
            height_now = struct.unpack(
                '<i', bytes(uc_.mem_read(self_ptr + 60, 4)))[0]
            case = state['case']
            assert x == case['pos_x'], ('accessor x', x, case['pos_x'])
            assert y == case['pos_y'] + height_now, \
                ('accessor y', y, case['pos_y'], height_now)
            state['accessor'].append((x, y))
            uc_.reg_write(UC_ARM_REG_R0, 0)
            uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))
            return
        recv = uc_.reg_read(UC_ARM_REG_R0)
        sel_ptr = uc_.reg_read(UC_ARM_REG_R1)
        sel = bytes(uc_.mem_read(sel_ptr, 64)).split(b'\0')[0].decode()
        arg2 = uc_.reg_read(UC_ARM_REG_R2)
        sp = uc_.reg_read(UC_ARM_REG_SP)
        case = state['case']
        if sel == 'isStaticTree':
            state['calls'].append((IS_STATIC_TREE, 0))
            uc_.reg_write(UC_ARM_REG_R0, case.get('is_static_tree', 0))
        elif sel == 'worldTime':
            assert recv == case['world_token'], ('worldTime receiver', hex(recv))
            state['calls'].append((WORLD_TIME, 0))
            lo, hi = struct.unpack('<II',
                                   struct.pack('<d', case['world_time']))
            uc_.reg_write(UC_ARM_REG_R0, lo)
            uc_.reg_write(UC_ARM_REG_R1, hi)
        elif sel == 'isGrowingInCompost':
            state['calls'].append((IS_GROWING_IN_COMPOST, 0))
            uc_.reg_write(UC_ARM_REG_R0, case.get('is_growing_in_compost', 0))
        elif sel == 'incrementHeight':
            state['calls'].append((INCREMENT_HEIGHT, 0))
            hai = case.get('height_after_increment', -1)
            mhrai = case.get('max_height_reached_after_increment', -1)
            if hai >= 0:
                word(self_ptr + 60, hai)
            if mhrai >= 0:
                word(self_ptr + 64, mhrai)
            uc_.reg_write(UC_ARM_REG_R0, 0)
        elif sel == 'updateGrowth:':
            adult = arg2 & 0xff
            if adult:
                spill = struct.unpack(
                    '<f', bytes(uc_.mem_read(sp + 0x44, 4)))[0]
                state['calls'].append((UPDATE_GROWTH_ADULT, f32bits(spill)))
            else:
                state['calls'].append((UPDATE_GROWTH_NO, 0))
            uc_.reg_write(UC_ARM_REG_R0, 0)
        elif sel == 'sowTreeNearParent:adult:adultMaxAge:':
            assert recv == case['dynamic_world_token'], \
                ('sow receiver', hex(recv))
            assert arg2 == self_ptr, ('sow tree arg', hex(arg2))
            assert uc_.reg_read(UC_ARM_REG_R3) == 1, 'sow adult = 1'
            bits = struct.unpack('<I', bytes(uc_.mem_read(sp, 4)))[0]
            state['calls'].append((SOW_TREE, bits))
            uc_.reg_write(UC_ARM_REG_R0, 0)
        elif sel == 'removeAllOwnedTiles:':
            state['calls'].append((REMOVE_ALL, 0))
            uc_.reg_write(UC_ARM_REG_R0, 0)
        else:
            raise AssertionError(('unimplemented message', hex(recv), sel))
        uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

    uc.hook_add(UC_HOOK_CODE, hook, begin=stub, end=stub + 4)
    uc.hook_add(UC_HOOK_CODE, hook, begin=TILE_ACCESSOR, end=TILE_ACCESSOR + 4)

    repo = Path(__file__).resolve().parents[1]
    import os
    libcxx = Path(os.environ.get('PREFIX', '')) / 'lib/libc++_shared.so'
    if libcxx.is_file():
        ctypes.CDLL(str(libcxx), mode=ctypes.RTLD_GLOBAL)
    fns = []
    for opt in (0, 2):
        lib = a.output_dir / f'tree_grow-O{opt}.so'
        subprocess.run(['clang++', '-std=c++17', f'-O{opt}', '-UNDEBUG',
                        '-fno-fast-math', '-ffp-contract=off', '-fPIC',
                        '-shared',
                        '-I' + str(repo / 'reconstruction/recovered'),
                        str(repo / 'tools/tree_grow_in_time_arm_bridge.cpp'),
                        str(repo / 'reconstruction/recovered/tree_grow_in_time.cpp'),
                        '-o', str(lib)], check=True)
        cdll = ctypes.CDLL(str(lib))
        fn = cdll.recovered_tree_grow_run
        fn.argtypes = [ctypes.c_uint8, ctypes.c_uint8, ctypes.c_double,
                       ctypes.c_double, ctypes.c_uint8, ctypes.c_float,
                       ctypes.c_float, ctypes.c_float, ctypes.c_float,
                       ctypes.c_int32, ctypes.c_int32, ctypes.c_int32,
                       ctypes.c_int32, ctypes.c_int32, ctypes.c_uint32,
                       ctypes.c_uint32, ctypes.c_int32, ctypes.c_int32,
                       ctypes.c_char_p, ctypes.c_char_p]
        fn.restype = ctypes.c_uint32
        fns.append(fn)

    def word_at(image, off):
        return struct.unpack('<I', image[off:off + 4])[0]

    rows = []
    for case in CASES:
        merged = dict(BASE)
        merged.update({k: v for k, v in case.items() if k != 'name'})
        state['case'] = merged
        state['calls'] = []
        state['accessor'] = []

        uc.mem_write(self_ptr, b'\x00' * IMAGE_SIZE)
        word(self_ptr + 4, merged['world_token'])
        word(self_ptr + 8, merged['dynamic_world_token'])
        word(self_ptr + 16, merged['pos_x'] & 0xffffffff)
        word(self_ptr + 20, merged['pos_y'] & 0xffffffff)
        word(self_ptr + 60, merged['height'] & 0xffffffff)
        word(self_ptr + 64, merged['max_height_reached'] & 0xffffffff)
        word(self_ptr + 68, f32bits(merged['growth_counter']))
        word(self_ptr + 72, f32bits(merged['growth_rate']))
        word(self_ptr + 88, merged['max_height'] & 0xffffffff)
        word(self_ptr + 92, f32bits(merged['max_age']))
        word(self_ptr + 96, f32bits(merged['age']))
        uc.mem_write(self_ptr + 104, bytes([merged['dead'] & 0xff]))

        lo, hi = struct.unpack('<II',
                               struct.pack('<d', merged['time_since_saved']))
        sp = stack + 0x8000
        uc.reg_write(UC_ARM_REG_R0, self_ptr)
        uc.reg_write(UC_ARM_REG_R1, cmd_region)
        uc.reg_write(UC_ARM_REG_R2, lo)
        uc.reg_write(UC_ARM_REG_R3, hi)
        uc.reg_write(UC_ARM_REG_SP, sp)
        uc.reg_write(UC_ARM_REG_LR, stop)
        uc.emu_start(IMP, stop, count=500000)
        assert uc.reg_read(UC_ARM_REG_PC) == stop, 'method did not return'

        arm_image = bytes(uc.mem_read(self_ptr, IMAGE_SIZE))
        arm_trace = list(state['calls'])

        cpp_images, cpp_traces = [], []
        for fn in fns:
            image_out = ctypes.create_string_buffer(IMAGE_SIZE)
            trace_out = ctypes.create_string_buffer(32 * 8)
            n = fn(merged.get('is_static_tree', 0),
                   merged.get('is_growing_in_compost', 0),
                   merged['world_time'], merged['time_since_saved'],
                   merged['dead'], merged['max_age'], merged['age'],
                   merged['growth_counter'], merged['growth_rate'],
                   merged['max_height'], merged['height'],
                   merged['max_height_reached'], merged['pos_x'],
                   merged['pos_y'], merged['world_token'],
                   merged['dynamic_world_token'],
                   merged.get('height_after_increment', -1),
                   merged.get('max_height_reached_after_increment', -1),
                   image_out, trace_out)
            cpp_images.append(image_out.raw)
            cpp_traces.append(
                [(trace_out.raw[i * 8],
                  struct.unpack('<I', trace_out.raw[i * 8 + 4:i * 8 + 8])[0])
                 for i in range(n)])

        for image, trace in zip(cpp_images, cpp_traces):
            assert image == arm_image, (case['name'], 'image mismatch')
            assert trace == arm_trace, (case['name'], 'trace mismatch',
                                        trace, arm_trace)

        # Expectations computed independently of the recovered C++ pair.
        if case['name'] == 'death':
            assert struct.unpack('<d', arm_image[112:120])[0] == 115.0, \
                'timeDied = t + maxAge - age'
            assert (SOW_TREE, f32bits(85.0)) in arm_trace, \
                'adultMaxAge = 85.0f bits'
        if case['name'] == 'scripted_height_exit':
            assert word_at(arm_image, 64) == 10, 'mhr = max(10, 6)'
        if case['name'] == 'double_increment':
            assert sum(1 for c, _ in arm_trace if c == INCREMENT_HEIGHT) == 2
        rows.append({'case': case['name'], 'trace_len': len(arm_trace),
                     'tile_lookups': len(state['accessor'])})

    report = {
        'sha256': SHA, 'class': 'Tree', 'method': 'growInTimeSinceSaved:',
        'entry': f'0x{IMP:08x}', 'stage': 1, 'cases': len(rows), 'match': True,
        'boundary': (
            'Unicorn execution of the original 546-word method (STAGE 1: '
            'tile lookup 0xa12f24 hooked to nil, so the tile-record/PRNG '
            'block is a stage-2 slice) with synthetic world/dynamicWorld '
            'objects. The isStaticTree gate, dead checks, f64 elapsed math, '
            'maxAge comparison, growth loop (0.005-constant growthTime '
            'formula, increment/partial branches, spilled timeToGrow), '
            'compost/death paths and timeDied store execute for real. Not '
            'Foundation, not the original-app runtime, not device gameplay; '
            'incrementHeight mutations are scripted.'),
        'rows': rows,
    }
    (a.output_dir / 'tree-grow-arm-result.json').write_text(
        json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('sha256', 'cases', 'match',
                                             'boundary')}, indent=2))


if __name__ == '__main__':
    main()
