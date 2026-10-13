#!/usr/bin/env python3
"""Execute the ORIGINAL ARM body of DynamicObject -[initDerivedStuff:loadPhysicalBlockIfNeeded:]
(IMP 0x00839508, 242 words, batch b4k) under Unicorn and compare the instance image,
return value, and message trace byte-for-byte against the recovered C++ contract
(reconstruction/recovered/dynamic_object_init_derived_stuff.cpp, built at -O0 and -O2).

Synthetic model:
  * 0x00A16594 (convert world pos to macro tile coordinate) is hooked:
    writes (pos_x >> 5, pos_y >> 5) to output point struct and returns via LR.
  * 0x00A16CCC (lookupMacroTile in macroTiles table) is hooked:
    returns macro_tile_ptr in R0 and returns via LR.
  * objc_msgSend (GOT slot 0x0105B7A0) is stubbed:
    - [world macroTiles]
    - [world loadPhysicalBlockForMacroTile:atX:y:loadSurroundingBlocks:createIfNotCreated:]
    - [self shouldAddToMacroBlock]
    - [dynamicWorld loadDynamicObjectsIfNotAlreadyLoadedForMacroTile:includeSurfaceBlocks:]
    - [macroTile->dynamicObjects addObject:self]
    - [self objectType]
    - [dynamicWorld dynamicWorldChangedAtPos:objectType:]
"""
import argparse
import ctypes
import json
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from arm_harness import ARMSession, FixtureGraph
from trace_codes_gen import DYNAMIC_OBJECT_INIT_DERIVED_STUFF_CODES as TPC

SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
IMP = 0x00839508
IMAGE_SIZE = 48

GOT_MSGSEND = 0x0105B7A0
GOT_MSGSEND_VENEER = 0x0105FB18
HELPER_COORD = 0x00A16594
HELPER_LOOKUP = 0x00A16CCC

STUB_MSG = 0x72000000

SEL_MACRO_TILES = 'macroTiles'
SEL_LOAD_PHYSICAL = 'loadPhysicalBlockForMacroTile:atX:y:loadSurroundingBlocks:createIfNotCreated:'
SEL_SHOULD_ADD = 'shouldAddToMacroBlock'
SEL_LOAD_DYN = 'loadDynamicObjectsIfNotAlreadyLoadedForMacroTile:includeSurfaceBlocks:'
SEL_ADD_OBJECT = 'addObject:'
SEL_OBJECT_TYPE = 'objectType'
SEL_WORLD_CHANGED = 'dynamicWorldChangedAtPos:objectType:'

BASE = {
    'self_ptr': 0x60000000,
    'world_ptr': 0x60010000,
    'dynamic_world_ptr': 0x60020000,
    'pos_x': 100,
    'pos_y': 200,
    'macro_tile_ptr': 0x60030000,
    'physical_block_loaded': True,
    'should_add_to_macro_block': True,
    'object_type': 24,
    'init_derived_stuff': True,
    'load_physical_block_if_needed': True,
}

CASES = [
    {
        'name': 'happy_path_with_init',
        'init_derived_stuff': True,
    },
    {
        'name': 'happy_path_without_init',
        'init_derived_stuff': False,
        'object_type': 42,
    },
    {
        'name': 'nil_macro_tile',
        'macro_tile_ptr': 0,
    },
    {
        'name': 'physical_block_unloaded_do_load',
        'physical_block_loaded': False,
        'load_physical_block_if_needed': True,
    },
    {
        'name': 'physical_block_unloaded_dont_load',
        'physical_block_loaded': False,
        'load_physical_block_if_needed': False,
    },
    {
        'name': 'dont_add_to_macro_block',
        'should_add_to_macro_block': False,
    },
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    ap.add_argument('--output-dir', type=Path, required=True)
    a = ap.parse_args()
    a.output_dir.mkdir(parents=True, exist_ok=True)

    session = ARMSession(a.elf, SHA)
    uc = session.uc
    graph = FixtureGraph(uc)

    uc.mem_map(STUB_MSG, 0x1000)
    session.patch_got(GOT_MSGSEND, STUB_MSG)
    session.patch_got(GOT_MSGSEND_VENEER, STUB_MSG)

    cmd_sel = graph.command_selector('initDerivedStuff:loadPhysicalBlockIfNeeded:')

    state = {
        'case': None,
        'trace': [],
    }

    def hook(uc_, address, size, data):
        from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                                       UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_PC,
                                       UC_ARM_REG_LR)
        case = state['case']

        if address == HELPER_COORD:
            pt_out = uc_.reg_read(UC_ARM_REG_R0)
            x = uc_.reg_read(UC_ARM_REG_R1)
            y = uc_.reg_read(UC_ARM_REG_R2)
            session.word(pt_out + 0, x >> 5)
            session.word(pt_out + 4, y >> 5)
            uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))
            return
        elif address == HELPER_LOOKUP:
            uc_.reg_write(UC_ARM_REG_R0, case['macro_tile_ptr'])
            uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))
            return

        assert address == STUB_MSG
        recv = uc_.reg_read(UC_ARM_REG_R0)
        sel_ptr = uc_.reg_read(UC_ARM_REG_R1)
        sel = bytes(uc_.mem_read(sel_ptr, 128)).split(b'\0')[0].decode()
        r2 = uc_.reg_read(UC_ARM_REG_R2)
        r3 = uc_.reg_read(UC_ARM_REG_R3)

        if sel == SEL_MACRO_TILES:
            state['trace'].append((TPC['WorldMacroTiles'], recv))
            uc_.reg_write(UC_ARM_REG_R0, 0x71000000)
        elif sel == SEL_LOAD_PHYSICAL:
            state['trace'].append((TPC['LoadPhysicalBlock'], r2))
            uc_.reg_write(UC_ARM_REG_R0, 1)
        elif sel == SEL_SHOULD_ADD:
            ans = 1 if case['should_add_to_macro_block'] else 0
            state['trace'].append((TPC['ShouldAddToMacroBlock'], ans))
            uc_.reg_write(UC_ARM_REG_R0, ans)
        elif sel == SEL_LOAD_DYN:
            state['trace'].append((TPC['LoadDynamicObjects'], r2))
            uc_.reg_write(UC_ARM_REG_R0, 1)
        elif sel == SEL_ADD_OBJECT:
            state['trace'].append((TPC['AddObject'], r2))
            uc_.reg_write(UC_ARM_REG_R0, recv)
        elif sel == SEL_OBJECT_TYPE:
            otype = case['object_type']
            state['trace'].append((TPC['ObjectType'], otype))
            uc_.reg_write(UC_ARM_REG_R0, otype)
        elif sel == SEL_WORLD_CHANGED:
            sp = uc_.reg_read(UC_ARM_REG_SP)
            otype = struct.unpack('<I', bytes(uc_.mem_read(sp, 4)))[0]
            state['trace'].append((TPC['DynamicWorldChanged'], otype))
            uc_.reg_write(UC_ARM_REG_R0, 1)
        else:
            raise RuntimeError(f"Unhandled selector: {sel}")

        uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

    from unicorn import UC_HOOK_CODE
    uc.hook_add(UC_HOOK_CODE, hook, begin=STUB_MSG, end=STUB_MSG + 4)
    uc.hook_add(UC_HOOK_CODE, hook, begin=HELPER_COORD, end=HELPER_COORD + 4)
    uc.hook_add(UC_HOOK_CODE, hook, begin=HELPER_LOOKUP, end=HELPER_LOOKUP + 4)

    # Build C++ bridge
    root = Path(__file__).resolve().parents[1]
    bridge_src = root / 'tools/dynamic_object_init_derived_stuff_arm_bridge.cpp'
    contract_src = root / 'reconstruction/recovered/dynamic_object_init_derived_stuff.cpp'
    fns = []
    for opt in (0, 2):
        so_path = a.output_dir / f'dynamic_object_init_derived_stuff-O{opt}.so'
        cmd = [
            'clang++', f'-O{opt}', '-shared', '-fPIC', '-std=c++17',
            '-I', str(root / 'reconstruction/recovered'),
            str(bridge_src), str(contract_src),
            '-o', str(so_path)
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode == 0, res.stderr
        cdll = ctypes.CDLL(str(so_path))
        fn = cdll.recovered_dynamic_object_init_derived_stuff_run
        fn.argtypes = [
            ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
            ctypes.c_int32, ctypes.c_int32, ctypes.c_uint32,
            ctypes.c_uint32, ctypes.c_uint32, ctypes.c_int32,
            ctypes.c_uint32, ctypes.c_uint32,
            ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint32)
        ]
        fn.restype = ctypes.c_uint32
        fns.append((opt, fn))

    # Preload libc++_shared.so in Termux if needed
    libcpp = Path('/data/data/com.termux/files/usr/lib/libc++_shared.so')
    if libcpp.exists():
        try:
            ctypes.CDLL(str(libcpp), mode=ctypes.RTLD_GLOBAL)
        except Exception:
            pass

    macro_tile_mem = 0x60030000
    uc.mem_map(macro_tile_mem, 0x1000)

    from unicorn.arm_const import UC_ARM_REG_R0

    rows = []
    for case in CASES:
        merged = dict(BASE)
        merged.update({k: v for k, v in case.items() if k != 'name'})
        state['case'] = merged
        state['trace'] = []

        self_ptr = merged['self_ptr']
        uc.mem_write(self_ptr, b'\x00' * IMAGE_SIZE)
        session.word(self_ptr + 4, merged['world_ptr'])
        session.word(self_ptr + 8, merged['dynamic_world_ptr'])
        session.word(self_ptr + 16, merged['pos_x'])
        session.word(self_ptr + 20, merged['pos_y'])

        if merged['macro_tile_ptr'] != 0:
            uc.mem_write(merged['macro_tile_ptr'], b'\x00' * 32)
            session.word(merged['macro_tile_ptr'] + 4, 1 if merged['physical_block_loaded'] else 0)
            session.word(merged['macro_tile_ptr'] + 12, 0x60040000)

        r2 = 1 if merged['init_derived_stuff'] else 0
        r3 = 1 if merged['load_physical_block_if_needed'] else 0

        session.run(IMP, sp_offset=0x8000,
                    R0=self_ptr, R1=cmd_sel, R2=r2, R3=r3)

        arm_ret = uc.reg_read(UC_ARM_REG_R0) & 0xff
        arm_image = bytes(uc.mem_read(self_ptr, IMAGE_SIZE))
        arm_trace = list(state['trace'])

        # C++ comparison
        for opt, fn in fns:
            cpp_img_buf = ctypes.create_string_buffer(IMAGE_SIZE)
            cpp_trace_buf = ctypes.create_string_buffer(32 * 8)
            cpp_ret = ctypes.c_uint32(0)
            n = fn(
                merged['self_ptr'], merged['world_ptr'], merged['dynamic_world_ptr'],
                merged['pos_x'], merged['pos_y'], merged['macro_tile_ptr'],
                1 if merged['physical_block_loaded'] else 0,
                1 if merged['should_add_to_macro_block'] else 0,
                merged['object_type'],
                1 if merged['init_derived_stuff'] else 0,
                1 if merged['load_physical_block_if_needed'] else 0,
                cpp_img_buf, cpp_trace_buf, ctypes.byref(cpp_ret)
            )
            cpp_image = cpp_img_buf.raw
            cpp_trace = []
            for i in range(n):
                rec = cpp_trace_buf.raw[i*8:(i+1)*8]
                code = rec[0]
                arg = struct.unpack('<I', rec[4:8])[0]
                cpp_trace.append((code, arg))

            assert (arm_ret != 0) == (cpp_ret.value != 0), f"-O{opt} return mismatch in {case['name']}"
            assert arm_image == cpp_image, f"-O{opt} image mismatch in {case['name']}"
            assert arm_trace == cpp_trace, (f"-O{opt} trace mismatch in {case['name']}", arm_trace, cpp_trace)

        rows.append({
            'case': case['name'],
            'trace_len': len(arm_trace),
            'ret_val': arm_ret != 0
        })

    report = {
        'sha256': SHA,
        'class': 'DynamicObject',
        'method': 'initDerivedStuff:loadPhysicalBlockIfNeeded:',
        'imp': hex(IMP),
        'cases': len(CASES),
        'match': True,
        'rows': rows,
        'boundary': (
            "Unicorn execution of the original 242-word method. [world macroTiles], "
            "macro tile conversion and lookup, macroTileOwner assignment (self+12), "
            "nil-macroTile early exit, physicalBlock check and loadPhysicalBlockForMacroTile: dispatch, "
            "[self shouldAddToMacroBlock] check, loadDynamicObjectsIfNotAlreadyLoadedForMacroTile: dispatch, "
            "[macroTile->dynamicObjects addObject:self], and optional dynamicWorldChangedAtPos:objectType: "
            "notification execute bit-for-bit."
        )
    }

    (a.output_dir / 'dynamic_object_init_derived_stuff_arm_result.json').write_text(json.dumps(report, indent=2))
    print(f"dynamic_object_init_derived_stuff_arm: PASS ({len(CASES)} cases)")
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
