#!/usr/bin/env python3
"""Execute the ORIGINAL ARM body of FreightCar -[initWithWorld:dynamicWorld:saveDict:chestSaveDict:cache:]
(IMP 0x00A403E8, 134 words, batch b4h) under Unicorn and compare the instance image
and message trace byte-for-byte against the recovered C++ contract
(reconstruction/recovered/freight_car_init.cpp, built at -O0 and -O2).

Synthetic model:
  * objc_msgSendSuper2 (GOT slot 0x0105B79C) is stubbed; it verifies the struct is
    {self, OBJC_CLASS_$_FreightCar (0x00E919D0)}, the selector is
    initWithWorld:dynamicWorld:saveDict:cache:, and the four arguments match.
  * objc_msgSend (veneer 0x001C281C via GOT slot 0x0105FB18, and 0x0105B7A0) is stubbed;
    it handles:
    - [Chest alloc] (receiver is OBJC_CLASS_$_Chest 0x00E92240)
    - [chest initWithWorld:world dynamicWorld:dynamicWorld saveDict:chestSaveDict cache:cache]
      (world is read from self->world @ +4)
    - [chest setProxyObjectOwner:self] (receiver is chest, arg is self)
    - [chest setFloatPosAndUpdatePosition:self->floatPos] (receiver is chest,
      arg is Vector2 read from self->floatPos @ +24: x in r2, y in r3)
Checked per case:
  * 256-byte instance image (self->chest @ 220, self->world @ 4, self->floatPos @ 24/28)
  * Message trace (code, arg LE32)
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
from trace_codes_gen import FREIGHT_CAR_INIT_CODES as FC

SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
IMP = 0x00A403E8
IMAGE_SIZE = 256

GOT_SUPER2 = 0x0105B79C
GOT_MSGSEND = 0x0105FB18
GOT_MSGSEND_ALT = 0x0105B7A0

CHEST_CLASS = 0x00E92240
FREIGHTCAR_CLASS = 0x00E919D0

SUPER_SELECTOR = 'initWithWorld:dynamicWorld:saveDict:cache:'
ALLOC_SELECTOR = 'alloc'
PROXY_SELECTOR = 'setProxyObjectOwner:'
FLOATPOS_SELECTOR = 'setFloatPosAndUpdatePosition:'

STUB_SUPER = 0x72000000
STUB_SEND = 0x72100000

CHEST_ALLOC_TOKEN = 0xC8E57001
CHEST_INIT_TOKEN = 0xC8E57002

BASE = {
    'self_ptr': 0x60000000,
    'world_token': 0x51CE0004,
    'dynamic_world_token': 0x51CE0005,
    'save_dict_token': 0x51CE0006,
    'chest_save_dict_token': 0x51CE0007,
    'cache_token': 0x51CE0008,
    'float_pos_x': 100.5,
    'float_pos_y': 200.25,
    'super_returns_nil': 0,
    'chest_alloc_token': CHEST_ALLOC_TOKEN,
    'chest_init_token': CHEST_INIT_TOKEN,
}

CASES = [
    {'name': 'happy_path'},
    {'name': 'nil_super', 'super_returns_nil': 1},
    {'name': 'negative_coords', 'float_pos_x': -35.25, 'float_pos_y': -108.5},
    {'name': 'origin_coords', 'float_pos_x': 0.0, 'float_pos_y': 0.0},
    {'name': 'large_coords', 'float_pos_x': 65536.0, 'float_pos_y': 32768.5},
    {'name': 'subnormal_coords', 'float_pos_x': 1e-40, 'float_pos_y': -1e-40},
    {'name': 'distinct_tokens',
     'world_token': 0x11111111, 'dynamic_world_token': 0x22222222,
     'save_dict_token': 0x33333333, 'chest_save_dict_token': 0x44444444,
     'cache_token': 0x55555555, 'chest_alloc_token': 0x66666666,
     'chest_init_token': 0x77777777},
]


def f32bits(value):
    return struct.unpack('<I', struct.pack('<f', value))[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    ap.add_argument('--output-dir', type=Path, required=True)
    a = ap.parse_args()
    a.output_dir.mkdir(parents=True, exist_ok=True)

    session = ARMSession(a.elf, SHA)
    uc = session.uc
    graph = FixtureGraph(uc)

    uc.mem_map(STUB_SUPER, 0x1000)
    uc.mem_map(STUB_SEND, 0x1000)
    session.patch_got(GOT_SUPER2, STUB_SUPER)
    session.patch_got(GOT_MSGSEND, STUB_SEND)
    session.patch_got(GOT_MSGSEND_ALT, STUB_SEND)

    cmd_sel = graph.command_selector('initWithWorld:dynamicWorld:saveDict:chestSaveDict:cache:')

    state = {'case': None, 'trace': []}

    def hook(uc_, address, size, data):
        from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                                       UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_PC,
                                       UC_ARM_REG_LR)
        case = state['case']
        if address == STUB_SUPER:
            struct_ptr = uc_.reg_read(UC_ARM_REG_R0)
            recv = session.read_word(struct_ptr)
            cls = session.read_word(struct_ptr + 4)
            sel_ptr = uc_.reg_read(UC_ARM_REG_R1)
            sel = bytes(uc_.mem_read(sel_ptr, 64)).split(b'\0')[0].decode()
            r2 = uc_.reg_read(UC_ARM_REG_R2)
            r3 = uc_.reg_read(UC_ARM_REG_R3)
            sp = uc_.reg_read(UC_ARM_REG_SP)
            a0 = session.read_word(sp)
            a1 = session.read_word(sp + 4)

            assert recv == case['self_ptr'], ('super recv', hex(recv), hex(case['self_ptr']))
            assert cls == FREIGHTCAR_CLASS, ('super cls', hex(cls), hex(FREIGHTCAR_CLASS))
            assert sel == SUPER_SELECTOR, sel
            assert r2 == case['world_token'], ('super world', hex(r2))
            assert r3 == case['dynamic_world_token'], ('super dyn', hex(r3))
            assert a0 == case['save_dict_token'], ('super saveDict', hex(a0))
            assert a1 == case['cache_token'], ('super cache', hex(a1))

            state['trace'].append((FC['MsgSendSuper'], case['save_dict_token']))
            if case['super_returns_nil']:
                uc_.reg_write(UC_ARM_REG_R0, 0)
            else:
                uc_.reg_write(UC_ARM_REG_R0, case['self_ptr'])
        elif address == STUB_SEND:
            recv = uc_.reg_read(UC_ARM_REG_R0)
            sel_ptr = uc_.reg_read(UC_ARM_REG_R1)
            sel = bytes(uc_.mem_read(sel_ptr, 64)).split(b'\0')[0].decode()
            r2 = uc_.reg_read(UC_ARM_REG_R2)
            r3 = uc_.reg_read(UC_ARM_REG_R3)
            sp = uc_.reg_read(UC_ARM_REG_SP)

            if sel == ALLOC_SELECTOR:
                assert recv == CHEST_CLASS, ('alloc recv', hex(recv))
                state['trace'].append((FC['ChestAlloc'], case['chest_alloc_token']))
                uc_.reg_write(UC_ARM_REG_R0, case['chest_alloc_token'])
            elif sel == SUPER_SELECTOR:
                assert recv == case['chest_alloc_token'], ('chest init recv', hex(recv))
                assert r2 == case['world_token'], ('chest init world', hex(r2))
                assert r3 == case['dynamic_world_token'], ('chest init dyn', hex(r3))
                a0 = session.read_word(sp)
                a1 = session.read_word(sp + 4)
                assert a0 == case['chest_save_dict_token'], ('chest init saveDict', hex(a0))
                assert a1 == case['cache_token'], ('chest init cache', hex(a1))
                state['trace'].append((FC['ChestInitWithWorld'], case['chest_save_dict_token']))
                uc_.reg_write(UC_ARM_REG_R0, case['chest_init_token'])
            elif sel == PROXY_SELECTOR:
                assert recv == case['chest_init_token'], ('proxy recv', hex(recv))
                assert r2 == case['self_ptr'], ('proxy owner', hex(r2))
                state['trace'].append((FC['ChestSetProxyObjectOwner'], case['self_ptr']))
                uc_.reg_write(UC_ARM_REG_R0, 0)
            elif sel == FLOATPOS_SELECTOR:
                assert recv == case['chest_init_token'], ('floatpos recv', hex(recv))
                expected_x = f32bits(case['float_pos_x'])
                expected_y = f32bits(case['float_pos_y'])
                assert r2 == expected_x, ('floatpos x', hex(r2), hex(expected_x))
                assert r3 == expected_y, ('floatpos y', hex(r3), hex(expected_y))
                state['trace'].append((FC['ChestSetFloatPosAndUpdatePosition'], expected_x))
                uc_.reg_write(UC_ARM_REG_R0, 0)
            else:
                raise AssertionError(('unexpected msgSend sel', sel))
        else:
            raise AssertionError(('unexpected hook address', hex(address)))

        from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_LR
        uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

    from unicorn import UC_HOOK_CODE
    uc.hook_add(UC_HOOK_CODE, hook, begin=STUB_SUPER, end=STUB_SUPER + 4)
    uc.hook_add(UC_HOOK_CODE, hook, begin=STUB_SEND, end=STUB_SEND + 4)

    repo = Path(__file__).resolve().parents[1]
    import os
    env = dict(os.environ)
    prefix_lib = Path('/data/data/com.termux/files/usr/lib')
    if prefix_lib.exists():
        env['LD_LIBRARY_PATH'] = str(prefix_lib) + ':' + env.get('LD_LIBRARY_PATH', '')

    for opt in (0, 2):
        so = a.output_dir / f'freight_car-O{opt}.so'
        cmd = ['clang++', '-std=c++17', f'-O{opt}', '-fPIC', '-shared',
               '-UNDEBUG', '-fno-fast-math', '-ffp-contract=off',
               '-I' + str(repo / 'reconstruction/recovered'),
               str(repo / 'reconstruction/recovered/freight_car_init.cpp'),
               str(repo / 'tools/freight_car_init_arm_bridge.cpp'),
               '-o', str(so)]
        subprocess.run(cmd, check=True, env=env)

    lib_path = prefix_lib / 'libc++_shared.so'
    if lib_path.exists():
        ctypes.CDLL(str(lib_path), mode=ctypes.RTLD_GLOBAL)

    fns = []
    for opt in (0, 2):
        so = a.output_dir / f'freight_car-O{opt}.so'
        dll = ctypes.CDLL(str(so))
        fn = dll.recovered_freight_car_init_run
        fn.argtypes = [
            ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
            ctypes.c_uint32, ctypes.c_uint32, ctypes.c_float, ctypes.c_float,
            ctypes.c_uint8, ctypes.c_uint32, ctypes.c_uint32,
            ctypes.c_char_p, ctypes.c_char_p
        ]
        fn.restype = ctypes.c_uint32
        fns.append((opt, fn))

    rows = []
    for case in CASES:
        merged = dict(BASE)
        merged.update({k: v for k, v in case.items() if k != 'name'})
        state['case'] = merged
        state['trace'] = []

        self_ptr = merged['self_ptr']
        uc.mem_write(self_ptr, b'\x00' * IMAGE_SIZE)
        # Pre-populate self ivars (world@4, dynamicWorld@8, floatPos@24/28)
        graph.word(self_ptr + 4, merged['world_token'])
        graph.word(self_ptr + 8, merged['dynamic_world_token'])
        graph.word(self_ptr + 24, f32bits(merged['float_pos_x']))
        graph.word(self_ptr + 28, f32bits(merged['float_pos_y']))

        # Prepare stack arguments:
        # arg4 = saveDict, arg5 = chestSaveDict, arg6 = cache
        stack_top = session.stack + 0x8000
        uc.mem_write(stack_top, struct.pack('<III',
                                            merged['save_dict_token'],
                                            merged['chest_save_dict_token'],
                                            merged['cache_token']))

        session.run(IMP, sp_offset=0x8000,
                    R0=self_ptr, R1=cmd_sel,
                    R2=merged['world_token'],
                    R3=merged['dynamic_world_token'])

        from unicorn.arm_const import UC_ARM_REG_R0
        ret_val = uc.reg_read(UC_ARM_REG_R0)
        expected_ret = 0 if merged['super_returns_nil'] else self_ptr
        assert ret_val == expected_ret, ('ret val', hex(ret_val), hex(expected_ret))

        arm_image = bytes(uc.mem_read(self_ptr, IMAGE_SIZE))
        arm_trace = list(state['trace'])

        # Run C++ models at -O0 and -O2
        for opt, fn in fns:
            cpp_img_buf = ctypes.create_string_buffer(IMAGE_SIZE)
            cpp_trace_buf = ctypes.create_string_buffer(16 * 8)
            n = fn(
                merged['self_ptr'], merged['world_token'],
                merged['dynamic_world_token'], merged['save_dict_token'],
                merged['chest_save_dict_token'], merged['cache_token'],
                merged['float_pos_x'], merged['float_pos_y'],
                merged['super_returns_nil'], merged['chest_alloc_token'],
                merged['chest_init_token'],
                cpp_img_buf, cpp_trace_buf
            )
            cpp_image = cpp_img_buf.raw
            cpp_trace = []
            for i in range(n):
                rec = cpp_trace_buf.raw[i*8:(i+1)*8]
                code = rec[0]
                arg = struct.unpack('<I', rec[4:8])[0]
                cpp_trace.append((code, arg))

            assert arm_image == cpp_image, (f"-O{opt} image mismatch in {case['name']}")
            assert arm_trace == cpp_trace, (f"-O{opt} trace mismatch in {case['name']}", arm_trace, cpp_trace)

        rows.append({
            'case': case['name'],
            'trace_len': len(arm_trace),
            'returned_ptr': hex(ret_val)
        })

    report = {
        'sha256': SHA,
        'class': 'FreightCar',
        'method': 'initWithWorld:dynamicWorld:saveDict:chestSaveDict:cache:',
        'imp': hex(IMP),
        'cases': len(CASES),
        'match': True,
        'rows': rows,
        'boundary': (
            'Unicorn execution of the original 134-word method (the 4th selector '
            'variant front member). The objc_msgSendSuper2 call, nil-super guard, '
            'Chest child alloc, Chest child initWithWorld: initialization with chestSaveDict, '
            'chest ivar store at self+220, [chest setProxyObjectOwner:self] and '
            '[chest setFloatPosAndUpdatePosition:self->floatPos] execute against '
            'the original ARM32 code bit-for-bit.'
        )
    }
    report_path = a.output_dir / 'freight_car_init_arm_result.json'
    report_path.write_text(json.dumps(report, indent=2))
    print(f"freight_car_init_arm: PASS ({len(CASES)} cases)")
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
