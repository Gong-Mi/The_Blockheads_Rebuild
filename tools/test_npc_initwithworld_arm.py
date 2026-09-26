#!/usr/bin/env python3
"""Execute the ORIGINAL ARM loader `-[NPC initWithWorld:dynamicWorld:saveDict:
cache:]` (0x00644b24) under Unicorn with synthetic ObjC messages and compare it
to the recovered C++ contract (reconstruction/recovered/npc_init_with_world.cpp,
built at -O0 and -O2).

Synthetic graph (stated limits — not Foundation, not the original-app runtime):
  * `objc_msgSendSuper2` is stubbed: it asserts the struct is
    {self, OBJC_CLASS_$_NPC}, the selector is the loader selector and the four
    arguments are the harness pointers, then returns self (or nil in the
    nil-super case).
  * `objc_msgSend` is stubbed for `loadValuesFromSaveDict:` only.
  * The real `bl 0x006445d8` wrapper and the real ABI veneer 0x001c2804 execute;
    only the veneer's final slot (0x0105fb10, imported lrand48) is patched to a
    stub, so the wrapper chain itself is part of what is being exercised.
Checked per case: return register, the call order (super → hook → lrand48), and
the exact IEEE-754 bits written to randomHarmFromHungerTimer@144.

On Termux run with LIBUNICORN_PATH="$PREFIX/lib"; results stay outside the
repository (CI has no original ELF).
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
IMP = 0x00644B24
GOT_SUPER2 = 0x0105B79C
GOT_MSGSEND = 0x0105B7A0
LRAND48_SLOT = 0x0105FB10
NPC_CLASS_OBJECT = 0x00E90828
TIMER_OFFSET = 144
SUPER_SELECTOR = 'initWithWorld:dynamicWorld:saveDict:cache:'
HOOK_SELECTOR = 'loadValuesFromSaveDict:'

CASES = [0, 1, 2, 3, 1024, 1048576, 1 << 23, 123456789, 1073741823,
         1 << 30, 2147483646, 2147483647, -1, -2147483648]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    ap.add_argument('--output-dir', type=Path, required=True)
    ap.add_argument('--keep-built', action='store_true')
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
    # The loader uses VFP (vmov/vldr/vcvt/vdiv/vmul/vadd/vstr): enable CP10/CP11
    # in CPACR and set FPEXC.EN, otherwise Unicorn raises UC_ERR_INSN_INVALID on
    # the first VFP instruction.
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

    graph, stack, stop, stub_super, stub_send, stub_rand = (
        0x60000000, 0x70000000, 0x71000000, 0x72000000, 0x72100000, 0x72200000)
    for base in (graph, stop, stub_super, stub_send, stub_rand):
        uc.mem_map(base, 0x1000)
    uc.mem_map(stack, 0x10000)
    sel_region = 0x73000000
    uc.mem_map(sel_region, 0x1000)

    def word(at, value):
        uc.mem_write(at, struct.pack('<I', value & 0xffffffff))

    # Patch the three imported entry points used by this method.
    word(GOT_SUPER2, stub_super)
    word(GOT_MSGSEND, stub_send)
    word(LRAND48_SLOT, stub_rand)

    self_ptr = graph
    world, dyn, save_dict, cache = (graph + 0x100, graph + 0x200,
                                    graph + 0x300, graph + 0x400)
    super_sel = sel_region
    hook_sel = sel_region + 0x80
    uc.mem_write(super_sel, SUPER_SELECTOR.encode() + b'\0')
    uc.mem_write(hook_sel, HOOK_SELECTOR.encode() + b'\0')

    context = {'super_result': self_ptr, 'lrand48_value': 0}
    calls = []

    def hook(uc_, address, size, data):
        if address == stub_super:
            struct_ptr = uc_.reg_read(UC_ARM_REG_R0)
            recv = int.from_bytes(bytes(uc_.mem_read(struct_ptr, 4)), 'little')
            cls = int.from_bytes(bytes(uc_.mem_read(struct_ptr + 4, 4)), 'little')
            sel_ptr = uc_.reg_read(UC_ARM_REG_R1)
            sel = bytes(uc_.mem_read(sel_ptr, 96)).split(b'\0')[0].decode()
            r2 = uc_.reg_read(UC_ARM_REG_R2)
            r3 = uc_.reg_read(UC_ARM_REG_R3)
            sp = uc_.reg_read(UC_ARM_REG_SP)
            a0 = int.from_bytes(bytes(uc_.mem_read(sp, 4)), 'little')
            a1 = int.from_bytes(bytes(uc_.mem_read(sp + 4, 4)), 'little')
            assert recv == self_ptr, ('super receiver', hex(recv))
            assert cls == NPC_CLASS_OBJECT, ('super class', hex(cls))
            assert sel == SUPER_SELECTOR, sel
            assert (r2, r3, a0, a1) == (world, dyn, save_dict, cache), \
                (hex(r2), hex(r3), hex(a0), hex(a1))
            calls.append('super')
            uc_.reg_write(UC_ARM_REG_R0, context['super_result'])
        elif address == stub_send:
            recv = uc_.reg_read(UC_ARM_REG_R0)
            sel_ptr = uc_.reg_read(UC_ARM_REG_R1)
            sel = bytes(uc_.mem_read(sel_ptr, 96)).split(b'\0')[0].decode()
            arg = uc_.reg_read(UC_ARM_REG_R2)
            assert recv == self_ptr, ('hook receiver', hex(recv))
            assert sel == HOOK_SELECTOR, sel
            assert arg == save_dict, ('hook argument', hex(arg))
            calls.append('loadValuesFromSaveDict')
            uc_.reg_write(UC_ARM_REG_R0, 0)
        elif address == stub_rand:
            calls.append('lrand48')
            uc_.reg_write(UC_ARM_REG_R0, context['lrand48_value'] & 0xffffffff)
        else:
            raise AssertionError(('unexpected stub entry', hex(address)))
        uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

    for addr in (stub_super, stub_send, stub_rand):
        uc.hook_add(UC_HOOK_CODE, hook, begin=addr, end=addr + 4)

    # Recovered C++ built at -O0 and -O2 through the bridge.
    repo = Path(__file__).resolve().parents[1]
    bits_fns, trace_fns = [], []
    for opt in (0, 2):
        lib = a.output_dir / f'npc_init-O{opt}.so'
        subprocess.run(['clang++', '-std=c++17', f'-O{opt}', '-UNDEBUG',
                        '-fno-fast-math', '-ffp-contract=off', '-fPIC', '-shared',
                        '-I' + str(repo / 'reconstruction/recovered'),
                        str(repo / 'tools/npc_init_with_world_arm_bridge.cpp'),
                        str(repo / 'reconstruction/recovered/npc_init_with_world.cpp'),
                        '-o', str(lib)], check=True)
        cdll = ctypes.CDLL(str(lib))
        bits = cdll.recovered_npc_hunger_timer_bits
        bits.argtypes = [ctypes.c_int32]
        bits.restype = ctypes.c_uint32
        trace = cdll.recovered_npc_init_trace
        trace.argtypes = [ctypes.c_int32, ctypes.c_int32]
        trace.restype = ctypes.c_uint32
        bits_fns.append(bits)
        trace_fns.append(trace)

    def arm_run(lrand48_value, super_returns_nil):
        calls.clear()
        context['lrand48_value'] = lrand48_value
        context['super_result'] = 0 if super_returns_nil else self_ptr
        uc.mem_write(self_ptr + TIMER_OFFSET, b'\0' * 4)
        sp = stack + 0x8000
        for reg, value in ((UC_ARM_REG_R0, self_ptr), (UC_ARM_REG_R1, super_sel),
                           (UC_ARM_REG_R2, world), (UC_ARM_REG_R3, dyn)):
            uc.reg_write(reg, value)
        uc.reg_write(UC_ARM_REG_SP, sp)
        uc.reg_write(UC_ARM_REG_LR, stop)
        word(sp, save_dict)
        word(sp + 4, cache)
        uc.emu_start(IMP, stop, count=20000)
        assert uc.reg_read(UC_ARM_REG_PC) == stop, 'method did not return'
        ret = uc.reg_read(UC_ARM_REG_R0)
        timer = bytes(uc.mem_read(self_ptr + TIMER_OFFSET, 4))
        order = list(calls)
        return ret, timer, order

    def trace_bits(order, returned_nil):
        table = {'super': 1 << 0, 'loadValuesFromSaveDict': 1 << 1,
                 'lrand48': 1 << 2}
        bits = 0
        for name in order:
            bits |= table[name]
        if returned_nil:
            bits |= 0x80000000
        return bits

    rows = []
    for value in CASES:
        ret, timer, order = arm_run(value, False)
        assert ret == self_ptr, ('return value', hex(ret))
        assert order == ['super', 'loadValuesFromSaveDict', 'lrand48'], order
        cpp_bits = [fn(value) for fn in bits_fns]
        cpp_trace = [fn(value, 0) for fn in trace_fns]
        arm_bits = int.from_bytes(timer, 'little')
        rows.append({'lrand48': value, 'arm_timer_bits': f'0x{arm_bits:08x}',
                     'cpp_timer_bits': [f'0x{b:08x}' for b in cpp_bits],
                     'arm_trace': trace_bits(order, False),
                     'cpp_trace': cpp_trace})
        assert cpp_bits == [arm_bits, arm_bits], (value, hex(arm_bits),
                                                  [hex(b) for b in cpp_bits])
        assert cpp_trace == [trace_bits(order, False)] * 2, (value, order)
    # Nil-super path: only the super call, no hook, no lrand48, timer untouched.
    ret, timer, order = arm_run(0, True)
    assert ret == 0, ('nil-super return', hex(ret))
    assert order == ['super'], order
    assert timer == b'\0\0\0\0', ('nil-super timer', timer.hex())
    nil_cpp = [fn(0, 1) for fn in trace_fns]
    assert nil_cpp == [trace_bits(order, True)] * 2, (nil_cpp, order)
    rows.append({'lrand48': None, 'case': 'super_returns_nil',
                 'arm_timer_bits': '0x00000000',
                 'cpp_timer_bits': ['0x00000000', '0x00000000'],
                 'arm_trace': trace_bits(order, True), 'cpp_trace': nil_cpp})

    report = {
        'sha256': SHA, 'method': 'initWithWorld:dynamicWorld:saveDict:cache:',
        'class': 'NPC', 'entry': f'0x{IMP:08x}',
        'cases': len(rows), 'match': True,
        'boundary': ('Unicorn execution of the original ARM method with a '
                     'synthetic ObjC message graph (stubbed objc_msgSendSuper2 / '
                     'loadValuesFromSaveDict: / lrand48 veneer slot) compared '
                     'bit-exactly to the recovered C++ at -O0 and -O2. The real '
                     '0x006445d8 wrapper and the 0x001c2804 veneer execute. Not '
                     'Foundation, not the original-app runtime, not device '
                     'gameplay, and the superclass initialiser plus the hook body '
                     'are stubs.'),
        'rows': rows,
    }
    (a.output_dir / 'npc-initwithworld-arm-result.json').write_text(
        json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('sha256', 'cases', 'match',
                                             'boundary')}, indent=2))


if __name__ == '__main__':
    main()
