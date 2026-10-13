#!/usr/bin/env python3
"""Execute the ORIGINAL ARM bodies of the forwarder5b batch (SurfaceBlock 22,
PassengerCar 44, HandCar 41, Mirror 64, SnowSurfaceBlock 29) under Unicorn and
compare the call traces with the recovered contract
(reconstruction/recovered/object_forwarder_init.cpp at -O0 and -O2).

Synthetic model (stated limits — not Foundation, not the original-app runtime):
  * `objc_msgSendSuper2` is stubbed; it asserts the struct is
    {self, OBJC_CLASS_$_<that class>} (resolved from the entry's own superref
    cell), the selector is the loader selector and the four arguments are the
    harness pointers.
  * `objc_msgSend` is stubbed for the post-init hook; for Mirror and
    SnowSurfaceBlock it asserts the selector is that class's own hook name
    (initSubDerivedItems) — the three super-only bodies must not reach it.
  * the instance window is a zeroed 128-byte region; after each run it must
    still be all-zero, which is the executed counterpart of the batch's
    "writes no own ivar" claim.

Per class and per case: returned register, call order, trace bits vs the
contract, and the instance-window purity.
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
GOT_SUPER2 = 0x0105B79C
GOT_MSGSEND = 0x0105B7A0
SUPER_SELECTOR = 'initWithWorld:dynamicWorld:saveDict:cache:'
HOOK_SELECTOR = 'initSubDerivedItems'

# (class, type id, imp, superref slot, hook selector or None)
# cells from reconstruction/reverse-v3/native/forwarder5b_initwithworld.json
ENTRIES = [
    ('SurfaceBlock', 22, 0x00812E64, 0x00E8BD70, None),
    ('SnowSurfaceBlock', 29, 0x00D8D89C, 0x00E8BF38, HOOK_SELECTOR),
    ('HandCar', 41, 0x00A4F564, 0x00E8BE2C, None),
    ('PassengerCar', 44, 0x0081BCC8, 0x00E8BD78, None),
    ('Mirror', 64, 0x00A9F434, 0x00E8BE5C, HOOK_SELECTOR),
]
# code words, pinned by the batch's evidence json (sanity check on the pin)
WORDS = {'SurfaceBlock': 57, 'SnowSurfaceBlock': 71, 'HandCar': 60,
         'PassengerCar': 60, 'Mirror': 71}

IMAGE_SIZE = 128


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

    graph, stack, stop, stub_super, stub_send = (
        0x60000000, 0x70000000, 0x71000000, 0x72000000, 0x72100000)
    uc.mem_map(graph, 0x10000)
    uc.mem_map(stack, 0x10000)
    uc.mem_map(stop, 0x1000)
    uc.mem_map(stub_super, 0x1000)
    uc.mem_map(stub_send, 0x1000)
    sel_region = 0x73000000
    uc.mem_map(sel_region, 0x1000)
    uc.mem_write(sel_region, SUPER_SELECTOR.encode() + b'\0')
    uc.mem_write(sel_region + 0x80, HOOK_SELECTOR.encode() + b'\0')

    def word(at, value):
        uc.mem_write(at, struct.pack('<I', value & 0xffffffff))

    def read_word(at):
        return int.from_bytes(bytes(uc.mem_read(at, 4)), 'little')

    word(GOT_SUPER2, stub_super)
    word(GOT_MSGSEND, stub_send)

    self_ptr = graph
    world, dyn, save_dict, cache = (graph + 0x100, graph + 0x200,
                                    graph + 0x300, graph + 0x400)
    ctx = {'super_result': self_ptr, 'expect_class': 0, 'hook': None,
           'entries': []}

    def cstring(ptr):
        return bytes(uc.mem_read(ptr, 96)).split(b'\0')[0].decode()

    def hook(uc_, address, size, data):
        if address == stub_super:
            struct_ptr = uc_.reg_read(UC_ARM_REG_R0)
            recv = read_word(struct_ptr)
            cls = read_word(struct_ptr + 4)
            sel = cstring(uc_.reg_read(UC_ARM_REG_R1))
            r2 = uc_.reg_read(UC_ARM_REG_R2)
            r3 = uc_.reg_read(UC_ARM_REG_R3)
            sp = uc_.reg_read(UC_ARM_REG_SP)
            a0 = read_word(sp)
            a1 = read_word(sp + 4)
            assert recv == self_ptr, ('super receiver', hex(recv))
            assert cls == ctx['expect_class'], \
                ('super class', hex(cls), hex(ctx['expect_class']))
            assert sel == SUPER_SELECTOR, sel
            assert (r2, r3, a0, a1) == (world, dyn, save_dict, cache), \
                tuple(hex(v) for v in (r2, r3, a0, a1))
            ctx['entries'].append('super')
            uc_.reg_write(UC_ARM_REG_R0, ctx['super_result'])
        elif address == stub_send:
            recv = uc_.reg_read(UC_ARM_REG_R0)
            sel = cstring(uc_.reg_read(UC_ARM_REG_R1))
            assert recv == self_ptr, ('hook receiver', hex(recv))
            assert ctx['hook'] is not None, ('hook call in a super-only body', sel)
            assert sel == ctx['hook'], (sel, ctx['hook'])
            ctx['entries'].append('hook')
            uc_.reg_write(UC_ARM_REG_R0, 0)
        else:
            raise AssertionError(('unexpected stub entry', hex(address)))
        uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

    for addr in (stub_super, stub_send):
        uc.hook_add(UC_HOOK_CODE, hook, begin=addr, end=addr + 4)

    repo = Path(__file__).resolve().parents[1]
    bridges = {}
    for opt in (0, 2):
        lib = a.output_dir / f'forwarder5b-O{opt}.so'
        subprocess.run(['clang++', '-std=c++17', f'-O{opt}', '-UNDEBUG',
                        '-fno-fast-math', '-ffp-contract=off', '-fPIC', '-shared',
                        '-I' + str(repo / 'reconstruction/recovered'),
                        str(repo / 'tools/object_forwarder_init_arm_bridge.cpp'),
                        str(repo / 'reconstruction/recovered/object_forwarder_init.cpp'),
                        '-o', str(lib)], check=True)
        cdll = ctypes.CDLL(str(lib))
        fn = cdll.recovered_forwarder_trace_ex
        fn.argtypes = [ctypes.c_int32, ctypes.c_int32]
        fn.restype = ctypes.c_uint32
        bridges[opt] = fn

    def arm_run(entry, super_returns_nil):
        cls, type_id, imp, superref, hook_name = entry
        ctx.update(super_result=0 if super_returns_nil else self_ptr,
                   expect_class=read_word(superref), hook=hook_name,
                   entries=[])
        uc.mem_write(self_ptr, b'\x00' * IMAGE_SIZE)
        sp = stack + 0x8000
        for reg, value in ((UC_ARM_REG_R0, self_ptr), (UC_ARM_REG_R1, sel_region),
                           (UC_ARM_REG_R2, world), (UC_ARM_REG_R3, dyn)):
            uc.reg_write(reg, value)
        uc.reg_write(UC_ARM_REG_SP, sp)
        uc.reg_write(UC_ARM_REG_LR, stop)
        word(sp, save_dict)
        word(sp + 4, cache)
        uc.emu_start(imp, stop, count=20000)
        assert uc.reg_read(UC_ARM_REG_PC) == stop, f'{cls}: no return'
        ret = uc.reg_read(UC_ARM_REG_R0)
        image = bytes(uc.mem_read(self_ptr, IMAGE_SIZE))
        return ret, list(ctx['entries']), image

    def bits_of(order, returned_nil):
        bits = 0
        for name in order:
            bits |= {'super': 1 << 0, 'hook': 1 << 1}[name]
        if returned_nil:
            bits |= 0x80000000
        return bits

    rows = []
    for entry in ENTRIES:
        cls, type_id, imp, superref, hook_name = entry
        for super_returns_nil in (False, True):
            ret, order, image = arm_run(entry, super_returns_nil)
            expected_ret = 0 if super_returns_nil else self_ptr
            assert ret == expected_ret, (cls, super_returns_nil, hex(ret))
            expected_order = (['super'] if super_returns_nil else
                              (['super', 'hook'] if hook_name else ['super']))
            assert order == expected_order, (cls, super_returns_nil, order)
            # executed counterpart of the batch's "writes no own ivar" claim
            assert image == b'\x00' * IMAGE_SIZE, (cls, 'own-ivar writes')
            bits = bits_of(order, super_returns_nil)
            cpp = [bridges[opt](1 if super_returns_nil else 0,
                                1 if hook_name else 0) for opt in (0, 2)]
            assert cpp == [bits, bits], (cls, super_returns_nil, hex(bits),
                                         [hex(c) for c in cpp])
            rows.append({'class': cls, 'type_id': type_id,
                         'imp': f'0x{imp:08x}', 'code_words': WORDS[cls],
                         'hook': hook_name,
                         'super_returns_nil': super_returns_nil,
                         'arm_return': f'0x{ret:08x}', 'arm_trace': bits,
                         'cpp_trace': cpp, 'instance_window_zero': True})

    # the three super-only bodies must produce IDENTICAL traces (shared shape)
    super_only = [r for r in rows if r['hook'] is None and not r['super_returns_nil']]
    assert len({r['arm_trace'] for r in super_only}) == 1, super_only
    # the two hooked bodies likewise
    hooked = [r for r in rows if r['hook'] is not None and not r['super_returns_nil']]
    assert len({r['arm_trace'] for r in hooked}) == 1, hooked

    report = {
        'sha256': SHA, 'batch': 'forwarder5b', 'cases': len(rows), 'match': True,
        'imp_addrs': {e[0]: f'0x{e[2]:08x}' for e in ENTRIES},
        'boundary': ('Unicorn execution of the five original 5b bodies with a '
                     'synthetic ObjC graph (stubbed objc_msgSendSuper2 + the '
                     'hook dispatch), compared to the recovered contract at '
                     '-O0/-O2 on trace bits, return value and the zeroed '
                     'instance window. Not Foundation, not the original-app '
                     'runtime, not device gameplay.'),
        'rows': rows,
    }
    (a.output_dir / 'forwarder5b-arm-result.json').write_text(
        json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in
                      ('sha256', 'batch', 'cases', 'match')}, indent=2))


if __name__ == '__main__':
    main()
