#!/usr/bin/env python3
"""Execute the ORIGINAL ARM bodies of the five shared-skeleton forwarders
(ClownFish / Shark / Scorpion / Dodo / DonkeyLike, 74 words each, batch b3f)
under Unicorn and compare the call traces with the recovered C++ contract
(reconstruction/recovered/object_forwarder_init.cpp at -O0 and -O2).

Synthetic model (stated limits — not Foundation, not the original-app runtime):
  * `objc_msgSendSuper2` is stubbed; it asserts the struct is
    {self, OBJC_CLASS_$_<that class>} (resolved from the entry's own superref
    cell), the selector is the loader selector and the four arguments are the
    harness pointers.
  * `objc_msgSend` is stubbed for the zero-argument `loadDerivedStuff` hook.
Checked per entry and per case: returned register, the call order, and the
trace bits. Additionally the five entries must produce identical traces, which
is the executed counterpart of b3f's byte-identical 69-word skeleton.
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
HOOK_SELECTOR = 'loadDerivedStuff'
ENTRIES = [
    ('ClownFish', 0x0078E420, 0x0078E548, 0x00E8BD38),
    ('Shark', 0x007C8918, 0x007C8A40, 0x00E8BD54),
    ('Scorpion', 0x00893D58, 0x00893E80, 0x00E8BDAC),
    ('Dodo', 0x00A6B7DC, 0x00A6B904, 0x00E8BE3C),
    ('DonkeyLike', 0x00AB0C3C, 0x00AB0D64, 0x00E8BE6C),
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
    context = {'super_result': self_ptr, 'expect_class': 0}
    calls = []

    def hook(uc_, address, size, data):
        if address == stub_super:
            struct_ptr = uc_.reg_read(UC_ARM_REG_R0)
            recv = read_word(struct_ptr)
            cls = read_word(struct_ptr + 4)
            sel_ptr = uc_.reg_read(UC_ARM_REG_R1)
            sel = bytes(uc_.mem_read(sel_ptr, 96)).split(b'\0')[0].decode()
            r2 = uc_.reg_read(UC_ARM_REG_R2)
            r3 = uc_.reg_read(UC_ARM_REG_R3)
            sp = uc_.reg_read(UC_ARM_REG_SP)
            a0 = read_word(sp)
            a1 = read_word(sp + 4)
            assert recv == self_ptr, ('super receiver', hex(recv))
            assert cls == context['expect_class'], ('super class', hex(cls),
                                                    hex(context['expect_class']))
            assert sel == SUPER_SELECTOR, sel
            assert (r2, r3, a0, a1) == (world, dyn, save_dict, cache), \
                (hex(r2), hex(r3), hex(a0), hex(a1))
            calls.append('super')
            uc_.reg_write(UC_ARM_REG_R0, context['super_result'])
        elif address == stub_send:
            recv = uc_.reg_read(UC_ARM_REG_R0)
            sel_ptr = uc_.reg_read(UC_ARM_REG_R1)
            sel = bytes(uc_.mem_read(sel_ptr, 96)).split(b'\0')[0].decode()
            assert recv == self_ptr, ('hook receiver', hex(recv))
            assert sel == HOOK_SELECTOR, sel
            calls.append('hook')
            uc_.reg_write(UC_ARM_REG_R0, 0)
        else:
            raise AssertionError(('unexpected stub entry', hex(address)))
        uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

    for addr in (stub_super, stub_send):
        uc.hook_add(UC_HOOK_CODE, hook, begin=addr, end=addr + 4)

    repo = Path(__file__).resolve().parents[1]
    trace_fns = []
    for opt in (0, 2):
        lib = a.output_dir / f'forwarder-O{opt}.so'
        subprocess.run(['clang++', '-std=c++17', f'-O{opt}', '-UNDEBUG',
                        '-fno-fast-math', '-ffp-contract=off', '-fPIC', '-shared',
                        '-I' + str(repo / 'reconstruction/recovered'),
                        str(repo / 'tools/object_forwarder_init_arm_bridge.cpp'),
                        str(repo / 'reconstruction/recovered/object_forwarder_init.cpp'),
                        '-o', str(lib)], check=True)
        cdll = ctypes.CDLL(str(lib))
        fn = cdll.recovered_forwarder_trace
        fn.argtypes = [ctypes.c_int32]
        fn.restype = ctypes.c_uint32
        trace_fns.append(fn)

    def trace_bits(order, returned_nil):
        bits = 0
        for name in order:
            bits |= {'super': 1 << 0, 'hook': 1 << 1}[name]
        if returned_nil:
            bits |= 0x80000000
        return bits

    def arm_run(entry, super_returns_nil):
        cls, imp, boundary, superref = entry
        calls.clear()
        context['expect_class'] = read_word(superref)
        context['super_result'] = 0 if super_returns_nil else self_ptr
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
        return ret, list(calls)

    rows = []
    traces = {}
    for entry in ENTRIES:
        cls = entry[0]
        for super_returns_nil in (False, True):
            ret, order = arm_run(entry, super_returns_nil)
            expected_ret = 0 if super_returns_nil else self_ptr
            assert ret == expected_ret, (cls, super_returns_nil, hex(ret))
            expected_order = ['super'] if super_returns_nil else ['super', 'hook']
            assert order == expected_order, (cls, super_returns_nil, order)
            bits = trace_bits(order, super_returns_nil)
            cpp = [fn(1 if super_returns_nil else 0) for fn in trace_fns]
            assert cpp == [bits, bits], (cls, super_returns_nil, hex(bits),
                                        [hex(c) for c in cpp])
            traces.setdefault(cls, {})['nil' if super_returns_nil else 'ok'] = bits
            rows.append({'class': cls, 'entry': f'0x{entry[1]:08x}',
                         'super_returns_nil': super_returns_nil,
                         'arm_return': f'0x{ret:08x}', 'arm_trace': bits,
                         'cpp_trace': cpp})
    # Executed counterpart of the b3f sha256 skeleton identity.
    ok_traces = {c: t['ok'] for c, t in traces.items()}
    nil_traces = {c: t['nil'] for c, t in traces.items()}
    assert len(set(ok_traces.values())) == 1, ok_traces
    assert len(set(nil_traces.values())) == 1, nil_traces

    report = {
        'sha256': SHA, 'selector': SUPER_SELECTOR,
        'hook': HOOK_SELECTOR, 'entries': len(ENTRIES),
        'cases': len(rows), 'match': True,
        'identical_traces_across_entries': True,
        'boundary': ('Unicorn execution of the five original 74-word bodies '
                     'with a synthetic ObjC message graph (stubbed '
                     'objc_msgSendSuper2 asserting {self, own class} + selector '
                     '+ four arguments, and a stubbed zero-argument '
                     'loadDerivedStuff hook), compared to the recovered C++ at '
                     '-O0/-O2. Not Foundation, not the original-app runtime, not '
                     'device gameplay; the superclass initialiser and the hook '
                     'body are stubs.'),
        'rows': rows,
    }
    (a.output_dir / 'forwarder-arm-result.json').write_text(
        json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('sha256', 'entries', 'cases',
                                             'match',
                                             'identical_traces_across_entries')},
                     indent=2))


if __name__ == '__main__':
    main()
