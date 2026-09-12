#!/usr/bin/env python3
"""Pinned original ARM ENTRY only vs C++ O0/O2. No full-pickup claim.

Execute 0xc61c00 through entry rejection/return or stop BEFORE 0xc61db4.
Only objc_msgSend is hooked. Field loads/branches execute original bytes.
The state ivar is INLINE storage, not a pointer: self + ivar + 0x60/0x68.
"""
import argparse
import hashlib
import itertools
import json
import struct
import subprocess
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_READ
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC

SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'

def main():
    p = argparse.ArgumentParser()
    p.add_argument('elf', type=Path)
    p.add_argument('--output-dir', type=Path, required=True)
    args = p.parse_args()
    assert hashlib.sha256(args.elf.read_bytes()).hexdigest() == SHA
    args.output_dir.mkdir(parents=True, exist_ok=True)
    with args.elf.open('rb') as f:
        elf = ELFFile(f)
        loads = [(s['p_vaddr'], s['p_memsz'], s.data()) for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
    u = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    pages = set()
    for base, size, _ in loads:
        pages.update(range(base & ~4095, (base + size + 4095) & ~4095, 4096))
    for page in sorted(pages):
        u.mem_map(page, 4096)
    for base, _, data in loads:
        u.mem_write(base, data)
    def word(addr): return struct.unpack('<I', u.mem_read(addr, 4))[0]
    def put(addr, value): u.mem_write(addr, struct.pack('<I', value & 0xffffffff))
    pic = (0xc61c14 + 8 + word(0xc62bb8)) & 0xffffffff
    def slot(pool): return (pic + word(pool)) & 0xffffffff
    def ivar(pool): return word(word(slot(pool)))
    offsets = dict(world=ivar(0xc62bc4), state=ivar(0xc62bc8), ignoring=ivar(0xc62bd0))
    assert offsets == dict(world=4, state=0x38, ignoring=0x2b4), offsets
    sels = {word(slot(va)): name for va, name in [(0xc62bc0, 'dragging'), (0xc62bcc, 'priority'), (0xc62bd4, 'meditating')]}
    assert len(sels) == 3
    heap, stack, stop, send = 0x60000000, 0x70000000, 0x71000000, 0x71001000
    u.mem_map(heap, 0x10000)
    u.mem_map(stack, 0x10000)
    u.mem_map(stop, 0x2000)
    u.mem_write(send, bytes.fromhex('1eff2fe1'))  # bx lr, hook supplies return
    put(slot(0xc62bbc), send)
    self_, freeblock, world = heap, heap + 0x2000, heap + 0x3000
    put(self_ + offsets['world'], world)
    # Poison the inline state's first word: dereferencing it is not valid.
    put(self_ + offsets['state'], 0xdead0000)
    fields = {self_ + offsets['state'] + 0x60: 'gateA', self_ + offsets['state'] + 0x68: 'gateB', self_ + offsets['ignoring']: 'ignoring'}
    trace, context = [], {}
    def read(uc, access, address, size, value, data):
        if address in fields:
            assert size == 1
            trace.append(fields[address])
    def code(uc, address, size, data):
        if address == 0xc61db4:
            context['allowed'] = True
            uc.emu_stop()
        elif address == send:
            sel = uc.reg_read(UC_ARM_REG_R1)
            assert sel in sels, hex(sel)
            name = sels[sel]
            receiver = uc.reg_read(UC_ARM_REG_R0)
            assert receiver == {'dragging': world, 'priority': freeblock, 'meditating': self_}[name]
            trace.append(name)
            uc.reg_write(UC_ARM_REG_R0, context[name] & 0xffffffff)
    u.hook_add(UC_HOOK_CODE, code)
    u.hook_add(UC_HOOK_MEM_READ, read, begin=self_, end=self_ + 0x1000)
    cases = list(itertools.product([0, 1, -128], [0, 1, -128], [0, 1, -128], [0, 1, -128], [0, 1, -128], [0, 1, -128], [0, 1, 2]))
    arm = []
    for dragging, a, b, intentional, ignoring, meditating, priority in cases:
        context.update(allowed=False, dragging=dragging, priority=[0, self_, heap + 0x4000][priority], meditating=meditating)
        for address, value in zip(fields, (a, b, ignoring)):
            u.mem_write(address, bytes([value & 255]))
        sp = stack + 0x8000
        # Fifth argument resides at ENTRY sp, not sp+8.
        put(sp, intentional)
        for reg, value in [(UC_ARM_REG_R0, self_), (UC_ARM_REG_R1, 0), (UC_ARM_REG_R2, freeblock), (UC_ARM_REG_R3, 0), (UC_ARM_REG_SP, sp), (UC_ARM_REG_LR, stop)]:
            u.reg_write(reg, value)
        trace.clear()
        u.emu_start(0xc61c00, stop, count=1000)
        pc = u.reg_read(UC_ARM_REG_PC)
        assert pc in (stop, 0xc61db4), hex(pc)
        if not context['allowed']:
            assert u.reg_read(UC_ARM_REG_R0) == 0
        arm.append(' '.join([str(int(context['allowed']))] + trace))
    root = Path(__file__).resolve().parents[1]
    input_ = ''.join(' '.join(map(str, case)) + '\n' for case in cases)
    reports = []
    for opt in ('O0', 'O2'):
        exe = args.output_dir / ('pickup-entry-' + opt)
        subprocess.run(['clang++', '-std=c++17', '-' + opt, '-UNDEBUG', str(root / 'tools/pickup_entry_probe.cpp'), str(root / 'reconstruction/recovered/inventory_pickup.cpp'), '-o', str(exe)], check=True)
        cpp = subprocess.run([str(exe)], input=input_, text=True, capture_output=True, check=True).stdout.splitlines()
        assert len(cpp) == len(arm)
        mismatches = [dict(input=case, arm=a, cpp=b) for case, a, b in zip(cases, arm, cpp) if a != b]
        reports.append(dict(optimization=opt, cases=len(cases), mismatches=mismatches))
    # Negative controls compile real altered C++ without modifying the worktree.
    source = (root / 'reconstruction/recovered/inventory_pickup.cpp').read_text()
    negative = []
    for name, old, new in [
        ('skip-intentional-gate', 'if (intentional == 0 &&', 'if (false &&'),
        ('ignore-negative-dragging', 'r.worldUIDragging(world) != 0', 'r.worldUIDragging(world) > 0'),
        ('omit-second-state-gate', 'r.stateGateB(state) != 0', 'false'),
    ]:
        assert source.count(old) == 1
        altered = args.output_dir / (name + '.cpp')
        altered.write_text(source.replace(old, new))
        exe = args.output_dir / name
        subprocess.run(['clang++', '-std=c++17', '-O2', '-UNDEBUG', '-I' + str(root / 'reconstruction/recovered'), str(root / 'tools/pickup_entry_probe.cpp'), str(altered), '-o', str(exe)], check=True)
        lines = subprocess.run([str(exe)], input=input_, text=True, capture_output=True, check=True).stdout.splitlines()
        assert len(lines) == len(arm)
        differences = sum(a != b for a, b in zip(arm, lines))
        assert differences > 0, name
        negative.append(dict(name=name, mismatches=differences))
    report = dict(negative_controls=negative, sha256=SHA, offsets=offsets, scope='entry only: stop before 0xc61db4; synthetic message receivers; original memory loads and branches; no full pickup/Foundation/APK acceptance', results=reports)
    (args.output_dir / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({**report, 'results': [{**r, 'mismatches': len(r['mismatches'])} for r in reports]}))
    assert all(not r['mismatches'] for r in reports)

if __name__ == '__main__':
    main()
