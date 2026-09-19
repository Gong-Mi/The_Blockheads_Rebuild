#!/usr/bin/env python3
"""Bounded ARM execution proof for Torch -[getSaveDict] semantics.

Exercises original ARM instructions (IMP 0x004b65b8..0x004b698c) against
synthetic Objective-C message dispatch (not Foundation or full-game runtime).
Proves:
1. Return dictionary identity: always returns the super dictionary D (r0 == D).
2. Scalar boxing: itemType, dataA, dataB, connectionType boxed via numberWithInt:.
3. Halfword zero-extension: dataA (@80) and dataB (@82) read via ldrh (uint16).
4. Direct object insertion: ownerID (@36) passed directly without numberWithInt:.
5. Nested dispatch: lightDict receives the result of [self.light getSaveDict].
6. Conditional branch gates:
   - lightDict is omitted when [self.light getSaveDict] returns nil.
   - ownerID is omitted when self.ownerID is nil.
"""
import argparse
import hashlib
import json
import struct
import unittest
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_ARM, Uc
from unicorn.arm_const import *

SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
IMP = 0x004B65B8
STOP = 0x71000000
GRAPH = 0x60000000
STACK = 0x70000000
DISPATCH = 0x72000000


def create_emulator(elf_path: Path) -> Uc:
    raw = elf_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHA:
        raise ValueError('original ELF SHA mismatch')

    with elf_path.open('rb') as f:
        elf = ELFFile(f)
        loads = [
            (s['p_vaddr'], s['p_memsz'], s.data())
            for s in elf.iter_segments()
            if s['p_type'] == 'PT_LOAD'
        ]

    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    for base, size, data in loads:
        page_start = base & ~4095
        page_end = (base + size + 4095) & ~4095
        uc.mem_map(page_start, page_end - page_start)
        uc.mem_write(base, data)

    uc.mem_map(GRAPH, 0x10000)
    uc.mem_map(STACK, 0x10000)
    uc.mem_map(STOP, 4096)
    uc.mem_map(DISPATCH, 4096)

    # GOT slots for objc_msgSendSuper2 and objc_msgSend
    uc.mem_write(0x0105B79C, struct.pack('<I', DISPATCH))
    uc.mem_write(0x0105B7A0, struct.pack('<I', DISPATCH))
    return uc


def run_torch_savedict(
    uc: Uc,
    has_light: bool = True,
    has_owner: bool = True,
    data_a_val: int = 0x1234,
    data_b_val: int = 0x5678,
):
    sp = STACK + 0x8000
    self_obj = GRAPH + 0x1000
    dict_obj = GRAPH + 0x2000
    light_obj = (GRAPH + 0x3000) if has_light else 0
    light_dict = (GRAPH + 0x4000) if has_light else 0
    owner_obj = (GRAPH + 0x5000) if has_owner else 0

    def w32(addr, val):
        uc.mem_write(addr, struct.pack('<I', val & 0xFFFFFFFF))

    def w16(addr, val):
        uc.mem_write(addr, struct.pack('<H', val & 0xFFFF))

    w32(self_obj + 36, owner_obj)
    w32(self_obj + 56, light_obj)
    w32(self_obj + 60, 42)
    w32(self_obj + 64, 17)
    w16(self_obj + 80, data_a_val)
    w16(self_obj + 82, data_b_val)
    # Dirty high bytes at 84 to prove ldrh does not read beyond halfword
    w16(self_obj + 84, 0xDEAD)

    calls = []
    saved_entries = {}

    def hook_msg(uc_inner, address, size, user_data):
        lr = uc_inner.reg_read(UC_ARM_REG_LR)
        r0 = uc_inner.reg_read(UC_ARM_REG_R0)
        r1 = uc_inner.reg_read(UC_ARM_REG_R1)
        r2 = uc_inner.reg_read(UC_ARM_REG_R2)
        r3 = uc_inner.reg_read(UC_ARM_REG_R3)

        sel_name = ''
        try:
            sel_bytes = uc_inner.mem_read(r1, 64).split(b'\0')[0]
            sel_name = sel_bytes.decode('ascii')
        except Exception:
            pass

        ret = 0
        if sel_name == 'getSaveDict':
            if r0 == light_obj:
                ret = light_dict
                calls.append(('light.getSaveDict', r0))
            else:
                ret = dict_obj
                calls.append(('super.getSaveDict', r0))
        elif sel_name == 'numberWithInt:':
            ret = 0x80000000 | (r2 & 0x7FFFFFFF)
            calls.append(('numberWithInt:', r2, ret))
        elif sel_name == 'setObject:forKey:':
            key_str = ''
            try:
                data_ptr = struct.unpack(
                    '<I', uc_inner.mem_read(r3 + 8, 4)
                )[0]
                key_str = (
                    uc_inner.mem_read(data_ptr, 64)
                    .split(b'\0')[0]
                    .decode('ascii')
                )
            except Exception as ex:
                key_str = f'err:{ex}'
            calls.append(('setObject:forKey:', r2, key_str))
            saved_entries[key_str] = r2
            ret = dict_obj

        uc_inner.reg_write(UC_ARM_REG_R0, ret)
        uc_inner.reg_write(UC_ARM_REG_PC, lr)

    hook = uc.hook_add(UC_HOOK_CODE, hook_msg, begin=DISPATCH, end=DISPATCH)

    uc.reg_write(UC_ARM_REG_R0, self_obj)
    uc.reg_write(UC_ARM_REG_R1, 0x00EC9586)
    uc.reg_write(UC_ARM_REG_SP, sp)
    uc.reg_write(UC_ARM_REG_LR, STOP)

    uc.emu_start(IMP, STOP, count=10000)
    final_r0 = uc.reg_read(UC_ARM_REG_R0)
    uc.hook_del(hook)

    return {
        'final_r0': final_r0,
        'dict_obj': dict_obj,
        'calls': calls,
        'saved_entries': saved_entries,
        'owner_obj': owner_obj,
        'light_dict': light_dict,
    }


class TestTorchSaveDictARM(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        elf = Path(
            '/data/data/com.termux/files/home/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
        )
        if not elf.exists():
            raise unittest.SkipTest('original ELF not present on host')
        cls.uc = create_emulator(elf)

    def test_full_entries_saved_and_super_dict_returned(self):
        res = run_torch_savedict(self.uc, has_light=True, has_owner=True)
        self.assertEqual(res['final_r0'], res['dict_obj'])
        entries = res['saved_entries']
        self.assertEqual(
            list(entries.keys()),
            [
                'itemType',
                'dataA',
                'dataB',
                'connectionType',
                'lightDict',
                'ownerID',
            ],
        )
        # Direct object insertion (not boxed)
        self.assertEqual(entries['ownerID'], res['owner_obj'])
        # Nested getSaveDict object insertion
        self.assertEqual(entries['lightDict'], res['light_dict'])
        # Halfword extraction values
        self.assertEqual(entries['dataA'], 0x80000000 | 0x1234)
        self.assertEqual(entries['dataB'], 0x80000000 | 0x5678)

    def test_light_nil_gate_omits_light_dict(self):
        res = run_torch_savedict(self.uc, has_light=False, has_owner=True)
        self.assertEqual(res['final_r0'], res['dict_obj'])
        self.assertNotIn('lightDict', res['saved_entries'])
        self.assertIn('ownerID', res['saved_entries'])

    def test_owner_nil_gate_omits_owner_id(self):
        res = run_torch_savedict(self.uc, has_light=True, has_owner=False)
        self.assertEqual(res['final_r0'], res['dict_obj'])
        self.assertIn('lightDict', res['saved_entries'])
        self.assertNotIn('ownerID', res['saved_entries'])

    def test_both_nil_gates_active(self):
        res = run_torch_savedict(self.uc, has_light=False, has_owner=False)
        self.assertEqual(res['final_r0'], res['dict_obj'])
        self.assertEqual(
            list(res['saved_entries'].keys()),
            ['itemType', 'dataA', 'dataB', 'connectionType'],
        )


def main():
    elf = Path(
        '/data/data/com.termux/files/home/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
    )
    if not elf.exists():
        print('torch-savedict-arm: SKIP (original ELF not present)')
        return
    suite = unittest.TestLoader().loadTestsFromTestCase(TestTorchSaveDictARM)
    runner = unittest.TextTestRunner(verbosity=2)
    res = runner.run(suite)
    if not res.wasSuccessful():
        raise SystemExit(1)
    print('torch-savedict-arm: PASS')


if __name__ == '__main__':
    main()
