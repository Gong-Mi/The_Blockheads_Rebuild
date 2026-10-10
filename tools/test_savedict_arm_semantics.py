#!/usr/bin/env python3
"""Bounded ARM execution proof for getSaveDict semantics across subclass families.

Exercises original ARM32 instructions from the hash-pinned libApplication.so
against synthetic Objective-C message dispatch (not Foundation or full-game runtime).
Demonstrates the Stage C methodology across 3 distinct entity hierarchies:
1. Torch (0x004b65b8): nested getSaveDict call, ldrh halfword zero-extension,
   direct object insertion (ownerID), and dual nil-branches.
2. ArtificialLight (0x00a942d4): 8 scalar int properties boxed with numberWithInt:,
   including grid origin x (self+84) and y (self+88) offset arithmetic.
3. Sign (0x005faeb4): InteractionObject inheritance, 3 direct-object nil gates
   (text, ownerID, ownerName) and 2 boxed integer connection/offset properties.
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


class TestTorchSaveDictARM(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        elf = Path(
            '/data/data/com.termux/files/home/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
        )
        if not elf.exists():
            raise unittest.SkipTest('original ELF not present on host')
        cls.uc = create_emulator(elf)

    def _run_torch(
        self,
        has_light: bool = True,
        has_owner: bool = True,
        data_a_val: int = 0x1234,
        data_b_val: int = 0x5678,
    ):
        uc = self.uc
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

        uc.emu_start(0x004B65B8, STOP, count=10000)
        final_r0 = uc.reg_read(UC_ARM_REG_R0)
        uc.hook_del(hook)

        return {
            'final_r0': final_r0,
            'dict_obj': dict_obj,
            'saved_entries': saved_entries,
            'owner_obj': owner_obj,
            'light_dict': light_dict,
        }

    def test_torch_all_entries_saved(self):
        res = self._run_torch(has_light=True, has_owner=True)
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
        self.assertEqual(entries['ownerID'], res['owner_obj'])
        self.assertEqual(entries['lightDict'], res['light_dict'])
        self.assertEqual(entries['dataA'], 0x80000000 | 0x1234)
        self.assertEqual(entries['dataB'], 0x80000000 | 0x5678)

    def test_torch_nil_gates(self):
        res_no_light = self._run_torch(has_light=False, has_owner=True)
        self.assertNotIn('lightDict', res_no_light['saved_entries'])
        self.assertIn('ownerID', res_no_light['saved_entries'])

        res_no_owner = self._run_torch(has_light=True, has_owner=False)
        self.assertIn('lightDict', res_no_owner['saved_entries'])
        self.assertNotIn('ownerID', res_no_owner['saved_entries'])


class TestArtificialLightSaveDictARM(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        elf = Path(
            '/data/data/com.termux/files/home/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
        )
        if not elf.exists():
            raise unittest.SkipTest('original ELF not present on host')
        cls.uc = create_emulator(elf)

    def test_artificial_light_all_scalar_entries(self):
        uc = self.uc
        sp = STACK + 0x8000
        self_obj = GRAPH + 0x3000
        dict_obj = GRAPH + 0x4000

        def w32(addr, val):
            uc.mem_write(addr, struct.pack('<I', val & 0xFFFFFFFF))

        w32(self_obj + 64, 255)  # maxRed
        w32(self_obj + 68, 200)  # maxGreen
        w32(self_obj + 72, 150)  # maxBlue
        w32(self_obj + 76, 80)  # maxHeat
        w32(self_obj + 80, 12)  # radius
        w32(self_obj + 84, 0xFFFFFFFB)  # contributionGridOrigin.x = -5
        w32(self_obj + 88, 10)  # contributionGridOrigin.y = 10
        w32(self_obj + 96, 2)  # lightDirection

        saved_entries = {}

        def hook_msg(uc_inner, address, size, user_data):
            lr = uc_inner.reg_read(UC_ARM_REG_LR)
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
                ret = dict_obj
            elif sel_name == 'numberWithInt:':
                ret = 0x80000000 | (r2 & 0x7FFFFFFF)
            elif sel_name == 'setObject:forKey:':
                try:
                    data_ptr = struct.unpack(
                        '<I', uc_inner.mem_read(r3 + 8, 4)
                    )[0]
                    key_str = (
                        uc_inner.mem_read(data_ptr, 64)
                        .split(b'\0')[0]
                        .decode('ascii')
                    )
                except Exception:
                    key_str = 'unknown'
                saved_entries[key_str] = r2
                ret = dict_obj

            uc_inner.reg_write(UC_ARM_REG_R0, ret)
            uc_inner.reg_write(UC_ARM_REG_PC, lr)

        hook = uc.hook_add(UC_HOOK_CODE, hook_msg, begin=DISPATCH, end=DISPATCH)
        uc.reg_write(UC_ARM_REG_R0, self_obj)
        uc.reg_write(UC_ARM_REG_R1, 0x00F0F35C)
        uc.reg_write(UC_ARM_REG_SP, sp)
        uc.reg_write(UC_ARM_REG_LR, STOP)

        uc.emu_start(0x00A942D4, STOP, count=10000)
        final_r0 = uc.reg_read(UC_ARM_REG_R0)
        uc.hook_del(hook)

        self.assertEqual(final_r0, dict_obj)
        self.assertEqual(
            list(saved_entries.keys()),
            [
                'maxRed',
                'maxGreen',
                'maxBlue',
                'maxHeat',
                'radius',
                'contributionGridOrigin.x',
                'contributionGridOrigin.y',
                'lightDirection',
            ],
        )
        self.assertEqual(saved_entries['maxRed'], 0x80000000 | 255)
        self.assertEqual(saved_entries['maxGreen'], 0x80000000 | 200)
        self.assertEqual(saved_entries['maxBlue'], 0x80000000 | 150)
        self.assertEqual(saved_entries['maxHeat'], 0x80000000 | 80)
        self.assertEqual(saved_entries['radius'], 0x80000000 | 12)
        self.assertEqual(
            saved_entries['contributionGridOrigin.x'], 0xFFFFFFFB
        )  # -5
        self.assertEqual(saved_entries['contributionGridOrigin.y'], 0x80000000 | 10)
        self.assertEqual(saved_entries['lightDirection'], 0x80000000 | 2)


class TestSignSaveDictARM(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        elf = Path(
            '/data/data/com.termux/files/home/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
        )
        if not elf.exists():
            raise unittest.SkipTest('original ELF not present on host')
        cls.uc = create_emulator(elf)

    def _run_sign(
        self,
        has_text: bool = True,
        has_owner_id: bool = True,
        has_owner_name: bool = True,
    ):
        uc = self.uc
        sp = STACK + 0x8000
        self_obj = GRAPH + 0x3000
        dict_obj = GRAPH + 0x4000
        text_obj = (GRAPH + 0x5000) if has_text else 0
        owner_id_obj = (GRAPH + 0x6000) if has_owner_id else 0
        owner_name_obj = (GRAPH + 0x7000) if has_owner_name else 0

        def w32(addr, val):
            uc.mem_write(addr, struct.pack('<I', val & 0xFFFFFFFF))

        w32(self_obj + 36, owner_id_obj)
        w32(self_obj + 84, owner_name_obj)
        w32(self_obj + 100, text_obj)
        w32(self_obj + 112, 3)
        w32(self_obj + 116, 1)

        saved_entries = {}

        def hook_msg(uc_inner, address, size, user_data):
            lr = uc_inner.reg_read(UC_ARM_REG_LR)
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
                ret = dict_obj
            elif sel_name == 'numberWithInt:':
                ret = 0x80000000 | (r2 & 0x7FFFFFFF)
            elif sel_name == 'setObject:forKey:':
                try:
                    data_ptr = struct.unpack(
                        '<I', uc_inner.mem_read(r3 + 8, 4)
                    )[0]
                    key_str = (
                        uc_inner.mem_read(data_ptr, 64)
                        .split(b'\0')[0]
                        .decode('ascii')
                    )
                except Exception:
                    key_str = 'unknown'
                saved_entries[key_str] = r2
                ret = dict_obj

            uc_inner.reg_write(UC_ARM_REG_R0, ret)
            uc_inner.reg_write(UC_ARM_REG_PC, lr)

        hook = uc.hook_add(UC_HOOK_CODE, hook_msg, begin=DISPATCH, end=DISPATCH)
        uc.reg_write(UC_ARM_REG_R0, self_obj)
        uc.reg_write(UC_ARM_REG_R1, 0x00ED8491)
        uc.reg_write(UC_ARM_REG_SP, sp)
        uc.reg_write(UC_ARM_REG_LR, STOP)

        uc.emu_start(0x005FAEB4, STOP, count=10000)
        final_r0 = uc.reg_read(UC_ARM_REG_R0)
        uc.hook_del(hook)

        return {
            'final_r0': final_r0,
            'dict_obj': dict_obj,
            'saved_entries': saved_entries,
            'text_obj': text_obj,
            'owner_id_obj': owner_id_obj,
            'owner_name_obj': owner_name_obj,
        }

    def test_sign_all_non_nil(self):
        res = self._run_sign(has_text=True, has_owner_id=True, has_owner_name=True)
        self.assertEqual(res['final_r0'], res['dict_obj'])
        entries = res['saved_entries']
        self.assertEqual(
            list(entries.keys()),
            ['text', 'ownerID', 'ownerName', 'connectionType', 'offsetType'],
        )
        # Direct object references
        self.assertEqual(entries['text'], res['text_obj'])
        self.assertEqual(entries['ownerID'], res['owner_id_obj'])
        self.assertEqual(entries['ownerName'], res['owner_name_obj'])
        # Boxed ints
        self.assertEqual(entries['connectionType'], 0x80000000 | 3)
        self.assertEqual(entries['offsetType'], 0x80000000 | 1)

    def test_sign_nil_gates(self):
        res_no_text = self._run_sign(
            has_text=False, has_owner_id=True, has_owner_name=True
        )
        self.assertNotIn('text', res_no_text['saved_entries'])
        self.assertIn('ownerID', res_no_text['saved_entries'])

        res_no_owner = self._run_sign(
            has_text=True, has_owner_id=False, has_owner_name=True
        )
        self.assertNotIn('ownerID', res_no_owner['saved_entries'])
        self.assertIn('text', res_no_owner['saved_entries'])


def main():
    elf = Path(
        '/data/data/com.termux/files/home/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
    )
    if not elf.exists():
        print('savedict-arm-semantics: SKIP (original ELF not present)')
        return
    suite = unittest.TestSuite()
    suite.addTests(
        unittest.TestLoader().loadTestsFromTestCase(TestTorchSaveDictARM)
    )
    suite.addTests(
        unittest.TestLoader().loadTestsFromTestCase(
            TestArtificialLightSaveDictARM
        )
    )
    suite.addTests(
        unittest.TestLoader().loadTestsFromTestCase(TestSignSaveDictARM)
    )
    runner = unittest.TextTestRunner(verbosity=2)
    res = runner.run(suite)
    if not res.wasSuccessful():
        raise SystemExit(1)
    print('savedict-arm-semantics: PASS (Torch, ArtificialLight, Sign)')


if __name__ == '__main__':
    main()
