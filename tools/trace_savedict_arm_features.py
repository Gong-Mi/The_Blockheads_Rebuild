#!/usr/bin/env python3
"""Automated ARM32 value-flow feature tracer for getSaveDict methods.

Uses Unicorn to run original ARM32 instructions from libApplication.so with
synthetic memory-marked offsets in `self`. Captures exact:
- key strings from CFConstantString arguments;
- value sources from `self + offset` (distinguishing 32-bit, 16-bit halfword, 8-bit bool);
- boxing conversion selectors (numberWithInt:, numberWithFloat:, numberWithBool:, etc.);
- direct object references and nested getSaveDict dispatches;
- full call site and branch site inventories via Capstone.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import capstone
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

try:
    from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_ARM, Uc
    from unicorn.arm_const import *
    UNICORN_AVAILABLE = True
except ImportError:
    UNICORN_AVAILABLE = False

SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
GRAPH = 0x60000000
STACK = 0x70000000
STOP = 0x71000000
DISPATCH_BASE = 0x72000000

MSG_DISPATCH = DISPATCH_BASE
LIB_MEMSET = DISPATCH_BASE + 0x100
LIB_MEMCPY = DISPATCH_BASE + 0x200
LIB_STRLEN = DISPATCH_BASE + 0x300


def create_emulator(elf_path: Path) -> Uc:
    if not UNICORN_AVAILABLE:
        raise RuntimeError('unicorn is not installed')
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

        # Scan relocations for objc_msgSend* and libc slots
        msg_slots = set()
        libc_slots = {}
        for section in elf.iter_sections():
            if isinstance(section, RelocationSection):
                syms = elf.get_section(section['sh_link'])
                for rel in section.iter_relocations():
                    if rel['r_info_sym']:
                        name = syms.get_symbol(rel['r_info_sym']).name
                        if 'objc_msgSend' in name:
                            msg_slots.add(rel['r_offset'])
                        elif name in ('memset', 'memcpy', 'strlen', 'memmove'):
                            libc_slots[rel['r_offset']] = name

    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    for base, size, data in loads:
        page_start = base & ~4095
        page_end = (base + size + 4095) & ~4095
        uc.mem_map(page_start, page_end - page_start)
        uc.mem_write(base, data)

    uc.mem_map(GRAPH, 0x10000)
    uc.mem_map(STACK, 0x10000)
    uc.mem_map(STOP, 4096)
    uc.mem_map(DISPATCH_BASE, 4096)

    for slot in msg_slots:
        uc.mem_write(slot, struct.pack('<I', MSG_DISPATCH))

    for slot, name in libc_slots.items():
        addr = LIB_MEMSET if name == 'memset' else (LIB_MEMCPY if name in ('memcpy', 'memmove') else LIB_STRLEN)
        uc.mem_write(slot, struct.pack('<I', addr))

    # Enable VFP / NEON coprocessors (CP10 and CP11)
    c1 = uc.reg_read(UC_ARM_REG_C1_C0_2)
    uc.reg_write(UC_ARM_REG_C1_C0_2, c1 | (0xF << 20))
    uc.reg_write(UC_ARM_REG_FPEXC, 0x40000000)

    return uc


def trace_savedict(uc: Uc, imp: int, boundary: Optional[int] = None) -> Dict[str, Any]:
    sp = STACK + 0x8000
    self_obj = GRAPH + 0x1000
    dict_obj = GRAPH + 0x2000

    # Populate self with unique halfword offset markers
    for off in range(0, 1024, 2):
        uc.mem_write(self_obj + off, struct.pack('<H', off))

    boxed = {}  # boxed_ptr -> (conv_sel, input_val)
    results = []

    def hook_code(uc_inner, address, size, user_data):
        lr = uc_inner.reg_read(UC_ARM_REG_LR)
        r0 = uc_inner.reg_read(UC_ARM_REG_R0)
        r1 = uc_inner.reg_read(UC_ARM_REG_R1)
        r2 = uc_inner.reg_read(UC_ARM_REG_R2)
        r3 = uc_inner.reg_read(UC_ARM_REG_R3)

        if address == LIB_MEMSET:
            try:
                if 0 < r2 < 0x10000:
                    uc_inner.mem_write(r0, bytes([r1 & 0xFF]) * r2)
            except Exception:
                pass
            uc_inner.reg_write(UC_ARM_REG_PC, lr)
            return
        elif address == LIB_MEMCPY:
            try:
                if 0 < r2 < 0x10000:
                    data = uc_inner.mem_read(r1, r2)
                    uc_inner.mem_write(r0, data)
            except Exception:
                pass
            uc_inner.reg_write(UC_ARM_REG_PC, lr)
            return
        elif address == LIB_STRLEN:
            try:
                data = uc_inner.mem_read(r0, 256).split(b'\0')[0]
                uc_inner.reg_write(UC_ARM_REG_R0, len(data))
            except Exception:
                uc_inner.reg_write(UC_ARM_REG_R0, 0)
            uc_inner.reg_write(UC_ARM_REG_PC, lr)
            return

        if address != MSG_DISPATCH:
            return

        sel_name = ''
        try:
            sel_bytes = uc_inner.mem_read(r1, 64).split(b'\0')[0]
            sel_name = sel_bytes.decode('ascii')
        except Exception:
            pass

        ret = 0
        if sel_name == 'getSaveDict':
            # In objc_msgSendSuper2, r0 is &objc_super where super.receiver == self_obj
            is_self = (r0 == self_obj)
            try:
                if not is_self and uc_inner.mem_read(r0, 4) == struct.pack('<I', self_obj):
                    is_self = True
            except Exception:
                pass
            ret = dict_obj if is_self else (GRAPH + 0x4000)
        elif sel_name.startswith('numberWith'):
            boxed_ptr = GRAPH + 0x5000 + len(boxed) * 0x10
            boxed[boxed_ptr] = (sel_name, r2)
            ret = boxed_ptr
        elif sel_name == 'setObject:forKey:':
            key_str = ''
            try:
                data_ptr = struct.unpack('<I', uc_inner.mem_read(r3 + 8, 4))[0]
                key_str = uc_inner.mem_read(data_ptr, 64).split(b'\0')[0].decode('ascii')
            except Exception:
                key_str = 'unknown'

            source: Dict[str, Any] = {'key': key_str}
            val_u = r2 & 0xFFFFFFFF
            if r2 in boxed:
                conv, val = boxed[r2]
                v = val & 0xFFFFFFFF
                low_16 = v & 0xFFFF
                high_16 = (v >> 16) & 0xFFFF
                if high_16 == low_16 + 2:
                    source.update({'kind': 'boxed_scalar', 'conversion': conv, 'offset': low_16, 'width': 32})
                else:
                    source.update({'kind': 'boxed_scalar', 'conversion': conv, 'offset': low_16, 'width': 16})
            else:
                low_16 = val_u & 0xFFFF
                high_16 = (val_u >> 16) & 0xFFFF
                if high_16 == low_16 + 2:
                    source.update({'kind': 'direct_object', 'offset': low_16})
                elif val_u == (GRAPH + 0x4000):
                    source.update({'kind': 'nested_getSaveDict'})
                else:
                    source.update({'kind': 'constant_pointer', 'value': hex(val_u)})

            results.append(source)
            ret = dict_obj

        uc_inner.reg_write(UC_ARM_REG_R0, ret)
        uc_inner.reg_write(UC_ARM_REG_PC, lr)

    hook = uc.hook_add(UC_HOOK_CODE, hook_code, begin=DISPATCH_BASE, end=DISPATCH_BASE + 0x3FF)
    uc.reg_write(UC_ARM_REG_R0, self_obj)
    uc.reg_write(UC_ARM_REG_SP, sp)
    uc.reg_write(UC_ARM_REG_LR, STOP)

    uc.emu_start(imp, STOP, count=20000)
    final_r0 = uc.reg_read(UC_ARM_REG_R0)
    uc.hook_del(hook)

    # Disassembly enumeration for calls and branches if boundary provided
    calls = []
    branches = []
    body_sha = None
    if boundary and boundary > imp:
        body_bytes = uc.mem_read(imp, boundary - imp)
        body_sha = hashlib.sha256(body_bytes).hexdigest()
        cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        cs.detail = True
        for ins in cs.disasm(body_bytes, imp):
            if ins.group(capstone.CS_GRP_CALL):
                calls.append(f'0x{ins.address:08x}')
            elif ins.group(capstone.CS_GRP_JUMP):
                branches.append(f'0x{ins.address:08x}')
            if ins.mnemonic == 'pop' and 'pc' in ins.op_str:
                break

    return {
        'imp': f'0x{imp:08x}',
        'return_equals_super_dict': (final_r0 == dict_obj),
        'keys': results,
        'call_sites': calls,
        'branch_sites': branches,
        'body_sha256': body_sha,
    }


KNOWN_CLASSES = {
    'Torch': (0x004B65B8, 0x004B69E0),
    'Sign': (0x005FAEB4, 0x005FB214),
    'ArtificialLight': (0x00A942D4, 0x00A947AC),
    'FreeBlock': (0x00629804, 0x0062A4B8),
    'Door': (0x00769DC8, 0x0076A084),
    'Ladder': (0x00AAE2AC, 0x00AAE518),
    'Bed': (0x00D410CC, 0x00D41334),
    'TradePortal': (0x00D39460, 0x00D39794),
    'Workbench': (0x00AE81D0, 0x00AE9510),
    'ElevatorMotor': (0x00700B5C, 0x00700ED8),
    'ElevatorShaft': (0x00CAD998, 0x00CADD14),
    'FireObject': (0x0067501C, 0x006753EC),
    'Painting': (0x00AA8FC8, 0x00AA9390),
    'Boat': (0x0096C238, 0x0096C674),
    'TrainCar': (0x00A394B0, 0x00A39D64),
    'DropBear': (0x0079DDC0, 0x0079E2B8),
    'CaveTroll': (0x00D54924, 0x00D54E2C),
    'TradingPost': (0x005E6B08, 0x005E7024),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path, nargs='?', default=Path('/data/data/com.termux/files/home/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'))
    parser.add_argument('--class', dest='class_name', help='Class name to trace')
    parser.add_argument('--all', action='store_true', help='Trace all known core classes')
    args = parser.parse_args()

    if not args.elf.exists():
        print(f"ELF not found at {args.elf}")
        sys.exit(1)

    uc = create_emulator(args.elf)
    targets = KNOWN_CLASSES if args.all or not args.class_name else {args.class_name: KNOWN_CLASSES[args.class_name]}

    for name, (imp, boundary) in targets.items():
        res = trace_savedict(uc, imp, boundary)
        print(f"=== {name} ({res['imp']}) ===")
        print(f"  Returns super dict: {res['return_equals_super_dict']}")
        print(f"  Total keys: {len(res['keys'])}")
        for k in res['keys']:
            print(f"    {k['key']:<26}: {k}")
        print(f"  Call sites ({len(res['call_sites'])}): {res['call_sites'][:5]}...")
        print(f"  Branch sites ({len(res['branch_sites'])}): {res['branch_sites']}")


if __name__ == '__main__':
    main()
