#!/usr/bin/env python3
"""Execute the ORIGINAL ARM body of TradingPost -[initSlotsWithSaveDict:]
(IMP 0x005E4914, 243 words, batch b4j) under Unicorn and compare the instance image
and message trace byte-for-byte against the recovered C++ contract
(reconstruction/recovered/trading_post_init_slots.cpp, built at -O0 and -O2).

Synthetic model:
  * objc_msgSend (GOT slot 0x0105B7A0) is stubbed:
    - [NSMutableArray alloc] / [array init]
    - [saveDict objectForKey:@"sellSlot"]
    - [sellSlotArray countByEnumeratingWithState:objects:count:]
    - [InventoryItem alloc]
    - [item initWithSaveData:itemData]
    - [item autorelease]
    - [item itemType] -> returns itemType integer
    - [sellSlotArray addObject:item]
  * memset (0x001C2924 via slot 0x0105FB70) is routed natively
  * objc_enumerationMutation (0x001C2E28 via slot 0x0105FD1C) is stubbed (no-op)
  * The itemType != 11 filter executes against real ARM instructions (cmp r0, #0xb).
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
from trace_codes_gen import TRADING_POST_INIT_SLOTS_CODES as TPC

SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
IMP = 0x005E4914
IMAGE_SIZE = 160

GOT_MSGSEND = 0x0105B7A0
MEMSET_SLOT = 0x0105FB70
MUTATION_SLOT = 0x0105FD1C

ARRAY_CLASS_SLOT = 0x00E8A0EC
ITEM_CLASS_SLOT = 0x00E8A0F0

ARRAY_CLASS = 0x00E91C00
ITEM_CLASS = 0x00E91CA0

ALLOC_SEL = 'alloc'
INIT_SEL = 'init'
OFK_SEL = 'objectForKey:'
ENUM_SEL = 'countByEnumeratingWithState:objects:count:'
INIT_WITH_SAVE_DATA_SEL = 'initWithSaveData:'
AUTORELEASE_SEL = 'autorelease'
ITEM_TYPE_SEL = 'itemType'
ADD_OBJECT_SEL = 'addObject:'

STUB_MSG = 0x72000000
STUB_MEMSET = 0x72100000
STUB_MUTATION = 0x72200000

BASE = {
    'self_ptr': 0x60000000,
    'sell_slot_array_token': 0x5E115107,
}

CASES = [
    {
        'name': 'missing_sell_slot',
        'has_sell_slot_key': False,
        'items': [],
    },
    {
        'name': 'empty_sell_slot',
        'has_sell_slot_key': True,
        'items': [],
    },
    {
        'name': 'single_item',
        'has_sell_slot_key': True,
        'items': [(0x8001, 1)],
    },
    {
        'name': 'item_filtered_11',
        'has_sell_slot_key': True,
        'items': [(0x8002, 11)],
    },
    {
        'name': 'mixed_items',
        'has_sell_slot_key': True,
        'items': [(0x8010, 5), (0x8011, 11), (0x8012, 25), (0x8013, 11)],
    },
    {
        'name': 'chunked_items_cross_16',
        'has_sell_slot_key': True,
        'items': [(0x9000 + i, 11 if i % 3 == 0 else (i + 1)) for i in range(18)],
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
    uc.mem_map(STUB_MEMSET, 0x1000)
    uc.mem_map(STUB_MUTATION, 0x1000)

    session.patch_got(GOT_MSGSEND, STUB_MSG)
    session.patch_got(MEMSET_SLOT, STUB_MEMSET)
    session.patch_got(MUTATION_SLOT, STUB_MUTATION)

    session.word(ARRAY_CLASS_SLOT, ARRAY_CLASS)
    session.word(ITEM_CLASS_SLOT, ITEM_CLASS)

    cmd_sel = graph.command_selector('initSlotsWithSaveDict:')

    items_page = 0x60080000
    uc.mem_map(items_page, 0x1000)

    state = {
        'case': None,
        'trace': [],
        'enum_idx': 0,
        'item_map': {},
    }

    def hook(uc_, address, size, data):
        from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                                       UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_PC,
                                       UC_ARM_REG_LR)
        case = state['case']

        if address == STUB_MEMSET:
            dst = uc_.reg_read(UC_ARM_REG_R0)
            val = uc_.reg_read(UC_ARM_REG_R1) & 0xff
            n = uc_.reg_read(UC_ARM_REG_R2)
            uc_.mem_write(dst, bytes([val]) * n)
            uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))
            return
        elif address == STUB_MUTATION:
            uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))
            return

        if address != STUB_MSG:
            print(f"DEBUG: unexpected hook address: {hex(address)}")
        assert address == STUB_MSG
        recv = uc_.reg_read(UC_ARM_REG_R0)
        sel_ptr = uc_.reg_read(UC_ARM_REG_R1)
        sel = bytes(uc_.mem_read(sel_ptr, 64)).split(b'\0')[0].decode()
        r2 = uc_.reg_read(UC_ARM_REG_R2)

        if sel == ALLOC_SEL:
            if recv == ARRAY_CLASS:
                state['trace'].append((TPC['AllocNSMutableArray'], case['sell_slot_array_token']))
                uc_.reg_write(UC_ARM_REG_R0, case['sell_slot_array_token'])
            elif recv == ITEM_CLASS:
                # InventoryItem alloc
                cur_pos = state['enum_idx'] - state['batch_count'] + state['sub_idx']
                curr_item_tok = case['items'][cur_pos][0]
                state['trace'].append((TPC['AllocInventoryItem'], curr_item_tok))
                state['sub_idx'] += 1
                uc_.reg_write(UC_ARM_REG_R0, curr_item_tok)
            else:
                uc_.reg_write(UC_ARM_REG_R0, 0x70000001)
        elif sel == INIT_SEL:
            state['trace'].append((TPC['InitNSMutableArray'], recv))
            uc_.reg_write(UC_ARM_REG_R0, recv)
        elif sel == OFK_SEL:
            # saveDict objectForKey:@"sellSlot"
            if case['has_sell_slot_key']:
                ret_val = case['sell_slot_array_token']
                state['trace'].append((TPC['ObjectForKey'], ret_val))
                uc_.reg_write(UC_ARM_REG_R0, ret_val)
            else:
                state['trace'].append((TPC['ObjectForKey'], 0))
                uc_.reg_write(UC_ARM_REG_R0, 0)
        elif sel == ENUM_SEL:
            items = case['items']
            remaining = len(items) - state['enum_idx']
            batch_count = min(remaining, 16)
            state['trace'].append((TPC['FastEnumeration'], batch_count))

            state_ptr = r2
            if batch_count > 0:
                for i in range(batch_count):
                    tok, _ = items[state['enum_idx'] + i]
                    session.word(items_page + i * 4, tok)
                session.word(state_ptr + 0, 0)
                session.word(state_ptr + 4, items_page)
                session.word(state_ptr + 8, items_page + 0x200)
                state['current_item_tok'] = items[state['enum_idx']][0]
                state['enum_sub_idx'] = 0
                state['batch_count'] = batch_count
                state['sub_idx'] = 0
                state['enum_idx'] += batch_count
                uc_.reg_write(UC_ARM_REG_R0, batch_count)
            else:
                uc_.reg_write(UC_ARM_REG_R0, 0)
        elif sel == INIT_WITH_SAVE_DATA_SEL:
            item_data = r2
            state['trace'].append((TPC['InitWithSaveData'], item_data))
            uc_.reg_write(UC_ARM_REG_R0, item_data)
        elif sel == AUTORELEASE_SEL:
            state['trace'].append((TPC['AutoreleaseItem'], recv))
            uc_.reg_write(UC_ARM_REG_R0, recv)
        elif sel == ITEM_TYPE_SEL:
            itype = state['item_map'].get(recv, 0)
            state['trace'].append((TPC['ItemType'], itype))
            uc_.reg_write(UC_ARM_REG_R0, itype)
        elif sel == ADD_OBJECT_SEL:
            obj = r2
            state['trace'].append((TPC['AddObject'], obj))
            uc_.reg_write(UC_ARM_REG_R0, recv)
        else:
            raise RuntimeError(f"Unhandled selector: {sel}")

        uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

    from unicorn import UC_HOOK_CODE
    uc.hook_add(UC_HOOK_CODE, hook, begin=STUB_MSG, end=STUB_MSG + 4)
    uc.hook_add(UC_HOOK_CODE, hook, begin=STUB_MEMSET, end=STUB_MEMSET + 4)
    uc.hook_add(UC_HOOK_CODE, hook, begin=STUB_MUTATION, end=STUB_MUTATION + 4)

    # Build C++ bridge
    root = Path(__file__).resolve().parents[1]
    bridge_src = root / 'tools/trading_post_init_slots_arm_bridge.cpp'
    contract_src = root / 'reconstruction/recovered/trading_post_init_slots.cpp'
    fns = []
    for opt in (0, 2):
        so_path = a.output_dir / f'trading_post_init_slots-O{opt}.so'
        cmd = [
            'clang++', f'-O{opt}', '-shared', '-fPIC', '-std=c++17',
            '-I', str(root / 'reconstruction/recovered'),
            str(bridge_src), str(contract_src),
            '-o', str(so_path)
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode == 0, res.stderr
        cdll = ctypes.CDLL(str(so_path))
        fn = cdll.recovered_trading_post_init_slots_run
        fn.argtypes = [
            ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_char_p, ctypes.c_char_p
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

    save_dict_ptr = 0x60010000
    uc.mem_map(save_dict_ptr, 0x1000)

    rows = []
    for case in CASES:
        merged = dict(BASE)
        merged.update({k: v for k, v in case.items() if k != 'name'})
        state['case'] = merged
        state['trace'] = []
        state['enum_idx'] = 0
        state['item_map'] = {tok: itype for tok, itype in merged['items']}
        state['current_item_tok'] = merged['items'][0][0] if merged['items'] else 0
        state['enum_sub_idx'] = 0
        state['batch_count'] = 0

        self_ptr = merged['self_ptr']
        uc.mem_write(self_ptr, b'\x00' * IMAGE_SIZE)

        session.run(IMP, sp_offset=0x8000,
                    R0=self_ptr, R1=cmd_sel, R2=save_dict_ptr)

        arm_image = bytes(uc.mem_read(self_ptr, IMAGE_SIZE))
        arm_trace = list(state['trace'])

        # C++ comparison
        item_toks = [tok for tok, _ in merged['items']]
        item_types = [itype for _, itype in merged['items']]
        c_tok_arr = (ctypes.c_uint32 * len(item_toks))(*item_toks) if item_toks else None
        c_type_arr = (ctypes.c_uint32 * len(item_types))(*item_types) if item_types else None

        for opt, fn in fns:
            cpp_img_buf = ctypes.create_string_buffer(IMAGE_SIZE)
            cpp_trace_buf = ctypes.create_string_buffer(128 * 8)
            n = fn(
                merged['self_ptr'], merged['sell_slot_array_token'],
                1 if merged['has_sell_slot_key'] else 0,
                len(item_toks), c_tok_arr, c_type_arr,
                cpp_img_buf, cpp_trace_buf
            )
            cpp_image = cpp_img_buf.raw
            cpp_trace = []
            for i in range(n):
                rec = cpp_trace_buf.raw[i*8:(i+1)*8]
                code = rec[0]
                arg = struct.unpack('<I', rec[4:8])[0]
                cpp_trace.append((code, arg))

            assert arm_image == cpp_image, f"-O{opt} image mismatch in {case['name']}"
            assert arm_trace == cpp_trace, (f"-O{opt} trace mismatch in {case['name']}", arm_trace, cpp_trace)

        rows.append({
            'case': case['name'],
            'trace_len': len(arm_trace),
            'item_count': len(item_toks)
        })

    report = {
        'sha256': SHA,
        'class': 'TradingPost',
        'method': 'initSlotsWithSaveDict:',
        'imp': hex(IMP),
        'cases': len(CASES),
        'match': True,
        'rows': rows,
        'boundary': (
            "Unicorn execution of the original 243-word method. [[NSMutableArray alloc] init], "
            "objectForKey:@'sellSlot' lookup, countByEnumeratingWithState:objects:count: fast-enumeration "
            "loop in chunks of up to 16, [[InventoryItem alloc] initWithSaveData:] child construction, "
            "[item autorelease], [item itemType] extraction with itemType == 11 filter (0xb), "
            "and self->needsToUpdateBitmapString store at offset 124 execute bit-for-bit."
        )
    }

    (a.output_dir / 'trading_post_init_slots_arm_result.json').write_text(json.dumps(report, indent=2))
    print(f"trading_post_init_slots_arm: PASS ({len(CASES)} cases)")
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
