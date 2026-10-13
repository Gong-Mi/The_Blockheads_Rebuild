#!/usr/bin/env python3
"""Execute the ORIGINAL ARM body of TradePortal -[loadPriceOffsets:]
(IMP 0x00D37A78, 197 words, batch b4i) under Unicorn and compare the instance image
and message trace byte-for-byte against the recovered C++ contract
(reconstruction/recovered/trade_portal_price_offsets.cpp, built at -O0 and -O2).

Synthetic model:
  * objc_msgSend (GOT slot 0x0105B7A0) is stubbed:
    - countByEnumeratingWithState:objects:count: on sourceDict
    - objectForKey: on sourceDict -> returns boxed double
    - doubleValue on boxed double -> returns f64 softfp pair r0:r1
    - [NSNumber numberWithDouble:clamped_d0] (receiver is OBJC_CLASS_$_NSNumber 0x00E8B754)
    - [self->localPriceOffsets setObject:num forKey:key]
  * memset (0x001C2924 via slot 0x0105FB70) is routed natively
  * objc_enumerationMutation (0x001C2E28 via slot 0x0105FD1C) is stubbed (no-op)
  * The clamp sequence:
      if (val < 0.5) val = 0.5;
      else if (val > 2.0) val = 2.0;
    executes against real ARM VFP instructions (vcmpe.f64 / bpl / ble).
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
from trace_codes_gen import TRADE_PORTAL_PRICE_OFFSETS_CODES as TPC

SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
IMP = 0x00D37A78
IMAGE_SIZE = 160

GOT_MSGSEND = 0x0105B7A0
MEMSET_SLOT = 0x0105FB70
MUTATION_SLOT = 0x0105FD1C
NSNUMBER_CLASS_SLOT = 0x00E8B754
NSNUMBER_CLASS = 0x00E92400

ENUM_SELECTOR = 'countByEnumeratingWithState:objects:count:'
OFK_SELECTOR = 'objectForKey:'
DOUBLE_VAL_SELECTOR = 'doubleValue'
NUM_WITH_DOUBLE_SELECTOR = 'numberWithDouble:'
SET_OBJ_SELECTOR = 'setObject:forKey:'

STUB_MSG = 0x72000000
STUB_MEMSET = 0x72100000
STUB_MUTATION = 0x72200000

BASE = {
    'self_ptr': 0x60000000,
    'local_price_offsets_token': 0xD1C70001,
}

CASES = [
    {
        'name': 'empty_dict',
        'entries': [],
    },
    {
        'name': 'clamp_low_edge',
        'entries': [('item_01', 0.1), ('item_02', 0.499999), ('item_03', 0.5)],
    },
    {
        'name': 'clamp_high_edge',
        'entries': [('item_10', 2.0), ('item_11', 2.00001), ('item_12', 100.0)],
    },
    {
        'name': 'within_range',
        'entries': [('flint', 0.75), ('copper', 1.0), ('iron', 1.5)],
    },
    {
        'name': 'negative_values',
        'entries': [('wood', -10.0), ('stone', -0.0001)],
    },
    {
        'name': 'nan_float',
        'entries': [('corrupted', float('nan'))],
    },
]


def f64_to_pair(val):
    raw = struct.pack('<d', val)
    return struct.unpack('<II', raw)


def pair_to_f64(lo, hi):
    raw = struct.pack('<II', lo, hi)
    return struct.unpack('<d', raw)[0]


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
    session.word(NSNUMBER_CLASS_SLOT, NSNUMBER_CLASS)

    cmd_sel = graph.command_selector('loadPriceOffsets:')

    items_page = 0x60080000
    uc.mem_map(items_page, 0x1000)

    state = {
        'case': None,
        'trace': [],
        'enum_idx': 0,
        'key_map': {},
        'val_map': {},
        'num_map': {},
        'next_token': 0x80000000,
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

        assert address == STUB_MSG
        recv = uc_.reg_read(UC_ARM_REG_R0)
        sel_ptr = uc_.reg_read(UC_ARM_REG_R1)
        sel = bytes(uc_.mem_read(sel_ptr, 64)).split(b'\0')[0].decode()
        r2 = uc_.reg_read(UC_ARM_REG_R2)
        r3 = uc_.reg_read(UC_ARM_REG_R3)

        if sel == ENUM_SELECTOR:
            entries = case['entries']
            remaining = len(entries) - state['enum_idx']
            batch_count = min(remaining, 16)
            state['trace'].append((TPC['FastEnumeration'], batch_count))

            state_ptr = r2
            if batch_count > 0:
                for i in range(batch_count):
                    k_str, _ = entries[state['enum_idx'] + i]
                    k_tok = state['key_map'][k_str]
                    session.word(items_page + i * 4, k_tok)
                session.word(state_ptr + 0, 0)
                session.word(state_ptr + 4, items_page)
                session.word(state_ptr + 8, items_page + 0x200)
                state['enum_idx'] += batch_count
                uc_.reg_write(UC_ARM_REG_R0, batch_count)
            else:
                uc_.reg_write(UC_ARM_REG_R0, 0)
        elif sel == OFK_SELECTOR:
            key_tok = r2
            state['trace'].append((TPC['ObjectForKey'], key_tok))
            val_tok = state['val_map'][key_tok]
            uc_.reg_write(UC_ARM_REG_R0, val_tok)
        elif sel == DOUBLE_VAL_SELECTOR:
            val_tok = recv
            key_tok = state['val_to_key'][val_tok]
            state['trace'].append((TPC['DoubleValue'], key_tok))
            raw_val = state['key_to_raw'][key_tok]
            lo, hi = f64_to_pair(raw_val)
            uc_.reg_write(UC_ARM_REG_R0, lo)
            uc_.reg_write(UC_ARM_REG_R1, hi)
        elif sel == NUM_WITH_DOUBLE_SELECTOR:
            assert recv == NSNUMBER_CLASS, ('numberWithDouble class', hex(recv))
            lo, hi = r2, r3
            d_val = pair_to_f64(lo, hi)
            state['trace'].append((TPC['NumberWithDouble'], lo))
            num_tok = state['next_token']
            state['next_token'] += 4
            state['num_map'][num_tok] = d_val
            uc_.reg_write(UC_ARM_REG_R0, num_tok)
        elif sel == SET_OBJ_SELECTOR:
            num_tok = r2
            key_tok = uc_.reg_read(UC_ARM_REG_R3)
            assert recv == case['local_price_offsets_token']
            state['trace'].append((TPC['SetObjectForKey'], key_tok))
            uc_.reg_write(UC_ARM_REG_R0, 0)
        else:
            raise AssertionError(('unexpected sel', sel))

        uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

    from unicorn import UC_HOOK_CODE
    uc.hook_add(UC_HOOK_CODE, hook, begin=STUB_MSG, end=STUB_MSG + 4)
    uc.hook_add(UC_HOOK_CODE, hook, begin=STUB_MEMSET, end=STUB_MEMSET + 4)
    uc.hook_add(UC_HOOK_CODE, hook, begin=STUB_MUTATION, end=STUB_MUTATION + 4)

    repo = Path(__file__).resolve().parents[1]
    import os
    env = dict(os.environ)
    prefix_lib = Path('/data/data/com.termux/files/usr/lib')
    if prefix_lib.exists():
        env['LD_LIBRARY_PATH'] = str(prefix_lib) + ':' + env.get('LD_LIBRARY_PATH', '')

    for opt in (0, 2):
        so = a.output_dir / f'trade_portal-O{opt}.so'
        cmd = ['clang++', '-std=c++17', f'-O{opt}', '-fPIC', '-shared',
               '-UNDEBUG', '-fno-fast-math', '-ffp-contract=off',
               '-I' + str(repo / 'reconstruction/recovered'),
               str(repo / 'reconstruction/recovered/trade_portal_price_offsets.cpp'),
               str(repo / 'tools/trade_portal_price_offsets_arm_bridge.cpp'),
               '-o', str(so)]
        subprocess.run(cmd, check=True, env=env)

    lib_path = prefix_lib / 'libc++_shared.so'
    if lib_path.exists():
        ctypes.CDLL(str(lib_path), mode=ctypes.RTLD_GLOBAL)

    fns = []
    for opt in (0, 2):
        so = a.output_dir / f'trade_portal-O{opt}.so'
        dll = ctypes.CDLL(str(so))
        fn = dll.recovered_trade_portal_price_offsets_run
        fn.argtypes = [
            ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_double),
            ctypes.c_char_p, ctypes.c_char_p
        ]
        fn.restype = ctypes.c_uint32
        fns.append((opt, fn))

    rows = []
    source_dict_page = 0x60090000
    uc.mem_map(source_dict_page, 0x1000)

    for case in CASES:
        merged = dict(BASE)
        merged.update({k: v for k, v in case.items() if k != 'name'})
        state['case'] = merged
        state['trace'] = []
        state['enum_idx'] = 0
        state['key_map'] = {}
        state['val_map'] = {}
        state['val_to_key'] = {}
        state['key_to_raw'] = {}
        state['num_map'] = {}
        state['next_token'] = 0x80000000

        # Build tokens for keys and values
        key_tokens = []
        raw_vals = []
        for i, (k_name, r_val) in enumerate(merged['entries']):
            k_tok = 0xA0000000 + i * 4
            v_tok = 0xB0000000 + i * 4
            state['key_map'][k_name] = k_tok
            state['val_map'][k_tok] = v_tok
            state['val_to_key'][v_tok] = k_tok
            state['key_to_raw'][k_tok] = r_val
            key_tokens.append(k_tok)
            raw_vals.append(r_val)

        self_ptr = merged['self_ptr']
        uc.mem_write(self_ptr, b'\x00' * IMAGE_SIZE)
        graph.word(self_ptr + 128, merged['local_price_offsets_token'])

        session.run(IMP, sp_offset=0x8000,
                    R0=self_ptr, R1=cmd_sel, R2=source_dict_page)

        arm_image = bytes(uc.mem_read(self_ptr, IMAGE_SIZE))
        arm_trace = list(state['trace'])

        # C++ comparison
        c_key_arr = (ctypes.c_uint32 * len(key_tokens))(*key_tokens) if key_tokens else None
        c_val_arr = (ctypes.c_double * len(raw_vals))(*raw_vals) if raw_vals else None

        for opt, fn in fns:
            cpp_img_buf = ctypes.create_string_buffer(IMAGE_SIZE)
            cpp_trace_buf = ctypes.create_string_buffer(64 * 8)
            n = fn(
                merged['self_ptr'], merged['local_price_offsets_token'],
                len(key_tokens), c_key_arr, c_val_arr,
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
            'entry_count': len(key_tokens)
        })

    report = {
        'sha256': SHA,
        'class': 'TradePortal',
        'method': 'loadPriceOffsets:',
        'imp': hex(IMP),
        'cases': len(CASES),
        'match': True,
        'rows': rows,
        'boundary': (
            'Unicorn execution of the original 197-word method (price-offset normalization). '
            'The countByEnumeratingWithState:objects:count: fast-enumeration loop, '
            'objectForKey: lookup, doubleValue extraction, [0.5, 2.0] VFP clamping '
            '(vcmpe.f64 / bpl / ble), [NSNumber numberWithDouble:] instantiation, and '
            '[self->localPriceOffsets setObject:forKey:] execute bit-for-bit.'
        )
    }
    report_path = a.output_dir / 'trade_portal_price_offsets_arm_result.json'
    report_path.write_text(json.dumps(report, indent=2))
    print(f"trade_portal_price_offsets_arm: PASS ({len(CASES)} cases)")
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
