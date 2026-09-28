#!/usr/bin/env python3
"""Execute the ORIGINAL ARM bodies of the mid-tier key-table family under
Unicorn and compare against the module's own spec table (via
tools/midtier_arm_bridge.cpp -> reconstruction/recovered/midtier_full.h).

Covered here (10 classes; Boat 32 has the probe/default shape and is handled
separately): Window 31, Rail 40, Ladder 19, Egg 30, Column 53, Stairs 54,
Door 20, Wire 38, ElevatorShaft 56, ElevatorMotor 55.

Synthetic model (stated limits — not Foundation, not the original-app runtime):
  * objc_msgSendSuper2 stubbed: asserts {self, own-class-from-the-superref-cell},
    the loader selector and the four argument pointers.
  * objc_msgSend stubbed for the whole read chain: objectForKey: on the
    saveDict (key names resolved through the REAL ELF CFString objects),
    intValue / boolValue / unsignedIntValue / floatValue (s0) / retain, and the
    unconditional initSubDerivedItems tail hook. Conversions on a nil receiver
    return 0 (objc_msgSend-to-nil semantics).
  * case 0: every key present; case 1: even-index keys present (odd ones nil);
    case 2: nil super -> must return nil with no reads at all.

Per class and per case: the call-label sequence, the 256-byte instance image
and the return register must equal the bridge's (spec-table) expectation; the
sequence comparison also pins the READ ORDER the loader claims.
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
                               UC_ARM_REG_PC, UC_ARM_REG_S0, UC_ARM_REG_C1_C0_2,
                               UC_ARM_REG_FPEXC)

SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
GOT_SUPER2 = 0x0105B79C
GOT_MSGSEND = 0x0105B7A0
SUPER_SELECTOR = 'initWithWorld:dynamicWorld:saveDict:cache:'
HOOK_SELECTOR = 'initSubDerivedItems'
IMAGE_SIZE = 256
TOKEN_BASE = 0x5E1A0000

# (class, type id, imp, superref slot) — cells from the batch json
ENTRIES = [
    ('Window', 31, 0x00C98944, 0x00E8BED4),
    ('Rail', 40, 0x0077AB90, 0x00E8BD24),
    ('Ladder', 19, 0x00AADCD4, 0x00E8BE68),
    ('Egg', 30, 0x00D4E30C, 0x00E8BF24),
    ('Column', 53, 0x00834A30, 0x00E8BD80),
    ('Stairs', 54, 0x006CC734, 0x00E8BCC0),
    ('Door', 20, 0x007694FC, 0x00E8BD1C),
    ('Wire', 38, 0x0095002C, 0x00E8BDC0),
    ('ElevatorShaft', 56, 0x00CAD2CC, 0x00E8BEE8),
    ('ElevatorMotor', 55, 0x0070046C, 0x00E8BCE8),
]
INT_VALUE = 0x00012345
UINT_VALUE = 0x0001FFF1
FLOAT_VALUE = 1.5
BOOL_VALUE = 1
CONV_LABEL = {'intValue': 'int', 'boolValue': 'bool',
              'unsignedIntValue': 'uint', 'floatValue': 'float',
              'retain': 'retain'}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    ap.add_argument('--output-dir', type=Path, required=True)
    ap.add_argument('--dump', action='store_true',
                    help='print each class\'s ARM read order and exit')
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
    for base in (graph, stack):
        uc.mem_map(base, 0x10000)
    for base in (stop, stub_super, stub_send):
        uc.mem_map(base, 0x1000)
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
    ctx = {'case': 0, 'super_result': self_ptr, 'expect_class': 0,
           'keys': {}, 'pending_key': None, 'pending_token': 0,
           'labels': [], 'lenient': False, 'token_names': {}, 'nested': {}}

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
            ctx['labels'].append('super')
            uc_.reg_write(UC_ARM_REG_R0, ctx['super_result'])
        elif address == stub_send:
            recv = uc_.reg_read(UC_ARM_REG_R0)
            sel = cstring(uc_.reg_read(UC_ARM_REG_R1))
            if sel == 'objectForKey:':
                name = cstring(read_word(uc_.reg_read(UC_ARM_REG_R2) + 8))
                parent = ctx['nested'].get(name)
                if parent is not None and not ctx['lenient']:
                    # nested read: the body goes through self-><parent>
                    pidx, ppresent = ctx['keys'][parent]
                    expected = (TOKEN_BASE + pidx * 0x10) if ppresent else 0
                    assert recv == expected,                         ('nested receiver', name, hex(recv), hex(expected))
                    idx, present = ctx['keys'][name]
                    token = (TOKEN_BASE + idx * 0x10
                             if (present and ppresent) else 0)
                    ctx['pending_key'] = name
                    ctx['pending_token'] = token
                    ctx['labels'].append('ofk:' + name)
                    uc_.reg_write(UC_ARM_REG_R0, token)
                    uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))
                    return
                if ctx['lenient'] and recv != save_dict:
                    parent = ctx['token_names'].get(recv, '?')
                    ctx['labels'].append(f'ofk:{name}(in {parent})')
                    ctx['pending_key'] = name
                    ctx['pending_token'] = 0
                    uc_.reg_write(UC_ARM_REG_R0, 0)
                    uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))
                    return
                assert recv == save_dict, ('ofk receiver', hex(recv))
                assert name in ctx['keys'], ('unknown key', name)
                idx, present = ctx['keys'][name]
                token = TOKEN_BASE + idx * 0x10 if present else 0
                ctx['pending_key'] = name
                ctx['pending_token'] = token
                ctx['labels'].append('ofk:' + name)
                uc_.reg_write(UC_ARM_REG_R0, token)
            elif sel in CONV_LABEL:
                key = ctx['pending_key']
                assert key is not None, ('conversion before any key', sel)
                ctx['labels'].append(CONV_LABEL[sel] + ':' + key)
                # the original bodies do `vmov s0, r0` after floatValued
                # calls: the float comes back through r0 (objc_msgSend's
                # integer return path), so the stub sets BOTH r0 and s0.
                float_bits = struct.unpack('<I', struct.pack('<f', FLOAT_VALUE))[0]
                if recv == 0:
                    value = 0            # msgSend-to-nil
                    if sel == 'floatValue':
                        uc_.reg_write(UC_ARM_REG_S0, 0)
                elif ctx['lenient']:
                    value = float_bits if sel == 'floatValue' else 0
                    if sel == 'floatValue':
                        uc_.reg_write(UC_ARM_REG_S0, float_bits)
                else:
                    assert recv == ctx['pending_token'], \
                        ('conv receiver', hex(recv), sel, key)
                    if sel == 'intValue':
                        value = INT_VALUE
                    elif sel == 'boolValue':
                        value = BOOL_VALUE
                    elif sel == 'unsignedIntValue':
                        value = UINT_VALUE
                    elif sel == 'floatValue':
                        value = float_bits
                        uc_.reg_write(UC_ARM_REG_S0, float_bits)
                    else:            # retain
                        value = recv
                uc_.reg_write(UC_ARM_REG_R0, value & 0xffffffff)
            elif sel == HOOK_SELECTOR:
                assert recv == self_ptr, ('hook receiver', hex(recv))
                ctx['labels'].append('hook')
                uc_.reg_write(UC_ARM_REG_R0, 0)
            else:
                raise AssertionError(('unexpected selector', sel))
        else:
            raise AssertionError(('unexpected stub entry', hex(address)))
        uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

    for addr in (stub_super, stub_send):
        uc.hook_add(UC_HOOK_CODE, hook, begin=addr, end=addr + 4)

    repo = Path(__file__).resolve().parents[1]
    bridges = {}
    for opt in (0, 2):
        lib = a.output_dir / f'midtier-O{opt}.so'
        subprocess.run(['clang++', '-std=c++17', f'-O{opt}', '-UNDEBUG',
                        '-fno-fast-math', '-ffp-contract=off', '-fPIC', '-shared',
                        '-I' + str(repo / 'reconstruction/recovered'),
                        '-I' + str(repo / 'app/src/main/cpp'),
                        str(repo / 'tools/midtier_arm_bridge.cpp'),
                        str(repo / 'reconstruction/recovered/midtier_full.cpp'),
                        str(repo / 'app/src/main/cpp/original_save_dict.cpp'),
                        str(repo / 'app/src/main/cpp/dynamic_object_registry.cpp'),
                        '-o', str(lib)], check=True)
        cdll = ctypes.CDLL(str(lib))
        keys_fn = cdll.recovered_midtier_key_list
        keys_fn.argtypes = [ctypes.c_int32]
        keys_fn.restype = ctypes.c_char_p
        nested_fn = cdll.recovered_midtier_nested_in
        nested_fn.argtypes = [ctypes.c_int32, ctypes.c_char_p]
        nested_fn.restype = ctypes.c_char_p
        seq_fn = cdll.recovered_midtier_sequence
        seq_fn.argtypes = [ctypes.c_int32, ctypes.c_int32]
        seq_fn.restype = ctypes.c_char_p
        img_fn = cdll.recovered_midtier_image
        img_fn.argtypes = [ctypes.c_int32, ctypes.c_int32, ctypes.c_uint32,
                           ctypes.c_char_p, ctypes.c_int]
        img_fn.restype = ctypes.c_int
        bridges[opt] = (keys_fn, seq_fn, img_fn, nested_fn)

    def arm_run(entry, case_id):
        cls, type_id, imp, superref = entry
        keys_fn, seq_fn, img_fn, nested_fn = bridges[0]
        key_list = keys_fn(type_id).decode().split(',')
        ctx['case'] = case_id
        ctx['expect_class'] = read_word(superref)
        ctx['super_result'] = 0 if case_id == 2 else self_ptr
        ctx['keys'] = {}
        ctx['token_names'] = {}
        ctx['nested'] = {}
        for name in key_list:
            parent = nested_fn(type_id, name.encode()).decode()
            if parent:
                ctx['nested'][name] = parent
        for idx, name in enumerate(key_list):
            present = (case_id == 0) or (idx % 2 == 0)
            if case_id == 2:
                present = False
            ctx['keys'][name] = (idx, present)
            ctx['token_names'][TOKEN_BASE + idx * 0x10] = name
        ctx['pending_key'] = None
        ctx['pending_token'] = 0
        ctx['labels'] = []
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
        return ret, list(ctx['labels']), image

    if getattr(a, 'dump', False):
        ctx['lenient'] = True
        keys_fn, seq_fn, img_fn, nested_fn = bridges[0]
        for entry in ENTRIES:
            cls, type_id, imp, superref = entry
            ret, labels, _ = arm_run(entry, 0)
            keys = [l.split(':', 1)[1] for l in labels if l.startswith('ofk:')]
            print(f"{cls:14s} arm_order={keys}")
            print(f"{'':14s} spec_order={keys_fn(type_id).decode().split(',')}")
        return

    rows = []
    for entry in ENTRIES:
        cls, type_id, imp, superref = entry
        for case_id in (0, 1, 2):
            ret, labels, image = arm_run(entry, case_id)
            expected_ret = 0 if case_id == 2 else self_ptr
            assert ret == expected_ret, (cls, case_id, hex(ret))
            for opt in (0, 2):
                keys_fn, seq_fn, img_fn, nested_fn = bridges[opt]
                expected_seq = seq_fn(type_id, case_id).decode()
                assert ','.join(labels) == expected_seq, \
                    (cls, case_id, opt, ','.join(labels), expected_seq)
                buf = ctypes.create_string_buffer(IMAGE_SIZE)
                assert img_fn(type_id, case_id, TOKEN_BASE, buf, IMAGE_SIZE) == IMAGE_SIZE
                if buf.raw != image:
                    diff = [i for i in range(IMAGE_SIZE)
                            if buf.raw[i] != image[i]]
                    for off in diff:
                        print(f'  {cls} case {case_id} image diff at +{off}: '
                              f'arm={image[off]:02x} cpp={buf.raw[off]:02x}')
                assert buf.raw == image, (cls, case_id, opt, 'image mismatch')
            rows.append({'class': cls, 'type_id': type_id, 'case': case_id,
                         'arm_return': f'0x{ret:08x}',
                         'labels': labels,
                         'image_sha256': hashlib.sha256(image).hexdigest()[:32]})

    report = {
        'sha256': SHA, 'batch': 'midtier-keytable', 'classes': len(ENTRIES),
        'cases': len(rows), 'match': True,
        'boundary': ('Unicorn execution of the ten original key-table bodies '
                     'with a synthetic ObjC graph (stubbed super2 + the '
                     'objectForKey:/conversions/retain/hook dispatch), '
                     'compared to the module spec table (midtier_full.h) at '
                     '-O0/-O2 on call sequence, 256-byte instance image and '
                     'return register. Not Foundation, not the original-app '
                     'runtime, not device gameplay.'),
        'rows': rows,
    }
    (a.output_dir / 'midtier-arm-result.json').write_text(
        json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in
                      ('sha256', 'batch', 'classes', 'cases', 'match')},
                     indent=2))


if __name__ == '__main__':
    main()
