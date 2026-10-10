#!/usr/bin/env python3
"""Execute the ORIGINAL ARM body of
-[InteractionObject initWithWorld:dynamicWorld:saveDict:cache:]
(0x005f4634, 352 words) under Unicorn and compare the resulting 96-byte
instance image and the full call trace with the recovered C++ contract
(reconstruction/recovered/interaction_object_init.cpp at -O0 and -O2).

Synthetic model (stated limits — not Foundation, not the original-app
runtime):
  * objc_msgSendSuper2 is stubbed; it asserts {receiver, own-class superref
    cell} + the loader selector + the four argument pointers, then returns
    the case's super result.
  * objc_msgSend is stubbed for the whole read chain:
      objectForKey: on the saveDict (keys resolved through the REAL ELF
        CFString objects, data pointer at +8) -> the case's boxed token or 0;
      boolValue / intValue / unsignedIntValue on the token -> the case value
        (a nil receiver returns 0, the objc_msgSend-to-nil semantics);
      retain -> the receiver token;
      isServer on dynamicWorld -> the case flag;
      getOwnerNameForObjectOwnerID: -> the case's resolved token.
  * the instance memory is a zeroed 96-byte region at the graph base (the
    image-size rationale lives in the contract header).

Everything else (Foundation, boxed values, world side) is synthetic; the
differential is the executed counterpart of the decoded flow (call order +
store widths).
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
IMP = 0x005F4634
GOT_SUPER2 = 0x0105B79C
GOT_MSGSEND = 0x0105B7A0
SUPERREF_SLOT = 0x00E8BC68
LOADER_SELECTOR = 'initWithWorld:dynamicWorld:saveDict:cache:'
IMAGE_SIZE = 96

# must match tools/interaction_object_arm_bridge.cpp::makeInputs
CASES = [
    dict(in_use=1, flipped=1, owner_id=0x60001020,
         paint=0x10005, blockhead=-7, is_server=1, resolved=0x60001060),
    dict(super_nil=True),
    dict(),
    dict(paint=0x1234),
    dict(is_server=1, resolved=0x60001060),
    dict(owner_id=0x60001020, owner_name=0x60001030),
    dict(paint=0x1FFFF),
    dict(owner_id=0x60001020, owner_name=0x60001030, is_server=1,
         resolved=0x60001060),
]

# enum order of InteractionInitCall in the contract (bit index = position)
CALL_BIT_ORDER = [
    'super', 'ofk_isInUse', 'bool_isInUse', 'ofk_flipped', 'bool_flipped',
    'ofk_ownerID', 'retain_ownerID', 'ofk_ownerName', 'retain_ownerName',
    'ofk_paintColor', 'uint_paintColor', 'probe_blockhead', 'ofk_blockhead',
    'int_blockhead', 'isServer', 'resolve_ownerName', 'retain_resolved',
]
# harness-side call labels -> contract bit names
LABEL_TO_BIT = {
    'super': 'super',
    'ofk_isInUse': 'ofk_isInUse', 'bool_isInUse': 'bool_isInUse',
    'ofk_flipped': 'ofk_flipped', 'bool_flipped': 'bool_flipped',
    'ofk_ownerID': 'ofk_ownerID', 'retain_ownerID': 'retain_ownerID',
    'ofk_ownerName': 'ofk_ownerName', 'retain_ownerName': 'retain_ownerName',
    'ofk_paintColor': 'ofk_paintColor', 'uint_paintColor': 'uint_paintColor',
    'ofk_blockhead_1': 'probe_blockhead', 'ofk_blockhead_2': 'ofk_blockhead',
    'int_blockhead': 'int_blockhead', 'isServer': 'isServer',
    'resolve_ownerName': 'resolve_ownerName',
    'retain_resolved': 'retain_resolved',
}


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
    uc.mem_write(sel_region, LOADER_SELECTOR.encode() + b'\0')

    def word(at, value):
        uc.mem_write(at, struct.pack('<I', value & 0xffffffff))

    def read_word(at):
        return int.from_bytes(bytes(uc.mem_read(at, 4)), 'little')

    word(GOT_SUPER2, stub_super)
    word(GOT_MSGSEND, stub_send)

    self_ptr = graph
    world, dyn, save_dict, cache = (graph + 0x100, graph + 0x200,
                                    graph + 0x300, graph + 0x400)
    box_base = graph + 0x1000

    st = {'calls': [], 'case': None, 'super_result': self_ptr,
          'expect_class': 0, 'tokens': {}, 'pending_key': None,
          'pending_token': 0, 'pending_value': 0, 'last_producer': None,
          'blockhead_reads': 0, 'resolved_token': 0}

    def cstring(ptr):
        return bytes(uc.mem_read(ptr, 96)).split(b'\0')[0].decode()

    def hook(uc_, address, size, data):
        lr = uc_.reg_read(UC_ARM_REG_LR)
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
            assert cls == st['expect_class'], ('super class', hex(cls))
            assert sel == LOADER_SELECTOR, sel
            assert (r2, r3, a0, a1) == (world, dyn, save_dict, cache), \
                tuple(hex(v) for v in (r2, r3, a0, a1))
            st['calls'].append('super')
            uc_.reg_write(UC_ARM_REG_R0, st['super_result'])
        elif address == stub_send:
            recv = uc_.reg_read(UC_ARM_REG_R0)
            sel = cstring(uc_.reg_read(UC_ARM_REG_R1))
            if sel == 'objectForKey:':
                assert recv == save_dict, ('ofk receiver', hex(recv))
                name = cstring(read_word(uc_.reg_read(UC_ARM_REG_R2) + 8))
                if name == 'currentBlockheadIndex':
                    st['blockhead_reads'] += 1
                    label = f'ofk_blockhead_{st["blockhead_reads"]}'
                else:
                    label = 'ofk_' + name
                entry = st['tokens'].get(name)
                st['pending_key'] = name
                st['pending_token'] = entry[0] if entry else 0
                st['pending_value'] = entry[1] if entry else 0
                st['calls'].append(label)
                uc_.reg_write(UC_ARM_REG_R0, st['pending_token'])
            elif sel in ('boolValue', 'intValue', 'unsignedIntValue'):
                if recv == 0:
                    value = 0                      # msgSend-to-nil semantics
                else:
                    assert recv == st['pending_token'], \
                        ('conv receiver', hex(recv), sel, st['pending_key'])
                    value = st['pending_value']
                tag = {'boolValue': 'bool', 'intValue': 'int',
                       'unsignedIntValue': 'uint'}[sel]
                short = ('blockhead'
                         if st['pending_key'] == 'currentBlockheadIndex'
                         else st['pending_key'])
                st['calls'].append(tag + '_' + short)
                if st['pending_key'] == 'currentBlockheadIndex':
                    assert tag == 'int'
                uc_.reg_write(UC_ARM_REG_R0, value & 0xffffffff)
            elif sel == 'retain':
                if recv == 0:
                    st['calls'].append('retain_' + (st['pending_key'] or 'nil'))
                    uc_.reg_write(UC_ARM_REG_R0, 0)
                else:
                    # the tail's retain operates on the resolved world name
                    if st['last_producer'] == 'resolve':
                        st['calls'].append('retain_resolved')
                    else:
                        assert recv == st['pending_token'], \
                            ('retain receiver', hex(recv))
                        st['calls'].append('retain_' + st['pending_key'])
                    uc_.reg_write(UC_ARM_REG_R0, recv)
            elif sel == 'isServer':
                assert recv == dyn, ('isServer receiver', hex(recv))
                st['calls'].append('isServer')
                uc_.reg_write(UC_ARM_REG_R0,
                              st['case'].get('is_server', 0))
            elif sel == 'getOwnerNameForObjectOwnerID:':
                assert recv == dyn, ('resolve receiver', hex(recv))
                assert st['case'].get('owner_id'), 'resolve without ownerID'
                st['calls'].append('resolve_ownerName')
                st['last_producer'] = 'resolve'
                st['resolved_token'] = st['case'].get('resolved', 0)
                uc_.reg_write(UC_ARM_REG_R0, st['resolved_token'])
            else:
                raise AssertionError(('unexpected selector', sel))
        else:
            raise AssertionError(('unexpected stub entry', hex(address)))
        uc_.reg_write(UC_ARM_REG_PC, lr)

    for addr in (stub_super, stub_send):
        uc.hook_add(UC_HOOK_CODE, hook, begin=addr, end=addr + 4)

    def arm_run(case):
        st['case'] = case
        st['calls'] = []
        st['super_result'] = 0 if case.get('super_nil') else self_ptr
        st['expect_class'] = read_word(SUPERREF_SLOT)
        st['tokens'] = {}
        st['pending_key'] = None
        st['pending_token'] = 0
        st['last_producer'] = None
        st['blockhead_reads'] = 0
        mapping = [('isInUse', 'in_use'), ('flipped', 'flipped'),
                   ('ownerID', 'owner_id'), ('ownerName', 'owner_name'),
                   ('paintColor', 'paint'),
                   ('currentBlockheadIndex', 'blockhead')]
        for i, (key, field) in enumerate(mapping):
            if field in case:
                st['tokens'][key] = (box_base + i * 0x10, case[field])
        uc.mem_write(self_ptr, b'\x00' * IMAGE_SIZE)
        # the real super init stores world@4 / dynamicWorld@8 into the
        # instance before returning; the stubbed super must do the same,
        # otherwise the tail's [self+8 isServer] reads nil.
        word(self_ptr + 4, world)
        word(self_ptr + 8, dyn)
        sp = stack + 0x8000
        for reg, value in ((UC_ARM_REG_R0, self_ptr), (UC_ARM_REG_R1, sel_region),
                           (UC_ARM_REG_R2, world), (UC_ARM_REG_R3, dyn)):
            uc.reg_write(reg, value)
        uc.reg_write(UC_ARM_REG_SP, sp)
        uc.reg_write(UC_ARM_REG_LR, stop)
        word(sp, save_dict)
        word(sp + 4, cache)
        uc.emu_start(IMP, stop, count=20000)
        assert uc.reg_read(UC_ARM_REG_PC) == stop, 'no return'
        ret = uc.reg_read(UC_ARM_REG_R0)
        image = bytearray(uc.mem_read(self_ptr, IMAGE_SIZE))
        # +4 (world) / +8 (dynamicWorld) are stores of the STUBBED super init,
        # outside this contract's slice: zero them before the comparison.
        image[4:12] = b'\x00' * 8
        return ret, list(st['calls']), bytes(image)

    def bits_of(labels):
        bits = 0
        for label in labels:
            name = LABEL_TO_BIT.get(label)
            assert name is not None, ('unknown label', label)
            bits |= 1 << CALL_BIT_ORDER.index(name)
        return bits

    repo = Path(__file__).resolve().parents[1]
    fns = []
    for opt in (0, 2):
        lib = a.output_dir / f'interaction-O{opt}.so'
        subprocess.run(['clang++', '-std=c++17', f'-O{opt}', '-UNDEBUG',
                        '-fno-fast-math', '-ffp-contract=off', '-fPIC', '-shared',
                        '-I' + str(repo / 'reconstruction/recovered'),
                        str(repo / 'tools/interaction_object_arm_bridge.cpp'),
                        str(repo / 'reconstruction/recovered/interaction_object_init.cpp'),
                        '-o', str(lib)], check=True)
        cdll = ctypes.CDLL(str(lib))
        fn = cdll.recovered_interaction_arm_case
        fn.argtypes = [ctypes.c_uint32, ctypes.c_char_p]
        fn.restype = ctypes.c_uint64
        fns.append(fn)

    rows = []
    for case_id, case in enumerate(CASES):
        ret, labels, image = arm_run(case)
        expected_ret = 0 if case.get('super_nil') else self_ptr
        assert ret == expected_ret, (case_id, hex(ret))
        arm_bits = bits_of(labels)
        if expected_ret == 0:
            arm_bits |= 1 << 40  # returned-nil flag (matches the bridge)
        cpp_bits = []
        for fn in fns:
            buf = ctypes.create_string_buffer(IMAGE_SIZE)
            bits = fn(case_id, buf)
            cpp_bits.append((bits, bytes(buf.raw)))
        for bits, cpp_image in cpp_bits:
            assert bits == arm_bits, \
                (case_id, hex(arm_bits), hex(bits), labels)
            if cpp_image != image:
                diff = [i for i in range(IMAGE_SIZE)
                        if cpp_image[i] != image[i]]
                print(f'case {case_id} image diff at {diff}')
                for off in diff:
                    print(f'  +{off}: arm={image[off]:02x} cpp={cpp_image[off]:02x}')
            assert cpp_image == image, (case_id, 'image mismatch')
        rows.append({'case': case_id, 'arm_return': f'0x{ret:08x}',
                     'trace_bits': arm_bits,
                     'image_sha256': hashlib.sha256(image).hexdigest()[:32],
                     'calls': labels})

    report = {
        'sha256': SHA, 'imp': f'0x{IMP:08x}',
        'selector': LOADER_SELECTOR, 'cases': len(CASES), 'match': True,
        'image_size': IMAGE_SIZE,
        'boundary': ('Unicorn execution of the original 352-word body with a '
                     'synthetic ObjC message graph (stubbed objc_msgSendSuper2 '
                     '+ the dispatch stub for objectForKey:/conversions/retain/'
                     'isServer/getOwnerNameForObjectOwnerID:), compared to the '
                     'recovered C++ contract at -O0/-O2 on image and call '
                     'trace. Not Foundation, not the original-app runtime, not '
                     'device gameplay; the world side and the boxed values are '
                     'synthetic.'),
        'rows': rows,
    }
    (a.output_dir / 'interaction-arm-result.json').write_text(
        json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in
                      ('sha256', 'imp', 'cases', 'match')}, indent=2))


if __name__ == '__main__':
    main()
