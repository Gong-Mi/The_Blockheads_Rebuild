#!/usr/bin/env python3
"""Execute the ORIGINAL ARM `-[NPC loadValuesFromSaveDict:]` (0x00643b20, 603
words) under Unicorn with a synthetic save dictionary and compare the
resulting instance image and message trace against the recovered C++ contract
(reconstruction/recovered/npc_load_values_from_save_dict.cpp, built at -O0 and
-O2).

Synthetic graph (stated limits — not Foundation, not the original-app
runtime):
  * `objc_msgSend` (GOT slot 0x0105b7a0) is stubbed and dispatches on the
    selector string the body loads from its own selref cells:
      - objectForKey:      receiver must be the synthetic save dictionary;
        the key is the CFString OBJECT in r2, resolved through its +8 data
        pointer. Present keys return a per-key box, absent keys return nil.
      - floatValue/intValue/boolValue/unsignedIntegerValue: the receiver is
        the box; the per-key payload is returned raw (single precision bits
        travel through vmov s0, r0 -> vstr unchanged).
      - retain / autorelease: identity, so object payloads and the old
        name/tameCounts tokens are observed as receivers.
      - dictionaryWithDictionary:: the receiver must be the synthetic
        NSMutableDictionary class object (classref cell 0x00e8a238 is patched
        because its file word is 0); returns the fixed kNpcLoadDictCopyToken
        both sides store at tameCountsByClientID@104.
  * Everything else — the whole 603-word body, the group gates (fullness /
    layCooldownTimer / breed / currentBlockheadIndex probes), the str/strh/
    strb/vstr stores at their decoded widths, the -1 default store, the
    two-level ivar-offset resolution — executes for real.
Checked per case: the exact call trace, the 160-byte instance image, and
expectations computed independently of the C++ pair (strh truncations, the
-1 default, the copy token, untouched bytes staying zero).
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
IMP = 0x00643B20
GOT_MSGSEND = 0x0105B7A0
NSMUTABLEDICTIONARY_CLASSREF = 0x00E8A238
COPY_TOKEN = 0x00D1C700
IMAGE_SIZE = 160

KEYS = ['fullness', 'layTimer', 'damage', 'age',
        'layCooldownTimer', 'tameCooldownTimer', 'mateCooldownTimer',
        'hasBred', 'hasBeenFedByBlockheadOrChest', 'mateBreed',
        'breed', 'tamedClientID', 'name', 'tameCountsByClientID',
        'currentBlockheadIndex']

# Trace codes follow the C++ enum NpcLoadCall exactly (order chosen to keep
# the per-key ObjectForKey codes stable): object keys after tamedClientID
# continue at 14/15/17 because 12/13/16 are Retain/Autorelease/
# DictionaryWithDictionary.
OFK = {'fullness': 0, 'layTimer': 1, 'damage': 2, 'age': 3,
       'layCooldownTimer': 4, 'tameCooldownTimer': 5, 'mateCooldownTimer': 6,
       'hasBred': 7, 'hasBeenFedByBlockheadOrChest': 8, 'mateBreed': 9,
       'breed': 10, 'tamedClientID': 11, 'name': 14,
       'tameCountsByClientID': 15, 'currentBlockheadIndex': 17}
FLOAT_VALUE, INT_VALUE, BOOL_VALUE, UINT_VALUE = 18, 19, 20, 21
RETAIN, AUTO_RELEASE, DICT_WITH_DICT = 12, 13, 16

# Object-key payloads are the per-key box addresses; filled in after mapping.
DEFAULT_BITS = {
    'fullness': 0x3F8CCCCD,            # 1.1f
    'layTimer': 0x41200000,            # 10.0f
    'damage': 70000,
    'age': 0x42200000,                 # 40.0f
    'layCooldownTimer': 0x3FC00000,    # 1.5f
    'tameCooldownTimer': 0x40200000,   # 2.5f
    'mateCooldownTimer': 0x40600000,   # 3.5f
    'hasBred': 1,
    'hasBeenFedByBlockheadOrChest': 1,
    'mateBreed': 0xFFFFFFFF,           # -1
    'breed': 0x12345678,
    'currentBlockheadIndex': 7,
}

CASES = [
    {'name': 'all_present_old_nil'},
    {'name': 'all_present_old_set', 'old_name': 0x0D1A5E11,
     'old_tame_counts': 0x0D1C7000},
    {'name': 'missing_fullness', 'absent': ['fullness']},
    {'name': 'missing_laycooldown', 'absent': ['layCooldownTimer']},
    {'name': 'missing_breed', 'absent': ['breed']},
    {'name': 'missing_currentblockhead', 'absent': ['currentBlockheadIndex']},
    {'name': 'missing_tamecounts', 'absent': ['tameCountsByClientID']},
    {'name': 'missing_tamedclientid_name',
     'absent': ['tamedClientID', 'name'], 'old_name': 0x0D1A5E11},
    {'name': 'truncations'},
    {'name': 'float_edges',
     'bits': {'fullness': 0x00000001, 'layTimer': 0x7F7FFFFF,
              'age': 0xFF800000, 'layCooldownTimer': 0x7FC00000,
              'tameCooldownTimer': 0x80800000,
              'mateCooldownTimer': 0x3EAAAAAB}},
]


def expected_trace(present):
    t = [OFK['fullness']]
    if present['fullness']:
        t += [OFK['fullness'], FLOAT_VALUE,
              OFK['layTimer'], FLOAT_VALUE,
              OFK['damage'], INT_VALUE,
              OFK['age'], FLOAT_VALUE]
    t += [OFK['layCooldownTimer']]
    if present['layCooldownTimer']:
        t += [OFK['layCooldownTimer'], FLOAT_VALUE,
              OFK['tameCooldownTimer'], FLOAT_VALUE,
              OFK['mateCooldownTimer'], FLOAT_VALUE,
              OFK['hasBred'], BOOL_VALUE,
              OFK['hasBeenFedByBlockheadOrChest'], BOOL_VALUE,
              OFK['mateBreed'], INT_VALUE]
    t += [OFK['breed']]
    if present['breed']:
        t += [OFK['breed'], UINT_VALUE]
    t += [OFK['tamedClientID'], RETAIN,
          AUTO_RELEASE,
          OFK['name'], RETAIN,
          AUTO_RELEASE,
          OFK['tameCountsByClientID']]
    if present['tameCountsByClientID']:
        t += [DICT_WITH_DICT, RETAIN]
    t += [OFK['currentBlockheadIndex']]
    if present['currentBlockheadIndex']:
        t += [OFK['currentBlockheadIndex'], INT_VALUE]
    return t


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

    graph, stack, stop, stub = (0x60000000, 0x70000000, 0x71000000, 0x72000000)
    for base in (graph, stack, stop, stub):
        uc.mem_map(base, 0x10000 if base in (graph, stack) else 0x1000)
    cmd_region = 0x73000000
    uc.mem_map(cmd_region, 0x1000)

    def word(at, value):
        uc.mem_write(at, struct.pack('<I', value & 0xffffffff))

    self_ptr = graph
    save_dict = graph + 0x1000
    cfstring_base = graph + 0x2000
    cstring_base = graph + 0x3000
    box_base = graph + 0x4000
    nsmutabledict_class = graph + 0x5000

    # Synthetic CFString objects: {isa, info, data_ptr, len}; the body passes
    # the OBJECT in r2, so the stub resolves the key via the +8 data pointer.
    for i, name in enumerate(KEYS):
        cs = cfstring_base + i * 0x20
        s = cstring_base + i * 0x20
        uc.mem_write(s, name.encode() + b'\0')
        word(cs + 0, 0x11111111)          # isa (synthetic, never dereferenced)
        word(cs + 4, 0)                   # info
        word(cs + 8, s)                   # data pointer
        word(cs + 12, len(name))          # length
        # per-key box: {key_index, payload}
        word(box_base + i * 0x20 + 0, i)
        word(box_base + i * 0x20 + 4, DEFAULT_BITS.get(name, 0))

    boxes = {name: box_base + i * 0x20 for i, name in enumerate(KEYS)}
    cfstrings = {name: cfstring_base + i * 0x20 for i, name in enumerate(KEYS)}
    for name in ('tamedClientID', 'name', 'tameCountsByClientID'):
        word(boxes[name] + 4, boxes[name])  # object payload = box address

    word(GOT_MSGSEND, stub)
    word(NSMUTABLEDICTIONARY_CLASSREF, nsmutabledict_class)
    uc.mem_write(cmd_region, b'loadValuesFromSaveDict:\0')

    state = {'present': {k: True for k in KEYS}, 'calls': []}

    def hook(uc_, address, size, data):
        recv = uc_.reg_read(UC_ARM_REG_R0)
        sel_ptr = uc_.reg_read(UC_ARM_REG_R1)
        sel = bytes(uc_.mem_read(sel_ptr, 64)).split(b'\0')[0].decode()
        arg = uc_.reg_read(UC_ARM_REG_R2)
        if sel == 'objectForKey:':
            assert recv == save_dict, ('objectForKey receiver', hex(recv))
            data_ptr = int.from_bytes(bytes(uc_.mem_read(arg + 8, 4)), 'little')
            key = bytes(uc_.mem_read(data_ptr, 48)).split(b'\0')[0].decode()
            assert key in boxes, (hex(arg), repr(key))
            state['calls'].append(OFK[key])
            uc_.reg_read(UC_ARM_REG_R3)
            uc_.reg_write(UC_ARM_REG_R0,
                          boxes[key] if state['present'][key] else 0)
        elif sel in ('floatValue', 'intValue', 'boolValue',
                     'unsignedIntegerValue'):
            key_index = int.from_bytes(bytes(uc_.mem_read(recv, 4)), 'little')
            payload = int.from_bytes(bytes(uc_.mem_read(recv + 4, 4)),
                                     'little')
            assert 0 <= key_index < len(KEYS), ('box receiver', hex(recv))
            code = {'floatValue': FLOAT_VALUE, 'intValue': INT_VALUE,
                    'boolValue': BOOL_VALUE,
                    'unsignedIntegerValue': UINT_VALUE}[sel]
            state['calls'].append(code)
            uc_.reg_write(UC_ARM_REG_R0, payload & 0xffffffff)
        elif sel == 'retain':
            state['calls'].append(RETAIN)
            uc_.reg_write(UC_ARM_REG_R0, recv)
        elif sel == 'autorelease':
            state['calls'].append(AUTO_RELEASE)
            uc_.reg_write(UC_ARM_REG_R0, recv)
        elif sel == 'dictionaryWithDictionary:':
            assert recv == nsmutabledict_class, ('class receiver', hex(recv))
            assert arg == boxes['tameCountsByClientID'], \
                ('copy source', hex(arg))
            state['calls'].append(DICT_WITH_DICT)
            uc_.reg_write(UC_ARM_REG_R0, COPY_TOKEN)
        else:
            raise AssertionError(('unimplemented message', hex(recv), sel))
        uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

    uc.hook_add(UC_HOOK_CODE, hook, begin=stub, end=stub + 4)

    repo = Path(__file__).resolve().parents[1]
    # Termux clang++ links the shared bridge against libc++_shared.so, which
    # is not in the default loader namespace for dlopen; preload it so the
    # bridge's dependency resolves (no-op on hosts where it is absent).
    import os
    libcxx = Path(os.environ.get('PREFIX', '')) / 'lib/libc++_shared.so'
    if libcxx.is_file():
        ctypes.CDLL(str(libcxx), mode=ctypes.RTLD_GLOBAL)
    fns = []
    for opt in (0, 2):
        lib = a.output_dir / f'npc_load_values-O{opt}.so'
        subprocess.run(['clang++', '-std=c++17', f'-O{opt}', '-UNDEBUG',
                        '-fno-fast-math', '-ffp-contract=off', '-fPIC',
                        '-shared',
                        '-I' + str(repo / 'reconstruction/recovered'),
                        str(repo / 'tools/npc_load_values_arm_bridge.cpp'),
                        str(repo / 'reconstruction/recovered'
                            '/npc_load_values_from_save_dict.cpp'),
                        '-o', str(lib)], check=True)
        cdll = ctypes.CDLL(str(lib))
        fn = cdll.recovered_npc_load_values_run
        fn.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint32),
                       ctypes.c_uint32, ctypes.c_uint32,
                       ctypes.c_char_p, ctypes.c_char_p]
        fn.restype = ctypes.c_uint32
        fns.append(fn)

    def halfword(image, off):
        return struct.unpack('<H', image[off:off + 2])[0]

    def word_at(image, off):
        return struct.unpack('<I', image[off:off + 4])[0]

    rows = []
    for case in CASES:
        absent = set(case.get('absent', []))
        present = {k: k not in absent for k in KEYS}
        state['present'] = present
        state['calls'] = []

        uc.mem_write(self_ptr, b'\x00' * IMAGE_SIZE)
        word(self_ptr + 92, case.get('old_name', 0))
        word(self_ptr + 104, case.get('old_tame_counts', 0))

        for name, value in case.get('bits', {}).items():
            word(boxes[name] + 4, value & 0xffffffff)

        sp = stack + 0x8000
        uc.reg_write(UC_ARM_REG_R0, self_ptr)
        uc.reg_write(UC_ARM_REG_R1, cmd_region)
        uc.reg_write(UC_ARM_REG_R2, save_dict)
        uc.reg_write(UC_ARM_REG_SP, sp)
        uc.reg_write(UC_ARM_REG_LR, stop)
        uc.emu_start(IMP, stop, count=200000)
        assert uc.reg_read(UC_ARM_REG_PC) == stop, 'method did not return'

        arm_image = bytes(uc.mem_read(self_ptr, IMAGE_SIZE))
        arm_trace = list(state['calls'])
        expected = expected_trace(present)
        assert arm_trace == expected, (case['name'], arm_trace, expected)

        # Restore default payloads mutated by earlier cases.
        for name, value in DEFAULT_BITS.items():
            word(boxes[name] + 4, value & 0xffffffff)
        for name in ('tamedClientID', 'name', 'tameCountsByClientID'):
            word(boxes[name] + 4, boxes[name])

        present_bytes = bytes(1 if present[k] else 0 for k in KEYS)
        bits = (ctypes.c_uint32 * len(KEYS))()
        for i, name in enumerate(KEYS):
            if name in case.get('bits', {}):
                value = case['bits'][name]
            elif name in DEFAULT_BITS:
                value = DEFAULT_BITS[name]
            else:
                value = boxes[name]  # object payload = the box address
            bits[i] = value & 0xffffffff

        cpp_images, cpp_traces = [], []
        for fn in fns:
            image_out = ctypes.create_string_buffer(IMAGE_SIZE)
            trace_out = ctypes.create_string_buffer(64)
            n = fn(present_bytes, bits, case.get('old_name', 0),
                   case.get('old_tame_counts', 0), image_out, trace_out)
            cpp_images.append(image_out.raw)
            cpp_traces.append(list(trace_out.raw[:n]))

        for image, trace in zip(cpp_images, cpp_traces):
            assert image == arm_image, (case['name'], 'image mismatch')
            assert trace == arm_trace, (case['name'], 'trace mismatch')

        # Expectations computed independently of the recovered C++ pair.
        if case['name'] in ('all_present_old_nil', 'all_present_old_set',
                            'truncations'):
            assert halfword(arm_image, 54) == 4464, \
                ('damage strh truncation', case['name'])
            assert halfword(arm_image, 98) == 0xFFFF, 'mateBreed strh -1'
            assert halfword(arm_image, 96) == 0x5678, 'breed strh truncation'
        if case['name'] == 'missing_currentblockhead':
            assert word_at(arm_image, 136) == 0xFFFFFFFF, \
                'absent index leaves the -1 default'
        if case['name'] == 'missing_fullness':
            assert word_at(arm_image, 68) == 0 and \
                word_at(arm_image, 80) == 0 and \
                halfword(arm_image, 54) == 0 and \
                word_at(arm_image, 88) == 0, 'group 1 fully skipped'
        if case['name'] == 'missing_tamecounts':
            assert word_at(arm_image, 104) == 0 and \
                DICT_WITH_DICT not in arm_trace, 'no dictionary copy'
        rows.append({'case': case['name'], 'trace_len': len(arm_trace)})

    report = {
        'sha256': SHA, 'class': 'NPC', 'method': 'loadValuesFromSaveDict:',
        'entry': f'0x{IMP:08x}', 'cases': len(rows), 'match': True,
        'boundary': (
            'Unicorn execution of the original 603-word method with a '
            'synthetic save dictionary (objectForKey: + conversion + retain/'
            'autorelease + dictionaryWithDictionary: stubs; the classref '
            'cell and the msgSend GOT slot patched). The group gates, the '
            'str/strh/strb/vstr stores at decoded widths, the -1 default '
            'store and the two-level ivar-offset resolution execute for '
            'real. Not Foundation, not the original-app runtime, not device '
            'gameplay; the dictionary, the boxes and the mutable-dictionary '
            'copy are stubs agreed with the recovered C++ by the fixed '
            'kNpcLoadDictCopyToken.'),
        'rows': rows,
    }
    (a.output_dir / 'npc-loadvalues-arm-result.json').write_text(
        json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('sha256', 'cases', 'match',
                                             'boundary')}, indent=2))


if __name__ == '__main__':
    main()
