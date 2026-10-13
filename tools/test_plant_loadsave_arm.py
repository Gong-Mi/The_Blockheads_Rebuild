#!/usr/bin/env python3
"""Execute the ORIGINAL ARM `-[Plant loadSaveDictValues:]` (0x009554a0, 332
words) under Unicorn with a synthetic save dictionary and compare the resulting
object fields against the recovered C++ contract
(reconstruction/recovered/plant_load_save_dict.cpp, built at -O0 and -O2).

Synthetic model (stated limits — not Foundation, not the original-app runtime):
  * `objc_msgSend` is stubbed for `objectForKey:` on a fake save dictionary
    (one distinct boxed value object per key) and for the value conversions
    `intValue` / `floatValue` / `boolValue` / `doubleValue` on those boxes.
  * `worldTime` is stubbed on the fake world object pointed at by self+4.
  * Everything else executes for real: the whole 332-word body, the
    destructive stores into the object's 100-byte instance (word / float /
    halfword / byte widths as decoded), the real local clamp helper at
    0x004c0b70 (called twice), and the saveTime gate.
Checked per case: every planted field read back at its ivar offset and width,
plus explicit expectations for the clamp edges and the 1800-second gate.
"""
import argparse
import ctypes
import hashlib
import json
import struct
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR,
                               UC_ARM_REG_PC, UC_ARM_REG_C1_C0_2,
                               UC_ARM_REG_FPEXC)

SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
IMP = 0x009554A0
GOT_MSGSEND = 0x0105B7A0
WORLD_IVAR = 4
OFFSETS = {'seasonOffset': (68, 'word'), 'age': (72, 'float'),
           'gatherProgress': (80, 'word'), 'frozen': (76, 'byte'),
           'flowering': (85, 'byte'), 'hasFloweredThisSeason': (84, 'byte'),
           'maxAgeGene': (54, 'halfword'), 'growthRateGene': (56, 'halfword')}
PLANT_INSTANCE_SIZE = 100

# Same inputs as the C++ contract test (keep both lists in sync).
CASES = [
    {'seasonOffset': 0, 'age': 0.0, 'gatherProgress': 0, 'hasFloweredThisSeason': 0,
     'flowering': 0, 'frozen': 0, 'maxAgeGene': 0, 'growthRateGene': 0,
     'saveTime': 0.0, 'worldTime': 0.0},
    {'seasonOffset': 1, 'age': 1.5, 'gatherProgress': 2, 'hasFloweredThisSeason': 1,
     'flowering': 1, 'frozen': 1, 'maxAgeGene': 1, 'growthRateGene': 1,
     'saveTime': 0.0, 'worldTime': 0.0},
    {'seasonOffset': 100, 'age': 42.25, 'gatherProgress': 7,
     'hasFloweredThisSeason': 1, 'flowering': 0, 'frozen': 1,
     'maxAgeGene': 255, 'growthRateGene': 255, 'saveTime': 0.0, 'worldTime': 0.0},
    {'seasonOffset': -5, 'age': -1.0, 'gatherProgress': -3,
     'hasFloweredThisSeason': 0, 'flowering': 1, 'frozen': 0,
     'maxAgeGene': 256, 'growthRateGene': 65535, 'saveTime': 0.0, 'worldTime': 0.0},
    {'seasonOffset': 7, 'age': 0.5, 'gatherProgress': 9,
     'hasFloweredThisSeason': 1, 'flowering': 1, 'frozen': 0,
     'maxAgeGene': 32768, 'growthRateGene': 300, 'saveTime': 0.0, 'worldTime': 0.0},
    {'seasonOffset': 3, 'age': 2.0, 'gatherProgress': 4,
     'hasFloweredThisSeason': 1, 'flowering': 0, 'frozen': 1,
     'maxAgeGene': -1, 'growthRateGene': -2, 'saveTime': 0.0, 'worldTime': 0.0},
    {'seasonOffset': 11, 'age': 3.75, 'gatherProgress': 12,
     'hasFloweredThisSeason': 1, 'flowering': 1, 'frozen': 1,
     'maxAgeGene': 254, 'growthRateGene': 2, 'saveTime': 1000.0,
     'worldTime': 2800.5},
    {'seasonOffset': 12, 'age': 4.0, 'gatherProgress': 13,
     'hasFloweredThisSeason': 1, 'flowering': 1, 'frozen': 1,
     'maxAgeGene': 60, 'growthRateGene': 60, 'saveTime': 1000.0,
     'worldTime': 2800.0},
    {'seasonOffset': 13, 'age': 5.0, 'gatherProgress': 14,
     'hasFloweredThisSeason': 1, 'flowering': 0, 'frozen': 1,
     'maxAgeGene': 60, 'growthRateGene': 60, 'saveTime': 1000.0,
     'worldTime': 2799.9999},
    {'seasonOffset': 0, 'age': 0.0, 'gatherProgress': 0,
     'hasFloweredThisSeason': 0, 'flowering': 0, 'frozen': 0,
     'maxAgeGene': 1000, 'growthRateGene': 1000, 'saveTime': 500.0,
     'worldTime': 2300.5},
]
KEYS = ['seasonOffset', 'age', 'gatherProgress', 'frozen', 'flowering',
        'hasFloweredThisSeason', 'maxAgeGene', 'growthRateGene', 'saveTime']


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

    graph, stack, stop, stub = (0x60000000, 0x70000000, 0x71000000, 0x72000000)
    uc.mem_map(graph, 0x10000)
    uc.mem_map(stack, 0x10000)
    uc.mem_map(stop, 0x1000)
    uc.mem_map(stub, 0x1000)
    uc.mem_map(0x73000000, 0x1000)   # selector strings

    def word(at, value):
        uc.mem_write(at, struct.pack('<I', value & 0xffffffff))

    word(GOT_MSGSEND, stub)

    self_ptr = graph
    world = graph + 0x2000
    save_dict = graph + 0x3000
    boxes = {key: graph + 0x4000 + i * 0x100 for i, key in enumerate(KEYS)}
    sel_base = 0x73000000
    sel_addrs = {}
    for i, name in enumerate(KEYS + ['objectForKey:', 'intValue', 'floatValue',
                                     'boolValue', 'doubleValue', 'worldTime']):
        addr = sel_base + i * 0x40
        sel_addrs[name] = addr
        uc.mem_write(addr, name.encode() + b'\0')
    key_strings = {name: sel_addrs[name] for name in KEYS}

    word(self_ptr + WORLD_IVAR, world)
    case = {}

    def hook(uc_, address, size, data):
        recv = uc_.reg_read(UC_ARM_REG_R0)
        sel_ptr = uc_.reg_read(UC_ARM_REG_R1)
        sel = bytes(uc_.mem_read(sel_ptr, 64)).split(b'\0')[0].decode()
        arg = uc_.reg_read(UC_ARM_REG_R2)
        if sel == 'objectForKey:':
            assert recv == save_dict, ('objectForKey receiver', hex(recv))
            # The caller passes a CFString object, not a bare C string: read the
            # data pointer at +8 when the direct read does not yield a key.
            key = bytes(uc_.mem_read(arg, 32)).split(b'\0')[0].decode('latin-1')
            if key not in boxes:
                data_ptr = int.from_bytes(bytes(uc_.mem_read(arg + 8, 4)), 'little')
                key = bytes(uc_.mem_read(data_ptr, 32)).split(b'\0')[0].decode()
            assert key in boxes, (hex(arg), repr(key))
            uc_.reg_write(UC_ARM_REG_R0, boxes[key])
        elif sel in ('intValue', 'floatValue', 'boolValue', 'doubleValue'):
            key = next((k for k, v in boxes.items() if v == recv), None)
            assert key is not None, ('box receiver', hex(recv))
            value = case[key]
            if sel == 'intValue':
                uc_.reg_write(UC_ARM_REG_R0, value & 0xffffffff)
            elif sel == 'boolValue':
                uc_.reg_write(UC_ARM_REG_R0, 1 if value else 0)
            elif sel == 'floatValue':
                uc_.reg_write(UC_ARM_REG_R0,
                              struct.unpack('<I', struct.pack('<f', value))[0])
            else:  # doubleValue → softfp pair in r0:r1
                lo, hi = struct.unpack('<II', struct.pack('<d', value))
                uc_.reg_write(UC_ARM_REG_R0, lo)
                uc_.reg_write(UC_ARM_REG_R1, hi)
        elif sel == 'worldTime':
            assert recv == world, ('worldTime receiver', hex(recv))
            lo, hi = struct.unpack('<II', struct.pack('<d', case['worldTime']))
            uc_.reg_write(UC_ARM_REG_R0, lo)
            uc_.reg_write(UC_ARM_REG_R1, hi)
        else:
            raise AssertionError(('unimplemented message', hex(recv), sel))
        uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

    uc.hook_add(UC_HOOK_CODE, hook, begin=stub, end=stub + 4)

    repo = Path(__file__).resolve().parents[1]
    fns = []
    for opt in (0, 2):
        lib = a.output_dir / f'plant_load-O{opt}.so'
        import subprocess
        subprocess.run(['clang++', '-std=c++17', f'-O{opt}', '-UNDEBUG',
                        '-fno-fast-math', '-ffp-contract=off', '-fPIC', '-shared',
                        '-I' + str(repo / 'reconstruction/recovered'),
                        str(repo / 'tools/plant_load_save_dict_arm_bridge.cpp'),
                        str(repo / 'reconstruction/recovered/plant_load_save_dict.cpp'),
                        '-o', str(lib)], check=True)
        cdll = ctypes.CDLL(str(lib))
        cdll.recovered_plant_load_fields.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        fns.append(cdll.recovered_plant_load_fields)

    class In(ctypes.Structure):
        _fields_ = [('season_offset', ctypes.c_int32), ('age', ctypes.c_float),
                    ('gather_progress', ctypes.c_int32),
                    ('has_flowered', ctypes.c_int32),
                    ('flowering', ctypes.c_int32), ('frozen', ctypes.c_int32),
                    ('max_age_gene', ctypes.c_int32),
                    ('growth_rate_gene', ctypes.c_int32),
                    ('save_time', ctypes.c_double), ('world_time', ctypes.c_double)]

    class Out(ctypes.Structure):
        _fields_ = [('season_offset', ctypes.c_int32), ('age', ctypes.c_float),
                    ('gather_progress', ctypes.c_int32),
                    ('has_flowered', ctypes.c_uint8),
                    ('flowering', ctypes.c_uint8), ('frozen', ctypes.c_uint8),
                    ('max_age_gene', ctypes.c_uint16),
                    ('growth_rate_gene', ctypes.c_uint16)]

    def read_field(name):
        addr, kind = OFFSETS[name]
        if kind == 'word':
            return struct.unpack('<i', bytes(uc.mem_read(self_ptr + addr, 4)))[0]
        if kind == 'float':
            return struct.unpack('<f', bytes(uc.mem_read(self_ptr + addr, 4)))[0]
        if kind == 'halfword':
            return struct.unpack('<H', bytes(uc.mem_read(self_ptr + addr, 2)))[0]
        return struct.unpack('<B', bytes(uc.mem_read(self_ptr + addr, 1)))[0]

    rows = []
    for case_values in CASES:
        case.clear()
        case.update(case_values)
        uc.mem_write(self_ptr, b'\x00' * PLANT_INSTANCE_SIZE)
        word(self_ptr + WORLD_IVAR, world)
        sp = stack + 0x8000
        uc.reg_write(UC_ARM_REG_R0, self_ptr)
        uc.reg_write(UC_ARM_REG_R1, sel_addrs['objectForKey:'])
        uc.reg_write(UC_ARM_REG_R2, save_dict)
        uc.reg_write(UC_ARM_REG_SP, sp)
        uc.reg_write(UC_ARM_REG_LR, stop)
        uc.emu_start(IMP, stop, count=200000)
        assert uc.reg_read(UC_ARM_REG_PC) == stop, 'method did not return'
        arm = {name: read_field(name) for name in OFFSETS}
        arm['age'] = struct.unpack('<f', struct.pack('<f', arm['age']))[0]
        inp = In(season_offset=case['seasonOffset'], age=case['age'],
                 gather_progress=case['gatherProgress'],
                 has_flowered=case['hasFloweredThisSeason'],
                 flowering=case['flowering'], frozen=case['frozen'],
                 max_age_gene=case['maxAgeGene'],
                 growth_rate_gene=case['growthRateGene'],
                 save_time=case['saveTime'], world_time=case['worldTime'])
        cpp_results = []
        for fn in fns:
            out = Out()
            fn(ctypes.byref(inp), ctypes.byref(out))
            cpp_results.append({'seasonOffset': out.season_offset, 'age': out.age,
                                'gatherProgress': out.gather_progress,
                                'frozen': out.frozen, 'flowering': out.flowering,
                                'hasFloweredThisSeason': out.has_flowered,
                                'maxAgeGene': out.max_age_gene,
                                'growthRateGene': out.growth_rate_gene})
        for cpp in cpp_results:
            for name in OFFSETS:
                assert abs(arm[name] - cpp[name]) == 0, (case, name, arm[name],
                                                         cpp[name])
        # explicit expectations independent of the C++ pair
        expected_flag = 0 if (case['worldTime'] - case['saveTime'] > 1800.0) \
            else case['hasFloweredThisSeason']
        assert arm['hasFloweredThisSeason'] == expected_flag, (case, arm)
        expected_max = min(max(case['maxAgeGene'] & 0xFFFF, 1), 255)
        expected_growth = min(max(case['growthRateGene'] & 0xFFFF, 1), 255)
        assert arm['maxAgeGene'] == expected_max, (case, arm)
        assert arm['growthRateGene'] == expected_growth, (case, arm)
        rows.append({'inputs': case_values, 'arm': arm, 'cpp': cpp_results[0]})

    report = {
        'sha256': SHA, 'class': 'Plant', 'method': 'loadSaveDictValues:',
        'entry': f'0x{IMP:08x}', 'cases': len(rows), 'match': True,
        'boundary': ('Unicorn execution of the original 332-word method with a '
                     'synthetic save dictionary (objectForKey: + int/float/bool/'
                     'doubleValue + worldTime stubs). The destructive stores at '
                     'their decoded widths, the real 0x004c0b70 clamp helper and '
                     'the saveTime 1800s gate execute for real. Not Foundation, '
                     'not the original-app runtime, not device gameplay; the '
                     'world object and the dictionary are stubs.'),
        'rows': rows,
    }
    (a.output_dir / 'plant-loadsave-arm-result.json').write_text(
        json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('sha256', 'cases', 'match',
                                             'boundary')}, indent=2))


if __name__ == '__main__':
    main()
