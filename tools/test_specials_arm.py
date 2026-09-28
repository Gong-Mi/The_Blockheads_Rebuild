#!/usr/bin/env python3
"""Execute the ORIGINAL ARM bodies of the "special" loaders under Unicorn.

Batch coverage (incremental, class by class): the five bespoke bodies whose
shapes are not flat key tables —
  SteamTrain 42 (0x00d18834), OwnershipSign 60 (0x00a34b18),
  Painting 52 (0x00aa81e8), DropBear 25 (0x0079d538), CaveTroll 39 (0x00d538cc).

Phase 1 (this file's --dump mode): a LENIENT recorder — the stubs accept every
selector the body throws at them, recording (selector, receiver kind, args)
and returning benign values (tokens for objectForKey:, 1/0x12345/0x1FFF1/1.5
for the conversions). The dump is the ground truth for modelling the
per-class expectation, which then gets pinned (phase 2) in
tools/specials_arm_bridge.cpp the way the mid-tier differential does.

Synthetic model (stated limits — not Foundation, not the original-app
runtime): objc_msgSendSuper2 is stubbed (asserts {self, own-class}, the loader
selector and the four arguments); the instance is a zeroed 512-byte window.
"""
import argparse
import ctypes
import hashlib
import json
import struct
import subprocess
import sys
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
IMAGE_SIZE = 512
TOKEN_BASE = 0x5E1B0000
INT_VALUE = 0x00012345
UINT_VALUE = 0x0001FFF1
BOOL_VALUE = 1
FLOAT_BITS = struct.unpack('<I', struct.pack('<f', 1.5))[0]

ENTRIES = [
    ('SteamTrain', 42, 0x00D18834, 0x00E8BF10, 180),
    ('OwnershipSign', 60, 0x00A34B18, 0x00E8BE20, 352),
    ('Painting', 52, 0x00AA81E8, 0x00E8BE64, 358),
    ('DropBear', 25, 0x0079D538, 0x00E8BD3C, 404),
    ('CaveTroll', 39, 0x00D538CC, 0x00E8BF2C, 408),
]
CONV = {'intValue': ('int', INT_VALUE), 'boolValue': ('bool', BOOL_VALUE),
        'unsignedIntValue': ('uint', UINT_VALUE), 'floatValue': ('float', FLOAT_BITS)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    ap.add_argument('--output-dir', type=Path, required=True)
    ap.add_argument('--dump', action='store_true',
                    help='lenient run: print every recorded call per class')
    ap.add_argument('--class', dest='only', default=None,
                    help='restrict to one class name')
    ap.add_argument('--dump-images', metavar='CLASS',
                    help='print labels + nonzero bytes for one class across cases')
    ap.add_argument('--is-server', dest='is_server', action='store_true',
                    help='answer [world/dyn isServer] with 1 in dump mode')
    ap.add_argument('--trace', action='store_true',
                    help='record the last PCs and print them on a crash')
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
    from collections import deque
    pc_ring = deque(maxlen=256)
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
    for base in (graph, stack):
        uc.mem_map(base, 0x10000)
    for base in (stop, stub_super, stub_send):
        uc.mem_map(base, 0x1000)
    sel_region = 0x73000000
    uc.mem_map(sel_region, 0x1000)
    uc.mem_write(sel_region, SUPER_SELECTOR.encode() + b'\0')

    def word(at, value):
        uc.mem_write(at, struct.pack('<I', value & 0xffffffff))

    def read_word(at):
        return int.from_bytes(bytes(uc.mem_read(at, 4)), 'little')

    word(GOT_SUPER2, stub_super)
    word(GOT_MSGSEND, stub_send)
    # The binary has a SECOND set of msgSend pointers: the PLT's own GOT slots
    # (rel.plt, e.g. objc_msgSend at 0x105FB18). Bodies that call the PLT
    # stub (CaveTroll does) would otherwise run the unresolved lazy resolver
    # into address 0. Patch EVERY slot whose import is one of our stubs.
    from elftools.elf.relocation import RelocationSection
    with a.elf.open('rb') as f2:
        elf2 = ELFFile(f2)
        plt_slots = 0
        for sec in elf2.iter_sections():
            if sec['sh_type'] not in ('SHT_REL', 'SHT_RELA'):
                continue
            symtab2 = elf2.get_section(sec['sh_link'])
            for rel in sec.iter_relocations():
                sym = symtab2.get_symbol(rel['r_info_sym'])
                if sym.name == 'objc_msgSend':
                    word(rel['r_offset'], stub_send)
                    plt_slots += 1
                elif sym.name in ('objc_msgSendSuper2',):
                    word(rel['r_offset'], stub_super)
                    plt_slots += 1
    if a.trace:
        print(f'  patched {plt_slots} PLT msgSend slot(s)')

    self_ptr = graph + 0x1000
    world, dyn, save_dict, cache = (graph + 0x100, graph + 0x200,
                                    graph + 0x300, graph + 0x400)
    tokens = {}
    ctx = {'class': None, 'super_result': self_ptr, 'expect_class': 0,
           'calls': [], 'pending_key': None, 'pending_token': 0,
           'data_token': 0, 'data_bytes': b'\xAA\xBB\xCC\xDD',
           'is_server': 0, 'banned': 0, 'resolve_token': 0,
           'world_time': 1000.0, 'max_age': 100000.0}

    def cstring(ptr):
        return bytes(uc.mem_read(ptr, 128)).split(b'\0')[0].decode()

    def token_for(name):
        if name not in tokens:
            tokens[name] = TOKEN_BASE + len(tokens) * 0x10
        return tokens[name]

    def hook(uc_, address, size, data):
        if address == stub_super:
            struct_ptr = uc_.reg_read(UC_ARM_REG_R0)
            recv = read_word(struct_ptr)
            cls = read_word(struct_ptr + 4)
            sel = cstring(uc_.reg_read(UC_ARM_REG_R1))
            sp = uc_.reg_read(UC_ARM_REG_SP)
            assert recv == self_ptr, ('super receiver', hex(recv))
            assert cls == ctx['expect_class'], ('super class', hex(cls))
            assert sel == SUPER_SELECTOR, sel
            ctx['calls'].append('super')
            uc_.reg_write(UC_ARM_REG_R0, ctx['super_result'])
        elif address == stub_send:
            recv = uc_.reg_read(UC_ARM_REG_R0)
            sel = cstring(uc_.reg_read(UC_ARM_REG_R1))
            if ctx.get('case') is not None and sel in ctx.get('extras', ()):
                ctx['calls'].append(sel)
                uc_.reg_write(UC_ARM_REG_R0, 0)
                uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))
                return
            if sel == 'objectForKey:':
                name = cstring(read_word(uc_.reg_read(UC_ARM_REG_R2) + 8))
                if recv == save_dict:
                    tok = token_for(name)
                    if ctx.get('case') is not None:
                        # modelled run: absent keys read as nil
                        case_id = ctx['case']
                        idx = ctx.get('idx_by_name', {}).get(name)
                        present = present_of(case_id, idx) if idx is not None else True
                        if not present:
                            tok = 0
                    ctx['pending_key'] = name
                    ctx['pending_token'] = tok
                    ctx['calls'].append(f'ofk:{name}')
                    uc_.reg_write(UC_ARM_REG_R0, tok)
                else:
                    ctx['calls'].append(f'ofk:{name}(recv={hex(recv)})')
                    uc_.reg_write(UC_ARM_REG_R0, 0)
            elif sel in CONV:
                key = ctx['pending_key']
                tag, value = CONV[sel]
                ctx['calls'].append(f'{tag}:{key}')
                if recv == 0:
                    value = 0
                if sel == 'floatValue':
                    uc_.reg_write(UC_ARM_REG_S0, value)
                uc_.reg_write(UC_ARM_REG_R0, value)
            elif sel in ('retain', 'autorelease'):
                if ctx.get('case') is not None:
                    ctx['calls'].append(sel)      # model mode: bare label
                else:
                    kind = ('self' if recv == self_ptr else
                            ('nil' if recv == 0 else hex(recv)))
                    ctx['calls'].append(f'{sel}({kind})')
                uc_.reg_write(UC_ARM_REG_R0, recv)
            elif sel in ('length', 'bytes'):
                ctx['calls'].append(sel)
                if sel == 'length':
                    uc_.reg_write(UC_ARM_REG_R0, len(ctx['data_bytes']))
                else:
                    uc_.reg_write(UC_ARM_REG_R0, graph + 0x3000)
            elif sel in ('worldWidthMacro', 'worldHeightMacro'):
                # the coordinate-wrap helper loops on worldWidthMacro*32;
                # returning 0 would spin forever. 4 macro-tiles = 128 tiles.
                ctx['calls'].append(sel)
                uc_.reg_write(UC_ARM_REG_R0, 4)
            elif sel == 'isServer':
                ctx['calls'].append('isServer' if recv != save_dict else 'isServer(saveDict?)')
                uc_.reg_write(UC_ARM_REG_R0, ctx['is_server'])
            elif sel.startswith('getOwnerNameForObjectOwnerID'):
                ctx['calls'].append('resolveOwnerName')
                # a FIXED token so the bridge can predict the stored value
                ctx['resolve_token'] = TOKEN_BASE + 0x100
                uc_.reg_write(UC_ARM_REG_R0, ctx['resolve_token'])
            elif sel.startswith('playerIsBannedWithID') or sel.startswith('playerIsBanned'):
                ctx['calls'].append('playerIsBanned')
                uc_.reg_write(UC_ARM_REG_R0, ctx['banned'])
            elif sel == 'maxAge':
                ctx['calls'].append(sel)
                bits = struct.unpack('<I', struct.pack('<f', ctx['max_age']))[0]
                uc_.reg_write(UC_ARM_REG_R0, bits)
            elif sel == 'worldTime':
                ctx['calls'].append(sel)
                # the body reads it as a DOUBLE via vmov d1, r0, r1
                dbits = struct.unpack('<Q', struct.pack('<d', ctx['world_time']))[0]
                uc_.reg_write(UC_ARM_REG_R0, dbits & 0xffffffff)
                uc_.reg_write(UC_ARM_REG_R1, (dbits >> 32) & 0xffffffff)
                uc_.reg_write(UC_ARM_REG_S0,
                              struct.unpack('<I', struct.pack('<f', ctx['world_time']))[0])
            else:
                ctx['calls'].append(f'{sel}(recv={hex(recv)})')
                uc_.reg_write(UC_ARM_REG_R0, 0)
        else:
            raise AssertionError(('unexpected stub entry', hex(address)))
        uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

    for addr in (stub_super, stub_send):
        uc.hook_add(UC_HOOK_CODE, hook, begin=addr, end=addr + 4)

    # The in-ELF PLT veneer for memcpy (0x1C2894 -> GOT slot 0x105FB40,
    # rel.plt idx 16): CaveTroll's state blob copy calls it.
    VENEER_MEMCPY = 0x1C2894

    def veneer_hook(uc_, address, size, data):
        assert address == VENEER_MEMCPY, hex(address)
        dest = uc_.reg_read(UC_ARM_REG_R0)
        src = uc_.reg_read(UC_ARM_REG_R1)
        count = uc_.reg_read(UC_ARM_REG_R2)
        if count:
            uc_.mem_write(dest, bytes(uc_.mem_read(src, count)))
        ctx['calls'].append('memcpy')
        uc_.reg_write(UC_ARM_REG_R0, dest)
        uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

    uc.hook_add(UC_HOOK_CODE, veneer_hook, begin=VENEER_MEMCPY,
                end=VENEER_MEMCPY + 4)

    # the state-blob bytes live at graph+0x3000
    uc.mem_write(graph + 0x3000, ctx['data_bytes'])

    def present_of(case_id, idx):
        if case_id == 0:
            return True
        if case_id == 1:
            return idx % 2 == 0
        if case_id == 3:
            return idx % 2 == 1
        return False

    def arm_run(entry, case_id=None):
        cls, type_id, imp, superref, words = entry
        ctx['class'] = cls
        ctx['case'] = case_id
        ctx['super_result'] = 0 if case_id == 2 else self_ptr
        ctx['expect_class'] = read_word(superref)
        ctx['calls'] = []
        ctx['pending_key'] = None
        tokens.clear()
        if a.trace:
            pc_ring.clear()
            uc.hook_add(UC_HOOK_CODE, lambda uc_, addr, size, data: pc_ring.append(addr))
        uc.mem_write(self_ptr, b'\x00' * IMAGE_SIZE)
        word(self_ptr + 4, world)    # the real super init stores world@4
        word(self_ptr + 8, dyn)      # ... and dynamicWorld@8
        sp = stack + 0x8000
        for reg, value in ((UC_ARM_REG_R0, self_ptr), (UC_ARM_REG_R1, sel_region),
                           (UC_ARM_REG_R2, world), (UC_ARM_REG_R3, dyn)):
            uc.reg_write(reg, value)
        uc.reg_write(UC_ARM_REG_SP, sp)
        uc.reg_write(UC_ARM_REG_LR, stop)
        word(sp, save_dict)
        word(sp + 4, cache)
        try:
            uc.emu_start(imp, stop, count=40000)
        except Exception as e:
            if a.trace:
                print(f'  CRASH in {cls}: {e}')
                print(f'  last PCs: {[hex(p) for p in pc_ring]}')
                print(f'  calls: {ctx["calls"]}')
                print(f'  registers: r0={uc.reg_read(UC_ARM_REG_R0):#x} '
                      f'r1={uc.reg_read(UC_ARM_REG_R1):#x} '
                      f'r2={uc.reg_read(UC_ARM_REG_R2):#x} '
                      f'lr={uc.reg_read(UC_ARM_REG_LR):#x}')
            raise
        if uc.reg_read(UC_ARM_REG_PC) != stop:
            if a.trace:
                print(f'  NO-RETURN in {cls}: pc={uc.reg_read(UC_ARM_REG_PC):#x}')
                print(f'  last PCs: {[hex(p) for p in list(pc_ring)[-40:]]}')
                print(f'  calls: {ctx["calls"]}')
            raise AssertionError(f'{cls}: no return')
        ret = uc.reg_read(UC_ARM_REG_R0)
        image = bytearray(uc.mem_read(self_ptr, IMAGE_SIZE))
        image[4:12] = b'\x00' * 8   # the stubbed super's base slots
        return ret, list(ctx['calls']), bytes(image)

    ctx['is_server'] = 1 if a.is_server else 0

    if a.dump:
        rows = []
        for entry in ENTRIES:
            if a.only and entry[0] != a.only:
                continue
            ret, calls, image = arm_run(entry)
            print(f'--- {entry[0]} ret=0x{ret:08x}')
            for c in calls:
                print(f'    {c}')
            nz = [(i, image[i]) for i in range(IMAGE_SIZE) if image[i]]
            print('    image nonzero bytes:', nz[:40])
            rows.append({'class': entry[0], 'ret': f'0x{ret:08x}', 'calls': calls,
                         'nonzero': nz[:40]})
        (a.output_dir / 'specials-dump.json').write_text(
            json.dumps(rows, indent=2) + '\n')
        return

    if a.dump_images:
        for entry in ENTRIES:
            if entry[0] != a.dump_images:
                continue
            repo = Path(__file__).resolve().parents[1]
            lib = a.output_dir / 'specials-O0.so'
            subprocess.run(['clang++', '-std=c++17', '-O0', '-UNDEBUG',
                            '-fno-fast-math', '-ffp-contract=off', '-fPIC',
                            '-shared', str(repo / 'tools/specials_arm_bridge.cpp'),
                            '-o', str(lib)], check=True)
            cdll = ctypes.CDLL(str(lib))
            keys_fn = cdll.recovered_specials_key_list
            keys_fn.argtypes = [ctypes.c_int32]
            keys_fn.restype = ctypes.c_char_p
            key_list = keys_fn(entry[1]).decode().split(',')
            for case_id in (0, 1, 2, 3):
                ctx['idx_by_name'] = {name: i for i, name in enumerate(key_list)}
                ret, calls, image = arm_run(entry, case_id)
                nz = [(i, image[i]) for i in range(IMAGE_SIZE) if image[i]]
                print(f'--- {entry[0]} case {case_id} ret=0x{ret:08x}')
                print('    calls:', ','.join(calls))
                print('    nonzero:', nz)
        return

    # ---- phase 2: compare the modelled classes against the bridge ----------
    repo = Path(__file__).resolve().parents[1]
    bridges = {}
    for opt in (0, 2):
        lib = a.output_dir / f'specials-O{opt}.so'
        subprocess.run(['clang++', '-std=c++17', f'-O{opt}', '-UNDEBUG',
                        '-fno-fast-math', '-ffp-contract=off', '-fPIC', '-shared',
                        str(repo / 'tools/specials_arm_bridge.cpp'),
                        '-o', str(lib)], check=True)
        cdll = ctypes.CDLL(str(lib))
        keys_fn = cdll.recovered_specials_key_list
        keys_fn.argtypes = [ctypes.c_int32]
        keys_fn.restype = ctypes.c_char_p
        seq_fn = cdll.recovered_specials_sequence
        seq_fn.argtypes = [ctypes.c_int32, ctypes.c_int32]
        seq_fn.restype = ctypes.c_char_p
        img_fn = cdll.recovered_specials_image
        img_fn.argtypes = [ctypes.c_int32, ctypes.c_int32, ctypes.c_uint32,
                           ctypes.c_char_p, ctypes.c_int]
        img_fn.restype = ctypes.c_int
        extra_fn = cdll.recovered_specials_extra
        extra_fn.argtypes = [ctypes.c_int32]
        extra_fn.restype = ctypes.c_char_p
        bridges[opt] = (keys_fn, seq_fn, img_fn, extra_fn)

    MODELLED = {'SteamTrain', 'OwnershipSign', 'Painting', 'DropBear',
                'CaveTroll'}
    ctx['is_server'] = 1   # phase 2 always runs the server-gated paths
    rows = []
    for entry in ENTRIES:
        cls, type_id, imp, superref, words = entry
        if cls not in MODELLED:
            continue
        keys_fn, seq_fn, img_fn, extra_fn = bridges[0]
        key_list = keys_fn(type_id).decode().split(',')
        ctx['extras'] = set(x for x in extra_fn(type_id).decode().split(',') if x)
        for case_id in (0, 1, 2, 3, 4):
            ctx['idx_by_name'] = {name: i for i, name in enumerate(key_list)}
            death = (cls == 'DropBear' and case_id == 4)
            ctx['max_age'] = 0.0 if death else 100000.0
            ctx['world_time'] = 1000.0
            ctx['death_case'] = death
            ret, calls, image = arm_run(entry, case_id)
            expected_ret = 0 if (case_id == 2 or (death and cls == 'DropBear')) else self_ptr
            assert ret == expected_ret, (cls, case_id, hex(ret))
            for opt in (0, 2):
                keys_fn, seq_fn, img_fn, extra_fn = bridges[opt]
                expected_seq = seq_fn(type_id, case_id).decode()
                assert ','.join(calls) == expected_seq, \
                    (cls, case_id, opt, ','.join(calls), expected_seq)
                buf = ctypes.create_string_buffer(IMAGE_SIZE)
                assert img_fn(type_id, case_id, TOKEN_BASE, buf,
                              IMAGE_SIZE) == IMAGE_SIZE
                if buf.raw != image:
                    diff = [i for i in range(IMAGE_SIZE)
                            if buf.raw[i] != image[i]]
                    for off in diff:
                        print(f'  {cls} case {case_id} image diff at +{off}: '
                              f'arm={image[off]:02x} cpp={buf.raw[off]:02x}')
                assert buf.raw == image, (cls, case_id, opt, 'image mismatch')
            rows.append({'class': cls, 'type_id': type_id, 'case': case_id,
                         'arm_return': f'0x{ret:08x}', 'calls': calls,
                         'image_sha256': hashlib.sha256(image).hexdigest()[:32]})

    report = {'sha256': SHA, 'batch': 'specials',
              'classes': sorted(MODELLED), 'cases': len(rows), 'match': True,
              'rows': rows,
              'boundary': ('Unicorn execution of the original special-loader '
                           'bodies with a synthetic ObjC graph against the '
                           'pinned model in tools/specials_arm_bridge.cpp at '
                           '-O0/-O2 (call sequence, 512-byte image, return '
                           'register). Not Foundation, not the original-app '
                           'runtime, not device gameplay.')}
    (a.output_dir / 'specials-arm-result.json').write_text(
        json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('sha256', 'batch', 'classes',
                                             'cases', 'match')}, indent=2))


if __name__ == '__main__':
    main()
