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
import re
import struct
import subprocess
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import (Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE,
                     UC_HOOK_MEM_WRITE)
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
    ('ArtificialLight', 21, 0x00A93C64, 0x00E8BE48, 412),
    ('TrainCar', 43, 0x00A3892C, 0x00E8BE24, 363),
    # mid-tier key-table classes (imps/superrefs from the batch jsons; used by
    # --dump / --emit-spec; the pinned MODEL for them lives in the midtier
    # harness/bridge)
    ('Window', 31, 0x00C98944, 0x00E8BED4, 139),
    ('Rail', 40, 0x0077AB90, 0x00E8BD24, 180),
    ('Boat', 32, 0x0096B818, 0x00E8BDD4, 214),
    ('Ladder', 19, 0x00AADCD4, 0x00E8BE68, 139),
    ('Egg', 30, 0x00D4E30C, 0x00E8BF24, 236),
    ('Column', 53, 0x00834A30, 0x00E8BD80, 197),
    ('Stairs', 54, 0x006CC734, 0x00E8BCC0, 205),
    ('Door', 20, 0x007694FC, 0x00E8BD1C, 210),
    ('Wire', 38, 0x0095002C, 0x00E8BDC0, 220),
    ('ElevatorShaft', 56, 0x00CAD2CC, 0x00E8BEE8, 214),
    ('ElevatorMotor', 55, 0x0070046C, 0x00E8BCE8, 218),
    # the tree growth state machine (hooks6 batch; no super call, world-heavy)
    ('Tree', 1, 0x004C2568, 0x00E8BC30, 546),
    # the input front: UIManager's touch routing (the router's full block
    # chain, run_ui_router in ui_touch_router.h; the UI_CASES fixture drives
    # it — dump mode still records it leniently)
    ('UIManager', 72, 0x00AD7748, 0x00000000, 576),
    # the first subclass overrides: CraftUI's five touch methods (the panel
    # shape — the own-rect test + the children-delegation orders)
    ('CraftUIRect', 73, 0x00B80EB4, 0x00000000, 95),
    ('CraftUIInUI', 74, 0x00B81030, 0x00000000, 134),
    ('CraftUIPress', 75, 0x00B81248, 0x00000000, 137),
    ('CraftUIMove', 76, 0x00B8146C, 0x00000000, 103),
    ('CraftUIEnd', 77, 0x00B81608, 0x00000000, 103),
    # the DPad panel: the pure forward + the rotated hit test (the 232w body
    # with its 0x0070591C rotation helper inside the span)
    ('DPadInUI', 78, 0x0070561C, 0x00000000, 24),
    ('DPadRect', 79, 0x0070567C, 0x00000000, 232),
    # the UI front: MJControl's press lifecycle + MJView's touch contract
    ('MJControl', 70, 0x009F6894, 0x00E8BE18, 240),
    ('MJView', 71, 0x006614A8, 0x00E8BC90, 176),
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
    ap.add_argument('--fake-tile', choices=('gene', 'zero'), default=None,
                    help='answer loadPhysicalBlockForMacroTile: with a '
                         'synthetic tile whose slots carry the gene pattern '
                         '(--fake-tile gene) or zeros (--fake-tile zero)')
    ap.add_argument('--r2r3-floats', default=None,
                    help='pass two float32 VALUES in r2:r3 (CGPoint args), '
                         'e.g. "50.0,50.0"')
    ap.add_argument('--r2r3-double', default=None,
                    help='pass the float64 VALUE in r2:r3 (for methods whose '
                         'first argument is a double, e.g. saveTime)')
    ap.add_argument('--static-tree', dest='static_tree', action='store_true',
                    help='answer [self isStaticTree] with 1 (the static branch)')
    ap.add_argument('--seed', default=None,
                    help='comma list off=word (hex) written into the instance '
                         'before the run, e.g. 96=0x32,92=0x64 (tree growth)')
    ap.add_argument('--emit-spec', metavar='CLASS',
                    help='run the class (lenient) and emit its key table JSON '
                         'from the memory-write hook + call trace')
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
    # a synthetic tile world for the tree's gene read (--fake-tile): the tile
    # struct's +8 word points at the contents base; each 64-byte slot carries
    # the gene pattern (or zeros for the control run)
    FTI = 0x60020000
    uc.mem_map(FTI, 0x10000)
    uc.mem_write(FTI + 8, struct.pack('<I', FTI + 0x1000))
    # a synthetic macroTiles array (--fake-tile): entries point at one fake
    # element (byte@+1 = 0, word@+4 = 0) -> the lookup reaches the loader
    FTA, FTE = 0x60030000, 0x60030400
    uc.mem_map(FTA, 0x10000)
    for i in range(16):
        uc.mem_write(FTA + i * 4, struct.pack('<I', FTE))
    uc.mem_write(FTE + 4, struct.pack('<I', 0))
    uc.mem_write(sel_region, SUPER_SELECTOR.encode() + b'\0')

    def word(at, value):
        uc.mem_write(at, struct.pack('<I', value & 0xffffffff))


    def read_word(at):
        return int.from_bytes(bytes(uc.mem_read(at, 4)), 'little')
    if a.fake_tile:
        slot = bytearray(64)
        if a.fake_tile == 'gene':
            slot[7] = 0x08
            slot[0xe:0x10] = (0x0200).to_bytes(2, 'little')
            slot[0x10:0x12] = (0x0100).to_bytes(2, 'little')
            slot[0x12:0x14] = (0x0040).to_bytes(2, 'little')
        for i in range(0x4000 // 64):
            uc.mem_write(FTI + 0x1000 + i * 64, bytes(slot))

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
        out = bytearray()
        for i in range(128):
            try:
                byte = bytes(uc.mem_read(ptr + i, 1))
            except Exception:
                break
            if byte == b'\0':
                break
            out += byte
        return out.decode('latin1')

    tokens_by_addr = {}

    def token_for(name):
        if name not in tokens:
            tokens[name] = TOKEN_BASE + len(tokens) * 0x10
            tokens_by_addr[tokens[name]] = name
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
            if sel == SUPER_SELECTOR:
                ctx['calls'].append('super')
                uc_.reg_write(UC_ARM_REG_R0, ctx['super_result'])
            else:
                # a real super call ([super startTouch:point]): answer with
                # the base default (0) and record it by name — the model side
                # emits the same label.
                ctx['calls'].append(f'super({sel})')
                uc_.reg_write(UC_ARM_REG_R0, 0)
        elif address == stub_send:
            recv = uc_.reg_read(UC_ARM_REG_R0)
            sel = cstring(uc_.reg_read(UC_ARM_REG_R1))
            if ctx.get('case') is not None and sel in ctx.get('extras', ()):
                ctx['calls'].append(sel)
                uc_.reg_write(UC_ARM_REG_R0, 0)
                uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))
                return
            fixture = ctx.get('ui_fixture') or {}
            pinned = (fixture.get('ret1') or {}).get(recv)
            if pinned is not None and sel in pinned:
                # the UI fixture's per-receiver answer (a pinned 1)
                ctx['calls'].append(f'{sel}(recv={hex(recv)})')
                uc_.reg_write(UC_ARM_REG_R0, 1)
                uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))
                return
            if (sel == 'countByEnumeratingWithState:objects:count:'
                    and fixture.get('enum_recv')
                    and recv == fixture['enum_recv']):
                # the uiViews fixture: the FIRST call answers the batch (the
                # state's itemsPtr@+4 / mutationsPtr@+8 are filled), every
                # later call answers 0 (the exhausted enumeration)
                items = fixture.get('views') or []
                state = uc_.reg_read(UC_ARM_REG_R2)
                ctx['ui_enum_calls'] = ctx.get('ui_enum_calls', 0) + 1
                if ctx['ui_enum_calls'] == 1 and items:
                    for k, ptr in enumerate(items):
                        word(UI_ITEMS + k * 4, ptr)
                    word(state + 4, UI_ITEMS)
                    word(state + 8, UI_MUT)
                    uc_.reg_write(UC_ARM_REG_R0, len(items))
                else:
                    uc_.reg_write(UC_ARM_REG_R0, 0)
                ctx['calls'].append(f'{sel}(recv={hex(recv)})')
                uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))
                return
            if sel == 'objectForKey:':
                key_ptr = uc_.reg_read(UC_ARM_REG_R2)
                if key_ptr in tokens_by_addr:
                    name = tokens_by_addr[key_ptr]   # a stub-made NSString
                else:
                    name = cstring(read_word(key_ptr + 8))
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
            elif sel.startswith('loadPhysicalBlockForMacroTile'):
                ctx['calls'].append(
                    f'loadPhysicalBlock(recv={recv:#x})'
                    + (f' -> {FTI:#x} (fake tile)'
                       if a.fake_tile else ''))
                uc_.reg_write(UC_ARM_REG_R0, FTI if a.fake_tile else 0)
            elif sel == 'isStaticTree':
                ctx['calls'].append(f'isStaticTree(={1 if a.static_tree else 0})')
                uc_.reg_write(UC_ARM_REG_R0, 1 if a.static_tree else 0)
            elif sel == 'maxNumberOfRiders':
                ctx['calls'].append(sel)
                uc_.reg_write(UC_ARM_REG_R0, 2)   # force the rider loop
            elif sel == 'stringWithFormat:':
                # the literal is a CFString object: its data pointer sits at +8
                raw = uc_.reg_read(UC_ARM_REG_R2)
                try:
                    fmt = cstring(read_word(raw + 8))
                except Exception:
                    fmt = cstring(raw)
                arg = uc_.reg_read(UC_ARM_REG_R3)
                key = fmt.replace('%d', str(arg)) if '%d' in fmt else fmt
                ctx['calls'].append(f'format->{key}')
                tok = token_for(key)
                uc_.reg_write(UC_ARM_REG_R0, tok)
            elif sel == 'unsignedLongLongValue':
                ctx['calls'].append('ull:' + (ctx['pending_key'] or '?'))
                uc_.reg_write(UC_ARM_REG_R0, 0x55667788)
                uc_.reg_write(UC_ARM_REG_R1, 0x11223344)
            elif sel == 'addObject:':
                ctx['calls'].append('addObject')
                uc_.reg_write(UC_ARM_REG_R0, 0)
            elif sel in ('array',):
                ctx['calls'].append('array')
                uc_.reg_write(UC_ARM_REG_R0, 0x5E1C0000)
            elif sel == 'macroTiles':
                ctx['calls'].append(
                    f'macroTiles(recv={recv:#x})'
                    + (f' -> {FTA:#x} (fake array)' if a.fake_tile else ''))
                uc_.reg_write(UC_ARM_REG_R0, FTA if a.fake_tile else 0)
            elif sel in ('worldWidthMacro', 'worldHeightMacro'):
                # the coordinate-wrap helper loops on worldWidthMacro*32;
                # returning 0 would spin forever. 4 macro-tiles = 128 tiles.
                ctx['calls'].append(sel)
                uc_.reg_write(UC_ARM_REG_R0, 4)
            elif sel in ('alloc', 'allocWithZone:'):
                ctx['calls'].append('alloc')
                ptr = heap_ptr[0]
                heap_ptr[0] += 0x100
                word(ptr, VTABLE_STUB)      # the fake vtable pointer
                uc_.reg_write(UC_ARM_REG_R0, ptr)
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
            elif sel in ('hidden', 'ignoreEvents'):
                # MJView getters: answer from the instance's own ivar so the
                # seeds drive the gates (hidden@4 / ignoreEvents@56).
                off = 4 if sel == 'hidden' else 56
                ctx['calls'].append(f'{sel}(recv={hex(recv)})')
                uc_.reg_write(UC_ARM_REG_R0, read_word(self_ptr + off) & 0xFF)
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

    # The .plt: entry i sits at 0x1C27D4 + i*12 and belongs to rel.plt[i].
    # A generic handler serves every imported call the bodies make, so no
    # body trips the unresolved lazy resolver.
    VENEER_MEMCPY = 0x1C2894
    PLT_FIRST = 0x1C27D4
    PLT_STEP = 12
    plt_names = {}
    with a.elf.open('rb') as f2:
        elf2 = ELFFile(f2)
        from elftools.elf.relocation import RelocationSection
        idx = 0
        for sec in elf2.iter_sections():
            if sec['sh_type'] not in ('SHT_REL', 'SHT_RELA') or 'plt' not in sec.name:
                continue
            symtab2 = elf2.get_section(sec['sh_link'])
            for rel in sec.iter_relocations():
                sym = symtab2.get_symbol(rel['r_info_sym'])
                plt_names[PLT_FIRST + idx * PLT_STEP] = sym.name
                idx += 1
    # scratch regions for stub-created objects (tokens, the rider array)
    uc.mem_map(TOKEN_BASE & ~0xFFF, 0x20000)
    heap_ptr = [graph + 0x8000]
    VTABLE_STUB = 0x72300000
    uc.mem_map(VTABLE_STUB, 0x1000)
    uc.mem_write(VTABLE_STUB, b'\x00' * 0x40)
    # the router differential's uiViews fixture: the fast-enumeration items
    # array plus the stable mutations marker the mutation guard compares
    UI_FIX = 0x74000000
    uc.mem_map(UI_FIX, 0x1000)
    UI_ITEMS = UI_FIX + 0x100
    UI_MUT = UI_FIX + 0x200
    word(UI_MUT, 0)

    def vcall_hook(uc_, address, size, data):
        # any virtual call arriving at the fake vtable's entry page
        ctx['calls'].append(f'vcall@{address - VTABLE_STUB:#x}')
        target = VTABLE_STUB + 0x80
        # jump into the tail of the page: a `bx lr` we place there
        uc_.reg_write(UC_ARM_REG_PC, target)

    uc.hook_add(UC_HOOK_CODE, vcall_hook, begin=VTABLE_STUB, end=VTABLE_STUB + 0x100)
    # a one-instruction `bx lr` trampoline at VTABLE_STUB+0x80 area
    # (0xE12FFF1E = bx lr)
    uc.mem_write(VTABLE_STUB + 0x80, bytes.fromhex('1eff2fe1'))

    def veneer_hook(uc_, address, size, data):
        name = plt_names.get(address)
        if name is None:
            return          # mid-entry instruction: let the stub run
        if name in ('objc_msgSend', 'objc_msgSendSuper2'):
            # these slots are already patched to jump straight at the stubs;
            # let the PLT entry execute (it lands in the stub) instead of
            # hijacking it here
            return
        r0 = uc_.reg_read(UC_ARM_REG_R0)
        if name == 'memcpy':
            dest = r0
            src = uc_.reg_read(UC_ARM_REG_R1)
            count = uc_.reg_read(UC_ARM_REG_R2)
            if count:
                uc_.mem_write(dest, bytes(uc_.mem_read(src, count)))
            ctx['calls'].append('memcpy')
            uc_.reg_write(UC_ARM_REG_R0, dest)
        elif name in ('malloc', 'operator new(unsigned int)',
                      '_Znwj', '_Znaj'):
            ctx['calls'].append(f'alloc({name})')
            uc_.reg_write(UC_ARM_REG_R0, heap_ptr[0])
            heap_ptr[0] += 0x100
        elif name in ('__aeabi_idiv', '__aeabi_uidiv', '__aeabi_idivmod',
                      '__aeabi_uidivmod'):
            a_ = uc_.reg_read(UC_ARM_REG_R0)
            b_ = uc_.reg_read(UC_ARM_REG_R1)
            if a_ >= 0x80000000:
                a_ -= 0x100000000
            if b_ >= 0x80000000:
                b_ -= 0x100000000
            q = abs(a_) // abs(b_) if b_ else 0
            if (a_ < 0) != (b_ < 0):
                q = -q
            ctx['calls'].append(f'{name}({a_},{b_})->{q}')
            uc_.reg_write(UC_ARM_REG_R0, q & 0xffffffff)
            if name.endswith('mod'):
                uc_.reg_write(UC_ARM_REG_R1, (a_ - q * b_) & 0xffffffff)
        elif name in ('sinf', 'cosf'):
            # the DPad hit test's rotation: answer with the true float value
            # (a platform-libm stand-in; softfp: the arg/return ride in R0 —
            # the caller's vmov r0, s0 / vmov s0, r0 pair). The model side
            # computes the same math; the tested points keep margins far
            # from the +-80 edges, so any 1-ulp libm difference cannot flip
            # a comparison.
            import math as _math
            a_bits = uc_.reg_read(UC_ARM_REG_R0)
            angle = struct.unpack('<f', struct.pack('<I', a_bits))[0]
            value = _math.sin(angle) if name == 'sinf' else _math.cos(angle)
            uc_.reg_write(UC_ARM_REG_R0,
                          struct.unpack('<I',
                                        struct.pack('<f', value))[0])
            ctx['calls'].append(f'import({name})')
        elif name in ('lrand48',):
            ctx['calls'].append('lrand48')
            uc_.reg_write(UC_ARM_REG_R0, 12345)
        else:
            ctx['calls'].append(f'import({name})')
            uc_.reg_write(UC_ARM_REG_R0, 0)
        uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

    # cover EVERY .plt entry: 611 rel.plt rows => the table runs up to .text
    uc.hook_add(UC_HOOK_CODE, veneer_hook, begin=PLT_FIRST, end=0x1C4480)

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
        ctx['ui_enum_calls'] = 0
        tokens.clear()
        if a.trace:
            pc_ring.clear()
            ctx['low_jump_done'] = False

            def trace_hook(uc_, addr, size, data):
                if addr < 0x1000 and not ctx['low_jump_done']:
                    ctx['low_jump_done'] = True
                    print(f'  LOW JUMP in {cls}: entered {addr:#x}; '
                          f'prev PCs {[hex(p) for p in list(pc_ring)[-8:]]}')
                    print(f'    r0={uc_.reg_read(UC_ARM_REG_R0):#x} '
                          f'r1={uc_.reg_read(UC_ARM_REG_R1):#x} '
                          f'r2={uc_.reg_read(UC_ARM_REG_R2):#x} '
                          f'r3={uc_.reg_read(UC_ARM_REG_R3):#x} '
                          f'lr={uc_.reg_read(UC_ARM_REG_LR):#x} '
                          f'sp={uc_.reg_read(UC_ARM_REG_SP):#x}')
                    print(f'    calls: {ctx["calls"][-6:]}')
                pc_ring.append(addr)
            uc.hook_add(UC_HOOK_CODE, trace_hook)
        uc.mem_write(self_ptr, b'\x00' * IMAGE_SIZE)
        word(self_ptr + 4, world)    # the real super init stores world@4
        word(self_ptr + 8, dyn)      # ... and dynamicWorld@8
        if a.seed:
            for pair in a.seed.split(','):
                off_s, val_s = pair.split('=')
                word(self_ptr + int(off_s, 0), int(val_s, 0))
        sp = stack + 0x8000
        for reg, value in ((UC_ARM_REG_R0, self_ptr), (UC_ARM_REG_R1, sel_region),
                           (UC_ARM_REG_R2, world), (UC_ARM_REG_R3, dyn)):
            uc.reg_write(reg, value)
        if a.r2r3_double is not None:
            import struct as _s
            lo, hi = _s.unpack('<II', _s.pack('<d', float(a.r2r3_double)))
            uc.reg_write(UC_ARM_REG_R2, lo)
            uc.reg_write(UC_ARM_REG_R3, hi)
        if a.r2r3_floats is not None:
            import struct as _s
            xs, ys = a.r2r3_floats.split(',')
            uc.reg_write(UC_ARM_REG_R2,
                         _s.unpack('<I', _s.pack('<f', float(xs)))[0])
            uc.reg_write(UC_ARM_REG_R3,
                         _s.unpack('<I', _s.pack('<f', float(ys)))[0])
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
        # The DynamicObject entries carry the stubbed super's base slots at
        # 4..11 (world@4 / dynamicWorld@8) — stub artifacts, normalized away.
        # The UI entries keep those offsets: @4 is MJView.hidden, @8 the
        # frame, and the CraftUI fixture reads its window floats back from
        # @8/+0xc — real state the differential must compare.
        if not cls.startswith(('MJView', 'MJControl', 'UIManager',
                               'CraftUI', 'DPad')):
            image[4:12] = b'\x00' * 8
        return ret, list(ctx['calls']), bytes(image)

    ctx['is_server'] = 1 if a.is_server else 0
    writes = []

    def mem_write_hook(uc_, access, address, size, value, user):
        if self_ptr <= address < self_ptr + IMAGE_SIZE:
            writes.append((address - self_ptr, size, value))

    uc.hook_add(UC_HOOK_MEM_WRITE, mem_write_hook, begin=self_ptr,
                end=self_ptr + IMAGE_SIZE - 1)

    if a.emit_spec:
        target = None
        for entry in ENTRIES:
            if entry[0] == a.emit_spec:
                target = entry
        assert target is not None, f'no ENTRIES row for {a.emit_spec}'
        cls, type_id, imp, superref, words = target
        ctx['lenient'] = True
        writes.clear()
        ret, calls, image = arm_run(target, 0)
        # pair each write with the most recent (key, conversion) from the trace
        spec = {'class': cls, 'type_id': type_id, 'imp': f'0x{imp:08x}',
                'code_words': words, 'calls': calls, 'keys': [], 'defaults': []}
        conv_map = {'int': 'Int', 'bool': 'Bool', 'uint': 'UInt',
                    'float': 'Float', 'retain': 'Object'}
        # the k-th conversion pairs with the k-th instance write (each read
        # stores exactly once in the flat-key bodies); writes issued BEFORE
        # any conversion are the unconditional defaults.
        events = []
        cur_key = None
        for c in calls:
            if c.startswith('ofk:'):
                cur_key = c[4:].split('(')[0]
            elif c == 'retain' or c.startswith('retain('):
                events.append((cur_key, 'Object'))
            elif ':' in c and c.split(':')[0] in conv_map:
                events.append((cur_key, conv_map[c.split(':')[0]]))
        # pair each conversion with the first matching SUBSEQUENT write (the
        # stub's return values are known constants, so value equality is the
        # robust key — a pre-block default like Boat's -1@120 then falls out
        # as a leftover => 'defaults')
        expect = {'Int': 0x00012345, 'UInt': 0x0001FFF1, 'Bool': 1,
                  'Float': 0x3FC00000}
        taken = [False] * len(writes)
        for key, conv in events:
            for wi in range(len(writes)):
                if taken[wi]:
                    continue
                off, size, val = writes[wi]
                mask = (1 << (8 * size)) - 1
                if conv == 'Object':
                    match = 0x5E1B0000 <= val < 0x5E1C0000
                else:
                    match = (val & mask) == (expect[conv] & mask)
                if match:
                    taken[wi] = True
                    spec['keys'].append({'key': key, 'conv': conv,
                                         'width': size, 'offset': off,
                                         'value': f'0x{val:08x}'})
                    break
        for wi, (off, size, val) in enumerate(writes):
            if not taken[wi]:
                spec['defaults'].append({'offset': off, 'width': size,
                                         'value': f'0x{val:08x}'})
        spec['writes_total'] = len(writes)
        spec['writes'] = [{'offset': o, 'width': s_, 'value': f'0x{v:08x}'}
                          for o, s_, v in writes]
        print(json.dumps(spec, indent=2))
        out = a.output_dir / f'spec_{cls}.json'
        out.write_text(json.dumps(spec, indent=2) + '\n')
        print(f'wrote {out}')
        return

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
                            str(repo / 'reconstruction/recovered/ui_control.cpp'),
                            str(repo / 'reconstruction/recovered/ui_touch_router.cpp'),
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
                        str(repo / 'reconstruction/recovered/ui_control.cpp'),
                        str(repo / 'reconstruction/recovered/ui_touch_router.cpp'),
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
        ui_seq_fn = cdll.recovered_ui_seq
        ui_seq_fn.argtypes = [ctypes.c_int32, ctypes.c_int32]
        ui_seq_fn.restype = ctypes.c_char_p
        ui_img_fn = cdll.recovered_ui_img
        ui_img_fn.argtypes = [ctypes.c_int32, ctypes.c_int32, ctypes.c_uint32,
                              ctypes.c_char_p, ctypes.c_int]
        ui_img_fn.restype = ctypes.c_int
        ui_ret_fn = cdll.recovered_ui_ret
        ui_ret_fn.argtypes = [ctypes.c_int32, ctypes.c_int32]
        ui_ret_fn.restype = ctypes.c_int
        bridges[opt] = (keys_fn, seq_fn, img_fn, extra_fn,
                        ui_seq_fn, ui_img_fn, ui_ret_fn)

    MODELLED = {'SteamTrain', 'OwnershipSign', 'Painting', 'DropBear',
                'CaveTroll', 'TrainCar', 'ArtificialLight'}
    ctx['is_server'] = 1   # phase 2 always runs the server-gated paths
    rows = []
    for entry in ENTRIES:
        cls, type_id, imp, superref, words = entry
        if cls not in MODELLED:
            continue
        keys_fn, seq_fn, img_fn, extra_fn, ui_seq_fn, ui_img_fn, ui_ret_fn = bridges[0]
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
                keys_fn, seq_fn, img_fn, extra_fn, ui_seq_fn, ui_img_fn, ui_ret_fn = bridges[opt]
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

    # ---- phase 2b: the UI front (MJControl -startTouch:) ------------------
    # The seeds mirror the harness's --seed runs the model was built from;
    # the labels are compared with the (recv=0x…) decorations stripped (those
    # are stub artifacts, not semantics).
    def fb(v):
        # the float's raw bits (seeds are word writes)
        return f'0x{struct.unpack("<I", struct.pack("<f", v))[0]:08x}'

    def frame(wx, wy, ox, oy):
        # the CraftUI fixture: windowInfo = self_ptr (its +8/+0xc words read
        # back as the window floats); translationOffset = the 212/216 floats
        return (f'128=0x60001000,8={fb(wx)},12={fb(wy)},'
                f'212={fb(ox)},216={fb(oy)}')

    CHILD_SB, CHILD_CB, CHILD_CS = 0x60020600, 0x60020700, 0x60020800
    CHILD_SEEDS = (f'148=0x{CHILD_SB:08x},208=0x{CHILD_CB:08x},'
                   f'164=0x{CHILD_CS:08x}')

    def dpad_frame(rs, wx8, wy, w10, w14, w1c):
        # the DPad fixture: windowInfo = self_ptr; the method reads the
        # fields from self+8/+0xc/+0x10/+0x14/+0x1c and rightSide@160 (byte)
        return (f'112=0x60001000,8={fb(wx8)},12={fb(wy)},16={fb(w10)},'
                f'20={fb(w14)},28={fb(w1c)},160={1 if rs else 0}')

    UI_CASES = {
        'MJControl': {
            0: ('50,50',
                '80=0x0,84=0x0,88=0x42c80000,92=0x42c80000,71=0x1,60=0x60030000',
                {}),
            1: ('500,500',
                '80=0x0,84=0x0,88=0x42c80000,92=0x42c80000,71=0x1,60=0x60030000',
                {}),
            2: ('50,50',
                '80=0x0,84=0x0,88=0x42c80000,92=0x42c80000,71=0x0,60=0x60030000',
                {}),
        },
        'UIManager': {
            # the router's block-chain cases: the seeds are the UI ivars,
            # 'ret1' pins a receiver's method to answer 1, and 'views' is
            # the uiViews@140 batch the enumeration fixture serves. Every
            # row is mirrored by ui_touch_router.h's run_ui_router (the
            # bridge's ui_router_case) — no case-fitted strings.
            0: ('50,50', '32=0x60020200', {}),
            1: ('50,50', '32=0x60020200,20=0x60020000', {}),
            2: ('50,50',
                '20=0x60020000,24=0x60020100,32=0x60020200,36=0x60020300,100=0x60020400',
                {}),
            3: ('50,50', '40=0x1,32=0x60020200,20=0x60020000', {}),
            # 4: hidePauseUI@148 set: the pauseUI block returns 1, no call
            4: ('50,50', '24=0x60020100,148=0x1', {}),
            # 5: the cameraUI block: call + paused fallback, merged result 0
            5: ('50,50', '100=0x60020400', {}),
            # 6: mapDisplayed@152 set: exits before the uiViews pass
            6: ('50,50', '20=0x60020000,152=0x1', {}),
            # 7: the tcUI call handles: the paused fallback is skipped
            7: ('50,50', '40=0x1,32=0x60020200,20=0x60020000',
                {'ret1': {0x60020200: ['startTouch:tapCount:']}}),
            # 8: the cameraUI call handles: no fallback, returns 1
            8: ('50,50', '100=0x60020400',
                {'ret1': {0x60020400: ['startTouch:tapCount:']}}),
            # 9: a displayed dpad misses: falls through to the worldUI block
            9: ('50,50', '36=0x60020300,20=0x60020000',
                {'ret1': {0x60020300: ['displayed']}}),
            # 10: a displayed dpad handles: returns 1 right away
            10: ('50,50', '36=0x60020300',
                 {'ret1': {0x60020300: ['displayed',
                                        'startTouch:tapCount:index:']}}),
            # 11: the worldUI call handles: @154 becomes 1 and is returned
            11: ('50,50', '20=0x60020000',
                 {'ret1': {0x60020000: ['startTouch:tapCount:index:']}}),
            # 12: a hidden view in the batch is skipped (displayed=0)
            12: ('50,50', '20=0x60020000,140=0x60020500',
                 {'enum_recv': 0x60020500, 'views': [0x60020600]}),
            # 13: a displayed view handles: @154 = 1, return 1
            13: ('50,50', '20=0x60020000,140=0x60020500',
                 {'enum_recv': 0x60020500, 'views': [0x60020600],
                  'ret1': {0x60020600: ['displayed',
                                        'startTouch:tapCount:']}}),
            # 14: a displayed view contains the point but does not handle:
            # the search ends there (no further batch call)
            14: ('50,50', '20=0x60020000,140=0x60020500',
                 {'enum_recv': 0x60020500, 'views': [0x60020600],
                  'ret1': {0x60020600: ['displayed',
                                        'touchIsInViewAtAll:']}}),
            # 15: a displayed view misses both: the batch is exhausted
            15: ('50,50', '20=0x60020000,140=0x60020500',
                 {'enum_recv': 0x60020500, 'views': [0x60020600],
                  'ret1': {0x60020600: ['displayed']}}),
            # 16: cameraUI misses, the paused fallback handles: merged 1
            16: ('50,50', '100=0x60020400,20=0x60020000',
                 {'ret1': {0x60020000: ['startTouch:tapCount:paused:index:']}}),
            # 17: batch order: the hidden first view is skipped, the second
            # displayed view handles
            17: ('50,50', '20=0x60020000,140=0x60020500',
                 {'enum_recv': 0x60020500,
                  'views': [0x60020600, 0x60020700],
                  'ret1': {0x60020700: ['displayed',
                                        'startTouch:tapCount:']}}),
            # 18: the in-view view ends the search before a view that would
            # have handled (its calls never happen)
            18: ('50,50', '20=0x60020000,140=0x60020500',
                 {'enum_recv': 0x60020500,
                  'views': [0x60020600, 0x60020700],
                  'ret1': {0x60020600: ['displayed',
                                        'touchIsInViewAtAll:'],
                           0x60020700: ['displayed',
                                        'startTouch:tapCount:']}}),
        },
        'CraftUIRect': {
            # touchIsInViewAtAll: — the own-rect test, EVERY edge exclusive
            0: ('50,50', frame(0, 0, 0, 0), {}),        # inside
            1: ('200,50', frame(0, 0, 0, 0), {}),       # x >= 130
            2: ('-130,50', frame(0, 0, 0, 0), {}),      # x == -130
            3: ('50,0', frame(0, 0, 0, 0), {}),         # y == 0
            4: ('50,302', frame(0, 0, 0, 0), {}),       # y == 302
            5: ('150,90', frame(100, 60, 30, 20), {}),  # local (20, 10)
        },
        'CraftUIInUI': {
            # touchIsInUI: — children OR, first nonzero wins (no own rect);
            # expect_recv pins the SB, CB, CS receiver order
            0: ('50,50', f'{frame(0, 0, 0, 0)},{CHILD_SEEDS}',
                {'expect_recv': [CHILD_SB, CHILD_CB, CHILD_CS]}),
            1: ('50,50', f'{frame(0, 0, 0, 0)},{CHILD_SEEDS}',
                {'expect_recv': [CHILD_SB],
                 'ret1': {CHILD_SB: ['touchIsInUI:']}}),
            2: ('50,50', f'{frame(0, 0, 0, 0)},{CHILD_SEEDS}',
                {'expect_recv': [CHILD_SB, CHILD_CB],
                 'ret1': {CHILD_CB: ['touchIsInUI:']}}),
            3: ('50,50', f'{frame(0, 0, 0, 0)},{CHILD_SEEDS}',
                {'expect_recv': [CHILD_SB, CHILD_CB, CHILD_CS],
                 'ret1': {CHILD_CS: ['touchIsInUI:']}}),
        },
        'CraftUIPress': {
            # startTouch:tapCount: — children startTouch:, same order
            0: ('50,50', f'{frame(0, 0, 0, 0)},{CHILD_SEEDS}',
                {'expect_recv': [CHILD_SB, CHILD_CB, CHILD_CS]}),
            1: ('50,50', f'{frame(0, 0, 0, 0)},{CHILD_SEEDS}',
                {'expect_recv': [CHILD_SB],
                 'ret1': {CHILD_SB: ['startTouch:']}}),
            2: ('50,50', f'{frame(0, 0, 0, 0)},{CHILD_SEEDS}',
                {'expect_recv': [CHILD_SB, CHILD_CB],
                 'ret1': {CHILD_CB: ['startTouch:']}}),
            3: ('50,50', f'{frame(0, 0, 0, 0)},{CHILD_SEEDS}',
                {'expect_recv': [CHILD_SB, CHILD_CB, CHILD_CS],
                 'ret1': {CHILD_CS: ['startTouch:']}}),
        },
        'CraftUIMove': {
            # moveTouch: — ALL THREE children, CB, CS, SB order; void
            0: ('50,50', f'{frame(0, 0, 0, 0)},{CHILD_SEEDS}',
                {'void': True,
                 'expect_recv': [CHILD_CB, CHILD_CS, CHILD_SB]}),
        },
        'CraftUIEnd': {
            # endTouch: — ALL THREE children, CB, CS, SB order; void
            0: ('50,50', f'{frame(0, 0, 0, 0)},{CHILD_SEEDS}',
                {'void': True,
                 'expect_recv': [CHILD_CB, CHILD_CS, CHILD_SB]}),
        },
        'DPadInUI': {
            # touchIsInUI: — the pure forward to touchIsInViewAtAll: (the
            # reply is the fixture's, pinned via ret1 on self)
            0: ('50,50', '', {}),
            1: ('50,50', '',
                {'ret1': {0x60001000: ['touchIsInViewAtAll:']}}),
        },
        'DPadRect': {
            # touchIsInViewAtAll: — the +-80 square after rebasing + rotating
            # by -pi/4 (0xBF490FDB); every case keeps a wide margin to the
            # edges, and 5/6/7 distinguish the w10 / w1c / rightSide terms
            # from their omission (each would flip the result)
            0: ('120.0,120.0', dpad_frame(0, 0, 0, 0, 0, 0), {}),  # center
            1: ('165.96194458007812,194.2462158203125',
                dpad_frame(0, 0, 0, 0, 0, 0), {}),                 # rx=+85
            2: ('74.03805541992188,194.2462158203125',
                dpad_frame(0, 0, 0, 0, 0, 0), {}),                 # ry=+85
            3: ('120.0,197.78173828125',
                dpad_frame(0, 0, 0, 0, 0, 0), {}),                 # (55,55) in
            4: ('120.0,240.20816040039062',
                dpad_frame(0, 0, 0, 0, 0, 0), {}),                 # (85,85) out
            5: ('215.86143493652344,175.86143493652344',
                dpad_frame(0, 0, 0, 40, 0, 0), {}),   # w10=40: rx=79 (in)
            6: ('64.13856506347656,200.86143493652344',
                dpad_frame(0, 0, 0, 0, 0, 25), {}),   # w1c=25: ry=79 (in)
            7: ('-50.0,120.0', dpad_frame(1, 50, 7, 0, 30, 0), {}),  # mirrored
            8: ('-4.038055419921875,194.2462158203125',
                dpad_frame(1, 50, 7, 0, 30, 0), {}),               # rx=+85
        },
        'MJView': {
            # 0/1: the empty-subviews cases (inside/outside — the base view
            # has no self test, so both are 0); 2/3: the gate cases.
            0: ('50,50',
                '4=0x0,56=0x0,8=0x0,12=0x0,16=0x42c80000,20=0x42c80000,52=0x6000f000',
                {}),
            1: ('500,500',
                '4=0x0,56=0x0,8=0x0,12=0x0,16=0x42c80000,20=0x42c80000,52=0x6000f000',
                {}),
            2: ('50,50',
                '4=0x1,56=0x0,8=0x0,12=0x0,16=0x42c80000,20=0x42c80000,52=0x6000f000',
                {}),
            3: ('50,50',
                '4=0x0,56=0x1,8=0x0,12=0x0,16=0x42c80000,20=0x42c80000,52=0x6000f000',
                {}),
        },
    }
    ui_modelled = []
    for entry in ENTRIES:
        cls, type_id, imp, superref, words = entry
        if cls not in UI_CASES:
            continue
        ui_modelled.append(cls)
        for case_id, (pt, seed, fixture) in sorted(UI_CASES[cls].items()):
            a.seed = seed
            a.r2r3_floats = pt
            ctx['ui_fixture'] = fixture
            ret, calls, image = arm_run(entry, case_id)
            arm_seq = ','.join(re.sub(r'\(recv=[^)]*\)', '', c) for c in calls)
            expect_recv = fixture.get('expect_recv')
            if expect_recv is not None:
                # the delegation-order proof: the receivers the ARM actually
                # messaged, in order (the stripped labels cannot distinguish
                # same-selector calls)
                got_recv = [int(re.search(r'\(recv=0x([0-9a-f]+)\)', c)
                                .group(1), 16) for c in calls]
                assert got_recv == expect_recv, (cls, case_id, calls)
            for opt in (0, 2):
                ui_seq_fn, ui_img_fn, ui_ret_fn = bridges[opt][4:]
                expected_seq = ui_seq_fn(type_id, case_id).decode()
                assert arm_seq == expected_seq, \
                    (cls, case_id, opt, arm_seq, expected_seq)
                expected_ret = ui_ret_fn(type_id, case_id)
                if not fixture.get('void'):
                    # void methods (moveTouch:/endTouch:) leave r0 at the
                    # fixture's last stub answer — not semantics, so it is
                    # recorded but not compared.
                    assert ret == expected_ret, (cls, case_id, opt, hex(ret))
                buf = ctypes.create_string_buffer(IMAGE_SIZE)
                assert ui_img_fn(type_id, case_id, TOKEN_BASE, buf,
                                 IMAGE_SIZE) == IMAGE_SIZE
                if buf.raw != image:
                    for off in range(IMAGE_SIZE):
                        if buf.raw[off] != image[off]:
                            print(f'  {cls} case {case_id} image diff at '
                                  f'+{off}: arm={image[off]:02x} '
                                  f'cpp={buf.raw[off]:02x}')
                assert buf.raw == image, (cls, case_id, opt, 'image mismatch')
            rows.append({'class': cls, 'type_id': type_id, 'case': case_id,
                         'arm_return': f'0x{ret:08x}', 'calls': calls,
                         'image_sha256': hashlib.sha256(image).hexdigest()[:32]})
        a.seed = None
        a.r2r3_floats = None
        ctx['ui_fixture'] = {}

    report = {'sha256': SHA, 'batch': 'specials',
              'classes': sorted(MODELLED | set(ui_modelled)),
              'cases': len(rows), 'match': True,
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
