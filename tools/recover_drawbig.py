#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The DynamicWorld draw cluster (preDrawUpdate/drawOpaqueObjects/drawFreeBlocks): the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 2344 instruction words, from the pinned original libApplication.so
(1.7.6, armeabi-v7a).  Every instruction word is re-verified; tool refuses to
emit on drift.

Verification rules (each one is a claim this file makes about its own evidence):
  * coverage    - the checked-in listing must cover [start, end) exactly once per word,
                  and every word is re-read from the pinned ELF.
  * PIC base    - recomputed from the `add rX, pc, rY` anchor and its pool literal;
                  must equal 0x0105faf4.
  * cells       - selector cells: the slot is base + signed(pool value) and the C string
                  it points at must be the named selector.  Import cells: the slot must be
                  a PLT/GOT slot whose relocation names the import, or - for functions
                  reached through an ABS32 relocation - a relocation whose symbol names
                  it (the route used is recorded per cell).  Ivar cells: the slot
                  holds a pointer to OBJC_IVAR_$_<Class>.<name> in .dynsym plus the
                  offset word.  Class cells: the slot either holds the OBJC_CLASS_$_
                  symbol value (.dynsym) or - for classes imported from the system
                  frameworks - carries an ABS32 relocation whose symbol is the class;
                  both routes are checked, the relocation route is named when used.
  * calls       - the set of bl/blx rows inside the body must equal the spec's set, and
                  every `bl <name>` route's computed target must match ROUTE_TARGETS.
  * branches    - the set of conditional/unconditional b* rows whose destination lands
                  inside the body must equal the spec's set.  Rows outside the body are
                  literal-pool words that mask as branches; they are recorded in
                  `disjoint_branch_rows` instead of being silently dropped.
  * anchors     - the listed instruction texts must match the listing byte for byte.

Machine-generated spec tables + hand-written semantics; see
reconstruction/reverse-v3/native/DRAW_PASS.md for the prose and boundaries.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

sys.path.insert(0, str(Path(__file__).resolve().parent))
from trace_objc_dispatch import ELFMemory
from recover_drawframe_slices import verify_disassembly

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
EXPECTED_SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
EXPECTED_BASE = 0x0105FAF4

ROUTE_TARGETS = {
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__': 0x005dc5d8,
    'bl method.std::__1::__tree_std::__1::pair_int__int___std::__1::__map_value_compare_int__int__std::__1::less_int___true___std::__1::allocator_std::__1::pair_int__int_____.__tree_std::__1::__map_value_compare_int__int__std::__1::less_int___true__const_': 0x0072fb18,
    'bl method.std::__1::map_int__int__std::__1::less_int___std::__1::allocator_std::__1::pair_int_const__int_____._map__': 0x0072fa7c,
    'bl method.std::__1::map_int__int__std::__1::less_int___std::__1::allocator_std::__1::pair_int_const__int_____.operator___int_const_': 0x0086c818,
    'bl sym.imp._Unwind_Resume': 0x001c29c0,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
}

SPECS = [
    dict(
        name='wtl_predrawupdate_camerami',
        method='DynamicWorld -[preDrawUpdate:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        types='v28@0:4f8i12i16i20i24',
        start=9245096,
        end=9246700,
        disasm='disasm_worldtileloader_predrawupdate_cameraminxworld_cameramaxx.txt',
        base_add=9245112,
        base_literal=9246696,
        boundary='ARM.exidx end 0x008d17ec (listing bound); next ObjC IMP 0x008d17ec DynamicWorld -[drawOpaqueObjects:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:hideUIType:]',
        selectors={
                 0x8d17d4: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8d17dc: (15216680, 'preDrawUpdate:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:'),
        },
        imports={
                 0x8d17d0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8d17d8: (17162216, 'OBJC_IVAR_$_DynamicWorld.netBlockheads', 48),
                 0x8d17e0: (17162212, 'OBJC_IVAR_$_DynamicWorld.netBlockheadsWithDisconnectedClients', 52),
                 0x8d17e4: (17162220, 'OBJC_IVAR_$_DynamicWorld.blockheads', 44),
        },
        classes={},
        instructions=[(9245096, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9245164, 'ldr r0, [0x008d17d8]'), (9245448, 'ldr r2, [0x008d17dc]'), (9245704, 'ldr r4, [0x008d17e0]'), (9245944, 'ldr r2, [0x008d17dc]'), (9246696, 'rsbseq lr, r8, r4, lsr sb')],
        calls=[(9245268, 'bl sym.imp.memset'), (9245332, 'blx lr'), (9245432, 'bl sym.imp.objc_enumerationMutation'), (9245544, 'blx ip'), (9245644, 'blx ip'), (9245764, 'bl sym.imp.memset'), (9245828, 'blx lr'), (9245928, 'bl sym.imp.objc_enumerationMutation'), (9246040, 'blx ip'), (9246140, 'blx ip'), (9246260, 'bl sym.imp.memset'), (9246324, 'blx lr'), (9246424, 'bl sym.imp.objc_enumerationMutation'), (9246536, 'blx ip'), (9246636, 'blx ip')],
        branches=[(9245344, 'beq', 9245668), (9245424, 'beq', 9245436), (9245572, 'blo', 9245388), (9245664, 'bne', 9245388), (9245668, 'b', 9245672), (9245840, 'beq', 9246164), (9245920, 'beq', 9245932), (9246068, 'blo', 9245884), (9246160, 'bne', 9245884), (9246164, 'b', 9246168), (9246336, 'beq', 9246660), (9246416, 'beq', 9246428), (9246564, 'blo', 9246380), (9246656, 'bne', 9246380), (9246660, 'b', 9246664)],
        semantics=('preDrawUpdate:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld: updates per-object draw state before the draw pass. Prologue 0x008d11a8 (frame 0x260; base 0x105faf4). Args: projection float + four camera ints.\nPass 1: the **ffffe4f4 netBlockheads** collection (@0x8d11ec) is enumerated (the fast-enumeration walk @0x8d1294-0x8d12f8); per blockhead the **ffe23534 call** (cell 0x8d17dc, @0x8d1308) runs with the camera float (vldr s0 from [fp,-0x28]) and the 4-byte array element (`add ip, ip, lr, lsl 2` @0x8d131c); the loop guards @0x8d1370-0x8d1384.\nPass 2: the **ffffe4f0 local-client family** (@0x8d1408) repeats the same walk and ffe23534 call (@0x8d14f8-0x8d1574) - the two-collection pre-draw update.\n'),
    ),
    dict(
        name='wtl_drawopaqueobjects_proj',
        method='DynamicWorld -[drawOpaqueObjects:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:hideUIType:]',
        types='v160@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76i140i144i148i152i156',
        start=9246700,
        end=9252280,
        disasm='disasm_worldtileloader_drawopaqueobjects_projectionmatrix_model.txt',
        base_add=9246728,
        base_literal=9247316,
        boundary='ARM.exidx end 0x008d2db8 (listing bound); next ObjC IMP 0x008d2db8 DynamicWorld -[drawInFrontOfBlocksObjects:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:hideUIType:]',
        selectors={
                 0x8d1a5c: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8d1a64: (15216684, 'draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:'),
                 0x8d2d90: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8d2d94: (15216684, 'draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:'),
        },
        imports={
                 0x8d1a58: (17151904, 'objc_msgSend'),
                 0x8d2d8c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8d1a60: (17162216, 'OBJC_IVAR_$_DynamicWorld.netBlockheads', 48),
                 0x8d2d98: (17162212, 'OBJC_IVAR_$_DynamicWorld.netBlockheadsWithDisconnectedClients', 52),
                 0x8d2da0: (17162220, 'OBJC_IVAR_$_DynamicWorld.blockheads', 44),
                 0x8d2db0: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
        },
        classes={},
        instructions=[(9246700, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9247380, 'ldr r4, [0x008d1a60]'), (9247504, 'blx lr'), (9248596, 'ldr r4, [0x008d2d98]'), (9249124, 'ldr r5, [0x008d2d94]'), (9252264, 'invalid'), (9252276, 'rsbseq ip, r8, r8, lsr 31')],
        calls=[(9247440, 'bl sym.imp.memset'), (9247504, 'blx lr'), (9247608, 'bl sym.imp.objc_enumerationMutation'), (9248420, 'bl loc.imp.objc_msgSend'), (9248528, 'blx ip'), (9248656, 'bl sym.imp.memset'), (9248720, 'blx lr'), (9248824, 'bl sym.imp.objc_enumerationMutation'), (9249636, 'bl loc.imp.objc_msgSend'), (9249744, 'blx ip'), (9249872, 'bl sym.imp.memset'), (9249936, 'blx lr'), (9250040, 'bl sym.imp.objc_enumerationMutation'), (9250852, 'bl loc.imp.objc_msgSend'), (9250960, 'blx ip'), (9252156, 'bl loc.imp.objc_msgSend'), (9252192, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__')],
        branches=[(9247308, 'beq', 9250992), (9247312, 'b', 9247340), (9247516, 'beq', 9248552), (9247600, 'beq', 9247612), (9248448, 'blo', 9247564), (9248548, 'bne', 9247564), (9248552, 'b', 9248556), (9248732, 'beq', 9249768), (9248816, 'beq', 9248828), (9249664, 'blo', 9248780), (9249764, 'bne', 9248780), (9249768, 'b', 9249772), (9249948, 'beq', 9250984), (9250032, 'beq', 9250044), (9250880, 'blo', 9249996), (9250980, 'bne', 9249996), (9250984, 'b', 9250988), (9250988, 'b', 9250992), (9251008, 'bge', 9252228), (9251328, 'beq', 9252208), (9252204, 'b', 9251240), (9252208, 'b', 9252212), (9252224, 'b', 9251000)],
        semantics=('drawOpaqueObjects:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:hideUIType: draws the opaque dynamic objects. Prologue 0x008d17ec (frame 0x860 + 16-aligned; base 0x105faf4). Args: the full camera/projection/matrix + hideUIType bundle (the 33-argument packed frame).\nPass 1: the **ffffe4f4 netBlockheads** (@0x8d1a94) enumerated (@0x8d1b10-0x8d1b78); per element the packed 33-argument call marshals the camera bundle (the ldr/str store wall @0x8d1b90-0x8d1e00) into the **ffe23538 dispatch** (@0x8d2164-0x8d2260) with the frame head at sp.\nPass 2: the **ffffe4f0 family** (@0x8d1f54) repeats with the same ffe23538 dispatch (@0x8d2164/0x8d2d94 cell) and the same argument marshalling (@0x8d2260+).\nTail: the **0x00E4AA1C jump table** (cell 0x8d2da8, the 8-arm family table) resolves the final per-family arm (@0x8d28b0+ region) before the epilogue - the opaque draw pass (hiddenUIType-gated).\n'),
    ),
    dict(
        name='wtl_drawfreeblocks_project',
        method='DynamicWorld -[drawFreeBlocks:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:hideUIType:]',
        types='v160@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76i140i144i148i152i156',
        start=9258848,
        end=9261040,
        disasm='disasm_worldtileloader_drawfreeblocks_projectionmatrix_modelvie.txt',
        base_add=9258868,
        base_literal=9261036,
        boundary='ARM.exidx end 0x008d4ff0 (listing bound); next ObjC IMP 0x008d4ff0 DynamicWorld -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:hideUIType:]',
        selectors={
                 0x8d4fd8: (15216012, 'pos'),
                 0x8d4fdc: (15216452, 'itemType'),
                 0x8d4fe4: (15216684, 'draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:'),
        },
        imports={},
        ivars={
                 0x8d4fd0: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
        },
        classes={},
        instructions=[(9258848, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9259516, 'add r1, r0, 0xa8'), (9259776, 'tst r0, 1'), (9260016, 'bl method.std::__1::map_int__int__std::__1::less_int___std::__1::allocator_std::__1::pair_int_const__int_____.operator___int_const_'), (9260888, 'bl loc.imp.objc_msgSend'), (9260916, 'bl method.std::__1::map_int__int__std::__1::less_int___std::__1::allocator_std::__1::pair_int_const__int_____._map__'), (9261036, 'rsbseq fp, r8, r8, ror r3')],
        calls=[(9259484, 'bl method.std::__1::__tree_std::__1::pair_int__int___std::__1::__map_value_compare_int__int__std::__1::less_int___true___std::__1::allocator_std::__1::pair_int__int_____.__tree_std::__1::__map_value_compare_int__int__std::__1::less_int___true__const_'), (9259900, 'bl loc.imp.objc_msgSend_stret'), (9259940, 'bl sym.imp.memset'), (9259976, 'bl loc.imp.objc_msgSend'), (9260016, 'bl method.std::__1::map_int__int__std::__1::less_int___std::__1::allocator_std::__1::pair_int_const__int_____.operator___int_const_'), (9260060, 'bl method.std::__1::map_int__int__std::__1::less_int___std::__1::allocator_std::__1::pair_int_const__int_____.operator___int_const_'), (9260888, 'bl loc.imp.objc_msgSend'), (9260916, 'bl method.std::__1::map_int__int__std::__1::less_int___std::__1::allocator_std::__1::pair_int_const__int_____._map__'), (9260964, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9260984, 'bl method.std::__1::map_int__int__std::__1::less_int___std::__1::allocator_std::__1::pair_int_const__int_____._map__'), (9261004, 'bl sym.imp._Unwind_Resume')],
        branches=[(9259436, 'beq', 9260992), (9259780, 'beq', 9260980), (9259784, 'b', 9259788), (9259884, 'beq', 9259912), (9259904, 'b', 9259908), (9259908, 'b', 9259944), (9259984, 'b', 9259988), (9260024, 'b', 9260028), (9260048, 'bge', 9260928), (9260068, 'b', 9260072), (9260892, 'b', 9260896), (9260896, 'b', 9260928), (9260924, 'b', 9261000), (9260928, 'b', 9260932), (9260976, 'b', 9259688)],
        semantics=("drawFreeBlocks:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:hideUIType: draws the free blocks. Prologue 0x008d4760 (frame 0x3d0 + 16-aligned; base 0x105faf4).\nBuild: the **ffffe54c member's +0xa8 slice** (`add r1, r0, 0xa8` @0x8d49fc) is tree-walked (the eor/tst guard @0x8d4ae8-0x8d4b00); per node the position is read via the ffe23298 stret (@0x8d4b88) and the **`std::__1::map<int, int>`** (constructed @0x8d49dc via __tree) is updated through `operator[]` (@0x8d4bf0) keyed by the objectType (`lsl r0, r0, 0xb` <<11 macro maths @0x8d4bac + ffe23450 @0x8d4bbc).\nDraw: the huge 33-argument frame is marshalled (@0x8d4c48-0x8d4f4c) and the **ffe23538 dispatch** call runs (@0x8d4f58); the map is destroyed via `~map<int,int>()` (@0x8d4f74) - the free-block draw pass.\n"),
    ),
]


def signed(v: int) -> int:
    return v - (1 << 32) if v & 0x80000000 else v


def bl_target(site: int, word: int) -> int:
    if word >> 24 != 0xEB:
        raise ValueError(f'{site:#x} is not ARM bl')
    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 1 << 24
    return (site + 8 + (imm << 2)) & 0xffffffff


def recover(path: Path) -> dict:
    data = path.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    if sha != EXPECTED_SHA:
        raise ValueError('unsupported ELF SHA-256; fixed-IMP analysis requires pinned original')
    memory = ELFMemory(path)
    elf = ELFFile(io.BytesIO(data))

    def cstr(addr):
        off = memory.offset(addr, 1)
        if off is None:
            return None
        end = data.find(b'\0', off, off + 256)
        return data[off:end].decode('utf-8', 'replace') if end >= 0 else None

    dynsym = {}
    for sec in elf.iter_sections():
        if sec.name == '.dynsym':
            for s in sec.iter_symbols():
                if s['st_value']:
                    dynsym.setdefault(s['st_value'], s.name)
    relocs = {}
    for sec in elf.iter_sections():
        if not isinstance(sec, RelocationSection):
            continue
        syms = elf.get_section(sec['sh_link'])
        for r in sec.iter_relocations():
            if r['r_info_sym']:
                relocs[r['r_offset']] = syms.get_symbol(r['r_info_sym']).name

    methods = []
    for spec in SPECS:
        text = (NATIVE / spec['disasm']).read_text()
        words = verify_disassembly(memory, text, spec['start'], spec['end'])
        rows = {}
        for mm in re.finditer(r'\b(0x[0-9a-f]{8})\s+[0-9a-f]{8}\s+(.*)', text):
            rows[int(mm.group(1), 16)] = mm.group(2).split(';')[0].strip()

        base = None
        if spec['base_add'] is not None:
            base = (spec['base_add'] + 8 + signed(memory.word(spec['base_literal']))) & 0xffffffff
            if base != EXPECTED_BASE:
                raise ValueError(f"{spec['name']}: PIC base drift {base:#x}")

        selectors = {}
        for cell, (expected_slot, expected_name) in spec['selectors'].items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: selector cell {cell:#x} -> {slot:#x}")
            got = cstr(memory.word(slot))
            if got != expected_name:
                raise ValueError(f"{spec['name']}: selector drifted at {cell:#x}: {got!r}")
            selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'selector': got}

        for cell, (expected_slot, expected_symbol) in spec.get('classes', {}).items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: class cell {cell:#x} -> {slot:#x}")
            entry = memory.word(slot)
            if entry is None:
                got = relocs.get(slot, '')
                if got != expected_symbol:
                    raise ValueError(f"{spec['name']}: class reloc drifted at {cell:#x}: {got!r}")
                selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'class': got,
                                              'route': 'ABS32 relocation symbol'}
                continue
            got = dynsym.get(entry, '')
            if got != expected_symbol:
                raise ValueError(f"{spec['name']}: class drifted at {cell:#x}: {got!r}")
            selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'class': got,
                                          'route': 'dynsym entry at slot word'}

        for cell, (expected_slot, expected_name) in spec['imports'].items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: import cell {cell:#x} -> {slot:#x}")
            got = memory.imports.get(slot)
            route = 'PLT/GOT relocation (R_ARM_JUMP_SLOT / GLOB_DAT)'
            if got is None:
                got = relocs.get(slot)
                route = 'ABS32 relocation symbol'
            if got != expected_name:
                raise ValueError(f"{spec['name']}: import drifted at {cell:#x}: {got!r} ({route})")
            selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'import': got, 'route': route}

        ivars = {}
        for cell, (expected_slot, expected_symbol, expected_offset) in spec['ivars'].items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: ivar cell {cell:#x} -> {slot:#x}")
            entry = memory.word(slot)
            symbol = dynsym.get(entry, '')
            offset = memory.word(entry)
            if symbol != expected_symbol or offset != expected_offset:
                raise ValueError(f"{spec['name']}: ivar {cell:#x} drifted: {symbol!r}@{offset}")
            ivars[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'symbol': symbol, 'offset': offset}

        inrange = {a: ins for a, ins in rows.items() if spec['start'] <= a < spec['end']}
        listed = {a for a, ins in inrange.items() if re.match(r'^blx?\s', ins)}
        expected_sites = {site for site, _ in spec['calls']}
        if listed != expected_sites:
            raise ValueError(f"{spec['name']}: call set drifted: {sorted(listed ^ expected_sites)}")
        calls = []
        for site, route in spec['calls']:
            if rows[site] != route:
                raise ValueError(f"{spec['name']}: route drifted at {site:#x}: {rows[site]!r}")
            target = None
            if route.startswith('bl '):
                target = bl_target(site, memory.word(site))
                expected = ROUTE_TARGETS.get(route)
                if expected is None or target != expected:
                    raise ValueError(f"{spec['name']}: bl target drifted at {site:#x}: {target:#x}")
            calls.append({'site': f'0x{site:08x}', 'route': route,
                          'callee': f'0x{target:08x}' if target else None})

        listed_branches = set()
        disjoint = []
        for a, ins in inrange.items():
            m = re.match(r'^(b\w*)\s+(0x[0-9a-f]+)', ins)
            if not m or m.group(1) in ('bl', 'blx'):
                continue
            dest = int(m.group(2), 16)
            if spec['start'] <= dest < spec['end']:
                listed_branches.add((a, m.group(1), dest))
            else:
                disjoint.append({'address': f'0x{a:08x}', 'mnemonic': m.group(1),
                                 'destination': f'0x{dest:08x}'})
        expected_branches = {(a, mn, dest) for a, mn, dest in spec['branches']}
        if listed_branches != expected_branches:
            raise ValueError(f"{spec['name']}: branch set drifted: {sorted(listed_branches ^ expected_branches)}")

        for address, expected_text in spec['instructions']:
            if rows.get(address) != expected_text:
                raise ValueError(f"{spec['name']}: instruction drifted at {address:#x}: "
                                 f"{rows.get(address)!r} != {expected_text!r}")

        methods.append({
            'name': spec['name'],
            'method': spec['method'],
            'types': spec['types'],
            'imp': f"0x{spec['start']:08x}",
            'boundary_end': f"0x{spec['end']:08x}",
            'boundary': spec['boundary'],
            'verified_words': words,
            'pic_base': f'0x{base:08x}' if base else None,
            'selectors': selectors,
            'ivars': ivars,
            'calls': calls,
            'branches': [{'address': f'0x{a:08x}', 'mnemonic': mn,
                          'destination': f'0x{d:08x}'}
                         for a, mn, d in spec['branches']],
            'disjoint_branch_rows': disjoint,
            'semantics': spec['semantics'],
        })

    return {
        'schema': 1,
        'elf_sha256': sha,
        'batch': 'DynamicWorld draw cluster (E41): preDrawUpdate:cameraMinXWorld:..., drawOpaqueObjects:...:hideUIType: and drawFreeBlocks:...:hideUIType:; 3 bodies',
        'claim': ('a static bounded-body map with per-instruction anchors; the wire-format markers, the '
                  'NSLog key strings, the C++ container member layouts and the packet helper at 0x8b84c8 are '
                  'outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'draw_pass.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale draw_pass.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
