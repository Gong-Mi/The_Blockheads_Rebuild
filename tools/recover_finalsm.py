#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The DynamicWorld final smalls (crystal/freeblock/light/blockhead-selection): the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 380 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/FINAL_SMALLS.md for the prose and boundaries.
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
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_': 0x008bcb78,
    'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const': 0x00910a74,
}

SPECS = [
    dict(
        name='wtl_playtimecrystalreceive',
        method='DynamicWorld -[playTimeCrystalReceivedSoundAtPos:]',
        types='v16@0:4{?=ii}8',
        start=9299536,
        end=9300096,
        disasm='disasm_worldtileloader_playtimecrystalreceivedsoundatpos_.txt',
        base_add=9299552,
        base_literal=9300092,
        boundary='ARM.exidx end 0x008de880 (listing bound); next ObjC IMP 0x008de880 DynamicWorld -[createFreeBlockAtPosition:forForegroundContents:forTile:priorityBlockhead:]',
        selectors={
                 0x8de864: (15216060, 'instance'),
                 0x8de868: (15216500, 'multiSoundNamed:'),
                 0x8de870: (15216504, 'playAtPosition:afterDelay:'),
        },
        imports={
                 0x8de86c: (16333672, '__CFConstantStringClassReference'),
                 0x8de874: (16333848, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x8de854: (17162392, 'OBJC_IVAR_$_DynamicWorld.freeBlockSoundDelay', 7364),
        },
        classes={
                 0x8de85c: (15247876, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(9299536, 'push {r4, sl, fp, lr}'), (9299600, 'vldr s2, [r0]'), (9299620, 'bpl 0x8de84c'), (9299688, 'bl loc.imp.objc_msgSend'), (9299736, 'vcvt.f32.s32 s2, s2'), (9300092, 'rsbseq r1, r8, ip, lsl 9')],
        calls=[(9299688, 'bl loc.imp.objc_msgSend'), (9299720, 'bl loc.imp.objc_msgSend'), (9299760, 'bl method.Vector2.Vector2_float__float_'), (9299844, 'bl loc.imp.objc_msgSend'), (9299868, 'bl loc.imp.objc_msgSend'), (9299892, 'bl loc.imp.objc_msgSend'), (9299932, 'bl method.Vector2.Vector2_float__float_'), (9300008, 'bl loc.imp.objc_msgSend')],
        branches=[(9299620, 'bpl', 9300044)],
        semantics=("playTimeCrystalReceivedSoundAtPos: plays the time-crystal received sound. Prologue 0x008de650 (frame 0x60; base 0x105faf4).\nGate: the **ffffe5a4 float member** read (`vldr s2, [r0]` @0x8de690) compared against 1.0 (`vmov.f32 s0, 1; vcmpe.f32` @0x8de668-0x8de6a4): a value **>= 1** exits (`bpl 0x8de84c`).\nPlay: class ffe2af10 + ffe232c8 (@0x8de6b8-0x8de6e8) + the **0xfff34074 sound string** (cell 0x8de86c) + ffe23480 (@0x8de6ec-0x8de708); the position ints convert via vcvt.f32.s32 (@0x8de714-0x8de718) - the crystal sound (ffffe5a4 is the same accumulator E24's free-block sound uses).\n"),
    ),
    dict(
        name='wtl_freeblockwithuniqueid_',
        method='DynamicWorld -[freeblockWithUniqueID:]',
        types='@16@0:4Q8',
        start=9302696,
        end=9302980,
        disasm='disasm_worldtileloader_freeblockwithuniqueid_.txt',
        base_add=9302712,
        base_literal=9302976,
        boundary='ARM.exidx end 0x008df3c4 (listing bound); next ObjC IMP 0x008df3c4 DynamicWorld -[createBackgroundContentFreeBlockAtPosition:forTile:removeBlockhead:]',
        selectors={},
        imports={},
        ivars={
                 0x8df3b8: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8df3bc: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
        },
        classes={},
        instructions=[(9302696, 'push {r4, sl, fp, lr}'), (9302756, 'add r0, r0, 0xa8'), (9302780, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9302824, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_'), (9302888, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9302976, 'rsbseq r0, r8, r4, lsr r8')],
        calls=[(9302780, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9302824, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_'), (9302888, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9302932, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_')],
        branches=[(9302788, 'bls', 9302840), (9302836, 'b', 9302956), (9302896, 'bls', 9302948), (9302944, 'b', 9302956)],
        semantics=("freeblockWithUniqueID: resolves a free block by uniqueID. Prologue 0x008df2a8 (frame 0x38; base 0x105faf4).\nLookup 1: the **ffffe54c member's +0xa8 free-block slice** (`add r0, r0, 0xa8` @0x8df2e4) `__count_unique(u64)` (@0x8df2fc): hit -> `operator[](u64 const&)` (@0x8df328) returns (@0x8df334).\nLookup 2: miss -> the **ffffe550 member's +0xa8 slice** (@0x8df338-0x8df368) with the same pair - the free-block lookup sharing the +0xa8 slice with E41's drawFreeBlocks walk.\n"),
    ),
    dict(
        name='wtl_lightchangedatmacropos',
        method='DynamicWorld -[lightChangedAtMacroPos:sendReliably:]',
        types='v20@0:4{?=ii}8c16',
        start=9313128,
        end=9313264,
        disasm='disasm_worldtileloader_lightchangedatmacropos_sendreliably_.txt',
        base_add=9313196,
        base_literal=9313260,
        boundary='ARM.exidx end 0x008e1bf0 (listing bound); next ObjC IMP 0x008e1bf0 DynamicWorld -[snowChangedAtMacroPos:]',
        selectors={
                 0x8e1be8: (15216756, 'lightChangedAtMacroPos:sendReliably:sendAtAll:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(9313128, 'push {r4, sl, fp, lr}'), (9313160, 'strb ip, [sp, 0x17]'), (9313188, 'ldr r2, [0x008e1be8]'), (9313228, 'str r1, [lr]'), (9313244, 'bl loc.imp.objc_msgSend'), (9313260, 'rsbseq sp, r7, r0, asr 30')],
        calls=[(9313244, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=("lightChangedAtMacroPos:sendReliably: (the 2-argument overload) forwards a light change with the reliability byte. Prologue 0x008e1b68 (frame 0x30; base 0x105faf4).\nBody: the **ffe23580 call** (@0x8e1ba4-0x8e1bdc) with the frame carrying the sxtb'd sendReliably byte (`strb ip, [sp, 0x17]` @0x8e1b88 then `sxtb r1, r1; str r1, [lr]` @0x8e1bc8-0x8e1bcc) and the constant 1 (`mov r4, 1; str r4, [lr, 4]` @0x8e1bc0-0x8e1bc4) - the overload E23's 3-argument version forwards into.\n"),
    ),
    dict(
        name='wtl_activeblockhead',
        method='DynamicWorld -[activeBlockhead]',
        types='@8@0:4',
        start=9317292,
        end=9317564,
        disasm='disasm_worldtileloader_activeblockhead.txt',
        base_add=9317308,
        base_literal=9317560,
        boundary='ARM.exidx end 0x008e2cbc (listing bound); next ObjC IMP 0x008e2cbc DynamicWorld -[activeBlockheadIndex]',
        selectors={
                 0x8e2ca8: (15215864, 'count'),
                 0x8e2cb4: (15215808, 'objectAtIndex:'),
        },
        imports={
                 0x8e2ca4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8e2cac: (17162220, 'OBJC_IVAR_$_DynamicWorld.blockheads', 44),
                 0x8e2cb0: (17162320, 'OBJC_IVAR_$_DynamicWorld.activeBlockheadIndex', 7360),
        },
        classes={},
        instructions=[(9317292, 'push {r4, sl, fp, lr}'), (9317324, 'add ip, ip, r2'), (9317364, 'ldr r0, [r0]'), (9317428, 'b 0x8e2c98'), (9317444, 'ldr r2, [0x008e2cb4]'), (9317560, 'rsbseq ip, r7, r0, lsr pc')],
        calls=[(9317404, 'blx r3'), (9317520, 'blx r3')],
        branches=[(9317416, 'blo', 9317432), (9317428, 'b', 9317528)],
        semantics=('activeBlockhead returns the currently active blockhead. Prologue 0x008e2bac (frame 0x20; base 0x105faf4).\nBody: the **ffffe4f8 blockheads** collection count via ffe23204 (@0x8e2bc8-0x8e2bc4) compared with the **ffffe55c active index** (read @0x8e2be8-0x8e2bf4): index within count -> the object via ffe231cc (@0x8e2c44); out of range -> nil (@0x8e2c28-0x8e2c34) - the active-blockhead resolver.\n'),
    ),
    dict(
        name='wtl_activeblockheadindex',
        method='DynamicWorld -[activeBlockheadIndex]',
        types='i8@0:4',
        start=9317564,
        end=9317624,
        disasm='disasm_worldtileloader_activeblockheadindex.txt',
        base_add=9317572,
        base_literal=9317620,
        boundary='ARM.exidx end 0x008e2cf8 (listing bound); next ObjC IMP 0x008e2cf8 DynamicWorld -[selectedBlockheadChanged:]',
        selectors={},
        imports={},
        ivars={
                 0x8e2cf0: (17162320, 'OBJC_IVAR_$_DynamicWorld.activeBlockheadIndex', 7360),
        },
        classes={},
        instructions=[(9317564, 'sub sp, sp, 8'), (9317576, 'ldr r3, [0x008e2cf0]'), (9317604, 'ldr r0, [r0]'), (9317620, 'rsbseq ip, r7, r8, lsr 28')],
        calls=[],
        branches=[],
        semantics=('activeBlockheadIndex (getter) returns the active blockhead index. Prologue 0x008e2cbc (frame 0; base 0x105faf4).\nBody: the **ffffe55c member** read directly (@0x8e2cc8-0x8e2ce4) - the index getter (the same slot selectedBlockheadChanged: writes).\n'),
    ),
    dict(
        name='wtl_selectedblockheadchang',
        method='DynamicWorld -[selectedBlockheadChanged:]',
        types='v12@0:4i8',
        start=9317624,
        end=9317832,
        disasm='disasm_worldtileloader_selectedblockheadchanged_.txt',
        base_add=9317640,
        base_literal=9317828,
        boundary='ARM.exidx end 0x008e2dc8 (listing bound); next ObjC IMP 0x008e2dc8 DynamicWorld -[sowTreeNearParent:adult:adultMaxAge:]',
        selectors={
                 0x8e2db8: (15215864, 'count'),
        },
        imports={
                 0x8e2db4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8e2dbc: (17162220, 'OBJC_IVAR_$_DynamicWorld.blockheads', 44),
                 0x8e2dc0: (17162320, 'OBJC_IVAR_$_DynamicWorld.activeBlockheadIndex', 7360),
        },
        classes={},
        instructions=[(9317624, 'push {r4, sl, fp, lr}'), (9317652, 'ldr lr, [0x008e2db8]'), (9317720, 'blx ip'), (9317764, 'str r2, [r0]'), (9317800, 'str r0, [r1]'), (9317828, 'rsbseq ip, r7, r4, ror 27')],
        calls=[(9317720, 'blx ip')],
        branches=[(9317732, 'bhs', 9317772), (9317768, 'b', 9317804)],
        semantics=('selectedBlockheadChanged: sets the active blockhead index. Prologue 0x008e2cf8 (frame 0x20; base 0x105faf4).\nBody: the **ffffe4f8 count** via ffe23204 (@0x8e2d14-0x8e2d58) compared with the argument (`cmp r1, r0; bhs` @0x8e2d60-0x8e2d64): in range -> the index stored to **ffffe55c** (`str r2, [r0]` @0x8e2d84); out of range -> 0 stored (@0x8e2d8c-0x8e2da8) - the selection setter (pair with the activeBlockheadIndex getter).\n'),
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
        'batch': 'DynamicWorld final smalls (E42): playTimeCrystalReceivedSoundAtPos:, freeblockWithUniqueID:, lightChangedAtMacroPos:sendReliably: (2-arg), activeBlockhead, activeBlockheadIndex and selectedBlockheadChanged:; 6 bodies',
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
                        default=NATIVE / 'final_smalls.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale final_smalls.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
