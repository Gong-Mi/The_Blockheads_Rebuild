#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The DynamicWorld last smalls (elevator/rail/tree/painting-send): the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 536 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/LAST_SMALLS.md for the prose and boundaries.
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
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
}

SPECS = [
    dict(
        name='wtl_openelevatoratpos_',
        method='DynamicWorld -[openElevatorAtPos:]',
        types='v16@0:4{?=ii}8',
        start=9354576,
        end=9354960,
        disasm='disasm_worldtileloader_openelevatoratpos_.txt',
        base_add=9354592,
        base_literal=9354956,
        boundary='ARM.exidx end 0x008ebed0 (listing bound); next ObjC IMP 0x008ebed0 DynamicWorld -[elevatorMotorAtPos:]',
        selectors={
                 0x8ebeac: (15216932, 'open'),
                 0x8ebeb8: (15216060, 'instance'),
                 0x8ebebc: (15216500, 'multiSoundNamed:'),
                 0x8ebec4: (15216888, 'playAtPosition:'),
                 0x8ebec8: (15216928, 'elevatorShaftAtPos:'),
        },
        imports={
                 0x8ebea8: (17151904, 'objc_msgSend'),
                 0x8ebec0: (16333928, '__CFConstantStringClassReference'),
        },
        ivars={},
        classes={
                 0x8ebeb0: (15247876, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(9354576, 'push {r4, sl, fp, lr}'), (9354628, 'ldr r0, [0x008ebeb0]'), (9354692, 'bl loc.imp.objc_msgSend'), (9354716, 'vmov r2, s2'), (9354728, 'mov r0, r3'), (9354956, 'rsbseq r3, r7, ip, lsl 27')],
        calls=[(9354668, 'bl loc.imp.objc_msgSend'), (9354692, 'bl loc.imp.objc_msgSend'), (9354732, 'bl method.Vector2.Vector2_float__float_'), (9354760, 'bl loc.imp.objc_msgSend'), (9354816, 'bl loc.imp.objc_msgSend'), (9354832, 'bl loc.imp.objc_msgSend'), (9354864, 'bl sym.makeIntpair_int__int_'), (9354892, 'bl loc.imp.objc_msgSend'), (9354908, 'blx r2')],
        branches=[],
        semantics=("openElevatorAtPos: plays the elevator-open sound at a position. Prologue 0x008ebd50 (frame 0x50; base 0x105faf4).\nBody: class **ffe2af10** + ffe232c8 (@0x8ebd84-0x8ebdac) + the **0xfff34174 sound string** (cell 0x8ebec0) + ffe23480 (@0x8ebdb0-0x8ebdc4); the position ints convert via vcvt.f32.s32 (@0x8ebdd0-0x8ebddc) - the elevator sound (class ffe2af10/ffe232c8 shared with E42's crystal player) + the ffe23630 call (cell 0x8ebeac).\n"),
    ),
    dict(
        name='wtl_elevatormotoratpos_',
        method='DynamicWorld -[elevatorMotorAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9354960,
        end=9355072,
        disasm='disasm_worldtileloader_elevatormotoratpos_.txt',
        base_add=9355020,
        base_literal=9355068,
        boundary='ARM.exidx end 0x008ebf40 (listing bound); next ObjC IMP 0x008ebf40 DynamicWorld -[elevatorMotorForShaftAtPos:]',
        selectors={
                 0x8ebf38: (15216868, 'objectOfType:atPos:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(9354960, 'push {fp, lr}'), (9354972, 'movw ip, 0x37'), (9355012, 'ldr r1, [0x008ebf38]'), (9355048, 'str ip, [sp, 4]'), (9355068, 'rsbseq r3, r7, r0, ror 23')],
        calls=[(9355052, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=("elevatorMotorAtPos: returns the elevator motor at a position. Prologue 0x008ebed0 (frame 0x28; base 0x105faf4).\nBody: the type **0x37 (55)** (`movw ip, 0x37` / `mov r2, 0x37` @0x8ebedc/0x8ebf24) + the **ffe235f0 lookup** (@0x8ebf04-0x8ebf2c) - the elevator-motor accessor (the type E23's elevatorMotorForShaftAtPos: scans for).\n"),
    ),
    dict(
        name='wtl_addelevatormotoratpos_',
        method='DynamicWorld -[addElevatorMotorAtPos:ofType:saveDict:placedByClient:]',
        types='v28@0:4{?=ii}8i16@20@24',
        start=9358668,
        end=9358832,
        disasm='disasm_worldtileloader_addelevatormotoratpos_oftype_savedict_pl.txt',
        base_add=9358760,
        base_literal=9358828,
        boundary='ARM.exidx end 0x008ecdf0 (listing bound); next ObjC IMP 0x008ecdf0 DynamicWorld -[removeElevatorMotorAtPos:]',
        selectors={
                 0x8ecde8: (15216920, 'addStandardObjectAtPos:objectType:itemType:saveDict:placedByClient:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(9358668, 'push {r4, r5, fp, lr}'), (9358752, 'ldr ip, [0x008ecde8]'), (9358792, 'mov r1, 0x37'), (9358828, 'rsbseq r2, r7, r4, asr 26')],
        calls=[(9358812, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('addElevatorMotorAtPos:ofType:saveDict:placedByClient: creates an elevator motor. Prologue 0x008ecd4c (frame 0x40; base 0x105faf4).\nBody: the type **0x37 (55)** (`mov r1, 0x37` @0x8ecdc8) + the **ffe23624 add call** frame (@0x8ecda0-0x8ecddc) - the motor add leg (the E36/E37/E38 family shape).\n'),
    ),
    dict(
        name='wtl_removeelevatormotoratp',
        method='DynamicWorld -[removeElevatorMotorAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9358832,
        end=9359012,
        disasm='disasm_worldtileloader_removeelevatormotoratpos_.txt',
        base_add=9358848,
        base_literal=9359008,
        boundary='ARM.exidx end 0x008ecea4 (listing bound); next ObjC IMP 0x008ecea4 DynamicWorld -[addRailAtPos:ofType:ownedByStation:]',
        selectors={
                 0x8ece94: (15216884, 'removeStandardObject:'),
                 0x8ece98: (15216948, 'elevatorMotorAtPos:'),
        },
        imports={
                 0x8ece90: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9358832, 'push {r4, sl, fp, lr}'), (9358860, 'ldr r4, [0x008ece94]'), (9358904, 'ldr r1, [0x008ece98]'), (9358976, 'blx r3'), (9359008, 'rsbseq r2, r7, ip, ror 25')],
        calls=[(9358936, 'bl loc.imp.objc_msgSend'), (9358976, 'blx r3')],
        branches=[],
        semantics=("removeElevatorMotorAtPos: removes the elevator motor at a position. Prologue 0x008ecdf0 (frame 0x38; base 0x105faf4).\nBody: the **ffe23600 gate** (cell 0x8ece94) + the **ffe23640 remove call** (cell 0x8ece98, @0x8ece38-0x8ece80) - the same ffe23640 cell E23's elevatorMotorForShaftAtPos: hits (pair confirmed).\n"),
    ),
    dict(
        name='wtl_getrailatpos_',
        method='DynamicWorld -[getRailAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9359956,
        end=9360068,
        disasm='disasm_worldtileloader_getrailatpos_.txt',
        base_add=9360016,
        base_literal=9360064,
        boundary='ARM.exidx end 0x008ed2c4 (listing bound); next ObjC IMP 0x008ed2c4 DynamicWorld -[removeRailAtPos:]',
        selectors={
                 0x8ed2bc: (15216868, 'objectOfType:atPos:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(9359956, 'push {fp, lr}'), (9359968, 'movw ip, 0x28'), (9360008, 'ldr r1, [0x008ed2bc]'), (9360044, 'str ip, [sp, 4]'), (9360064, 'rsbseq r2, r7, ip, asr r8')],
        calls=[(9360048, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('getRailAtPos: returns the rail at a position. Prologue 0x008ed254 (frame 0x28; base 0x105faf4).\nBody: the type **0x28 (40)** (`movw ip, 0x28` / `mov r2, 0x28` @0x8ed260/0x8ed2a8) + the **ffe235f0 lookup** (@0x8ed288-0x8ed2b0) - the rail accessor.\n'),
    ),
    dict(
        name='wtl_removerailatpos_',
        method='DynamicWorld -[removeRailAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9360068,
        end=9360292,
        disasm='disasm_worldtileloader_removerailatpos_.txt',
        base_add=9360084,
        base_literal=9360288,
        boundary='ARM.exidx end 0x008ed3a4 (listing bound); next ObjC IMP 0x008ed3a4 DynamicWorld -[windowAtPos:]',
        selectors={
                 0x8ed390: (15216852, 'railOrStationNameChanged'),
                 0x8ed394: (15216884, 'removeStandardObject:'),
                 0x8ed398: (15216956, 'getRailAtPos:'),
        },
        imports={
                 0x8ed38c: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9360068, 'push {r4, r5, r6, sl, fp, lr}'), (9360100, 'ldr r5, [0x008ed390]'), (9360152, 'ldr r1, [0x008ed398]'), (9360232, 'blx r3'), (9360252, 'blx r2'), (9360288, 'rsbseq r2, r7, r8, lsl r8')],
        calls=[(9360192, 'bl loc.imp.objc_msgSend'), (9360232, 'blx r3'), (9360252, 'blx r2')],
        branches=[],
        semantics=("removeRailAtPos: removes the rail at a position. Prologue 0x008ed2c4 (frame 0x48; base 0x105faf4).\nBody: the **ffe235e0 check** (cell 0x8ed390, @0x8ed2e4) + the **ffe23600 gate** + the **ffe23648 remove call** (cell 0x8ed398, @0x8ed318-0x8ed368) + a following ffe230-family call (@0x8ed374-0x8ed37c) - the rail removal (ffe235e0 shared with E34's railOrStationNameChanged).\n"),
    ),
    dict(
        name='wtl_treeatpos_',
        method='DynamicWorld -[treeAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9369112,
        end=9369336,
        disasm='disasm_worldtileloader_treeatpos_.txt',
        base_add=9369180,
        base_literal=9369328,
        boundary='ARM.exidx end 0x008ef6f8 (listing bound); next ObjC IMP 0x008ef6f8 DynamicWorld -[getPlantAtPos:]',
        selectors={
                 0x8ef6f4: (15216868, 'objectOfType:atPos:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(9369112, 'push {r4, sl, fp, lr}'), (9369156, 'bge 0x8ef6d8'), (9369188, 'ldr r2, [r3, r2, lsl 2]'), (9369248, 'bl loc.imp.objc_msgSend'), (9369292, 'add r0, r0, 1'), (9369332, 'invalid')],
        calls=[(9369248, 'bl loc.imp.objc_msgSend')],
        branches=[(9369156, 'bge', 9369304), (9369268, 'beq', 9369284), (9369280, 'b', 9369312), (9369284, 'b', 9369288), (9369300, 'b', 9369148)],
        semantics=("treeAtPos: returns the tree at a position across the tree families. Prologue 0x008ef618 (frame 0x38; base 0x105faf4). Args: tree class index (r0), the position.\nGate: `if (arg >= 0xb) return nil` (@0x8ef640-0x8ef644) - **11 tree classes**.\nLoop: the **0x00E4AA64 jump table** (cell 0x8ef6ec, the 11-arm tree-family table @0x8ef654-0x8ef664) selects the ffe235f0 type per family; the loop increments through the arms (`add r0, r0, 1` @0x8ef6cc) probing each via the ffe235f0 lookup (@0x8ef678-0x8ef6a0) until a hit (@0x8ef6b4) or exhaustion (@0x8ef6d8) - the tree resolver (the table sits adjacent to E23's 0xE4AA60 life-fraction table).\n"),
    ),
    dict(
        name='wtl_sendpaintingdataforpai',
        method='DynamicWorld -[sendPaintingDataForPaintingWithID:toClient:]',
        types='v20@0:4Q8@16',
        start=9443008,
        end=9443752,
        disasm='disasm_worldtileloader_sendpaintingdataforpaintingwithid_toclie.txt',
        base_add=9443024,
        base_literal=9443748,
        boundary='ARM.exidx end 0x009019a8 (listing bound); next ObjC IMP 0x009019a8 DynamicWorld -[paintingDataRecievedFromServer:]',
        selectors={
                 0x90196c: (15217276, 'paintingWithID:'),
                 0x901974: (15217280, 'imageData'),
                 0x901978: (15216188, 'length'),
                 0x90197c: (15217100, 'sendNetworkData:toPeers:reliable:'),
                 0x901980: (15216588, 'arrayWithObject:'),
                 0x90198c: (15216184, 'appendData:'),
                 0x901990: (15216220, 'appendBytes:length:'),
                 0x90199c: (15216180, 'dataWithBytes:length:'),
                 0x9019a0: (15216160, 'uniqueID'),
        },
        imports={
                 0x901970: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x901988: (17162256, 'OBJC_IVAR_$_DynamicWorld.server', 16),
        },
        classes={
                 0x901984: (15247880, 'OBJC_CLASS_$_NSArray'),
                 0x901994: (15247844, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(9443008, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9443040, 'add r5, r5, ip'), (9443088, 'bl loc.imp.objc_msgSend'), (9443156, 'mov r1, r3'), (9443200, 'ldr r2, [0x00901978]'), (9443748, 'rsbseq lr, r5, ip, lsl r4')],
        calls=[(9443088, 'bl loc.imp.objc_msgSend'), (9443164, 'blx r3'), (9443228, 'blx r2'), (9443464, 'bl loc.imp.objc_msgSend'), (9443488, 'bl loc.imp.objc_msgSend'), (9443536, 'blx ip'), (9443560, 'blx r3'), (9443628, 'blx ip'), (9443676, 'blx lr')],
        branches=[(9443108, 'beq', 9443684), (9443184, 'beq', 9443680), (9443236, 'bls', 9443680), (9443680, 'b', 9443684)],
        semantics=("sendPaintingDataForPaintingWithID:toClient: sends a painting's pixel data to a client. Prologue 0x009016c0 (frame 0xb0; base 0x105faf4).\nBody: the **ffe23788/ffe2378c** checks (@0x9016dc/0x901738) resolve the painting and client; the **ffe23348 8-byte data accessor** (cell 0x901978, @0x901780) slices the payload; the ffe23790 parse follows - the sender half of the E32 painting pair (requestPaintingDataForPainting: / paintingDataRecievedFromServer:) with the same 8-byte convention.\n"),
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
        'batch': 'DynamicWorld last smalls (E43): openElevatorAtPos:, elevatorMotorAtPos:, addElevatorMotorAtPos:..., removeElevatorMotorAtPos:, getRailAtPos:, removeRailAtPos:, treeAtPos: and sendPaintingDataForPaintingWithID:toClient:; 8 bodies',
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
                        default=NATIVE / 'last_smalls.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale last_smalls.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
