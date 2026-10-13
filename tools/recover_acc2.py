#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The DynamicWorld structure-part accessor family B (ladder/column/stairs/elevatorShaft): the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 456 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/ACCESSOR_B.md for the prose and boundaries.
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
}

SPECS = [
    dict(
        name='wtl_ladderatpos_',
        method='DynamicWorld -[ladderAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9352296,
        end=9352408,
        disasm='disasm_worldtileloader_ladderatpos_.txt',
        base_add=9352356,
        base_literal=9352404,
        boundary='ARM.exidx end 0x008eb4d8 (listing bound); next ObjC IMP 0x008eb4d8 DynamicWorld -[addLadderAtPos:ofType:saveDict:placedByClient:]',
        selectors={
                 0x8eb4d0: (15216868, 'objectOfType:atPos:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(9352296, 'push {fp, lr}'), (9352404, 'rsbseq r4, r7, r8, asr 12')],
        calls=[(9352388, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('ladderAtPos: is the ladder accessor of the structure-part triplet. Prologue 0x008eb468 (frame 0x28; base 0x105faf4).\nBody: the type **0x13 (19)** (`movw ip, 0x13` / `mov r2, 0x13`) + the **ffe235f0 lookup** call with the pos argument - the ladder-at-position accessor (28 words).\n'),
    ),
    dict(
        name='wtl_addladderatpos_oftype_',
        method='DynamicWorld -[addLadderAtPos:ofType:saveDict:placedByClient:]',
        types='v28@0:4{?=ii}8i16@20@24',
        start=9352408,
        end=9352572,
        disasm='disasm_worldtileloader_addladderatpos_oftype_savedict_placedbyc.txt',
        base_add=9352500,
        base_literal=9352568,
        boundary='ARM.exidx end 0x008eb57c (listing bound); next ObjC IMP 0x008eb57c DynamicWorld -[removeLadderAtPos:]',
        selectors={
                 0x8eb574: (15216920, 'addStandardObjectAtPos:objectType:itemType:saveDict:placedByClient:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(9352408, 'push {r4, r5, fp, lr}'), (9352492, 'ldr ip, [0x008eb574]'), (9352568, 'ldrhteq r4, [r7], -0x58')],
        calls=[(9352552, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('addladderAtPos:ofType:saveDict:placedByClient: creates a ladder. Prologue 0x008eb4d8 (frame 0x40; base 0x105faf4).\nFrame: the four arguments are packed (the r1/r2/r3 + stack pair per the listing @0x8eb504-@0x8eb558); the type **0x13 (19)** immediate (`mov r1, 0x13`) rides the frame head; the **ffe23624 add call** (@0x8eb52c) with the workbench-family shape (type, ofType, saveDict, placedByClient) creates the structure part (41 words).\n'),
    ),
    dict(
        name='wtl_removeladderatpos_',
        method='DynamicWorld -[removeLadderAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9352572,
        end=9352752,
        disasm='disasm_worldtileloader_removeladderatpos_.txt',
        base_add=9352588,
        base_literal=9352748,
        boundary='ARM.exidx end 0x008eb630 (listing bound); next ObjC IMP 0x008eb630 DynamicWorld -[columnAtPos:]',
        selectors={
                 0x8eb620: (15216884, 'removeStandardObject:'),
                 0x8eb624: (15216924, 'ladderAtPos:'),
        },
        imports={
                 0x8eb61c: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9352572, 'push {r4, sl, fp, lr}'), (9352600, 'ldr r4, [0x008eb620]'), (9352644, 'ldr r1, [0x008eb624]'), (9352748, 'rsbseq r4, r7, r0, ror 10')],
        calls=[(9352676, 'bl loc.imp.objc_msgSend'), (9352716, 'blx r3')],
        branches=[],
        semantics=('removeladderAtPos: removes the ladder at a position. Prologue 0x008eb57c (frame 0x38; base 0x105faf4).\nBody: the **ffe23600 gate** (cell @0x8eb598) + the **ffe23628 remove call** (@0x8eb5c4) with the pos - the ladder removal leg (45 words).\n'),
    ),
    dict(
        name='wtl_columnatpos_',
        method='DynamicWorld -[columnAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9352752,
        end=9352864,
        disasm='disasm_worldtileloader_columnatpos_.txt',
        base_add=9352812,
        base_literal=9352860,
        boundary='ARM.exidx end 0x008eb6a0 (listing bound); next ObjC IMP 0x008eb6a0 DynamicWorld -[addColumnAtPos:ofType:saveDict:placedByClient:]',
        selectors={
                 0x8eb698: (15216868, 'objectOfType:atPos:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(9352752, 'push {fp, lr}'), (9352860, 'rsbseq r4, r7, r0, lsl 9')],
        calls=[(9352844, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('columnAtPos: is the column accessor of the structure-part triplet. Prologue 0x008eb630 (frame 0x28; base 0x105faf4).\nBody: the type **0x35 (53)** (`movw ip, 0x35` / `mov r2, 0x35`) + the **ffe235f0 lookup** call with the pos argument - the column-at-position accessor (28 words).\n'),
    ),
    dict(
        name='wtl_addcolumnatpos_oftype_',
        method='DynamicWorld -[addColumnAtPos:ofType:saveDict:placedByClient:]',
        types='v28@0:4{?=ii}8i16@20@24',
        start=9352864,
        end=9353028,
        disasm='disasm_worldtileloader_addcolumnatpos_oftype_savedict_placedbyc.txt',
        base_add=9352956,
        base_literal=9353024,
        boundary='ARM.exidx end 0x008eb744 (listing bound); next ObjC IMP 0x008eb744 DynamicWorld -[removeColumnAtPos:]',
        selectors={
                 0x8eb73c: (15216920, 'addStandardObjectAtPos:objectType:itemType:saveDict:placedByClient:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(9352864, 'push {r4, r5, fp, lr}'), (9352948, 'ldr ip, [0x008eb73c]'), (9353024, 'ldrshteq r4, [r7], -0x30')],
        calls=[(9353008, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('addcolumnAtPos:ofType:saveDict:placedByClient: creates a column. Prologue 0x008eb6a0 (frame 0x40; base 0x105faf4).\nFrame: the four arguments are packed (the r1/r2/r3 + stack pair per the listing @0x8eb6cc-@0x8eb720); the type **0x35 (53)** immediate (`mov r1, 0x35`) rides the frame head; the **ffe23624 add call** (@0x8eb6f4) with the workbench-family shape (type, ofType, saveDict, placedByClient) creates the structure part (41 words).\n'),
    ),
    dict(
        name='wtl_removecolumnatpos_',
        method='DynamicWorld -[removeColumnAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9353028,
        end=9353208,
        disasm='disasm_worldtileloader_removecolumnatpos_.txt',
        base_add=9353044,
        base_literal=9353204,
        boundary='ARM.exidx end 0x008eb7f8 (listing bound); next ObjC IMP 0x008eb7f8 DynamicWorld -[stairsAtPos:]',
        selectors={
                 0x8eb7e8: (15216884, 'removeStandardObject:'),
                 0x8eb7ec: (15216720, 'columnAtPos:'),
        },
        imports={
                 0x8eb7e4: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9353028, 'push {r4, sl, fp, lr}'), (9353056, 'ldr r4, [0x008eb7e8]'), (9353100, 'ldr r1, [0x008eb7ec]'), (9353204, 'invalid')],
        calls=[(9353132, 'bl loc.imp.objc_msgSend'), (9353172, 'blx r3')],
        branches=[],
        semantics=('removecolumnAtPos: removes the column at a position. Prologue 0x008eb744 (frame 0x38; base 0x105faf4).\nBody: the **ffe23600 gate** (cell @0x8eb760) + the **ffe2355c remove call** (@0x8eb78c) with the pos - the column removal leg (45 words).\n'),
    ),
    dict(
        name='wtl_stairsatpos_',
        method='DynamicWorld -[stairsAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9353208,
        end=9353320,
        disasm='disasm_worldtileloader_stairsatpos_.txt',
        base_add=9353268,
        base_literal=9353316,
        boundary='ARM.exidx end 0x008eb868 (listing bound); next ObjC IMP 0x008eb868 DynamicWorld -[addStairsAtPos:ofType:saveDict:placedByClient:]',
        selectors={
                 0x8eb860: (15216868, 'objectOfType:atPos:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(9353208, 'push {fp, lr}'), (9353316, 'ldrhteq r4, [r7], -0x28')],
        calls=[(9353300, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('stairsAtPos: is the stairs accessor of the structure-part triplet. Prologue 0x008eb7f8 (frame 0x28; base 0x105faf4).\nBody: the type **0x36 (54)** (`movw ip, 0x36` / `mov r2, 0x36`) + the **ffe235f0 lookup** call with the pos argument - the stairs-at-position accessor (28 words).\n'),
    ),
    dict(
        name='wtl_addstairsatpos_oftype_',
        method='DynamicWorld -[addStairsAtPos:ofType:saveDict:placedByClient:]',
        types='v28@0:4{?=ii}8i16@20@24',
        start=9353320,
        end=9353484,
        disasm='disasm_worldtileloader_addstairsatpos_oftype_savedict_placedbyc.txt',
        base_add=9353412,
        base_literal=9353480,
        boundary='ARM.exidx end 0x008eb90c (listing bound); next ObjC IMP 0x008eb90c DynamicWorld -[removeStairsAtPos:]',
        selectors={
                 0x8eb904: (15216920, 'addStandardObjectAtPos:objectType:itemType:saveDict:placedByClient:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(9353320, 'push {r4, r5, fp, lr}'), (9353404, 'ldr ip, [0x008eb904]'), (9353480, 'rsbseq r4, r7, r8, lsr 4')],
        calls=[(9353464, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('addstairsAtPos:ofType:saveDict:placedByClient: creates a stairs. Prologue 0x008eb868 (frame 0x40; base 0x105faf4).\nFrame: the four arguments are packed (the r1/r2/r3 + stack pair per the listing @0x8eb894-@0x8eb8e8); the type **0x36 (54)** immediate (`mov r1, 0x36`) rides the frame head; the **ffe23624 add call** (@0x8eb8bc) with the workbench-family shape (type, ofType, saveDict, placedByClient) creates the structure part (41 words).\n'),
    ),
    dict(
        name='wtl_removestairsatpos_',
        method='DynamicWorld -[removeStairsAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9353484,
        end=9353664,
        disasm='disasm_worldtileloader_removestairsatpos_.txt',
        base_add=9353500,
        base_literal=9353660,
        boundary='ARM.exidx end 0x008eb9c0 (listing bound); next ObjC IMP 0x008eb9c0 DynamicWorld -[addWireAtPos:ofType:saveDict:placedByClient:]',
        selectors={
                 0x8eb9b0: (15216884, 'removeStandardObject:'),
                 0x8eb9b4: (15216724, 'stairsAtPos:'),
        },
        imports={
                 0x8eb9ac: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9353484, 'push {r4, sl, fp, lr}'), (9353512, 'ldr r4, [0x008eb9b0]'), (9353556, 'ldr r1, [0x008eb9b4]'), (9353660, 'ldrsbteq r4, [r7], -0x10')],
        calls=[(9353588, 'bl loc.imp.objc_msgSend'), (9353628, 'blx r3')],
        branches=[],
        semantics=('removestairsAtPos: removes the stairs at a position. Prologue 0x008eb90c (frame 0x38; base 0x105faf4).\nBody: the **ffe23600 gate** (cell @0x8eb928) + the **ffe23560 remove call** (@0x8eb954) with the pos - the stairs removal leg (45 words).\n'),
    ),
    dict(
        name='wtl_elevatorshaftatpos_',
        method='DynamicWorld -[elevatorShaftAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9354120,
        end=9354232,
        disasm='disasm_worldtileloader_elevatorshaftatpos_.txt',
        base_add=9354180,
        base_literal=9354228,
        boundary='ARM.exidx end 0x008ebbf8 (listing bound); next ObjC IMP 0x008ebbf8 DynamicWorld -[addElevatorShaftAtPos:ofType:saveDict:placedByClient:]',
        selectors={
                 0x8ebbf0: (15216868, 'objectOfType:atPos:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(9354120, 'push {fp, lr}'), (9354228, 'rsbseq r3, r7, r8, lsr 30')],
        calls=[(9354212, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('elevatorShaftAtPos: is the elevatorShaft accessor of the structure-part triplet. Prologue 0x008ebb88 (frame 0x28; base 0x105faf4).\nBody: the type **0x38 (56)** (`movw ip, 0x38` / `mov r2, 0x38`) + the **ffe235f0 lookup** call with the pos argument - the elevatorShaft-at-position accessor (28 words).\n'),
    ),
    dict(
        name='wtl_addelevatorshaftatpos_',
        method='DynamicWorld -[addElevatorShaftAtPos:ofType:saveDict:placedByClient:]',
        types='v28@0:4{?=ii}8i16@20@24',
        start=9354232,
        end=9354396,
        disasm='disasm_worldtileloader_addelevatorshaftatpos_oftype_savedict_pl.txt',
        base_add=9354324,
        base_literal=9354392,
        boundary='ARM.exidx end 0x008ebc9c (listing bound); next ObjC IMP 0x008ebc9c DynamicWorld -[removeElevatorShaftAtPos:]',
        selectors={
                 0x8ebc94: (15216920, 'addStandardObjectAtPos:objectType:itemType:saveDict:placedByClient:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(9354232, 'push {r4, r5, fp, lr}'), (9354316, 'ldr ip, [0x008ebc94]'), (9354392, 'invalid')],
        calls=[(9354376, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('addelevatorShaftAtPos:ofType:saveDict:placedByClient: creates a elevatorShaft. Prologue 0x008ebbf8 (frame 0x40; base 0x105faf4).\nFrame: the four arguments are packed (the r1/r2/r3 + stack pair per the listing @0x8ebc24-@0x8ebc78); the type **0x38 (56)** immediate (`mov r1, 0x38`) rides the frame head; the **ffe23624 add call** (@0x8ebc4c) with the workbench-family shape (type, ofType, saveDict, placedByClient) creates the structure part (41 words).\n'),
    ),
    dict(
        name='wtl_removeelevatorshaftatp',
        method='DynamicWorld -[removeElevatorShaftAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9354396,
        end=9354576,
        disasm='disasm_worldtileloader_removeelevatorshaftatpos_.txt',
        base_add=9354412,
        base_literal=9354572,
        boundary='ARM.exidx end 0x008ebd50 (listing bound); next ObjC IMP 0x008ebd50 DynamicWorld -[openElevatorAtPos:]',
        selectors={
                 0x8ebd40: (15216884, 'removeStandardObject:'),
                 0x8ebd44: (15216928, 'elevatorShaftAtPos:'),
        },
        imports={
                 0x8ebd3c: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9354396, 'push {r4, sl, fp, lr}'), (9354424, 'ldr r4, [0x008ebd40]'), (9354468, 'ldr r1, [0x008ebd44]'), (9354572, 'rsbseq r3, r7, r0, asr 28')],
        calls=[(9354500, 'bl loc.imp.objc_msgSend'), (9354540, 'blx r3')],
        branches=[],
        semantics=('removeelevatorShaftAtPos: removes the elevatorShaft at a position. Prologue 0x008ebc9c (frame 0x38; base 0x105faf4).\nBody: the **ffe23600 gate** (cell @0x8ebcb8) + the **ffe2362c remove call** (@0x8ebce4) with the pos - the elevatorShaft removal leg (45 words).\n'),
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
        'batch': 'DynamicWorld structure-part accessor family B (E37): ladderAtPos:/addLadderAtPos:ofType:saveDict:placedByClient:/removeLadderAtPos:, columnAtPos:/addColumnAtPos:.../removeColumnAtPos:, stairsAtPos:/addStairsAtPos:.../removeStairsAtPos: and elevatorShaftAtPos:/addElevatorShaftAtPos:.../removeElevatorShaftAtPos:; 12 bodies',
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
                        default=NATIVE / 'accessor_b.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale accessor_b.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
