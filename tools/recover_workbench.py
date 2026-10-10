#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The DynamicWorld workbench/interaction cluster (workbench/portal/interaction/freeblock): the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 887 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/WORKBENCH_INTERACTION.md for the prose and boundaries.
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
    'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_': 0x008bcb78,
    'bl method.std::__1::map_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.operator___unsigned_long_long_': 0x008bd2e4,
    'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const': 0x00910a74,
    'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_______std::__1::__map_value_compare_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.__count_unique_unsigned_long_long__unsigned_long_long_const__const': 0x0090c648,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.worldIndexAtWorldPos_intpair__World_': 0x00a15838,
}

SPECS = [
    dict(
        name='wtl_workbenchatpos_',
        method='DynamicWorld -[workbenchAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9371196,
        end=9371792,
        disasm='disasm_worldtileloader_workbenchatpos_.txt',
        base_add=9371212,
        base_literal=9371788,
        boundary='ARM.exidx end 0x008f0090 (listing bound); next ObjC IMP 0x008f0090 DynamicWorld -[portal]',
        selectors={
                 0x8f0070: (15216868, 'objectOfType:atPos:'),
                 0x8f0080: (15217004, 'isDoubleHeight'),
                 0x8f0088: (15216512, 'type'),
        },
        imports={
                 0x8f007c: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9371196, 'push {r4, r5, fp, lr}'), (9371260, 'ldr r1, [0x008f0070]'), (9371364, 'sub ip, ip, 1'), (9371396, 'bl sym.makeIntpair_int__int_'), (9371476, 'ldr r2, [0x008f0080]'), (9371788, 'rsbseq pc, r6, r0, lsr 25')],
        calls=[(9371308, 'bl loc.imp.objc_msgSend'), (9371396, 'bl sym.makeIntpair_int__int_'), (9371440, 'bl loc.imp.objc_msgSend'), (9371504, 'blx r2'), (9371584, 'bl sym.makeIntpair_int__int_'), (9371628, 'bl loc.imp.objc_msgSend'), (9371692, 'blx r2')],
        branches=[(9371328, 'beq', 9371344), (9371340, 'b', 9371748), (9371460, 'beq', 9371532), (9371516, 'beq', 9371532), (9371528, 'b', 9371748), (9371648, 'beq', 9371740), (9371708, 'beq', 9371724), (9371720, 'bne', 9371736), (9371732, 'b', 9371748), (9371736, 'b', 9371740)],
        semantics=('workbenchAtPos: returns the workbench at a position. Prologue 0x008efe3c (frame 0x78; base 0x105faf4).\nBody: the **ffe235f0 lookup** with type **0x2d (45)** (@0x8efe54-0x8efeac); on miss/absent: the **pos.y - 1 probe** (`sub ip, ip, 1` @0x8efee4) + `makeIntpair` (@0x8eff04) + the second ffe235f0 fetch (@0x8eff08-0x8eff30) + the **ffe23678 check** (cell 0x8f0080, @0x8eff54) - workbenches resolve at the position or one below (the same y-1 pattern as doorAtPos:).\n'),
    ),
    dict(
        name='wtl_workbenchhasbeencrafte',
        method='DynamicWorld -[workbenchHasBeenCrafted]',
        types='c8@0:4',
        start=9371996,
        end=9372056,
        disasm='disasm_worldtileloader_workbenchhasbeencrafted.txt',
        base_add=9372004,
        base_literal=9372052,
        boundary='ARM.exidx end 0x008f0198 (listing bound); next ObjC IMP 0x008f0198 DynamicWorld -[assignCraftProgressUIToLoadedWorkbenches:]',
        selectors={},
        imports={},
        ivars={
                 0x8f0190: (17162316, 'OBJC_IVAR_$_DynamicWorld.workbenchHasBeenCrafted', 7370),
        },
        classes={},
        instructions=[(9371996, 'sub sp, sp, 8'), (9372008, 'ldr r3, [0x008f0190]'), (9372036, 'ldrsb r0, [r0]'), (9372052, 'rsbseq pc, r6, r8, lsl 19')],
        calls=[],
        branches=[],
        semantics=("workbenchHasBeenCrafted (getter) returns the crafted flag. Prologue 0x008f015c (frame 0; base 0x105faf4).\nBody: the **ffffe558 byte** read directly (`ldrsb r0, [r0]` @0x8f0184) - the flag E30's workbenchPlacedAtPosition: sets.\n"),
    ),
    dict(
        name='wtl_assigncraftprogressuit',
        method='DynamicWorld -[assignCraftProgressUIToLoadedWorkbenches:]',
        types='v12@0:4@8',
        start=9372056,
        end=9373008,
        disasm='disasm_worldtileloader_assigncraftprogressuitoloadedworkbenches.txt',
        base_add=9372072,
        base_literal=9373004,
        boundary='ARM.exidx end 0x008f0550 (listing bound); next ObjC IMP 0x008f0550 DynamicWorld -[interactionObjectAtPos:]',
        selectors={
                 0x8f0548: (15217008, 'setCraftProgressUI:'),
        },
        imports={
                 0x8f0544: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8f0534: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8f053c: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
        },
        classes={},
        instructions=[(9372056, 'push {r4, r5, fp, lr}'), (9372120, 'add r1, r0, 0x21c'), (9372376, 'beq 0x8f0374'), (9372392, 'ldr r2, [0x008f0548]'), (9372516, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9372532, 'sub r0, fp, 0x80'), (9373004, 'rsbseq pc, r6, r4, asr 18')],
        calls=[(9372480, 'blx r3'), (9372516, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9372920, 'blx r3'), (9372956, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__')],
        branches=[(9372376, 'beq', 9372532), (9372528, 'b', 9372292), (9372816, 'beq', 9372972), (9372968, 'b', 9372732)],
        semantics=("assignCraftProgressUIToLoadedWorkbenches: assigns the craft-progress UI to loaded workbenches. Prologue 0x008f0198 (frame 0x198; base 0x105faf4).\nWalk 1: the **ffffe54c member's +0x21c workbench slice** (`add r1, r0, 0x21c` @0x8f01d8) tree-walked (the eor/tst guard @0x8f02c4-0x8f02d8); per node the **ffe2367c call** (cell 0x8f0548, @0x8f02e8) with the node payload ([node+0x10]+8 @0x8f0310-0x8f031c); `__tree_next` advances (@0x8f0364).\nWalk 2: the **ffffe550** side repeats the pass (the continuation from @0x8f0374) - the UI assigner.\n"),
    ),
    dict(
        name='wtl_interactionobjectwithi',
        method='DynamicWorld -[interactionObjectWithID:]',
        types='@16@0:4Q8',
        start=9375816,
        end=9376388,
        disasm='disasm_worldtileloader_interactionobjectwithid_.txt',
        base_add=9375832,
        base_literal=9376384,
        boundary='ARM.exidx end 0x008f1284 (listing bound); next ObjC IMP 0x008f1284 DynamicWorld -[interactionObjectTypeForObjectAtPos:]',
        selectors={},
        imports={},
        ivars={
                 0x8f1264: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8f1270: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
        },
        classes={},
        instructions=[(9375816, 'push {r4, r5, r6, sl, fp, lr}'), (9375872, 'bge 0x8f1250'), (9375952, 'add r1, r2, r1'), (9375980, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9376080, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_'), (9376096, 'add r0, sp, 0x28'), (9376384, 'invalid')],
        calls=[(9375980, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9376080, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_'), (9376200, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9376300, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_')],
        branches=[(9375872, 'bge', 9376336), (9375988, 'beq', 9376096), (9376092, 'b', 9376344), (9376208, 'beq', 9376316), (9376312, 'b', 9376344), (9376316, 'b', 9376320), (9376332, 'b', 9375864)],
        semantics=('interactionObjectWithID: resolves an interaction object by ID. Prologue 0x008f1048 (frame 0x60; base 0x105faf4).\nGate: `if (arg >= 9) return nil` (@0x8f107c-0x8f1080).\nLookup 1: the **0x00E4AA90 jump table** (cell 0x8f1268, the 9-arm interaction family table) selects the ffffe54c slice (`movw r1, 0xc; mul` 12-byte striding @0x8f1088-0x8f10d0) `__count_unique(u64)` (@0x8f10ec): hit -> `operator[](u64 const&)` (@0x8f1150) returns (@0x8f115c).\nLookup 2: miss -> the ffffe550 segment path (the continuation from @0x8f1160) - the interaction-object lookup.\n'),
    ),
    dict(
        name='wtl_interactionobjecttypef',
        method='DynamicWorld -[interactionObjectTypeForObjectAtPos:]',
        types='S16@0:4{?=ii}8',
        start=9376388,
        end=9376596,
        disasm='disasm_worldtileloader_interactionobjecttypeforobjectatpos_.txt',
        base_add=9376404,
        base_literal=9376592,
        boundary='ARM.exidx end 0x008f1354 (listing bound); next ObjC IMP 0x008f1354 DynamicWorld -[removeWorkbenchAtPos:removeBlockhead:]',
        selectors={
                 0x8f1340: (15216740, 'interactionObjectAtPos:'),
                 0x8f134c: (15217020, 'interactionObjectType'),
        },
        imports={
                 0x8f1348: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9376388, 'push {fp, lr}'), (9376448, 'ldr r1, [0x008f1340]'), (9376548, 'strh r0, [fp, -2]'), (9376564, 'ldrh r0, [fp, -2]'), (9376592, 'rsbseq lr, r6, r8, asr r8')],
        calls=[(9376480, 'bl loc.imp.objc_msgSend'), (9376544, 'blx r2')],
        branches=[(9376500, 'beq', 9376556), (9376552, 'b', 9376564)],
        semantics=('interactionObjectTypeForObjectAtPos: returns the interaction-object type at a position. Prologue 0x008f1284 (frame 0x40; base 0x105faf4).\nBody: the **ffe23570 fetch** (@0x8f12c0-0x8f12e0) -> the **ffe23688 type read** (cell 0x8f134c, @0x8f1304) returned as a **uint16** (`strh r0, [fp, -2]` @0x8f1324, `ldrh r0, [fp, -2]` @0x8f1334); 0 on no object (@0x8f132c-0x8f1330) - the 16-bit interaction type query.\n'),
    ),
    dict(
        name='wtl_removeworkbenchatpos_r',
        method='DynamicWorld -[removeWorkbenchAtPos:removeBlockhead:]',
        types='@20@0:4{?=ii}8@16',
        start=9376596,
        end=9376860,
        disasm='disasm_worldtileloader_removeworkbenchatpos_removeblockhead_.txt',
        base_add=9376612,
        base_literal=9376856,
        boundary='ARM.exidx end 0x008f145c (listing bound); next ObjC IMP 0x008f145c DynamicWorld -[removeInteractionObjectAtPos:removeBlockhead:]',
        selectors={
                 0x8f1448: (15217024, 'isInUse'),
                 0x8f144c: (15216340, 'workbenchAtPos:'),
                 0x8f1454: (15217028, 'remove:'),
        },
        imports={
                 0x8f1444: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9376596, 'push {r4, r5, fp, lr}'), (9376628, 'ldr r5, [0x008f1448]'), (9376676, 'ldr r1, [0x008f144c]'), (9376776, 'ldr r2, [0x008f1454]'), (9376856, 'rsbseq lr, r6, r8, lsl 15')],
        calls=[(9376712, 'bl loc.imp.objc_msgSend'), (9376736, 'blx r2'), (9376812, 'blx r3')],
        branches=[(9376748, 'beq', 9376764), (9376760, 'b', 9376824)],
        semantics=('removeWorkbenchAtPos:removeBlockhead: removes a workbench. Prologue 0x008f1354 (frame 0x48; base 0x105faf4).\nBody: the **ffe233e0 check** (cell 0x8f144c, @0x8f13a4) - a hit returns 0 (@0x8f13f0); otherwise the **ffe23690 remove call** (cell 0x8f1454, @0x8f1408) with pos + removeBlockhead - the workbench removal.\n'),
    ),
    dict(
        name='wtl_removeinteractionobjec',
        method='DynamicWorld -[removeInteractionObjectAtPos:removeBlockhead:]',
        types='@20@0:4{?=ii}8@16',
        start=9376860,
        end=9377124,
        disasm='disasm_worldtileloader_removeinteractionobjectatpos_removeblock.txt',
        base_add=9376876,
        base_literal=9377120,
        boundary='ARM.exidx end 0x008f1564 (listing bound); next ObjC IMP 0x008f1564 DynamicWorld -[freeBlocksExistAtPos:]',
        selectors={
                 0x8f1550: (15217024, 'isInUse'),
                 0x8f1554: (15216740, 'interactionObjectAtPos:'),
                 0x8f155c: (15217028, 'remove:'),
        },
        imports={
                 0x8f154c: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9376860, 'push {r4, r5, fp, lr}'), (9376892, 'ldr r5, [0x008f1550]'), (9376940, 'ldr r1, [0x008f1554]'), (9377040, 'ldr r2, [0x008f155c]'), (9377120, 'rsbseq lr, r6, r0, lsl 13')],
        calls=[(9376976, 'bl loc.imp.objc_msgSend'), (9377000, 'blx r2'), (9377076, 'blx r3')],
        branches=[(9377012, 'beq', 9377028), (9377024, 'b', 9377088)],
        semantics=('removeInteractionObjectAtPos:removeBlockhead: removes an interaction object. Prologue 0x008f145c (frame 0x48; base 0x105faf4).\nBody: the **ffe23570 fetch** (cell 0x8f1554, @0x8f14ac) - a hit returns 0 (@0x8f14f8); otherwise the **ffe23690 remove call** (cell 0x8f155c, @0x8f1510) - the paired interaction removal (same shape as the workbench leg).\n'),
    ),
    dict(
        name='wtl_freeblocksexistatpos_',
        method='DynamicWorld -[freeBlocksExistAtPos:]',
        types='c16@0:4{?=ii}8',
        start=9377124,
        end=9377468,
        disasm='disasm_worldtileloader_freeblocksexistatpos_.txt',
        base_add=9377184,
        base_literal=9377456,
        boundary='ARM.exidx end 0x008f16bc (listing bound); next ObjC IMP 0x008f16bc DynamicWorld -[freeBlocksAtPos:]',
        selectors={},
        imports={},
        ivars={
                 0x8f16ac: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8f16b4: (17162364, 'OBJC_IVAR_$_DynamicWorld.freeBlocksByPosition', 2400),
        },
        classes={},
        instructions=[(9377124, 'push {fp, lr}'), (9377236, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9377300, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_______std::__1::__map_value_compare_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9377316, 'bls 0x8f1698'), (9377328, 'ldr r2, [0x008f16b4]'), (9377464, 'ldrhteq lr, [r6], -0x44')],
        calls=[(9377236, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9377300, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_______std::__1::__map_value_compare_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9377368, 'bl method.std::__1::map_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.operator___unsigned_long_long_')],
        branches=[(9377316, 'bls', 9377432)],
        semantics=("freeBlocksExistAtPos: answers whether free blocks exist at a position. Prologue 0x008f1564 (frame 0x60; base 0x105faf4).\nBody: `worldIndexAtWorldPos(intpair, World*)` (@0x8f15d4) -> the **ffffe588 registry** `__count_unique(u64)` (@0x8f1614): non-zero -> true (the cmp/bls path @0x8f161c-0x8f1624); the set itself is then fetched via `operator[]` (@0x8f1630+) - the third ffffe588 consumer (with E24's writer and E32/E35's movers).\n"),
    ),
    dict(
        name='wtl_getnextdynamicobjectid',
        method='DynamicWorld -[getNextDynamicObjectID]',
        types='Q8@0:4',
        start=9378424,
        end=9378508,
        disasm='disasm_worldtileloader_getnextdynamicobjectid.txt',
        base_add=9378448,
        base_literal=9378504,
        boundary='ARM.exidx end 0x008f1acc (listing bound); next ObjC IMP 0x008f1acc DynamicWorld -[checkForHarmableDynamicObjectUnderTap:ignoreLocalBlockheads:ignoreAllBlockheads:]',
        selectors={},
        imports={},
        ivars={
                 0x8f1ac4: (17162324, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectIDCount', 7352),
        },
        classes={},
        instructions=[(9378424, 'sub sp, sp, 8'), (9378460, 'ldr r1, [r0, r1]!'), (9378472, 'adc r2, r2, 0'), (9378484, 'mov r0, r1'), (9378504, 'rsbseq lr, r6, ip, asr r0')],
        calls=[],
        branches=[],
        semantics=('getNextDynamicObjectID returns the next dynamic-object ID. Prologue 0x008f1a78 (frame 0; base 0x105faf4).\nBody: the **ffffe560 64-bit counter** (`ldr r1, [r0, r1]!` @0x8f1a9c) is incremented with carry (`adds r1, r1, 1; adc r2, r2, 0` @0x8f1aa4-0x8f1aa8) and stored back; the new value is returned (@0x8f1ab4-0x8f1ac0) - the ID generator.\n'),
    ),
    dict(
        name='wtl_portal',
        method='DynamicWorld -[portal]',
        types='@8@0:4',
        start=9371792,
        end=9371996,
        disasm='disasm_worldtileloader_portal.txt',
        base_add=9371808,
        base_literal=9371992,
        boundary='ARM.exidx end 0x008f015c (listing bound); next ObjC IMP 0x008f015c DynamicWorld -[workbenchHasBeenCrafted]',
        selectors={
                 0x8f0148: (15216336, 'startPortalPos'),
                 0x8f0150: (15216340, 'workbenchAtPos:'),
        },
        imports={},
        ivars={
                 0x8f014c: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
        },
        classes={},
        instructions=[(9371792, 'push {fp, lr}'), (9371816, 'ldr ip, [0x008f0148]'), (9371896, 'bl loc.imp.objc_msgSend_stret'), (9371964, 'bl loc.imp.objc_msgSend'), (9371992, 'rsbseq pc, r6, ip, asr 20')],
        calls=[(9371896, 'bl loc.imp.objc_msgSend_stret'), (9371932, 'bl sym.imp.memset'), (9371964, 'bl loc.imp.objc_msgSend')],
        branches=[(9371880, 'beq', 9371904), (9371900, 'b', 9371936)],
        semantics=("portal (getter) computes the world's portal. Prologue 0x008f0090 (frame 0x28; base 0x105faf4).\nBody: the ffe233dc chain + the world ffffe4e4 (@0x8f00a8-0x8f00d4) + the stret read (@0x8f00f8) + the **ffe233e0 call** (cell 0x8f0150, @0x8f013c) - the computed portal getter.\n"),
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
        'batch': 'DynamicWorld workbench/interaction cluster (E39): workbenchAtPos:, workbenchHasBeenCrafted, assignCraftProgressUIToLoadedWorkbenches:, interactionObjectWithID:, interactionObjectTypeForObjectAtPos:, removeWorkbenchAtPos:removeBlockhead:, removeInteractionObjectAtPos:removeBlockhead:, freeBlocksExistAtPos:, getNextDynamicObjectID and portal; 10 bodies',
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
                        default=NATIVE / 'workbench_interaction.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale workbench_interaction.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
