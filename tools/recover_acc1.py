#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The DynamicWorld typed accessor family A (fire/torch/egg/painting): the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 711 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/ACCESSOR_A.md for the prose and boundaries.
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
    'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_': 0x008bcf24,
    'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_': 0x008bcb78,
    'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const': 0x00910a74,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileIsPlant_Tile_': 0x00a13ce0,
    'bl sym.worldIndexAtWorldPos_intpair__World_': 0x00a15838,
}

SPECS = [
    dict(
        name='wtl_placefireatposition_',
        method='DynamicWorld -[placeFireAtPosition:]',
        types='@16@0:4{?=ii}8',
        start=9339108,
        end=9339680,
        disasm='disasm_worldtileloader_placefireatposition_.txt',
        base_add=9339124,
        base_literal=9339676,
        boundary='ARM.exidx end 0x008e8320 (listing bound); next ObjC IMP 0x008e8320 DynamicWorld -[addTorchAtPos:ofType:dataA:dataB:saveDict:placedByClient:]',
        selectors={
                 0x8e82fc: (15216856, 'getPlantAtPos:'),
                 0x8e8304: (15216804, 'loadStandardDynamicObjectOfType:atPos:'),
                 0x8e8310: (15216020, 'sendNetDataIfNeededForObject:isCreation:'),
                 0x8e8314: (15216860, 'worldChangedAtPos:sendReliably:'),
        },
        imports={
                 0x8e830c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8e82f8: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
        },
        classes={},
        instructions=[(9339108, 'push {r4, r5, r6, sl, fp, lr}'), (9339180, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9339192, 'ldrsb r0, [r0, 0x16]'), (9339220, 'bl sym.tileIsPlant_Tile_'), (9339332, 'strb r1, [r2, 0xb]'), (9339432, 'bl loc.imp.objc_msgSend'), (9339676, 'ldrshteq r7, [r7], -0x98')],
        calls=[(9339180, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9339220, 'bl sym.tileIsPlant_Tile_'), (9339304, 'bl loc.imp.objc_msgSend'), (9339432, 'bl loc.imp.objc_msgSend'), (9339572, 'bl loc.imp.objc_msgSend'), (9339616, 'blx ip')],
        branches=[(9339200, 'beq', 9339216), (9339212, 'b', 9339628), (9339232, 'beq', 9339344), (9339316, 'bne', 9339344), (9339340, 'b', 9339628), (9339452, 'beq', 9339620)],
        semantics=('placeFireAtPosition: places fire (or burns a plant) at a position. Prologue 0x008e80e4 (frame 0x78; base 0x105faf4).\nTile probe: `tileAtWorldPositionLoaded(int, int, World*)` (C call @0x8e812c, world via ffffe4e4); the tile byte at +0x16 must be zero (@0x8e8138-0x8e8140 -> return).\nPlant branch: `tileIsPlant(Tile*)` (C call @0x8e8154): a plant -> the ffe235e4 call (@0x8e817c-0x8e81a8) and the byte [r2+0xb] cleared (`strb r1, [r2, 0xb]` @0x8e81c4) - the plant burns.\nCreate: otherwise the type **0x10 (16)** (`movw r1, 0x10`, `mov lr, 0x10` @0x8e81d4-0x8e820c) + the ffe235b0 creation call (@0x8e81ec-0x8e8228) with the pos argument.\n'),
    ),
    dict(
        name='wtl_objectoftype_atpos_',
        method='DynamicWorld -[objectOfType:atPos:]',
        types='@20@0:4i8{?=ii}12',
        start=9340596,
        end=9341068,
        disasm='disasm_worldtileloader_objectoftype_atpos_.txt',
        base_add=9340612,
        base_literal=9341064,
        boundary='ARM.exidx end 0x008e888c (listing bound); next ObjC IMP 0x008e888c DynamicWorld -[torchAtPos:]',
        selectors={
                 0x8e887c: (15216544, 'needsRemoved'),
        },
        imports={
                 0x8e8878: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8e886c: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8e8874: (17162312, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsByWorldPosIndex', 1620),
        },
        classes={},
        instructions=[(9340596, 'push {r4, sl, fp, lr}'), (9340728, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9340764, 'add r1, r1, r1, lsl 1'), (9340804, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9340876, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9340936, 'add r1, sp, 0x18'), (9341064, 'rsbseq r7, r7, r8, lsr 8')],
        calls=[(9340728, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9340804, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9340876, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9340920, 'blx r3'), (9340996, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_')],
        branches=[(9340812, 'beq', 9341016), (9340932, 'bne', 9341012), (9341008, 'b', 9341024), (9341012, 'b', 9341016)],
        semantics=("objectOfType:atPos: resolves the dynamic object of a type at a position. Prologue 0x008e86b4 (frame 0x68; base 0x105faf4).\nLookup 1: `worldIndexAtWorldPos(intpair, World*)` (world via ffffe4e4 @0x8e86f8-0x8e8738) -> the **ffffe554 map's 12-byte segment** (`add r1, r1, r1, lsl 1` <<2 @0x8e875c) `__count_unique(u64)` (@0x8e8784): hit -> `operator[](u64&&)` (@0x8e87cc) -> the **ffe234ac gate** (@0x8e87dc): loaded -> return the object (@0x8e8804).\nLookup 2: the not-loaded / miss path continues with the second ffffe554 walk (@0x8e8808+) - the same two-registry resolver shape as E31's loadStandardDynamicObjectOfType:atPos:.\n"),
    ),
    dict(
        name='wtl_torchatpos_',
        method='DynamicWorld -[torchAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9341068,
        end=9341180,
        disasm='disasm_worldtileloader_torchatpos_.txt',
        base_add=9341128,
        base_literal=9341176,
        boundary='ARM.exidx end 0x008e88fc (listing bound); next ObjC IMP 0x008e88fc DynamicWorld -[removeStandardObject:]',
        selectors={
                 0x8e88f4: (15216868, 'objectOfType:atPos:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(9341068, 'push {fp, lr}'), (9341080, 'movw ip, 0x11'), (9341120, 'ldr r1, [0x008e88f4]'), (9341156, 'str ip, [sp, 4]'), (9341176, 'rsbseq r7, r7, r4, lsr 4')],
        calls=[(9341160, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('torchAtPos: returns the torch at a position. Prologue 0x008e888c (frame 0x28; base 0x105faf4).\nBody: the type **0x11 (17)** (`movw ip, 0x11`, `mov r2, 0x11` @0x8e8898/0x8e88e0) + the **ffe235f0 lookup** (@0x8e88c0-0x8e88e8) - the torch accessor of the typed pair.\n'),
    ),
    dict(
        name='wtl_removetorchatpos_',
        method='DynamicWorld -[removeTorchAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9342952,
        end=9343132,
        disasm='disasm_worldtileloader_removetorchatpos_.txt',
        base_add=9342968,
        base_literal=9343128,
        boundary='ARM.exidx end 0x008e909c (listing bound); next ObjC IMP 0x008e909c DynamicWorld -[createTreasureChestOrTrollAtTile:atPos:loadTroll:loadTreasure:]',
        selectors={
                 0x8e908c: (15216884, 'removeStandardObject:'),
                 0x8e9090: (15216728, 'torchAtPos:'),
        },
        imports={
                 0x8e9088: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9342952, 'push {r4, sl, fp, lr}'), (9342980, 'ldr r4, [0x008e908c]'), (9343120, 'invalid'), (9343096, 'blx r3'), (9343128, 'ldrshteq r6, [r7], -0xa4')],
        calls=[(9343056, 'bl loc.imp.objc_msgSend'), (9343096, 'blx r3')],
        branches=[],
        semantics=('removeTorchAtPos: removes the torch at a position. Prologue 0x008e8fe8 (frame 0x38; base 0x105faf4).\nBody: the **ffe23600 gate** (cell 0x8e908c) + the **ffe23564 remove call** (@0x8e9090-0x8e9078) with the pos - the torch removal leg.\n'),
    ),
    dict(
        name='wtl_eggatpos_',
        method='DynamicWorld -[eggAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9348920,
        end=9349032,
        disasm='disasm_worldtileloader_eggatpos_.txt',
        base_add=9348980,
        base_literal=9349028,
        boundary='ARM.exidx end 0x008ea7a8 (listing bound); next ObjC IMP 0x008ea7a8 DynamicWorld -[addEggAtPos:saveDict:]',
        selectors={
                 0x8ea7a0: (15216868, 'objectOfType:atPos:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(9348920, 'push {fp, lr}'), (9348932, 'movw ip, 0x1e'), (9348972, 'ldr r1, [0x008ea7a0]'), (9349008, 'str ip, [sp, 4]'), (9349028, 'rsbseq r5, r7, r8, ror r3')],
        calls=[(9349012, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('eggAtPos: returns the egg at a position. Prologue 0x008ea738 (frame 0x28; base 0x105faf4).\nBody: the type **0x1e (30)** (`movw ip, 0x1e`, `mov r2, 0x1e` @0x8ea744/0x8ea78c) + the **ffe235f0 lookup** (@0x8ea76c-0x8ea794) - the dodo-egg accessor.\n'),
    ),
    dict(
        name='wtl_addeggatpos_savedict_',
        method='DynamicWorld -[addEggAtPos:saveDict:]',
        types='v20@0:4{?=ii}8@16',
        start=9349032,
        end=9349672,
        disasm='disasm_worldtileloader_addeggatpos_savedict_.txt',
        base_add=9349048,
        base_literal=9349668,
        boundary='ARM.exidx end 0x008eaa28 (listing bound); next ObjC IMP 0x008eaa28 DynamicWorld -[removeEggAtPos:]',
        selectors={
                 0x8ea9f8: (15215804, 'alloc'),
                 0x8eaa04: (15216904, 'initWithWorld:dynamicWorld:atPosition:cache:saveDict:'),
                 0x8eaa0c: (15216020, 'sendNetDataIfNeededForObject:isCreation:'),
                 0x8eaa10: (15216168, 'objectType'),
                 0x8eaa1c: (15216160, 'uniqueID'),
        },
        imports={
                 0x8eaa08: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8ea9fc: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8eaa00: (17162232, 'OBJC_IVAR_$_DynamicWorld.cache', 7336),
                 0x8eaa18: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
                 0x8eaa20: (17162312, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsByWorldPosIndex', 1620),
        },
        classes={
                 0x8ea9f0: (15247988, 'OBJC_CLASS_$_Egg'),
        },
        instructions=[(9349032, 'push {r4, r5, r6, r7, fp, lr}'), (9349080, 'ldr r0, [0x008ea9f0]'), (9349128, 'ldr r2, [0x008ea9fc]'), (9349188, 'ldr r4, [0x008eaa04]'), (9349220, 'str r5, [r7]'), (9349668, 'rsbseq r5, r7, r4, lsr r3')],
        calls=[(9349120, 'bl loc.imp.objc_msgSend'), (9349236, 'bl loc.imp.objc_msgSend'), (9349304, 'bl loc.imp.objc_msgSend'), (9349364, 'bl loc.imp.objc_msgSend'), (9349384, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9349444, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9349472, 'bl loc.imp.objc_msgSend'), (9349528, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9349604, 'blx r4')],
        branches=[(9349256, 'beq', 9349608)],
        semantics=('addEggAtPos:saveDict: creates/loads an egg at a position. Prologue 0x008ea7a8 (frame 0x90; base 0x105faf4).\nCreate: the class **ffe2af80** alloc/init (cells ffe2af80/ffe231c8 @0x8ea7d8-0x8ea800) + the world chain (ffffe4e4/ffffe504 @0x8ea808-0x8ea83c) + the **ffe23614 add call** (@0x8ea844-0x8ea864) with the saveDict argument - the egg adder (type 30 family).\n'),
    ),
    dict(
        name='wtl_removeeggatpos_',
        method='DynamicWorld -[removeEggAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9349672,
        end=9349852,
        disasm='disasm_worldtileloader_removeeggatpos_.txt',
        base_add=9349688,
        base_literal=9349848,
        boundary='ARM.exidx end 0x008eaadc (listing bound); next ObjC IMP 0x008eaadc DynamicWorld -[paintingWithID:]',
        selectors={
                 0x8eaacc: (15216884, 'removeStandardObject:'),
                 0x8eaad0: (15216908, 'eggAtPos:'),
        },
        imports={
                 0x8eaac8: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9349672, 'push {r4, sl, fp, lr}'), (9349700, 'ldr r4, [0x008eaacc]'), (9349840, 'invalid'), (9349816, 'blx r3'), (9349848, 'ldrhteq r5, [r7], -4')],
        calls=[(9349776, 'bl loc.imp.objc_msgSend'), (9349816, 'blx r3')],
        branches=[],
        semantics=('removeEggAtPos: removes the egg at a position. Prologue 0x008eaa28 (frame 0x38; base 0x105faf4).\nBody: the **ffe23600 gate** (cell 0x8eaacc) + the **ffe23618 remove call** (@0x8eaad0-0x8eaab8) - the egg removal leg.\n'),
    ),
    dict(
        name='wtl_paintingwithid_',
        method='DynamicWorld -[paintingWithID:]',
        types='@16@0:4Q8',
        start=9349852,
        end=9350136,
        disasm='disasm_worldtileloader_paintingwithid_.txt',
        base_add=9349868,
        base_literal=9350132,
        boundary='ARM.exidx end 0x008eabf8 (listing bound); next ObjC IMP 0x008eabf8 DynamicWorld -[paintingAtPos:]',
        selectors={},
        imports={},
        ivars={
                 0x8eabec: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8eabf0: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
        },
        classes={},
        instructions=[(9349852, 'push {r4, sl, fp, lr}'), (9349912, 'add r0, r0, 0x270'), (9349936, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9349980, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_'), (9350044, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9350132, 'rsbseq r5, r7, r0')],
        calls=[(9349936, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9349980, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_'), (9350044, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9350088, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_')],
        branches=[(9349944, 'beq', 9349996), (9349992, 'b', 9350112), (9350052, 'beq', 9350104), (9350100, 'b', 9350112)],
        semantics=("paintingWithID: resolves a painting by ID. Prologue 0x008eaadc (frame 0x38; base 0x105faf4).\nLookup 1: the **ffffe54c member's +0x270 slice** (`add r0, r0, 0x270` @0x8eab18) `__count_unique(u64)` (@0x8eab30): hit -> `operator[](u64 const&)` (@0x8eab5c) returns (@0x8eab68).\nLookup 2: miss -> the **ffffe550 member's +0x270 slice** with the same `__count_unique` (@0x8eab9c from @0x8eab6c) - the two-registry painting lookup (the same +0x270 offset E33's mute walk addresses).\n"),
    ),
    dict(
        name='wtl_paintingatpos_',
        method='DynamicWorld -[paintingAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9350136,
        end=9350248,
        disasm='disasm_worldtileloader_paintingatpos_.txt',
        base_add=9350196,
        base_literal=9350244,
        boundary='ARM.exidx end 0x008eac68 (listing bound); next ObjC IMP 0x008eac68 DynamicWorld -[addPaintingAtPos:ofType:saveDict:placedByClient:clientName:]',
        selectors={
                 0x8eac60: (15216868, 'objectOfType:atPos:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(9350136, 'push {fp, lr}'), (9350148, 'movw ip, 0x34'), (9350188, 'ldr r1, [0x008eac60]'), (9350224, 'str ip, [sp, 4]'), (9350244, 'ldrhteq r4, [r7], -0xe8')],
        calls=[(9350228, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('paintingAtPos: returns the painting at a position. Prologue 0x008eabf8 (frame 0x28; base 0x105faf4).\nBody: the type **0x34 (52)** (`movw ip, 0x34`, `mov r2, 0x34` @0x8eac04/0x8eac4c) + the **ffe235f0 lookup** (@0x8eac2c-0x8eac54) - the painting-at-position accessor.\n'),
    ),
    dict(
        name='wtl_removepaintingatpos_',
        method='DynamicWorld -[removePaintingAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9351180,
        end=9351360,
        disasm='disasm_worldtileloader_removepaintingatpos_.txt',
        base_add=9351196,
        base_literal=9351356,
        boundary='ARM.exidx end 0x008eb0c0 (listing bound); next ObjC IMP 0x008eb0c0 DynamicWorld -[addStandardObjectAtPos:objectType:itemType:saveDict:placedByClient:]',
        selectors={
                 0x8eb0b0: (15216884, 'removeStandardObject:'),
                 0x8eb0b4: (15216716, 'paintingAtPos:'),
        },
        imports={
                 0x8eb0ac: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9351180, 'push {r4, sl, fp, lr}'), (9351208, 'ldr r4, [0x008eb0b0]'), (9351348, 'invalid'), (9351324, 'blx r3'), (9351356, 'ldrsbteq r4, [r7], -0xa0')],
        calls=[(9351284, 'bl loc.imp.objc_msgSend'), (9351324, 'blx r3')],
        branches=[],
        semantics=('removePaintingAtPos: removes the painting at a position. Prologue 0x008eb00c (frame 0x38; base 0x105faf4).\nBody: the **ffe23600 gate** (cell 0x8eb0b0) + the **ffe23558 remove call** (@0x8eb0b4-0x8eb09c) - the painting removal leg.\n'),
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
        'batch': 'DynamicWorld typed accessor family A (E36): placeFireAtPosition:, objectOfType:atPos:, torchAtPos:, removeTorchAtPos:, eggAtPos:, addEggAtPos:saveDict:, removeEggAtPos:, paintingWithID:, paintingAtPos: and removePaintingAtPos:; 10 bodies',
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
                        default=NATIVE / 'accessor_a.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale accessor_a.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
