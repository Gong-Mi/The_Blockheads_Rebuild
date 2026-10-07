#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld placement-actions cluster (E30).

The DynamicWorld placement-actions cluster: the seed sower dispatch, the
workbench placer, the dynamic-world change recorder, the background free-block
factory, the rail/standard/painting adders and the pole-taken recorder:
1 body, 1808 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/PLACEMENT.md for the prose and boundaries.
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
    'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_': 0x008bcf24,
    'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const': 0x00910a74,
    'bl method.void_std::__1::vector_intpair__std::__1::allocator_intpair___.__push_back_slow_path_intpair_const__intpair_const_': 0x0052d84c,
    'bl sym.classForDynamicObjectType_int_': 0x00b597bc,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__stack_chk_fail': 0x001c28b8,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.objectTypeIsInteractionObject_int_': 0x008bcacc,
    'bl sym.plantTypeForSeedItemType_ItemType_': 0x008e4c98,
    'bl sym.treeTypeForSeedItemType_ItemType_': 0x008e4b2c,
    'bl sym.worldIndexAtWorldPos_intpair__World_': 0x00a15838,
}

SPECS = [
    dict(
        name='wtl_sowtreeorplantatpositi',
        method='DynamicWorld -[sowTreeOrPlantAtPosition:itemType:maxHeight:growthRate:]',
        types='v28@0:4{?=ii}8i16s20s24',
        start=9325000,
        end=9325356,
        disasm='disasm_worldtileloader_sowtreeorplantatposition_itemtype_maxhei.txt',
        base_add=9325128,
        base_literal=9325352,
        boundary='ARM.exidx end 0x008e4b2c (listing bound); next ObjC IMP 0x008e4e44 DynamicWorld -[loadTreeAtPosition:type:maxHeight:growthRate:adultTree:adultMaxAge:]',
        selectors={
                 0x8e4b1c: (15216364, 'loadPlantAtPosition:type:maxAgeGene:growthRateGene:adult:'),
                 0x8e4b24: (15216392, 'loadTreeAtPosition:type:maxHeight:growthRate:adultTree:adultMaxAge:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(9325000, 'push {r4, r5, fp, lr}'), (9325056, 'bl sym.treeTypeForSeedItemType_ItemType_'), (9325244, 'bl sym.plantTypeForSeedItemType_ItemType_'), (9325156, 'str r5, [r4, 0x10]'), (9325204, 'bl loc.imp.objc_msgSend'), (9325328, 'bl loc.imp.objc_msgSend'), (9325352, 'rsbseq fp, r7, r4, lsr 1')],
        calls=[(9325056, 'bl sym.treeTypeForSeedItemType_ItemType_'), (9325108, 'bl sym.treeTypeForSeedItemType_ItemType_'), (9325204, 'bl loc.imp.objc_msgSend'), (9325244, 'bl sym.plantTypeForSeedItemType_ItemType_'), (9325328, 'bl loc.imp.objc_msgSend')],
        branches=[(9325072, 'beq', 9325212), (9325208, 'b', 9325332)],
        semantics=('sowTreeOrPlantAtPosition:itemType:maxHeight:growthRate: dispatches a seed to the tree or plant sower. Prologue 0x008e49c8 (frame 0x50; base 0x105faf4).\nDispatch: `treeTypeForSeedItemType(ItemType)` (C call @0x8e4a00): non-zero -> the tree sower call (dispatch slot ffe23414 cell 0x8e4b24, @0x8e4a94) with the packed args (type, x, y, maxHeight/growthRate; the float 0x47c34f80 = 100000.0f stored at frame+0x10 via the movw/movt pair @0x8e4a5c-0x8e4a64); zero -> `plantTypeForSeedItemType(ItemType)` (C call @0x8e4abc) -> the plant sower call via ffe233f8 (cell 0x8e4b1c, @0x8e4b10). Epilogue 0x8e4b14.\n'),
    ),
    dict(
        name='wtl_workbenchplacedatposit',
        method='DynamicWorld -[workbenchPlacedAtPosition:ofType:saveDict:placedByClient:clientName:]',
        types='@32@0:4{?=ii}8i16@20@24@28',
        start=9336328,
        end=9337440,
        disasm='disasm_worldtileloader_workbenchplacedatposition_oftype_savedic.txt',
        base_add=9336344,
        base_literal=9337436,
        boundary='ARM.exidx end 0x008e7a60 (listing bound); next ObjC IMP 0x008e7a60 DynamicWorld -[interactionObjectPlacedAtPosition:withItem:flipped:saveDict:placedByClient:clientName:]',
        selectors={
                 0x8e7a18: (15215804, 'alloc'),
                 0x8e7a24: (15216828, 'initWithWorld:dynamicWorld:atPosition:cache:type:flipped:saveDict:placedByClient:clientName:'),
                 0x8e7a2c: (15216020, 'sendNetDataIfNeededForObject:isCreation:'),
                 0x8e7a30: (15216168, 'objectType'),
                 0x8e7a3c: (15216160, 'uniqueID'),
                 0x8e7a48: (15216512, 'type'),
                 0x8e7a4c: (15216012, 'pos'),
                 0x8e7a50: (15216308, 'addIndex:'),
        },
        imports={
                 0x8e7a28: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8e7a1c: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8e7a20: (17162232, 'OBJC_IVAR_$_DynamicWorld.cache', 7336),
                 0x8e7a38: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
                 0x8e7a40: (17162312, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsByWorldPosIndex', 1620),
                 0x8e7a44: (17162316, 'OBJC_IVAR_$_DynamicWorld.workbenchHasBeenCrafted', 7370),
                 0x8e7a54: (17162204, 'OBJC_IVAR_$_DynamicWorld.portalPositions', 7332),
        },
        classes={
                 0x8e7a10: (15247864, 'OBJC_CLASS_$_Workbench'),
        },
        instructions=[(9336328, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9336440, 'bl loc.imp.objc_msgSend'), (9336736, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9336880, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9337000, 'strb r0, [r1]'), (9337044, 'blx r2'), (9337436, 'ldrsbteq r8, [r7], -0x44')],
        calls=[(9336440, 'bl loc.imp.objc_msgSend'), (9336588, 'bl loc.imp.objc_msgSend'), (9336656, 'bl loc.imp.objc_msgSend'), (9336716, 'bl loc.imp.objc_msgSend'), (9336736, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9336796, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9336824, 'bl loc.imp.objc_msgSend'), (9336880, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9336956, 'blx r4'), (9337044, 'blx r2'), (9337096, 'blx r2'), (9337160, 'bl loc.imp.objc_msgSend_stret'), (9337196, 'bl sym.imp.memset'), (9337284, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9337340, 'blx r3')],
        branches=[(9336608, 'beq', 9337348), (9336968, 'beq', 9337004), (9337052, 'beq', 9337108), (9337104, 'bne', 9337344), (9337144, 'beq', 9337168), (9337164, 'b', 9337200), (9337344, 'b', 9337348)],
        semantics=('workbenchPlacedAtPosition:ofType:saveDict:placedByClient:clientName: creates and registers a workbench. Prologue 0x008e7608 (frame 0xd0; base 0x105faf4).\nCreation: class cell ffe2af04 (0x8e7a10) + alloc/init (ffe231c8) + the packed create (dispatch ffe235c8 cell 0x8e7a24, 8-arg frame @0x8e76d8-0x8e770c).\nRegistration: `[obj objectType]` (ffe23334) -> the ffffe550 map segment (cell 0x8e7a38, 12-byte stride) with `[obj uniqueID]` (ffe2332c) -> `map<u64, DynamicObject*>::operator[](u64&&)` (@0x8e77a0) stores it; `worldIndexAtWorldPos` (@0x8e77dc) -> the ffffe554 map (cell 0x8e7a40) `operator[](u64&&)` (@0x8e7830); the ffe232a0 flag-1 call (cell 0x8e7a2c) closes.\nWorkbench post: the ffe2348c call checked `== 1` (@0x8e78b8-0x8e7900) and the **ffffe558 flag byte set to 1** (`strb r0, [r1]` @0x8e78a8) - the per-world workbench-present flag.\n'),
    ),
    dict(
        name='wtl_dynamicworldchangedatp',
        method='DynamicWorld -[dynamicWorldChangedAtPos:objectType:]',
        types='v20@0:4{?=ii}8i16',
        start=9311120,
        end=9312172,
        disasm='disasm_worldtileloader_dynamicworldchangedatpos_objecttype_.txt',
        base_add=9311136,
        base_literal=9312168,
        boundary='ARM.exidx end 0x008e17ac (listing bound); next ObjC IMP 0x008e17ac DynamicWorld -[exploreLightChangedAtMacroPos:clientLightBlockIndex:]',
        selectors={
                 0x8e17a0: (15216284, 'dynamicWorldChangedAtPos:objectType:'),
        },
        imports={},
        ivars={
                 0x8e179c: (17162348, 'OBJC_IVAR_$_DynamicWorld.dynamicWorldChangedMacroPositions', 6540),
        },
        classes={},
        instructions=[(9311120, 'push {r4, r5, r6, r7, fp, lr}'), (9311168, 'cmp r0, 0x16'), (9311260, 'bl sym.makeIntpair_int__int_'), (9311320, 'add r1, r2, r1'), (9311656, 'b 0x8e15ec'), (9311844, 'movw r0, 0'), (9312168, 'rsbseq lr, r7, ip, asr 14')],
        calls=[(9311216, 'bl sym.imp.__aeabi_idiv'), (9311236, 'bl sym.imp.__aeabi_idiv'), (9311260, 'bl sym.makeIntpair_int__int_'), (9312060, 'bl method.void_std::__1::vector_intpair__std::__1::allocator_intpair___.__push_back_slow_path_intpair_const__intpair_const_'), (9312068, 'bl sym.objectTypeIsInteractionObject_int_'), (9312140, 'bl loc.imp.objc_msgSend')],
        branches=[(9311176, 'beq', 9311192), (9311188, 'bne', 9311196), (9311192, 'b', 9312148), (9311580, 'beq', 9311724), (9311628, 'bne', 9311660), (9311644, 'bne', 9311660), (9311656, 'b', 9311724), (9311660, 'b', 9311664), (9311720, 'b', 9311392), (9311732, 'bne', 9312148), (9311840, 'beq', 9312052), (9311988, 'beq', 9312032), (9312048, 'b', 9312064), (9312080, 'beq', 9312144), (9312144, 'b', 9312148)],
        semantics=("dynamicWorldChangedAtPos:objectType: records a changed macro position for the dynamic-world save. Prologue 0x008e1390 (frame 0x150; base 0x105faf4).\nGate: `objectType == 0x16 or 0x1d -> return` (@0x8e13c0-0x8e13d8).\nRecord: /32 (`movw r0, 0x20` + `__aeabi_idiv` @0x8e13dc-0x8e1404) + `makeIntpair` (@0x8e141c) -> the **ffffe578 member's 12-byte segments** (`movw r1, 0xc; mul` @0x8e1424-0x8e1458, the 65-segment structure): the segment is scanned (dedup state, found flag [sp,0x4f] @0x8e1598-0x8e15a8); a not-found pair proceeds to the append (@0x8e15f8+: the segment push with the memmove-style iterator fixups @0x8e1664-0x8e16e4).\nBoundary: the ffffe578 member is the container E21's saveGameWithWorldData sweeps (its +0x120 slice) and .cxx_destruct destroys (the 0x30c loop).\n"),
    ),
    dict(
        name='wtl_createbackgroundconten',
        method='DynamicWorld -[createBackgroundContentFreeBlockAtPosition:forTile:removeBlockhead:]',
        types='v24@0:4{?=ii}8^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}16@20',
        start=9302980,
        end=9303972,
        disasm='disasm_worldtileloader_createbackgroundcontentfreeblockatpositi.txt',
        base_add=9303088,
        base_literal=9303960,
        boundary='ARM.exidx end 0x008df7a4 (listing bound); next ObjC IMP 0x008df7a4 DynamicWorld -[worldChangedAtPos:sendReliably:]',
        selectors={
                 0x8df778: (15216752, 'removeWindowAtPos:'),
                 0x8df780: (15216272, 'getSaveDict'),
                 0x8df788: (15216388, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
                 0x8df794: (15216748, 'removeDoorAtPos:'),
                 0x8df79c: (15216452, 'itemType'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(9302980, 'push {r4, r5, fp, lr}'), (9303028, 'ldrb r0, [r0, 0xc]'), (9303256, 'movwgt r2, 1'), (9303344, 'bl loc.imp.objc_msgSend'), (9303364, 'bne 0x8df650'), (9303596, 'str r1, [r5, 4]'), (9303968, 'rsbseq r0, r8, r0, ror 12')],
        calls=[(9303124, 'bl loc.imp.objc_msgSend'), (9303204, 'bl loc.imp.objc_msgSend'), (9303236, 'bl loc.imp.objc_msgSend'), (9303344, 'bl loc.imp.objc_msgSend'), (9303436, 'bl loc.imp.objc_msgSend'), (9303516, 'bl loc.imp.objc_msgSend'), (9303624, 'bl loc.imp.objc_msgSend'), (9303716, 'bl loc.imp.objc_msgSend'), (9303796, 'bl loc.imp.objc_msgSend'), (9303904, 'bl loc.imp.objc_msgSend')],
        branches=[(9303036, 'beq', 9303056), (9303052, 'bne', 9303352), (9303144, 'beq', 9303348), (9303348, 'b', 9303920), (9303364, 'bne', 9303632), (9303456, 'beq', 9303628), (9303628, 'b', 9303916), (9303644, 'bne', 9303912), (9303736, 'beq', 9303908), (9303908, 'b', 9303912), (9303912, 'b', 9303916), (9303916, 'b', 9303920)],
        semantics=("createBackgroundContentFreeBlockAtPosition:forTile:removeBlockhead: creates the free block for a background tile's content. Prologue 0x008df3c4 (frame 0xa8; base 0x105faf4).\nTile markers: the tile byte at +0xc inspected: 0x46 ('F') or 0x4b ('K') -> arm 1 (@0x8df3f4-0x8df40c): the ffe23578 call + objectType (ffe23450) + the ffe2339c read; the byte at [r1+6] compared **> 0xaa** sets the flag (r2 = 1 when > 0xaa @0x8df4cc-0x8df4d8) and the 8-arg create ffe23410 runs (flag at +0x18, @0x8df4f4-0x8df530). The 0x45 ('E') marker opens arm 2 (@0x8df53c-0x8df544): the ffe2357c call + the same 0xaa-flag + 8-arg create (@0x8df5e4-0x8df62c). The removeBlockhead argument rides the packed frames.\n"),
    ),
    dict(
        name='wtl_addrailatpos_oftype_ow',
        method='DynamicWorld -[addRailAtPos:ofType:ownedByStation:]',
        types='v24@0:4{?=ii}8i16c20',
        start=9359012,
        end=9359956,
        disasm='disasm_worldtileloader_addrailatpos_oftype_ownedbystation_.txt',
        base_add=9359028,
        base_literal=9359952,
        boundary='ARM.exidx end 0x008ed254 (listing bound); next ObjC IMP 0x008ed254 DynamicWorld -[getRailAtPos:]',
        selectors={
                 0x8ed21c: (15216544, 'needsRemoved'),
                 0x8ed22c: (15215804, 'alloc'),
                 0x8ed234: (15216952, 'initWithWorld:dynamicWorld:atPosition:cache:type:ownedByStation:'),
                 0x8ed238: (15216852, 'railOrStationNameChanged'),
                 0x8ed23c: (15216020, 'sendNetDataIfNeededForObject:isCreation:'),
                 0x8ed240: (15216168, 'objectType'),
                 0x8ed24c: (15216160, 'uniqueID'),
        },
        imports={
                 0x8ed218: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8ed20c: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8ed214: (17162312, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsByWorldPosIndex', 1620),
                 0x8ed230: (17162232, 'OBJC_IVAR_$_DynamicWorld.cache', 7336),
                 0x8ed248: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
        },
        classes={
                 0x8ed224: (15247996, 'OBJC_CLASS_$_Rail'),
        },
        instructions=[(9359012, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9359152, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9359220, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9359396, 'bl loc.imp.objc_msgSend'), (9359524, 'bl loc.imp.objc_msgSend'), (9359664, 'add r1, sp, 0x60'), (9359952, 'rsbseq r2, r7, r8, lsr ip')],
        calls=[(9359152, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9359220, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9359284, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9359328, 'blx r3'), (9359396, 'bl loc.imp.objc_msgSend'), (9359524, 'bl loc.imp.objc_msgSend'), (9359592, 'bl loc.imp.objc_msgSend'), (9359652, 'bl loc.imp.objc_msgSend'), (9359672, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9359704, 'bl loc.imp.objc_msgSend'), (9359760, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9359852, 'blx lr'), (9359872, 'blx r2')],
        branches=[(9359228, 'beq', 9359352), (9359340, 'bne', 9359348), (9359344, 'b', 9359876), (9359348, 'b', 9359352), (9359544, 'beq', 9359876)],
        semantics=('addRailAtPos:ofType:ownedByStation: adds a rail object. Prologue 0x008ecea4 (frame 0xb8; base 0x105faf4).\nExistence: `worldIndexAtWorldPos(intpair, World*)` (@0x8ecf30) -> the **ffffe554 member + 0x1e0 slice** (cell 0x8ed214) `__count_unique(u64)` (@0x8ecf74): an existing rail exits via the ffe234ac gate (@0x8ecfe0).\nCreate: class cell ffe2af88 (0x8ed224) + alloc/init (ffe231c8) + the packed create (dispatch ffe23644 cell 0x8ed234, 5-arg frame with the ownedByStation sxtb @0x8ed07c-0x8ed0a4); registration via `[obj objectType]` -> the ffffe550 map + uniqueID (ffe2332c) `operator[](u64&&)` (@0x8ed130) stores the rail.\n'),
    ),
    dict(
        name='wtl_addstandardobjectatpos',
        method='DynamicWorld -[addStandardObjectAtPos:objectType:itemType:saveDict:placedByClient:]',
        types='v32@0:4{?=ii}8i16i20@24@28',
        start=9351360,
        end=9352296,
        disasm='disasm_worldtileloader_addstandardobjectatpos_objecttype_itemty.txt',
        base_add=9351376,
        base_literal=9352292,
        boundary='ARM.exidx end 0x008eb468 (listing bound); next ObjC IMP 0x008eb468 DynamicWorld -[ladderAtPos:]',
        selectors={
                 0x8eb438: (15216544, 'needsRemoved'),
                 0x8eb440: (15215804, 'alloc'),
                 0x8eb44c: (15216916, 'initWithWorld:dynamicWorld:atPosition:cache:type:saveDict:placedByClient:'),
                 0x8eb450: (15216020, 'sendNetDataIfNeededForObject:isCreation:'),
                 0x8eb454: (15216168, 'objectType'),
                 0x8eb460: (15216160, 'uniqueID'),
        },
        imports={
                 0x8eb434: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8eb428: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8eb430: (17162312, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsByWorldPosIndex', 1620),
                 0x8eb448: (17162232, 'OBJC_IVAR_$_DynamicWorld.cache', 7336),
                 0x8eb45c: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
        },
        classes={},
        instructions=[(9351360, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9351516, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9351592, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9351748, 'bl sym.classForDynamicObjectType_int_'), (9351908, 'bl loc.imp.objc_msgSend'), (9351984, 'ldr r2, [0x008eb45c]'), (9352292, 'rsbseq r4, r7, ip, lsl sl')],
        calls=[(9351516, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9351592, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9351664, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9351708, 'blx r3'), (9351748, 'bl sym.classForDynamicObjectType_int_'), (9351776, 'bl loc.imp.objc_msgSend'), (9351908, 'bl loc.imp.objc_msgSend'), (9351976, 'bl loc.imp.objc_msgSend'), (9352036, 'bl loc.imp.objc_msgSend'), (9352056, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9352088, 'bl loc.imp.objc_msgSend'), (9352144, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9352220, 'blx r4')],
        branches=[(9351600, 'beq', 9351732), (9351720, 'bne', 9351728), (9351724, 'b', 9352224), (9351728, 'b', 9351732), (9351928, 'beq', 9352224)],
        semantics=("addStandardObjectAtPos:objectType:itemType:saveDict:placedByClient: adds a standard dynamic object. Prologue 0x008eb0c0 (frame 0xc0; base 0x105faf4).\nExistence: worldIndexAtWorldPos (@0x8eb15c) -> the ffffe554 member's 12-byte segment (cell 0x8eb430) `__count_unique(u64)` (@0x8eb1a8): an existing object exits via ffe234ac (@0x8eb21c).\nCreate: **`classForDynamicObjectType(int)`** (C call @0x8eb244) + alloc/init (ffe231c8) + the packed create (dispatch ffe23620 cell 0x8eb44c, 6-arg frame @0x8eb2bc-0x8eb2e4); registration via objectType (ffe23334) -> the ffffe550 map + uniqueID (@0x8eb330+).\n"),
    ),
    dict(
        name='wtl_addpaintingatpos_oftyp',
        method='DynamicWorld -[addPaintingAtPos:ofType:saveDict:placedByClient:clientName:]',
        types='v32@0:4{?=ii}8i16@20@24@28',
        start=9350248,
        end=9351180,
        disasm='disasm_worldtileloader_addpaintingatpos_oftype_savedict_placedb.txt',
        base_add=9350264,
        base_literal=9351176,
        boundary='ARM.exidx end 0x008eb00c (listing bound); next ObjC IMP 0x008eb00c DynamicWorld -[removePaintingAtPos:]',
        selectors={
                 0x8eafd8: (15216544, 'needsRemoved'),
                 0x8eafe8: (15215804, 'alloc'),
                 0x8eaff0: (15216912, 'initWithWorld:dynamicWorld:atPosition:cache:type:saveDict:placedByClient:clientName:'),
                 0x8eaff4: (15216020, 'sendNetDataIfNeededForObject:isCreation:'),
                 0x8eaff8: (15216168, 'objectType'),
                 0x8eb004: (15216160, 'uniqueID'),
        },
        imports={
                 0x8eafd4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8eafc8: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8eafd0: (17162312, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsByWorldPosIndex', 1620),
                 0x8eafec: (17162232, 'OBJC_IVAR_$_DynamicWorld.cache', 7336),
                 0x8eb000: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
        },
        classes={
                 0x8eafe0: (15247992, 'OBJC_CLASS_$_Painting'),
        },
        instructions=[(9350248, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9350404, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9350472, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9350648, 'bl loc.imp.objc_msgSend'), (9350788, 'bl loc.imp.objc_msgSend'), (9350856, 'bl loc.imp.objc_msgSend'), (9351176, 'rsbseq r4, r7, r4, ror lr')],
        calls=[(9350404, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9350472, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9350536, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9350580, 'blx r3'), (9350648, 'bl loc.imp.objc_msgSend'), (9350788, 'bl loc.imp.objc_msgSend'), (9350856, 'bl loc.imp.objc_msgSend'), (9350916, 'bl loc.imp.objc_msgSend'), (9350936, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9350968, 'bl loc.imp.objc_msgSend'), (9351024, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9351100, 'blx r4')],
        branches=[(9350480, 'beq', 9350604), (9350592, 'bne', 9350600), (9350596, 'b', 9351104), (9350600, 'b', 9350604), (9350808, 'beq', 9351104)],
        semantics=('addPaintingAtPos:ofType:saveDict:placedByClient:clientName: adds a painting. Prologue 0x008eac68 (frame 0xc8; base 0x105faf4). Same shape as addStandardObjectAtPos with the painting cells: the existence check uses the **ffffe554 + 0x270 slice** (cell 0x8eafd0, `__count_unique` @0x8ead48, ffe234ac gate @0x8eadb4); the creation uses class cell ffe2af84 (0x8eafe0) + the packed create (dispatch ffe2361c cell 0x8eaff0, 7-arg frame @0x8eae58-0x8eae84); registration through the ffffe550 map (@0x8eaec8+).\n'),
    ),
    dict(
        name='wtl_poleitemtaken_',
        method='DynamicWorld -[poleItemTaken:]',
        types='v12@0:4i8',
        start=9451100,
        end=9452008,
        disasm='disasm_worldtileloader_poleitemtaken_.txt',
        base_add=9451116,
        base_literal=9452004,
        boundary='ARM.exidx end 0x009039e8 (listing bound); next ObjC IMP 0x009039e8 DynamicWorld -[checkAndRestorePoleItems:]',
        selectors={
                 0x9039ac: (15215980, 'customRules'),
                 0x9039bc: (15215800, 'init'),
                 0x9039c0: (15215804, 'alloc'),
                 0x9039c8: (15215944, 'setObject:forKey:'),
                 0x9039d0: (15215816, 'stringWithFormat:'),
                 0x9039d8: (15217336, 'numberWithDouble:'),
                 0x9039dc: (15216488, 'worldTime'),
        },
        imports={
                 0x9039a8: (17151968, '__stack_chk_guard'),
                 0x9039b8: (17151904, 'objc_msgSend'),
                 0x9039cc: (16334200, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x9039a4: (17162252, 'OBJC_IVAR_$_DynamicWorld.client', 20),
                 0x9039b0: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x9039b4: (17162328, 'OBJC_IVAR_$_DynamicWorld.poleItemTakenTimes', 9516),
        },
        classes={
                 0x9039c4: (15247784, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x9039d4: (15247792, 'OBJC_CLASS_$_NSString'),
                 0x9039e0: (15247832, 'OBJC_CLASS_$_NSNumber'),
        },
        instructions=[(9451100, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9451184, 'bne 0x90397c'), (9451432, 'beq 0x90397c'), (9451580, 'str r0, [r1]'), (9451620, 'ldr r4, [0x009039d0]'), (9452004, 'rsbseq ip, r5, r0, lsl 9')],
        calls=[(9451260, 'bl loc.imp.objc_msgSend_stret'), (9451296, 'bl sym.imp.memset'), (9451384, 'bl loc.imp.objc_msgSend_stret'), (9451420, 'bl sym.imp.memset'), (9451544, 'blx r2'), (9451560, 'blx r2'), (9451788, 'blx r8'), (9451820, 'blx ip'), (9451860, 'blx lr'), (9451896, 'blx ip'), (9451936, 'bl sym.imp.__stack_chk_fail')],
        branches=[(9451184, 'bne', 9451900), (9451244, 'beq', 9451268), (9451264, 'b', 9451300), (9451308, 'beq', 9451436), (9451368, 'beq', 9451392), (9451388, 'b', 9451424), (9451432, 'beq', 9451900), (9451472, 'bne', 9451584), (9451924, 'bne', 9451936)],
        semantics=("poleItemTaken: records that an ownership-pole item was taken. Prologue 0x0090365c (frame 0xf8; base 0x105faf4).\nGates: self.client (ffffe518, cell 0x9039a4) == 0 -> exit 0x90397c (@0x9036b0); two 0x40-byte stret reads with byte[0] and byte[0x4c] == 1 (@0x903724-0x9037a8: the same world-struct checks as E23's pole restorer).\nRegistry: the ffffe564 dict (cell 0x9039b4) is lazily created (`[[NSMutableDictionary alloc] init]`, cells ffe231c4/ffe231c8/ffe2aeb4 @0x9037d4-0x90383c) and updated via `setObject:forKey:` (ffe23254 cell 0x9039c8) with the `stringWithFormat:` key built from 0xfff34284 (cell 0x9039cc - the SAME format string as E23's pole restorer) - the taken-pole record.\n"),
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
        'batch': 'DynamicWorld placement-actions cluster (E30): sowTreeOrPlantAtPosition:itemType:maxHeight:growthRate:, workbenchPlacedAtPosition:..., dynamicWorldChangedAtPos:objectType:, createBackgroundContentFreeBlockAtPosition:..., addRailAtPos:..., addStandardObjectAtPos:..., addPaintingAtPos:... and poleItemTaken:; 8 bodies',
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
                        default=NATIVE / 'placement.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale placement.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
