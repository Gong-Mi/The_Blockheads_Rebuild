#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld world-mutation & client-request cluster (E26).

The DynamicWorld world-mutation and client-request cluster: the
worldContentsChanged queue producer, the interaction-object placement, the
standard-object/door removals with lighting recalculation, the client free-block
materialization, the client-departure removal sweep and the train-car placer:
1 body, 2673 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/WORLD_MUTATE.md for the prose and boundaries.
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
    'bl 0x8b1db0': 0x008b1db0,
    'bl 0x8e7ec4': 0x008e7ec4,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__': 0x005dc5d8,
    'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_': 0x008bcf24,
    'bl method.std::__1::map_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.operator___unsigned_long_long_': 0x008bd2e4,
    'bl method.std::__1::pair_std::__1::__tree_iterator_DynamicObject__std::__1::__tree_node_DynamicObject__void___int___bool__std::__1::__tree_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject___.__insert_unique_DynamicObject__DynamicObject_': 0x0090c82c,
    'bl method.void_std::__1::vector_intpair__std::__1::allocator_intpair___.__push_back_slow_path_intpair_const__intpair_const_': 0x0052d84c,
    'bl sym.classForInteractionObjectType_unsigned_short_': 0x005f3f50,
    'bl sym.imp.NSLog': 0x001c2a5c,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.objectTypeCanBeLoadedOnlyWhenClientOwnerOnline_int_': 0x008ba904,
    'bl sym.objectTypeIsInteractionObject_int_': 0x008bcacc,
    'bl sym.recalculateDrawBlockLightingForTile_int__int__MacroTile__World_': 0x00a18f68,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileIsSolid_Tile_': 0x00a1179c,
    'bl sym.worldIndexAtWorldPos_intpair__World_': 0x00a15838,
}

SPECS = [
    dict(
        name='wtl_worldcontentschangedat',
        method='DynamicWorld -[worldContentsChangedAtPos:]',
        types='v16@0:4{?=ii}8',
        start=9307244,
        end=9308880,
        disasm='disasm_worldtileloader_worldcontentschangedatpos_.txt',
        base_add=9307260,
        base_literal=9308876,
        boundary='ARM.exidx end 0x008e0ad0 (listing bound); next ObjC IMP 0x008e0ad0 DynamicWorld -[waterChangedAtPos:fullBlock:]',
        selectors={},
        imports={},
        ivars={
                 0x8e0ac4: (17162424, 'OBJC_IVAR_$_DynamicWorld.worldContentsChangedPositions', 6516),
                 0x8e0ac8: (17162340, 'OBJC_IVAR_$_DynamicWorld.worldChangedMacroPositions', 7320),
        },
        classes={},
        instructions=[(9307244, 'push {r4, r5, r6, sl, fp, lr}'), (9307392, 'add r0, sp, 0x68'), (9307708, 'ldrsb r0, [sp, 0x7f]'), (9308036, 'movw r0, 0x20'), (9308100, 'bl sym.makeIntpair_int__int_'), (9308532, 'ldrsb r0, [sp, 0x4f]'), (9308876, 'rsbseq pc, r7, r0, ror r6')],
        calls=[(9308028, 'bl method.void_std::__1::vector_intpair__std::__1::allocator_intpair___.__push_back_slow_path_intpair_const__intpair_const_'), (9308056, 'bl sym.imp.__aeabi_idiv'), (9308076, 'bl sym.imp.__aeabi_idiv'), (9308100, 'bl sym.makeIntpair_int__int_'), (9308852, 'bl method.void_std::__1::vector_intpair__std::__1::allocator_intpair___.__push_back_slow_path_intpair_const__intpair_const_')],
        branches=[(9307564, 'beq', 9307708), (9307612, 'bne', 9307644), (9307628, 'bne', 9307644), (9307640, 'b', 9307708), (9307644, 'b', 9307648), (9307704, 'b', 9307392), (9307716, 'bne', 9308036), (9307808, 'beq', 9308020), (9307956, 'beq', 9308000), (9308016, 'b', 9308032), (9308032, 'b', 9308036), (9308388, 'beq', 9308532), (9308436, 'bne', 9308468), (9308452, 'bne', 9308468), (9308464, 'b', 9308532), (9308468, 'b', 9308472), (9308528, 'b', 9308216), (9308540, 'bne', 9308860), (9308632, 'beq', 9308844), (9308780, 'beq', 9308824), (9308840, 'b', 9308856), (9308856, 'b', 9308860)],
        semantics=("worldContentsChangedAtPos: records a world-contents change and routes it to the dirty macro queue. Prologue 0x008e046c (frame 0x250; base 0x105faf4). Argument: pos pair r2/r3.\nExact-position dedup: the vector inside ivar ffffe5c4 (cell 0x8e0ac4, @0x8e0484) is scanned (state at sp+0x78, found flag [sp,0x7f], loop 0x8e0500-0x8e0638); a new pair is appended via the libc++ slow path (@0x8e077c).\nMacro pair + queue: the position is divided by 32 (`movw r0, 0x20` + `__aeabi_idiv` @0x8e0784-0x8e07ac) and packed with `makeIntpair` (@0x8e07c4); the macro pair is deduped (state at sp+0x48, flag [sp,0x4f]) and pushed into the worldChangedMacroPositions vector inside ivar ffffe570 (cell 0x8e0ac8, @0x8e07c8-0x8e0a98). Epilogue after 0x8e0abc.\nBoundary: the queue family is the E22/E23 consumer set; this producer's own position vector is ffffe5c4.\n"),
    ),
    dict(
        name='wtl_interactionobjectplace',
        method='DynamicWorld -[interactionObjectPlacedAtPosition:withItem:flipped:saveDict:placedByClient:clientName:]',
        types='@36@0:4{?=ii}8@16c20@24@28@32',
        start=9337440,
        end=9338564,
        disasm='disasm_worldtileloader_interactionobjectplacedatposition_withit.txt',
        base_add=9337456,
        base_literal=9338560,
        boundary='ARM.exidx end 0x008e7ec4 (listing bound); next ObjC IMP 0x008e80e4 DynamicWorld -[placeFireAtPosition:]',
        selectors={
                 0x8e7e78: (15216452, 'itemType'),
                 0x8e7e7c: (15215804, 'alloc'),
                 0x8e7e8c: (15216832, 'initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:'),
                 0x8e7e90: (15216020, 'sendNetDataIfNeededForObject:isCreation:'),
                 0x8e7e94: (15216168, 'objectType'),
                 0x8e7ea0: (15216160, 'uniqueID'),
                 0x8e7ea8: (15216852, 'railOrStationNameChanged'),
                 0x8e7eb0: (15216836, 'landOwnerID'),
                 0x8e7eb4: (15216840, 'widthRadius'),
                 0x8e7eb8: (15216844, 'heightRadius'),
                 0x8e7ebc: (15216848, 'ownershipSignWasPlacedOrChangedAtPos:withLandOwner:widthRadius:heightRadius:wasRemoved:'),
        },
        imports={
                 0x8e7e74: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8e7e84: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8e7e88: (17162232, 'OBJC_IVAR_$_DynamicWorld.cache', 7336),
                 0x8e7e9c: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
                 0x8e7ea4: (17162312, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsByWorldPosIndex', 1620),
        },
        classes={},
        instructions=[(9337440, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9337544, 'blx r8'), (9337572, 'bl sym.classForInteractionObjectType_unsigned_short_'), (9337796, 'bl loc.imp.objc_msgSend'), (9337944, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9338088, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9338384, 'ldrh r0, [fp, -0x46]'), (9338560, 'rsbseq r8, r7, ip, ror r0')],
        calls=[(9337544, 'blx r8'), (9337548, 'bl 0x8e7ec4'), (9337572, 'bl sym.classForInteractionObjectType_unsigned_short_'), (9337636, 'bl loc.imp.objc_msgSend'), (9337796, 'bl loc.imp.objc_msgSend'), (9337864, 'bl loc.imp.objc_msgSend'), (9337924, 'bl loc.imp.objc_msgSend'), (9337944, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9338004, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9338032, 'bl loc.imp.objc_msgSend'), (9338088, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9338164, 'blx r4'), (9338252, 'bl loc.imp.objc_msgSend'), (9338284, 'bl loc.imp.objc_msgSend'), (9338316, 'bl loc.imp.objc_msgSend'), (9338376, 'bl loc.imp.objc_msgSend'), (9338436, 'blx r2')],
        branches=[(9337564, 'beq', 9338464), (9337592, 'beq', 9338460), (9337816, 'beq', 9338448), (9338176, 'bne', 9338384), (9338380, 'b', 9338444), (9338392, 'bne', 9338440), (9338440, 'b', 9338444), (9338444, 'b', 9338448), (9338456, 'b', 9338472), (9338460, 'b', 9338464)],
        semantics=('interactionObjectPlacedAtPosition:withItem:flipped:saveDict:placedByClient:clientName: creates and registers an interaction object. Prologue 0x008e7a60 (frame 0xd0; base 0x105faf4). Arguments: pos pair, item, flipped byte [fp,-0x35], saveDict, placedByClient, clientName [fp,0x18].\nType resolution: the local helper `bl 0x8e7ec4` yields the interaction type (unsigned short, [fp,-0x46]); 0 exits; `classForInteractionObjectType(unsigned short)` (C call @0x8e7ae4) resolves the class; a NULL class exits.\nCreation: the class alloc/init pair (cells ffe231c8/ffe2af0c region @0x8e7afc-0x8e7b28) with the packed 6-arg init (the world, pos, flipped, saveDict, placedByClient, clientName at the send frame sp+0x0..0x1c; dispatch slot ffe235cc cell 0x8e7e8c, @0x8e7b8c-0x8e7bc4).\nRegistration: `[obj objectType]` (ffe23334) -> the ffffe550 map segment (cell 0x8e7e9c, 12-byte stride) with `[obj uniqueID]` (ffe2332c) -> `std::__1::map<unsigned long long, DynamicObject*>::operator[](u64&&)` (@0x8e7c58) stores it; then `worldIndexAtWorldPos(intpair, World*)` (@0x8e7c94) -> the ffffe554 map (cell 0x8e7ea4) `operator[](u64&&)` (@0x8e7ce8); the ffe232a0 flag-1 call (cell 0x8e7e90) closes (@0x8e7cec-0x8e7d34).\nType specials: type == 8 -> the ffe235d0/ffe235d4/ffe235d8/ffe235dc chain (@0x8e7d38-0x8e7e08); type == 6 -> the ffe235e0 call (cell 0x8e7ea8, @0x8e7e10-0x8e7e44). Epilogue 0x8e7e6c.\n'),
    ),
    dict(
        name='wtl_removestandardobject_',
        method='DynamicWorld -[removeStandardObject:]',
        types='v12@0:4@8',
        start=9341180,
        end=9342952,
        disasm='disasm_worldtileloader_removestandardobject_.txt',
        base_add=9341196,
        base_literal=9342948,
        boundary='ARM.exidx end 0x008e8fe8 (listing bound); next ObjC IMP 0x008e8fe8 DynamicWorld -[removeTorchAtPos:]',
        selectors={
                 0x8e8fac: (15216168, 'objectType'),
                 0x8e8fb0: (15216872, 'occupiesNormalContents'),
                 0x8e8fb4: (15216528, 'setNeedsRemoved:'),
                 0x8e8fb8: (15216876, 'occupiesForegroundContents'),
                 0x8e8fbc: (15216880, 'occupiesBackgroundContents'),
                 0x8e8fc0: (15216012, 'pos'),
                 0x8e8fc8: (15216860, 'worldChangedAtPos:sendReliably:'),
                 0x8e8fd8: (15216748, 'removeDoorAtPos:'),
        },
        imports={
                 0x8e8fa8: (17151904, 'objc_msgSend'),
                 0x8e8fe0: (16333896, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x8e8fc4: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
        },
        classes={},
        instructions=[(9341180, 'push {r4, sl, fp, lr}'), (9341240, 'blx ip'), (9341276, 'bl sym.objectTypeIsInteractionObject_int_'), (9341836, 'strb ip, [r0, 3]'), (9342288, 'strb ip, [r0, 0xb]'), (9342424, 'ldr r0, [0x008e8fa8]'), (9342948, 'rsbseq r7, r7, r0, ror 3')],
        calls=[(9341240, 'blx ip'), (9341276, 'bl sym.objectTypeIsInteractionObject_int_'), (9341308, 'bl sym.imp.NSLog'), (9341388, 'bl loc.imp.objc_msgSend_stret'), (9341424, 'bl sym.imp.memset'), (9341456, 'bl loc.imp.objc_msgSend'), (9341540, 'blx ip'), (9341560, 'blx r2'), (9341628, 'bl loc.imp.objc_msgSend_stret'), (9341664, 'bl sym.imp.memset'), (9341728, 'bl loc.imp.objc_msgSend_stret'), (9341764, 'bl sym.imp.memset'), (9341804, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9341884, 'bl loc.imp.objc_msgSend_stret'), (9341920, 'bl sym.imp.memset'), (9341964, 'bl loc.imp.objc_msgSend'), (9342012, 'blx r2'), (9342080, 'bl loc.imp.objc_msgSend_stret'), (9342116, 'bl sym.imp.memset'), (9342180, 'bl loc.imp.objc_msgSend_stret'), (9342216, 'bl sym.imp.memset'), (9342256, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9342336, 'bl loc.imp.objc_msgSend_stret'), (9342372, 'bl sym.imp.memset'), (9342416, 'bl loc.imp.objc_msgSend'), (9342464, 'blx r2'), (9342532, 'bl loc.imp.objc_msgSend_stret'), (9342568, 'bl sym.imp.memset'), (9342632, 'bl loc.imp.objc_msgSend_stret'), (9342668, 'bl sym.imp.memset'), (9342708, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9342788, 'bl loc.imp.objc_msgSend_stret'), (9342824, 'bl sym.imp.memset'), (9342868, 'bl loc.imp.objc_msgSend')],
        branches=[(9341256, 'beq', 9341292), (9341268, 'beq', 9341292), (9341288, 'beq', 9341316), (9341312, 'b', 9342880), (9341324, 'bne', 9341468), (9341372, 'beq', 9341396), (9341392, 'b', 9341428), (9341464, 'b', 9342880), (9341572, 'beq', 9341972), (9341612, 'beq', 9341636), (9341632, 'b', 9341668), (9341712, 'beq', 9341736), (9341732, 'b', 9341768), (9341868, 'beq', 9341892), (9341888, 'b', 9341924), (9341968, 'b', 9342880), (9342024, 'beq', 9342424), (9342064, 'beq', 9342088), (9342084, 'b', 9342120), (9342164, 'beq', 9342188), (9342184, 'b', 9342220), (9342320, 'beq', 9342344), (9342340, 'b', 9342376), (9342420, 'b', 9342876), (9342476, 'beq', 9342872), (9342516, 'beq', 9342540), (9342536, 'b', 9342572), (9342616, 'beq', 9342640), (9342636, 'b', 9342672), (9342772, 'beq', 9342796), (9342792, 'b', 9342828), (9342872, 'b', 9342876), (9342876, 'b', 9342880)],
        semantics=('removeStandardObject: removes a standard world object with tile bookkeeping. Prologue 0x008e88fc (frame 0x130; base 0x105faf4).\nRefuse path: `[obj objectType]` (ffe23334) == 0xe or 0x18, or `objectTypeIsInteractionObject(int)` (C call @0x8e895c) -> NSLog (string 0xfff34154) and exit (@0x8e896c-0x8e8980).\nType 0x14 path: pos getter (ffe23298) + the ffe23578 call (cell 0x8e8fd8, @0x8e89f4) then exit.\nMain path: the ffe235f4 gate with flag 1 (@0x8e8a2c-0x8e8a84); on pass `tileAtWorldPositionLoaded(x, y, world)` (world cell 0x8e8fc4) clears the tile type byte (`strb [tile+3] = 0` @0x8e8b8c) and the ffe235e8 flag-1 call runs (cells 0x8e8fc8/0x8e8fd4, @0x8e8be4-0x8e8c0c). The ffe235f8 gate (@0x8e8c14-0x8e8c48) opens a second tile pass clearing the byte at [tile+0xb] (@0x8e8d50) with the same ffe235e8 notify (@0x8e8da8-0x8e8dd0); the ffe235fc gate (@0x8e8dd8-0x8e8e0c) opens further pos reads. Epilogue 0x8e8f9c.\n'),
    ),
    dict(
        name='wtl_removedooratpos_',
        method='DynamicWorld -[removeDoorAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9362488,
        end=9363952,
        disasm='disasm_worldtileloader_removedooratpos_.txt',
        base_add=9362504,
        base_literal=9363948,
        boundary='ARM.exidx end 0x008ee1f0 (listing bound); next ObjC IMP 0x008ee1f0 DynamicWorld -[placeBoatInWaterAtPos:saveDict:placedByClient:]',
        selectors={
                 0x8ee1c0: (15216868, 'objectOfType:atPos:'),
                 0x8ee1d0: (15216452, 'itemType'),
                 0x8ee1d8: (15216036, 'macroTiles'),
                 0x8ee1dc: (15216528, 'setNeedsRemoved:'),
                 0x8ee1e4: (15216860, 'worldChangedAtPos:sendReliably:'),
                 0x8ee1e8: (15216976, 'removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:'),
        },
        imports={
                 0x8ee1cc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8ee1d4: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
        },
        classes={},
        instructions=[(9362488, 'push {r4, r5, fp, lr}'), (9362560, 'ldr r1, [0x008ee1c0]'), (9362684, 'cmp r0, 0x34'), (9362800, 'strb lr, [r0, 0xc]'), (9363568, 'cmp r0, 0x130'), (9363712, 'bl sym.recalculateDrawBlockLightingForTile_int__int__MacroTile__World_'), (9363948, 'rsbseq r1, r7, r4, lsr 29')],
        calls=[(9362608, 'bl loc.imp.objc_msgSend'), (9362672, 'blx r2'), (9362756, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9362856, 'blx r3'), (9362900, 'bl sym.recalculateDrawBlockLightingForTile_int__int__MacroTile__World_'), (9362928, 'bl sym.makeIntpair_int__int_'), (9363004, 'bl sym.makeIntpair_int__int_'), (9363048, 'bl loc.imp.objc_msgSend'), (9363112, 'blx r2'), (9363196, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9363296, 'blx r3'), (9363340, 'bl sym.recalculateDrawBlockLightingForTile_int__int__MacroTile__World_'), (9363368, 'bl sym.makeIntpair_int__int_'), (9363476, 'blx r3'), (9363508, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9363556, 'blx r3'), (9363672, 'bl loc.imp.objc_msgSend'), (9363712, 'bl sym.recalculateDrawBlockLightingForTile_int__int__MacroTile__World_'), (9363768, 'bl loc.imp.objc_msgSend'), (9363884, 'blx lr')],
        branches=[(9362628, 'beq', 9362952), (9362688, 'beq', 9362704), (9362700, 'bne', 9362948), (9362948, 'b', 9363408), (9363068, 'beq', 9363404), (9363128, 'beq', 9363144), (9363140, 'bne', 9363392), (9363388, 'b', 9363400), (9363400, 'b', 9363404), (9363404, 'b', 9363408), (9363420, 'beq', 9363892), (9363572, 'bne', 9363592), (9363588, 'b', 9363604), (9363780, 'beq', 9363888), (9363888, 'b', 9363892)],
        semantics=("removeDoorAtPos: removes a door at a position with lighting recalculation. Prologue 0x008edc38 (frame 0xe0; base 0x105faf4). Argument: pos pair.\nProbe: the world tile resolver ffe235f0 (cell 0x8ee1c0) is called with the value 0x14 (@0x8edc80-0x8edcb0) to resolve the door-fragment type at the position.\nDoor arms: `[obj objectType]` (ffe23450) == 0x34 or 0xa4 (door halves) -> `tileAtWorldPositionLoaded(x, y+1, world)` clears the byte at [tile+0xc] (`strb [tile+0xc] = 0` @0x8edd70) and calls `recalculateDrawBlockLightingForTile(int, int, MacroTile*, World*)` (C call @0x8eddd4); the second arm probes (x, y-1) with the same clears and call (@0x8ede08-0x8edf8c); the result pair is rebuilt with `makeIntpair`.\nRetry/special: the ffe2349c flag call (@0x8edfd0-0x8ee028) then a third tile read: when the tile's object type resolves to 0x130 the byte at [tile+3] is cleared, otherwise [tile+0xc] (@0x8ee070-0x8ee090); `recalculateDrawBlockLightingForTile` runs again (@0x8ee100) and the ffe235e8 flag-1 notify (cell 0x8ee1e4); when the changed flag [fp,-0x19] is set the ffe2365c call (cell 0x8ee1e8) closes. Epilogue.\n"),
    ),
    dict(
        name='wtl_createclientfreeblocks',
        method='DynamicWorld -[createClientFreeblocksWithData:]',
        types='v12@0:4@8',
        start=9243792,
        end=9245096,
        disasm='disasm_worldtileloader_createclientfreeblockswithdata_.txt',
        base_add=9243808,
        base_literal=9245092,
        boundary='ARM.exidx end 0x008d11a8 (listing bound); next ObjC IMP 0x008d11a8 DynamicWorld -[preDrawUpdate:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        selectors={
                 0x8d1168: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8d116c: (15215988, 'gzipInflate'),
                 0x8d1170: (15216676, 'initWithWorld:dynamicWorld:cache:netData:avoidFreeblockDupeObjectIds:'),
                 0x8d1180: (15215804, 'alloc'),
                 0x8d1188: (15216012, 'pos'),
                 0x8d1194: (15216160, 'uniqueID'),
                 0x8d1198: (15216020, 'sendNetDataIfNeededForObject:isCreation:'),
        },
        imports={
                 0x8d1164: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8d1174: (17162428, 'OBJC_IVAR_$_DynamicWorld.avoidFreeblockDupeObjectIds', 9504),
                 0x8d1178: (17162232, 'OBJC_IVAR_$_DynamicWorld.cache', 7336),
                 0x8d117c: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8d118c: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8d11a0: (17162364, 'OBJC_IVAR_$_DynamicWorld.freeBlocksByPosition', 2400),
        },
        classes={
                 0x8d1184: (15247872, 'OBJC_CLASS_$_FreeBlock'),
        },
        instructions=[(9243792, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9243856, 'bl 0x8b1db0'), (9244236, 'blx r6'), (9244448, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9244636, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9245092, 'rsbseq lr, r8, ip, asr 28')],
        calls=[(9243852, 'blx ip'), (9243856, 'bl 0x8b1db0'), (9243940, 'bl sym.imp.memset'), (9243988, 'blx lr'), (9244088, 'bl sym.imp.objc_enumerationMutation'), (9244236, 'blx r6'), (9244340, 'blx lr'), (9244428, 'bl loc.imp.objc_msgSend'), (9244448, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9244512, 'bl loc.imp.objc_msgSend_stret'), (9244548, 'bl sym.imp.memset'), (9244636, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9244696, 'bl method.std::__1::map_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.operator___unsigned_long_long_'), (9244752, 'bl method.std::__1::pair_std::__1::__tree_iterator_DynamicObject__std::__1::__tree_node_DynamicObject__void___int___bool__std::__1::__tree_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject___.__insert_unique_DynamicObject__DynamicObject_'), (9244888, 'blx lr'), (9244992, 'blx ip')],
        branches=[(9244000, 'beq', 9245016), (9244080, 'beq', 9244092), (9244360, 'beq', 9244892), (9244496, 'beq', 9244520), (9244516, 'b', 9244552), (9244892, 'b', 9244896), (9244920, 'blo', 9244044), (9245012, 'bne', 9244044), (9245016, 'b', 9245020)],
        semantics=("createClientFreeblocksWithData: materializes the free blocks a client saw and registers them. Prologue 0x008d0c90 (frame 0x198; base 0x105faf4). Argument: the client data blob.\nParse: the shared parser `bl 0x8b1db0` (@0x8d0cd0) turns the blob into the object list; enumerate (@0x8d0cd4-0x8d0d60).\nPer entry: the ffe23530 call (cell 0x8d1170) + the ffffe5c8 list (cell 0x8d1174) + the ffffe504 slice (cell 0x8d1178) + the world (ffffe4e4) feed the alloc/init pair (cells ffe231c8/ffe2af0c @0x8d0df0-0x8d0e4c) and the creation dispatch (ffe23660 family, packed 5-arg frame @0x8d0e7c-0x8d0eb4).\nRegistration: the ffffe54c +0xa8 slice (cells 0x8d118c/0x8d1190) with `[obj uniqueID]` (ffe2332c) -> `map<u64, DynamicObject*>::operator[](u64&&)` (@0x8d0f20) stores the object; `worldIndexAtWorldPos` (pos via ffe23298, @0x8d0fdc) -> the ffffe588 map (cell 0x8d11a0) `operator[](u64&&)`; the ffe232a0 flag-1 call (cell 0x8d1198) closes. Epilogue 0x8d1158.\nBoundary: this is the same registration family as E24's master FreeBlock factory (uniqueID map + worldIndex position map).\n"),
    ),
    dict(
        name='wtl_removedynamicobjectsbe',
        method='DynamicWorld -[removeDynamicObjectsBelongingToClient:]',
        types='v12@0:4@8',
        start=9457176,
        end=9458440,
        disasm='disasm_worldtileloader_removedynamicobjectsbelongingtoclient_.txt',
        base_add=9457192,
        base_literal=9458436,
        boundary='ARM.exidx end 0x00905308 (listing bound); next ObjC IMP 0x00905308 DynamicWorld -[clientBlockheadWithID:fromClient:requestsDyamicObjectRemovalWithID:]',
        selectors={
                 0x9052f8: (15216280, 'isEqualToString:'),
                 0x9052fc: (15216276, 'clientIDForSavingSeperatelyAndOnlyLoadingWhilePlayerOnline'),
                 0x905300: (15216528, 'setNeedsRemoved:'),
        },
        imports={
                 0x9052f4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x9052e4: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x9052ec: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
        },
        classes={},
        instructions=[(9457176, 'push {r4, r5, fp, lr}'), (9457236, 'bl sym.objectTypeCanBeLoadedOnlyWhenClientOwnerOnline_int_'), (9457544, 'beq 0x905094'), (9457696, 'movw r0, 1'), (9458104, 'beq 0x9052c4'), (9458436, 'rsbseq sl, r5, r4, asr 25')],
        calls=[(9457236, 'bl sym.objectTypeCanBeLoadedOnlyWhenClientOwnerOnline_int_'), (9457660, 'blx ip'), (9457680, 'blx r3'), (9457756, 'blx ip'), (9457796, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9458220, 'blx ip'), (9458240, 'blx r3'), (9458316, 'blx ip'), (9458356, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__')],
        branches=[(9457228, 'bge', 9458396), (9457248, 'beq', 9458376), (9457544, 'beq', 9457812), (9457692, 'beq', 9457760), (9457760, 'b', 9457764), (9457808, 'b', 9457460), (9458104, 'beq', 9458372), (9458252, 'beq', 9458320), (9458320, 'b', 9458324), (9458368, 'b', 9458020), (9458372, 'b', 9458376), (9458376, 'b', 9458380), (9458392, 'b', 9457220)],
        semantics=("removeDynamicObjectsBelongingToClient: marks every owner-online object type's objects for removal when a client leaves. Prologue 0x00904e18 (frame 0x1a8; base 0x105faf4).\nLoop: `for i in 0..0x41 (65)` (cmp 0x41 @0x904e48): skip unless `objectTypeCanBeLoadedOnlyWhenClientOwnerOnline(int)` (C call @0x904e54) holds.\nPer i: the ffffe54c map segment (cell 0x9052e4, 12-byte stride) is tree-iterated (state at sp+0x60, `std::__1::tree_next` @0x905084): per node the position member ([node+0x10]+8) feeds the ffe233a0/ffe233a4 pair (cells 0x9052fc/0x9052f8, @0x904fa4-0x905010) and the ffe2349c flag-1 call marks the node (cell 0x905300, @0x905020-0x90505c) - the needsRemoved family of E21/E24. Then the same pass repeats over the ffffe550 segment (cell 0x9052ec, @0x905094-0x9052c4). Exit 0x9052dc.\n"),
    ),
    dict(
        name='wtl_placetraincaratpos_oft',
        method='DynamicWorld -[placeTrainCarAtPos:ofType:saveDict:placedByClient:]',
        types='v28@0:4{?=ii}8i16@20@24',
        start=9365248,
        end=9367376,
        disasm='disasm_worldtileloader_placetraincaratpos_oftype_savedict_place.txt',
        base_add=9365264,
        base_literal=9367372,
        boundary='ARM.exidx end 0x008eef50 (listing bound); next ObjC IMP 0x008eef50 DynamicWorld -[checkForTrainCarUnderTap:]',
        selectors={
                 0x8eef00: (15216988, 'checkForTrainCarUnderTap:'),
                 0x8eef10: (15215804, 'alloc'),
                 0x8eef18: (15216980, 'initWithWorld:dynamicWorld:atPosition:cache:saveDict:placedByClient:'),
                 0x8eef38: (15216020, 'sendNetDataIfNeededForObject:isCreation:'),
                 0x8eef3c: (15216168, 'objectType'),
                 0x8eef48: (15216160, 'uniqueID'),
        },
        imports={
                 0x8eef34: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8eeefc: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8eef14: (17162232, 'OBJC_IVAR_$_DynamicWorld.cache', 7336),
                 0x8eef44: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
        },
        classes={
                 0x8eef08: (15248012, 'OBJC_CLASS_$_PassengerCar'),
                 0x8eef1c: (15247860, 'OBJC_CLASS_$_FreightCar'),
                 0x8eef24: (15248008, 'OBJC_CLASS_$_SteamTrain'),
                 0x8eef2c: (15248004, 'OBJC_CLASS_$_HandCar'),
        },
        instructions=[(9365248, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9365344, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9365516, 'ldr r0, [0x008eef2c]'), (9365724, 'bl sym.makeIntpair_int__int_'), (9365828, 'bl sym.tileIsSolid_Tile_'), (9367092, 'ldr r2, [0x008eef3c]'), (9367364, 'invalid'), (9367372, 'ldrsbteq r1, [r7], -0x3c')],
        calls=[(9365344, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9365436, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9365548, 'bl loc.imp.objc_msgSend'), (9365672, 'bl loc.imp.objc_msgSend'), (9365724, 'bl sym.makeIntpair_int__int_'), (9365776, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9365828, 'bl sym.tileIsSolid_Tile_'), (9365868, 'bl sym.makeIntpair_int__int_'), (9365936, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9365996, 'bl sym.makeIntpair_int__int_'), (9366064, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9366188, 'bl method.Vector2.Vector2_float__float_'), (9366220, 'bl loc.imp.objc_msgSend'), (9366308, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9366320, 'bl sym.tileIsSolid_Tile_'), (9366436, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9366448, 'bl sym.tileIsSolid_Tile_'), (9366564, 'bl loc.imp.objc_msgSend'), (9366688, 'bl loc.imp.objc_msgSend'), (9366744, 'bl loc.imp.objc_msgSend'), (9366868, 'bl loc.imp.objc_msgSend'), (9366924, 'bl loc.imp.objc_msgSend'), (9367048, 'bl loc.imp.objc_msgSend'), (9367124, 'bl loc.imp.objc_msgSend'), (9367184, 'bl loc.imp.objc_msgSend'), (9367204, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9367280, 'blx r4')],
        branches=[(9365364, 'beq', 9365496), (9365380, 'beq', 9365496), (9365456, 'beq', 9365492), (9365472, 'bne', 9365492), (9365492, 'b', 9365496), (9365512, 'bne', 9365684), (9365680, 'b', 9367068), (9365700, 'bge', 9366520), (9365796, 'beq', 9366500), (9365820, 'beq', 9366104), (9365840, 'beq', 9365972), (9365956, 'beq', 9365968), (9365968, 'b', 9366100), (9366084, 'beq', 9366096), (9366096, 'b', 9366100), (9366100, 'b', 9366104), (9366112, 'beq', 9366496), (9366240, 'beq', 9366492), (9366332, 'beq', 9366352), (9366348, 'b', 9366488), (9366364, 'beq', 9366484), (9366380, 'beq', 9366484), (9366460, 'bne', 9366480), (9366480, 'b', 9366484), (9366484, 'b', 9366488), (9366488, 'b', 9366520), (9366492, 'b', 9366496), (9366496, 'b', 9366500), (9366500, 'b', 9366504), (9366516, 'b', 9365692), (9366528, 'bne', 9366700), (9366696, 'b', 9367064), (9366708, 'bne', 9366880), (9366876, 'b', 9367060), (9366888, 'bne', 9367056), (9367056, 'b', 9367060), (9367060, 'b', 9367064), (9367064, 'b', 9367068), (9367080, 'beq', 9367284)],
        semantics=("placeTrainCarAtPos:ofType:saveDict:placedByClient: places a train car on a rail. Prologue 0x008ee700 (frame 0x100; base 0x105faf4). Arguments: pos pair, ofType, saveDict, placedByClient [fp,0x10].\nRail gates: `tileAtWorldPositionLoaded(x, y, world)` (world cell 0x8eeefc) requires the tile byte [tile+0xb] == 0x62 ('b', the rail marker) (@0x8ee77c-0x8ee784) and the below tile (y-1) also 0x62 (@0x8ee7d8-0x8ee7e0).\nType arms: ofType == 0xcc -> class cell ffe2af90 (@0x8ee80c) + alloc/init + the packed creation (5-arg frame, dispatch ffe23660 cell 0x8eef18, @0x8ee884-0x8ee8a8); 0xcd -> class ffe2af94 (@0x8eec04); 0xce -> class ffe2af00 (@0x8eecb8); 0xd0 -> class ffe2af98 (@0x8eed6c) - the four car classes.\nSearch loop: when ofType is not one of the direct arms `for i in 0..2` (cmp 2 @0x8ee8c0) probes makeIntpair offsets (@0x8ee8d8) with `tileIsSolid(Tile*)` (C call @0x8ee944) and the 0x62 checks (@0x8ee928-0x8eea50); on success the candidate is built as Vector2(float x+5, float y+1) (`vcvt` + `vadd` 5/1 @0x8eea6c-0x8eeaa8).\n\nVerification and loops: the accepted candidate re-checks the tile and below with `tileIsSolid` (@0x8eeadc-0x8eebd8); the loop tail (@0x8eebec) continues.\nRegistration: when the created object is non-null `[obj objectType]` (ffe23334, cell 0x8eef3c) -> the ffffe550 map segment (cell 0x8eef44, 12-byte stride) registers it (uniqueID path). Epilogue.\n"),
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
        'batch': 'DynamicWorld world-mutation cluster (E26): worldContentsChangedAtPos:, interactionObjectPlacedAtPosition:..., removeStandardObject:, removeDoorAtPos:, createClientFreeblocksWithData:, removeDynamicObjectsBelongingToClient: and placeTrainCarAtPos:ofType:saveDict:placedByClient:; 7 bodies',
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
                        default=NATIVE / 'world_mutate.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale world_mutate.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
