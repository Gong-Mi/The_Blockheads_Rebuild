#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld object query & lifecycle cluster (E24).

The DynamicWorld object query and lifecycle cluster: the full teardown, the
remote-removal receiver, the server repair pass, the occupant/position queries,
the interaction-object probe lattice, the client-disconnect cleanup and the two
free-block factories:
1 body, 6108 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/OBJECT_LIFE.md for the prose and boundaries.
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
    'bl 0x8df004': 0x008df004,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__': 0x005dc5d8,
    'bl method.std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.clear__': 0x00914f20,
    'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_': 0x008bcf24,
    'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_': 0x008bcb78,
    'bl method.std::__1::map_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.operator___unsigned_long_long_': 0x008bd2e4,
    'bl method.std::__1::pair_std::__1::__tree_iterator_DynamicObject__std::__1::__tree_node_DynamicObject__void___int___bool__std::__1::__tree_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject___.__insert_unique_DynamicObject__DynamicObject_': 0x0090c82c,
    'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const': 0x00910a74,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.itemTypeFromTileIsForegorund_Tile__intpair__signed_char__World_': 0x00a18044,
    'bl sym.itemTypeIsColumn_ItemType_': 0x005b291c,
    'bl sym.itemTypeIsPainting_ItemType_': 0x005b902c,
    'bl sym.itemTypeIsStairs_ItemType_': 0x005b2b0c,
    'bl sym.itemTypeIsTorch_ItemType_': 0x005df794,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.objectTypeHasStaticPosition_int_': 0x008b68ac,
    'bl sym.objectTypeIsNPC_int_': 0x008c4b74,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileIsWorkbench_Tile_': 0x00a1436c,
    'bl sym.worldIndexAtWorldPos_intpair__World_': 0x00a15838,
}

SPECS = [
    dict(
        name='dyn_dealloc',
        method='DynamicWorld -[dealloc]',
        types='v8@0:4',
        start=9098016,
        end=9102480,
        disasm='disasm_worldtileloader_dealloc_dynamicworld.txt',
        base_add=9098036,
        base_literal=9101640,
        boundary='ARM.exidx end 0x008ae490 (listing bound); next ObjC IMP 0x008ae490 DynamicWorld -[mainThreadRemoveDirFromConversionList:]',
        selectors={
                 0x8ae150: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8ae418: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8ae420: (15215844, 'blockheadWillBeUnloaded:'),
                 0x8ae42c: (15215852, 'release'),
                 0x8ae44c: (15215856, 'dealloc'),
                 0x8ae48c: (15215848, 'cleanup'),
        },
        imports={
                 0x8ae14c: (17151904, 'objc_msgSend'),
                 0x8ae414: (17151904, 'objc_msgSend'),
                 0x8ae448: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0x8ae154: (17162220, 'OBJC_IVAR_$_DynamicWorld.blockheads', 44),
                 0x8ae41c: (17162220, 'OBJC_IVAR_$_DynamicWorld.blockheads', 44),
                 0x8ae424: (17162216, 'OBJC_IVAR_$_DynamicWorld.netBlockheads', 48),
                 0x8ae428: (17162212, 'OBJC_IVAR_$_DynamicWorld.netBlockheadsWithDisconnectedClients', 52),
                 0x8ae430: (17162208, 'OBJC_IVAR_$_DynamicWorld.clientBlockheadInventoriesToSave', 56),
                 0x8ae434: (17162272, 'OBJC_IVAR_$_DynamicWorld.wirePathCreator', 9496),
                 0x8ae438: (17162280, 'OBJC_IVAR_$_DynamicWorld.versionOneToTwoConversionList', 9464),
                 0x8ae43c: (17162268, 'OBJC_IVAR_$_DynamicWorld.clientFreeblockArrayToSend', 8412),
                 0x8ae440: (17162196, 'OBJC_IVAR_$_DynamicWorld.worldSaveDirectory', 40),
                 0x8ae444: (17162204, 'OBJC_IVAR_$_DynamicWorld.portalPositions', 7332),
                 0x8ae454: (17162284, 'OBJC_IVAR_$_DynamicWorld.liveServerClientBlockheadInventories', 9500),
                 0x8ae458: (17162288, 'OBJC_IVAR_$_DynamicWorld.netCreateDynamicObjects', 7372),
                 0x8ae460: (17162292, 'OBJC_IVAR_$_DynamicWorld.netUpdateDynamicObjects', 7632),
                 0x8ae464: (17162296, 'OBJC_IVAR_$_DynamicWorld.netUpdateCreationDataDynamicObjects', 7892),
                 0x8ae468: (17162300, 'OBJC_IVAR_$_DynamicWorld.netRemoveDynamicObjects', 8152),
                 0x8ae46c: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8ae474: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
                 0x8ae47c: (17162312, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsByWorldPosIndex', 1620),
        },
        classes={
                 0x8ae450: (15252912, 'OBJC_CLASS_$_DynamicWorld'),
        },
        instructions=[(9098016, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9098040, 'sub r3, fp, 0x2b8'), (9098504, 'add r0, sp, 0x270'), (9098968, 'add r0, sp, 0x208'), (9099444, 'cmp r0, 4'), (9100360, 'movw r0, 0'), (9100596, 'cmp r0, 0x41'), (9101516, 'bl method.std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.clear__'), (9101568, 'bl method.std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.clear__'), (9101620, 'bl method.std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.clear__'), (9102476, 'invalid')],
        calls=[(9098132, 'bl sym.imp.memset'), (9098196, 'blx lr'), (9098296, 'bl sym.imp.objc_enumerationMutation'), (9098376, 'blx ip'), (9098476, 'blx ip'), (9098596, 'bl sym.imp.memset'), (9098660, 'blx lr'), (9098760, 'bl sym.imp.objc_enumerationMutation'), (9098840, 'blx ip'), (9098940, 'blx ip'), (9099060, 'bl sym.imp.memset'), (9099124, 'blx lr'), (9099224, 'bl sym.imp.objc_enumerationMutation'), (9099304, 'blx ip'), (9099404, 'blx ip'), (9099844, 'blx r2'), (9099880, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9100288, 'blx r2'), (9100324, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9100472, 'blx r5'), (9100508, 'blx r3'), (9100544, 'blx r3'), (9100580, 'blx r3'), (9100984, 'blx r2'), (9101020, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9101416, 'blx r2'), (9101452, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9101516, 'bl method.std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.clear__'), (9101568, 'bl method.std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.clear__'), (9101620, 'bl method.std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.clear__'), (9101780, 'blx r6'), (9101816, 'blx r3'), (9101852, 'blx r3'), (9101888, 'blx r3'), (9101924, 'blx r3'), (9102044, 'bl loc.imp.objc_msgSend'), (9102088, 'bl loc.imp.objc_msgSend'), (9102132, 'bl loc.imp.objc_msgSend'), (9102184, 'blx r2'), (9102304, 'blx lr'), (9102344, 'blx r2')],
        branches=[(9098208, 'beq', 9098500), (9098288, 'beq', 9098300), (9098404, 'blo', 9098252), (9098496, 'bne', 9098252), (9098500, 'b', 9098504), (9098672, 'beq', 9098964), (9098752, 'beq', 9098764), (9098868, 'blo', 9098716), (9098960, 'bne', 9098716), (9098964, 'b', 9098968), (9099136, 'beq', 9099428), (9099216, 'beq', 9099228), (9099332, 'blo', 9099180), (9099424, 'bne', 9099180), (9099428, 'b', 9099432), (9099448, 'bge', 9100360), (9099756, 'beq', 9099896), (9099892, 'b', 9099672), (9100200, 'beq', 9100340), (9100336, 'b', 9100116), (9100340, 'b', 9100344), (9100356, 'b', 9099440), (9100600, 'bge', 9101656), (9100896, 'beq', 9101036), (9101032, 'b', 9100812), (9101328, 'beq', 9101468), (9101464, 'b', 9101244), (9101636, 'b', 9100592), (9101948, 'bge', 9102204), (9102200, 'b', 9101940)],
        semantics=('dealloc is the full teardown of the DynamicWorld object graph. Prologue 0x008ad320 (frame 0x178+0x400; base 0x105faf4).\nPhase 1 (three collections): enumerate the blockheads collection ivar ffffe4f8 (cell 0x8ae154, @0x8ad338), then netBlockheads ffffe4f4 (@0x8ad508), then ffffe4f0 (@0x8ad6d8): per item `blockheadWillBeUnloaded:` (selector cell 0x8ae420 ffe231f0, count marker 2) runs, and each loop body clears state via memset + the enumeration continuation pattern.\nPhase 2: `for i in 0..4` (cmp 4 @0x8ad8b4) with a SWITCH jump table (cells 0x8ae480 0xffdeaf18 + 0x8ae484 0x7b2220 -> table @ 0x00E4AA0C, dispatch @0x8ad8d4): the ffffe54c map segment (12-byte stride, cell 0x8ae46c) and then the ffffe550 segment (cell 0x8ae474) are tree-iterated (std::__tree_next @0x8ada68/0x8adc24); per node the selector ffe231f4 runs with the position member ([node+0x10]+8).\nPhase 3: a packed call on ffffe4ec + the three collections (selector ffe231f8, cells 0x8ae42c/0x8ae430/0x8ae428/0x8ae424/0x8ae41c) releases the blockhead collections (@0x8adc48-0x8add24). Then `for i in 0..0x41 (65)` (cmp 0x41 @0x8add34): per segment the three per-type registries are cleared with `std::__1::__tree<std::pair<u64, DynamicObject*>>::clear()` - ffffe54c @0x8ae0cc, ffffe550 @0x8ae100, ffffe554 @0x8ae134 (12*3 stride arithmetic). Tail 0x8ae158: the packed release of ffffe52c/ffffe534/ffffe528/ffffe4e0/ffffe4e8 (collections/arrays) with ffe231f8; epilogue.\n'),
    ),
    dict(
        name='wtl_remoteremove_forobject',
        method='DynamicWorld -[remoteRemove:forObjectsOfType:fromClient:]',
        types='v20@0:4@8i12@16',
        start=9191948,
        end=9194356,
        disasm='disasm_worldtileloader_remoteremove_forobjectsoftype_fromclient.txt',
        base_add=9191964,
        base_literal=9194352,
        boundary='ARM.exidx end 0x008c4b74 (listing bound); next ObjC IMP 0x008c4c20 DynamicWorld -[updateNetObjects]',
        selectors={
                 0x8c4b10: (15216420, 'isServer'),
                 0x8c4b14: (15216280, 'isEqualToString:'),
                 0x8c4b18: (15216432, 'playerUpdate'),
                 0x8c4b20: (15216428, 'playerIsAdminWithID:'),
                 0x8c4b24: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8c4b28: (15216144, 'array'),
                 0x8c4b30: (15216436, 'getBytes:length:'),
                 0x8c4b38: (15216444, 'mayOnlyBeRemovedByOwner'),
                 0x8c4b3c: (15216448, 'ownerID'),
                 0x8c4b40: (15216452, 'itemType'),
                 0x8c4b44: (15216008, 'addObject:'),
                 0x8c4b4c: (15216160, 'uniqueID'),
                 0x8c4b54: (15216440, 'clientID'),
                 0x8c4b64: (15215804, 'alloc'),
                 0x8c4b68: (15215800, 'init'),
                 0x8c4b6c: (15216424, 'addObjectsFromArray:'),
        },
        imports={
                 0x8c4b0c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8c4b1c: (17162256, 'OBJC_IVAR_$_DynamicWorld.server', 16),
                 0x8c4b34: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8c4b48: (17162216, 'OBJC_IVAR_$_DynamicWorld.netBlockheads', 48),
                 0x8c4b58: (17162300, 'OBJC_IVAR_$_DynamicWorld.netRemoveDynamicObjects', 8152),
        },
        classes={
                 0x8c4b2c: (15247780, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(9191948, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9191968, 'ldr lr, [fp, 8]'), (9192180, 'bl sym.objectTypeIsNPC_int_'), (9192696, 'movw r3, 8'), (9193096, 'eor r1, r1, r3'), (9193464, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9193520, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_'), (9194352, 'ldrsbteq fp, [sb], -0x80')],
        calls=[(9192028, 'blx r4'), (9192124, 'blx r3'), (9192180, 'bl sym.objectTypeIsNPC_int_'), (9192280, 'blx ip'), (9192300, 'blx r3'), (9192400, 'blx r3'), (9192520, 'blx r2'), (9192544, 'bl sym.imp.memset'), (9192592, 'blx lr'), (9192692, 'bl sym.imp.objc_enumerationMutation'), (9192776, 'blx ip'), (9192884, 'bl sym.imp.memset'), (9192948, 'blx lr'), (9193048, 'bl sym.imp.objc_enumerationMutation'), (9193084, 'bl loc.imp.objc_msgSend'), (9193180, 'blx ip'), (9193200, 'blx r3'), (9193264, 'blx r3'), (9193372, 'blx ip'), (9193464, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9193520, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_'), (9193572, 'blx r3'), (9193648, 'blx ip'), (9193668, 'blx r3'), (9193736, 'blx r2'), (9193796, 'blx r3'), (9193912, 'blx ip'), (9194060, 'bl loc.imp.objc_msgSend'), (9194076, 'bl loc.imp.objc_msgSend'), (9194184, 'blx r3'), (9194240, 'blx r3')],
        branches=[(9192040, 'beq', 9193948), (9192052, 'bne', 9192148), (9192136, 'bne', 9192144), (9192140, 'b', 9194244), (9192144, 'b', 9192332), (9192156, 'beq', 9192172), (9192168, 'bne', 9192176), (9192172, 'b', 9194244), (9192192, 'beq', 9192200), (9192196, 'b', 9194244), (9192312, 'beq', 9192320), (9192316, 'b', 9194244), (9192320, 'b', 9192324), (9192324, 'b', 9192328), (9192328, 'b', 9192332), (9192412, 'bne', 9193944), (9192604, 'beq', 9193936), (9192684, 'beq', 9192696), (9192788, 'bne', 9193404), (9192960, 'beq', 9193396), (9193040, 'beq', 9193052), (9193112, 'bne', 9193272), (9193116, 'b', 9193120), (9193212, 'beq', 9193268), (9193268, 'b', 9193272), (9193272, 'b', 9193276), (9193300, 'blo', 9193004), (9193392, 'bne', 9193004), (9193396, 'b', 9193400), (9193400, 'b', 9193812), (9193472, 'bls', 9193808), (9193584, 'beq', 9193684), (9193680, 'beq', 9193804), (9193692, 'bne', 9193748), (9193744, 'beq', 9193800), (9193800, 'b', 9193804), (9193804, 'b', 9193808), (9193808, 'b', 9193812), (9193812, 'b', 9193816), (9193840, 'blo', 9192648), (9193932, 'bne', 9192648), (9193936, 'b', 9193940), (9193940, 'b', 9193944), (9193944, 'b', 9193948), (9194012, 'bne', 9194120), (9194132, 'beq', 9194192), (9194188, 'b', 9194244)],
        semantics=("remoteRemove:forObjectsOfType:fromClient: applies a client's removal request. Prologue 0x008c420c (frame 0x1e8; base 0x105faf4). Arguments: data list [-0x2c], objectType [-0x30], client [fp,8] -> [-0x34].\nGates: the ffe23430 call (cell 0x8c4b10) must be nonzero (else exit 0x8c49dc); for objectType == 0x3c the ffffe51c-slot gate (ffe23438 call @0x8c42b0) must hold; objectType 0xe and 0x1f exit early (@0x8c42d4); `objectTypeIsNPC(int)` (C call @0x8c42f4) exits; a second ffe23438 gate exits (0x8c43d4).\nMain: the data list [-0x2c] is enumerated (isKindOfClass: cell 0x8c4b28/0x8c4b2c); per entry `getBytes:length:8` (selector cell 0x8c4b30 ffe23440, `movw r3, 8` @0x8c44f8) reads the 8-byte object ID into fp-0xa8.\n- objectType == 0x18 (Blockhead): enumerate netBlockheads ivar ffffe4f4 (cell 0x8c4b48); per bh `[bh uniqueID]` (cell 0x8c4b4c ffe2332c) eor/orr-matches the ID (@0x8c4688-0x8c4698); on match `[bh clientID]` (cell 0x8c4b54 ffe23444) is compared with the client argument, and the match is added with `addObject:` (cell 0x8c4b44 ffe23294) into the collection [-0x3c].\n- otherwise: the ffffe54c map segment for the objectType (cell 0x8c4b34, 12-byte stride @0x8c47d8) -> `__count_unique(u64)` (C++ call @0x8c47f8) -> `map<u64,DynamicObject*>::operator[](u64)` (@0x8c4830) -> the ffe23448 call (cell 0x8c4b38) gate -> the ffe2344c call (cell 0x8c4b3c) gate -> when the second returns 0x14 and `[obj objectType]` (cell 0x8c4b40 ffe23450) equals 0x130 the object is skipped (0x8c4910); otherwise `addObject:` (ffe23294) collects it. Exit 0x8c49d0/0x8c4b04. Pairs with E21's client-side removal sender (packet marker 0xc).\n"),
    ),
    dict(
        name='wtl_dorepairfortileatpos_',
        method='DynamicWorld -[doRepairForTileAtPos:]',
        types='v16@0:4{?=ii}8',
        start=9461200,
        end=9463776,
        disasm='disasm_worldtileloader_dorepairfortileatpos_.txt',
        base_add=9461216,
        base_literal=9463772,
        boundary='ARM.exidx end 0x009067e0 (listing bound); next ObjC IMP 0x009067e0 DynamicWorld -[loadDebugChestAtPos:chest:]',
        selectors={
                 0x906780: (15216748, 'removeDoorAtPos:'),
                 0x906788: (15216452, 'itemType'),
                 0x906790: (15216272, 'getSaveDict'),
                 0x906794: (15216388, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
                 0x9067a8: (15216012, 'pos'),
                 0x9067b4: (15216128, 'worldWidthMacro'),
                 0x9067c8: (15217380, 'removeObjectDueToRepair:'),
        },
        imports={
                 0x9067c4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x90677c: (17162256, 'OBJC_IVAR_$_DynamicWorld.server', 16),
                 0x906798: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x9067a0: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
                 0x9067ac: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
        },
        classes={},
        instructions=[(9461200, 'push {r4, sl, fp, lr}'), (9461220, 'movw lr, 0'), (9461552, 'cmp r0, 0x41'), (9461588, 'bl sym.objectTypeHasStaticPosition_int_'), (9462516, 'cmp r0, 0'), (9462676, 'str r3, [fp, -0x94]'), (9463612, 'str r0, [fp, -0x104]'), (9463772, 'rsbseq sb, r5, ip, lsl 26')],
        calls=[(9461348, 'bl loc.imp.objc_msgSend'), (9461428, 'bl loc.imp.objc_msgSend'), (9461460, 'bl loc.imp.objc_msgSend'), (9461536, 'bl loc.imp.objc_msgSend'), (9461588, 'bl sym.objectTypeHasStaticPosition_int_'), (9462008, 'bl loc.imp.objc_msgSend_stret'), (9462044, 'bl sym.imp.memset'), (9462140, 'bl loc.imp.objc_msgSend'), (9462164, 'bl sym.imp.__aeabi_idiv'), (9462248, 'bl loc.imp.objc_msgSend'), (9462356, 'bl loc.imp.objc_msgSend'), (9462372, 'bl sym.imp.__aeabi_idiv'), (9462456, 'bl loc.imp.objc_msgSend'), (9462572, 'blx r3'), (9462612, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9463028, 'bl loc.imp.objc_msgSend_stret'), (9463064, 'bl sym.imp.memset'), (9463160, 'bl loc.imp.objc_msgSend'), (9463184, 'bl sym.imp.__aeabi_idiv'), (9463268, 'bl loc.imp.objc_msgSend'), (9463376, 'bl loc.imp.objc_msgSend'), (9463392, 'bl sym.imp.__aeabi_idiv'), (9463476, 'bl loc.imp.objc_msgSend'), (9463592, 'blx r3'), (9463632, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__')],
        branches=[(9461272, 'bne', 9461280), (9461276, 'b', 9463668), (9461368, 'beq', 9461540), (9461556, 'bge', 9463668), (9461568, 'beq', 9461604), (9461580, 'beq', 9461604), (9461600, 'bne', 9461608), (9461604, 'b', 9463652), (9461900, 'beq', 9462628), (9461992, 'beq', 9462016), (9462012, 'b', 9462048), (9462060, 'bne', 9462576), (9462176, 'blt', 9462280), (9462276, 'b', 9462512), (9462384, 'bge', 9462488), (9462484, 'b', 9462504), (9462520, 'bne', 9462576), (9462576, 'b', 9462580), (9462624, 'b', 9461816), (9462920, 'beq', 9463648), (9463012, 'beq', 9463036), (9463032, 'b', 9463068), (9463080, 'bne', 9463596), (9463196, 'blt', 9463300), (9463296, 'b', 9463532), (9463404, 'bge', 9463508), (9463504, 'b', 9463524), (9463540, 'bne', 9463596), (9463596, 'b', 9463600), (9463644, 'b', 9462836), (9463648, 'b', 9463652), (9463664, 'b', 9461548)],
        semantics=("doRepairForTileAtPos: runs the server-side repair pass for the tile objects near a position. Prologue 0x00905dd0 (frame 0x278; base 0x105faf4).\nGate: the ffffe51c slot on self (cell 0x90677c) must be nonzero, else exit 0x906774 (server-only). Pre-step: the ffe23578 call chain (@0x905e38-0x905e74) builds state, then the 8-arg create call ffe23410 (cell 0x906794) runs with the packed args (flag 1 at +0x18; @0x905eec-0x905f20) - the same create shape as E23's pole restore and E24's free blocks.\nMain loop: `for i in 0..0x41 (65)` (cmp 0x41 @0x905f30): skip i == 0x15 and i == 0x14 (@0x905f3c-0x905f4c); `objectTypeHasStaticPosition(int)` (C call @0x905f54) is required.\nPer i: the ffffe54c map segment (cell 0x906798, 12-byte stride) is tree-iterated; per node the position (pos getter ffe23298 cell 0x9067a8 with the [node+0x10]+8 member) is compared through the wrap-distance math: worldWidthMacro (cell 0x9067b4 ffe2330c) `<< 5` then `__aeabi_idiv` against the object pos with the 2/5 constants and `rsb r0, r0, 0` negation (@0x906130-0x9062f4) - the cylindrical wrap distance; in range the repair hook ffe237f0 (cell 0x9067c8) runs on the node (@0x9062fc-0x90632c). The same pass repeats over the ffffe550 segment (@0x906364-0x906760). Loop tail @0x906768; epilogue 0x906774.\n"),
    ),
    dict(
        name='wtl_blockheadatpos_',
        method='DynamicWorld -[blockheadAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9389476,
        end=9392008,
        disasm='disasm_worldtileloader_blockheadatpos_.txt',
        base_add=9389492,
        base_literal=9392004,
        boundary='ARM.exidx end 0x008f4f88 (listing bound); next ObjC IMP 0x008f4f88 DynamicWorld -[loadGlowBlockIfNeededAtPos:tile:]',
        selectors={
                 0x8f4f6c: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8f4f74: (15216012, 'pos'),
                 0x8f4f78: (15217068, 'crouching'),
        },
        imports={
                 0x8f4f68: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8f4f70: (17162220, 'OBJC_IVAR_$_DynamicWorld.blockheads', 44),
                 0x8f4f7c: (17162216, 'OBJC_IVAR_$_DynamicWorld.netBlockheads', 48),
                 0x8f4f80: (17162212, 'OBJC_IVAR_$_DynamicWorld.netBlockheadsWithDisconnectedClients', 52),
        },
        classes={},
        instructions=[(9389476, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9389524, 'ldr r8, [0x008f4f70]'), (9389908, 'cmp r0, r1'), (9390016, 'cmp r0, r1'), (9390124, 'sub r1, r1, 1'), (9391176, 'ldr r4, [0x008f4f80]'), (9391964, 'ldr r0, [fp, -0x20]'), (9392004, 'rsbseq fp, r6, r8, lsr r5')],
        calls=[(9389612, 'bl sym.imp.memset'), (9389676, 'blx lr'), (9389776, 'bl sym.imp.objc_enumerationMutation'), (9389860, 'bl loc.imp.objc_msgSend_stret'), (9389896, 'bl sym.imp.memset'), (9389968, 'bl loc.imp.objc_msgSend_stret'), (9390004, 'bl sym.imp.memset'), (9390076, 'bl loc.imp.objc_msgSend_stret'), (9390112, 'bl sym.imp.memset'), (9390176, 'blx r2'), (9390304, 'blx ip'), (9390424, 'bl sym.imp.memset'), (9390488, 'blx lr'), (9390588, 'bl sym.imp.objc_enumerationMutation'), (9390672, 'bl loc.imp.objc_msgSend_stret'), (9390708, 'bl sym.imp.memset'), (9390780, 'bl loc.imp.objc_msgSend_stret'), (9390816, 'bl sym.imp.memset'), (9390888, 'bl loc.imp.objc_msgSend_stret'), (9390924, 'bl sym.imp.memset'), (9390988, 'blx r2'), (9391116, 'blx ip'), (9391236, 'bl sym.imp.memset'), (9391300, 'blx lr'), (9391400, 'bl sym.imp.objc_enumerationMutation'), (9391484, 'bl loc.imp.objc_msgSend_stret'), (9391520, 'bl sym.imp.memset'), (9391592, 'bl loc.imp.objc_msgSend_stret'), (9391628, 'bl sym.imp.memset'), (9391700, 'bl loc.imp.objc_msgSend_stret'), (9391736, 'bl sym.imp.memset'), (9391800, 'blx r2'), (9391928, 'blx ip')],
        branches=[(9389688, 'beq', 9390328), (9389768, 'beq', 9389780), (9389844, 'beq', 9389868), (9389864, 'b', 9389900), (9389912, 'bne', 9390204), (9389952, 'beq', 9389976), (9389972, 'b', 9390008), (9390020, 'beq', 9390192), (9390060, 'beq', 9390084), (9390080, 'b', 9390116), (9390132, 'bne', 9390204), (9390188, 'bne', 9390204), (9390200, 'b', 9391964), (9390204, 'b', 9390208), (9390232, 'blo', 9389732), (9390324, 'bne', 9389732), (9390328, 'b', 9390332), (9390500, 'beq', 9391140), (9390580, 'beq', 9390592), (9390656, 'beq', 9390680), (9390676, 'b', 9390712), (9390724, 'bne', 9391016), (9390764, 'beq', 9390788), (9390784, 'b', 9390820), (9390832, 'beq', 9391004), (9390872, 'beq', 9390896), (9390892, 'b', 9390928), (9390944, 'bne', 9391016), (9391000, 'bne', 9391016), (9391012, 'b', 9391964), (9391016, 'b', 9391020), (9391044, 'blo', 9390544), (9391136, 'bne', 9390544), (9391140, 'b', 9391144), (9391312, 'beq', 9391952), (9391392, 'beq', 9391404), (9391468, 'beq', 9391492), (9391488, 'b', 9391524), (9391536, 'bne', 9391828), (9391576, 'beq', 9391600), (9391596, 'b', 9391632), (9391644, 'beq', 9391816), (9391684, 'beq', 9391708), (9391704, 'b', 9391740), (9391756, 'bne', 9391828), (9391812, 'bne', 9391828), (9391824, 'b', 9391964), (9391828, 'b', 9391832), (9391856, 'blo', 9391356), (9391948, 'bne', 9391356), (9391952, 'b', 9391956)],
        semantics=('blockheadAtPos: returns the blockhead at a position. Prologue 0x008f45a4 (frame 0x2f0; base 0x105faf4). Arguments: pos pair.\nThe same three-collection scan as blockheadOccupiesTileAtPos: blockheads ffffe4f8 (@0x8f45d4), netBlockheads ffffe4f4 (@0x8f491c), ffffe4f0 (@0x8f4c48). Per item: pos stret reads ffe23298 (cell 0x8f4f74); x == argument (@0x8f4754); y == argument (@0x8f47c0); pos.y - 1 == argument (@0x8f482c `sub r1, r1, 1`); the ffe236b8 gate (cell 0x8f4f78) decides. On success the item (kept in [fp,-0x34]) is returned via 0x8f4f5c; non-matches continue. The tail completes pass 3 over ffffe4f0 and the return path. Epilogue after 0x8f4f5c.\n'),
    ),
    dict(
        name='wtl_blockheadoccupiestilea',
        method='DynamicWorld -[blockheadOccupiesTileAtPos:ignoreBlockhead:]',
        types='c20@0:4{?=ii}8@16',
        start=9386880,
        end=9389476,
        disasm='disasm_worldtileloader_blockheadoccupiestileatpos_ignoreblockhe.txt',
        base_add=9386896,
        base_literal=9389472,
        boundary='ARM.exidx end 0x008f45a4 (listing bound); next ObjC IMP 0x008f45a4 DynamicWorld -[blockheadAtPos:]',
        selectors={
                 0x8f4588: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8f4590: (15216012, 'pos'),
                 0x8f4594: (15217068, 'crouching'),
        },
        imports={
                 0x8f4584: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8f458c: (17162220, 'OBJC_IVAR_$_DynamicWorld.blockheads', 44),
                 0x8f4598: (17162216, 'OBJC_IVAR_$_DynamicWorld.netBlockheads', 48),
                 0x8f459c: (17162212, 'OBJC_IVAR_$_DynamicWorld.netBlockheadsWithDisconnectedClients', 52),
        },
        classes={},
        instructions=[(9386880, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9386932, 'ldr sl, [0x008f458c]'), (9387232, 'cmp r1, r3'), (9387344, 'cmp r0, r1'), (9387452, 'cmp r0, r1'), (9387560, 'sub r1, r1, 1'), (9387584, 'ldr r2, [0x008f4594]'), (9389472, 'rsbseq fp, r6, ip, asr pc')],
        calls=[(9387032, 'bl sym.imp.memset'), (9387096, 'blx lr'), (9387196, 'bl sym.imp.objc_enumerationMutation'), (9387296, 'bl loc.imp.objc_msgSend_stret'), (9387332, 'bl sym.imp.memset'), (9387404, 'bl loc.imp.objc_msgSend_stret'), (9387440, 'bl sym.imp.memset'), (9387512, 'bl loc.imp.objc_msgSend_stret'), (9387548, 'bl sym.imp.memset'), (9387612, 'blx r2'), (9387740, 'blx ip'), (9387860, 'bl sym.imp.memset'), (9387924, 'blx lr'), (9388024, 'bl sym.imp.objc_enumerationMutation'), (9388124, 'bl loc.imp.objc_msgSend_stret'), (9388160, 'bl sym.imp.memset'), (9388232, 'bl loc.imp.objc_msgSend_stret'), (9388268, 'bl sym.imp.memset'), (9388340, 'bl loc.imp.objc_msgSend_stret'), (9388376, 'bl sym.imp.memset'), (9388440, 'blx r2'), (9388568, 'blx ip'), (9388688, 'bl sym.imp.memset'), (9388752, 'blx lr'), (9388852, 'bl sym.imp.objc_enumerationMutation'), (9388952, 'bl loc.imp.objc_msgSend_stret'), (9388988, 'bl sym.imp.memset'), (9389060, 'bl loc.imp.objc_msgSend_stret'), (9389096, 'bl sym.imp.memset'), (9389168, 'bl loc.imp.objc_msgSend_stret'), (9389204, 'bl sym.imp.memset'), (9389268, 'blx r2'), (9389396, 'blx ip')],
        branches=[(9387108, 'beq', 9387764), (9387188, 'beq', 9387200), (9387240, 'beq', 9387640), (9387280, 'beq', 9387304), (9387300, 'b', 9387336), (9387348, 'bne', 9387640), (9387388, 'beq', 9387412), (9387408, 'b', 9387444), (9387456, 'beq', 9387628), (9387496, 'beq', 9387520), (9387516, 'b', 9387552), (9387568, 'bne', 9387640), (9387624, 'bne', 9387640), (9387636, 'b', 9389432), (9387640, 'b', 9387644), (9387668, 'blo', 9387152), (9387760, 'bne', 9387152), (9387764, 'b', 9387768), (9387936, 'beq', 9388592), (9388016, 'beq', 9388028), (9388068, 'beq', 9388468), (9388108, 'beq', 9388132), (9388128, 'b', 9388164), (9388176, 'bne', 9388468), (9388216, 'beq', 9388240), (9388236, 'b', 9388272), (9388284, 'beq', 9388456), (9388324, 'beq', 9388348), (9388344, 'b', 9388380), (9388396, 'bne', 9388468), (9388452, 'bne', 9388468), (9388464, 'b', 9389432), (9388468, 'b', 9388472), (9388496, 'blo', 9387980), (9388588, 'bne', 9387980), (9388592, 'b', 9388596), (9388764, 'beq', 9389420), (9388844, 'beq', 9388856), (9388896, 'beq', 9389296), (9388936, 'beq', 9388960), (9388956, 'b', 9388992), (9389004, 'bne', 9389296), (9389044, 'beq', 9389068), (9389064, 'b', 9389100), (9389112, 'beq', 9389284), (9389152, 'beq', 9389176), (9389172, 'b', 9389208), (9389224, 'bne', 9389296), (9389280, 'bne', 9389296), (9389292, 'b', 9389432), (9389296, 'b', 9389300), (9389324, 'blo', 9388808), (9389416, 'bne', 9388808), (9389420, 'b', 9389424)],
        semantics=('blockheadOccupiesTileAtPos:ignoreBlockhead: answers whether a blockhead occupies a tile. Prologue 0x008f3b80 (frame 0x2f0; base 0x105faf4). Arguments: pos pair [fp,8]+[fp,0xc], ignoreBlockhead.\nThree collection passes: blockheads ivar ffffe4f8 (cell 0x8f458c, @0x8f3bb4), netBlockheads ffffe4f4 (cell 0x8f4598, @0x8f3f18), ffffe4f0 (cell 0x8f459c, @0x8f4248). Per item: skip when the item equals ignoreBlockhead (@0x8f3ce0); then the pos is read with the stret getter ffe23298 three times: x == argument (@0x8f3d50), then y == argument (@0x8f3dbc), then pos.y - 1 == argument (@0x8f3e28, `sub r1, r1, 1`); the ffe236b8 call (cell 0x8f4594) gate must pass; on success the found flag [fp,-0x1d] = 1 and the body exits via 0x8f4578. Non-matches continue the enumeration (@0x8f3e78). Exit 0x8f456c/0x8f4578.\n'),
    ),
    dict(
        name='wtl_interactionobjectatpos',
        method='DynamicWorld -[interactionObjectAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9373008,
        end=9375816,
        disasm='disasm_worldtileloader_interactionobjectatpos_.txt',
        base_add=9373024,
        base_literal=9375812,
        boundary='ARM.exidx end 0x008f1048 (listing bound); next ObjC IMP 0x008f1048 DynamicWorld -[interactionObjectWithID:]',
        selectors={
                 0x8f0ff4: (15216868, 'objectOfType:atPos:'),
                 0x8f1004: (15217012, 'twoBlocksWide'),
                 0x8f1008: (15217016, 'flipped'),
                 0x8f1018: (15216340, 'workbenchAtPos:'),
                 0x8f103c: (15217004, 'isDoubleHeight'),
        },
        imports={
                 0x8f1000: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8f0fec: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
        },
        classes={},
        instructions=[(9373008, 'push {r4, r5, r6, r7, fp, lr}'), (9373112, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9373052, 'mov r0, 0'), (9374436, 'cmp r0, 2'), (9374704, 'add r3, ip, r3, lsl 2'), (9374720, 'cmp r3, 0x2f'), (9375572, 'movw r0, 0'), (9375812, 'rsbseq pc, r6, ip, lsl 11')],
        calls=[(9373112, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9373184, 'bl loc.imp.objc_msgSend'), (9373308, 'bl loc.imp.objc_msgSend'), (9373396, 'bl sym.makeIntpair_int__int_'), (9373440, 'bl loc.imp.objc_msgSend'), (9373504, 'blx r2'), (9373560, 'blx r2'), (9373640, 'bl sym.makeIntpair_int__int_'), (9373684, 'bl loc.imp.objc_msgSend'), (9373748, 'blx r2'), (9373804, 'blx r2'), (9373884, 'bl sym.makeIntpair_int__int_'), (9373928, 'bl loc.imp.objc_msgSend'), (9373992, 'blx r2'), (9374048, 'blx r2'), (9374128, 'bl sym.makeIntpair_int__int_'), (9374172, 'bl loc.imp.objc_msgSend'), (9374236, 'blx r2'), (9374292, 'blx r2'), (9374388, 'bl loc.imp.objc_msgSend'), (9374528, 'bl sym.makeIntpair_int__int_'), (9374572, 'bl loc.imp.objc_msgSend'), (9374836, 'bl loc.imp.objc_msgSend'), (9374924, 'bl sym.makeIntpair_int__int_'), (9374968, 'bl loc.imp.objc_msgSend'), (9375032, 'blx r2'), (9375088, 'blx r2'), (9375168, 'bl sym.makeIntpair_int__int_'), (9375212, 'bl loc.imp.objc_msgSend'), (9375276, 'blx r2'), (9375332, 'blx r2'), (9375412, 'bl sym.makeIntpair_int__int_'), (9375456, 'bl loc.imp.objc_msgSend'), (9375520, 'blx r2'), (9375624, 'bl sym.makeIntpair_int__int_'), (9375668, 'bl loc.imp.objc_msgSend')],
        branches=[(9373204, 'beq', 9373220), (9373216, 'b', 9375712), (9373328, 'beq', 9373344), (9373340, 'b', 9375712), (9373460, 'beq', 9373588), (9373516, 'beq', 9373588), (9373572, 'beq', 9373588), (9373584, 'b', 9375712), (9373704, 'beq', 9373832), (9373760, 'beq', 9373832), (9373816, 'beq', 9373832), (9373828, 'b', 9375712), (9373948, 'beq', 9374076), (9374004, 'beq', 9374076), (9374060, 'bne', 9374076), (9374072, 'b', 9375712), (9374192, 'beq', 9374320), (9374248, 'beq', 9374320), (9374304, 'bne', 9374320), (9374316, 'b', 9375712), (9374408, 'beq', 9374424), (9374420, 'b', 9375712), (9374440, 'bge', 9374648), (9374460, 'bge', 9374628), (9374592, 'beq', 9374608), (9374604, 'b', 9375712), (9374608, 'b', 9374612), (9374624, 'b', 9374452), (9374628, 'b', 9374632), (9374644, 'b', 9374432), (9374664, 'bge', 9375572), (9374732, 'beq', 9375552), (9374744, 'beq', 9375552), (9374756, 'beq', 9375552), (9374856, 'beq', 9374872), (9374868, 'b', 9375712), (9374988, 'beq', 9375116), (9375044, 'beq', 9375116), (9375100, 'beq', 9375116), (9375112, 'b', 9375712), (9375232, 'beq', 9375360), (9375288, 'beq', 9375360), (9375344, 'bne', 9375360), (9375356, 'b', 9375712), (9375476, 'beq', 9375548), (9375532, 'beq', 9375548), (9375544, 'b', 9375712), (9375548, 'b', 9375552), (9375552, 'b', 9375556), (9375568, 'b', 9374656), (9375688, 'beq', 9375704), (9375700, 'b', 9375712)],
        semantics=('interactionObjectAtPos: probes the tile and its neighbourhood for interaction objects. Prologue 0x008f0550 (frame 0x168; base 0x105faf4).\nProbe core: `tileAtWorldPositionLoaded(int, int, World*)` (C call @0x8f05b8, world via ffffe4e4), then the per-type resolver ffe235f0 (cell 0x8f0ff4) called with the probe type code; the gate pair ffe23680 (cell 0x8f1004) and ffe23684 (cell 0x8f1008) must both pass before the found path (0x8f0fe0); failures probe the next cell.\nProbe cells and type codes: the tile itself and (x, y+1), (x, y-1), (x-1, y) variants with type codes 0x2f (@0x8f05e8), 0x3c (@0x8f0660), 0x31 (@0x8f0b04), 0x32 (0x8f0f58); a nested `for a in 0..2 / for b in 0..2` sub-grid (@0x8f0ae4 / 0x8f0af8) probes makeIntpair offsets; a 9-arm SWITCH jump table (cells 0x8f1024 0xffdeaf9c + 0x8f1028 0x76ef04 -> table @ 0x00E4AA90, dispatch @0x8f0bf0) iterates the nine probe slots and skips codes already handled (`cmp r3, 0x2f` / `cmp r0, 0x3c` / `cmp r0, 0x31` @0x8f0c00-0x8f0c24). The last arm uses the third gate ffe23678 (cell 0x8f103c) before concluding. Exit path 0x8f0fe0.\n'),
    ),
    dict(
        name='wtl_clientdisconnected_sim',
        method='DynamicWorld -[clientDisconnected:simulate:]',
        types='v16@0:4@8c12',
        start=9405856,
        end=9408460,
        disasm='disasm_worldtileloader_clientdisconnected_simulate_.txt',
        base_add=9405872,
        base_literal=9408456,
        boundary='ARM.exidx end 0x008f8fcc (listing bound); next ObjC IMP 0x008f8fcc DynamicWorld -[ridableObjectWithID:]',
        selectors={
                 0x8f8f64: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8f8f6c: (15216280, 'isEqualToString:'),
                 0x8f8f70: (15216440, 'clientID'),
                 0x8f8f74: (15216528, 'setNeedsRemoved:'),
                 0x8f8f7c: (15215800, 'init'),
                 0x8f8f80: (15215804, 'alloc'),
                 0x8f8f88: (15216328, 'containsObject:'),
                 0x8f8f8c: (15216008, 'addObject:'),
                 0x8f8f9c: (15217124, 'remoteBlockheadRemovedWithID:'),
                 0x8f8fa0: (15216160, 'uniqueID'),
                 0x8f8fa8: (15215996, 'removeObject:'),
                 0x8f8fac: (15216116, 'saveBlockheads'),
                 0x8f8fb0: (15216104, 'inventoryNeedsSaving'),
                 0x8f8fb4: (15216100, 'prepareInventoryForSaving'),
                 0x8f8fb8: (15216112, 'setInventoryNeedsSaving:'),
                 0x8f8fbc: (15216108, 'saveBlockheadInventory:'),
                 0x8f8fc0: (15215860, 'removeObjectForKey:'),
        },
        imports={
                 0x8f8f60: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8f8f68: (17162216, 'OBJC_IVAR_$_DynamicWorld.netBlockheads', 48),
                 0x8f8f78: (17162400, 'OBJC_IVAR_$_DynamicWorld.disconnectedClientsSaveDirNames', 9468),
                 0x8f8f98: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8f8fa4: (17162212, 'OBJC_IVAR_$_DynamicWorld.netBlockheadsWithDisconnectedClients', 52),
                 0x8f8fc4: (17162284, 'OBJC_IVAR_$_DynamicWorld.liveServerClientBlockheadInventories', 9500),
        },
        classes={
                 0x8f8f84: (15247780, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(9405856, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9405944, 'ldr r4, [0x008f8f68]'), (9406316, 'cmp r0, 9'), (9406348, 'ldr r1, [r2, r1, lsl 2]'), (9406796, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9407404, 'ldr r5, [0x008f8fa4]'), (9408268, 'b 0x8f8f10'), (9408456, 'rsbseq r7, r6, ip, lsr r5')],
        calls=[(9406012, 'bl sym.imp.memset'), (9406076, 'blx lr'), (9406176, 'bl sym.imp.objc_enumerationMutation'), (9406268, 'blx ip'), (9406288, 'blx r3'), (9406720, 'bl loc.imp.objc_msgSend'), (9406760, 'bl loc.imp.objc_msgSend'), (9406796, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9406952, 'blx r2'), (9406968, 'blx r2'), (9407060, 'blx r3'), (9407144, 'blx r3'), (9407212, 'blx ip'), (9407328, 'blx ip'), (9407520, 'blx r2'), (9407560, 'blx ip'), (9407580, 'bl sym.imp.memset'), (9407644, 'blx lr'), (9407744, 'bl sym.imp.objc_enumerationMutation'), (9407836, 'blx ip'), (9407856, 'blx r3'), (9407932, 'blx ip'), (9407952, 'blx r2'), (9408044, 'blx lr'), (9408072, 'blx r3'), (9408136, 'blx ip'), (9408240, 'blx ip'), (9408340, 'blx r3')],
        branches=[(9405908, 'beq', 9408344), (9406088, 'beq', 9407352), (9406168, 'beq', 9406180), (9406300, 'beq', 9407220), (9406320, 'bge', 9406832), (9406628, 'beq', 9406812), (9406808, 'b', 9406544), (9406812, 'b', 9406816), (9406828, 'b', 9406312), (9406840, 'beq', 9407152), (9406880, 'bne', 9406992), (9407072, 'bne', 9407148), (9407148, 'b', 9407216), (9407216, 'b', 9407220), (9407256, 'blo', 9406132), (9407348, 'bne', 9406132), (9407352, 'b', 9407356), (9407364, 'bne', 9408272), (9407656, 'beq', 9408264), (9407736, 'beq', 9407748), (9407868, 'beq', 9408140), (9407964, 'beq', 9408076), (9408140, 'b', 9408144), (9408168, 'blo', 9407700), (9408260, 'bne', 9407700), (9408264, 'b', 9408268), (9408268, 'b', 9408272)],
        semantics=('clientDisconnected:simulate: cleans up after a departing client. Prologue 0x008f85a0 (frame 0x2b0; base 0x105faf4). Arguments: client [fp,8], simulate byte [fp,-0xc5].\nGate: client == 0 exits at 0x8f8f58. Pass 1: enumerate netBlockheads ffffe4f4 (cell 0x8f8f68, @0x8f85f8); per bh `[bh clientID]` (ffe23444 cell 0x8f8f70) compared with the client argument (@0x8f873c-0x8f8758); on match `for i in 0..9` (cmp 9 @0x8f876c) with the 9-arm SWITCH jump table (cells 0x8f8f90 0xffdeaf9c + 0x8f8f94 0x767368 -> table @ 0x00E4AA90, dispatch @0x8f878c): the ffffe54c map segments (cell 0x8f8f98, 12-byte stride @0x8f87a4) are tree-iterated (std::__tree_next @0x8f894c); per node the ffe236f0 call (cell 0x8f8f9c) runs with the pos member and `[obj uniqueID]` (ffe2332c cell 0x8f8fa0) per node.\nSimulate branch: when [fp,-0xc5] != 0 the path skips to 0x8f8f10; otherwise the ffffe5ac dict (cell 0x8f8f78) is lazily created (`[[NSMutableDictionary alloc] init]`, cells 0x8f8f7c/0x8f8f80/0x8f8f84) and stored back (@0x8f8a04), then the ffe233d4 call (cell 0x8f8f88) runs against it. Pass 2: enumerate ffffe4f0 (cell 0x8f8fa4, @0x8f8bac): per item `[item clientID]` compared (cell 0x8f8f70), then the flag pair ffe232f4/ffe232f0 (cells 0x8f8fb0/0x8f8fb4) and the pair ffe232fc/ffe232f8 (cells 0x8f8fb8/0x8f8fbc) run - the same pairs clientConnected sets. Exit 0x8f8f08/0x8f8f10.\n'),
    ),
    dict(
        name='dyn_freeblock_fg',
        method='DynamicWorld -[createFreeBlockAtPosition:forForegroundContents:forTile:priorityBlockhead:]',
        types='v28@0:4{?=ii}8c16^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}20@24',
        start=9300096,
        end=9302020,
        disasm='disasm_worldtileloader_createfreeblockatposition_forforegroundcontents_fortile_prio.txt',
        base_add=9300112,
        base_literal=9302016,
        boundary='ARM.exidx end 0x008df004 (listing bound); next ObjC IMP 0x008df2a8 DynamicWorld -[freeblockWithUniqueID:]',
        selectors={
                 0x8def98: (15216740, 'interactionObjectAtPos:'),
                 0x8defa4: (15216744, 'destroyItemType'),
                 0x8defac: (15216272, 'getSaveDict'),
                 0x8defb0: (15216388, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
                 0x8defb4: (15216528, 'setNeedsRemoved:'),
                 0x8defb8: (15216340, 'workbenchAtPos:'),
                 0x8defc0: (15216512, 'type'),
                 0x8defc8: (15216304, 'level'),
                 0x8defcc: (15216732, 'wireAtPos:'),
                 0x8defd4: (15216728, 'torchAtPos:'),
                 0x8defdc: (15216724, 'stairsAtPos:'),
                 0x8defe4: (15216720, 'columnAtPos:'),
                 0x8defec: (15216716, 'paintingAtPos:'),
                 0x8deff8: (15216440, 'clientID'),
                 0x8deffc: (15216736, 'tileIsLitForClient:atPos:tile:'),
        },
        imports={
                 0x8defa0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8def90: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
        },
        classes={},
        instructions=[(9300096, 'push {r4, r5, r6, sl, fp, lr}'), (9300296, 'bl sym.itemTypeFromTileIsForegorund_Tile__intpair__signed_char__World_'), (9300328, 'bl sym.itemTypeIsPainting_ItemType_'), (9300632, 'cmp r0, 0xb2'), (9301076, 'bl sym.tileIsWorkbench_Tile_'), (9301328, 'bl 0x8df004'), (9301488, 'ldrb r0, [r0, 3]'), (9302016, 'rsbseq r1, r8, ip, asr r2')],
        calls=[(9300296, 'bl sym.itemTypeFromTileIsForegorund_Tile__intpair__signed_char__World_'), (9300328, 'bl sym.itemTypeIsPainting_ItemType_'), (9300388, 'bl loc.imp.objc_msgSend'), (9300404, 'bl sym.itemTypeIsColumn_ItemType_'), (9300464, 'bl loc.imp.objc_msgSend'), (9300480, 'bl sym.itemTypeIsStairs_ItemType_'), (9300540, 'bl loc.imp.objc_msgSend'), (9300556, 'bl sym.itemTypeIsTorch_ItemType_'), (9300616, 'bl loc.imp.objc_msgSend'), (9300684, 'bl loc.imp.objc_msgSend'), (9300796, 'blx r2'), (9300884, 'bl loc.imp.objc_msgSend'), (9300960, 'bl loc.imp.objc_msgSend'), (9301064, 'bl loc.imp.objc_msgSend'), (9301076, 'bl sym.tileIsWorkbench_Tile_'), (9301160, 'bl loc.imp.objc_msgSend'), (9301276, 'bl loc.imp.objc_msgSend'), (9301308, 'bl loc.imp.objc_msgSend'), (9301328, 'bl 0x8df004'), (9301360, 'bl loc.imp.objc_msgSend'), (9301448, 'bl loc.imp.objc_msgSend'), (9301476, 'blx r3'), (9301568, 'bl loc.imp.objc_msgSend'), (9301632, 'blx r2'), (9301700, 'bl loc.imp.objc_msgSend'), (9301732, 'bl loc.imp.objc_msgSend'), (9301820, 'bl loc.imp.objc_msgSend'), (9301884, 'blx ip')],
        branches=[(9300172, 'beq', 9300208), (9300188, 'bne', 9300208), (9300200, 'bne', 9300208), (9300204, 'b', 9301896), (9300312, 'beq', 9301072), (9300340, 'beq', 9300400), (9300396, 'b', 9300708), (9300416, 'beq', 9300476), (9300472, 'b', 9300704), (9300492, 'beq', 9300552), (9300548, 'b', 9300700), (9300568, 'beq', 9300628), (9300624, 'b', 9300696), (9300636, 'bne', 9300692), (9300692, 'b', 9300696), (9300696, 'b', 9300700), (9300700, 'b', 9300704), (9300704, 'b', 9300708), (9300752, 'beq', 9300808), (9300804, 'b', 9300820), (9300816, 'b', 9300820), (9301068, 'b', 9301896), (9301088, 'beq', 9301484), (9301180, 'beq', 9301480), (9301480, 'b', 9301892), (9301496, 'bne', 9301888), (9301588, 'beq', 9301824), (9301640, 'beq', 9301824), (9301888, 'b', 9301892), (9301892, 'b', 9301896)],
        semantics=('createFreeBlockAtPosition:forForegroundContents:forTile:priorityBlockhead: creates the drop for a broken foreground tile. Prologue 0x008de880 (frame 0x120).\nGates: argument byte [fp,-0x21]; when [tile] is non-null with byte0 == 0x10 and the flag is clear the flow continues (@0x8de8c4-0x8de8ec).\nItem resolution: `itemTypeFromTileIsForegorund(Tile*, intpair, signed char, World*)` (C call @0x8de948, world via ffffe4e4) resolves the item type; then the classifier ladder: `itemTypeIsPainting(ItemType)` (@0x8de968), `itemTypeIsColumn` (@0x8de9b4), `itemTypeIsStairs` (@0x8dea00), `itemTypeIsTorch` (@0x8dea4c) and the literal `cmp r0, 0xb2` (@0x8dea98) route into the per-class arms (cells ffe23558/ffe2355c/ffe23560/ffe23564/ffe23568 with string refs 0xfff34064 family).\nCreation: the ffe2339c call (cell 0x8defac) + the ffe23444 clientID read (cell 0x8deff8) + the ffe2356c call with the uxtb flag (@0x8debd4-0x8debec) then the 8-arg create ffe23410 (cell 0x8defb0) with the packed args (obj/0/0/0/flag/..) @0x8dec04-0x8dec48.\nWorkbench special: `tileIsWorkbench(Tile*)` (C call @0x8dec54) opens the workbench path: the ffe233e0 macro lookup (cell 0x8defb8), ffe2349c (cell 0x8defb4), ffe2348c (cell 0x8defc0), the local helper `bl 0x8df004`, ffe233bc (cell 0x8defc8) and a second ffe23410 create with flag 1 (@0x8ded78-0x8dede8). The tile byte 0x30 arm (@0x8dedf0) runs the ffe23570/ffe23574 chain + another ffe23410 create with flag 1 (@0x8def00-0x8def3c) and closes with ffe2349c (cell 0x8defb4). Epilogue 0x8def88.\n'),
    ),
    dict(
        name='dyn_freeblock_full',
        method='DynamicWorld -[createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:]',
        types='v48@0:4{?=ii}8i16S20S24@28@32c36i40@44',
        start=9297016,
        end=9299536,
        disasm='disasm_worldtileloader_createfreeblockatposition_oftype_dataa_datab_subitems_dynami.txt',
        base_add=9297032,
        base_literal=9299532,
        boundary='ARM.exidx end 0x008de650 (listing bound); next ObjC IMP 0x008de650 DynamicWorld -[playTimeCrystalReceivedSoundAtPos:]',
        selectors={
                 0x8de5c4: (15215804, 'alloc'),
                 0x8de5d0: (15216704, 'initWithWorld:dynamicWorld:atPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:cache:hovers:priorityBlockhead:'),
                 0x8de5dc: (15216712, 'setSoundType:'),
                 0x8de5e0: (15216708, 'setCreationSoundPlayTime:'),
                 0x8de5e4: (15216488, 'worldTime'),
                 0x8de5f4: (15216060, 'instance'),
                 0x8de5f8: (15216500, 'multiSoundNamed:'),
                 0x8de600: (15216504, 'playAtPosition:afterDelay:'),
                 0x8de620: (15216012, 'pos'),
                 0x8de62c: (15216160, 'uniqueID'),
                 0x8de630: (15216020, 'sendNetDataIfNeededForObject:isCreation:'),
                 0x8de63c: (15216008, 'addObject:'),
                 0x8de648: (15216700, 'creationNetDataForFreeblockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:priorityBlockhead:soundType:creationSoundPlayTime:'),
        },
        imports={
                 0x8de5d8: (17151904, 'objc_msgSend'),
                 0x8de5fc: (16333736, '__CFConstantStringClassReference'),
                 0x8de608: (16333720, '__CFConstantStringClassReference'),
                 0x8de610: (16333704, '__CFConstantStringClassReference'),
                 0x8de618: (16333688, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x8de5b8: (17162252, 'OBJC_IVAR_$_DynamicWorld.client', 20),
                 0x8de5c8: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8de5cc: (17162232, 'OBJC_IVAR_$_DynamicWorld.cache', 7336),
                 0x8de5d4: (17162392, 'OBJC_IVAR_$_DynamicWorld.freeBlockSoundDelay', 7364),
                 0x8de624: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8de638: (17162364, 'OBJC_IVAR_$_DynamicWorld.freeBlocksByPosition', 2400),
                 0x8de640: (17162268, 'OBJC_IVAR_$_DynamicWorld.clientFreeblockArrayToSend', 8412),
        },
        classes={
                 0x8de5bc: (15247872, 'OBJC_CLASS_$_FreeBlock'),
                 0x8de5ec: (15247876, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(9297016, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9297136, 'cmp r1, 0xb'), (9297384, 'vmov d0, r0, r1'), (9298036, 'vcmpe.f32 s0, s4'), (9298240, 'ldr r0, [0x008de5ec]'), (9298932, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9299180, 'bl method.std::__1::map_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.operator___unsigned_long_long_'), (9299236, 'bl method.std::__1::pair_std::__1::__tree_iterator_DynamicObject__std::__1::__tree_node_DynamicObject__void___int___bool__std::__1::__tree_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject___.__insert_unique_DynamicObject__DynamicObject_'), (9299532, 'rsbseq r1, r8, r4, ror 28')],
        calls=[(9297380, 'bl loc.imp.objc_msgSend'), (9297500, 'bl loc.imp.objc_msgSend'), (9297544, 'blx ip'), (9297584, 'bl loc.imp.objc_msgSend'), (9297796, 'bl loc.imp.objc_msgSend'), (9297948, 'blx r3'), (9297984, 'blx r3'), (9298008, 'blx r3'), (9298092, 'bl loc.imp.objc_msgSend'), (9298116, 'bl loc.imp.objc_msgSend'), (9298156, 'bl method.Vector2.Vector2_float__float_'), (9298220, 'bl loc.imp.objc_msgSend'), (9298272, 'bl loc.imp.objc_msgSend'), (9298296, 'bl loc.imp.objc_msgSend'), (9298336, 'bl method.Vector2.Vector2_float__float_'), (9298400, 'bl loc.imp.objc_msgSend'), (9298496, 'bl loc.imp.objc_msgSend'), (9298520, 'bl loc.imp.objc_msgSend'), (9298560, 'bl method.Vector2.Vector2_float__float_'), (9298624, 'bl loc.imp.objc_msgSend'), (9298664, 'bl loc.imp.objc_msgSend'), (9298688, 'bl loc.imp.objc_msgSend'), (9298728, 'bl method.Vector2.Vector2_float__float_'), (9298792, 'bl loc.imp.objc_msgSend'), (9298912, 'bl loc.imp.objc_msgSend'), (9298932, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9298996, 'bl loc.imp.objc_msgSend_stret'), (9299032, 'bl sym.imp.memset'), (9299120, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9299180, 'bl method.std::__1::map_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.operator___unsigned_long_long_'), (9299236, 'bl method.std::__1::pair_std::__1::__tree_iterator_DynamicObject__std::__1::__tree_node_DynamicObject__void___int___bool__std::__1::__tree_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject___.__insert_unique_DynamicObject__DynamicObject_'), (9299372, 'blx lr')],
        branches=[(9297144, 'bne', 9297152), (9297148, 'b', 9299376), (9297188, 'beq', 9297552), (9297548, 'b', 9299376), (9297812, 'beq', 9298848), (9298044, 'bpl', 9298844), (9298056, 'bne', 9298228), (9298224, 'b', 9298804), (9298236, 'bne', 9298408), (9298404, 'b', 9298800), (9298416, 'bne', 9298632), (9298460, 'bpl', 9298632), (9298628, 'b', 9298796), (9298796, 'b', 9298800), (9298800, 'b', 9298804), (9298844, 'b', 9298848), (9298980, 'beq', 9299004), (9299000, 'b', 9299036)],
        semantics=('createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead: is the master FreeBlock factory (nine arguments). Prologue 0x008ddc78 (frame 0x1d8; base 0x105faf4).\nGate: ofType == 0xb returns immediately (@0x8ddcf0). When self.client (ffffe518, cell 0x8de5b8) != 0 the client arm runs: the collection call ffe23294 + class cell ffe2af0c (@0x8ddd28-0x8ddd50) and the packed creation with worldTime as a double converted to float (`vmov d0, r0, r1` + `vcvt.f32.f64` @0x8ddde8-0x8dde10, worldTime cell 0x8de5e4 ffe23474) against the ffffe528 slice (@0x8ddd3c).\nServer/default arm: `[[NSMutableArray alloc] init]` pair (cells ffe2af0c + ffe231c8 @0x8dde90-0x8ddeb0), the ffffe504 slice (cell 0x8de5cc), then the second packed creation call (ffe2354c cell 0x8de5d0; args incl. the subItems/type fields at +0x0..+0x24 with sxtb/uxth conversions @0x8ddf34-0x8ddf84); when the result is zero the flow skips to registration (0x8de3a0).\nPost-creation: the ffffe5a4 float field (cell 0x8de5d4) is compared against 1.0 (`vcmpe.f32 s0, s4` @0x8de074-0x8de07c; skip when >= 1.0) and the creation flag r0 selects the SOUND: r0 == 1 -> 0xfff34074 voice? no - r0 == 1 path @0x8de084-0x8de0e4 (cells ffe2af10/ffe232c8/ffe23480); r0 == 3 -> sound string 0xfff34094 (@0x8de140-0x8de1e0, Vector2(pos) + worldTime double -> the playback call ffe23484 cell 0x8de600); r0 == 4 -> gated by the ffffe5a4 field < const (cell 0x8de5e8) -> sound 0xfff340a4 (@0x8de220-0x8de2c0); else -> sound 0xfff340b4 (@0x8de2c8-0x8de368). Each playback builds Vector2(pos) (C++ ctor calls @0x8de1a0/0x8de280/0x8de328) and passes worldTime as double. Then the ffffe5a4 field accumulates a const (cell 0x8de61c, `vadd` @0x8de374-0x8de398).\nRegistration (0x8de3a0+): the ffffe54c map +0xa8 slice (cell 0x8de624/0x8de628) with `[obj uniqueID]` (cell 0x8de62c ffe2332c) -> `std::__1::map<unsigned long long, DynamicObject*>::operator[](u64&&)` (@0x8de3f4) stores the object; the object pos (stret getter ffe23298 cell 0x8de620) feeds `worldIndexAtWorldPos(intpair, World*)` (@0x8de4b0) -> `std::__1::map<unsigned long long, std::__1::set<DynamicObject*>>::operator[](u64&&)` on the ffffe588 map (cell 0x8de638, @0x8de4ec) -> `std::__1::__tree<DynamicObject*>::__insert_unique` (@0x8de524) - the position registration the E22 unloader later erases; closes with the ffe232a0 call (cell 0x8de630) + sxtb flag (@0x8de45c-0x8de5a8). Epilogue 0x8de5b0.\n'),
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
        'batch': 'DynamicWorld object query & lifecycle cluster (E24): dealloc, remoteRemove:forObjectsOfType:fromClient:, doRepairForTileAtPos:, blockheadAtPos:, blockheadOccupiesTileAtPos:ignoreBlockhead:, interactionObjectAtPos:, clientDisconnected:simulate: and the two createFreeBlockAtPosition: factories; 9 bodies',
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
                        default=NATIVE / 'object_life.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale object_life.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
