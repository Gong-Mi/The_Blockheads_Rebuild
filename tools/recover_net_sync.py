#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld net-sync + blockhead-load cluster (E21).

The DynamicWorld multiplayer-sync cluster: the dirty-macro-tile flush, the 65-slot
network reconciliation loop, the per-object packet sender, the disconnected-client
blockhead restore, the client inventory receiver and the client blockhead-data
loader:
1 body, 10076 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/NET_SYNC.md for the prose and boundaries.
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
    'bl 0x8b84c8': 0x008b84c8,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_': 0x008bcf24,
    'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_': 0x008bcb78,
    'bl method.std::__1::map_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.operator___unsigned_long_long_': 0x008bd2e4,
    'bl method.std::__1::pair_std::__1::__tree_iterator_DynamicObject__std::__1::__tree_node_DynamicObject__void___int___bool__std::__1::__tree_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject___.__insert_unique_DynamicObject__DynamicObject_': 0x0090c82c,
    'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const': 0x00910a74,
    'bl sym.classForDynamicObjectType_int_': 0x00b597bc,
    'bl sym.classForInteractionObjectType_unsigned_short_': 0x005f3f50,
    'bl sym.imp.NSLog': 0x001c2a5c,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__aeabi_memmove': 0x001c3f08,
    'bl sym.imp.__stack_chk_fail': 0x001c28b8,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.macroPosForWorldPos_intpair__World_': 0x00a16594,
    'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_': 0x00a16ccc,
    'bl sym.objectTypeHasStaticPosition_int_': 0x008b68ac,
    'bl sym.objectTypeIsInteractionObject_int_': 0x008bcacc,
    'bl sym.worldIndexAtWorldPos_intpair__World_': 0x00a15838,
}

SPECS = [
    dict(
        name='wtl_saveandsendonlyblockst',
        method='DynamicWorld -[saveAndSendOnlyBlocksThatNeedToBeSent]',
        types='v8@0:4',
        start=9128440,
        end=9130752,
        disasm='disasm_worldtileloader_saveandsendonlyblocksthatneedtobesent.txt',
        base_add=9128456,
        base_literal=9130748,
        boundary='ARM.exidx end 0x008b5300 (listing bound); next ObjC IMP 0x008b5300 DynamicWorld -[initialDynamicObjectsNetDataForMacroTileIndex:wireForClient:]',
        selectors={
                 0x8b52e4: (15216036, 'macroTiles'),
                 0x8b52ec: (15216124, 'savePhysicalBlockForMacroTile:sendReliably:dontSend:onlySaveIfClientsNeedIt:'),
        },
        imports={
                 0x8b52e0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8b52d8: (17162256, 'OBJC_IVAR_$_DynamicWorld.server', 16),
                 0x8b52dc: (17162340, 'OBJC_IVAR_$_DynamicWorld.worldChangedMacroPositions', 7320),
                 0x8b52e8: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8b52f4: (17162344, 'OBJC_IVAR_$_DynamicWorld.worldChangedSendUnreliablyMacroPositions', 6084),
        },
        classes={},
        instructions=[(9128440, 'push {r4, r5, r6, sl, fp, lr}'), (9128572, 'cmp r0, 0'), (9129056, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (9129180, 'str r4, [sp]'), (9129464, 'bl sym.imp.__aeabi_memmove'), (9129780, 'movw r0, 3'), (9130748, 'rsbseq fp, sl, r4, ror 1')],
        calls=[(9128568, 'bl sym.imp.__aeabi_idiv'), (9128672, 'blx lr'), (9129056, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (9129196, 'blx r4'), (9129464, 'bl sym.imp.__aeabi_memmove'), (9129840, 'bl sym.imp.__aeabi_idiv'), (9129936, 'blx lr'), (9130088, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (9130228, 'blx r4'), (9130496, 'bl sym.imp.__aeabi_memmove')],
        branches=[(9128504, 'beq', 9130704), (9128576, 'bls', 9129780), (9128956, 'beq', 9129776), (9129076, 'beq', 9129704), (9129212, 'beq', 9129700), (9129548, 'beq', 9129644), (9129640, 'b', 9129532), (9129688, 'blt', 9129696), (9129692, 'b', 9129776), (9129696, 'b', 9129700), (9129700, 'b', 9129704), (9129712, 'beq', 9129772), (9129772, 'b', 9128784), (9129776, 'b', 9129780), (9129848, 'bls', 9130700), (9130108, 'beq', 9130696), (9130244, 'beq', 9130692), (9130580, 'beq', 9130676), (9130672, 'b', 9130564), (9130692, 'b', 9130696), (9130696, 'b', 9130700), (9130700, 'b', 9130704)],
        semantics=('saveAndSendOnlyBlocksThatNeedToBeSent flushes the dirty-macro-tile queues after networking has been updated. Prologue 0x008b49f8. Gate: [self server] (cell 0x008b52d8) must be non-NULL, else return (0x008b52d0).\nPass 1 (0x008b4a3c-0x8b4f2c): the worldChangedMacroPositions vector (cell 0x008b52dc; libc++ vector of 3-counted records) is checked for length ((end-start)/3 via __aeabi_idiv) and iterated with the C++ iterator protocol ([sp,0xd0]); per entry: the macro position pair drives `macroTileAtMacroPostion(x, y, macroTile, world)` (route 0x008b4c60, macroTiles fetch cell 0x008b52e4, world cell 0x008b52e8); a NULL tile skips the entry; otherwise `[world savePhysicalBlockForMacroTile:macroTile sendReliably:1 dontSend:0 onlySaveIfClientsNeedIt:1]` (selector cell 0x008b52ec) is dispatched; a nonzero result byte erases the entry through the libc++ vector erase path (__aeabi_memmove at 0x008b4df8 with the 8-byte stride and iterator fixups 0x008b4e3c-0x008b4ea8) and sets the progress flag [sp,0xbf] (loop guard cmp 4 at 0x8b4ec8).\nPass 2 (0x008b4f34): the same protocol over worldChangedSendUnreliablyMacroPositions (cell 0x008b52f4) with `savePhysicalBlockForMacroTile:... sendReliably:0 ...` (the unreliable queue); success erases (0x8b5160+ memmove path) and [sp,0x7b] records the result; both passes exit at 0x8b52cc/0x8b52d0.\n'),
    ),
    dict(
        name='wtl_updatenetobjects',
        method='DynamicWorld -[updateNetObjects]',
        types='v8@0:4',
        start=9194528,
        end=9207780,
        disasm='disasm_worldtileloader_updatenetobjects.txt',
        base_add=9194548,
        base_literal=9198604,
        boundary='ARM.exidx end 0x008c7fe4 (listing bound); next ObjC IMP 0x008c7fe4 DynamicWorld -[sendNetDataIfNeededForObject:isCreation:]',
        selectors={
                 0x8c5c1c: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8c5da8: (15215884, 'objectForKey:'),
                 0x8c5dac: (15215864, 'count'),
                 0x8c5db0: (15216456, 'indexSet'),
                 0x8c5db8: (15216436, 'getBytes:length:'),
                 0x8c5dbc: (15216308, 'addIndex:'),
                 0x8c62f4: (15215992, 'blockheadWithIDIncludingNet:'),
                 0x8c63d8: (15216280, 'isEqualToString:'),
                 0x8c63dc: (15216464, 'localNetID'),
                 0x8c63e0: (15216440, 'clientID'),
                 0x8c63e4: (15215968, 'autorelease'),
                 0x8c63e8: (15216460, 'initWithWorld:dynamicWorld:cache:netData:'),
                 0x8c63f4: (15215804, 'alloc'),
                 0x8c6568: (15215852, 'release'),
                 0x8c656c: (15216468, 'removeFromMacroBlock'),
                 0x8c6570: (15216472, 'setClientID:'),
                 0x8c6574: (15216476, 'playerInfoForPeerID:'),
                 0x8c6740: (15216480, 'setClientName:'),
                 0x8c6744: (15216008, 'addObject:'),
                 0x8c674c: (15216012, 'pos'),
                 0x8c6750: (15216020, 'sendNetDataIfNeededForObject:isCreation:'),
                 0x8c6760: (15216484, 'lightBlockIndex'),
                 0x8c6964: (15216016, 'fullyLoadIfNeededAroundPos:clientLightBlockIndex:forBlockhead:'),
                 0x8c6cec: (15216160, 'uniqueID'),
                 0x8c6cf0: (15216492, 'creationSoundPlayTime'),
                 0x8c6cf4: (15216488, 'worldTime'),
                 0x8c6d04: (15216452, 'itemType'),
                 0x8c6d08: (15216496, 'soundType'),
                 0x8c6d14: (15216060, 'instance'),
                 0x8c6d18: (15216500, 'multiSoundNamed:'),
                 0x8c6d20: (15216504, 'playAtPosition:afterDelay:'),
                 0x8c72e4: (15216508, 'waitingForBlocks'),
                 0x8c72f4: (15216512, 'type'),
                 0x8c7e00: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8c7e04: (15216516, 'removeObjectsAtIndexes:'),
                 0x8c7e10: (15215864, 'count'),
                 0x8c7fa8: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8c7fac: (15215864, 'count'),
                 0x8c7fb0: (15216436, 'getBytes:length:'),
                 0x8c7fb8: (15216160, 'uniqueID'),
                 0x8c7fc0: (15216520, 'remoteCreationDataUpdate:'),
                 0x8c7fc8: (15216096, 'removeAllObjects'),
                 0x8c7fd4: (15216524, 'remoteUpdate:'),
                 0x8c7fdc: (15216528, 'setNeedsRemoved:'),
        },
        imports={
                 0x8c5c18: (17151904, 'objc_msgSend'),
                 0x8c6564: (16333640, '__CFConstantStringClassReference'),
                 0x8c673c: (16333656, '__CFConstantStringClassReference'),
                 0x8c6d1c: (16333672, '__CFConstantStringClassReference'),
                 0x8c6d28: (16333688, '__CFConstantStringClassReference'),
                 0x8c6d30: (16333704, '__CFConstantStringClassReference'),
                 0x8c72d8: (16333720, '__CFConstantStringClassReference'),
                 0x8c72e0: (16333736, '__CFConstantStringClassReference'),
                 0x8c78a0: (17151904, 'objc_msgSend'),
                 0x8c7fa4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8c5c10: (17162256, 'OBJC_IVAR_$_DynamicWorld.server', 16),
                 0x8c5c14: (17162252, 'OBJC_IVAR_$_DynamicWorld.client', 20),
                 0x8c5c20: (17162300, 'OBJC_IVAR_$_DynamicWorld.netRemoveDynamicObjects', 8152),
                 0x8c5c28: (17162288, 'OBJC_IVAR_$_DynamicWorld.netCreateDynamicObjects', 7372),
                 0x8c6238: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8c623c: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
                 0x8c63ec: (17162232, 'OBJC_IVAR_$_DynamicWorld.cache', 7336),
                 0x8c63f0: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8c6748: (17162216, 'OBJC_IVAR_$_DynamicWorld.netBlockheads', 48),
                 0x8c6754: (17162248, 'OBJC_IVAR_$_DynamicWorld.serverClients', 24),
                 0x8c6cfc: (17162364, 'OBJC_IVAR_$_DynamicWorld.freeBlocksByPosition', 2400),
                 0x8c6d00: (17162392, 'OBJC_IVAR_$_DynamicWorld.freeBlockSoundDelay', 7364),
                 0x8c72f0: (17162312, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsByWorldPosIndex', 1620),
                 0x8c72f8: (17162316, 'OBJC_IVAR_$_DynamicWorld.workbenchHasBeenCrafted', 7370),
                 0x8c7890: (17162204, 'OBJC_IVAR_$_DynamicWorld.portalPositions', 7332),
                 0x8c78a4: (17162252, 'OBJC_IVAR_$_DynamicWorld.client', 20),
                 0x8c7e08: (17162296, 'OBJC_IVAR_$_DynamicWorld.netUpdateCreationDataDynamicObjects', 7892),
                 0x8c7fb4: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8c7fbc: (17162216, 'OBJC_IVAR_$_DynamicWorld.netBlockheads', 48),
                 0x8c7fcc: (17162292, 'OBJC_IVAR_$_DynamicWorld.netUpdateDynamicObjects', 7632),
        },
        classes={
                 0x8c5db4: (15247788, 'OBJC_CLASS_$_NSMutableIndexSet'),
                 0x8c63f8: (15247828, 'OBJC_CLASS_$_Blockhead'),
                 0x8c6c00: (15247872, 'OBJC_CLASS_$_FreeBlock'),
                 0x8c6d0c: (15247876, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(9194528, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9194648, 'movw r0, 0'), (9198636, 'ldr r0, [fp, -0x108]'), (9198936, 'ldr r0, [sp, 0x360]'), (9199688, 'beq 0x8c6064'), (9202720, 'bl sym.imp.memset'), (9203456, 'movw r0, 0'), (9204904, 'movw r0, 0'), (9206356, 'movw r0, 0'), (9207100, 'movw r0, 1'), (9207392, 'add r4, sp, 0x400'), (9207776, 'ldrsbteq r7, [sb], -0xdc')],
        calls=[(9194836, 'bl sym.imp.memset'), (9194884, 'blx lr'), (9194984, 'bl sym.imp.objc_enumerationMutation'), (9195076, 'blx r3'), (9195140, 'blx r2'), (9195272, 'blx r2'), (9195308, 'bl sym.imp.memset'), (9195356, 'blx lr'), (9195456, 'bl sym.imp.objc_enumerationMutation'), (9195540, 'blx ip'), (9195616, 'blx r3'), (9195716, 'bl sym.imp.memset'), (9195764, 'blx lr'), (9195864, 'bl sym.imp.objc_enumerationMutation'), (9195908, 'bl loc.imp.objc_msgSend'), (9196064, 'blx ip'), (9196156, 'blx r3'), (9196236, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9196308, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9196368, 'blx r3'), (9196444, 'bl loc.imp.objc_msgSend'), (9196508, 'blx r3'), (9196692, 'blx r5'), (9196776, 'blx lr'), (9196792, 'blx r2'), (9196816, 'blx r2'), (9196856, 'blx r3'), (9196888, 'blx r3'), (9196916, 'bl sym.imp.NSLog'), (9197000, 'blx r4'), (9197020, 'blx r2'), (9197060, 'blx ip'), (9197168, 'blx r3'), (9197308, 'blx r3'), (9197388, 'blx r3'), (9197456, 'blx r3'), (9197528, 'blx r3'), (9197636, 'blx r3'), (9197660, 'blx r3'), (9197776, 'bl loc.imp.objc_msgSend_stret'), (9197812, 'bl sym.imp.memset'), (9197904, 'bl loc.imp.objc_msgSend'), (9197920, 'bl loc.imp.objc_msgSend'), (9197976, 'bl loc.imp.objc_msgSend'), (9198020, 'blx ip'), (9198084, 'blx r2'), (9198176, 'bl sym.imp.memset'), (9198224, 'blx lr'), (9198324, 'bl sym.imp.objc_enumerationMutation'), (9198368, 'bl loc.imp.objc_msgSend'), (9198460, 'blx r3'), (9198564, 'blx ip'), (9198752, 'blx r5'), (9198836, 'blx lr'), (9198924, 'bl loc.imp.objc_msgSend'), (9198944, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9199008, 'bl loc.imp.objc_msgSend_stret'), (9199068, 'bl sym.imp.memset'), (9199216, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9199276, 'bl method.std::__1::map_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.operator___unsigned_long_long_'), (9199332, 'bl method.std::__1::pair_std::__1::__tree_iterator_DynamicObject__std::__1::__tree_node_DynamicObject__void___int___bool__std::__1::__tree_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject___.__insert_unique_DynamicObject__DynamicObject_'), (9199460, 'blx ip'), (9199496, 'blx r3'), (9199524, 'blx r2'), (9199704, 'bl loc.imp.objc_msgSend_stret'), (9199744, 'bl sym.imp.memset'), (9199800, 'blx r3'), (9199824, 'blx r2'), (9199868, 'bl loc.imp.objc_msgSend'), (9199892, 'bl loc.imp.objc_msgSend'), (9199932, 'bl method.Vector2.Vector2_float__float_'), (9199996, 'bl loc.imp.objc_msgSend'), (9200048, 'bl loc.imp.objc_msgSend'), (9200072, 'bl loc.imp.objc_msgSend'), (9200112, 'bl method.Vector2.Vector2_float__float_'), (9200176, 'bl loc.imp.objc_msgSend'), (9200236, 'bl loc.imp.objc_msgSend'), (9200260, 'bl loc.imp.objc_msgSend'), (9200300, 'bl method.Vector2.Vector2_float__float_'), (9200364, 'bl loc.imp.objc_msgSend'), (9200464, 'bl loc.imp.objc_msgSend'), (9200488, 'bl loc.imp.objc_msgSend'), (9200528, 'bl method.Vector2.Vector2_float__float_'), (9200592, 'bl loc.imp.objc_msgSend'), (9200668, 'bl loc.imp.objc_msgSend'), (9200692, 'bl loc.imp.objc_msgSend'), (9200732, 'bl method.Vector2.Vector2_float__float_'), (9200796, 'bl loc.imp.objc_msgSend'), (9200920, 'blx r2'), (9200984, 'blx r3'), (9201024, 'bl sym.objectTypeIsInteractionObject_int_'), (9201092, 'blx ip'), (9201104, 'bl sym.classForInteractionObjectType_unsigned_short_'), (9201196, 'blx r2'), (9201280, 'blx lr'), (9201376, 'bl loc.imp.objc_msgSend'), (9201396, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9201460, 'bl loc.imp.objc_msgSend_stret'), (9201536, 'bl sym.imp.memset'), (9201592, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9201668, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9201724, 'blx r3'), (9201784, 'blx r2'), (9201868, 'blx r2'), (9201920, 'blx r2'), (9202012, 'bl loc.imp.objc_msgSend_stret'), (9202052, 'bl sym.imp.memset'), (9202092, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9202148, 'blx r3'), (9202220, 'blx r2'), (9202284, 'blx r3'), (9202304, 'bl sym.classForDynamicObjectType_int_'), (9202396, 'blx r2'), (9202480, 'blx lr'), (9202576, 'bl loc.imp.objc_msgSend'), (9202596, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9202612, 'bl sym.objectTypeHasStaticPosition_int_'), (9202680, 'bl loc.imp.objc_msgSend_stret'), (9202720, 'bl sym.imp.memset'), (9202776, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9202852, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9202912, 'blx r3'), (9203056, 'blx r2'), (9203120, 'blx r3'), (9203248, 'blx ip'), (9203324, 'blx r3'), (9203428, 'blx ip'), (9203564, 'blx r2'), (9203664, 'bl sym.imp.memset'), (9203712, 'blx lr'), (9203812, 'bl sym.imp.objc_enumerationMutation'), (9203996, 'blx ip'), (9204016, 'bl sym.imp.memset'), (9204080, 'blx lr'), (9204180, 'bl sym.imp.objc_enumerationMutation'), (9204216, 'bl loc.imp.objc_msgSend'), (9204300, 'blx r3'), (9204404, 'blx ip'), (9204560, 'blx ip'), (9204616, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9204676, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_'), (9204724, 'blx r3'), (9204832, 'blx ip'), (9204900, 'blx r2'), (9205012, 'blx r2'), (9205120, 'bl sym.imp.memset'), (9205168, 'blx lr'), (9205272, 'bl sym.imp.objc_enumerationMutation'), (9205452, 'blx ip'), (9205472, 'bl sym.imp.memset'), (9205536, 'blx lr'), (9205640, 'bl sym.imp.objc_enumerationMutation'), (9205676, 'bl loc.imp.objc_msgSend'), (9205760, 'blx r3'), (9205872, 'blx ip'), (9206008, 'blx ip'), (9206064, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9206120, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_'), (9206168, 'blx r3'), (9206284, 'blx ip'), (9206352, 'blx r2'), (9206412, 'blx r2'), (9206516, 'bl sym.imp.memset'), (9206564, 'blx lr'), (9206668, 'bl sym.imp.objc_enumerationMutation'), (9206756, 'blx ip'), (9206864, 'bl sym.imp.memset'), (9206928, 'blx lr'), (9207028, 'bl sym.imp.objc_enumerationMutation'), (9207064, 'bl loc.imp.objc_msgSend'), (9207160, 'blx ip'), (9207264, 'blx ip'), (9207380, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9207440, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_'), (9207504, 'blx lr'), (9207616, 'blx ip'), (9207684, 'blx r2')],
        branches=[(9194600, 'bne', 9194648), (9194640, 'bne', 9194648), (9194644, 'b', 9207708), (9194668, 'bge', 9207708), (9194896, 'beq', 9203452), (9194976, 'beq', 9194988), (9195096, 'beq', 9203328), (9195148, 'bls', 9203328), (9195368, 'beq', 9203272), (9195448, 'beq', 9195460), (9195564, 'beq', 9195636), (9195632, 'b', 9203152), (9195776, 'beq', 9196088), (9195856, 'beq', 9195868), (9195944, 'bne', 9195964), (9195948, 'b', 9195952), (9195960, 'b', 9196092), (9195964, 'b', 9195968), (9195992, 'blo', 9195820), (9196084, 'bne', 9195820), (9196088, 'b', 9196092), (9196104, 'beq', 9196176), (9196172, 'b', 9203152), (9196244, 'bne', 9196320), (9196316, 'beq', 9196388), (9196384, 'b', 9203152), (9196396, 'bne', 9198636), (9196456, 'beq', 9196528), (9196524, 'b', 9203152), (9196900, 'beq', 9197064), (9197076, 'beq', 9198028), (9197116, 'beq', 9197172), (9197184, 'bne', 9197196), (9197236, 'beq', 9197320), (9197316, 'b', 9197396), (9197476, 'beq', 9197532), (9197692, 'beq', 9198024), (9197760, 'beq', 9197784), (9197780, 'b', 9197816), (9198024, 'b', 9198600), (9198040, 'beq', 9198596), (9198092, 'bls', 9198596), (9198236, 'beq', 9198588), (9198316, 'beq', 9198328), (9198404, 'bne', 9198464), (9198408, 'b', 9198412), (9198464, 'b', 9198468), (9198492, 'blo', 9198280), (9198584, 'bne', 9198280), (9198588, 'b', 9198592), (9198592, 'b', 9198596), (9198596, 'b', 9198600), (9198600, 'b', 9203140), (9198644, 'bne', 9201020), (9198856, 'beq', 9200860), (9198992, 'beq', 9199040), (9199012, 'b', 9199072), (9199568, 'bpl', 9200856), (9199596, 'ble', 9200856), (9199648, 'bpl', 9200852), (9199688, 'beq', 9199716), (9199708, 'b', 9199748), (9199832, 'bne', 9200004), (9200000, 'b', 9200812), (9200012, 'bne', 9200192), (9200180, 'b', 9200808), (9200200, 'bne', 9200376), (9200368, 'b', 9200804), (9200384, 'bne', 9200636), (9200428, 'bpl', 9200636), (9200596, 'b', 9200800), (9200800, 'b', 9200804), (9200804, 'b', 9200808), (9200808, 'b', 9200812), (9200852, 'b', 9200856), (9200856, 'b', 9200992), (9200932, 'bne', 9200988), (9200988, 'b', 9200992), (9200992, 'b', 9203136), (9201036, 'beq', 9202300), (9201300, 'beq', 9202160), (9201444, 'beq', 9201508), (9201464, 'b', 9201540), (9201740, 'bne', 9202156), (9201792, 'beq', 9201828), (9201876, 'beq', 9201932), (9201928, 'bne', 9202152), (9201996, 'beq', 9202024), (9202016, 'b', 9202056), (9202152, 'b', 9202156), (9202156, 'b', 9202292), (9202232, 'bne', 9202288), (9202288, 'b', 9202292), (9202292, 'b', 9203132), (9202500, 'beq', 9202996), (9202624, 'beq', 9202864), (9202664, 'beq', 9202692), (9202684, 'b', 9202724), (9202916, 'b', 9203128), (9203068, 'bne', 9203124), (9203124, 'b', 9203128), (9203128, 'b', 9203132), (9203132, 'b', 9203136), (9203136, 'b', 9203140), (9203176, 'blo', 9195412), (9203268, 'bne', 9195412), (9203272, 'b', 9203276), (9203328, 'b', 9203332), (9203356, 'blo', 9194940), (9203448, 'bne', 9194940), (9203452, 'b', 9203456), (9203520, 'beq', 9204904), (9203572, 'bls', 9204904), (9203724, 'beq', 9204856), (9203804, 'beq', 9203816), (9203852, 'bne', 9204476), (9204092, 'beq', 9204428), (9204172, 'beq', 9204184), (9204244, 'bne', 9204304), (9204248, 'b', 9204252), (9204304, 'b', 9204308), (9204332, 'blo', 9204136), (9204424, 'bne', 9204136), (9204428, 'b', 9204432), (9204432, 'b', 9204732), (9204624, 'bls', 9204728), (9204728, 'b', 9204732), (9204732, 'b', 9204736), (9204760, 'blo', 9203768), (9204852, 'bne', 9203768), (9204856, 'b', 9204860), (9204968, 'beq', 9206356), (9205020, 'bls', 9206356), (9205180, 'beq', 9206308), (9205264, 'beq', 9205276), (9205312, 'bne', 9205928), (9205548, 'beq', 9205896), (9205632, 'beq', 9205644), (9205704, 'bne', 9205764), (9205708, 'b', 9205712), (9205764, 'b', 9205768), (9205792, 'blo', 9205596), (9205892, 'bne', 9205596), (9205896, 'b', 9205900), (9205900, 'b', 9206176), (9206072, 'bls', 9206172), (9206172, 'b', 9206176), (9206176, 'b', 9206180), (9206204, 'blo', 9205228), (9206304, 'bne', 9205228), (9206308, 'b', 9206312), (9206368, 'beq', 9207688), (9206420, 'bls', 9207688), (9206576, 'beq', 9207640), (9206660, 'beq', 9206672), (9206768, 'bne', 9207316), (9206940, 'beq', 9207288), (9207020, 'beq', 9207032), (9207092, 'bne', 9207164), (9207096, 'b', 9207100), (9207164, 'b', 9207168), (9207192, 'blo', 9206984), (9207284, 'bne', 9206984), (9207288, 'b', 9207292), (9207292, 'b', 9207512), (9207388, 'bls', 9207508), (9207508, 'b', 9207512), (9207512, 'b', 9207516), (9207540, 'blo', 9206624), (9207636, 'bne', 9206624), (9207640, 'b', 9207644), (9207688, 'b', 9207692), (9207704, 'b', 9194660)],
        semantics=('updateNetObjects is the per-slot network reconciliation loop (server and client), the frame is 0xba0 bytes. Gate: [self server] == 0 && [self client] == 0 -> return (0x8c4c68-0x8c4c94).\nOuter loop i in 0..0x40 (65, 0x8c4c98): per slot i the body reads netRemoveDynamicObjects[i] (cell 0x8c5c20) into [-0x98] (an NSMutableIndexSet) and netCreateDynamicObjects[i] (cell 0x8c5c28) into [-0x9c], clearing a 0x20-byte enumeration state (memset).\nPhase A (0x8c4d58-0x8c6ef8): enumerate the create slot; per entry: `objectForKey:` (cell 0x8c5da8) -> [-0x104]; a count <= 0 skips (0x8c6e80); `getBytes:length:8` (cell 0x8c5db8 ffe23440) reads the incoming 8-byte object ID into fp-0x190; an eor/orr comparison against the current ID pair sets the match flag [-0x191]; on match the slot index is added to the removal index set via `addIndex:` (cell 0x8c5dbc) and the counter [-0x110] increments. Objects of slot value 0xe instantiate FreeBlocks (0x8c5c2c): `[[FreeBlock alloc] init...]` (class cell 0x8c6c00, init cells 0x8c63e8/0x8c63f4, cache ffe504, world ffe4e4); the object is stored into the dynamicObjectsToAdd +0xa8 map slice via `std::map<u64,DynamicObject*>::operator[]` keyed by `[obj uniqueID]` (cell 0x8c6cec); `[obj pos]` (cell 0x8c674c) feeds worldIndexAtWorldPos and the `std::map<u64, set<DynamicObject*>>` on freeBlocksByPosition (cell 0x8c6cfc) gets the object through `__tree insert_unique`; then the creation-sound ladder (0x8c6048-0x8c64ac): the elapsed `creationSoundPlayTime - worldTime` must lie inside (-4, 4) seconds and the freeBlockSoundDelay (cell 0x8c6d00) must be < 1.0; per objectType (0xb/1/3/4 gates) MJSoundManager `multiSoundNamed:` (cells 0x8c6d18/0x8c6d08) + `playAtPosition:afterDelay:` (cell 0x8c6d20) is dispatched with a Vector2 of the position and the escalating delay (strings 0xfff34074/0x84/0x94/0xa4/0xb4).\nPhase B (0x8c6f00-0x8c7478): netUpdateCreationDataDynamicObjects[i] (cell 0x8c7e08): per entry: 24-byte records (0x18 in cmp at 0x8c7084) come from netBlockheads (cell 0x8c7fbc ffe4f4) via `getBytes:length:0x18`; `[obj uniqueID]` (cell 0x8c7fb8) eor/orr matched against the record -> `remoteCreationDataUpdate:` (cell 0x8c7fc0) on the blockhead; other slots go through the dynamicObjects map (cell 0x8c7fb4) `__count_unique` + `operator[]` -> `remoteCreationDataUpdate:`; the slot buffer is cleared with `removeAllObjects` (cell 0x8c7fc8).\nPhase C (0x8c74a8-0x8c7a50): netUpdateDynamicObjects[i] (cell 0x8c7fcc): the same two-branch protocol -> `remoteUpdate:` (cell 0x8c7fd4); clear with removeAllObjects.\nPhase D (0x8c7a54-0x8c7fe4): the removal application: when the phase-A index set [-0x98] has entries (count via cell 0x8c7fac): per index `getBytes:length:8` -> the same two-branch lookup -> `setNeedsRemoved: 1` (cell 0x8c7fdc ffe2349c; r2 = sxtb 1) at 0x8c7d3c (blockhead branch) and 0x8c7e60-0x8c7e98 (map branch). Exits at 0x8c7f88/0x8c7f9c.\n'),
    ),
    dict(
        name='wtl_sendnetdataifneededfor',
        method='DynamicWorld -[sendNetDataIfNeededForObject:isCreation:]',
        types='v16@0:4@8c12',
        start=9207780,
        end=9213760,
        disasm='disasm_worldtileloader_sendnetdataifneededforobject_iscreation_.txt',
        base_add=9207796,
        base_literal=9211720,
        boundary='ARM.exidx end 0x008c9740 (listing bound); next ObjC IMP 0x008c9740 DynamicWorld -[simulate:]',
        selectors={
                 0x8c8f50: (15216532, 'needsNetDataToBeSent'),
                 0x8c8f54: (15216536, 'creationDataNeedsToBeSent'),
                 0x8c8f58: (15216540, 'updateNeedsToBeSent'),
                 0x8c8f5c: (15216544, 'needsRemoved'),
                 0x8c8f68: (15216168, 'objectType'),
                 0x8c8f6c: (15215864, 'count'),
                 0x8c8f74: (15216012, 'pos'),
                 0x8c8f78: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8c8f7c: (15216548, 'allValues'),
                 0x8c8f88: (15216128, 'worldWidthMacro'),
                 0x8c8f8c: (15216160, 'uniqueID'),
                 0x8c9414: (15216552, 'connected'),
                 0x8c9418: (15216560, 'unwireDynamicObject:'),
                 0x8c9424: (15216180, 'dataWithBytes:length:'),
                 0x8c9428: (15216556, 'addRemovalObjectDataToSend:ofType:objectID:'),
                 0x8c942c: (15216564, 'dynamicObjectIsWired:'),
                 0x8c9430: (15216152, 'creationNetDataForClient:'),
                 0x8c9434: (15216440, 'clientID'),
                 0x8c96c8: (15216568, 'addCreationDataUpdateObjectDataToSend:ofType:'),
                 0x8c96d0: (15216536, 'creationDataNeedsToBeSent'),
                 0x8c96d4: (15216540, 'updateNeedsToBeSent'),
                 0x8c96d8: (15216544, 'needsRemoved'),
                 0x8c96e0: (15216192, 'sendDataToServer:reliable:'),
                 0x8c96e4: (15216184, 'appendData:'),
                 0x8c96e8: (15216176, 'gzipDeflate'),
                 0x8c96ec: (15216588, 'arrayWithObject:'),
                 0x8c96f4: (15216220, 'appendBytes:length:'),
                 0x8c96f8: (15216180, 'dataWithBytes:length:'),
                 0x8c9700: (15216156, 'updateNetDataForClient:'),
                 0x8c9704: (15216152, 'creationNetDataForClient:'),
                 0x8c9710: (15216160, 'uniqueID'),
                 0x8c9714: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8c9718: (15216580, 'blockIsWired:'),
                 0x8c971c: (15216164, 'wireDynamicObject:'),
                 0x8c9720: (15216440, 'clientID'),
                 0x8c9724: (15216584, 'addCreationObjectDataToSend:ofType:objectID:'),
                 0x8c9728: (15216576, 'addUpdateObjectDataToSend:ofType:reliable:'),
                 0x8c972c: (15216572, 'unreliableUpdateNeedsToBeSent'),
                 0x8c9730: (15216560, 'unwireDynamicObject:'),
                 0x8c9734: (15216600, 'setCreationDataNeedsToBeSent:'),
                 0x8c9738: (15216596, 'setUnreliableUpdateNeedsToBeSent:'),
                 0x8c973c: (15216592, 'setUpdateNeedsToBeSent:'),
        },
        imports={
                 0x8c8f4c: (17151904, 'objc_msgSend'),
                 0x8c96cc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8c8f60: (17162396, 'OBJC_IVAR_$_DynamicWorld.sendUnreliableCounter', 9476),
                 0x8c8f64: (17162256, 'OBJC_IVAR_$_DynamicWorld.server', 16),
                 0x8c8f70: (17162248, 'OBJC_IVAR_$_DynamicWorld.serverClients', 24),
                 0x8c8f80: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8c96dc: (17162252, 'OBJC_IVAR_$_DynamicWorld.client', 20),
        },
        classes={
                 0x8c941c: (15247812, 'OBJC_CLASS_$_NSData'),
                 0x8c96f0: (15247880, 'OBJC_CLASS_$_NSArray'),
                 0x8c96fc: (15247844, 'OBJC_CLASS_$_NSMutableData'),
                 0x8c9708: (15247812, 'OBJC_CLASS_$_NSData'),
        },
        instructions=[(9207780, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9207816, 'ldrsb r0, [fp, -0x29]'), (9208692, 'bl sym.macroPosForWorldPos_intpair__World_'), (9209080, 'ldr r0, [0x008c8f4c]'), (9210096, 'ldr r0, [0x008c96cc]'), (9210804, 'movw r0, 0'), (9211212, 'ldrsb r0, [fp, -0x29]'), (9212984, 'ldr r0, [0x008c96cc]'), (9213488, 'movw r0, 0'), (9213756, 'invalid')],
        calls=[(9207872, 'blx r2'), (9207928, 'blx r2'), (9207996, 'blx r3'), (9208072, 'blx r3'), (9208148, 'blx r3'), (9208312, 'blx r3'), (9208412, 'blx r2'), (9208476, 'bl loc.imp.objc_msgSend_stret'), (9208512, 'bl sym.imp.memset'), (9208692, 'bl sym.macroPosForWorldPos_intpair__World_'), (9208740, 'bl loc.imp.objc_msgSend'), (9208776, 'bl loc.imp.objc_msgSend'), (9208820, 'blx r3'), (9208844, 'bl sym.imp.memset'), (9208892, 'blx lr'), (9208992, 'bl sym.imp.objc_enumerationMutation'), (9209064, 'blx r2'), (9209132, 'blx r2'), (9209224, 'bl loc.imp.objc_msgSend'), (9209292, 'bl loc.imp.objc_msgSend'), (9209316, 'blx r3'), (9209372, 'blx r3'), (9209428, 'blx r2'), (9209528, 'blx ip'), (9209560, 'blx r3'), (9209640, 'blx ip'), (9209688, 'blx r2'), (9209744, 'blx r2'), (9209844, 'blx ip'), (9209876, 'blx r3'), (9209992, 'blx ip'), (9210016, 'blx r3'), (9210080, 'blx r3'), (9210144, 'blx r3'), (9210216, 'blx r3'), (9210304, 'blx ip'), (9210336, 'blx r3'), (9210428, 'bl loc.imp.objc_msgSend'), (9210516, 'blx ip'), (9210548, 'blx r3'), (9210648, 'blx lr'), (9210772, 'blx ip'), (9210860, 'bl sym.objectTypeIsInteractionObject_int_'), (9211416, 'blx r3'), (9211464, 'blx ip'), (9211504, 'blx ip'), (9211540, 'blx ip'), (9211544, 'bl 0x8b84c8'), (9211636, 'blx r2'), (9211664, 'blx r3'), (9211712, 'blx lr'), (9211832, 'blx r2'), (9211888, 'blx r2'), (9212096, 'blx r3'), (9212144, 'blx ip'), (9212184, 'blx ip'), (9212220, 'blx ip'), (9212224, 'bl 0x8b84c8'), (9212316, 'blx r2'), (9212344, 'blx r3'), (9212392, 'blx lr'), (9212436, 'blx r2'), (9212644, 'blx r3'), (9212692, 'blx ip'), (9212732, 'blx ip'), (9212768, 'blx ip'), (9212772, 'bl 0x8b84c8'), (9212864, 'blx r2'), (9212892, 'blx r3'), (9212940, 'blx lr'), (9213148, 'bl loc.imp.objc_msgSend'), (9213192, 'bl loc.imp.objc_msgSend'), (9213212, 'bl loc.imp.objc_msgSend'), (9213260, 'blx ip'), (9213300, 'blx ip'), (9213304, 'bl 0x8b84c8'), (9213396, 'blx r2'), (9213424, 'blx r3'), (9213472, 'blx lr'), (9213572, 'blx r4'), (9213600, 'blx r3'), (9213628, 'blx r3')],
        branches=[(9207828, 'bne', 9207944), (9207884, 'bne', 9207944), (9207940, 'beq', 9213632), (9208016, 'bne', 9208192), (9208092, 'bne', 9208192), (9208168, 'bne', 9208192), (9208212, 'bne', 9208256), (9208248, 'beq', 9208256), (9208252, 'b', 9213632), (9208348, 'beq', 9210804), (9208420, 'bls', 9210804), (9208460, 'beq', 9208484), (9208480, 'b', 9208516), (9208904, 'beq', 9210796), (9208984, 'beq', 9208996), (9209076, 'beq', 9210672), (9209144, 'beq', 9209324), (9209320, 'b', 9210668), (9209384, 'beq', 9210096), (9209440, 'beq', 9209648), (9209456, 'bne', 9209568), (9209580, 'beq', 9209644), (9209644, 'b', 9209648), (9209700, 'bne', 9209760), (9209756, 'beq', 9210092), (9209772, 'bne', 9209884), (9209896, 'beq', 9210088), (9210028, 'bne', 9210084), (9210084, 'b', 9210088), (9210088, 'b', 9210092), (9210092, 'b', 9210664), (9210156, 'beq', 9210660), (9210232, 'bne', 9210344), (9210356, 'beq', 9210656), (9210444, 'bne', 9210556), (9210568, 'beq', 9210652), (9210652, 'b', 9210656), (9210656, 'b', 9210660), (9210660, 'b', 9210664), (9210664, 'b', 9210668), (9210668, 'b', 9210672), (9210672, 'b', 9210676), (9210700, 'blo', 9208948), (9210792, 'bne', 9208948), (9210796, 'b', 9210800), (9210800, 'b', 9213488), (9210840, 'beq', 9213484), (9210852, 'beq', 9211212), (9210872, 'bne', 9211212), (9210884, 'beq', 9211212), (9210896, 'beq', 9211212), (9210908, 'beq', 9211212), (9210920, 'beq', 9211212), (9210932, 'beq', 9211212), (9210944, 'beq', 9211212), (9210956, 'beq', 9211212), (9210968, 'beq', 9211212), (9210980, 'beq', 9211212), (9210992, 'beq', 9211212), (9211004, 'beq', 9211212), (9211016, 'beq', 9211212), (9211028, 'beq', 9211212), (9211040, 'beq', 9211212), (9211052, 'beq', 9211212), (9211064, 'beq', 9211212), (9211076, 'beq', 9211212), (9211088, 'beq', 9211212), (9211100, 'beq', 9211212), (9211112, 'beq', 9211212), (9211124, 'beq', 9211212), (9211136, 'beq', 9211212), (9211148, 'beq', 9211212), (9211160, 'beq', 9211212), (9211172, 'beq', 9211212), (9211184, 'beq', 9211212), (9211196, 'beq', 9211212), (9211208, 'bne', 9213484), (9211220, 'beq', 9211792), (9211716, 'b', 9213480), (9211844, 'bne', 9212984), (9211900, 'beq', 9212396), (9212448, 'beq', 9212944), (9212944, 'b', 9213476), (9213476, 'b', 9213480), (9213480, 'b', 9213484), (9213484, 'b', 9213488)],
        semantics=('sendNetDataIfNeededForObject:isCreation: builds and sends the per-object network packets in both directions. Prologue 0x008c7fe4. Arguments: object [-0x28], isCreation byte [-0x29].\nNeeds-flags gate (0x8c8008-0x8c8188): when isCreation is 0 the object must report `needsNetDataToBeSent` (cell 0x8c8f50) or `creationDataNeedsToBeSent` (cell 0x8c8f54); the combined result flag [-0x2a] is built from `updateNeedsToBeSent` (0x8c8f58) / `needsRemoved` (0x8c8f5c) / isCreation; a further ivar gate (cell 0x8c8f60) can short-circuit; the exit is 0x8c96c0.\nServer path ([self server] ffe51c != 0, serverClients ffe514 count > 0): `[obj pos]` (cell 0x8c8f74) -> `macroPosForWorldPos(pair, world)` (route 0x008c8374) -> line-major macro index via `mla` with worldWidthMacro (cell 0x8c8f88) -> [-0x44]; `[obj uniqueID]` (cell 0x8c8f8c) -> the 8-byte ID pair. Per connected client (enumerate; `[client connected]` cell 0x8c9414):\n  - `[obj needsRemoved]` (0x8c8f5c): `[client unwireDynamicObject:obj]` (cell 0x8c9418) then `[NSData dataWithBytes:fp-0x50 length:8]` (cells 0x8c941c/0x8c9424, NSData ffe2aed0) and `[client addRemovalObjectDataToSend:data ofType:objectType objectID:hi,lo]` (cell 0x8c9428 ffe234b8).\n  - else `[client dynamicObjectIsWired:obj]` (cell 0x8c942c): wired: `creationDataNeedsToBeSent` -> `[obj creationNetDataForClient:client.clientID]` (cells 0x8c9430/0x8c9434 ffe23324/ffe23444) -> `[client addCreationDataUpdateObjectDataToSend:data ofType:objectType]` (cell 0x8c96c8); `updateNeedsToBeSent` -> `[client addUpdateObjectDataToSend:...ofType:reliable:1]` (cells 0x8c96d4/0x8c9728 ffe234a8/ffe234cc); `unreliableUpdateNeedsToBeSent` (cell 0x8c972c) -> reliable:0; not wired: `[obj uniqueID]` + `[client wireDynamicObject:obj]` (cell 0x8c971c ffe23330 region) + `[client addCreationObjectDataToSend:data ofType:objectID:]` (cell 0x8c9724 ffe234d4) and finally the update send (0x8c8acc).\nClient path (0x8c8bb4): [self client] (cell 0x8c96dc) != 0; the object type [-0x30] must be in the whitelist: 0x18, any objectTypeIsInteractionObject (route 0x008c8bec), 0xa, 0x1b, 0x3b, 0xb, 0xc, 0x3d, 0x3e, 0x21, 0x22, 0x3a, 0xd, 0x33, 0x1c, 0x3f, 0x19, 0xe, 0x20, 0x28, 0x1f, 0x26, 0x37, 0x29, 0x2a, 0x2b, 0x2c, 0x23, 0x24, 0x27 (chain 0x8c8bdc-0x8c8d48; else exit 0x8c962c).\n  - isCreation: a packet is built with `gzipDeflate` (cell 0x8c96ec, NSMutableData ffe2af14 at 0x8c96f0) + `appendData:` (cell 0x8c96f4) + the shared helper `bl 0x8b84c8` (the packet-append helper from the save line) and sent as `[self.client sendDataToServer:data reliable:1]` (cell 0x8c96e0, client ffe518); markers 0xa/0xb/0x45 distinguish the packet family.\n  - !isCreation: `updateNeedsToBeSent` -> the same gzip packet, reliable:1 (marker 0xb); `unreliableUpdateNeedsToBeSent` -> reliable:0; `needsRemoved` (0x8c9438): NSData dataWithBytes:length:8 of the uniqueID plus a 1-byte type marker 0xc + appendBytes + sendDataToServer:reliable:1.\nTail (0x8c9630): `setUpdateNeedsToBeSent:0` / `setUnreliableUpdateNeedsToBeSent:0` / `setCreationDataNeedsToBeSent:0` (cells 0x8c9734/0x8c9738/0x8c973c) with sxtb 0 - the needs flags are cleared after sending; epilogue 0x8c96c0.\n'),
    ),
    dict(
        name='wtl_loadanyblockheadsfordi',
        method='DynamicWorld -[loadAnyBlockheadsForDisconnectedClients]',
        types='v8@0:4',
        start=9215148,
        end=9223308,
        disasm='disasm_worldtileloader_loadanyblockheadsfordisconnectedclients.txt',
        base_add=9215164,
        base_literal=9217280,
        boundary='ARM.exidx end 0x008cbc8c (listing bound); next ObjC IMP 0x008cbc8c DynamicWorld -[finishSimulating]',
        selectors={
                 0x8ca508: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8cad2c: (15215988, 'gzipInflate'),
                 0x8cad30: (15215900, 'dataForKey:'),
                 0x8cad38: (15215816, 'stringWithFormat:'),
                 0x8cad44: (15216240, 'hasFinishedDatabaseMigrationTo17'),
                 0x8cad4c: (15215828, 'fileExistsAtPath:'),
                 0x8cad50: (15215824, 'defaultManager'),
                 0x8cad58: (15215880, 'stringByAppendingPathComponent:'),
                 0x8cad6c: (15216608, 'substringWithRange:'),
                 0x8cad70: (15216188, 'length'),
                 0x8cad74: (15215904, 'dataWithContentsOfFile:'),
                 0x8cb1c8: (15215884, 'objectForKey:'),
                 0x8cb2ac: (15215912, 'unsignedLongValue'),
                 0x8cb2b0: (15216160, 'uniqueID'),
                 0x8cb824: (15215968, 'autorelease'),
                 0x8cb828: (15216004, 'initWithWorld:dynamicWorld:saveDict:savedInventorySlots:cache:repositionOnLoadFailure:clientSaveDir:clientLocallySavedDict:'),
                 0x8cb830: (15215804, 'alloc'),
                 0x8cb838: (15216000, 'propertyListWithData:options:format:error:'),
                 0x8cb840: (15216012, 'pos'),
                 0x8cb844: (15216008, 'addObject:'),
                 0x8cb848: (15216480, 'setClientName:'),
                 0x8cb850: (15216476, 'playerInfoForPeerID:'),
                 0x8cbbe4: (15216472, 'setClientID:'),
                 0x8cbbec: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8cbc00: (15215884, 'objectForKey:'),
                 0x8cbc08: (15215912, 'unsignedLongValue'),
                 0x8cbc0c: (15216160, 'uniqueID'),
                 0x8cbc14: (15215804, 'alloc'),
                 0x8cbc1c: (15216008, 'addObject:'),
                 0x8cbc30: (15216484, 'lightBlockIndex'),
                 0x8cbc34: (15216016, 'fullyLoadIfNeededAroundPos:clientLightBlockIndex:forBlockhead:'),
                 0x8cbc38: (15215800, 'init'),
                 0x8cbc40: (15216200, 'clientSaveDir'),
                 0x8cbc44: (15215944, 'setObject:forKey:'),
                 0x8cbc48: (15216144, 'array'),
                 0x8cbc50: (15216172, 'getSaveDictIncludingWorkbenchOrInterationObject:'),
                 0x8cbc58: (15216204, 'replaceObjectAtIndex:withObject:'),
                 0x8cbc60: (15216612, 'stopRiding'),
                 0x8cbc64: (15216028, 'stopInteractingWithInteractionObjectsIfNoInteractionObject'),
                 0x8cbc6c: (15215996, 'removeObject:'),
                 0x8cbc70: (15215844, 'blockheadWillBeUnloaded:'),
                 0x8cbc74: (15216468, 'removeFromMacroBlock'),
                 0x8cbc78: (15215980, 'customRules'),
                 0x8cbc7c: (15216032, 'die'),
                 0x8cbc80: (15216616, 'notifyPlayersChanged'),
                 0x8cbc84: (15216440, 'clientID'),
                 0x8cbc88: (15216096, 'removeAllObjects'),
        },
        imports={
                 0x8ca504: (17151904, 'objc_msgSend'),
                 0x8ca510: (17151968, '__stack_chk_guard'),
                 0x8cad34: (16333032, '__CFConstantStringClassReference'),
                 0x8cad60: (16333768, '__CFConstantStringClassReference'),
                 0x8cad64: (16333752, '__CFConstantStringClassReference'),
                 0x8cb1c4: (16333064, '__CFConstantStringClassReference'),
                 0x8cb2a8: (16333080, '__CFConstantStringClassReference'),
                 0x8cb2b8: (16333112, '__CFConstantStringClassReference'),
                 0x8cb6d0: (16333784, '__CFConstantStringClassReference'),
                 0x8cb84c: (16333656, '__CFConstantStringClassReference'),
                 0x8cbbe8: (17151904, 'objc_msgSend'),
                 0x8cbbf4: (17151968, '__stack_chk_guard'),
                 0x8cbbfc: (16333832, '__CFConstantStringClassReference'),
                 0x8cbc04: (16333080, '__CFConstantStringClassReference'),
                 0x8cbc10: (16333816, '__CFConstantStringClassReference'),
                 0x8cbc18: (16333800, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x8ca50c: (17162400, 'OBJC_IVAR_$_DynamicWorld.disconnectedClientsSaveDirNames', 9468),
                 0x8cad40: (17162240, 'OBJC_IVAR_$_DynamicWorld.worldDatabase', 32),
                 0x8cad48: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8cad5c: (17162196, 'OBJC_IVAR_$_DynamicWorld.worldSaveDirectory', 40),
                 0x8cb2a0: (17162212, 'OBJC_IVAR_$_DynamicWorld.netBlockheadsWithDisconnectedClients', 52),
                 0x8cb82c: (17162232, 'OBJC_IVAR_$_DynamicWorld.cache', 7336),
                 0x8cb854: (17162256, 'OBJC_IVAR_$_DynamicWorld.server', 16),
                 0x8cbbf0: (17162400, 'OBJC_IVAR_$_DynamicWorld.disconnectedClientsSaveDirNames', 9468),
                 0x8cbbf8: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8cbc20: (17162256, 'OBJC_IVAR_$_DynamicWorld.server', 16),
                 0x8cbc24: (17162372, 'OBJC_IVAR_$_DynamicWorld.disconnectedClientsCachedSaveDictsNotDone', 9472),
                 0x8cbc28: (17162248, 'OBJC_IVAR_$_DynamicWorld.serverClients', 24),
                 0x8cbc5c: (17162216, 'OBJC_IVAR_$_DynamicWorld.netBlockheads', 48),
        },
        classes={
                 0x8cad3c: (15247792, 'OBJC_CLASS_$_NSString'),
                 0x8cad54: (15247796, 'OBJC_CLASS_$_NSFileManager'),
                 0x8cb1c0: (15247812, 'OBJC_CLASS_$_NSData'),
                 0x8cb834: (15247828, 'OBJC_CLASS_$_Blockhead'),
                 0x8cb83c: (15247824, 'OBJC_CLASS_$_NSPropertyListSerialization'),
                 0x8cbc3c: (15247784, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x8cbc4c: (15247780, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(9215148, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9215364, 'add r1, r1, 8'), (9216528, 'movw r0, 0'), (9217428, 'sub lr, fp, 0x100'), (9220692, 'ldr r0, [fp, -0x29c]'), (9220804, 'ldr r0, [0x008cbbe8]'), (9221460, 'movw r0, 0'), (9221996, 'blx r2'), (9223304, 'invalid')],
        calls=[(9215276, 'bl sym.imp.memset'), (9215340, 'blx lr'), (9215440, 'bl sym.imp.objc_enumerationMutation'), (9215608, 'blx r4'), (9215640, 'blx r3'), (9215664, 'blx r2'), (9215668, 'bl 0x8b1db0'), (9215752, 'blx r2'), (9216032, 'bl loc.imp.objc_msgSend'), (9216096, 'bl loc.imp.objc_msgSend'), (9216132, 'bl loc.imp.objc_msgSend'), (9216200, 'bl loc.imp.objc_msgSend'), (9216252, 'blx r4'), (9216296, 'blx ip'), (9216340, 'blx ip'), (9216376, 'blx r3'), (9216396, 'blx r3'), (9216488, 'blx ip'), (9216512, 'blx r2'), (9216516, 'bl 0x8b1db0'), (9216660, 'blx r7'), (9216684, 'bl sym.imp.memset'), (9216732, 'blx lr'), (9216832, 'bl sym.imp.objc_enumerationMutation'), (9216972, 'bl loc.imp.objc_msgSend'), (9216988, 'bl loc.imp.objc_msgSend'), (9217032, 'bl sym.imp.memset'), (9217096, 'blx lr'), (9217196, 'bl sym.imp.objc_enumerationMutation'), (9217232, 'bl loc.imp.objc_msgSend'), (9217400, 'blx ip'), (9217596, 'bl loc.imp.objc_msgSend'), (9217628, 'blx r3'), (9217712, 'blx r2'), (9217960, 'bl loc.imp.objc_msgSend'), (9218024, 'bl loc.imp.objc_msgSend'), (9218060, 'bl loc.imp.objc_msgSend'), (9218128, 'bl loc.imp.objc_msgSend'), (9218176, 'bl loc.imp.objc_msgSend'), (9218252, 'bl loc.imp.objc_msgSend'), (9218296, 'blx ip'), (9218332, 'blx r3'), (9218352, 'blx r3'), (9218424, 'blx r3'), (9218672, 'blx r2'), (9218720, 'blx lr'), (9218756, 'blx r3'), (9218876, 'blx r5'), (9218892, 'blx r2'), (9219136, 'blx r6'), (9219176, 'blx ip'), (9219220, 'blx r3'), (9219252, 'blx r3'), (9219292, 'blx ip'), (9219364, 'bl loc.imp.objc_msgSend_stret'), (9219476, 'bl sym.imp.memset'), (9219556, 'bl loc.imp.objc_msgSend'), (9219572, 'bl loc.imp.objc_msgSend'), (9219628, 'bl loc.imp.objc_msgSend'), (9219732, 'blx r2'), (9219748, 'blx r2'), (9219824, 'blx r3'), (9219928, 'blx r3'), (9220032, 'blx lr'), (9220080, 'blx lr'), (9220216, 'blx ip'), (9220260, 'bl sym.imp.memset'), (9220308, 'blx lr'), (9220408, 'bl sym.imp.objc_enumerationMutation'), (9220456, 'bl loc.imp.objc_msgSend'), (9220472, 'bl loc.imp.objc_msgSend'), (9220504, 'bl loc.imp.objc_msgSend'), (9220664, 'blx ip'), (9220760, 'blx ip'), (9220852, 'blx r3'), (9220992, 'blx r2'), (9221012, 'blx r2'), (9221044, 'bl sym.imp.memset'), (9221108, 'blx lr'), (9221208, 'bl sym.imp.objc_enumerationMutation'), (9221252, 'bl loc.imp.objc_msgSend'), (9221288, 'bl loc.imp.objc_msgSend'), (9221432, 'blx ip'), (9221568, 'blx r5'), (9221592, 'blx r3'), (9221632, 'blx ip'), (9221708, 'bl loc.imp.objc_msgSend_stret'), (9221744, 'bl sym.imp.memset'), (9221832, 'bl loc.imp.objc_msgSend_stret'), (9221876, 'bl sym.imp.memset'), (9221932, 'blx r2'), (9221996, 'blx r2'), (9222016, 'bl sym.imp.NSLog'), (9222036, 'bl sym.imp.NSLog'), (9222144, 'blx ip'), (9222244, 'bl sym.imp.NSLog'), (9222348, 'bl sym.imp.memset'), (9222412, 'blx lr'), (9222512, 'bl sym.imp.objc_enumerationMutation'), (9222584, 'blx r2'), (9222708, 'blx ip'), (9222844, 'blx r5'), (9222868, 'blx r3'), (9222908, 'blx ip'), (9223012, 'blx ip'), (9223104, 'blx r2'), (9223136, 'bl sym.imp.__stack_chk_fail')],
        branches=[(9215352, 'beq', 9223036), (9215432, 'beq', 9215444), (9215688, 'bne', 9216528), (9215764, 'bne', 9216528), (9216408, 'beq', 9216524), (9216524, 'b', 9216528), (9216540, 'beq', 9222232), (9216744, 'beq', 9222168), (9216824, 'beq', 9216836), (9217108, 'beq', 9217424), (9217188, 'beq', 9217200), (9217260, 'bne', 9217300), (9217264, 'b', 9217268), (9217276, 'b', 9217428), (9217300, 'b', 9217304), (9217328, 'blo', 9217152), (9217420, 'bne', 9217152), (9217424, 'b', 9217428), (9217440, 'bne', 9222044), (9217648, 'bne', 9218436), (9217724, 'bne', 9218436), (9218364, 'beq', 9218432), (9218432, 'b', 9218436), (9218448, 'beq', 9222024), (9218912, 'beq', 9222004), (9219348, 'beq', 9219448), (9219368, 'b', 9219480), (9219660, 'bne', 9219772), (9219844, 'beq', 9220860), (9219948, 'bne', 9220084), (9220320, 'beq', 9220688), (9220400, 'beq', 9220412), (9220524, 'bne', 9220556), (9220528, 'b', 9220532), (9220540, 'b', 9220692), (9220592, 'blo', 9220364), (9220684, 'bne', 9220364), (9220688, 'b', 9220692), (9220700, 'beq', 9220804), (9220764, 'b', 9220856), (9220856, 'b', 9220860), (9221120, 'beq', 9221456), (9221200, 'beq', 9221212), (9221316, 'bne', 9221332), (9221320, 'b', 9221324), (9221332, 'b', 9221336), (9221360, 'blo', 9221164), (9221452, 'bne', 9221164), (9221456, 'b', 9221460), (9221472, 'beq', 9221636), (9221692, 'beq', 9221716), (9221712, 'b', 9221748), (9221756, 'beq', 9221936), (9221816, 'beq', 9221848), (9221836, 'b', 9221880), (9221888, 'bne', 9221936), (9222000, 'b', 9222020), (9222020, 'b', 9222040), (9222040, 'b', 9222044), (9222044, 'b', 9222048), (9222072, 'blo', 9216788), (9222164, 'bne', 9216788), (9222168, 'b', 9222172), (9222172, 'b', 9222248), (9222424, 'beq', 9222732), (9222504, 'beq', 9222516), (9222596, 'bne', 9222608), (9222608, 'b', 9222612), (9222636, 'blo', 9222468), (9222728, 'bne', 9222468), (9222732, 'b', 9222736), (9222748, 'beq', 9222912), (9222912, 'b', 9222916), (9222940, 'blo', 9215396), (9223032, 'bne', 9215396), (9223036, 'b', 9223040), (9223124, 'bne', 9223136)],
        semantics=("loadAnyBlockheadsForDisconnectedClients restores the blockheads of clients that left the server. Prologue 0x008c9cac (frame 0x800; guard cell 0x8ca510). The outer loop enumerates self->disconnectedClientsSaveDirNames (cell 0x8ca50c): per name the save payload is fetched with `[[self worldDatabase] (ffe50c) dataForKey:]` (cell 0x8cad30) on a stringWithFormat: key (cells 0x8cad34-0x8cad3c, key 0xfff33df4) with `gzipInflate` (cell 0x8cad2c) and parsed through the shared parser `bl 0x8b1db0` -> [-0x148]; a NULL parse result takes the file branch: `hasFinishedDatabaseMigrationTo17` (cell 0x8cad44) gate then fileExistsAtPath:/defaultManager/stringByAppendingPathComponent (cells 0x8cad4c-0x8cad58) under worldSaveDirectory with substringWithRange: (cell 0x8cad6c) and `dataWithContentsOfFile:` (cell 0x8cad74).\nPer parsed save: the per-object entries are enumerated; each entry's ID (`objectForKey:` + intValue cell 0x8cb2ac) is compared (eor/orr) against the save's stored IDs; a hit sets the found flag [-0x1e1] (0x8ca4d0-0x8ca4fc). For unmatched entries the body checks `[[self worldDatabase] dataForKey:<client key 0xfff33e44>]` (0x8ca5a4-0x8ca63c): when the key exists the entry is skipped (0x8ca670 `bne`); otherwise the migration gate (0x8ca674) plus the file path (fileExistsAtPath:/defaultManager/stringByAppendingPathComponent/worldSaveDirectory/substringWithRange: key 0xfff340e4, cells 0x8cad44-0x8cad5c + 0x8cb6d0) resolves the per-blockhead file -> [-0xb4].\nConstruction and registration (0x8cb250-0x8cb604): when the entry carries a clientID != -1 the blockhead gets `setClientID:` (cell 0x8cbc58) else it is added with `addObject:` (cell 0x8cbc1c); the netBlockheads collection (cell 0x8cbc5c) is scanned with `[item uniqueID]` (cell 0x8cbc0c) eor/orr matching to find the counterpart [-0x304]; a found counterpart is removed from the collection via `removeObject:` (cell 0x8cbc6c) + `blockheadWillBeUnloaded:` (cell 0x8cbc70 ffe231f0) and, when customRules (cell 0x8cbc78) byte 0 is set and byte +0x32 == 4, killed with `die` (cell 0x8cbc7c ffe232ac, 0x8cb704-0x8cb72c). The Blockhead itself is built with the full init (class cell 0x8cb834, selector cell 0x8cb828: initWithWorld:dynamicWorld:saveDict:savedInventorySlots:cache:repositionOnLoadFailure:clientSaveDir:clientLocallySavedDict:) and `[bh fullyLoadIfNeededAroundPos:pos clientLightBlockIndex:-1 forBlockhead:]` (cell 0x8cbc34) runs when the client index is present. The second phase loops the netBlockheads map (0x8cb868-0x8cbafc) with `[? clientID]` (cell 0x8cbc84) matching against the loaded client's ID [-0xdc] to attach `setClientName:` (cell 0x8cb848) via `playerInfoForPeerID:` (cell 0x8cb850), and the final cleanup calls the classic save-dict helpers (getSaveDictIncludingWorkbenchOrInterationObject: cell 0x8cbc50, replaceObjectAtIndex:withObject: cell 0x8cbc58, stopRiding cell 0x8cbc60, stopInteractingWithInteractionObjectsIfNoInteractionObject cell 0x8cbc64, removeFromMacroBlock cell 0x8cbc74, notifyPlayersChanged cell 0x8cbc80, removeAllObjects cell 0x8cbc88) around the NSLog strings 0xfff340f4/0xfff34104/0xfff34114; the guard check closes the body (0x8cbb80+, __stack_chk_fail cell 0x8cbbf4 ffffbcec).\n"),
    ),
    dict(
        name='wtl_clientblockheadinvento',
        method='DynamicWorld -[clientBlockheadInventoryRecievedForPlayerID:blockheadID:data:]',
        types='v24@0:4@8Q12@20',
        start=9417352,
        end=9420432,
        disasm='disasm_worldtileloader_clientblockheadinventoryrecievedforplaye.txt',
        base_add=9417368,
        base_literal=9420428,
        boundary='ARM.exidx end 0x008fbe90 (listing bound); next ObjC IMP 0x008fbe90 DynamicWorld -[loadClientBlockheadsDataForPlayerID:]',
        selectors={
                 0x8fbdec: (15216000, 'propertyListWithData:options:format:error:'),
                 0x8fbdf0: (15215988, 'gzipInflate'),
                 0x8fbe00: (15215816, 'stringWithFormat:'),
                 0x8fbe10: (15215800, 'init'),
                 0x8fbe14: (15215804, 'alloc'),
                 0x8fbe1c: (15215884, 'objectForKey:'),
                 0x8fbe20: (15215944, 'setObject:forKey:'),
                 0x8fbe24: (15215940, 'dictionary'),
                 0x8fbe28: (15216144, 'array'),
                 0x8fbe30: (15216008, 'addObject:'),
                 0x8fbe34: (15216176, 'gzipDeflate'),
                 0x8fbe38: (15216088, 'dataWithPropertyList:format:options:error:'),
                 0x8fbe48: (15216140, 'isKindOfClass:'),
                 0x8fbe4c: (15216136, 'class'),
                 0x8fbe54: (15215808, 'objectAtIndex:'),
                 0x8fbe5c: (15215864, 'count'),
                 0x8fbe64: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8fbe68: (15215968, 'autorelease'),
                 0x8fbe6c: (15217148, 'initWithSaveData:'),
                 0x8fbe74: (15217152, 'updateSubItemSlot:atIndex:'),
                 0x8fbe78: (15215916, 'intValue'),
                 0x8fbe7c: (15216204, 'replaceObjectAtIndex:withObject:'),
                 0x8fbe80: (15217156, 'saveData'),
                 0x8fbe84: (15216424, 'addObjectsFromArray:'),
                 0x8fbe88: (15216096, 'removeAllObjects'),
        },
        imports={
                 0x8fbde8: (17151904, 'objc_msgSend'),
                 0x8fbdf8: (16333112, '__CFConstantStringClassReference'),
                 0x8fbe60: (16333992, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x8fbe0c: (17162284, 'OBJC_IVAR_$_DynamicWorld.liveServerClientBlockheadInventories', 9500),
                 0x8fbe40: (17162208, 'OBJC_IVAR_$_DynamicWorld.clientBlockheadInventoriesToSave', 56),
        },
        classes={
                 0x8fbdf4: (15247824, 'OBJC_CLASS_$_NSPropertyListSerialization'),
                 0x8fbe04: (15247792, 'OBJC_CLASS_$_NSString'),
                 0x8fbe18: (15247784, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x8fbe2c: (15247780, 'OBJC_CLASS_$_NSMutableArray'),
                 0x8fbe50: (15247880, 'OBJC_CLASS_$_NSArray'),
                 0x8fbe58: (15247816, 'OBJC_CLASS_$_NSDictionary'),
                 0x8fbe70: (15247976, 'OBJC_CLASS_$_InventoryItem'),
        },
        instructions=[(9417352, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9417716, 'movw r0, 0'), (9417968, 'ldr r0, [0x008fbde8]'), (9418264, 'ldr r0, [fp, -0x48]'), (9418476, 'ldr r0, [fp, -0x4c]'), (9419652, 'movw r0, 0'), (9419748, 'movw r2, 0'), (9419868, 'ldr r0, [0x008fbe60]'), (9420428, 'rsbseq r4, r6, r4, asr r8')],
        calls=[(9417600, 'bl loc.imp.objc_msgSend'), (9417644, 'blx r2'), (9417692, 'blx lr'), (9417824, 'blx r2'), (9417840, 'blx r2'), (9417944, 'blx r3'), (9418048, 'blx lr'), (9418096, 'blx lr'), (9418160, 'blx r3'), (9418244, 'blx r3'), (9418352, 'blx ip'), (9418384, 'blx r3'), (9418460, 'blx ip'), (9418592, 'blx r6'), (9418620, 'blx r3'), (9418660, 'blx r2'), (9418692, 'blx r3'), (9418768, 'blx ip'), (9418800, 'blx r3'), (9418884, 'blx ip'), (9418916, 'blx r3'), (9418972, 'blx r2'), (9419192, 'blx r3'), (9419228, 'blx r3'), (9419248, 'blx r3'), (9419264, 'blx r2'), (9419288, 'bl sym.imp.memset'), (9419336, 'blx lr'), (9419436, 'bl sym.imp.objc_enumerationMutation'), (9419548, 'blx r4'), (9419588, 'blx r3'), (9419620, 'blx ip'), (9419720, 'blx ip'), (9419824, 'blx lr'), (9419860, 'blx ip'), (9419880, 'bl sym.imp.NSLog'), (9420020, 'blx r4'), (9420036, 'blx r2'), (9420212, 'bl loc.imp.objc_msgSend'), (9420248, 'blx ip')],
        branches=[(9417712, 'beq', 9420256), (9417752, 'bne', 9417864), (9417964, 'bne', 9418100), (9418180, 'bne', 9418464), (9418272, 'bge', 9418404), (9418400, 'b', 9418264), (9418484, 'bge', 9419912), (9418704, 'beq', 9418808), (9418804, 'b', 9419892), (9418928, 'beq', 9419888), (9418980, 'bls', 9419868), (9419348, 'beq', 9419744), (9419428, 'beq', 9419440), (9419648, 'blo', 9419392), (9419740, 'bne', 9419392), (9419744, 'b', 9419748), (9419864, 'b', 9419884), (9419884, 'b', 9419888), (9419888, 'b', 9419892), (9419892, 'b', 9419896), (9419908, 'b', 9418476), (9420056, 'beq', 9420252), (9420252, 'b', 9420256)],
        semantics=("clientBlockheadInventoryRecievedForPlayerID:blockheadID:data: stores an inventory snapshot sent by a client. Prologue 0x008fb288. Arguments: playerID [-0x28], blockheadID pair [-0x2c]/[-0x30], data [-0x34].\nDictionary bootstrap: `[self.liveServerClientBlockheadInventories (cell 0x8fbe0c)] objectForKey:playerID` (cell 0x8fbe1c); when absent a new `[[NSMutableDictionary alloc] init]` (cells 0x8fbe14/0x8fbe18 + init cell 0x8fbe10) is stored back into the ivar slot (0x8fb480 `str r0,[r1]`). Then the per-blockhead dict is fetched (`objectForKey:` cell 0x8fbe1c) and on absence created (0x8fb4f0-0x8fb540: alloc/init + `setObject:forKey:` (cell 0x8fbe20) with `dictionary` (cell 0x8fbe24)).\nPayload decode: the data argument goes through `gzipInflate` (cell 0x8fbdec ffe23280) and `[NSPropertyListSerialization propertyListWithData:options:format:error:]` (cell 0x8fbde0, class ffe2aedc at cell 0x8fbdf4) -> the inventory plist [-0x3c]; a NULL decode exits (0x8fbde0 region). The InventoryItem array slot 0..7 is walked (`cmp i, 8` at 0x8fb618 and 0x8fb6ec): per index the live dict's array (`objectForKey:` cell 0x8fbe1c + `array` cell 0x8fbe28) supplies the item; items are validated with `isKindOfClass:` (cell 0x8fbe48, class cell 0x8fbe4c/ffe2af14) against the incoming plist entries (`objectAtIndex:` cell 0x8fbe54 + intValue cell 0x8fbe78), reconstructed with `[[InventoryItem alloc] initWithSaveData:]` (cells 0x8fbe70/0x8fbe6c, class cell 0x8fbe70 ffe2af74) and `updateSubItemSlot:atIndex:` (cell 0x8fbe74 ffe2370c) while an NSLog (cell 0x8fbe60 fff341b4) records mismatches; the rebuilt array is written back with `setObject:forKey:` (cell 0x8fbe7c ffe23358 + `saveData` cell 0x8fbe80) and archived with `gzipDeflate` (cell 0x8fbe34) plus `dataWithPropertyList:format:options:error:` (cell 0x8fbe38) into clientBlockheadInventoriesToSave (cell 0x8fbe40 ffe538 region; the cell 0x8fbe30 addObjectsFromArray: mirrors the sequence). The trailing `movw lr, 0x64` (100) at 0x8fbc9c opens the final pass; epilogue follows the last setObject:.\n"),
    ),
    dict(
        name='wtl_loadclientblockheadsda',
        method='DynamicWorld -[loadClientBlockheadsDataForPlayerID:]',
        types='@12@0:4@8',
        start=9420432,
        end=9427952,
        disasm='disasm_worldtileloader_loadclientblockheadsdataforplayerid_.txt',
        base_add=9420448,
        base_literal=9424180,
        boundary='ARM.exidx end 0x008fdbf0 (listing bound); next ObjC IMP 0x008fdbf0 DynamicWorld -[isControllingBlockheadsForClientPlayer:]',
        selectors={
                 0x8fcd3c: (15215900, 'dataForKey:'),
                 0x8fcd44: (15215816, 'stringWithFormat:'),
                 0x8fcd58: (15215944, 'setObject:forKey:'),
                 0x8fcd5c: (15215940, 'dictionary'),
                 0x8fcd64: (15215988, 'gzipInflate'),
                 0x8fcd68: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8fcd70: (15215884, 'objectForKey:'),
                 0x8fd204: (15215912, 'unsignedLongValue'),
                 0x8fd20c: (15216240, 'hasFinishedDatabaseMigrationTo17'),
                 0x8fd214: (15215928, 'contentsOfDirectoryAtPath:error:'),
                 0x8fd218: (15215824, 'defaultManager'),
                 0x8fd220: (15215880, 'stringByAppendingPathComponent:'),
                 0x8fd230: (15216608, 'substringWithRange:'),
                 0x8fd684: (15216188, 'length'),
                 0x8fd688: (15215932, 'rangeOfString:'),
                 0x8fd698: (15217160, 'hasKey:'),
                 0x8fd69c: (15215904, 'dataWithContentsOfFile:'),
                 0x8fd6a4: (15217164, 'lastPathComponent'),
                 0x8fdb1c: (15215944, 'setObject:forKey:'),
                 0x8fdb20: (15215940, 'dictionary'),
                 0x8fdb28: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8fdb2c: (15215884, 'objectForKey:'),
                 0x8fdb30: (15215988, 'gzipInflate'),
                 0x8fdb38: (15215932, 'rangeOfString:'),
                 0x8fdb40: (15215864, 'count'),
                 0x8fdb50: (15215800, 'init'),
                 0x8fdb54: (15215804, 'alloc'),
                 0x8fdb58: (15216000, 'propertyListWithData:options:format:error:'),
                 0x8fdb64: (15216144, 'array'),
                 0x8fdb6c: (15216140, 'isKindOfClass:'),
                 0x8fdb70: (15216136, 'class'),
                 0x8fdb78: (15215808, 'objectAtIndex:'),
                 0x8fdb7c: (15216008, 'addObject:'),
                 0x8fdb80: (15216424, 'addObjectsFromArray:'),
                 0x8fdb84: (15217168, 'welcomeBackEventsMessageForClientID:'),
                 0x8fdb8c: (15217172, 'serializedData'),
                 0x8fdb90: (15215852, 'release'),
                 0x8fdb98: (15216084, 'finishEncoding'),
                 0x8fdb9c: (15216080, 'encodeObject:forKey:'),
                 0x8fdba0: (15216076, 'initForWritingWithMutableData:'),
                 0x8fdba8: (15216072, 'data'),
                 0x8fdbb0: (15215976, 'addIndexes:'),
                 0x8fdbb4: (15217140, 'foundItemsList'),
                 0x8fdbc4: (15217176, 'initWithIndexesInRange:'),
                 0x8fdbc8: (15217180, 'addIndexesInRange:'),
                 0x8fdbd0: (15216176, 'gzipDeflate'),
                 0x8fdbd4: (15215972, 'finishDecoding'),
                 0x8fdbd8: (15215968, 'autorelease'),
                 0x8fdbdc: (15215820, 'retain'),
                 0x8fdbe0: (15215964, 'decodeObjectForKey:'),
                 0x8fdbe4: (15215960, 'initForReadingWithData:'),
                 0x8fdbec: (15216088, 'dataWithPropertyList:format:options:error:'),
        },
        imports={
                 0x8fcd38: (17151904, 'objc_msgSend'),
                 0x8fcd40: (16333032, '__CFConstantStringClassReference'),
                 0x8fcd50: (16333960, '__CFConstantStringClassReference'),
                 0x8fcd54: (16334008, '__CFConstantStringClassReference'),
                 0x8fcd6c: (16333064, '__CFConstantStringClassReference'),
                 0x8fd1f4: (16332968, '__CFConstantStringClassReference'),
                 0x8fd1f8: (16334024, '__CFConstantStringClassReference'),
                 0x8fd200: (16333080, '__CFConstantStringClassReference'),
                 0x8fd228: (16333752, '__CFConstantStringClassReference'),
                 0x8fd68c: (16334040, '__CFConstantStringClassReference'),
                 0x8fdb18: (17151904, 'objc_msgSend'),
                 0x8fdb44: (16334056, '__CFConstantStringClassReference'),
                 0x8fdb60: (16334072, '__CFConstantStringClassReference'),
                 0x8fdb88: (16334088, '__CFConstantStringClassReference'),
                 0x8fdb94: (16333976, '__CFConstantStringClassReference'),
                 0x8fdbcc: (16334104, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x8fcd4c: (17162240, 'OBJC_IVAR_$_DynamicWorld.worldDatabase', 32),
                 0x8fd210: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8fd224: (17162196, 'OBJC_IVAR_$_DynamicWorld.worldSaveDirectory', 40),
                 0x8fdb34: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8fdb4c: (17162284, 'OBJC_IVAR_$_DynamicWorld.liveServerClientBlockheadInventories', 9500),
                 0x8fdbb8: (17162248, 'OBJC_IVAR_$_DynamicWorld.serverClients', 24),
        },
        classes={
                 0x8fcd48: (15247792, 'OBJC_CLASS_$_NSString'),
                 0x8fcd60: (15247784, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x8fd21c: (15247796, 'OBJC_CLASS_$_NSFileManager'),
                 0x8fd6a0: (15247812, 'OBJC_CLASS_$_NSData'),
                 0x8fdb24: (15247784, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x8fdb5c: (15247824, 'OBJC_CLASS_$_NSPropertyListSerialization'),
                 0x8fdb68: (15247780, 'OBJC_CLASS_$_NSMutableArray'),
                 0x8fdb74: (15247880, 'OBJC_CLASS_$_NSArray'),
                 0x8fdba4: (15247848, 'OBJC_CLASS_$_NSKeyedArchiver'),
                 0x8fdbac: (15247844, 'OBJC_CLASS_$_NSMutableData'),
                 0x8fdbbc: (15247788, 'OBJC_CLASS_$_NSMutableIndexSet'),
                 0x8fdbe8: (15247820, 'OBJC_CLASS_$_NSKeyedUnarchiver'),
        },
        instructions=[(9420432, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9420956, 'ldr r1, [fp, -0x274]'), (9421160, 'bl 0x8b1db0'), (9424960, 'ldr r0, [fp, -0x200]'), (9425460, 'ldr r0, [0x008fdb60]'), (9425612, 'movw r0, 0'), (9426600, 'ldr r0, [0x008fdb18]'), (9427632, 'movw r3, 0x64'), (9427948, 'invalid')],
        calls=[(9420660, 'blx lr'), (9420696, 'blx r3'), (9420740, 'blx ip'), (9420812, 'blx ip'), (9420844, 'blx r3'), (9420912, 'blx ip'), (9420944, 'blx r3'), (9421092, 'blx r4'), (9421128, 'blx ip'), (9421148, 'blx r2'), (9421160, 'bl 0x8b1db0'), (9421272, 'blx ip'), (9421296, 'bl sym.imp.memset'), (9421344, 'blx lr'), (9421444, 'bl sym.imp.objc_enumerationMutation'), (9421612, 'bl loc.imp.objc_msgSend'), (9421628, 'bl loc.imp.objc_msgSend'), (9421708, 'bl loc.imp.objc_msgSend'), (9421772, 'blx r5'), (9421816, 'blx ip'), (9421896, 'blx ip'), (9422000, 'blx ip'), (9422092, 'blx r2'), (9422444, 'bl loc.imp.objc_msgSend'), (9422508, 'bl loc.imp.objc_msgSend'), (9422544, 'bl loc.imp.objc_msgSend'), (9422612, 'bl loc.imp.objc_msgSend'), (9422664, 'blx r4'), (9422708, 'blx ip'), (9422744, 'blx r3'), (9422768, 'blx ip'), (9422792, 'bl sym.imp.memset'), (9422840, 'blx lr'), (9422940, 'bl sym.imp.objc_enumerationMutation'), (9423040, 'bl loc.imp.objc_msgSend_stret'), (9423076, 'bl sym.imp.memset'), (9423220, 'blx r7'), (9423284, 'blx r5'), (9423328, 'blx ip'), (9423408, 'blx r3'), (9423568, 'blx r5'), (9423612, 'blx lr'), (9423648, 'blx ip'), (9423760, 'blx ip'), (9423832, 'blx r2'), (9423924, 'bl sym.imp.memset'), (9423972, 'blx lr'), (9424072, 'bl sym.imp.objc_enumerationMutation'), (9424172, 'bl loc.imp.objc_msgSend_stret'), (9424272, 'bl sym.imp.memset'), (9424400, 'blx r2'), (9424416, 'blx r2'), (9424520, 'blx r3'), (9424624, 'blx lr'), (9424672, 'blx lr'), (9424792, 'blx r5'), (9424808, 'blx r2'), (9424856, 'blx lr'), (9424940, 'blx r3'), (9425100, 'blx ip'), (9425140, 'blx r3'), (9425164, 'blx r3'), (9425204, 'blx r2'), (9425236, 'blx r3'), (9425308, 'blx r3'), (9425388, 'blx ip'), (9425472, 'bl sym.imp.NSLog'), (9425580, 'blx ip'), (9425688, 'blx r3'), (9425776, 'blx ip'), (9426048, 'blx r7'), (9426080, 'blx r3'), (9426100, 'blx r3'), (9426128, 'blx r3'), (9426144, 'blx r2'), (9426160, 'blx r2'), (9426184, 'blx r2'), (9426204, 'blx r2'), (9426364, 'blx r7'), (9426380, 'blx r2'), (9426400, 'blx r3'), (9426420, 'blx r2'), (9426516, 'blx r2'), (9426552, 'blx ip'), (9426640, 'blx r2'), (9427028, 'bl loc.imp.objc_msgSend'), (9427096, 'bl loc.imp.objc_msgSend'), (9427168, 'bl loc.imp.objc_msgSend'), (9427208, 'blx ip'), (9427224, 'blx r2'), (9427256, 'blx r3'), (9427288, 'blx r3'), (9427324, 'blx r3'), (9427344, 'blx r3'), (9427388, 'blx ip'), (9427408, 'blx r2'), (9427448, 'blx ip'), (9427468, 'blx r2'), (9427488, 'blx r2'), (9427584, 'blx r2'), (9427620, 'blx ip'), (9427716, 'blx lr')],
        branches=[(9420964, 'beq', 9422032), (9421356, 'beq', 9422024), (9421436, 'beq', 9421448), (9421836, 'beq', 9421900), (9421900, 'b', 9421904), (9421928, 'blo', 9421400), (9422020, 'bne', 9421400), (9422024, 'b', 9422028), (9422028, 'b', 9422032), (9422104, 'bne', 9423792), (9422852, 'beq', 9423784), (9422932, 'beq', 9422944), (9423008, 'beq', 9423048), (9423044, 'b', 9423080), (9423092, 'beq', 9423660), (9423340, 'bne', 9423656), (9423428, 'beq', 9423652), (9423652, 'b', 9423656), (9423656, 'b', 9423660), (9423660, 'b', 9423664), (9423688, 'blo', 9422896), (9423780, 'bne', 9422896), (9423784, 'b', 9423788), (9423788, 'b', 9423792), (9423840, 'bls', 9425612), (9423984, 'beq', 9425604), (9424064, 'beq', 9424076), (9424140, 'beq', 9424244), (9424176, 'b', 9424276), (9424288, 'beq', 9425480), (9424328, 'bne', 9424440), (9424540, 'bne', 9424676), (9424876, 'beq', 9425460), (9424968, 'bge', 9425332), (9425248, 'beq', 9425312), (9425312, 'b', 9425316), (9425328, 'b', 9424960), (9425392, 'b', 9425476), (9425476, 'b', 9425480), (9425480, 'b', 9425484), (9425508, 'blo', 9424028), (9425600, 'bne', 9424028), (9425604, 'b', 9425608), (9425608, 'b', 9425612), (9425708, 'beq', 9425780), (9425792, 'beq', 9426600), (9426220, 'beq', 9426560), (9426440, 'beq', 9426556), (9426556, 'b', 9426560), (9426560, 'b', 9427632), (9426648, 'bls', 9427628), (9427508, 'beq', 9427624), (9427624, 'b', 9427628), (9427628, 'b', 9427632)],
        semantics=("loadClientBlockheadsDataForPlayerID: restores one client's blockhead data on the server. Prologue 0x008fbe90 (frame 0x650). The payload is fetched with `[[self worldDatabase] (cell 0x8fcd4c) dataForKey:]` (cell 0x8fcd3c) on a stringWithFormat: key (cells 0x8fcd40/0x8fcd44/0x8fcd48, key 0xfff33df4) combined with `gzipInflate` (cell 0x8fcd64); the parsed plist (via `bl 0x8b1db0`, plus `propertyListWithData:` at cell 0x8fcd58 region) yields the client's save dict [-0x5c]; a NULL dict exits (0x8fc09c -> 0x8fc4d0).\nMain pass: per blockhead entry the stored IDs are compared against the incoming values; matched blockheads run `welcomeBackEventsMessageForClientID:` (cell 0x8fdb84 ffe2371c) and the keyed-archive write pipeline - `initForWritingWithMutableData:` (cell 0x8fdbd4 ffe23270 hmm) with NSMutableData (cell 0x8fdbdc), `encodeObject:forKey:` (cell 0x8fdbd8 ffe2326c region), `finishEncoding` (cell 0x8fdb90) - producing the outgoing archive; mismatches log NSLog strings (0xfff341a4/0xfff34204/0xfff34214/0xfff34224) and continue (0x8fd234, 0x8fd33c). The 8-slot inventory loop (`cmp i, 8` at 0x8fd044) fetches `liveServerClientBlockheadInventories` (cell 0x8fdb4c ffe538) entries (`objectAtIndex:` cell 0x8fdb6c + class check cell 0x8fdb70 ffe2af14, isKindOfClass: cell 0x8fdb74 region) and rebuilds them through `initForReadingWithData:` (cell 0x8fbde4) / `decodeObjectForKey:` / `finishDecoding` (cells 0x8fdbd8-0x8fbde8) into the mutable dictionary (`setObject:forKey:` cells 0x8fdb1c/0x8fdb20/0x8fdb48). The tail (0x8fdab0) builds the return value with a final `setObject:forKey:` (cell 0x8fdbec ffe232e4) and the classic count marker `movw r3, 0x64` (100) before the epilogue at 0x8fdb10; the guard cell 0x8fdb18 anchors the pool.\n"),
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
        'batch': 'DynamicWorld net-sync cluster (E21): saveAndSendOnlyBlocksThatNeedToBeSent, updateNetObjects (65-slot reconciliation), sendNetDataIfNeededForObject:isCreation: (server wire/unwire + client packets), loadAnyBlockheadsForDisconnectedClients, clientBlockheadInventoryRecievedForPlayerID:blockheadID:data: and loadClientBlockheadsDataForPlayerID:; 6 bodies',
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
                        default=NATIVE / 'net_sync.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale net_sync.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
