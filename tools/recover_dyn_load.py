#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld dynamic-object load chain (E19).

The DynamicWorld dynamic-object load chain - the storage front's third line (after
the WorldTileLoader block bodies E14-E18): the per-macro-tile object restore, the
world-level dynamic-object + blockhead restore (with the one-to-two conversion
thread and the NSKeyedArchiver portal set) and the per-type constructor worker:
1 body, 11207 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/DYN_OBJECT_LOAD.md for the prose and boundaries.
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
    'bl 0x8ad2a4': 0x008ad2a4,
    'bl 0x8b1db0': 0x008b1db0,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.std::__1::__hash_const_iterator_std::__1::__hash_node_unsigned_int__void__const__std::__1::__hash_table_unsigned_int__std::__1::hash_unsigned_int___std::__1::equal_to_unsigned_int___std::__1::allocator_unsigned_int___.find_unsigned_int__unsigned_int_const__const': 0x009123a4,
    'bl method.std::__1::__hash_const_iterator_std::__1::__hash_node_unsigned_long_long__void__const__std::__1::__hash_table_unsigned_long_long__std::__1::hash_unsigned_long_long___std::__1::equal_to_unsigned_long_long___std::__1::allocator_unsigned_long_long___.find_unsigned_long_long__unsigned_long_long_const__const': 0x00910798,
    'bl method.std::__1::__hash_table_unsigned_int__std::__1::hash_unsigned_int___std::__1::equal_to_unsigned_int___std::__1::allocator_unsigned_int___.__insert_unique_unsigned_int_const_': 0x00910c58,
    'bl method.std::__1::__hash_table_unsigned_long_long__std::__1::hash_unsigned_long_long___std::__1::equal_to_unsigned_long_long___std::__1::allocator_unsigned_long_long___.__insert_unique_unsigned_long_long_const_': 0x0090f874,
    'bl method.std::__1::__tree_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject___.__insert_unique_DynamicObject_const_': 0x0090dc2c,
    'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__': 0x005dc5d8,
    'bl method.std::__1::map_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int_____std::__1::less_unsigned_int___std::__1::allocator_std::__1::pair_unsigned_int_const__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int________.at_unsigned_int_const_': 0x008ba928,
    'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_': 0x008bcf24,
    'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_': 0x008bcb78,
    'bl method.std::__1::map_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.operator___unsigned_long_long_': 0x008bd2e4,
    'bl method.std::__1::pair_std::__1::__tree_iterator_unsigned_int__std::__1::__tree_node_unsigned_int__void___int___bool__std::__1::__tree_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int___.__insert_unique_unsigned_int__unsigned_int_': 0x00912b98,
    'bl method.unsigned_long_std::__1::__hash_table_unsigned_int__std::__1::hash_unsigned_int___std::__1::equal_to_unsigned_int___std::__1::allocator_unsigned_int___.__erase_unique_unsigned_int__unsigned_int_const_': 0x0090d298,
    'bl method.unsigned_long_std::__1::__hash_table_unsigned_long_long__std::__1::hash_unsigned_long_long___std::__1::equal_to_unsigned_long_long___std::__1::allocator_unsigned_long_long___.__erase_unique_unsigned_long_long__unsigned_long_long_const_': 0x00913f9c,
    'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const': 0x00910a74,
    'bl sym.clamp_float__float__float_': 0x004be068,
    'bl sym.classForDynamicObjectType_int_': 0x00b597bc,
    'bl sym.classForInteractionObjectType_unsigned_short_': 0x005f3f50,
    'bl sym.dynamicObjectTypeForInteractionObjectType_unsigned_short_': 0x008bc89c,
    'bl sym.imp.NSLog': 0x001c2a5c,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__stack_chk_fail': 0x001c28b8,
    'bl sym.imp.__wrap_rename': 0x001c4184,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.macroIndexAtMacroPosition_int__int__World_': 0x00a174a4,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.objectTypeHasStaticPosition_int_': 0x008b68ac,
    'bl sym.objectTypeIsInteractionObject_int_': 0x008bcacc,
    'bl sym.objectTypeIsPlant_int_': 0x008bca20,
    'bl sym.objectTypeIsTree_int_': 0x008bc974,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileAtWorldPosition_int__int__MacroTile__World_': 0x00a16e68,
    'bl sym.tileIsAirOrSnow_Tile_': 0x00a12760,
    'bl sym.tileIsSolid_Tile_': 0x00a1179c,
    'bl sym.tileIsWater_Tile_': 0x00a11690,
    'bl sym.tileRequiresGlowBlock_Tile_': 0x00a14824,
    'bl sym.treeTypeForTreePromise_int_': 0x008c3a88,
    'bl sym.worldIndexAtWorldPos_intpair__World_': 0x00a15838,
}

SPECS = [
    dict(
        name='wtl_loaddynamicobjectsform',
        method='DynamicWorld -[loadDynamicObjectsForMacroTile:includeSurfaceBlocks:]',
        types='v16@0:4^{MacroTile=CCC^{PhysicalBlock}^{DrawBlock}@f}8c12',
        start=9165240,
        end=9190024,
        disasm='disasm_worldtileloader_loaddynamicobjectsformacrotile_includesu.txt',
        base_add=9165280,
        base_literal=9169160,
        boundary='ARM.exidx end 0x008c3a88 (listing bound); next ObjC IMP 0x008c3c08 DynamicWorld -[remoteCreate:forObjectsOfType:clientID:]',
        selectors={
                 0x8bea74: (15215816, 'stringWithFormat:'),
                 0x8bea7c: (15215884, 'objectForKey:'),
                 0x8bea80: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8bea84: (15215832, 'createDirectoryAtPath:withIntermediateDirectories:attributes:error:'),
                 0x8bea88: (15215824, 'defaultManager'),
                 0x8bea90: (15215880, 'stringByAppendingPathComponent:'),
                 0x8becd4: (15215888, 'UTF8String'),
                 0x8becd8: (15215864, 'count'),
                 0x8becdc: (15215860, 'removeObjectForKey:'),
                 0x8bece0: (15215852, 'release'),
                 0x8bece4: (15216320, 'set'),
                 0x8befe0: (15215900, 'dataForKey:'),
                 0x8befec: (15216324, 'stringByAppendingFormat:'),
                 0x8bf094: (15216316, 'loadDynamicObjectsOfType:fromData:physicalBlock:loadedPortal:clientOwnedID:'),
                 0x8bf098: (15216008, 'addObject:'),
                 0x8bf09c: (15216240, 'hasFinishedDatabaseMigrationTo17'),
                 0x8bf0a4: (15215928, 'contentsOfDirectoryAtPath:error:'),
                 0x8bf318: (15215932, 'rangeOfString:'),
                 0x8bf328: (15216328, 'containsObject:'),
                 0x8bf330: (15215916, 'intValue'),
                 0x8bf46c: (15215904, 'dataWithContentsOfFile:'),
                 0x8bf630: (15216208, 'allKeys'),
                 0x8bf638: (15216332, 'loadClientOwnedDynamicObjectsForClient:physicalBlock:'),
                 0x8bf63c: (15216336, 'startPortalPos'),
                 0x8bf640: (15216340, 'workbenchAtPos:'),
                 0x8bf64c: (15216344, 'placeWorkbenchOfType:atPos:saveDict:placedByClient:placedByBlockhead:placedByClientName:'),
                 0x8bfb78: (15216352, 'npcPositions'),
                 0x8bfb80: (15216348, 'plantPositions'),
                 0x8bfc68: (15216356, 'maxOfRockAndDirtHeightForX:'),
                 0x8bfc6c: (15216360, 'getX:Y:octaves:'),
                 0x8bfc78: (15216128, 'worldWidthMacro'),
                 0x8bfe10: (15216364, 'loadPlantAtPosition:type:maxAgeGene:growthRateGene:adult:'),
                 0x8c02ac: (15216368, 'loadNPCAtPosition:type:saveDict:isAdult:wasPlaced:placedByClient:'),
                 0x8c13cc: (15216372, 'updatePhysicalBlockToLatestVersion:'),
                 0x8c13d4: (15216380, 'treePositions'),
                 0x8c14e0: (15216376, 'lightChangedAtMacroPos:sendReliably:'),
                 0x8c1794: (15216384, 'lakeHeightForX:'),
                 0x8c1970: (15216388, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
                 0x8c197c: (15216360, 'getX:Y:octaves:'),
                 0x8c1ed0: (15216392, 'loadTreeAtPosition:type:maxHeight:growthRate:adultTree:adultMaxAge:'),
                 0x8c202c: (15216396, 'dynamicWorld'),
                 0x8c2030: (15216400, 'loadGlowBlockIfNeededAtPos:tile:'),
                 0x8c20c8: (15216396, 'dynamicWorld'),
                 0x8c20cc: (15216400, 'loadGlowBlockIfNeededAtPos:tile:'),
                 0x8c20d4: (15216404, 'addTorchAtPos:ofType:dataA:dataB:saveDict:placedByClient:'),
                 0x8c216c: (15216404, 'addTorchAtPos:ofType:dataA:dataB:saveDict:placedByClient:'),
                 0x8c2484: (15216408, 'createTreasureChestOrTrollAtTile:atPos:loadTroll:loadTreasure:'),
                 0x8c2490: (15216128, 'worldWidthMacro'),
                 0x8c2810: (15216364, 'loadPlantAtPosition:type:maxAgeGene:growthRateGene:adult:'),
                 0x8c2910: (15216364, 'loadPlantAtPosition:type:maxAgeGene:growthRateGene:adult:'),
                 0x8c3974: (15216368, 'loadNPCAtPosition:type:saveDict:isAdult:wasPlaced:placedByClient:'),
                 0x8c3a3c: (15216128, 'worldWidthMacro'),
                 0x8c3a40: (15216360, 'getX:Y:octaves:'),
                 0x8c3a48: (15216368, 'loadNPCAtPosition:type:saveDict:isAdult:wasPlaced:placedByClient:'),
                 0x8c3a5c: (15216364, 'loadPlantAtPosition:type:maxAgeGene:growthRateGene:adult:'),
                 0x8c3a64: (15216416, 'loadSnowSurfaceBlockAtPos:loadSnow:'),
                 0x8c3a6c: (15216036, 'macroTiles'),
                 0x8c3a74: (15216412, 'loadSurfaceBlockAtPos:'),
        },
        imports={
                 0x8be90c: (16333592, '__CFConstantStringClassReference'),
                 0x8bea6c: (16333400, '__CFConstantStringClassReference'),
                 0x8bea70: (17151904, 'objc_msgSend'),
                 0x8befe8: (16333608, '__CFConstantStringClassReference'),
                 0x8bf31c: (16332952, '__CFConstantStringClassReference'),
                 0x8bf32c: (16333624, '__CFConstantStringClassReference'),
                 0x8c0ad8: (17151904, 'objc_msgSend'),
                 0x8c2ad0: (17151904, 'objc_msgSend'),
                 0x8c3a34: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8be910: (17162252, 'OBJC_IVAR_$_DynamicWorld.client', 20),
                 0x8bea68: (17162280, 'OBJC_IVAR_$_DynamicWorld.versionOneToTwoConversionList', 9464),
                 0x8bea94: (17162196, 'OBJC_IVAR_$_DynamicWorld.worldSaveDirectory', 40),
                 0x8befe4: (17162236, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectDatabase', 36),
                 0x8bf0a0: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8bf62c: (17162256, 'OBJC_IVAR_$_DynamicWorld.server', 16),
                 0x8bf634: (17162248, 'OBJC_IVAR_$_DynamicWorld.serverClients', 24),
                 0x8bfb7c: (17162264, 'OBJC_IVAR_$_DynamicWorld.worldTileLoader', 8),
                 0x8bfc70: (17162228, 'OBJC_IVAR_$_DynamicWorld.treeDensityNoiseFunction', 7340),
                 0x8c13d0: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8c2488: (17162228, 'OBJC_IVAR_$_DynamicWorld.treeDensityNoiseFunction', 7340),
                 0x8c34e4: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8c3a30: (17162252, 'OBJC_IVAR_$_DynamicWorld.client', 20),
                 0x8c3a38: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8c3a44: (17162228, 'OBJC_IVAR_$_DynamicWorld.treeDensityNoiseFunction', 7340),
        },
        classes={
                 0x8bea78: (15247792, 'OBJC_CLASS_$_NSString'),
                 0x8bea8c: (15247796, 'OBJC_CLASS_$_NSFileManager'),
                 0x8bece8: (15247868, 'OBJC_CLASS_$_NSMutableSet'),
                 0x8bf504: (15247812, 'OBJC_CLASS_$_NSData'),
        },
        instructions=[(9165240, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9165364, 'movw r0, 0'), (9165404, 'ldr r0, [fp, -0x34]'), (9165664, 'sub r0, fp, 0x68'), (9166708, 'movw r0, 0'), (9169260, 'ldrsb r0, [fp, -0xb1]'), (9169772, 'ldr r0, [fp, -0x34]'), (9171772, 'ldr r0, [fp, -0x34]'), (9174160, 'ldr r0, [fp, -0x34]'), (9176096, 'ldr r0, [fp, -0x34]'), (9176516, 'ldr r0, [fp, -0x3a8]'), (9176988, 'ldr r0, [0x008c0ad8]'), (9177440, 'movw r1, 2'), (9177964, 'bl sym.treeTypeForTreePromise_int_'), (9182956, 'movw r0, 0'), (9185624, 'vstr d2, [sp, 0x178]'), (9188220, 'ldr r0, [fp, -0x3a8]'), (9188252, 'ldrsb r0, [fp, -0x2d]'), (9188256, 'cmp r0, 0'), (9189928, 'sub sp, fp, 0x18'), (9190020, 'rsbseq ip, sb, r4, lsr 12')],
        calls=[(9165356, 'bl sym.imp.NSLog'), (9165520, 'blx ip'), (9165640, 'blx r3'), (9165904, 'blx r3'), (9165940, 'blx r3'), (9165980, 'blx lr'), (9166008, 'bl sym.imp.memset'), (9166056, 'blx lr'), (9166156, 'bl sym.imp.objc_enumerationMutation'), (9166256, 'blx ip'), (9166280, 'blx r2'), (9166312, 'blx r3'), (9166332, 'bl sym.imp.__wrap_rename'), (9166436, 'blx ip'), (9166556, 'blx lr'), (9166592, 'blx r3'), (9166672, 'blx r3'), (9166768, 'blx r2'), (9166908, 'blx r4'), (9166952, 'blx ip'), (9167064, 'blx r4'), (9167128, 'blx r6'), (9167212, 'blx r2'), (9167456, 'blx r3'), (9167492, 'blx r3'), (9167516, 'blx ip'), (9167540, 'bl sym.imp.memset'), (9167588, 'blx lr'), (9167688, 'bl sym.imp.objc_enumerationMutation'), (9167788, 'bl loc.imp.objc_msgSend_stret'), (9167824, 'bl sym.imp.memset'), (9167948, 'blx r6'), (9168028, 'blx ip'), (9168068, 'blx r3'), (9168232, 'blx sl'), (9168256, 'blx r3'), (9168312, 'blx r3'), (9168384, 'blx r5'), (9168492, 'blx ip'), (9168628, 'blx r2'), (9168716, 'bl sym.imp.memset'), (9168764, 'blx lr'), (9168864, 'bl sym.imp.objc_enumerationMutation'), (9168952, 'blx ip'), (9169052, 'blx ip'), (9169152, 'bl loc.imp.objc_msgSend_stret'), (9169200, 'bl sym.imp.memset'), (9169212, 'bl sym.imp.__aeabi_idiv'), (9169240, 'bl sym.imp.__aeabi_idiv'), (9169340, 'bl loc.imp.objc_msgSend'), (9169440, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9169688, 'bl loc.imp.objc_msgSend'), (9169724, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9169876, 'blx lr'), (9169916, 'blx r3'), (9170076, 'bl loc.imp.objc_msgSend'), (9170300, 'bl sym.makeIntpair_int__int_'), (9170404, 'bl loc.imp.objc_msgSend'), (9170492, 'bl loc.imp.objc_msgSend'), (9170532, 'bl sym.clamp_float__float__float_'), (9170608, 'bl loc.imp.objc_msgSend'), (9170696, 'blx lr'), (9170760, 'bl sym.clamp_float__float__float_'), (9171268, 'bl loc.imp.objc_msgSend'), (9171352, 'bl loc.imp.objc_msgSend'), (9171448, 'bl sym.makeIntpair_int__int_'), (9171536, 'bl 0x8ad2a4'), (9171708, 'bl loc.imp.objc_msgSend'), (9171860, 'blx r3'), (9172020, 'bl loc.imp.objc_msgSend'), (9172104, 'bl sym.makeIntpair_int__int_'), (9172200, 'bl loc.imp.objc_msgSend'), (9172324, 'blx r3'), (9172468, 'bl loc.imp.objc_msgSend'), (9172632, 'bl sym.makeIntpair_int__int_'), (9172684, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9172712, 'bl sym.tileIsAirOrSnow_Tile_'), (9172796, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9173044, 'bl loc.imp.objc_msgSend'), (9173132, 'blx lr'), (9173440, 'bl loc.imp.objc_msgSend'), (9173528, 'blx lr'), (9174084, 'bl loc.imp.objc_msgSend'), (9174264, 'blx lr'), (9174304, 'blx r3'), (9174488, 'bl loc.imp.objc_msgSend'), (9174596, 'bl sym.makeIntpair_int__int_'), (9174648, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9174676, 'bl sym.tileIsAirOrSnow_Tile_'), (9174760, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9174952, 'bl loc.imp.objc_msgSend'), (9175216, 'bl loc.imp.objc_msgSend'), (9175304, 'bl loc.imp.objc_msgSend'), (9175344, 'bl sym.clamp_float__float__float_'), (9175420, 'bl loc.imp.objc_msgSend'), (9175508, 'blx lr'), (9175572, 'bl sym.clamp_float__float__float_'), (9176052, 'bl loc.imp.objc_msgSend'), (9176180, 'blx r3'), (9176336, 'bl sym.makeIntpair_int__int_'), (9176380, 'bl loc.imp.objc_msgSend'), (9176416, 'blx r3'), (9176456, 'blx r3'), (9176496, 'blx r3'), (9176628, 'blx r3'), (9176716, 'bl loc.imp.objc_msgSend'), (9176740, 'bl sym.imp.__aeabi_idiv'), (9176824, 'bl loc.imp.objc_msgSend'), (9176848, 'bl sym.imp.__aeabi_idiv'), (9176940, 'bl loc.imp.objc_msgSend'), (9176964, 'bl sym.imp.__aeabi_idiv'), (9177072, 'blx r3'), (9177248, 'bl sym.makeIntpair_int__int_'), (9177388, 'bl loc.imp.objc_msgSend'), (9177412, 'bl sym.imp.__aeabi_idiv'), (9177508, 'bl loc.imp.objc_msgSend'), (9177532, 'bl sym.imp.__aeabi_idiv'), (9177636, 'bl loc.imp.objc_msgSend'), (9177660, 'bl sym.imp.__aeabi_idiv'), (9177804, 'bl loc.imp.objc_msgSend'), (9177932, 'bl sym.makeIntpair_int__int_'), (9177964, 'bl sym.treeTypeForTreePromise_int_'), (9178196, 'bl loc.imp.objc_msgSend'), (9178280, 'bl loc.imp.objc_msgSend'), (9178324, 'bl sym.clamp_float__float__float_'), (9178400, 'bl loc.imp.objc_msgSend'), (9178480, 'blx lr'), (9178536, 'bl sym.clamp_float__float__float_'), (9179012, 'bl loc.imp.objc_msgSend'), (9179104, 'bl loc.imp.objc_msgSend'), (9179212, 'bl loc.imp.objc_msgSend'), (9179232, 'bl sym.tileRequiresGlowBlock_Tile_'), (9179288, 'bl loc.imp.objc_msgSend'), (9179348, 'bl loc.imp.objc_msgSend'), (9179428, 'bl loc.imp.objc_msgSend'), (9179500, 'bl loc.imp.objc_msgSend'), (9179580, 'bl loc.imp.objc_msgSend'), (9179652, 'bl loc.imp.objc_msgSend'), (9179728, 'bl loc.imp.objc_msgSend'), (9179800, 'bl loc.imp.objc_msgSend'), (9179876, 'bl loc.imp.objc_msgSend'), (9179948, 'bl loc.imp.objc_msgSend'), (9180028, 'bl loc.imp.objc_msgSend'), (9180100, 'bl loc.imp.objc_msgSend'), (9180292, 'bl loc.imp.objc_msgSend'), (9180376, 'bl loc.imp.objc_msgSend'), (9180640, 'bl loc.imp.objc_msgSend'), (9180724, 'bl loc.imp.objc_msgSend'), (9180768, 'bl sym.clamp_float__float__float_'), (9180844, 'bl loc.imp.objc_msgSend'), (9180924, 'blx lr'), (9180980, 'bl sym.clamp_float__float__float_'), (9181428, 'bl loc.imp.objc_msgSend'), (9181780, 'bl loc.imp.objc_msgSend'), (9181860, 'blx lr'), (9182184, 'bl loc.imp.objc_msgSend'), (9182264, 'blx lr'), (9182864, 'bl loc.imp.objc_msgSend'), (9183052, 'bl sym.makeIntpair_int__int_'), (9183144, 'bl sym.tileRequiresGlowBlock_Tile_'), (9183200, 'bl loc.imp.objc_msgSend'), (9183260, 'bl loc.imp.objc_msgSend'), (9183352, 'bl loc.imp.objc_msgSend'), (9183424, 'bl loc.imp.objc_msgSend'), (9183516, 'bl loc.imp.objc_msgSend'), (9183588, 'bl loc.imp.objc_msgSend'), (9183672, 'bl loc.imp.objc_msgSend'), (9183744, 'bl loc.imp.objc_msgSend'), (9183824, 'bl loc.imp.objc_msgSend'), (9183896, 'bl loc.imp.objc_msgSend'), (9183976, 'bl loc.imp.objc_msgSend'), (9184048, 'bl loc.imp.objc_msgSend'), (9184248, 'bl sym.makeIntpair_int__int_'), (9184600, 'bl loc.imp.objc_msgSend'), (9184684, 'bl loc.imp.objc_msgSend'), (9184728, 'bl sym.clamp_float__float__float_'), (9184804, 'bl loc.imp.objc_msgSend'), (9184884, 'blx lr'), (9184940, 'bl sym.clamp_float__float__float_'), (9185452, 'bl loc.imp.objc_msgSend'), (9185628, 'bl 0x8ad2a4'), (9185796, 'bl loc.imp.objc_msgSend'), (9185948, 'bl loc.imp.objc_msgSend'), (9186196, 'bl loc.imp.objc_msgSend'), (9186276, 'blx lr'), (9186572, 'bl loc.imp.objc_msgSend'), (9186652, 'blx lr'), (9187380, 'bl loc.imp.objc_msgSend'), (9187464, 'bl loc.imp.objc_msgSend'), (9187508, 'bl sym.clamp_float__float__float_'), (9187584, 'bl loc.imp.objc_msgSend'), (9187664, 'blx lr'), (9187720, 'bl sym.clamp_float__float__float_'), (9188212, 'bl loc.imp.objc_msgSend'), (9188420, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9188432, 'bl sym.tileIsWater_Tile_'), (9188540, 'bl sym.makeIntpair_int__int_'), (9188572, 'bl loc.imp.objc_msgSend'), (9188592, 'bl sym.tileIsAirOrSnow_Tile_'), (9188712, 'blx r2'), (9188756, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (9188768, 'bl sym.tileIsSolid_Tile_'), (9188788, 'bl sym.tileIsWater_Tile_'), (9188840, 'bl sym.makeIntpair_int__int_'), (9188884, 'bl loc.imp.objc_msgSend'), (9189032, 'blx r2'), (9189076, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (9189088, 'bl sym.tileIsWater_Tile_'), (9189156, 'bl sym.makeIntpair_int__int_'), (9189188, 'bl loc.imp.objc_msgSend'), (9189300, 'blx r2'), (9189344, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (9189356, 'bl sym.tileIsWater_Tile_'), (9189424, 'bl sym.makeIntpair_int__int_'), (9189456, 'bl loc.imp.objc_msgSend'), (9189572, 'blx r2'), (9189616, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (9189628, 'bl sym.tileIsWater_Tile_'), (9189696, 'bl sym.makeIntpair_int__int_'), (9189728, 'bl loc.imp.objc_msgSend'), (9189828, 'bl sym.makeIntpair_int__int_'), (9189872, 'bl loc.imp.objc_msgSend')],
        branches=[(9165340, 'bne', 9165364), (9165360, 'b', 9189928), (9165400, 'bne', 9188252), (9165416, 'ble', 9176220), (9165556, 'beq', 9166708), (9165660, 'beq', 9166704), (9166068, 'beq', 9166460), (9166148, 'beq', 9166160), (9166364, 'blo', 9166112), (9166456, 'bne', 9166112), (9166460, 'b', 9166464), (9166600, 'bne', 9166700), (9166700, 'b', 9166704), (9166704, 'b', 9166708), (9166800, 'bge', 9167152), (9166972, 'beq', 9167132), (9167132, 'b', 9167136), (9167148, 'b', 9166792), (9167224, 'bne', 9168524), (9167600, 'beq', 9168516), (9167680, 'beq', 9167692), (9167756, 'beq', 9167796), (9167792, 'b', 9167828), (9167840, 'bne', 9168392), (9168080, 'bne', 9168388), (9168388, 'b', 9168392), (9168392, 'b', 9168396), (9168420, 'blo', 9167644), (9168512, 'bne', 9167644), (9168516, 'b', 9168520), (9168520, 'b', 9168524), (9168564, 'beq', 9168636), (9168776, 'beq', 9169076), (9168856, 'beq', 9168868), (9168980, 'blo', 9168820), (9169072, 'bne', 9168820), (9169076, 'b', 9169080), (9169136, 'beq', 9169172), (9169156, 'b', 9169204), (9169228, 'bne', 9169772), (9169256, 'bne', 9169772), (9169268, 'bne', 9169772), (9169360, 'bne', 9169768), (9169380, 'bge', 9169560), (9169508, 'b', 9169372), (9169768, 'b', 9169772), (9169784, 'bge', 9171772), (9169944, 'bge', 9171768), (9170016, 'bne', 9171272), (9170112, 'blt', 9170128), (9170124, 'blt', 9170156), (9170128, 'b', 9171720), (9170836, 'bge', 9170852), (9170848, 'b', 9170860), (9170896, 'bge', 9170928), (9170908, 'b', 9170936), (9171016, 'bge', 9171032), (9171028, 'b', 9171040), (9171076, 'bge', 9171132), (9171088, 'b', 9171140), (9171280, 'beq', 9171296), (9171292, 'bne', 9171716), (9171388, 'blt', 9171404), (9171400, 'blt', 9171408), (9171404, 'b', 9171720), (9171460, 'bne', 9171496), (9171480, 'bge', 9171492), (9171484, 'b', 9171720), (9171492, 'b', 9171496), (9171716, 'b', 9171720), (9171732, 'b', 9169936), (9171768, 'b', 9171772), (9171784, 'bge', 9172236), (9171888, 'bge', 9172232), (9171944, 'bne', 9172208), (9172056, 'blt', 9172072), (9172068, 'blt', 9172080), (9172072, 'b', 9172212), (9172208, 'b', 9172212), (9172224, 'b', 9171880), (9172232, 'b', 9172236), (9172248, 'bge', 9174160), (9172352, 'bge', 9174156), (9172408, 'bne', 9174096), (9172504, 'blt', 9172520), (9172516, 'blt', 9172592), (9172520, 'b', 9174100), (9172704, 'beq', 9174092), (9172724, 'beq', 9174092), (9172740, 'bne', 9174092), (9172816, 'beq', 9174088), (9172832, 'beq', 9172868), (9172848, 'beq', 9172868), (9172864, 'bne', 9174088), (9173196, 'ble', 9173284), (9173228, 'ble', 9173280), (9173260, 'ble', 9173276), (9173276, 'b', 9173280), (9173280, 'b', 9173284), (9173576, 'ble', 9173628), (9173608, 'ble', 9173624), (9173624, 'b', 9173628), (9173768, 'bge', 9173788), (9173784, 'b', 9173796), (9173860, 'bge', 9173900), (9173876, 'b', 9173908), (9174088, 'b', 9174092), (9174092, 'b', 9174096), (9174096, 'b', 9174100), (9174112, 'b', 9172344), (9174156, 'b', 9174160), (9174172, 'bge', 9176096), (9174332, 'bge', 9176092), (9174404, 'beq', 9174432), (9174416, 'beq', 9174432), (9174428, 'bne', 9176068), (9174524, 'blt', 9174540), (9174536, 'blt', 9174556), (9174540, 'b', 9176072), (9174668, 'beq', 9176064), (9174688, 'beq', 9176064), (9174704, 'bne', 9176064), (9174780, 'beq', 9176060), (9174796, 'beq', 9174832), (9174812, 'beq', 9174832), (9174828, 'bne', 9176060), (9174840, 'bne', 9174960), (9174968, 'beq', 9174984), (9174980, 'bne', 9176056), (9175648, 'bge', 9175664), (9175660, 'b', 9175672), (9175708, 'bge', 9175732), (9175720, 'b', 9175740), (9175820, 'bge', 9175836), (9175832, 'b', 9175844), (9175880, 'bge', 9175916), (9175892, 'b', 9175924), (9176056, 'b', 9176060), (9176060, 'b', 9176064), (9176064, 'b', 9176068), (9176068, 'b', 9176072), (9176084, 'b', 9174324), (9176092, 'b', 9176096), (9176108, 'bge', 9176184), (9176196, 'b', 9188248), (9176524, 'bge', 9188244), (9176644, 'beq', 9176988), (9176752, 'beq', 9176988), (9176860, 'beq', 9176988), (9176984, 'bne', 9177824), (9177092, 'bge', 9177108), (9177104, 'b', 9177116), (9177160, 'bge', 9177180), (9177172, 'b', 9177188), (9177272, 'blt', 9177808), (9177308, 'bge', 9177808), (9177424, 'bne', 9177440), (9177436, 'b', 9177700), (9177544, 'bne', 9177560), (9177556, 'b', 9177696), (9177680, 'bne', 9177692), (9177692, 'b', 9177696), (9177696, 'b', 9177700), (9177808, 'b', 9188220), (9177852, 'ble', 9182956), (9177876, 'bge', 9182924), (9177980, 'beq', 9179228), (9178616, 'bge', 9178632), (9178628, 'b', 9178640), (9178676, 'bge', 9178692), (9178688, 'b', 9178700), (9178784, 'bge', 9178800), (9178796, 'b', 9178808), (9178844, 'bge', 9178880), (9178856, 'b', 9178888), (9179024, 'bne', 9179120), (9179112, 'b', 9179224), (9179128, 'bne', 9179220), (9179220, 'b', 9179224), (9179224, 'b', 9182904), (9179244, 'beq', 9179360), (9179352, 'b', 9182900), (9179372, 'bne', 9179512), (9179504, 'b', 9182896), (9179524, 'bne', 9179660), (9179656, 'b', 9182892), (9179672, 'bne', 9179808), (9179804, 'b', 9182888), (9179820, 'bne', 9179960), (9179952, 'b', 9182884), (9179972, 'bne', 9180120), (9180104, 'b', 9182880), (9180132, 'beq', 9180168), (9180148, 'beq', 9180168), (9180164, 'bne', 9180404), (9180248, 'bne', 9180380), (9180380, 'b', 9182876), (9180416, 'bne', 9181460), (9181060, 'bge', 9181080), (9181072, 'b', 9181088), (9181124, 'bge', 9181140), (9181136, 'b', 9181148), (9181232, 'bge', 9181248), (9181244, 'b', 9181256), (9181292, 'bge', 9181308), (9181304, 'b', 9181316), (9181432, 'b', 9182872), (9181472, 'beq', 9181508), (9181488, 'beq', 9181508), (9181504, 'bne', 9182868), (9181528, 'bne', 9181576), (9181540, 'b', 9181604), (9181588, 'bne', 9181600), (9181600, 'b', 9181604), (9181948, 'ble', 9182036), (9182004, 'ble', 9182032), (9182016, 'bne', 9182032), (9182032, 'b', 9182036), (9182312, 'ble', 9182400), (9182368, 'ble', 9182396), (9182380, 'ble', 9182396), (9182396, 'b', 9182400), (9182540, 'bge', 9182584), (9182556, 'b', 9182592), (9182656, 'bge', 9182680), (9182672, 'b', 9182688), (9182868, 'b', 9182872), (9182872, 'b', 9182876), (9182876, 'b', 9182880), (9182880, 'b', 9182884), (9182884, 'b', 9182888), (9182888, 'b', 9182892), (9182892, 'b', 9182896), (9182896, 'b', 9182900), (9182900, 'b', 9182904), (9182904, 'b', 9182908), (9182920, 'b', 9177868), (9182924, 'b', 9184104), (9182976, 'bge', 9184100), (9183088, 'beq', 9184076), (9183104, 'bgt', 9183140), (9183120, 'bgt', 9183140), (9183136, 'ble', 9184076), (9183156, 'beq', 9183284), (9183264, 'b', 9184072), (9183296, 'bne', 9183448), (9183428, 'b', 9184068), (9183460, 'bne', 9183604), (9183592, 'b', 9184064), (9183616, 'bne', 9183756), (9183748, 'b', 9184060), (9183768, 'bne', 9183908), (9183900, 'b', 9184056), (9183920, 'bne', 9184052), (9184052, 'b', 9184056), (9184056, 'b', 9184060), (9184060, 'b', 9184064), (9184064, 'b', 9184068), (9184068, 'b', 9184072), (9184072, 'b', 9184076), (9184076, 'b', 9184080), (9184092, 'b', 9182968), (9184100, 'b', 9184104), (9184136, 'ble', 9184144), (9184140, 'b', 9188220), (9184176, 'bge', 9184184), (9184180, 'b', 9188220), (9184312, 'bne', 9184348), (9184324, 'bne', 9184348), (9184336, 'bne', 9184348), (9184340, 'b', 9188220), (9184356, 'beq', 9185456), (9184368, 'blt', 9184384), (9184380, 'blt', 9184404), (9184384, 'b', 9188220), (9185020, 'bge', 9185036), (9185032, 'b', 9185044), (9185080, 'bge', 9185096), (9185092, 'b', 9185104), (9185188, 'bge', 9185204), (9185200, 'b', 9185212), (9185248, 'bge', 9185304), (9185260, 'b', 9185312), (9185464, 'beq', 9185960), (9185476, 'beq', 9185492), (9185488, 'bne', 9185808), (9185500, 'bne', 9185556), (9185520, 'bge', 9185528), (9185524, 'b', 9188220), (9185540, 'bge', 9185548), (9185544, 'b', 9188220), (9185548, 'b', 9185596), (9185564, 'blt', 9185580), (9185576, 'blt', 9185592), (9185580, 'b', 9188220), (9185592, 'b', 9185596), (9185804, 'b', 9185956), (9185816, 'blt', 9185832), (9185828, 'blt', 9185840), (9185832, 'b', 9188220), (9185956, 'b', 9185960), (9185968, 'beq', 9188216), (9185980, 'blt', 9185996), (9185992, 'blt', 9186016), (9185996, 'b', 9188220), (9186036, 'bne', 9187176), (9186336, 'ble', 9186424), (9186368, 'ble', 9186420), (9186400, 'ble', 9186416), (9186416, 'b', 9186420), (9186420, 'b', 9186424), (9186700, 'ble', 9186752), (9186732, 'ble', 9186748), (9186748, 'b', 9186752), (9186892, 'bge', 9186912), (9186908, 'b', 9186920), (9186984, 'bge', 9187008), (9187000, 'b', 9187016), (9187124, 'b', 9188112), (9187800, 'bge', 9187816), (9187812, 'b', 9187824), (9187860, 'bge', 9187880), (9187872, 'b', 9187888), (9187972, 'bge', 9187992), (9187984, 'b', 9188000), (9188036, 'bge', 9188064), (9188048, 'b', 9188072), (9188216, 'b', 9188220), (9188232, 'b', 9176516), (9188244, 'b', 9188248), (9188248, 'b', 9188252), (9188260, 'beq', 9189928), (9188284, 'bge', 9189924), (9188340, 'bge', 9189904), (9188444, 'beq', 9188588), (9188460, 'bge', 9188588), (9188500, 'bne', 9188576), (9188576, 'b', 9189884), (9188604, 'beq', 9189756), (9188780, 'bne', 9188804), (9188800, 'beq', 9188888), (9188924, 'bne', 9189744), (9189100, 'beq', 9189196), (9189116, 'ble', 9189196), (9189192, 'b', 9189740), (9189368, 'beq', 9189468), (9189384, 'ble', 9189468), (9189460, 'b', 9189736), (9189640, 'beq', 9189732), (9189656, 'ble', 9189732), (9189732, 'b', 9189736), (9189736, 'b', 9189740), (9189740, 'b', 9189744), (9189744, 'b', 9189880), (9189768, 'beq', 9189876), (9189784, 'bne', 9189876), (9189876, 'b', 9189880), (9189880, 'b', 9189884), (9189884, 'b', 9189888), (9189900, 'b', 9188332), (9189904, 'b', 9189908), (9189920, 'b', 9188276), (9189924, 'b', 9189928)],
        semantics=("loadDynamicObjectsForMacroTile:includeSurfaceBlocks: is the per-macro-tile dynamic-object restore for the local/server world. Prologue 0x008bd9b8 (frame 0x318+0xc00; PIC base via cell 0x008be908). Arguments: macroTile pointer [fp,-0x2c] (an ObjC struct pointer; its PhysicalBlock pointer lives at +4, so the block is macroTile->physicalBlock) and the includeSurfaceBlocks char [fp,-0x2d]. If macroTile->physicalBlock is NULL the body logs (string 0xfff34024) and returns (0x008c3a28). A [self client] read (ivar through cell 0x008be910) selects the client path (0x008c339c) - clients skip the local load and go straight to the surface-block pass.\n\nServer path, version ladder: the block's byte at +0xd (E16's version field) is read three times in a ladder - `>= 2` (0x008beb6c) -> `>= 6` (0x008bf33c) -> `>= 7` (0x008bf50c) -> `>= 8` (0x008bfc90); a byte <= 0 falls to 0x008c049c.\n- Version < 2: the one-to-two conversion pass - the body enumerates self->versionOneToTwoConversionList (cell 0x008bea68; stringWithFormat:/objectForKey:/rangeOfString:/componentsSeparatedByString: machinery), and per item runs a file migration: UTF8String-based paths under self->worldSaveDirectory are handed to `bl sym.imp.__wrap_rename` (0x008bddfc); afterwards removeObjectForKey:/release cleanups (0x008bde80-0x008bdf68).\n- Versions 2..5 (0x008bf33c): a 32-loop over npcPositions (index = i + (block->0 << 5)); marker 7 hits are zeroed and the position is reloaded via loadNPCAtPosition:type:saveDict:isAdult:wasPlaced:placedByClient: (cell 0x008c02ac) with stacked (0, 1, 0, 0, type).\n- Version 6 (0x008bf50c): a second 32-loop of the same family (marker gate cmp marker, 7 at 0x008bf3e0).\n- Version >= 8 (0x008c0420): if the byte at +0xd is still < 8 the body calls `[self.world updatePhysicalBlockToLatestVersion:physicalBlock]` (selector cell 0x008c13cc, world via cell 0x008c13d0) and then writes **byte +0xd = 8** - the direct caller of the E15 migration body. The `<= 0` arm (0x008c049c) also stamps 8 and issues lightChangedAtMacroPos:sendReliably:1 (cell 0x008c14e0) with makeIntpair(block->0, block->1), then reads back treePositions/plantPositions/npcPositions (cells 0x008bfb78/0x008bfb80) into locals.\n\nWorkbench fixup (0x008be958-0x008beb68): an idiv-derived comparison and `[self workbenchAtPos:]` (cell 0x008bf640); when nil and the surface flag allows, the two tiles at (x, y) and (x, y+1) from tileAtWorldPositionLoaded are stamped byte0=2, byte1=2, byte3=0, byte0xb=0, byte0xc=0; then placeWorkbenchOfType:atPos:saveDict:placedByClient:placedByBlockhead:placedByClientName: (cell 0x008bf64c) runs with zeroed stacked args and the tile at (x, y-1) gets byte0=0x19, byte2=1, byte3=0.\n\nThe 32-column outer loop (0x008c05c4, idx [fp,-0x3a8], x = (block->0 << 5) + i): quarter columns x == W*32/4, W*32/2 and W*32*3/4 (idivs 0x008c0648-0x008c0798) jump to 0x008c079c: the body samples `[self.worldTileLoader lakeHeightForX:x]` (cell 0x008c1794), max-combines with the tracked level, clamps to 0x200, adds 0x10 and requires the row to lie in [block->1 << 5, (block->1 + 1) << 5); then idiv W*32/2 == x selects promise id 0x8c else 0x8e, and loadTreeAtPosition:type:maxHeight:growthRate:adultTree:adultMaxAge: (cell 0x008c1970) plants it. Non-quarter columns run the main body from 0x008c0ae0.\n\nNon-quarter body: the tree-promise pool - 64-byte records based at block->tiles (+8); record byte3 is the promise type, mapped by treeTypeForTreePromise (0x008c0b6c); a nonzero type is consumed (byte3 = 0) and the record is planted as a tree: a treeDensityNoiseFunction noise chain (cell 0x008bfc70; constants 0x008c0ef0/0x008c0ef8) derives the geometry floats (packed into the DrawBlock at [fp,-0x6f0], fields +0x124/+0x11c/+0x118/+0x120 with clamp 0..1 and a x5.0 scale), then loadTreeAtPosition:... with the type and a f64 growth argument (0x497423fe); type 1 takes an extra arm (0x008c0ff0). x == W*16 selects promise id 0x8f and x == W*24 selects 0x8d (idiv pair at 0x008c0960) before planting. A second 32-loop (0x008c1eec) walks the same 64-byte records and acts on the nonzero ushort pairs at +0xe/+0x10.\n\nMarker scan (0x008bfd34-0x008c0404): per column the npcPositions and plantPositions arrays are read (index = i + (block->0 << 5), plant index = i; local y = value - (block->1 << 5) must be in 0..0x1f). Marker 6 (cmp marker, 6 at 0x8bec58) starts the treasure/troll arm: makeIntpair (0x008bed7c), the treeDensityNoiseFunction getX:Y:octaves: chain with constants (0, 8, 5, f64 0x3fddc432c0... / 0xca57a787...), two clamp(float, 0, 1) calls (0x008bee64/0x008bef48) with x5.0 scales, a 0..0xff clamp and the DrawBlock bit-packing (ushort +0x24/+0x26 into +0x16 and mirrors at +0x14/+0x12/+0x10/+0xe/+0xc/+2/+0, LOD ids 4/5/7 by magnitude - the same packing family the NPC arm uses at +0x3c/+0x3e). Marker 8 additionally repairs a tree-top glow block: tile (x, y) must be air-or-snow with byte1 == 2 and tile (x, y-1) must be an existing trunk (byte0 in {6, 0x1b, 0x1c}); then npc==8 zeroes npcPositions[idx] and reloads loadNPCAtPosition:..., while plant 9/0xa runs the noise chain and loadPlantAtPosition:type:maxAgeGene:growthRateGene:adult: (cell 0x008bfe10) with (8, sxth packed, sxth packed, 1). The generic arm (0x008c2f68) builds the same noise->pack->loadPlantAtPosition dispatch with loadPlantAtPosition (cells 0x008c3a5c) and type = the marker. The outer loop increments at 0x008c337c and exits at bound 0x20.\n\nSurface pass (self client == 0 only, gate at 0x008c33a0 on includeSurfaceBlocks): double loop j/x in 0..31: tileAtWorldPositionLoaded(x, y) - water with byte4 < 0xff -> loadSnowSurfaceBlockAtPos:loadSnow: (cell 0x008c3a74); air-or-snow -> macroTiles lookup (cell 0x008c3a6c) + tileAtWorldPosition(x, y-1/y/y+1, macroTile, world) (sym.tileAtWorldPosition_int__int__MacroTile__World_) - solid or water -> loadSurfaceBlockAtPos: (cell 0x008c3a64) with stacked 1; water byte4 > 1 neighbors -> snow calls; tile byte0 == 4 -> loadSurfaceBlockAtPos. Exits join the epilogue 0x008c3a28 (`sub sp, fp, 0x18; pop {r4-r8,sl,fp,pc}`).\n"),
    ),
    dict(
        name='wtl_loaddynamicobjects_rep',
        method='DynamicWorld -[loadDynamicObjects:repositionBlockheadLoadFailures:]',
        types='c16@0:4c8c12',
        start=9104812,
        end=9117104,
        disasm='disasm_worldtileloader_loaddynamicobjects_repositionblockheadlo.txt',
        base_add=9104832,
        base_literal=9108172,
        boundary='ARM.exidx end 0x008b1db0 (listing bound); next ObjC IMP 0x008b1dd4 DynamicWorld -[sendLightblocksToClients]',
        selectors={
                 0x8afadc: (15215900, 'dataForKey:'),
                 0x8afe6c: (15215828, 'fileExistsAtPath:'),
                 0x8afe70: (15215824, 'defaultManager'),
                 0x8afe78: (15215880, 'stringByAppendingPathComponent:'),
                 0x8afef8: (15215904, 'dataWithContentsOfFile:'),
                 0x8aff80: (15215908, 'dictionaryWithContentsOfFile:'),
                 0x8aff8c: (15215884, 'objectForKey:'),
                 0x8aff94: (15215920, 'boolValue'),
                 0x8affa0: (15215916, 'intValue'),
                 0x8affb0: (15215912, 'unsignedLongValue'),
                 0x8affbc: (15215924, 'initWithDictionary:'),
                 0x8affc0: (15215804, 'alloc'),
                 0x8b0308: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8b030c: (15215928, 'contentsOfDirectoryAtPath:error:'),
                 0x8b0314: (15215800, 'init'),
                 0x8b0318: (15215932, 'rangeOfString:'),
                 0x8b0328: (15215864, 'count'),
                 0x8b0330: (15215936, 'componentsSeparatedByString:'),
                 0x8b0334: (15215808, 'objectAtIndex:'),
                 0x8b033c: (15215816, 'stringWithFormat:'),
                 0x8b0820: (15215944, 'setObject:forKey:'),
                 0x8b0824: (15215940, 'dictionary'),
                 0x8b0828: (15215956, 'detachNewThreadSelector:toTarget:withObject:'),
                 0x8b082c: (15215952, 'conversionThread:'),
                 0x8b0834: (15215948, 'dictionaryWithDictionary:'),
                 0x8b0838: (15215852, 'release'),
                 0x8b083c: (15215972, 'finishDecoding'),
                 0x8b0840: (15215968, 'autorelease'),
                 0x8b0844: (15215820, 'retain'),
                 0x8b084c: (15215964, 'decodeObjectForKey:'),
                 0x8b0850: (15215960, 'initForReadingWithData:'),
                 0x8b085c: (15215976, 'addIndexes:'),
                 0x8b086c: (15215980, 'customRules'),
                 0x8b0878: (15215984, 'localPlayerID'),
                 0x8b087c: (15215988, 'gzipInflate'),
                 0x8b13f4: (15215888, 'UTF8String'),
                 0x8b1b6c: (15215900, 'dataForKey:'),
                 0x8b1d1c: (15215992, 'blockheadWithIDIncludingNet:'),
                 0x8b1d28: (15215884, 'objectForKey:'),
                 0x8b1d30: (15215912, 'unsignedLongValue'),
                 0x8b1d34: (15215804, 'alloc'),
                 0x8b1d38: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8b1d3c: (15215864, 'count'),
                 0x8b1d40: (15215968, 'autorelease'),
                 0x8b1d48: (15215980, 'customRules'),
                 0x8b1d54: (15215996, 'removeObject:'),
                 0x8b1d60: (15215844, 'blockheadWillBeUnloaded:'),
                 0x8b1d64: (15216000, 'propertyListWithData:options:format:error:'),
                 0x8b1d70: (15216004, 'initWithWorld:dynamicWorld:saveDict:savedInventorySlots:cache:repositionOnLoadFailure:clientSaveDir:clientLocallySavedDict:'),
                 0x8b1d7c: (15216008, 'addObject:'),
                 0x8b1d80: (15216012, 'pos'),
                 0x8b1d84: (15216020, 'sendNetDataIfNeededForObject:isCreation:'),
                 0x8b1d88: (15216016, 'fullyLoadIfNeededAroundPos:clientLightBlockIndex:forBlockhead:'),
                 0x8b1d94: (15216028, 'stopInteractingWithInteractionObjectsIfNoInteractionObject'),
                 0x8b1d98: (15216032, 'die'),
                 0x8b1dac: (15216024, 'blockheadsLoaded'),
        },
        imports={
                 0x8afad0: (17151968, '__stack_chk_guard'),
                 0x8afad4: (16332824, '__CFConstantStringClassReference'),
                 0x8afad8: (17151904, 'objc_msgSend'),
                 0x8aff7c: (16332840, '__CFConstantStringClassReference'),
                 0x8aff88: (16332904, '__CFConstantStringClassReference'),
                 0x8aff98: (16332888, '__CFConstantStringClassReference'),
                 0x8affa4: (16332872, '__CFConstantStringClassReference'),
                 0x8affac: (16332856, '__CFConstantStringClassReference'),
                 0x8b0304: (16332920, '__CFConstantStringClassReference'),
                 0x8b031c: (16332936, '__CFConstantStringClassReference'),
                 0x8b032c: (16332952, '__CFConstantStringClassReference'),
                 0x8b0338: (16332968, '__CFConstantStringClassReference'),
                 0x8b0848: (16333000, '__CFConstantStringClassReference'),
                 0x8b0858: (16332984, '__CFConstantStringClassReference'),
                 0x8b0868: (16333016, '__CFConstantStringClassReference'),
                 0x8b0874: (16333032, '__CFConstantStringClassReference'),
                 0x8b0880: (16333048, '__CFConstantStringClassReference'),
                 0x8b13f8: (16333064, '__CFConstantStringClassReference'),
                 0x8b1974: (16333096, '__CFConstantStringClassReference'),
                 0x8b197c: (16333080, '__CFConstantStringClassReference'),
                 0x8b1984: (16333112, '__CFConstantStringClassReference'),
                 0x8b1b68: (17151904, 'objc_msgSend'),
                 0x8b1d20: (17151968, '__stack_chk_guard'),
                 0x8b1d24: (17151904, 'objc_msgSend'),
                 0x8b1d50: (16333080, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x8afae0: (17162240, 'OBJC_IVAR_$_DynamicWorld.worldDatabase', 32),
                 0x8afe7c: (17162196, 'OBJC_IVAR_$_DynamicWorld.worldSaveDirectory', 40),
                 0x8aff90: (17162316, 'OBJC_IVAR_$_DynamicWorld.workbenchHasBeenCrafted', 7370),
                 0x8aff9c: (17162320, 'OBJC_IVAR_$_DynamicWorld.activeBlockheadIndex', 7360),
                 0x8affb4: (17162324, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectIDCount', 7352),
                 0x8affb8: (17162328, 'OBJC_IVAR_$_DynamicWorld.poleItemTakenTimes', 9516),
                 0x8b0310: (17162280, 'OBJC_IVAR_$_DynamicWorld.versionOneToTwoConversionList', 9464),
                 0x8b0860: (17162204, 'OBJC_IVAR_$_DynamicWorld.portalPositions', 7332),
                 0x8b0864: (17162252, 'OBJC_IVAR_$_DynamicWorld.client', 20),
                 0x8b0870: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8b1b70: (17162240, 'OBJC_IVAR_$_DynamicWorld.worldDatabase', 32),
                 0x8b1d2c: (17162320, 'OBJC_IVAR_$_DynamicWorld.activeBlockheadIndex', 7360),
                 0x8b1d44: (17162252, 'OBJC_IVAR_$_DynamicWorld.client', 20),
                 0x8b1d4c: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8b1d58: (17162220, 'OBJC_IVAR_$_DynamicWorld.blockheads', 44),
                 0x8b1d5c: (17162216, 'OBJC_IVAR_$_DynamicWorld.netBlockheads', 48),
                 0x8b1d74: (17162232, 'OBJC_IVAR_$_DynamicWorld.cache', 7336),
                 0x8b1d90: (17162332, 'OBJC_IVAR_$_DynamicWorld.hasLoadedBlockheads', 7368),
                 0x8b1d9c: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8b1da4: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
        },
        classes={
                 0x8afe74: (15247796, 'OBJC_CLASS_$_NSFileManager'),
                 0x8afefc: (15247812, 'OBJC_CLASS_$_NSData'),
                 0x8aff84: (15247816, 'OBJC_CLASS_$_NSDictionary'),
                 0x8affc4: (15247784, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x8b0340: (15247792, 'OBJC_CLASS_$_NSString'),
                 0x8b0830: (15247804, 'OBJC_CLASS_$_NSThread'),
                 0x8b0854: (15247820, 'OBJC_CLASS_$_NSKeyedUnarchiver'),
                 0x8b1d68: (15247824, 'OBJC_CLASS_$_NSPropertyListSerialization'),
                 0x8b1d78: (15247828, 'OBJC_CLASS_$_Blockhead'),
        },
        instructions=[(9104812, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9104896, 'movw r0, 0'), (9105028, 'ldr r0, [0x008afad8]'), (9105616, 'movw r0, 0'), (9106288, 'sub r0, fp, 0x328'), (9106404, 'ldr r0, [0x008b0310]'), (9108196, 'movw r0, 0'), (9108296, 'movw r0, 0'), (9108792, 'movw r0, 0'), (9111080, 'sxtb r0, r0'), (9111340, 'movw r0, 0'), (9111776, 'sub r0, fp, 0x3f8'), (9113672, 'movw r0, 0'), (9114196, 'sub lr, fp, 0x300'), (9114932, 'ldr r0, [0x008b1d24]'), (9115104, 'str r0, [fp, -0x534]'), (9116044, 'sub r8, fp, 0x400'), (9116892, 'movw r0, 1'), (9117100, 'invalid')],
        calls=[(9104976, 'blx r3'), (9105004, 'bl 0x8b1db0'), (9105152, 'blx r5'), (9105188, 'blx r3'), (9105208, 'blx r3'), (9105288, 'blx r3'), (9105316, 'bl 0x8b1db0'), (9105472, 'blx r5'), (9105508, 'blx r3'), (9105528, 'blx r3'), (9105600, 'blx r3'), (9105848, 'bl loc.imp.objc_msgSend'), (9105864, 'bl loc.imp.objc_msgSend'), (9105920, 'blx ip'), (9105936, 'blx r2'), (9105980, 'blx r3'), (9105996, 'blx r2'), (9106040, 'blx r3'), (9106136, 'blx r2'), (9106156, 'blx r3'), (9106252, 'blx ip'), (9106268, 'blx r2'), (9106532, 'blx r2'), (9106548, 'blx r2'), (9106600, 'blx ip'), (9106640, 'blx ip'), (9106664, 'bl sym.imp.memset'), (9106712, 'blx lr'), (9106812, 'bl sym.imp.objc_enumerationMutation'), (9106912, 'bl loc.imp.objc_msgSend_stret'), (9106948, 'bl sym.imp.memset'), (9107040, 'blx ip'), (9107064, 'blx r2'), (9107280, 'blx r6'), (9107316, 'blx r3'), (9107360, 'blx lr'), (9107404, 'blx ip'), (9107448, 'blx ip'), (9107492, 'blx r3'), (9107524, 'blx r3'), (9107568, 'blx ip'), (9107672, 'blx lr'), (9107720, 'blx lr'), (9107780, 'blx ip'), (9107888, 'blx ip'), (9107976, 'blx r2'), (9108108, 'blx r4'), (9108164, 'blx ip'), (9108264, 'blx r3'), (9108536, 'blx r3'), (9108572, 'blx r3'), (9108592, 'blx r3'), (9108620, 'blx r3'), (9108636, 'blx r2'), (9108652, 'blx r2'), (9108676, 'blx r2'), (9108696, 'blx r2'), (9108784, 'blx r3'), (9108920, 'blx r3'), (9109048, 'blx lr'), (9109088, 'blx ip'), (9109232, 'bl loc.imp.objc_msgSend_stret'), (9109276, 'bl sym.imp.memset'), (9109364, 'bl loc.imp.objc_msgSend_stret'), (9109476, 'bl sym.imp.memset'), (9109640, 'blx r2'), (9109684, 'blx ip'), (9109728, 'blx ip'), (9109856, 'blx lr'), (9109872, 'blx r2'), (9110064, 'blx r7'), (9110096, 'blx r3'), (9110132, 'blx r3'), (9110152, 'blx r3'), (9110244, 'blx ip'), (9110260, 'blx r2'), (9110480, 'blx r8'), (9110524, 'blx r3'), (9110560, 'blx r3'), (9110580, 'blx r3'), (9110640, 'blx r3'), (9110672, 'blx r3'), (9110692, 'bl sym.imp.__wrap_rename'), (9110928, 'blx r3'), (9110988, 'blx r3'), (9111020, 'blx r3'), (9111056, 'blx r3'), (9111076, 'blx r3'), (9111168, 'blx ip'), (9111184, 'blx r2'), (9111228, 'bl 0x8b1db0'), (9111312, 'blx ip'), (9111452, 'bl loc.imp.objc_msgSend_stret'), (9111488, 'bl sym.imp.memset'), (9111576, 'bl loc.imp.objc_msgSend_stret'), (9111712, 'bl sym.imp.memset'), (9111752, 'bl 0x8b1db0'), (9111912, 'blx ip'), (9111936, 'bl sym.imp.memset'), (9111984, 'blx lr'), (9112084, 'bl sym.imp.objc_enumerationMutation'), (9112188, 'bl loc.imp.objc_msgSend'), (9112204, 'bl loc.imp.objc_msgSend'), (9112284, 'bl loc.imp.objc_msgSend'), (9112404, 'bl loc.imp.objc_msgSend'), (9112472, 'bl loc.imp.objc_msgSend'), (9112556, 'blx r3'), (9112700, 'blx r5'), (9112736, 'blx r3'), (9112756, 'blx r3'), (9112828, 'blx r3'), (9112900, 'bl loc.imp.objc_msgSend'), (9113016, 'blx r4'), (9113056, 'blx ip'), (9113096, 'blx ip'), (9113180, 'blx lr'), (9113288, 'bl sym.imp.memset'), (9113336, 'blx lr'), (9113436, 'bl sym.imp.objc_enumerationMutation'), (9113484, 'bl loc.imp.objc_msgSend'), (9113500, 'bl loc.imp.objc_msgSend'), (9113640, 'blx ip'), (9113784, 'blx r3'), (9113904, 'blx lr'), (9113920, 'blx r2'), (9114024, 'blx r3'), (9114168, 'blx ip'), (9114324, 'bl sym.imp.memset'), (9114388, 'blx lr'), (9114492, 'bl sym.imp.objc_enumerationMutation'), (9114604, 'bl loc.imp.objc_msgSend_stret'), (9114648, 'bl sym.imp.memset'), (9114748, 'bl loc.imp.objc_msgSend'), (9114792, 'blx ip'), (9114900, 'blx ip'), (9115020, 'blx r2'), (9115504, 'blx r2'), (9115540, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9115944, 'blx r2'), (9115984, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9116144, 'bl sym.imp.memset'), (9116208, 'blx lr'), (9116312, 'bl sym.imp.objc_enumerationMutation'), (9116400, 'blx r3'), (9116508, 'bl loc.imp.objc_msgSend_stret'), (9116560, 'bl sym.imp.memset'), (9116652, 'bl loc.imp.objc_msgSend_stret'), (9116688, 'bl sym.imp.memset'), (9116748, 'blx r2'), (9116860, 'blx ip'), (9116952, 'bl sym.imp.__stack_chk_fail')],
        branches=[(9104892, 'beq', 9105616), (9104996, 'beq', 9105012), (9105024, 'bne', 9105332), (9105220, 'beq', 9105328), (9105308, 'beq', 9105324), (9105324, 'b', 9105328), (9105328, 'b', 9105332), (9105344, 'bne', 9105612), (9105540, 'beq', 9105608), (9105608, 'b', 9105612), (9105612, 'b', 9105616), (9105628, 'beq', 9108792), (9106060, 'beq', 9106180), (9106284, 'bge', 9108296), (9106724, 'beq', 9107912), (9106804, 'beq', 9106816), (9106880, 'beq', 9106920), (9106916, 'b', 9106952), (9106964, 'beq', 9107788), (9107072, 'bne', 9107784), (9107588, 'bne', 9107724), (9107784, 'b', 9107788), (9107788, 'b', 9107792), (9107816, 'blo', 9106768), (9107908, 'bne', 9106768), (9107912, 'b', 9107916), (9107984, 'bls', 9108196), (9108168, 'b', 9108292), (9108292, 'b', 9108296), (9108712, 'beq', 9108788), (9108788, 'b', 9108792), (9108836, 'bne', 9109120), (9108940, 'bne', 9109096), (9109096, 'b', 9111204), (9109156, 'beq', 9111200), (9109216, 'beq', 9109248), (9109236, 'b', 9109280), (9109288, 'beq', 9109492), (9109348, 'beq', 9109448), (9109368, 'b', 9109480), (9109488, 'beq', 9111200), (9109748, 'beq', 9110340), (9109892, 'bne', 9110272), (9110164, 'beq', 9110268), (9110268, 'b', 9110272), (9110272, 'b', 9111196), (9110592, 'beq', 9110700), (9111088, 'beq', 9111192), (9111192, 'b', 9111196), (9111196, 'b', 9111200), (9111200, 'b', 9111204), (9111220, 'beq', 9111324), (9111248, 'beq', 9111320), (9111320, 'b', 9111324), (9111336, 'beq', 9116892), (9111376, 'beq', 9111728), (9111436, 'beq', 9111460), (9111456, 'b', 9111492), (9111500, 'beq', 9111728), (9111560, 'beq', 9111684), (9111580, 'b', 9111716), (9111724, 'beq', 9116892), (9111744, 'beq', 9111760), (9111772, 'beq', 9114932), (9111996, 'beq', 9114192), (9112076, 'beq', 9112088), (9112320, 'beq', 9112480), (9112576, 'bne', 9112840), (9112768, 'beq', 9112836), (9112836, 'b', 9112840), (9112852, 'beq', 9114064), (9112920, 'beq', 9113100), (9113204, 'beq', 9113672), (9113348, 'beq', 9113664), (9113428, 'beq', 9113440), (9113524, 'bne', 9113540), (9113528, 'b', 9113532), (9113540, 'b', 9113544), (9113568, 'blo', 9113392), (9113660, 'bne', 9113392), (9113664, 'b', 9113668), (9113668, 'b', 9113672), (9113940, 'bne', 9113956), (9113952, 'b', 9114060), (9114048, 'blt', 9114056), (9114052, 'b', 9114196), (9114056, 'b', 9114060), (9114060, 'b', 9114064), (9114064, 'b', 9114068), (9114092, 'blo', 9112040), (9114188, 'bne', 9112040), (9114192, 'b', 9114196), (9114208, 'bne', 9114224), (9114220, 'b', 9116900), (9114400, 'beq', 9114924), (9114484, 'beq', 9114496), (9114588, 'beq', 9114620), (9114608, 'b', 9114652), (9114820, 'blo', 9114448), (9114920, 'bne', 9114448), (9114924, 'b', 9114928), (9114928, 'b', 9114932), (9115032, 'blo', 9115068), (9115116, 'bge', 9116044), (9115416, 'beq', 9115556), (9115552, 'b', 9115328), (9115852, 'beq', 9116000), (9115996, 'b', 9115764), (9116000, 'b', 9116004), (9116016, 'b', 9115108), (9116220, 'beq', 9116884), (9116304, 'beq', 9116316), (9116432, 'bne', 9116752), (9116492, 'beq', 9116532), (9116512, 'b', 9116564), (9116576, 'beq', 9116752), (9116636, 'beq', 9116660), (9116656, 'b', 9116692), (9116704, 'bne', 9116752), (9116752, 'b', 9116756), (9116780, 'blo', 9116268), (9116880, 'bne', 9116268), (9116884, 'b', 9116888), (9116888, 'b', 9116892), (9116932, 'bne', 9116952)],
        semantics=('loadDynamicObjects:repositionBlockheadLoadFailures: is the world-level dynamic-object + blockhead restore (returns a BOOL byte). Prologue 0x008aedac; arguments: arg1 byte [fp,-0x2dd] (load flag) and arg2 byte [fp,-0x2de] (repositionBlockheadLoadFailures). Stack guard at [fp,-0x20] (import 0x008afad0).\n\narg1 != 0 (0x008aee00-0x8af0cc): the dynamic-object payload is fetched from three sources in order - (1) [[self worldDatabase] dataForKey:@"..."] (selector cell 0x008afadc, worldDatabase via cell 0x008afae0), (2) fileExistsAtPath: / [NSFileManager defaultManager] / stringByAppendingPathComponent: / dataWithContentsOfFile: (cells 0x008afe6c-0x008afe78, keys 0xfff33d24/0xfff33d34), (3) dictionaryWithContentsOfFile: (cell 0x008aff80). Every non-nil result is handed to the local parser at 0x008b1db0 (`bl 0x8b1db0`, immediately after the body; usage label: payload parser) whose nonzero return is kept in [fp,-0x2e4].\n\nScalar restore (0x008af0e0-0x008af360): for each of the stored keys the body runs objectForKey: chains (cells 0x008aff8c/0x008affac/0x008affb0) and stores - an intValue written as an 8-byte {value, 0} into the activeBlockheadIndex slot (0x008af1e0), a boolValue stored as a byte into workbenchHasBeenCrafted (0x008af260), a third value into the poleItemTakenTimes/dynamicObjectIDCount family (0x008af300); the object count of the key is compared `cmp 2; bge 0x8afb48`.\n\ncount < 2 (0x008af370-0x008afb44): the one-to-two conversion - fast enumeration (countByEnumeratingWithState:, cell 0x008b0308) over self->versionOneToTwoConversionList (cell 0x008b0310); per item an 8-byte struct fetch is compared against the literal 0x7fffffff (cell 0x008b0324 - the sentinel pair); non-sentinel items go through componentsSeparatedByString:/objectAtIndex:/intValue with `== 4` gates and setObject:forKey:/dictionaryWithDictionary:; when the list still has objects the body spawns `[[NSThread alloc] detachNewThreadSelector:@selector(conversionThread:) toTarget:self withObject:...]` (cells 0x008b0828-0x008b0834) - the old-save conversion runs on a background thread; an empty list is released and nilled (0x008afae4: [list release], slot = 0).\n\ncount >= 2 (0x008afb48-0x008afd30): NSKeyedUnarchiver - [[NSKeyedUnarchiver alloc] initForReadingWithData:[fp,-0x2e4]] (cells 0x008b0850/0x008b084c, class 0x008b0854), decodeObjectForKey: (0x008b084c region), finishDecoding/autorelease; the decoded set feeds `[self.portalPositions addIndexes:]` (cells 0x008b085c/0x008b0860) - portal positions come from an NSKeyedArchiver set.\n\nClient gate (0x008afd38): [self client] (cell 0x008b0864) != 0 -> 0x008afe80 (skip the server-side conversion); else the file path is resolved again (fileExistsAtPath: / stringByAppendingPathComponent: / dataWithContentsOfFile: with keys 0xfff33de4) and on success the file is renamed into place with UTF8String + `__wrap_rename` (0x008b04a4), re-fetched, and `gzipInflate` (selector cell 0x008b087c) inflates the local-player payload into [fp,-0x3a0]; the parsed dict\'s key 0xfff33e14 load goes to [fp,-0x3c0] (0x008b06a4). If the primary payload [fp,-0x39c] is NULL the body jumps to the end (0x008b1cdc). The customRules gate: [self customRules] fetch, byte 0 != 0 and byte +0x32 == 4 -> end (0x8b072c-0x8b08ac).\n\nMain key loop (0x008b08e0-0x008b1250): fast enumeration over the parsed dict; per key the chains objectForKey:/stringWithFormat: (keys 0xfff33e34/0xfff33e24) and intValue produce the 64-bit object ID ([fp,-0x440]/[fp,-0x43c]); the localPlayerID chain (cell 0x008b0878) builds the per-object key 0xfff33e44; [[self worldDatabase] dataForKey:key] (0x008b0ba0) with the fileExistsAtPath:/dataWithContentsOfFile: fallback resolves the per-object payload [fp,-0x448]. On payload: `[self blockheadWithIDIncludingNet:{hi,lo}]` (cell 0x008b1d1c) finds an existing blockhead; when absent the body takes the unload path (self.blockheads removeObject:, blockheadWillBeUnloaded: - cells 0x008b1d54-0x008b1d60, ivars 0x008b1d58/0x008b1d5c). [NSPropertyListSerialization propertyListWithData:...] (cell 0x008b1d64, class 0x008b1d68) parses the payload to a plist [fp,-0x454]; the netBlockheads dict [fp,-0x3c0] is scanned with unsignedLongValue IDs compared via eor/orr against the current ID to find the matching net entry [fp,-0x458].\n\nBlockhead construction (0x008b1048-0x008b1250): `[[Blockhead alloc] initWithWorld:world dynamicWorld:self saveDict:plist savedInventorySlots:0 cache:cache repositionOnLoadFailure:arg2 clientSaveDir:... clientLocallySavedDict:[fp,-0x458]]` (full selector at cell 0x008b1d70, class 0x008b1d78, cache ivar 0x008b1d74) -> [fp,-0x4c4]; NULL clears the flag byte [-0x3cd], else [self.blockheads addObject:bh] (cell 0x008b1d7c) and the per-call counter [fp,-0x3cc] increments (>= 5 -> 0x008b1254).\n\nPost passes: (a) when the load flag is set, every blockhead gets `[bh pos]` (cell 0x008b1d80) then `[bh fullyLoadIfNeededAroundPos:pos clientLightBlockIndex:-1 forBlockhead:bh]` (cell 0x008b1d88; mvn ip,0 materialises the -1); (b) activeBlockheadIndex is clamped - when [self.blockheads count] <= index the slot is reset to 0 (0x008b1540) and `hasLoadedBlockheads = 1` (byte, cell 0x008b1d90); (c) the 65-entry scan over the 12-byte-stride dynamic-object arrays (cells 0x008b1d9c/0x008b1da4) walks the C++ maps with std::__1::__tree_next (route 0x005dc5d8); (d) final blockhead pass: per blockhead [bh pos] + [self customRules] fetches - byte 0 != 0 and byte +0x32 == 4 -> `[bh die]` (cell 0x008b1d98). Return: the byte [-0x2d1] (0 on the pass-less early exits at 0x8b1268, 1 at 0x8b1cdc), stack-guard checked at 0x008b1ce4 (import 0x008b1d20, __stack_chk_fail), epilogue.\n'),
    ),
    dict(
        name='wtl_loaddynamicobjectsofty',
        method='DynamicWorld -[loadDynamicObjectsOfType:fromData:physicalBlock:loadedPortal:clientOwnedID:]',
        types='v28@0:4i8@12^{PhysicalBlock=ii^{Tile}cCdII[32*][32C]}16^c20@24',
        start=9153108,
        end=9160860,
        disasm='disasm_worldtileloader_loaddynamicobjectsoftype_fromdata_physic.txt',
        base_add=9153128,
        base_literal=9157056,
        boundary='ARM.exidx end 0x008bc89c (listing bound); next ObjC IMP 0x008bd6bc DynamicWorld -[loadClientOwnedDynamicObjectsForClient:physicalBlock:]',
        selectors={
                 0x8bb9d4: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8bb9dc: (15215884, 'objectForKey:'),
                 0x8bbe10: (15215912, 'unsignedLongValue'),
                 0x8bbe34: (15215916, 'intValue'),
                 0x8bc0a0: (15216284, 'dynamicWorldChangedAtPos:objectType:'),
                 0x8bc2e0: (15216288, 'initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:'),
                 0x8bc2f0: (15215804, 'alloc'),
                 0x8bc418: (15216292, 'updateAllOwnedTilesToNewIDSize'),
                 0x8bc41c: (15216296, 'initWithWorld:dynamicWorld:saveDict:cache:'),
                 0x8bc6b4: (15215900, 'dataForKey:'),
                 0x8bc6c0: (15215816, 'stringWithFormat:'),
                 0x8bc6c8: (15216240, 'hasFinishedDatabaseMigrationTo17'),
                 0x8bc7f4: (15215904, 'dataWithContentsOfFile:'),
                 0x8bc7fc: (15215880, 'stringByAppendingPathComponent:'),
                 0x8bc810: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8bc814: (15215884, 'objectForKey:'),
                 0x8bc818: (15215916, 'intValue'),
                 0x8bc834: (15216296, 'initWithWorld:dynamicWorld:saveDict:cache:'),
                 0x8bc83c: (15215804, 'alloc'),
                 0x8bc844: (15216284, 'dynamicWorldChangedAtPos:objectType:'),
                 0x8bc850: (15216012, 'pos'),
                 0x8bc854: (15216304, 'level'),
                 0x8bc85c: (15216308, 'addIndex:'),
                 0x8bc868: (15216312, 'setLevelSilently:'),
                 0x8bc870: (15216300, 'initWithWorld:dynamicWorld:saveDict:chestSaveDict:cache:'),
                 0x8bc87c: (15216168, 'objectType'),
                 0x8bc880: (15216024, 'blockheadsLoaded'),
                 0x8bc898: (15216244, 'worldIndicesContainingTamedAnimals'),
        },
        imports={
                 0x8bb9cc: (16333448, '__CFConstantStringClassReference'),
                 0x8bb9d0: (17151904, 'objc_msgSend'),
                 0x8bb9d8: (16333064, '__CFConstantStringClassReference'),
                 0x8bbe0c: (16333080, '__CFConstantStringClassReference'),
                 0x8bbe38: (16333464, '__CFConstantStringClassReference'),
                 0x8bbfcc: (16333480, '__CFConstantStringClassReference'),
                 0x8bbfd4: (16333496, '__CFConstantStringClassReference'),
                 0x8bbfd8: (16333512, '__CFConstantStringClassReference'),
                 0x8bc0ac: (16333528, '__CFConstantStringClassReference'),
                 0x8bc6bc: (16333544, '__CFConstantStringClassReference'),
                 0x8bc80c: (17151904, 'objc_msgSend'),
                 0x8bc81c: (16333464, '__CFConstantStringClassReference'),
                 0x8bc828: (16333496, '__CFConstantStringClassReference'),
                 0x8bc82c: (16333512, '__CFConstantStringClassReference'),
                 0x8bc84c: (16333576, '__CFConstantStringClassReference'),
                 0x8bc86c: (16333560, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x8bb9c4: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8bb9c8: (17162388, 'OBJC_IVAR_$_DynamicWorld.currentlyLoadingMacroBlocks', 3732),
                 0x8bbe84: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8bbe88: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
                 0x8bbe8c: (17162360, 'OBJC_IVAR_$_DynamicWorld.currentlyAddingObjectIDs', 2432),
                 0x8bc0a8: (17162312, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsByWorldPosIndex', 1620),
                 0x8bc2e4: (17162224, 'OBJC_IVAR_$_DynamicWorld.seasonOffsetNoiseFunction', 7344),
                 0x8bc2e8: (17162228, 'OBJC_IVAR_$_DynamicWorld.treeDensityNoiseFunction', 7340),
                 0x8bc2ec: (17162232, 'OBJC_IVAR_$_DynamicWorld.cache', 7336),
                 0x8bc6b8: (17162236, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectDatabase', 36),
                 0x8bc800: (17162196, 'OBJC_IVAR_$_DynamicWorld.worldSaveDirectory', 40),
                 0x8bc804: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8bc808: (17162388, 'OBJC_IVAR_$_DynamicWorld.currentlyLoadingMacroBlocks', 3732),
                 0x8bc820: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
                 0x8bc824: (17162360, 'OBJC_IVAR_$_DynamicWorld.currentlyAddingObjectIDs', 2432),
                 0x8bc830: (17162312, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsByWorldPosIndex', 1620),
                 0x8bc838: (17162232, 'OBJC_IVAR_$_DynamicWorld.cache', 7336),
                 0x8bc860: (17162204, 'OBJC_IVAR_$_DynamicWorld.portalPositions', 7332),
                 0x8bc878: (17162332, 'OBJC_IVAR_$_DynamicWorld.hasLoadedBlockheads', 7368),
                 0x8bc88c: (17162364, 'OBJC_IVAR_$_DynamicWorld.freeBlocksByPosition', 2400),
                 0x8bc890: (17162248, 'OBJC_IVAR_$_DynamicWorld.serverClients', 24),
        },
        classes={
                 0x8bc420: (15247856, 'OBJC_CLASS_$_Shark'),
                 0x8bc6c4: (15247792, 'OBJC_CLASS_$_NSString'),
                 0x8bc7f8: (15247812, 'OBJC_CLASS_$_NSData'),
                 0x8bc848: (15247864, 'OBJC_CLASS_$_Workbench'),
                 0x8bc874: (15247860, 'OBJC_CLASS_$_FreightCar'),
        },
        instructions=[(9153108, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9153172, 'ldr r0, [fp, -0x194]'), (9153296, 'sub r0, fp, 0x1a8'), (9153504, 'sub r0, fp, 0x1a8'), (9153664, 'movw r0, 0'), (9154024, 'ldr r0, [fp, -0x1dc]'), (9154100, 'ldr r0, [fp, -0x194]'), (9154256, 'sub r0, fp, 0x228'), (9154480, 'bl method.std::__1::__hash_const_iterator_std::__1::__hash_node_unsigned_long_long__void__const__std::__1::__hash_table_unsigned_long_long__std::__1::hash_unsigned_long_long___std::__1::equal_to_unsigned_long_long___std::__1::allocator_unsigned_long_long___.find_unsigned_long_long__unsigned_long_long_const__const'), (9154792, 'ldr r0, [fp, -0x22c]'), (9157476, 'ldr r0, [fp, -0x2b4]'), (9158004, 'ldr r0, [fp, -0x2b8]'), (9158464, 'ldr r0, [fp, -0x2bc]'), (9158620, 'ldr r0, [fp, -0x2b4]'), (9158836, 'ldr r0, [fp, -0x194]'), (9159072, 'sub r1, fp, 0x228'), (9159316, 'bl sym.objectTypeHasStaticPosition_int_'), (9159636, 'cmp r0, 0xe'), (9160396, 'sub r0, fp, 0x228'), (9160600, 'movw r0, 0'), (9160856, 'invalid')],
        calls=[(9153272, 'bl sym.macroIndexAtMacroPosition_int__int__World_'), (9153376, 'bl method.std::__1::__hash_const_iterator_std::__1::__hash_node_unsigned_int__void__const__std::__1::__hash_table_unsigned_int__std::__1::hash_unsigned_int___std::__1::equal_to_unsigned_int___std::__1::allocator_unsigned_int___.find_unsigned_int__unsigned_int_const__const'), (9153496, 'bl sym.imp.NSLog'), (9153568, 'bl method.std::__1::__hash_table_unsigned_int__std::__1::hash_unsigned_int___std::__1::equal_to_unsigned_int___std::__1::allocator_unsigned_int___.__insert_unique_unsigned_int_const_'), (9153688, 'bl 0x8b1db0'), (9153836, 'blx ip'), (9153872, 'bl sym.imp.memset'), (9153920, 'blx lr'), (9154020, 'bl sym.imp.objc_enumerationMutation'), (9154068, 'bl loc.imp.objc_msgSend'), (9154084, 'bl loc.imp.objc_msgSend'), (9154192, 'blx ip'), (9154208, 'blx r2'), (9154224, 'bl sym.dynamicObjectTypeForInteractionObjectType_unsigned_short_'), (9154316, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9154388, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9154480, 'bl method.std::__1::__hash_const_iterator_std::__1::__hash_node_unsigned_long_long__void__const__std::__1::__hash_table_unsigned_long_long__std::__1::hash_unsigned_long_long___std::__1::equal_to_unsigned_long_long___std::__1::allocator_unsigned_long_long___.find_unsigned_long_long__unsigned_long_long_const__const'), (9154608, 'bl sym.imp.NSLog'), (9154644, 'bl loc.imp.objc_msgSend'), (9154668, 'bl loc.imp.objc_msgSend'), (9154700, 'bl loc.imp.objc_msgSend'), (9154716, 'bl loc.imp.objc_msgSend'), (9154784, 'bl loc.imp.objc_msgSend'), (9154796, 'bl sym.objectTypeHasStaticPosition_int_'), (9154868, 'bl loc.imp.objc_msgSend'), (9154892, 'bl loc.imp.objc_msgSend'), (9154924, 'bl loc.imp.objc_msgSend'), (9154940, 'bl loc.imp.objc_msgSend'), (9154992, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9155068, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9155124, 'bl sym.imp.NSLog'), (9155196, 'bl loc.imp.objc_msgSend'), (9155272, 'bl method.std::__1::__hash_table_unsigned_long_long__std::__1::hash_unsigned_long_long___std::__1::equal_to_unsigned_long_long___std::__1::allocator_unsigned_long_long___.__insert_unique_unsigned_long_long_const_'), (9155376, 'bl sym.objectTypeIsTree_int_'), (9155396, 'bl sym.classForDynamicObjectType_int_'), (9155512, 'blx r7'), (9155644, 'blx ip'), (9155708, 'blx r2'), (9155720, 'bl sym.objectTypeIsPlant_int_'), (9155740, 'bl sym.classForDynamicObjectType_int_'), (9155856, 'blx r7'), (9155988, 'blx ip'), (9156128, 'blx r5'), (9156212, 'blx ip'), (9156440, 'blx sl'), (9156456, 'blx r2'), (9156492, 'blx ip'), (9156536, 'blx ip'), (9156620, 'blx r2'), (9156736, 'blx lr'), (9156776, 'blx ip'), (9156808, 'bl 0x8b1db0'), (9156844, 'bl sym.imp.NSLog'), (9156940, 'blx r4'), (9157044, 'blx ip'), (9157104, 'bl sym.objectTypeIsInteractionObject_int_'), (9157176, 'bl loc.imp.objc_msgSend'), (9157200, 'bl loc.imp.objc_msgSend'), (9157232, 'bl loc.imp.objc_msgSend'), (9157248, 'bl loc.imp.objc_msgSend'), (9157320, 'bl loc.imp.objc_msgSend'), (9157376, 'bl loc.imp.objc_msgSend'), (9157452, 'blx ip'), (9157468, 'blx r2'), (9157644, 'blx sl'), (9157660, 'blx r2'), (9157696, 'blx r3'), (9157780, 'blx ip'), (9157888, 'bl loc.imp.objc_msgSend_stret'), (9157924, 'bl sym.imp.memset'), (9157980, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9158024, 'bl loc.imp.objc_msgSend'), (9158268, 'bl loc.imp.objc_msgSend_stret'), (9158316, 'bl sym.imp.memset'), (9158404, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9158460, 'blx r3'), (9158532, 'blx r2'), (9158588, 'blx r3'), (9158628, 'bl sym.classForInteractionObjectType_unsigned_short_'), (9158720, 'blx r5'), (9158804, 'blx ip'), (9158852, 'bl sym.classForDynamicObjectType_int_'), (9158944, 'blx r5'), (9159028, 'blx ip'), (9159144, 'blx ip'), (9159180, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_'), (9159268, 'blx r2'), (9159312, 'blx r2'), (9159316, 'bl sym.objectTypeHasStaticPosition_int_'), (9159384, 'bl loc.imp.objc_msgSend_stret'), (9159440, 'bl sym.imp.memset'), (9159496, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9159524, 'bl loc.imp.objc_msgSend'), (9159580, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9159632, 'blx r2'), (9159696, 'bl loc.imp.objc_msgSend_stret'), (9159744, 'bl sym.imp.memset'), (9159808, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9159868, 'bl method.std::__1::map_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.operator___unsigned_long_long_'), (9159912, 'bl method.std::__1::__tree_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject___.__insert_unique_DynamicObject_const_'), (9160088, 'bl loc.imp.objc_msgSend'), (9160108, 'bl loc.imp.objc_msgSend'), (9160140, 'bl loc.imp.objc_msgSend'), (9160156, 'bl method.std::__1::map_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int_____std::__1::less_unsigned_int___std::__1::allocator_std::__1::pair_unsigned_int_const__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int________.at_unsigned_int_const_'), (9160212, 'bl sym.macroIndexAtMacroPosition_int__int__World_'), (9160268, 'bl method.std::__1::pair_std::__1::__tree_iterator_unsigned_int__std::__1::__tree_node_unsigned_int__void___int___bool__std::__1::__tree_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int___.__insert_unique_unsigned_int__unsigned_int_'), (9160456, 'bl method.unsigned_long_std::__1::__hash_table_unsigned_long_long__std::__1::hash_unsigned_long_long___std::__1::equal_to_unsigned_long_long___std::__1::allocator_unsigned_long_long___.__erase_unique_unsigned_long_long__unsigned_long_long_const_'), (9160568, 'blx ip'), (9160676, 'bl method.unsigned_long_std::__1::__hash_table_unsigned_int__std::__1::hash_unsigned_int___std::__1::equal_to_unsigned_int___std::__1::allocator_unsigned_int___.__erase_unique_unsigned_int__unsigned_int_const_')],
        branches=[(9153184, 'beq', 9153212), (9153196, 'beq', 9153212), (9153208, 'blt', 9153216), (9153212, 'b', 9160684), (9153292, 'bne', 9153664), (9153480, 'beq', 9153504), (9153500, 'b', 9160684), (9153680, 'beq', 9153696), (9153708, 'beq', 9160600), (9153932, 'beq', 9160592), (9154012, 'beq', 9154024), (9154116, 'bne', 9154256), (9154240, 'beq', 9154252), (9154252, 'b', 9154256), (9154324, 'bne', 9160468), (9154396, 'bne', 9160468), (9154584, 'beq', 9154792), (9154788, 'b', 9160472), (9154808, 'beq', 9155208), (9155076, 'beq', 9155204), (9155088, 'beq', 9155128), (9155100, 'beq', 9155128), (9155200, 'b', 9160472), (9155204, 'b', 9155208), (9155388, 'beq', 9155716), (9155664, 'bge', 9155712), (9155712, 'b', 9159056), (9155732, 'beq', 9156000), (9155996, 'b', 9159052), (9156008, 'bne', 9156256), (9156020, 'bge', 9156252), (9156232, 'beq', 9156248), (9156248, 'b', 9156252), (9156252, 'b', 9159048), (9156264, 'bne', 9157088), (9156556, 'bne', 9156784), (9156632, 'bne', 9156784), (9156800, 'beq', 9156816), (9156828, 'bne', 9156848), (9157052, 'b', 9159044), (9157096, 'beq', 9157120), (9157116, 'beq', 9158836), (9157128, 'bne', 9157380), (9157484, 'bne', 9158620), (9157796, 'beq', 9157812), (9157808, 'bne', 9158464), (9157820, 'bne', 9158216), (9157872, 'beq', 9157896), (9157892, 'b', 9157928), (9158000, 'beq', 9158212), (9158040, 'bhi', 9158204), (9158100, 'b', 9158208), (9158116, 'b', 9158208), (9158132, 'b', 9158208), (9158152, 'b', 9158208), (9158176, 'b', 9158208), (9158192, 'b', 9158208), (9158204, 'b', 9158208), (9158208, 'b', 9158212), (9158212, 'b', 9158216), (9158252, 'beq', 9158288), (9158272, 'b', 9158320), (9158472, 'bne', 9158592), (9158488, 'bge', 9158592), (9158540, 'bne', 9158592), (9158600, 'b', 9158812), (9158812, 'b', 9159040), (9158844, 'beq', 9159036), (9159036, 'b', 9159040), (9159040, 'b', 9159044), (9159044, 'b', 9159048), (9159048, 'b', 9159052), (9159052, 'b', 9159056), (9159068, 'beq', 9160396), (9159224, 'beq', 9159272), (9159328, 'beq', 9159592), (9159368, 'beq', 9159412), (9159388, 'b', 9159444), (9159640, 'bne', 9160012), (9159680, 'beq', 9159716), (9159700, 'b', 9159748), (9160024, 'beq', 9160368), (9160368, 'b', 9160464), (9160464, 'b', 9160468), (9160468, 'b', 9160472), (9160496, 'blo', 9153976), (9160588, 'bne', 9153976), (9160592, 'b', 9160596), (9160596, 'b', 9160600), (9160612, 'bne', 9160684)],
        semantics=("loadDynamicObjectsOfType:fromData:physicalBlock:loadedPortal:clientOwnedID: instantiates the dynamic objects of one type from a serialized payload for one physical block (the per-type worker behind loadDynamicObjectsForMacroTile:). Prologue 0x008baa54 (frame 0x198+0x400); arguments: type int [fp,-0x194], data char* [fp,-0x198], physicalBlock [fp,-0x19c], loadedPortal out byte [fp,-0x1a0], clientOwnedID [fp,-0x1a4].\n\nType gate (0x008baa94): only 1..0x40 pass except type 0 and 0x15 - the body returns immediately for those (0x008bc7ec exit).\n\nReentrancy guard (only when clientOwnedID == 0, 0x008bab04): the macro index of the block (macroIndexAtMacroPosition(block->0, block->1, world), sym 0x00a174a4) is looked up in the std::__1::__hash_table<unsigned int> at self->currentlyLoadingMacroBlocks (cell 0x008bb9c8; find route 0x009123a4): a hit logs (string 0xfff33f94) and returns; otherwise the index is inserted (__insert_unique route 0x00910c58) - the macro tile is marked in-flight.\n\nPayload parse (0x008bac80): the data argument goes through the same parser as the world-level loader (`bl 0x8b1db0`); NULL -> 0x008bc798 (guard release + return).\n\nMain enumeration (0x008bacb0-0x8bc730): fast enumeration over the parsed dict (cell 0x008bb9d4). Per key: objectForKey:/stringWithFormat: chains (cells 0x008bb9dc/0x008bbdf8, keys 0xfff33e24) then unsignedLongValue (cell 0x008bbe10) produce the 64-bit ID ([fp,-0x228]/[-0x224]); when type == 0xf the key's intValue (cell 0x008bbe34) is passed through dynamicObjectTypeForInteractionObjectType(unsigned short) (sym 0x008bc89c) and a nonzero result replaces the effective type [fp,-0x22c].\nDedup gates: `std::map<u64, DynamicObject*>::__count_unique(id)` on the two 12-byte-stride maps (cells 0x008bbe84/0x008bbe88; routes 0x00910a74 count_unique) - a hit skips the object (0x008bc714); then the std::__1::__hash_table<unsigned long long> at self->currentlyAddingObjectIDs (cell 0x008bbe8c; find route 0x00910798) - a hit logs (string 0xfff33fb4), re-notifies via `[self dynamicWorldChangedAtPos:pos objectType:type]` (cell 0x008bc0a0, pos/objectType fetched from the key object, cell 0x008bbe34/0x008bbfd4 region) and skips.\n\nConstruction: objectTypeHasStaticPosition(type) (sym 0x008b68ac) selects the geometry arm. The static-position arm (0x008bb288+) and the dynamic arm both build the object. Three construction routes:\n- key-value == 1 (0x008bbb64-0x008bbc98): the Workbench route - [[Workbench alloc] initWithWorld:... dynamicWorld:self saveDict:[key objectForKey:...] cache:cache] (class cell 0x008bc848, init selector 0x008bc834 at cell 0x008bc834, cache cell 0x008bc838, world cell 0x008bc804, alloc cell 0x008bc83c, key 0xfff34014) -> the object [fp,-0x2b8].\n- otherwise classForInteractionObjectType(unsigned short) (sym 0x005f3f50, 0x008bbfdc) -> [[class alloc] initWithWorld:... dynamicWorld:... saveDict:key-bytes cache:...] -> [fp,-0x27c].\n- when type != 0x16: classForDynamicObjectType(type) (sym 0x00b597bc, 0x008bc0b4) -> [[class alloc] initWithWorld:... dynamicWorld:self saveDict:... cache:...] -> [fp,-0x27c].\nPost-init fixups: `[obj pos]` (cells 0x008bc850/0x008bc2e0 region) then tileAtWorldPositionLoaded(pos.x, pos.y-1, world); `[obj level]` (cell 0x008bc854) drives a 6-entry jump table (0x008bbdb0) writing tile byte0 = 0x19/0x21/0x22/0x23/0x24/0x25 (0x008bbdc8-0x008bbe2c); `[obj addIndex:worldIndexAtWorldPos(pos, world)]` (cell 0x008bc85c/0x008bc850, sym 0x00a15838); when the constructed class was the Workbench route (result == 2) and the block version +0xd < 6, `[obj level]` == 2 -> `[obj setLevelSilently:3]` (cell 0x008bc868, 0x008bbf90).\n\nRegistration: the object is stored into `std::map<u64, DynamicObject*>::operator[]` on the map at cell 0x008bc820 (route 0x008bcf24) - keyed by the 64-bit ID at the type*12 byte stride (0x008bc1a0-0x008bc208); `[obj blockheadsLoaded]` (cell 0x008bc880) runs when self->hasLoadedBlockheads (cell 0x008bc878); when objectTypeHasStaticPosition(type) the world-index is inserted via `std::map<u64, set<DynamicObject*>>::operator[]` on the map at cell 0x008bc830 followed by `__tree<DynamicObject*>::__insert_unique` (route 0x0090dc2c, 0x008bc314-0x008bc4e8); `[obj objectType]` (cell 0x008bc87c) == 0xe stores the object's macro index (macroIndexAtMacroPosition) into `std::map<unsigned int, set<unsigned int>*>::at(...)` -> `__tree<unsigned int>::__insert_unique` (route 0x00912b98) on the worldIndicesContainingTamedAnimals family (cell 0x008bc898). When clientOwnedID != 0 the same macro index is recorded under the client id via `[[self ... worldIndicesContainingTamedAnimals-like cell 0x008bc890 + freeBlocksByPosition 0x008bc88c] objectForKey:clientOwnedID]` + `map<u32,set<u32>*>::at` (route 0x008ba928) + `__insert_unique` (0x008bc55c-0x008bc6ac).\n\nSkips and cleanup: a key whose construction returned NULL erases the ID from currentlyAddingObjectIDs (`__erase_unique` route 0x00913f9c, cell 0x008bc824); the per-key loop continues at 0x008bc730. Exit (0x008bc798): when clientOwnedID == 0 the macro index is erased from the currentlyLoadingMacroBlocks hash table (`__erase_unique` route 0x0090d298, cell 0x008bc808) - the in-flight mark is released; dedup between already-present objects (two maps), in-flight adds (hash set) and finished loads is this method's contract.\n"),
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
        'batch': 'DynamicWorld dynamic-object load-chain batch (E19): loadDynamicObjectsForMacroTile:includeSurfaceBlocks: (the per-macro-tile restore with the version ladder 2/6/7/8, the tree-promise pool and the surface pass), loadDynamicObjects:repositionBlockheadLoadFailures: (three-source fetch, one-to-two conversion thread, NSKeyedUnarchiver portal set, Blockhead construction) and loadDynamicObjectsOfType:fromData:physicalBlock:loadedPortal:clientOwnedID: (the per-type constructor worker with the reentrancy guard and the dedup gates); 3 bodies',
        'claim': ('a static bounded-body map with per-instruction anchors; the payload parser at '
                  '0x008b1db0, the C++ container layouts behind the std::map/set/hash routes, the tile and '
                  'marker id names and the customRules world-type names are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'dyn_load.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale dyn_load.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
