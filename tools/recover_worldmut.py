#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The World class opens: the tile-mutation core - fill/remove/paint/place, the
900/450 day cycle, the polar sun arc and the sky gradient: the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 15099 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/WORLD_MUTATION.md for the prose and boundaries.
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
    'bl 0x55468c': 0x0055468c,
    'bl 0x559f54': 0x00559f54,
    'bl 0x564c54': 0x00564c54,
    'bl 0x579a48': 0x00579a48,
    'bl 0x579ab4': 0x00579ab4,
    'bl 0x582eb4': 0x00582eb4,
    'bl 0x583288': 0x00583288,
    'bl 0x58353c': 0x0058353c,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl method.Vector.Vector__': 0x004bed60,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector.Vector_float__float__float__float_': 0x004d0d08,
    'bl method.Vector.operator_Vector_': 0x004d6538,
    'bl method.Vector.operator_float__': 0x004b5c08,
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl method.std::__1::__hash_table_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___.__insert_unique_PhysicalBlock_const_': 0x005dd340,
    'bl method.std::__1::unordered_set_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___._unordered_set__': 0x0057598c,
    'bl method.unsigned_long_std::__1::__hash_table_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___.__erase_unique_PhysicalBlock__PhysicalBlock_const_': 0x005dce04,
    'bl sym.Vector::operator_Vector_': 0x0058198c,
    'bl sym.absoluteSeasonFraction_double_': 0x00a149f8,
    'bl sym.backWallIsMutable_Tile_': 0x00a1234c,
    'bl sym.clamp_float__float__float_': 0x004be068,
    'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_': 0x00a15404,
    'bl sym.getWorldUpVectorForX_float__World_': 0x00a148b0,
    'bl sym.imp._Unwind_Resume': 0x001c29c0,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__wrap_fmodf': 0x001c3d4c,
    'bl sym.imp.cos': 0x001c2948,
    'bl sym.interactionObjectItemTypeOccupiesForeground_ItemType_': 0x0057b6bc,
    'bl sym.itemTypeIsBlock_ItemType_': 0x004cc11c,
    'bl sym.itemTypeIsLightEmittingBlock_ItemType_': 0x00580f24,
    'bl sym.itemTypeIsPlacableOnTrees_ItemType_': 0x00580c20,
    'bl sym.itemTypeIsSowable_ItemType_': 0x0056871c,
    'bl sym.itemTypeIsTrainCar_ItemType_': 0x0057bd18,
    'bl sym.itemTypeIsTwoBlocksWide_ItemType_': 0x0057b5e4,
    'bl sym.itemTypeIsValidFillItem_ItemType_': 0x00580cdc,
    'bl sym.itemTypeOccupiesBackgroundContents_ItemType_': 0x00580be0,
    'bl sym.itemTypeOccupiesForegroundContents_ItemType_': 0x0057b630,
    'bl sym.linearInterpolate_float__float__float_': 0x00582a14,
    'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_': 0x00a16ccc,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.npcTypeFromCageItemType_ItemType_': 0x00580e5c,
    'bl sym.particleColorForTile_Tile_': 0x00a10a48,
    'bl sym.polarToRectangular_double__double_': 0x00582e00,
    'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_': 0x00a1915c,
    'bl sym.seasonForWorldX_int__double__World_': 0x00a14a48,
    'bl sym.tileAllowsPlacingOfSolidBlocks_Tile_': 0x00a12608,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileAtWorldPosition_int__int__MacroTile__World_': 0x00a16e68,
    'bl sym.tileContainsDoor_Tile_': 0x00a12818,
    'bl sym.tileContainsTrapDoor_Tile_': 0x00a12864,
    'bl sym.tileIsAirOrSnow_Tile_': 0x00a12760,
    'bl sym.tileIsAirWaterOrSnow_Tile_': 0x00a126dc,
    'bl sym.tileIsAir_Tile_': 0x00a12300,
    'bl sym.tileIsBush_Tile_': 0x00a13a4c,
    'bl sym.tileIsDeadTree_Tile_': 0x00a138fc,
    'bl sym.tileIsPlant_Tile_': 0x00a13ce0,
    'bl sym.tileIsSolid_Tile_': 0x00a1179c,
    'bl sym.tileIsTree_Tile_': 0x00a13214,
    'bl sym.tileIsUnplacedBlockMinableWithPickaxe_Tile_': 0x00a13694,
    'bl sym.tileIsWater_Tile_': 0x00a11690,
    'bl sym.tileIsWorkbench_Tile_': 0x00a1436c,
    'bl sym.tileTypeIsPortalBaseStone_TileType_': 0x00a146a0,
    'bl sym.worldIndexAtWorldPos_intpair__World_': 0x00a15838,
}

SPECS = [
    dict(
        name='wm_00',
        method='World -[decommisionAllBlocksBlockToSavePhyscialBlock:]',
        types='v12@0:4c8',
        start=5722616,
        end=5724556,
        disasm='disasm_worldtileloader_wm_00.txt',
        base_add=5722632,
        base_literal=5724552,
        boundary='ARM.exidx end 0x0057598c (listing bound); next ObjC IMP 0x005759bc World -[removeAnyBackgroundContentsForTile:atPos:removeBlockhead:]',
        selectors={
                 0x575980: (15196704, 'checkIfMacroTileCanBeDecommissioned:world:minAge:blockToSavePhyscialBlock:'),
        },
        imports={},
        ivars={
                 0x57596c: (17156364, 'OBJC_IVAR_$_World.usedPhysicalBlocks', 456),
                 0x575970: (17156368, 'OBJC_IVAR_$_World.freePhysicalBlocks', 476),
                 0x57597c: (17156340, 'OBJC_IVAR_$_World.macroTiles', 412),
        },
        classes={
                 0x575974: (15245460, 'OBJC_CLASS_$_WorldHelper'),
        },
        instructions=[(5722616, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5724552, 'adceq sl, lr, r4, ror 17')],
        calls=[(5723532, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (5723604, 'bl loc.imp.objc_msgSend'), (5723636, 'bl method.std::__1::unordered_set_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___._unordered_set__'), (5723700, 'bl method.std::__1::__hash_table_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___.__insert_unique_PhysicalBlock_const_'), (5724236, 'bl method.std::__1::__hash_table_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___.__insert_unique_PhysicalBlock_const_'), (5724408, 'bl method.unsigned_long_std::__1::__hash_table_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___.__erase_unique_PhysicalBlock__PhysicalBlock_const_'), (5724500, 'bl method.std::__1::unordered_set_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___._unordered_set__'), (5724520, 'bl sym.imp._Unwind_Resume')],
        branches=[(5723400, 'beq', 5723876), (5723404, 'b', 5723408), (5723456, 'beq', 5723648), (5723540, 'b', 5723544), (5723612, 'b', 5723616), (5723616, 'b', 5723648), (5723644, 'b', 5724516), (5723660, 'bne', 5723804), (5723704, 'b', 5723708), (5723800, 'b', 5723804), (5723804, 'b', 5723808), (5723872, 'b', 5723232), (5724148, 'beq', 5724496), (5724152, 'b', 5724156), (5724240, 'b', 5724244), (5724416, 'b', 5724420), (5724420, 'b', 5724424), (5724424, 'b', 5724428), (5724492, 'b', 5724000)],
        semantics=('[World decommisionAllBlocksBlockToSavePhyscialBlock:] (imp 0x005751f8, 497w): the decommission sweep - **`std::unordered_set` x2 + `__insert_unique(PhysicalBlock)` + `__erase_unique`** (the physical-block set drives the batch teardown) + macroTileAtMacroPostion + objc.\n'),
    ),
    dict(
        name='wm_01',
        method='World -[removeAnyBackgroundContentsForTile:atPos:removeBlockhead:]',
        types='v24@0:4^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}8{?=ii}12@20',
        start=5724604,
        end=5724872,
        disasm='disasm_worldtileloader_wm_01.txt',
        base_add=5724676,
        base_literal=5724860,
        boundary='ARM.exidx end 0x00575ac8 (listing bound); next ObjC IMP 0x00575ac8 World -[remoteRemoveBackWallRequest:fromClient:]',
        selectors={
                 0x575ac0: (15196708, 'createBackgroundContentFreeBlockAtPosition:forTile:removeBlockhead:'),
                 0x575ac4: (15196712, 'worldChangedAtPos:sendReliably:'),
        },
        imports={},
        ivars={
                 0x575ab8: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={},
        instructions=[(5724604, 'push {r4, r5, r6, sl, fp, lr}'), (5724868, 'invalid')],
        calls=[(5724764, 'bl loc.imp.objc_msgSend'), (5724844, 'bl loc.imp.objc_msgSend')],
        branches=[(5724660, 'beq', 5724848)],
        semantics=('[World ?] (imp 0x005759bc, 67w): the mutation support body.\n'),
    ),
    dict(
        name='wm_02',
        method='World -[remoteRemoveBackWallRequest:fromClient:]',
        types='I16@0:4@8@12',
        start=5724872,
        end=5725508,
        disasm='disasm_worldtileloader_wm_02.txt',
        base_add=5724888,
        base_literal=5725504,
        boundary='ARM.exidx end 0x00575d44 (listing bound); next ObjC IMP 0x00575d44 World -[remoteRemoveRequest:fromClient:]',
        selectors={
                 0x575d18: (15195656, 'getBytes:length:'),
                 0x575d1c: (15196716, 'tileIsProtectedAtPos:againstClient:'),
                 0x575d24: (15196720, 'blockheadWithIDIncludingNet:'),
                 0x575d30: (15196724, 'removeBackWallAtPos:removeBlockhead:'),
        },
        imports={
                 0x575d14: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x575d10: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x575d28: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x575d38: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
        },
        classes={},
        instructions=[(5724872, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5725504, 'adceq sl, lr, r4, lsl r0')],
        calls=[(5724972, 'blx r6'), (5725048, 'bl sym.makeIntpair_int__int_'), (5725092, 'bl loc.imp.objc_msgSend'), (5725280, 'bl loc.imp.objc_msgSend'), (5725328, 'bl sym.makeIntpair_int__int_'), (5725384, 'bl loc.imp.objc_msgSend')],
        branches=[(5725004, 'beq', 5725184), (5725020, 'beq', 5725184), (5725104, 'beq', 5725180), (5725176, 'b', 5725444), (5725180, 'b', 5725184), (5725208, 'beq', 5725288), (5725212, 'b', 5725216)],
        semantics=('[World remoteRemoveBackWallRequest:fromClient:] (imp 0x00575ac8, 159w): the backwall removal request - objc x3 + **makeIntpair x2** (the tile addressing!) + const 0x10.\n'),
    ),
    dict(
        name='wm_03',
        method='World -[remoteRemoveRequest:fromClient:]',
        types='I16@0:4@8@12',
        start=5725508,
        end=5726496,
        disasm='disasm_worldtileloader_wm_03.txt',
        base_add=5725524,
        base_literal=5726492,
        boundary='ARM.exidx end 0x00576120 (listing bound); next ObjC IMP 0x00576120 World -[removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:]',
        selectors={
                 0x5760dc: (15195656, 'getBytes:length:'),
                 0x5760e0: (15196716, 'tileIsProtectedAtPos:againstClient:'),
                 0x5760e8: (15196728, 'playerIsAdminWithID:'),
                 0x5760ec: (15196732, 'updatePlayer:'),
                 0x5760f0: (15196720, 'blockheadWithIDIncludingNet:'),
                 0x5760fc: (15196740, 'removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:onlyRemoveCOntents:onlyRemoveForegroundContents:'),
                 0x576104: (15196712, 'worldChangedAtPos:sendReliably:'),
                 0x576108: (15196736, 'removeWaterTileAtPos:'),
        },
        imports={
                 0x5760d8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5760d4: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x5760f4: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x576110: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
        },
        classes={},
        instructions=[(5725508, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5726492, 'umlaleq sb, lr, r8, sp')],
        calls=[(5725608, 'blx r6'), (5725684, 'bl sym.makeIntpair_int__int_'), (5725728, 'bl loc.imp.objc_msgSend'), (5725896, 'blx r3'), (5725980, 'blx r3'), (5726084, 'bl loc.imp.objc_msgSend'), (5726128, 'bl sym.makeIntpair_int__int_'), (5726160, 'bl loc.imp.objc_msgSend'), (5726248, 'bl loc.imp.objc_msgSend'), (5726296, 'bl sym.makeIntpair_int__int_'), (5726336, 'bl loc.imp.objc_msgSend')],
        branches=[(5725640, 'beq', 5725988), (5725656, 'beq', 5725988), (5725740, 'beq', 5725816), (5725812, 'b', 5726408), (5725824, 'bne', 5725984), (5725908, 'bne', 5725984), (5725984, 'b', 5725988), (5726012, 'beq', 5726092), (5726016, 'b', 5726020), (5726100, 'beq', 5726168), (5726164, 'b', 5726340)],
        semantics=('[World remoteRemoveRequest:fromClient:] (imp 0x00575d44, 247w): the removal request - objc x5 + **makeIntpair x3** + const 0x18.\n'),
    ),
    dict(
        name='wm_04',
        method='World -[shouldBeCrystalBlockAtPos:]',
        types='c16@0:4{?=ii}8',
        start=5726920,
        end=5727512,
        disasm='disasm_worldtileloader_wm_04.txt',
        base_add=5726936,
        base_literal=5727508,
        boundary='ARM.exidx end 0x00576518 (listing bound); next ObjC IMP 0x00576518 World -[removeBackWallAtPos:removeBlockhead:]',
        selectors={
                 0x576504: (15196748, 'shouldBeCrystalBlockAtX:y:'),
                 0x576510: (15196752, 'containsIndex:'),
        },
        imports={
                 0x576500: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5764ec: (17156060, 'OBJC_IVAR_$_World.customRules', 160),
                 0x5764f0: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
                 0x576508: (17156024, 'OBJC_IVAR_$_World.clientTileLoader', 972),
                 0x57650c: (17156384, 'OBJC_IVAR_$_World.clientTCMinedIndices', 3180),
        },
        classes={},
        instructions=[(5726920, 'push {fp, lr}'), (5727508, 'adceq sb, lr, r4, lsl r8')],
        calls=[(5727256, 'blx ip'), (5727344, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (5727416, 'blx r3')],
        branches=[(5726988, 'beq', 5727004), (5727000, 'b', 5727456), (5727012, 'bge', 5727072), (5727068, 'b', 5727180), (5727120, 'blt', 5727176), (5727176, 'b', 5727180), (5727272, 'beq', 5727448), (5727312, 'beq', 5727444), (5727428, 'beq', 5727440), (5727440, 'b', 5727444), (5727444, 'b', 5727448)],
        semantics=('[World shouldBeCrystalBlockAtPos:] (imp 0x005762c8, 148w): the crystal predicate - **`worldIndexAtWorldPos(int...)`** (the crystal blocks are seeded by world index!).\n'),
    ),
    dict(
        name='wm_05',
        method='World -[removeBackWallAtPos:removeBlockhead:]',
        types='v20@0:4{?=ii}8@16',
        start=5727512,
        end=5728376,
        disasm='disasm_worldtileloader_wm_05.txt',
        base_add=5727528,
        base_literal=5728372,
        boundary='ARM.exidx end 0x00576878 (listing bound); next ObjC IMP 0x00576878 World -[removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:onlyRemoveCOntents:onlyRemoveForegroundContents:sendWorldChangedNotifcation:dontRemoveContents:]',
        selectors={
                 0x576844: (15195644, 'sendDataToServer:reliable:'),
                 0x576848: (15195632, 'appendBytes:length:'),
                 0x57684c: (15195552, 'dataWithBytes:length:'),
                 0x576854: (15196300, 'uniqueID'),
                 0x576868: (15196712, 'worldChangedAtPos:sendReliably:'),
                 0x576870: (15196756, 'updateSunLightForTile:atPos:world:'),
        },
        imports={
                 0x576840: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x57683c: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x57685c: (17156340, 'OBJC_IVAR_$_World.macroTiles', 412),
                 0x576860: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={
                 0x576850: (15245284, 'OBJC_CLASS_$_NSMutableData'),
                 0x57686c: (15245460, 'OBJC_CLASS_$_WorldHelper'),
        },
        instructions=[(5727512, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5728372, 'adceq sb, lr, r4, asr 11')],
        calls=[(5727572, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5727600, 'bl sym.tileIsSolid_Tile_'), (5727868, 'bl loc.imp.objc_msgSend'), (5727920, 'blx ip'), (5727964, 'blx ip'), (5728012, 'blx lr'), (5728184, 'bl loc.imp.objc_msgSend'), (5728256, 'bl loc.imp.objc_msgSend'), (5728304, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_')],
        branches=[(5727592, 'beq', 5727616), (5727612, 'beq', 5727620), (5727616, 'b', 5728308), (5727656, 'beq', 5728016)],
        semantics=('[World removeBackWallAtPos:removeBlockhead:] (imp 0x00576518, 216w): the backwall removal - objc x3 + tileAtWorldPositionLoaded + **tileIsSolid** + **`reloadDrawBlockGeometryForTile`** (the geometry invalidation!) + consts 0x10/0x3a (58).\n'),
    ),
    dict(
        name='wm_06',
        method='World -[removeWaterTileAtPos:]',
        types='v16@0:4{?=ii}8',
        start=5735472,
        end=5736992,
        disasm='disasm_worldtileloader_wm_06.txt',
        base_add=5735488,
        base_literal=5736988,
        boundary='ARM.exidx end 0x00578a20 (listing bound); next ObjC IMP 0x00578a20 World -[updateTileGraphicForWorkbenchOfType:atPos:level:]',
        selectors={
                 0x5789d4: (15195644, 'sendDataToServer:reliable:'),
                 0x5789d8: (15195632, 'appendBytes:length:'),
                 0x5789dc: (15195552, 'dataWithBytes:length:'),
                 0x5789e4: (15196792, 'isAdmin'),
                 0x5789f4: (15196812, 'loadSnowSurfaceBlockAtPos:loadSnow:'),
                 0x5789fc: (15196816, 'loadSurfaceBlockAtPos:'),
                 0x578a10: (15196824, 'waterChangedAtPos:fullBlock:'),
                 0x578a18: (15196756, 'updateSunLightForTile:atPos:world:'),
        },
        imports={
                 0x5789d0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5789cc: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5789ec: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x578a08: (17156340, 'OBJC_IVAR_$_World.macroTiles', 412),
        },
        classes={
                 0x5789e0: (15245284, 'OBJC_CLASS_$_NSMutableData'),
                 0x578a14: (15245460, 'OBJC_CLASS_$_WorldHelper'),
        },
        instructions=[(5735472, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5736988, 'adceq r7, lr, ip, lsr 13')],
        calls=[(5735756, 'bl loc.imp.objc_msgSend'), (5735832, 'blx lr'), (5735876, 'blx ip'), (5735924, 'blx lr'), (5735940, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5736036, 'bl sym.tileIsAir_Tile_'), (5736068, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5736096, 'bl sym.tileIsSolid_Tile_'), (5736116, 'bl sym.tileIsWater_Tile_'), (5736220, 'bl loc.imp.objc_msgSend'), (5736240, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5736268, 'bl sym.tileIsWater_Tile_'), (5736360, 'bl loc.imp.objc_msgSend'), (5736384, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5736412, 'bl sym.tileIsWater_Tile_'), (5736504, 'bl loc.imp.objc_msgSend'), (5736528, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5736556, 'bl sym.tileIsWater_Tile_'), (5736648, 'bl loc.imp.objc_msgSend'), (5736776, 'bl loc.imp.objc_msgSend'), (5736848, 'bl loc.imp.objc_msgSend'), (5736896, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_')],
        branches=[(5735544, 'beq', 5735928), (5735960, 'bne', 5735968), (5735964, 'b', 5736900), (5736028, 'bne', 5736664), (5736048, 'beq', 5736664), (5736088, 'beq', 5736224), (5736108, 'bne', 5736148), (5736128, 'beq', 5736224), (5736144, 'ble', 5736224), (5736260, 'beq', 5736368), (5736280, 'beq', 5736368), (5736296, 'ble', 5736368), (5736364, 'b', 5736660), (5736404, 'beq', 5736512), (5736424, 'beq', 5736512), (5736440, 'ble', 5736512), (5736508, 'b', 5736656), (5736548, 'beq', 5736652), (5736568, 'beq', 5736652), (5736584, 'ble', 5736652), (5736652, 'b', 5736656), (5736656, 'b', 5736660), (5736660, 'b', 5736664)],
        semantics=('[World removeWaterTileAtPos:] (imp 0x00578430, 380w): the water removal - objc x7 + tileAtWorldPositionLoaded x5 + **tileIsWater x4** + tileIsAir/tileIsSolid + reload + consts 0x18/0x11.\n'),
    ),
    dict(
        name='wm_07',
        method='World -[updateTileGraphicForWorkbenchOfType:atPos:level:]',
        types='v24@0:4i8{?=ii}12i20',
        start=5736992,
        end=5737620,
        disasm='disasm_worldtileloader_wm_07.txt',
        base_add=5737008,
        base_literal=5737616,
        boundary='ARM.exidx end 0x00578c94 (listing bound); next ObjC IMP 0x00578c94 World -[remotePlaceWorkbenchRequest:fromPeer:]',
        selectors={
                 0x578c80: (15196712, 'worldChangedAtPos:sendReliably:'),
                 0x578c88: (15196828, 'updateiCloudRecentConnectionList'),
        },
        imports={
                 0x578c84: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x578c70: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x578c74: (17156340, 'OBJC_IVAR_$_World.macroTiles', 412),
                 0x578c7c: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={},
        instructions=[(5736992, 'push {r4, r5, r6, sl, fp, lr}'), (5737616, 'strhteq r7, [lr], ip')],
        calls=[(5737060, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5737232, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5737392, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (5737464, 'bl loc.imp.objc_msgSend'), (5737572, 'blx r2')],
        branches=[(5737080, 'beq', 5737304), (5737092, 'beq', 5737156), (5737104, 'beq', 5737156), (5737116, 'beq', 5737156), (5737128, 'beq', 5737156), (5737140, 'beq', 5737156), (5737152, 'bne', 5737276), (5737176, 'beq', 5737216), (5737188, 'beq', 5737216), (5737200, 'beq', 5737216), (5737212, 'bne', 5737272), (5737252, 'beq', 5737268), (5737268, 'b', 5737272), (5737272, 'b', 5737300), (5737300, 'b', 5737304), (5737496, 'beq', 5737576), (5737508, 'bne', 5737576)],
        semantics=('[World updateTileGraphicForWorkbenchOfType:atPos:level:] (imp 0x00578a20, 157w): the workbench graphic update - tileAtWorldPositionLoaded x2 + reload + consts 0x2f (47)/0x2e (46) (the workbench tier graphic codes).\n'),
    ),
    dict(
        name='wm_08',
        method='World -[remotePlaceWorkbenchRequest:fromPeer:]',
        types='v16@0:4@8@12',
        start=5737620,
        end=5738612,
        disasm='disasm_worldtileloader_wm_08.txt',
        base_add=5737636,
        base_literal=5738608,
        boundary='ARM.exidx end 0x00579074 (listing bound); next ObjC IMP 0x00579074 World -[placeWorkbenchOfType:atPos:saveDict:placedByClient:placedByBlockhead:placedByClientName:]',
        selectors={
                 0x579024: (15195656, 'getBytes:length:'),
                 0x579028: (15196716, 'tileIsProtectedAtPos:againstClient:'),
                 0x579034: (15195624, 'objectForKey:'),
                 0x57903c: (15196836, 'gzipInflate'),
                 0x579040: (15195652, 'length'),
                 0x579048: (15196832, 'subdataWithRange:'),
                 0x57904c: (15196844, 'clientBlockheadInventoryRecievedForPlayerID:blockheadID:data:'),
                 0x579058: (15196840, 'unsignedLongLongValue'),
                 0x579064: (15196848, 'playerInfoForPeerID:'),
                 0x57906c: (15196100, 'placeWorkbenchOfType:atPos:saveDict:placedByClient:placedByBlockhead:placedByClientName:'),
        },
        imports={
                 0x579020: (17151904, 'objc_msgSend'),
                 0x579030: (16232152, '__CFConstantStringClassReference'),
                 0x579038: (16232136, '__CFConstantStringClassReference'),
                 0x579054: (16232168, '__CFConstantStringClassReference'),
                 0x579068: (16232184, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x57901c: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x57905c: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={},
        instructions=[(5737620, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5738608, 'adceq r6, lr, r8, asr 28')],
        calls=[(5737720, 'blx r6'), (5737796, 'bl sym.makeIntpair_int__int_'), (5737840, 'bl loc.imp.objc_msgSend'), (5737924, 'bl loc.imp.objc_msgSend'), (5737992, 'bl loc.imp.objc_msgSend'), (5738016, 'blx r2'), (5738020, 'bl 0x559f54'), (5738100, 'blx ip'), (5738128, 'blx r3'), (5738208, 'bl loc.imp.objc_msgSend'), (5738224, 'bl loc.imp.objc_msgSend'), (5738304, 'bl loc.imp.objc_msgSend'), (5738348, 'bl sym.makeIntpair_int__int_'), (5738420, 'bl loc.imp.objc_msgSend'), (5738444, 'bl loc.imp.objc_msgSend'), (5738512, 'bl loc.imp.objc_msgSend')],
        branches=[(5737752, 'beq', 5737864), (5737768, 'beq', 5737864), (5737852, 'beq', 5737860), (5737856, 'b', 5738516), (5737860, 'b', 5737864), (5738148, 'beq', 5738308)],
        semantics=('[World remotePlaceWorkbenchRequest:fromPeer:] (imp 0x00578c94, 248w): the workbench place request - objc x9 + makeIntpair x2 + the helper 0x559f54 + const 0x10.\n'),
    ),
    dict(
        name='wm_09',
        method='World -[remotePlaceInteractionObjectRequest:fromPeer:]',
        types='v16@0:4@8@12',
        start=5741912,
        end=5743372,
        disasm='disasm_worldtileloader_wm_09.txt',
        base_add=5741928,
        base_literal=5743368,
        boundary='ARM.exidx end 0x0057a30c (listing bound); next ObjC IMP 0x0057a30c World -[placeInteractionObjectWithItem:atPos:saveDict:placedByClient:placedByBlockhead:placedByClientName:]',
        selectors={
                 0x57a2a0: (15195656, 'getBytes:length:'),
                 0x57a2a4: (15196716, 'tileIsProtectedAtPos:againstClient:'),
                 0x57a2b0: (15195624, 'objectForKey:'),
                 0x57a2b4: (15195860, 'autorelease'),
                 0x57a2b8: (15196896, 'initWithSaveData:'),
                 0x57a2c0: (15195752, 'alloc'),
                 0x57a2c8: (15196836, 'gzipInflate'),
                 0x57a2cc: (15195652, 'length'),
                 0x57a2d4: (15196832, 'subdataWithRange:'),
                 0x57a2d8: (15196312, 'itemType'),
                 0x57a2dc: (15196728, 'playerIsAdminWithID:'),
                 0x57a2e4: (15196844, 'clientBlockheadInventoryRecievedForPlayerID:blockheadID:data:'),
                 0x57a2f0: (15196840, 'unsignedLongLongValue'),
                 0x57a2fc: (15196848, 'playerInfoForPeerID:'),
                 0x57a304: (15196900, 'placeInteractionObjectWithItem:atPos:saveDict:placedByClient:placedByBlockhead:placedByClientName:'),
        },
        imports={
                 0x57a29c: (17151904, 'objc_msgSend'),
                 0x57a2ac: (16232136, '__CFConstantStringClassReference'),
                 0x57a2bc: (16231352, '__CFConstantStringClassReference'),
                 0x57a2e0: (16232152, '__CFConstantStringClassReference'),
                 0x57a2ec: (16232168, '__CFConstantStringClassReference'),
                 0x57a300: (16232184, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x57a298: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x57a2f4: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={
                 0x57a2c4: (15245472, 'OBJC_CLASS_$_InventoryItem'),
        },
        instructions=[(5741912, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5743368, 'adceq r5, lr, r4, lsl 27')],
        calls=[(5742012, 'blx r6'), (5742088, 'bl sym.makeIntpair_int__int_'), (5742132, 'bl loc.imp.objc_msgSend'), (5742216, 'bl loc.imp.objc_msgSend'), (5742284, 'bl loc.imp.objc_msgSend'), (5742308, 'blx r2'), (5742312, 'bl 0x559f54'), (5742472, 'blx r6'), (5742508, 'blx r3'), (5742540, 'blx r3'), (5742556, 'blx r2'), (5742584, 'blx r3'), (5742692, 'blx r3'), (5742776, 'blx r3'), (5742860, 'blx r3'), (5742940, 'bl loc.imp.objc_msgSend'), (5742956, 'bl loc.imp.objc_msgSend'), (5743036, 'bl loc.imp.objc_msgSend'), (5743076, 'bl sym.makeIntpair_int__int_'), (5743148, 'bl loc.imp.objc_msgSend'), (5743172, 'bl loc.imp.objc_msgSend'), (5743240, 'bl loc.imp.objc_msgSend')],
        branches=[(5742044, 'beq', 5742156), (5742060, 'beq', 5742156), (5742144, 'beq', 5742152), (5742148, 'b', 5743248), (5742152, 'b', 5742156), (5742620, 'beq', 5742800), (5742636, 'beq', 5742800), (5742704, 'bne', 5742796), (5742788, 'bne', 5742796), (5742792, 'b', 5743248), (5742796, 'b', 5742800), (5742880, 'beq', 5743040)],
        semantics=('[World remotePlaceInteractionObjectRequest:fromPeer:] (imp 0x00579d58, 365w): the interaction-object place request - objc x9 + makeIntpair x2 + the 0x559f54 helper + const **0x12d (301)** (the interaction-object item code!).\n'),
    ),
    dict(
        name='wm_10',
        method='World -[remoteFillRequest:placedByClient:]',
        types='I16@0:4@8@12',
        start=5748480,
        end=5750040,
        disasm='disasm_worldtileloader_wm_10.txt',
        base_add=5748496,
        base_literal=5750036,
        boundary='ARM.exidx end 0x0057bd18 (listing bound); next ObjC IMP 0x0057bd70 World -[remotePaintRequest:fromClient:]',
        selectors={
                 0x57bcb4: (15195652, 'length'),
                 0x57bcb8: (15195656, 'getBytes:length:'),
                 0x57bcc0: (15196832, 'subdataWithRange:'),
                 0x57bcc8: (15195624, 'objectForKey:'),
                 0x57bcd0: (15196844, 'clientBlockheadInventoryRecievedForPlayerID:blockheadID:data:'),
                 0x57bcdc: (15196840, 'unsignedLongLongValue'),
                 0x57bce8: (15196716, 'tileIsProtectedAtPos:againstClient:'),
                 0x57bcf8: (15196728, 'playerIsAdminWithID:'),
                 0x57bcfc: (15196732, 'updatePlayer:'),
                 0x57bd04: (15196848, 'playerInfoForPeerID:'),
                 0x57bd0c: (15196924, 'fillTile:atPos:withType:dataA:dataB:placedByClient:saveDict:placedByClientName:'),
                 0x57bd10: (15196712, 'worldChangedAtPos:sendReliably:'),
        },
        imports={
                 0x57bcb0: (17151904, 'objc_msgSend'),
                 0x57bcc4: (16232152, '__CFConstantStringClassReference'),
                 0x57bccc: (16232232, '__CFConstantStringClassReference'),
                 0x57bcd8: (16232168, '__CFConstantStringClassReference'),
                 0x57bd08: (16232184, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x57bce0: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x57bce4: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x57bcf0: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
        },
        classes={},
        instructions=[(5748480, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5750036, 'invalid')],
        calls=[(5748588, 'blx lr'), (5748628, 'blx r3'), (5748684, 'bl loc.imp.objc_msgSend'), (5748752, 'bl loc.imp.objc_msgSend'), (5748780, 'bl 0x559f54'), (5748860, 'blx ip'), (5748888, 'blx r3'), (5748968, 'bl loc.imp.objc_msgSend'), (5748984, 'bl loc.imp.objc_msgSend'), (5749064, 'bl loc.imp.objc_msgSend'), (5749156, 'bl sym.makeIntpair_int__int_'), (5749200, 'bl loc.imp.objc_msgSend'), (5749220, 'bl sym.itemTypeIsTrainCar_ItemType_'), (5749400, 'blx r3'), (5749484, 'blx r3'), (5749524, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5749568, 'bl sym.makeIntpair_int__int_'), (5749668, 'bl loc.imp.objc_msgSend'), (5749692, 'bl loc.imp.objc_msgSend'), (5749776, 'bl loc.imp.objc_msgSend'), (5749824, 'bl sym.makeIntpair_int__int_'), (5749864, 'bl loc.imp.objc_msgSend')],
        branches=[(5748636, 'bls', 5749076), (5748772, 'beq', 5749072), (5748908, 'beq', 5749068), (5749068, 'b', 5749072), (5749072, 'b', 5749076), (5749112, 'beq', 5749492), (5749128, 'beq', 5749492), (5749212, 'beq', 5749320), (5749232, 'bne', 5749320), (5749244, 'beq', 5749320), (5749316, 'b', 5749924), (5749328, 'bne', 5749488), (5749412, 'bne', 5749488), (5749488, 'b', 5749492)],
        semantics=('[World remoteFillRequest:placedByClient:] (imp 0x0057b700, 412w): the fill request - objc x10 + makeIntpair x3 + the 0x559f54 helper + **`itemTypeIsTrainCar(ItemType)`** (the car fill gate!) + tileAtWorldPositionLoaded + const 0x10.\n'),
    ),
    dict(
        name='wm_11',
        method='World -[remotePaintRequest:fromClient:]',
        types='v16@0:4@8@12',
        start=5750128,
        end=5750672,
        disasm='disasm_worldtileloader_wm_11.txt',
        base_add=5750144,
        base_literal=5750668,
        boundary='ARM.exidx end 0x0057bf90 (listing bound); next ObjC IMP 0x0057bf90 World -[fillTile:atPos:withType:]',
        selectors={
                 0x57bf6c: (15195656, 'getBytes:length:'),
                 0x57bf70: (15196716, 'tileIsProtectedAtPos:againstClient:'),
                 0x57bf78: (15196720, 'blockheadWithIDIncludingNet:'),
                 0x57bf84: (15196928, 'paintTile:atPos:colorIndex:faceIndex:paintBlockhead:'),
        },
        imports={
                 0x57bf68: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x57bf64: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x57bf7c: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={},
        instructions=[(5750128, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5750668, 'adceq r3, lr, ip, ror 26')],
        calls=[(5750228, 'blx r6'), (5750304, 'bl sym.makeIntpair_int__int_'), (5750348, 'bl loc.imp.objc_msgSend'), (5750468, 'bl loc.imp.objc_msgSend'), (5750488, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5750532, 'bl sym.makeIntpair_int__int_'), (5750616, 'bl loc.imp.objc_msgSend')],
        branches=[(5750260, 'beq', 5750372), (5750276, 'beq', 5750372), (5750360, 'beq', 5750368), (5750364, 'b', 5750620), (5750368, 'b', 5750372), (5750396, 'beq', 5750476), (5750400, 'b', 5750404)],
        semantics=('[World remotePaintRequest:fromClient:] (imp 0x0057bd70, 136w): the paint request - objc x3 + makeIntpair x2 + tileAtWorldPositionLoaded + const 0x18.\n'),
    ),
    dict(
        name='wm_12',
        method='World -[fillTile:atPos:withType:]',
        types='v24@0:4^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}8{?=ii}12i20',
        start=5750672,
        end=5750836,
        disasm='disasm_worldtileloader_wm_12.txt',
        base_add=5750752,
        base_literal=5750832,
        boundary='ARM.exidx end 0x0057c034 (listing bound); next ObjC IMP 0x0057c034 World -[fillTile:atPos:withType:dataA:dataB:placedByClient:saveDict:placedByClientName:]',
        selectors={
                 0x57c02c: (15196932, 'fillTile:atPos:withType:dataA:dataB:placedByClient:saveDict:placedByBlockhead:placedByClientName:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(5750672, 'push {r4, r5, fp, lr}'), (5750832, 'adceq r3, lr, ip, lsl 22')],
        calls=[(5750816, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[World fillTile:atPos:withType:] (imp 0x0057bf90, 41w): the short fill forwarder (objc x1).\n'),
    ),
    dict(
        name='wm_13',
        method='World -[sendGatherNotificationForTile:atPos:]',
        types='v20@0:4^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}8{?=ii}12',
        start=5771144,
        end=5771820,
        disasm='disasm_worldtileloader_wm_13.txt',
        base_add=5771160,
        base_literal=5771816,
        boundary='ARM.exidx end 0x0058122c (listing bound); next ObjC IMP 0x0058122c World -[remoteGatherRequest:]',
        selectors={
                 0x58120c: (15195604, 'count'),
                 0x581214: (15195632, 'appendBytes:length:'),
                 0x581218: (15195552, 'dataWithBytes:length:'),
                 0x581220: (15195640, 'sendNetworkData:toPeers:reliable:'),
                 0x581224: (15195644, 'sendDataToServer:reliable:'),
        },
        imports={
                 0x581208: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x581200: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x581204: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x581210: (17155964, 'OBJC_IVAR_$_World.serverClients', 956),
        },
        classes={
                 0x58121c: (15245284, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(5771144, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5771816, 'adceq lr, sp, r4, asr fp')],
        calls=[(5771328, 'blx r2'), (5771488, 'blx ip'), (5771532, 'blx ip'), (5771656, 'blx ip'), (5771760, 'blx lr')],
        branches=[(5771224, 'bne', 5771340), (5771264, 'beq', 5771768), (5771336, 'bls', 5771768), (5771564, 'beq', 5771664), (5771660, 'b', 5771764), (5771764, 'b', 5771768)],
        semantics=('[World sendGatherNotificationForTile:atPos:] (imp 0x00580f88, 169w): the gather notification sender (no external calls - pure message packing) consts 0x10/0x1a (26).\n'),
    ),
    dict(
        name='wm_14',
        method='World -[remoteGatherRequest:]',
        types='v12@0:4@8',
        start=5771820,
        end=5773708,
        disasm='disasm_worldtileloader_wm_14.txt',
        base_add=5771836,
        base_literal=5773704,
        boundary='ARM.exidx end 0x0058198c (listing bound); next ObjC IMP 0x00581a38 World -[paintTile:atPos:colorIndex:faceIndex:paintBlockhead:]',
        selectors={
                 0x58195c: (15195656, 'getBytes:length:'),
                 0x581970: (15197036, 'loadGatherBlockAtPos:'),
                 0x58197c: (15195544, 'instance'),
                 0x581984: (15197032, 'addParticleAtPos:velocity:color:gravityType:life:scale:'),
        },
        imports={
                 0x581958: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x581954: (17156340, 'OBJC_IVAR_$_World.macroTiles', 412),
                 0x581960: (17156516, 'OBJC_IVAR_$_World.dayColor', 888),
                 0x581968: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={
                 0x581974: (15245388, 'OBJC_CLASS_$_ParticleEmitter'),
        },
        instructions=[(5771820, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5773704, 'invalid')],
        calls=[(5771904, 'blx r4'), (5771940, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (5771988, 'bl sym.tileIsSolid_Tile_'), (5772040, 'bl sym.particleColorForTile_Tile_'), (5772048, 'bl method.Vector.operator_float__'), (5772460, 'bl method.Vector.Vector_float__float__float_'), (5772468, 'bl method.Vector.operator_float__'), (5772544, 'bl method.Vector.operator_float__'), (5772576, 'bl method.Vector.operator_float__'), (5772632, 'bl method.Vector.operator_float__'), (5772664, 'bl method.Vector.operator_float__'), (5772720, 'bl method.Vector.operator_float__'), (5772772, 'bl method.Vector.Vector_float__float__float_'), (5772780, 'bl method.Vector.operator_float__'), (5772796, 'bl method.Vector.operator_float__'), (5772812, 'bl method.Vector.operator_float__'), (5772844, 'bl method.Vector.Vector_float__float__float__float_'), (5772884, 'bl sym.Vector::operator_Vector_'), (5772976, 'bl method.Vector.Vector_float__float__float_'), (5773040, 'bl loc.imp.objc_msgSend'), (5773048, 'bl 0x564c54'), (5773088, 'bl 0x564c54'), (5773140, 'bl method.Vector.Vector_float__float__float_'), (5773180, 'bl method.Vector.operator_Vector_'), (5773184, 'bl 0x564c54'), (5773220, 'bl 0x564c54'), (5773260, 'bl method.Vector.Vector_float__float__float_'), (5773472, 'bl loc.imp.objc_msgSend'), (5773508, 'bl sym.tileIsUnplacedBlockMinableWithPickaxe_Tile_'), (5773612, 'bl sym.makeIntpair_int__int_'), (5773640, 'bl loc.imp.objc_msgSend')],
        branches=[(5771960, 'beq', 5773504), (5771980, 'bge', 5773504), (5772000, 'bne', 5772020), (5772016, 'beq', 5773504), (5772068, 'ble', 5773500), (5772188, 'bpl', 5772204), (5772200, 'b', 5772212), (5772252, 'bpl', 5772276), (5772264, 'b', 5772284), (5772324, 'ble', 5772392), (5773004, 'bge', 5773496), (5773488, 'b', 5772996), (5773496, 'b', 5773500), (5773500, 'b', 5773504), (5773520, 'beq', 5773556), (5773536, 'beq', 5773644), (5773552, 'bne', 5773644)],
        semantics=('[World remoteGatherRequest:] (imp 0x0058122c, 472w): the gather request - **operator float* x10 + Vector(float,float,float) x5** + the helper 0x564c54 x4 + tileIsSolid + consts **0x400 (1024)**/0x3f80 (1.0f) (the gather range sphere!).\n'),
    ),
    dict(
        name='wm_15',
        method='World -[paintTile:atPos:colorIndex:faceIndex:paintBlockhead:]',
        types='v32@0:4^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}8{?=ii}12S20C24@28',
        start=5773880,
        end=5776228,
        disasm='disasm_worldtileloader_wm_15.txt',
        base_add=5773896,
        base_literal=5776224,
        boundary='ARM.exidx end 0x00582364 (listing bound); next ObjC IMP 0x00582364 World -[removePaintAtTile:atPos:faceIndex:paintBlockhead:]',
        selectors={
                 0x582300: (15196300, 'uniqueID'),
                 0x58230c: (15195644, 'sendDataToServer:reliable:'),
                 0x582310: (15195632, 'appendBytes:length:'),
                 0x582314: (15195552, 'dataWithBytes:length:'),
                 0x582324: (15197052, 'ladderAtPos:'),
                 0x582328: (15197044, 'canBeRemovedByBlockhead:'),
                 0x58232c: (15197048, 'paint:'),
                 0x582334: (15197040, 'columnAtPos:'),
                 0x582338: (15197056, 'isPaintable'),
                 0x582340: (15196428, 'interactionObjectAtPos:'),
                 0x582348: (15197064, 'elevatorShaftAtPos:'),
                 0x582350: (15197060, 'stairsAtPos:'),
                 0x58235c: (15196712, 'worldChangedAtPos:sendReliably:'),
        },
        imports={
                 0x582308: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5822fc: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x58231c: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x582354: (17156340, 'OBJC_IVAR_$_World.macroTiles', 412),
        },
        classes={
                 0x582318: (15245284, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(5773880, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5776224, 'adceq lr, sp, r4, lsr 1')],
        calls=[(5774068, 'bl loc.imp.objc_msgSend'), (5774228, 'blx r8'), (5774272, 'blx ip'), (5774320, 'blx lr'), (5774432, 'bl loc.imp.objc_msgSend'), (5774504, 'blx r3'), (5774580, 'blx r3'), (5774696, 'bl loc.imp.objc_msgSend'), (5774768, 'blx r3'), (5774844, 'blx r3'), (5774896, 'bl sym.tileIsSolid_Tile_'), (5775028, 'bl loc.imp.objc_msgSend'), (5775052, 'blx r2'), (5775132, 'blx r3'), (5775208, 'blx r3'), (5775340, 'bl loc.imp.objc_msgSend'), (5775412, 'blx r3'), (5775488, 'blx r3'), (5775508, 'bl sym.tileIsSolid_Tile_'), (5775624, 'bl loc.imp.objc_msgSend'), (5775696, 'blx r3'), (5775772, 'blx r3'), (5776024, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (5776072, 'bl sym.makeIntpair_int__int_'), (5776112, 'bl loc.imp.objc_msgSend')],
        branches=[(5773984, 'beq', 5774324), (5774044, 'beq', 5774080), (5774344, 'bne', 5774596), (5774452, 'beq', 5774520), (5774516, 'beq', 5774592), (5774592, 'b', 5774864), (5774608, 'bne', 5774860), (5774716, 'beq', 5774784), (5774780, 'beq', 5774856), (5774856, 'b', 5774860), (5774860, 'b', 5774864), (5774872, 'bne', 5775228), (5774888, 'beq', 5774928), (5774908, 'bne', 5775228), (5774924, 'bne', 5775228), (5775064, 'beq', 5775224), (5775080, 'beq', 5775148), (5775144, 'beq', 5775220), (5775220, 'b', 5775224), (5775224, 'b', 5775228), (5775236, 'bne', 5775796), (5775252, 'bne', 5775504), (5775360, 'beq', 5775428), (5775424, 'beq', 5775500), (5775500, 'b', 5775792), (5775520, 'bne', 5775788), (5775536, 'bne', 5775788), (5775644, 'beq', 5775712), (5775708, 'beq', 5775784), (5775784, 'b', 5775788), (5775788, 'b', 5775792), (5775792, 'b', 5775796), (5775804, 'bne', 5776116), (5775824, 'bhi', 5775948), (5775880, 'b', 5775960), (5775896, 'b', 5775960), (5775912, 'b', 5775960), (5775928, 'b', 5775960), (5775944, 'b', 5775960)],
        semantics=('[World paintTile:atPos:colorIndex:faceIndex:paintBlockhead:] (imp 0x00581a38, 587w): the paint writer - objc x7 + tileIsSolid x2 + reload + makeIntpair + consts 0x18/0x19 (25) (the paint face codes!).\n'),
    ),
    dict(
        name='wm_16',
        method='World -[removePaintAtTile:atPos:faceIndex:paintBlockhead:]',
        types='v28@0:4^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}8{?=ii}12C20@24',
        start=5776228,
        end=5776392,
        disasm='disasm_worldtileloader_wm_16.txt',
        base_add=5776320,
        base_literal=5776388,
        boundary='ARM.exidx end 0x00582408 (listing bound); next ObjC IMP 0x00582408 World -[getWeatherFractionForPos:atWorldTime:]',
        selectors={
                 0x582400: (15196928, 'paintTile:atPos:colorIndex:faceIndex:paintBlockhead:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(5776228, 'push {r4, r5, fp, lr}'), (5776388, 'adceq sp, sp, ip, lsr 14')],
        calls=[(5776372, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[World removePaintAtTile:atPos:faceIndex:paintBlockhead:] (imp 0x00582364, 41w): the paint remover (objc x1).\n'),
    ),
    dict(
        name='wm_17',
        method='World -[getWeatherFractionForPos:atWorldTime:]',
        types='f24@0:4{?=ii}8d16',
        start=5776392,
        end=5776520,
        disasm='disasm_worldtileloader_wm_17.txt',
        base_add=5776460,
        base_literal=5776516,
        boundary='ARM.exidx end 0x00582488 (listing bound); next ObjC IMP 0x00582488 World -[getWeatherFractionForPos:atWorldTime:ignoreSandFraction:]',
        selectors={
                 0x582480: (15197068, 'getWeatherFractionForPos:atWorldTime:ignoreSandFraction:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(5776392, 'push {fp, lr}'), (5776516, 'adceq sp, sp, r0, lsr 13')],
        calls=[(5776492, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[World getWeatherFractionForPos:atWorldTime:] (imp 0x00582408, 32w): the 2-arg weather forwarder (objc x1 - delegates to the ignoreSandFraction worker).\n'),
    ),
    dict(
        name='wm_18',
        method='World -[getWeatherFractionForPos:atWorldTime:ignoreSandFraction:]',
        types='f28@0:4{?=ii}8d16c24',
        start=5776520,
        end=5777940,
        disasm='disasm_worldtileloader_wm_18.txt',
        base_add=5776536,
        base_literal=5777936,
        boundary='ARM.exidx end 0x00582a14 (listing bound); next ObjC IMP 0x00582a50 World -[getWeatherFractionForPos:]',
        selectors={
                 0x5829d0: (15197072, 'getX:Y:Z:octaves:'),
                 0x5829f4: (15197076, 'sandFractionForPos:highRes:'),
        },
        imports={
                 0x5829cc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5829c8: (17156060, 'OBJC_IVAR_$_World.customRules', 160),
                 0x5829d4: (17156148, 'OBJC_IVAR_$_World.weatherNoiseFunction', 656),
                 0x5829dc: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
                 0x5829e8: (17156104, 'OBJC_IVAR_$_World.worldTileLoader', 420),
                 0x5829ec: (17156024, 'OBJC_IVAR_$_World.clientTileLoader', 972),
                 0x582a0c: (17155920, 'OBJC_IVAR_$_World.noRainTimer', 940),
        },
        classes={},
        instructions=[(5776520, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5777936, 'adceq sp, sp, r4, asr r6')],
        calls=[(5776724, 'bl sym.imp.__aeabi_idiv'), (5776792, 'blx lr'), (5777092, 'bl loc.imp.objc_msgSend'), (5777180, 'bl loc.imp.objc_msgSend'), (5777300, 'bl sym.clamp_float__float__float_'), (5777756, 'bl sym.clamp_float__float__float_'), (5777804, 'bl sym.linearInterpolate_float__float__float_'), (5777832, 'bl sym.clamp_float__float__float_')],
        branches=[(5776832, 'beq', 5776952), (5776868, 'bne', 5776892), (5776888, 'b', 5776948), (5776924, 'bne', 5776944), (5776944, 'b', 5776948), (5776948, 'b', 5776952), (5776976, 'bne', 5777196), (5777016, 'beq', 5777108), (5777104, 'b', 5777192), (5777192, 'b', 5777196), (5777344, 'ble', 5777384), (5777380, 'b', 5777492), (5777396, 'ble', 5777464), (5777440, 'b', 5777488), (5777488, 'b', 5777492), (5777540, 'bpl', 5777816), (5777576, 'beq', 5777652), (5777612, 'beq', 5777816), (5777648, 'beq', 5777816)],
        semantics=('[World getWeatherFractionForPos:atWorldTime:ignoreSandFraction:] (imp 0x00582488, 355w): the weather/day worker - clamp_float x3 + __aeabi_idiv + linearInterpolate + objc x2 + consts 0x100 (256)/0xa (10)/0x384 (900!)/0x1c2 (450!)/0x4000: the 900-tick day split into 900/450 segments, interpolated.\n'),
    ),
    dict(
        name='wm_19',
        method='World -[getWeatherFractionForPos:]',
        types='f16@0:4{?=ii}8',
        start=5778000,
        end=5778136,
        disasm='disasm_worldtileloader_wm_19.txt',
        base_add=5778060,
        base_literal=5778128,
        boundary='ARM.exidx end 0x00582ad8 (listing bound); next ObjC IMP 0x00582ad8 World -[getDayNightFractionForX:atWorldTime:]',
        selectors={
                 0x582ad4: (15197080, 'getWeatherFractionForPos:atWorldTime:'),
        },
        imports={},
        ivars={
                 0x582acc: (17155924, 'OBJC_IVAR_$_World.worldTime', 648),
        },
        classes={},
        instructions=[(5778000, 'push {fp, lr}'), (5778132, 'invalid')],
        calls=[(5778104, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[World getWeatherFractionForPos:] (imp 0x00582a50, 34w): the 1-arg forwarder (const 0xa).\n'),
    ),
    dict(
        name='wm_20',
        method='World -[getDayNightFractionForX:atWorldTime:]',
        types='f20@0:4f8d12',
        start=5778136,
        end=5778944,
        disasm='disasm_worldtileloader_wm_20.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00582e00 (listing bound); next ObjC IMP 0x00583578 World -[dayColorForPosition:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(5778136, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5778940, 'strdmi r2, r3, [sb], -fp')],
        calls=[(5778180, 'bl sym.absoluteSeasonFraction_double_'), (5778212, 'bl sym.imp.__wrap_fmodf'), (5778252, 'bl sym.imp.cos'), (5778344, 'bl sym.polarToRectangular_double__double_'), (5778364, 'bl sym.getWorldUpVectorForX_float__World_'), (5778372, 'bl method.Vector.operator_float__'), (5778388, 'bl method.Vector.operator_float__'), (5778456, 'bl 0x582eb4'), (5778592, 'bl method.Vector.operator_float__'), (5778608, 'bl method.Vector.operator_float__'), (5778624, 'bl method.Vector.operator_float__'), (5778644, 'bl 0x58353c'), (5778880, 'bl 0x583288')],
        branches=[],
        semantics=('[World getDayNightFractionForX:atWorldTime:] (imp 0x00582ad8, 202w): the celestial arc - absoluteSeasonFraction(double) + __wrap_fmodf + cos + polarToRectangular(double...) + getWorldUpVectorForX + operator float* x5 + const 0x3f80 (1.0f): the sun/moon position from polar coordinates (season + time -> angle -> rect).\n'),
    ),
    dict(
        name='wm_21',
        method='World -[dayColorForPosition:]',
        types='{Vector=[4f]}16@0:4{?=ii}8',
        start=5780856,
        end=5782608,
        disasm='disasm_worldtileloader_wm_21.txt',
        base_add=5780872,
        base_literal=5782600,
        boundary='ARM.exidx end 0x00583c50 (listing bound); next ObjC IMP 0x00583c50 World -[preRenderUpdate:fastSlowDT:cameraZ:projectionMatrix:]',
        selectors={
                 0x583c14: (15196992, 'getDayNightFractionForX:atWorldTime:'),
                 0x583c1c: (15196996, 'getWeatherFractionForPos:'),
                 0x583c30: (15195748, 'data'),
                 0x583c34: (15197084, 'width'),
        },
        imports={
                 0x583c10: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x583c18: (17155924, 'OBJC_IVAR_$_World.worldTime', 648),
                 0x583c28: (17156236, 'OBJC_IVAR_$_World.dayColorImageData', 904),
                 0x583c38: (17156232, 'OBJC_IVAR_$_World.dayColorCloudyImageData', 908),
                 0x583c40: (17156060, 'OBJC_IVAR_$_World.customRules', 160),
        },
        classes={},
        instructions=[(5780856, 'push {r4, r5, r6, sl, fp, lr}'), (5782604, 'andeq r0, r0, r0')],
        calls=[(5780940, 'bl method.Vector.Vector__'), (5780996, 'bl loc.imp.objc_msgSend'), (5781064, 'blx r3'), (5781168, 'bl sym.clamp_float__float__float_'), (5781316, 'bl loc.imp.objc_msgSend'), (5781352, 'bl loc.imp.objc_msgSend'), (5781448, 'bl sym.linearInterpolate_float__float__float_'), (5781520, 'bl sym.linearInterpolate_float__float__float_'), (5781612, 'bl sym.linearInterpolate_float__float__float_'), (5781712, 'bl loc.imp.objc_msgSend'), (5781752, 'bl loc.imp.objc_msgSend'), (5781848, 'bl sym.linearInterpolate_float__float__float_'), (5781920, 'bl sym.linearInterpolate_float__float__float_'), (5782012, 'bl sym.linearInterpolate_float__float__float_'), (5782064, 'bl sym.linearInterpolate_float__float__float_'), (5782080, 'bl method.Vector.operator_float__'), (5782116, 'bl sym.linearInterpolate_float__float__float_'), (5782132, 'bl method.Vector.operator_float__'), (5782168, 'bl sym.linearInterpolate_float__float__float_'), (5782184, 'bl method.Vector.operator_float__'), (5782220, 'bl sym.linearInterpolate_float__float__float_'), (5782244, 'bl method.Vector.operator_float__'), (5782356, 'bl method.Vector.operator_float__'), (5782436, 'bl method.Vector.operator_float__'), (5782516, 'bl method.Vector.operator_float__')],
        branches=[(5781088, 'ble', 5781200), (5781180, 'b', 5781200), (5781252, 'bpl', 5781640), (5781652, 'ble', 5782040), (5782288, 'beq', 5782536)],
        semantics=('[World dayColorForPosition:] (imp 0x00583578, 438w): the sky color ramp - linearInterpolate x10 + clamp_float + operator float* x7 + objc x5 + Vector x1 + consts 0x14 (20)/0xff/0x7f: the multi-stop sky gradient.\n'),
    ),
    dict(
        name='wm_22',
        method='World -[lightPositionTop]',
        types='{Vector=[4f]}8@0:4',
        start=5817168,
        end=5817352,
        disasm='disasm_worldtileloader_wm_22.txt',
        base_add=5817184,
        base_literal=5817348,
        boundary='ARM.exidx end 0x0058c408 (listing bound); next ObjC IMP 0x0058c408 World -[lightPositionFront]',
        selectors={},
        imports={},
        ivars={
                 0x58c400: (17155888, 'OBJC_IVAR_$_World.roundedTranslation', 616),
        },
        classes={},
        instructions=[(5817168, 'push {fp, lr}'), (5817348, 'adceq r3, sp, ip, lsl 15')],
        calls=[(5817228, 'bl method.Vector2.operator_float__'), (5817280, 'bl method.Vector2.operator_float__'), (5817328, 'bl method.Vector.Vector_float__float__float_')],
        branches=[],
        semantics=('[World lightPositionTop] (imp 0x0058c350, 46w): the top light offset (operator float* x2 + Vector x1 + const 0xa (10)).\n'),
    ),
    dict(
        name='wm_23',
        method='World -[lightPositionFront]',
        types='{Vector=[4f]}8@0:4',
        start=5817352,
        end=5817688,
        disasm='disasm_worldtileloader_wm_23.txt',
        base_add=5817368,
        base_literal=5817684,
        boundary='ARM.exidx end 0x0058c558 (listing bound); next ObjC IMP 0x0058c558 World -[lightPositionRight]',
        selectors={},
        imports={},
        ivars={
                 0x58c544: (17155888, 'OBJC_IVAR_$_World.roundedTranslation', 616),
                 0x58c548: (17155872, 'OBJC_IVAR_$_World.pinchScale', 400),
                 0x58c550: (17155876, 'OBJC_IVAR_$_World.windowInfo', 152),
        },
        classes={},
        instructions=[(5817352, 'push {r4, r5, r6, sl, fp, lr}'), (5817684, 'invalid')],
        calls=[(5817532, 'bl method.Vector2.operator_float__'), (5817600, 'bl method.Vector2.operator_float__'), (5817652, 'bl method.Vector.Vector_float__float__float_')],
        branches=[],
        semantics=('[World lightPositionFront] (imp 0x0058c408, 84w): the front light offset (operator float* x2 + Vector x1 + consts 0x400 (1024)/0xc (12)).\n'),
    ),
    dict(
        name='wm_24',
        method='World -[lightPositionRight]',
        types='{Vector=[4f]}8@0:4',
        start=5817688,
        end=5818040,
        disasm='disasm_worldtileloader_wm_24.txt',
        base_add=5817704,
        base_literal=5818036,
        boundary='ARM.exidx end 0x0058c6b8 (listing bound); next ObjC IMP 0x0058c6b8 World -[lightPositionLeft]',
        selectors={},
        imports={},
        ivars={
                 0x58c6a4: (17155888, 'OBJC_IVAR_$_World.roundedTranslation', 616),
                 0x58c6a8: (17155872, 'OBJC_IVAR_$_World.pinchScale', 400),
                 0x58c6b0: (17155876, 'OBJC_IVAR_$_World.windowInfo', 152),
        },
        classes={},
        instructions=[(5817688, 'push {r4, r5, r6, r7, fp, lr}'), (5818036, 'adceq r3, sp, r4, lsl 11')],
        calls=[(5817884, 'bl method.Vector2.operator_float__'), (5817952, 'bl method.Vector2.operator_float__'), (5818004, 'bl method.Vector.Vector_float__float__float_')],
        branches=[],
        semantics=('[World lightPositionRight] (imp 0x0058c558, 88w): the right light offset (consts 0x400/0xc).\n'),
    ),
    dict(
        name='wm_25',
        method='World -[lightPositionLeft]',
        types='{Vector=[4f]}8@0:4',
        start=5818040,
        end=5818360,
        disasm='disasm_worldtileloader_wm_25.txt',
        base_add=5818056,
        base_literal=5818356,
        boundary='ARM.exidx end 0x0058c7f8 (listing bound); next ObjC IMP 0x0058c7f8 World -[render:cameraZ:projectionMatrix:pinchScale:]',
        selectors={},
        imports={},
        ivars={
                 0x58c7e4: (17155888, 'OBJC_IVAR_$_World.roundedTranslation', 616),
                 0x58c7e8: (17155872, 'OBJC_IVAR_$_World.pinchScale', 400),
                 0x58c7f0: (17155876, 'OBJC_IVAR_$_World.windowInfo', 152),
        },
        classes={},
        instructions=[(5818040, 'push {r4, r5, fp, lr}'), (5818356, 'adceq r3, sp, r4, lsr 8')],
        calls=[(5818196, 'bl method.Vector2.operator_float__'), (5818272, 'bl method.Vector2.operator_float__'), (5818324, 'bl method.Vector.Vector_float__float__float_')],
        branches=[],
        semantics=('[World lightPositionLeft] (imp 0x0058c6b8, 80w): the left light offset (consts 0x400/0xc/0x14).\n'),
    ),
    dict(
        name='wm_26',
        method='World -[decommisionBlock:blockToSavePhyscialBlock:]',
        types='v16@0:4^{MacroTile=CCC^{PhysicalBlock}^{DrawBlock}@f}8c12',
        start=5978992,
        end=5979768,
        disasm='disasm_worldtileloader_wm_26.txt',
        base_add=5979008,
        base_literal=5979764,
        boundary='ARM.exidx end 0x005b3e78 (listing bound); next ObjC IMP 0x005b3e78 World -[loadDynamicObjectsIfNotAlreadyLoadedForMacroTile:includeSurfaceBlocks:]',
        selectors={
                 0x5b3e54: (15195644, 'sendDataToServer:reliable:'),
                 0x5b3e58: (15195632, 'appendBytes:length:'),
                 0x5b3e5c: (15195552, 'dataWithBytes:length:'),
                 0x5b3e68: (15197500, 'removeDynamicObjectsForMacroTile:'),
                 0x5b3e70: (15197504, 'savePhysicalBlockForMacroTile:sendReliably:dontSend:onlySaveIfClientsNeedIt:'),
        },
        imports={
                 0x5b3e50: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5b3e4c: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5b3e64: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
                 0x5b3e6c: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={
                 0x5b3e60: (15245284, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(5978992, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5979764, 'adceq fp, sl, ip, ror 30')],
        calls=[(5979348, 'blx r8'), (5979392, 'blx ip'), (5979440, 'blx lr'), (5979528, 'blx r3'), (5979680, 'blx r4')],
        branches=[(5979064, 'beq', 5979444), (5979084, 'beq', 5979444), (5979456, 'beq', 5979532), (5979568, 'bne', 5979688), (5979580, 'beq', 5979688)],
        semantics=('[World decommisionBlock:blockToSavePhyscialBlock:] (imp 0x005b3b70, 194w): the single-block decommission (+0xd).\n'),
    ),
    dict(
        name='wm_27',
        method='World -[waterMovedFrom:fromTile:to:toTile:amount:]',
        types='v36@0:4{?=ii}8^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}16{?=ii}20^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}28i32',
        start=6036956,
        end=6039440,
        disasm='disasm_worldtileloader_wm_27.txt',
        base_add=6036972,
        base_literal=6039436,
        boundary='ARM.exidx end 0x005c2790 (listing bound); next ObjC IMP 0x005c2790 World -[iapStarted]',
        selectors={
                 0x5c2778: (15195544, 'instance'),
                 0x5c2788: (15197032, 'addParticleAtPos:velocity:color:gravityType:life:scale:'),
        },
        imports={},
        ivars={
                 0x5c2750: (17156644, 'OBJC_IVAR_$_World.cameraMinXWorld', 3044),
                 0x5c2754: (17156640, 'OBJC_IVAR_$_World.cameraMaxXWorld', 3048),
                 0x5c2758: (17156636, 'OBJC_IVAR_$_World.cameraMinYWorld', 3052),
                 0x5c275c: (17156632, 'OBJC_IVAR_$_World.cameraMaxYWorld', 3056),
                 0x5c2764: (17156516, 'OBJC_IVAR_$_World.dayColor', 888),
                 0x5c277c: (17156704, 'OBJC_IVAR_$_World.particleRandomNumberIndex', 3024),
                 0x5c2780: (17156344, 'OBJC_IVAR_$_World.particleRandomNumbers', 1024),
        },
        classes={
                 0x5c2770: (15245388, 'OBJC_CLASS_$_ParticleEmitter'),
        },
        instructions=[(6036956, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6039436, 'adceq sp, sb, r0, lsl 26')],
        calls=[(6037604, 'bl method.Vector.Vector_float__float__float_'), (6037612, 'bl method.Vector.operator_float__'), (6037688, 'bl method.Vector.operator_float__'), (6037720, 'bl method.Vector.operator_float__'), (6037776, 'bl method.Vector.operator_float__'), (6037808, 'bl method.Vector.operator_float__'), (6037864, 'bl method.Vector.operator_float__'), (6037916, 'bl method.Vector.Vector_float__float__float_'), (6037976, 'bl method.Vector.Vector_float__float__float__float_'), (6037984, 'bl method.Vector.operator_float__'), (6038000, 'bl method.Vector.operator_float__'), (6038016, 'bl method.Vector.operator_float__'), (6038048, 'bl method.Vector.Vector_float__float__float__float_'), (6038088, 'bl sym.Vector::operator_Vector_'), (6038248, 'bl method.Vector.Vector_float__float__float_'), (6038312, 'bl method.Vector.Vector_float__float__float_'), (6038348, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6038360, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (6038440, 'bl method.Vector.operator_float__'), (6038488, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6038500, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (6038580, 'bl method.Vector.operator_float__'), (6038608, 'bl method.Vector.operator_float__'), (6038644, 'bl method.Vector.operator_float__'), (6038676, 'bl method.Vector.operator_float__'), (6038712, 'bl method.Vector.operator_float__'), (6038768, 'bl sym.imp.__aeabi_idiv'), (6038820, 'bl loc.imp.objc_msgSend'), (6039064, 'bl method.Vector.Vector_float__float__float_'), (6039104, 'bl method.Vector.operator_Vector_'), (6039348, 'bl loc.imp.objc_msgSend')],
        branches=[(6037068, 'blt', 6037208), (6037108, 'bgt', 6037208), (6037148, 'blt', 6037208), (6037188, 'bgt', 6037208), (6037204, 'bgt', 6037212), (6037208, 'b', 6039368), (6037336, 'bpl', 6037352), (6037348, 'b', 6037360), (6037400, 'bpl', 6037420), (6037412, 'b', 6037428), (6037468, 'ble', 6037536), (6038372, 'beq', 6038472), (6038460, 'b', 6038604), (6038512, 'beq', 6038600), (6038600, 'b', 6038604), (6038636, 'ble', 6038672), (6038664, 'b', 6038736), (6038704, 'bpl', 6038732), (6038732, 'b', 6038736), (6038784, 'bge', 6039368), (6039364, 'b', 6038748)],
        semantics=('[World waterMovedFrom:fromTile:to:toTile:amount:] (imp 0x005c1ddc, 621w): the water flow - operator float* x15/x5/x2 + Vector constructs + tileAtWorldPositionLoaded x2 + **tileIsAirWaterOrSnow** + consts **0x4dd3 (the 1/17.0 flow divisor?)/0x1f4 (500!)**/0x64 (100)/0x20 (32)/0xcccd/0xdadc/0xff/0x400/0x3f80: the fluid level transfer with the 500-unit capacity.\n'),
    ),
    dict(
        name='wm_28',
        method='World -[sandFractionForPos:]',
        types='f16@0:4{?=ii}8',
        start=6123464,
        end=6123700,
        disasm='disasm_worldtileloader_wm_28.txt',
        base_add=6123504,
        base_literal=6123588,
        boundary='ARM.exidx end 0x005d70b4 (listing bound); next ObjC IMP 0x005d704c World -[hasRewardedVideoAvailable]',
        selectors={
                 0x5d7048: (15197076, 'sandFractionForPos:highRes:'),
                 0x5d70a8: (15198348, 'hasRewardedVideoAvailable'),
        },
        imports={
                 0x5d70a4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5d7040: (17156104, 'OBJC_IVAR_$_World.worldTileLoader', 420),
        },
        classes={},
        instructions=[(6123464, 'push {fp, lr}'), (6123696, 'umlaleq r8, r8, r0, sl')],
        calls=[(6123564, 'bl loc.imp.objc_msgSend'), (6123668, 'blx r3')],
        branches=[],
        semantics=('[World sandFractionForPos:] (imp 0x005d6fc8, 59w): the sand fraction accessor (objc x1).\n'),
    ),
    dict(
        name='wm_52',
        method='World -[removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:]',
        types='v28@0:4i8i12i16i20@24',
        start=5726496,
        end=5726688,
        disasm='disasm_worldtileloader_wm_52.txt',
        base_add=5726512,
        base_literal=5726684,
        boundary='ARM.exidx end 0x005761e0 (listing bound); next ObjC IMP 0x005761e0 World -[removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:onlyRemoveCOntents:onlyRemoveForegroundContents:]',
        selectors={
                 0x5761d8: (15196744, 'removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:onlyRemoveCOntents:onlyRemoveForegroundContents:sendWorldChangedNotifcation:dontRemoveContents:'),
        },
        imports={
                 0x5761d4: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(5726496, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5726684, 'invalid')],
        calls=[(5726664, 'blx r8')],
        branches=[],
        semantics=('[World removeTileAtWorldX:...removeBlockhead:] (imp 0x00576120, 48w): the 5-arg removal forwarder.\n'),
    ),
    dict(
        name='wm_51',
        method='World -[removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:onlyRemoveCOntents:onlyRemoveForegroundContents:]',
        types='v36@0:4i8i12i16i20@24c28c32',
        start=5726688,
        end=5726920,
        disasm='disasm_worldtileloader_wm_51.txt',
        base_add=5726704,
        base_literal=5726916,
        boundary='ARM.exidx end 0x005762c8 (listing bound); next ObjC IMP 0x005762c8 World -[shouldBeCrystalBlockAtPos:]',
        selectors={
                 0x5762c0: (15196744, 'removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:onlyRemoveCOntents:onlyRemoveForegroundContents:sendWorldChangedNotifcation:dontRemoveContents:'),
        },
        imports={
                 0x5762bc: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(5726688, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5726916, 'invalid')],
        calls=[(5726896, 'blx lr')],
        branches=[],
        semantics=('[World removeTileAtWorldX:...onlyRemoveCOntents:onlyRemoveForegroundContents:] (imp 0x005761e0, 58w): the 7-arg removal forwarder.\n'),
    ),
    dict(
        name='wm_50',
        method='World -[removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:onlyRemoveCOntents:onlyRemoveForegroundContents:sendWorldChangedNotifcation:dontRemoveContents:]',
        types='v44@0:4i8i12i16i20@24c28c32c36c40',
        start=5728376,
        end=5735472,
        disasm='disasm_worldtileloader_wm_50.txt',
        base_add=5728392,
        base_literal=5732436,
        boundary='ARM.exidx end 0x00578430 (listing bound); next ObjC IMP 0x00578430 World -[removeWaterTileAtPos:]',
        selectors={
                 0x57785c: (15196760, 'shouldBeCrystalBlockAtPos:'),
                 0x57786c: (15195892, 'init'),
                 0x577870: (15195752, 'alloc'),
                 0x577a34: (15196768, 'setCountWatcher:'),
                 0x577a38: (15196764, 'worldUI'),
                 0x577a40: (15195544, 'instance'),
                 0x577a48: (15196176, 'addIndex:'),
                 0x577a4c: (15196476, 'isEqualToString:'),
                 0x577bc0: (15196592, 'stringFromMD5'),
                 0x577bc8: (15195708, 'stringWithFormat:'),
                 0x577bd0: (15196780, 'amountString'),
                 0x577bd4: (15196776, 'modify:modifyString:'),
                 0x577bdc: (15196772, 'amount'),
                 0x577dd0: (15196784, 'playTimeCrystalReceivedSoundAtPos:'),
                 0x577dd4: (15196788, 'checkIfCanWarpInSecondBlockheadAfterItemAdded:dataB:'),
                 0x577dd8: (15195644, 'sendDataToServer:reliable:'),
                 0x577ddc: (15195632, 'appendBytes:length:'),
                 0x577de0: (15195552, 'dataWithBytes:length:'),
                 0x577de8: (15196792, 'isAdmin'),
                 0x577df0: (15196300, 'uniqueID'),
                 0x57813c: (15196796, 'isNet'),
                 0x578140: (15196292, 'isClientBlockheadBeingControlledByServer'),
                 0x578144: (15196800, 'addToCrystalDiscrepency:'),
                 0x5783a8: (15195544, 'instance'),
                 0x5783b0: (15196592, 'stringFromMD5'),
                 0x5783b8: (15195708, 'stringWithFormat:'),
                 0x5783c0: (15196780, 'amountString'),
                 0x5783c4: (15196776, 'modify:modifyString:'),
                 0x5783cc: (15196772, 'amount'),
                 0x5783d0: (15196788, 'checkIfCanWarpInSecondBlockheadAfterItemAdded:dataB:'),
                 0x5783dc: (15196804, 'createFreeBlockAtPosition:forForegroundContents:forTile:priorityBlockhead:'),
                 0x5783e8: (15196784, 'playTimeCrystalReceivedSoundAtPos:'),
                 0x5783ec: (15196808, 'removeAnyBackgroundContentsForTile:atPos:removeBlockhead:'),
                 0x5783fc: (15196712, 'worldChangedAtPos:sendReliably:'),
                 0x578404: (15196812, 'loadSnowSurfaceBlockAtPos:loadSnow:'),
                 0x57840c: (15196816, 'loadSurfaceBlockAtPos:'),
                 0x578420: (15196756, 'updateSunLightForTile:atPos:world:'),
                 0x578428: (15196820, 'worldContentsChangedAtPos:'),
        },
        imports={
                 0x577868: (17151904, 'objc_msgSend'),
                 0x577bc4: (16232120, '__CFConstantStringClassReference'),
                 0x577bd8: (16232104, '__CFConstantStringClassReference'),
                 0x5783a4: (17151904, 'objc_msgSend'),
                 0x5783b4: (16232120, '__CFConstantStringClassReference'),
                 0x5783c8: (16232104, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x577858: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x577864: (17156384, 'OBJC_IVAR_$_World.clientTCMinedIndices', 3180),
                 0x577a3c: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x577dc8: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x578090: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x5783a0: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5783d4: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x57842c: (17156340, 'OBJC_IVAR_$_World.macroTiles', 412),
        },
        classes={
                 0x577874: (15245336, 'OBJC_CLASS_$_NSMutableIndexSet'),
                 0x577a44: (15245464, 'OBJC_CLASS_$_CrystalManager'),
                 0x577bcc: (15245304, 'OBJC_CLASS_$_NSString'),
                 0x577de4: (15245284, 'OBJC_CLASS_$_NSMutableData'),
                 0x5783ac: (15245464, 'OBJC_CLASS_$_CrystalManager'),
                 0x5783bc: (15245304, 'OBJC_CLASS_$_NSString'),
                 0x57841c: (15245460, 'OBJC_CLASS_$_WorldHelper'),
        },
        instructions=[(5728376, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5735468, 'invalid')],
        calls=[(5728484, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5728604, 'bl sym.makeIntpair_int__int_'), (5728636, 'bl loc.imp.objc_msgSend'), (5728764, 'blx r2'), (5728780, 'blx r2'), (5728816, 'bl sym.makeIntpair_int__int_'), (5728832, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (5729044, 'blx r3'), (5729076, 'blx r3'), (5729124, 'blx ip'), (5729156, 'blx r3'), (5729436, 'blx sl'), (5729452, 'blx r2'), (5729508, 'blx ip'), (5729524, 'blx r2'), (5729560, 'blx r3'), (5729592, 'blx ip'), (5729624, 'blx r3'), (5729640, 'blx r2'), (5729688, 'blx lr'), (5729704, 'blx r2'), (5729736, 'blx r3'), (5729832, 'blx lr'), (5729848, 'blx r2'), (5729956, 'bl sym.makeIntpair_int__int_'), (5729984, 'bl loc.imp.objc_msgSend'), (5730052, 'blx ip'), (5730280, 'bl loc.imp.objc_msgSend'), (5730320, 'bl loc.imp.objc_msgSend'), (5730444, 'blx lr'), (5730488, 'blx ip'), (5730536, 'blx lr'), (5730544, 'bl sym.tileContainsDoor_Tile_'), (5730556, 'bl sym.tileContainsTrapDoor_Tile_'), (5730672, 'blx r2'), (5730740, 'blx r2'), (5730936, 'blx r3'), (5730984, 'blx r2'), (5731112, 'blx r2'), (5731160, 'blx ip'), (5731192, 'blx r3'), (5731472, 'blx sl'), (5731488, 'blx r2'), (5731544, 'blx ip'), (5731560, 'blx r2'), (5731596, 'blx r3'), (5731628, 'blx ip'), (5731660, 'blx r3'), (5731676, 'blx r2'), (5731724, 'blx lr'), (5731740, 'blx r2'), (5731772, 'blx r3'), (5731868, 'blx lr'), (5731884, 'blx r2'), (5731992, 'bl sym.makeIntpair_int__int_'), (5732020, 'bl loc.imp.objc_msgSend'), (5732088, 'blx ip'), (5732188, 'bl sym.makeIntpair_int__int_'), (5732252, 'bl loc.imp.objc_msgSend'), (5732352, 'bl sym.makeIntpair_int__int_'), (5732416, 'bl loc.imp.objc_msgSend'), (5732484, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (5732704, 'bl sym.makeIntpair_int__int_'), (5732756, 'bl loc.imp.objc_msgSend'), (5732776, 'bl sym.backWallIsMutable_Tile_'), (5732808, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5733152, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5733164, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (5733200, 'bl sym.backWallIsMutable_Tile_'), (5733544, 'bl sym.makeIntpair_int__int_'), (5733596, 'bl loc.imp.objc_msgSend'), (5733668, 'bl sym.makeIntpair_int__int_'), (5733708, 'bl loc.imp.objc_msgSend'), (5734164, 'bl sym.tileIsAir_Tile_'), (5734196, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5734224, 'bl sym.tileIsSolid_Tile_'), (5734244, 'bl sym.tileIsWater_Tile_'), (5734332, 'bl sym.makeIntpair_int__int_'), (5734372, 'bl loc.imp.objc_msgSend'), (5734392, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5734420, 'bl sym.tileIsWater_Tile_'), (5734508, 'bl sym.makeIntpair_int__int_'), (5734536, 'bl loc.imp.objc_msgSend'), (5734564, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5734592, 'bl sym.tileIsWater_Tile_'), (5734680, 'bl sym.makeIntpair_int__int_'), (5734708, 'bl loc.imp.objc_msgSend'), (5734744, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5734772, 'bl sym.tileIsWater_Tile_'), (5734860, 'bl sym.makeIntpair_int__int_'), (5734888, 'bl loc.imp.objc_msgSend'), (5735004, 'bl sym.makeIntpair_int__int_'), (5735032, 'bl loc.imp.objc_msgSend'), (5735096, 'bl sym.makeIntpair_int__int_'), (5735136, 'bl loc.imp.objc_msgSend'), (5735184, 'bl sym.makeIntpair_int__int_'), (5735232, 'bl loc.imp.objc_msgSend'), (5735316, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_')],
        branches=[(5728504, 'bne', 5728512), (5728508, 'b', 5735320), (5728548, 'beq', 5730540), (5728564, 'bne', 5730064), (5728576, 'ble', 5730064), (5728652, 'beq', 5730060), (5728692, 'bne', 5728804), (5729180, 'bgt', 5729876), (5729748, 'beq', 5729864), (5729860, 'bne', 5729872), (5729872, 'b', 5729876), (5729896, 'bge', 5730004), (5730000, 'b', 5729884), (5730060, 'b', 5730064), (5730612, 'beq', 5730772), (5730628, 'bne', 5730772), (5730684, 'beq', 5730700), (5730696, 'b', 5730768), (5730752, 'beq', 5730764), (5730764, 'b', 5730768), (5730768, 'b', 5730772), (5730808, 'bne', 5732480), (5730820, 'bne', 5732480), (5730832, 'bne', 5732480), (5730844, 'bne', 5732480), (5730860, 'bne', 5732104), (5730872, 'ble', 5732104), (5730884, 'beq', 5730944), (5730940, 'b', 5732100), (5730996, 'bne', 5732096), (5731216, 'bgt', 5731912), (5731784, 'beq', 5731900), (5731896, 'bne', 5731908), (5731908, 'b', 5731912), (5731932, 'bge', 5732040), (5732036, 'b', 5731920), (5732096, 'b', 5732100), (5732100, 'b', 5732476), (5732128, 'bhs', 5732272), (5732268, 'b', 5732116), (5732292, 'bhs', 5732472), (5732432, 'b', 5732280), (5732472, 'b', 5732476), (5732476, 'b', 5732480), (5732500, 'bne', 5733752), (5732516, 'beq', 5733748), (5732532, 'beq', 5733748), (5732548, 'beq', 5733748), (5732564, 'beq', 5733748), (5732580, 'beq', 5733748), (5732596, 'beq', 5733748), (5732636, 'bne', 5732760), (5732648, 'beq', 5732668), (5732664, 'bne', 5732760), (5732768, 'bne', 5733040), (5732788, 'beq', 5733040), (5732828, 'beq', 5732944), (5732844, 'beq', 5732944), (5732860, 'beq', 5732944), (5732876, 'bne', 5732912), (5732892, 'beq', 5732912), (5732908, 'bne', 5732944), (5732912, 'b', 5733036), (5732956, 'bne', 5732976), (5732972, 'bne', 5733032), (5733032, 'b', 5733036), (5733036, 'b', 5733040), (5733048, 'bne', 5733744), (5733064, 'bne', 5733744), (5733096, 'blt', 5733128), (5733136, 'beq', 5733740), (5733176, 'beq', 5733716), (5733192, 'beq', 5733716), (5733212, 'beq', 5733716), (5733228, 'beq', 5733716), (5733244, 'beq', 5733716), (5733276, 'beq', 5733296), (5733292, 'bne', 5733344), (5733308, 'b', 5733392), (5733356, 'beq', 5733376), (5733372, 'bne', 5733388), (5733388, 'b', 5733392), (5733404, 'bne', 5733452), (5733488, 'bne', 5733600), (5733504, 'bne', 5733600), (5733608, 'beq', 5733712), (5733712, 'b', 5733720), (5733716, 'b', 5733740), (5733736, 'b', 5733080), (5733740, 'b', 5733744), (5733744, 'b', 5733748), (5733748, 'b', 5733752), (5733760, 'beq', 5733792), (5733772, 'bne', 5733788), (5733788, 'b', 5734912), (5733800, 'beq', 5733876), (5733812, 'bne', 5733828), (5733828, 'b', 5734908), (5733888, 'beq', 5733920), (5733900, 'bne', 5733916), (5733916, 'b', 5733920), (5733932, 'beq', 5734088), (5733948, 'beq', 5734088), (5733964, 'beq', 5734088), (5733980, 'beq', 5734088), (5733996, 'beq', 5734088), (5734012, 'beq', 5734088), (5734028, 'beq', 5734088), (5734044, 'beq', 5734088), (5734060, 'beq', 5734088), (5734156, 'bne', 5734904), (5734176, 'beq', 5734904), (5734216, 'beq', 5734376), (5734236, 'bne', 5734276), (5734256, 'beq', 5734376), (5734272, 'ble', 5734376), (5734412, 'beq', 5734548), (5734432, 'beq', 5734548), (5734448, 'ble', 5734548), (5734540, 'b', 5734900), (5734584, 'beq', 5734728), (5734604, 'beq', 5734728), (5734620, 'ble', 5734728), (5734712, 'b', 5734896), (5734764, 'beq', 5734892), (5734784, 'beq', 5734892), (5734800, 'ble', 5734892), (5734892, 'b', 5734896), (5734896, 'b', 5734900), (5734900, 'b', 5734904), (5734904, 'b', 5734908), (5734908, 'b', 5734912), (5734920, 'beq', 5735240), (5734932, 'bne', 5734948), (5734944, 'beq', 5735040), (5735036, 'b', 5735236), (5735236, 'b', 5735240)],
        semantics=('[World removeTileAtWorldX:...onlyRemoveCOntents:onlyRemoveForegroundContents:sendWorldChangedNotifcation:dontRemoveContents:] (imp 0x00576878, 1774w): the full removal engine (9 args) - objc x17 + **makeIntpair x16** + tileAtWorldPositionLoaded x7 + **tileIsWater x4** + tileIsAirWaterOrSnow x2 + consts 0xc350 (50000!)/0xb (11)/0x18/0x11/0x30 (the big-ticket item codes!)\n'),
    ),
    dict(
        name='wm_55',
        method='World -[placeWorkbenchOfType:atPos:saveDict:placedByClient:placedByBlockhead:placedByClientName:]',
        types='v36@0:4i8{?=ii}12@20@24@28@32',
        start=5738612,
        end=5741128,
        disasm='disasm_worldtileloader_wm_55.txt',
        base_add=5738628,
        base_literal=5741124,
        boundary='ARM.exidx end 0x00579a48 (listing bound); next ObjC IMP 0x00579d58 World -[remotePlaceInteractionObjectRequest:fromPeer:]',
        selectors={
                 0x5799a4: (15196428, 'interactionObjectAtPos:'),
                 0x5799ac: (15195848, 'intValue'),
                 0x5799b4: (15195624, 'objectForKey:'),
                 0x5799b8: (15196880, 'updateTileGraphicForWorkbenchOfType:atPos:level:'),
                 0x5799c0: (15196884, 'workbenchPlacedAtPosition:ofType:saveDict:placedByClient:clientName:'),
                 0x5799cc: (15195544, 'instance'),
                 0x5799d0: (15195660, 'multiSoundNamed:'),
                 0x5799d8: (15196888, 'playAtPosition:'),
                 0x5799e0: (15196892, 'workbenchPlaced:'),
                 0x5799e8: (15196876, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
                 0x5799ec: (15195684, 'dictionary'),
                 0x5799f4: (15195632, 'appendBytes:length:'),
                 0x5799f8: (15195552, 'dataWithBytes:length:'),
                 0x579a04: (15195584, 'setObject:forKey:'),
                 0x579a08: (15196856, 'inventoryNeedsSaving'),
                 0x579a0c: (15196852, 'prepareInventoryForSaving'),
                 0x579a10: (15196860, 'saveItemSlotsArray'),
                 0x579a18: (15196868, 'numberWithUnsignedLongLong:'),
                 0x579a24: (15196864, 'dataWithPropertyList:format:options:error:'),
                 0x579a28: (15195608, 'gzipDeflate'),
                 0x579a30: (15196300, 'uniqueID'),
                 0x579a38: (15196872, 'setInventoryNeedsSaving:'),
                 0x579a3c: (15195644, 'sendDataToServer:reliable:'),
                 0x579a40: (15195612, 'appendData:'),
        },
        imports={
                 0x5799a8: (17151904, 'objc_msgSend'),
                 0x5799b0: (16232200, '__CFConstantStringClassReference'),
                 0x5799d4: (16232216, '__CFConstantStringClassReference'),
                 0x579a00: (16232136, '__CFConstantStringClassReference'),
                 0x579a14: (16232168, '__CFConstantStringClassReference'),
                 0x579a2c: (16232152, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x579998: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x57999c: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5799dc: (17156044, 'OBJC_IVAR_$_World.tutorial', 232),
        },
        classes={
                 0x5799c4: (15245280, 'OBJC_CLASS_$_MJSoundManager'),
                 0x5799f0: (15245288, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x5799fc: (15245284, 'OBJC_CLASS_$_NSMutableData'),
                 0x579a1c: (15245468, 'OBJC_CLASS_$_NSPropertyListSerialization'),
                 0x579a34: (15245292, 'OBJC_CLASS_$_NSNumber'),
        },
        instructions=[(5738612, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5741124, 'adceq r6, lr, r8, ror 20')],
        calls=[(5738876, 'blx r8'), (5738944, 'blx ip'), (5738976, 'blx r3'), (5739064, 'blx ip'), (5739144, 'blx ip'), (5739164, 'blx r2'), (5739232, 'blx r3'), (5739372, 'bl loc.imp.objc_msgSend'), (5739388, 'bl loc.imp.objc_msgSend'), (5739436, 'bl loc.imp.objc_msgSend'), (5739456, 'bl loc.imp.objc_msgSend'), (5739524, 'bl loc.imp.objc_msgSend'), (5739560, 'blx ip'), (5739624, 'blx ip'), (5739636, 'bl 0x55468c'), (5739728, 'blx r2'), (5739756, 'blx r3'), (5739804, 'blx lr'), (5739844, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5739888, 'bl sym.tileIsSolid_Tile_'), (5739936, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5740048, 'bl loc.imp.objc_msgSend'), (5740096, 'bl sym.tileIsSolid_Tile_'), (5740128, 'bl 0x579a48'), (5740160, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5740204, 'bl sym.tileIsSolid_Tile_'), (5740312, 'blx ip'), (5740328, 'blx r2'), (5740416, 'bl 0x579ab4'), (5740496, 'bl loc.imp.objc_msgSend'), (5740580, 'bl loc.imp.objc_msgSend'), (5740684, 'bl loc.imp.objc_msgSend'), (5740736, 'bl loc.imp.objc_msgSend'), (5740760, 'bl loc.imp.objc_msgSend'), (5740800, 'bl method.Vector2.Vector2_float__float_'), (5740828, 'bl loc.imp.objc_msgSend'), (5740940, 'blx r3')],
        branches=[(5738724, 'beq', 5739812), (5738996, 'beq', 5739068), (5739080, 'beq', 5739632), (5739176, 'beq', 5739628), (5739252, 'beq', 5739564), (5739628, 'b', 5739632), (5739808, 'b', 5740944), (5739828, 'bne', 5739924), (5739864, 'beq', 5739912), (5739880, 'bne', 5739904), (5739900, 'beq', 5739912), (5739956, 'bne', 5739964), (5739960, 'b', 5740944), (5740060, 'beq', 5740076), (5740072, 'b', 5740240), (5740088, 'bne', 5740112), (5740108, 'beq', 5740124), (5740120, 'b', 5740236), (5740140, 'beq', 5740232), (5740180, 'beq', 5740228), (5740196, 'bne', 5740220), (5740216, 'beq', 5740228), (5740228, 'b', 5740232), (5740232, 'b', 5740236), (5740236, 'b', 5740240), (5740344, 'beq', 5740504), (5740500, 'b', 5740944), (5740700, 'bne', 5740832), (5740868, 'beq', 5740944)],
        semantics=('[World placeWorkbenchOfType:atPos:saveDict:placedByClient:placedByBlockhead:placedByClientName:] (imp 0x00579074, 629w): the workbench placer - objc x12 + tileAtWorldPositionLoaded x3 + tileIsSolid x3 + the internal helpers 0x55468c/0x579a48/0x579ab4 + consts 0x10/0x15 (21)/0x64.\n'),
    ),
    dict(
        name='wm_53',
        method='World -[placeInteractionObjectWithItem:atPos:saveDict:placedByClient:placedByBlockhead:placedByClientName:]',
        types='@36@0:4@8{?=ii}12@20@24@28@32',
        start=5743372,
        end=5748196,
        disasm='disasm_worldtileloader_wm_53.txt',
        base_add=5743388,
        base_literal=5746716,
        boundary='ARM.exidx end 0x0057b5e4 (listing bound); next ObjC IMP 0x0057b700 World -[remoteFillRequest:placedByClient:]',
        selectors={
                 0x57b02c: (15195584, 'setObject:forKey:'),
                 0x57b030: (15196904, 'saveData'),
                 0x57b034: (15195684, 'dictionary'),
                 0x57b03c: (15195632, 'appendBytes:length:'),
                 0x57b040: (15195552, 'dataWithBytes:length:'),
                 0x57b564: (15196856, 'inventoryNeedsSaving'),
                 0x57b568: (15196852, 'prepareInventoryForSaving'),
                 0x57b574: (15196312, 'itemType'),
                 0x57b580: (15196428, 'interactionObjectAtPos:'),
                 0x57b588: (15196920, 'interactionObjectPlacedAtPosition:withItem:flipped:saveDict:placedByClient:clientName:'),
                 0x57b58c: (15196712, 'worldChangedAtPos:sendReliably:'),
                 0x57b59c: (15196908, 'dataA'),
                 0x57b5a0: (15196912, 'dataB'),
                 0x57b5a4: (15196916, 'subItems'),
                 0x57b5a8: (15196876, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
                 0x57b5ac: (15195584, 'setObject:forKey:'),
                 0x57b5b0: (15196860, 'saveItemSlotsArray'),
                 0x57b5b8: (15196868, 'numberWithUnsignedLongLong:'),
                 0x57b5c4: (15196864, 'dataWithPropertyList:format:options:error:'),
                 0x57b5c8: (15195608, 'gzipDeflate'),
                 0x57b5d0: (15196300, 'uniqueID'),
                 0x57b5d8: (15196872, 'setInventoryNeedsSaving:'),
                 0x57b5dc: (15195644, 'sendDataToServer:reliable:'),
                 0x57b5e0: (15195612, 'appendData:'),
        },
        imports={
                 0x57b024: (16231352, '__CFConstantStringClassReference'),
                 0x57b028: (17151904, 'objc_msgSend'),
                 0x57b450: (16232136, '__CFConstantStringClassReference'),
                 0x57b570: (17151904, 'objc_msgSend'),
                 0x57b5b4: (16232168, '__CFConstantStringClassReference'),
                 0x57b5cc: (16232152, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x57b020: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x57b56c: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x57b578: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x57b594: (17156340, 'OBJC_IVAR_$_World.macroTiles', 412),
        },
        classes={
                 0x57b038: (15245288, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x57b044: (15245284, 'OBJC_CLASS_$_NSMutableData'),
                 0x57b5bc: (15245468, 'OBJC_CLASS_$_NSPropertyListSerialization'),
                 0x57b5d4: (15245292, 'OBJC_CLASS_$_NSNumber'),
        },
        instructions=[(5743372, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5748192, 'invalid')],
        calls=[(5743712, 'blx ip'), (5743772, 'blx ip'), (5743804, 'blx r3'), (5743844, 'blx r3'), (5743880, 'blx ip'), (5743964, 'blx ip'), (5744044, 'blx ip'), (5744064, 'blx r2'), (5744132, 'blx r3'), (5744272, 'bl loc.imp.objc_msgSend'), (5744288, 'bl loc.imp.objc_msgSend'), (5744336, 'bl loc.imp.objc_msgSend'), (5744356, 'bl loc.imp.objc_msgSend'), (5744424, 'bl loc.imp.objc_msgSend'), (5744460, 'blx ip'), (5744524, 'blx ip'), (5744536, 'bl 0x55468c'), (5744636, 'blx r3'), (5744664, 'blx r3'), (5744712, 'blx lr'), (5744776, 'blx r2'), (5744800, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5744844, 'bl sym.tileIsSolid_Tile_'), (5744912, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5744980, 'bl loc.imp.objc_msgSend'), (5745052, 'blx r2'), (5745056, 'bl sym.itemTypeIsTwoBlocksWide_ItemType_'), (5745088, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5745116, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5745144, 'bl sym.tileIsSolid_Tile_'), (5745180, 'bl sym.tileIsSolid_Tile_'), (5745252, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5745280, 'bl sym.tileIsSolid_Tile_'), (5745344, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5745356, 'bl sym.tileIsSolid_Tile_'), (5745468, 'blx r2'), (5745472, 'bl sym.itemTypeOccupiesForegroundContents_ItemType_'), (5745556, 'blx r2'), (5745612, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5745680, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5745728, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5745776, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5745844, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5745924, 'blx r2'), (5745988, 'blx r3'), (5746020, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5746100, 'blx r2'), (5746104, 'bl sym.interactionObjectItemTypeOccupiesForeground_ItemType_'), (5746268, 'bl loc.imp.objc_msgSend'), (5746300, 'bl loc.imp.objc_msgSend'), (5746332, 'bl loc.imp.objc_msgSend'), (5746364, 'bl loc.imp.objc_msgSend'), (5746472, 'bl loc.imp.objc_msgSend'), (5746528, 'blx r2'), (5746532, 'bl sym.interactionObjectItemTypeOccupiesForeground_ItemType_'), (5746616, 'blx r2'), (5746620, 'bl sym.itemTypeIsTwoBlocksWide_ItemType_'), (5746664, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5746776, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5746992, 'bl loc.imp.objc_msgSend'), (5747064, 'bl loc.imp.objc_msgSend'), (5747084, 'blx r2'), (5747136, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5747192, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5747224, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5747256, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5747304, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5747384, 'bl sym.makeIntpair_int__int_'), (5747436, 'bl loc.imp.objc_msgSend'), (5747484, 'bl sym.makeIntpair_int__int_'), (5747524, 'bl loc.imp.objc_msgSend'), (5747568, 'bl sym.makeIntpair_int__int_'), (5747608, 'bl loc.imp.objc_msgSend'), (5747656, 'bl sym.makeIntpair_int__int_'), (5747696, 'bl loc.imp.objc_msgSend'), (5747744, 'bl sym.makeIntpair_int__int_'), (5747784, 'bl loc.imp.objc_msgSend'), (5747836, 'blx r2'), (5747900, 'blx r3'), (5747944, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5748044, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_')],
        branches=[(5743484, 'beq', 5744728), (5743896, 'beq', 5743968), (5743980, 'beq', 5744532), (5744076, 'beq', 5744528), (5744152, 'beq', 5744464), (5744528, 'b', 5744532), (5744724, 'b', 5748056), (5744784, 'bne', 5744880), (5744820, 'beq', 5744868), (5744836, 'bne', 5744860), (5744856, 'beq', 5744868), (5744992, 'beq', 5745004), (5745068, 'beq', 5745428), (5745136, 'beq', 5745176), (5745156, 'bne', 5745228), (5745172, 'bne', 5745228), (5745192, 'bne', 5745424), (5745208, 'beq', 5745228), (5745224, 'beq', 5745424), (5745272, 'beq', 5745420), (5745292, 'bne', 5745312), (5745308, 'beq', 5745324), (5745320, 'b', 5745416), (5745368, 'bne', 5745412), (5745384, 'beq', 5745404), (5745400, 'beq', 5745412), (5745412, 'b', 5745416), (5745416, 'b', 5745420), (5745420, 'b', 5745424), (5745424, 'b', 5745428), (5745484, 'beq', 5745516), (5745500, 'beq', 5745512), (5745512, 'b', 5745516), (5745564, 'bne', 5745884), (5745580, 'beq', 5745596), (5745592, 'b', 5745880), (5745632, 'bne', 5745652), (5745648, 'beq', 5745660), (5745700, 'beq', 5745712), (5745748, 'beq', 5745760), (5745796, 'bne', 5745816), (5745812, 'beq', 5745824), (5745864, 'beq', 5745876), (5745876, 'b', 5745880), (5745880, 'b', 5746060), (5745932, 'beq', 5746004), (5746000, 'bne', 5746056), (5746040, 'beq', 5746052), (5746052, 'b', 5746056), (5746056, 'b', 5746060), (5746116, 'beq', 5746148), (5746132, 'beq', 5746144), (5746144, 'b', 5746176), (5746160, 'beq', 5746172), (5746172, 'b', 5746176), (5746184, 'beq', 5746488), (5746484, 'b', 5748056), (5746544, 'beq', 5746564), (5746560, 'b', 5746576), (5746632, 'beq', 5746832), (5746644, 'beq', 5746760), (5746684, 'beq', 5746712), (5746712, 'b', 5746828), (5746796, 'beq', 5746824), (5746824, 'b', 5746828), (5746828, 'b', 5746832), (5747092, 'bne', 5747796), (5747788, 'b', 5747968), (5747844, 'beq', 5747916), (5747912, 'bne', 5747964), (5747964, 'b', 5747968)],
        semantics=('[World placeInteractionObjectWithItem:atPos:saveDict:placedByClient:placedByBlockhead:placedByClientName:] (imp 0x0057a30c, 1206w): the interaction-object placer - tileAtWorldPositionLoaded x20 + objc x18 + tileIsSolid x5 + makeIntpair x5 + **`itemTypeIsTwoBlocksWide` x2** + consts 0x16 (22)/0x64 (100)/0x14b (331!)/0x30/0x62 (98) (the object item codes!).\n'),
    ),
    dict(
        name='wm_56',
        method='World -[fillTile:atPos:withType:dataA:dataB:placedByClient:saveDict:placedByClientName:]',
        types='v44@0:4^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}8{?=ii}12i20S24S28@32@36@40',
        start=5750836,
        end=5751068,
        disasm='disasm_worldtileloader_wm_56.txt',
        base_add=5750976,
        base_literal=5751064,
        boundary='ARM.exidx end 0x0057c11c (listing bound); next ObjC IMP 0x0057c11c World -[fillTile:atPos:withType:dataA:dataB:placedByClient:saveDict:placedByBlockhead:placedByClientName:]',
        selectors={
                 0x57c114: (15196932, 'fillTile:atPos:withType:dataA:dataB:placedByClient:saveDict:placedByBlockhead:placedByClientName:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(5750836, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5751064, 'adceq r3, lr, ip, lsr 20')],
        calls=[(5751048, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[World fillTile:atPos:withType:dataA:dataB:placedByClient:saveDict:placedByClientName:] (imp 0x0057c034, 58w): the 7-arg fill forwarder (objc x1).\n'),
    ),
    dict(
        name='wm_54',
        method='World -[fillTile:atPos:withType:dataA:dataB:placedByClient:saveDict:placedByBlockhead:placedByClientName:]',
        types='v48@0:4^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}8{?=ii}12i20S24S28@32@36@40@44',
        start=5751068,
        end=5770208,
        disasm='disasm_worldtileloader_wm_54.txt',
        base_add=5751084,
        base_literal=5755132,
        boundary='ARM.exidx end 0x00580be0 (listing bound); next ObjC IMP 0x00580f88 World -[sendGatherNotificationForTile:atPos:]',
        selectors={
                 0x57d1c0: (15195684, 'dictionary'),
                 0x57d1c8: (15195632, 'appendBytes:length:'),
                 0x57d1cc: (15195552, 'dataWithBytes:length:'),
                 0x57d1d4: (15196792, 'isAdmin'),
                 0x57d360: (15196856, 'inventoryNeedsSaving'),
                 0x57d364: (15196852, 'prepareInventoryForSaving'),
                 0x57d3b0: (15196860, 'saveItemSlotsArray'),
                 0x57d3fc: (15195584, 'setObject:forKey:'),
                 0x57d418: (15196868, 'numberWithUnsignedLongLong:'),
                 0x57d424: (15196864, 'dataWithPropertyList:format:options:error:'),
                 0x57d470: (15195608, 'gzipDeflate'),
                 0x57d4a8: (15196300, 'uniqueID'),
                 0x57d540: (15196872, 'setInventoryNeedsSaving:'),
                 0x57d5c0: (15195604, 'count'),
                 0x57d60c: (15195612, 'appendData:'),
                 0x57d658: (15195644, 'sendDataToServer:reliable:'),
                 0x57d71c: (15196936, 'sowTreeOrPlantAtPosition:itemType:maxHeight:growthRate:'),
                 0x57d948: (15196940, 'objectType'),
                 0x57d950: (15196428, 'interactionObjectAtPos:'),
                 0x57d954: (15196944, 'type'),
                 0x57da14: (15196416, 'workbenchAtPos:'),
                 0x57db90: (15196876, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
                 0x57e670: (15196948, 'addTorchAtPos:ofType:dataA:dataB:saveDict:placedByClient:'),
                 0x57f1e0: (15196952, 'addEggAtPos:saveDict:'),
                 0x57f3c4: (15196956, 'addPaintingAtPos:ofType:saveDict:placedByClient:clientName:'),
                 0x57f3fc: (15196960, 'addWindowAtPos:ofType:saveDict:placedByClient:'),
                 0x57f5b0: (15196964, 'addLadderAtPos:ofType:saveDict:placedByClient:'),
                 0x57f6ac: (15196968, 'addWireAtPos:ofType:saveDict:placedByClient:'),
                 0x57f778: (15196972, 'addElevatorShaftAtPos:ofType:saveDict:placedByClient:'),
                 0x57f780: (15196976, 'addElevatorMotorAtPos:ofType:saveDict:placedByClient:'),
                 0x57f8d0: (15196980, 'addRailAtPos:ofType:ownedByStation:'),
                 0x57fa1c: (15196984, 'addDoorAtPos:ofType:saveDict:placedByClient:'),
                 0x5800b8: (15196988, 'worldTime'),
                 0x5800c0: (15196992, 'getDayNightFractionForX:atWorldTime:'),
                 0x5800c4: (15196996, 'getWeatherFractionForPos:'),
                 0x580360: (15197000, 'placeBoatInWaterAtPos:saveDict:placedByClient:'),
                 0x580368: (15197004, 'placeTrainCarAtPos:ofType:saveDict:placedByClient:'),
                 0x580370: (15197008, 'placeFireAtPosition:'),
                 0x580378: (15196744, 'removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:onlyRemoveCOntents:onlyRemoveForegroundContents:sendWorldChangedNotifcation:dontRemoveContents:'),
                 0x5806f8: (15197012, 'loadNPCAtPosition:type:saveDict:isAdult:wasPlaced:placedByClient:'),
                 0x580790: (15197016, 'addColumnAtPos:ofType:saveDict:placedByClient:'),
                 0x5809dc: (15197020, 'addStairsAtPos:ofType:saveDict:placedByClient:'),
                 0x580b7c: (15196712, 'worldChangedAtPos:sendReliably:'),
                 0x580b84: (15196820, 'worldContentsChangedAtPos:'),
                 0x580b90: (15196824, 'waterChangedAtPos:fullBlock:'),
                 0x580b98: (15196816, 'loadSurfaceBlockAtPos:'),
                 0x580ba8: (15196812, 'loadSnowSurfaceBlockAtPos:loadSnow:'),
                 0x580bb4: (15197024, 'loadGlowBlockIfNeededAtPos:tile:'),
                 0x580bc0: (15196756, 'updateSunLightForTile:atPos:world:'),
                 0x580bd8: (15197028, 'updateSunLightRemovedForTile:atPos:world:'),
        },
        imports={
                 0x57d1bc: (17151904, 'objc_msgSend'),
                 0x57d3f8: (16232168, '__CFConstantStringClassReference'),
                 0x57d48c: (16232152, '__CFConstantStringClassReference'),
                 0x57d574: (16232232, '__CFConstantStringClassReference'),
                 0x580374: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x57d160: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x57d65c: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x57f03c: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x57f6a4: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x580b70: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x580b74: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={
                 0x57d1c4: (15245288, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x57d1d0: (15245284, 'OBJC_CLASS_$_NSMutableData'),
                 0x57d41c: (15245468, 'OBJC_CLASS_$_NSPropertyListSerialization'),
                 0x57d4c4: (15245292, 'OBJC_CLASS_$_NSNumber'),
                 0x580bb8: (15245460, 'OBJC_CLASS_$_WorldHelper'),
        },
        instructions=[(5751068, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5770204, 'adceq pc, sp, ip, asr r0')],
        calls=[(5751480, 'blx r2'), (5751528, 'blx ip'), (5751572, 'blx ip'), (5751604, 'blx r3'), (5751688, 'blx ip'), (5751708, 'blx r2'), (5751776, 'blx r3'), (5751916, 'bl loc.imp.objc_msgSend'), (5751932, 'bl loc.imp.objc_msgSend'), (5751980, 'bl loc.imp.objc_msgSend'), (5752000, 'bl loc.imp.objc_msgSend'), (5752068, 'bl loc.imp.objc_msgSend'), (5752104, 'blx ip'), (5752168, 'blx ip'), (5752256, 'blx ip'), (5752300, 'blx r2'), (5752408, 'blx ip'), (5752436, 'blx r3'), (5752528, 'blx ip'), (5752540, 'bl sym.itemTypeIsSowable_ItemType_'), (5752664, 'bl loc.imp.objc_msgSend'), (5752728, 'bl sym.tileIsPlant_Tile_'), (5752772, 'bl sym.tileIsTree_Tile_'), (5752792, 'bl sym.tileIsDeadTree_Tile_'), (5752812, 'bl sym.tileIsBush_Tile_'), (5752964, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5753024, 'bl sym.itemTypeOccupiesBackgroundContents_ItemType_'), (5753088, 'bl sym.itemTypeOccupiesForegroundContents_ItemType_'), (5753260, 'bl loc.imp.objc_msgSend'), (5753276, 'blx r2'), (5753304, 'bl sym.tileIsWorkbench_Tile_'), (5753420, 'bl loc.imp.objc_msgSend'), (5753436, 'blx r2'), (5753548, 'bl loc.imp.objc_msgSend'), (5753564, 'blx r2'), (5753592, 'bl sym.itemTypeIsBlock_ItemType_'), (5753628, 'bl sym.tileAllowsPlacingOfSolidBlocks_Tile_'), (5753660, 'bl sym.tileIsSolid_Tile_'), (5753756, 'bl sym.itemTypeIsPlacableOnTrees_ItemType_'), (5753992, 'bl loc.imp.objc_msgSend'), (5754008, 'bl sym.itemTypeIsValidFillItem_ItemType_'), (5756692, 'bl loc.imp.objc_msgSend'), (5756880, 'bl loc.imp.objc_msgSend'), (5757064, 'bl loc.imp.objc_msgSend'), (5757248, 'bl loc.imp.objc_msgSend'), (5757452, 'bl loc.imp.objc_msgSend'), (5757644, 'bl loc.imp.objc_msgSend'), (5757828, 'bl loc.imp.objc_msgSend'), (5758020, 'bl loc.imp.objc_msgSend'), (5758204, 'bl loc.imp.objc_msgSend'), (5758388, 'bl loc.imp.objc_msgSend'), (5758572, 'bl loc.imp.objc_msgSend'), (5758756, 'bl loc.imp.objc_msgSend'), (5758940, 'bl loc.imp.objc_msgSend'), (5759124, 'bl loc.imp.objc_msgSend'), (5759308, 'bl loc.imp.objc_msgSend'), (5759492, 'bl loc.imp.objc_msgSend'), (5759676, 'bl loc.imp.objc_msgSend'), (5759820, 'bl loc.imp.objc_msgSend'), (5759988, 'bl loc.imp.objc_msgSend'), (5760148, 'bl loc.imp.objc_msgSend'), (5760308, 'bl loc.imp.objc_msgSend'), (5760564, 'bl loc.imp.objc_msgSend'), (5760780, 'bl loc.imp.objc_msgSend'), (5760944, 'bl loc.imp.objc_msgSend'), (5761108, 'bl loc.imp.objc_msgSend'), (5761276, 'bl loc.imp.objc_msgSend'), (5761424, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5761664, 'bl loc.imp.objc_msgSend'), (5761780, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5761804, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5761876, 'bl sym.tileIsSolid_Tile_'), (5761896, 'bl sym.tileIsUnplacedBlockMinableWithPickaxe_Tile_'), (5761920, 'bl sym.tileTypeIsPortalBaseStone_TileType_'), (5762060, 'bl sym.backWallIsMutable_Tile_'), (5762084, 'bl sym.tileTypeIsPortalBaseStone_TileType_'), (5762328, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5762356, 'bl sym.tileIsSolid_Tile_'), (5762376, 'bl sym.tileIsUnplacedBlockMinableWithPickaxe_Tile_'), (5762400, 'bl sym.tileTypeIsPortalBaseStone_TileType_'), (5762760, 'bl loc.imp.objc_msgSend'), (5762880, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5762908, 'bl sym.tileIsSolid_Tile_'), (5762928, 'bl sym.tileIsUnplacedBlockMinableWithPickaxe_Tile_'), (5763012, 'bl sym.tileTypeIsPortalBaseStone_TileType_'), (5763156, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5763184, 'bl sym.tileIsSolid_Tile_'), (5763204, 'bl sym.tileIsUnplacedBlockMinableWithPickaxe_Tile_'), (5763288, 'bl sym.tileTypeIsPortalBaseStone_TileType_'), (5763512, 'bl loc.imp.objc_msgSend'), (5763604, 'bl loc.imp.objc_msgSend'), (5763644, 'bl loc.imp.objc_msgSend'), (5763708, 'bl loc.imp.objc_msgSend'), (5763744, 'bl sym.seasonForWorldX_int__double__World_'), (5763804, 'bl loc.imp.objc_msgSend'), (5763856, 'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_'), (5763936, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5764228, 'bl loc.imp.objc_msgSend'), (5764380, 'bl loc.imp.objc_msgSend'), (5764488, 'bl loc.imp.objc_msgSend'), (5764684, 'blx ip'), (5764832, 'bl sym.npcTypeFromCageItemType_ItemType_'), (5764968, 'bl loc.imp.objc_msgSend'), (5765164, 'bl loc.imp.objc_msgSend'), (5765308, 'bl loc.imp.objc_msgSend'), (5765484, 'bl loc.imp.objc_msgSend'), (5765644, 'bl loc.imp.objc_msgSend'), (5765732, 'bl sym.backWallIsMutable_Tile_'), (5765988, 'bl sym.backWallIsMutable_Tile_'), (5766200, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5766592, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5766604, 'bl sym.tileIsSolid_Tile_'), (5766820, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5766908, 'bl sym.tileIsSolid_Tile_'), (5766928, 'bl sym.backWallIsMutable_Tile_'), (5767460, 'bl loc.imp.objc_msgSend'), (5767508, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5767520, 'bl sym.tileIsAirOrSnow_Tile_'), (5767596, 'bl sym.makeIntpair_int__int_'), (5767624, 'bl loc.imp.objc_msgSend'), (5767644, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5767656, 'bl sym.tileIsAirOrSnow_Tile_'), (5767732, 'bl sym.makeIntpair_int__int_'), (5767760, 'bl loc.imp.objc_msgSend'), (5767780, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5767792, 'bl sym.tileIsAirOrSnow_Tile_'), (5767868, 'bl sym.makeIntpair_int__int_'), (5767896, 'bl loc.imp.objc_msgSend'), (5767944, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (5768020, 'bl loc.imp.objc_msgSend'), (5768132, 'bl loc.imp.objc_msgSend'), (5768212, 'bl sym.makeIntpair_int__int_'), (5768252, 'bl loc.imp.objc_msgSend'), (5768308, 'bl sym.tileIsSolid_Tile_'), (5768328, 'bl sym.tileIsWater_Tile_'), (5768412, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5768424, 'bl sym.tileIsAir_Tile_'), (5768504, 'bl sym.makeIntpair_int__int_'), (5768544, 'bl loc.imp.objc_msgSend'), (5768664, 'bl sym.makeIntpair_int__int_'), (5768704, 'bl loc.imp.objc_msgSend'), (5768752, 'bl sym.itemTypeIsLightEmittingBlock_ItemType_'), (5768852, 'bl loc.imp.objc_msgSend'), (5768920, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5769196, 'bl sym.makeIntpair_int__int_'), (5769236, 'bl loc.imp.objc_msgSend'), (5769256, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5769268, 'bl sym.tileIsAirOrSnow_Tile_'), (5769344, 'bl sym.makeIntpair_int__int_'), (5769372, 'bl loc.imp.objc_msgSend'), (5769392, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5769404, 'bl sym.tileIsAirOrSnow_Tile_'), (5769480, 'bl sym.makeIntpair_int__int_'), (5769508, 'bl loc.imp.objc_msgSend'), (5769528, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5769540, 'bl sym.tileIsAirOrSnow_Tile_'), (5769616, 'bl sym.makeIntpair_int__int_'), (5769644, 'bl loc.imp.objc_msgSend'), (5769844, 'bl loc.imp.objc_msgSend'), (5769924, 'bl sym.makeIntpair_int__int_'), (5769972, 'bl loc.imp.objc_msgSend'), (5770080, 'bl loc.imp.objc_msgSend')],
        branches=[(5751236, 'beq', 5752536), (5751624, 'beq', 5752176), (5751720, 'beq', 5752172), (5751796, 'beq', 5752108), (5752172, 'b', 5752176), (5752188, 'beq', 5752260), (5752308, 'bls', 5752440), (5752532, 'b', 5752676), (5752552, 'beq', 5752672), (5752668, 'b', 5770088), (5752672, 'b', 5752676), (5752688, 'bne', 5752864), (5752704, 'beq', 5752860), (5752720, 'beq', 5752752), (5752740, 'bne', 5752748), (5752744, 'b', 5770088), (5752748, 'b', 5752752), (5752764, 'beq', 5752836), (5752784, 'bne', 5752832), (5752804, 'bne', 5752832), (5752824, 'bne', 5752832), (5752828, 'b', 5770088), (5752832, 'b', 5752836), (5752848, 'beq', 5752856), (5752852, 'b', 5770088), (5752856, 'b', 5752860), (5752860, 'b', 5752864), (5752908, 'bne', 5754004), (5752928, 'bne', 5753020), (5752944, 'beq', 5753016), (5752984, 'beq', 5753012), (5753000, 'beq', 5753012), (5753012, 'b', 5753016), (5753016, 'b', 5753020), (5753036, 'beq', 5753084), (5753052, 'bne', 5753072), (5753068, 'bne', 5753080), (5753080, 'b', 5753136), (5753100, 'beq', 5753132), (5753116, 'beq', 5753128), (5753128, 'b', 5753132), (5753132, 'b', 5753136), (5753144, 'beq', 5753160), (5753156, 'b', 5753816), (5753284, 'bne', 5753300), (5753296, 'b', 5753812), (5753316, 'beq', 5753588), (5753444, 'beq', 5753576), (5753572, 'bne', 5753588), (5753584, 'b', 5753808), (5753604, 'beq', 5753656), (5753620, 'beq', 5753656), (5753640, 'bne', 5753656), (5753652, 'b', 5753804), (5753672, 'beq', 5753752), (5753688, 'beq', 5753752), (5753700, 'beq', 5753752), (5753712, 'beq', 5753752), (5753724, 'beq', 5753752), (5753736, 'beq', 5753752), (5753748, 'b', 5753800), (5753768, 'beq', 5753796), (5753784, 'beq', 5753796), (5753796, 'b', 5753800), (5753800, 'b', 5753804), (5753804, 'b', 5753808), (5753808, 'b', 5753812), (5753812, 'b', 5753816), (5753824, 'beq', 5754000), (5753840, 'beq', 5753996), (5753856, 'beq', 5753996), (5753996, 'b', 5770088), (5754000, 'b', 5754004), (5754020, 'bne', 5754028), (5754024, 'b', 5770088), (5754064, 'bne', 5754100), (5754080, 'beq', 5754100), (5754096, 'b', 5754112), (5754108, 'b', 5754112), (5754132, 'bge', 5755352), (5754136, 'b', 5754140), (5754148, 'bge', 5755236), (5754152, 'b', 5754156), (5754168, 'bgt', 5755196), (5754172, 'b', 5754176), (5754184, 'bgt', 5755136), (5754188, 'b', 5754192), (5754200, 'bgt', 5754812), (5754204, 'b', 5754208), (5754216, 'bgt', 5754576), (5754220, 'b', 5754224), (5754232, 'bgt', 5754272), (5754236, 'b', 5754240), (5754248, 'beq', 5764388), (5754252, 'b', 5754256), (5754264, 'beq', 5756516), (5754268, 'b', 5765652), (5754280, 'bgt', 5754560), (5754284, 'b', 5754288), (5754296, 'bgt', 5754544), (5754300, 'b', 5754304), (5754312, 'bgt', 5754480), (5754316, 'b', 5754320), (5754328, 'bgt', 5754352), (5754332, 'b', 5754336), (5754344, 'beq', 5758764), (5754348, 'b', 5765652), (5754360, 'bgt', 5754448), (5754364, 'b', 5754368), (5754376, 'bgt', 5754432), (5754380, 'b', 5754384), (5754392, 'beq', 5761684), (5754396, 'b', 5754400), (5754408, 'beq', 5760412), (5754412, 'b', 5754416), (5754424, 'beq', 5759996), (5754428, 'b', 5765652), (5754440, 'beq', 5762784), (5754444, 'b', 5765652), (5754456, 'beq', 5757844), (5754460, 'b', 5754464), (5754472, 'beq', 5758028), (5754476, 'b', 5765652), (5754496, 'bhi', 5765652), (5754552, 'beq', 5763556), (5754556, 'b', 5765652), (5754568, 'beq', 5764096), (5754572, 'b', 5765652), (5754584, 'bgt', 5754656), (5754588, 'b', 5754592), (5754608, 'bhi', 5765652), (5754664, 'bgt', 5754796), (5754668, 'b', 5754672), (5754680, 'bgt', 5754764), (5754684, 'b', 5754688), (5754704, 'bhi', 5765652), (5754772, 'beq', 5760156), (5754776, 'b', 5754780), (5754788, 'beq', 5760572), (5754792, 'b', 5765652), (5754804, 'beq', 5756704), (5754808, 'b', 5765652), (5754828, 'bhi', 5765652), (5755156, 'bhi', 5765652), (5755208, 'beq', 5764788), (5755212, 'b', 5755216), (5755224, 'beq', 5761524), (5755228, 'b', 5765652), (5755252, 'bhi', 5765652), (5755272, 'bne', 5765332), (5755296, 'bne', 5765492), (5755316, 'bne', 5764788), (5755320, 'b', 5765652), (5755368, 'bhi', 5765652), (5755740, 'b', 5765664), (5755772, 'b', 5765664), (5755796, 'b', 5765664), (5755820, 'b', 5765664), (5755844, 'b', 5765664), (5755868, 'b', 5765664), (5755892, 'b', 5765664), (5755924, 'b', 5765664), (5755964, 'b', 5765664), (5755988, 'b', 5765664), (5756012, 'b', 5765664), (5756040, 'b', 5765664), (5756068, 'b', 5765664), (5756096, 'b', 5765664), (5756124, 'b', 5765664), (5756148, 'b', 5765664), (5756172, 'b', 5765664), (5756196, 'b', 5765664), (5756220, 'b', 5765664), (5756248, 'b', 5765664), (5756272, 'b', 5765664), (5756300, 'b', 5765664), (5756324, 'b', 5765664), (5756348, 'b', 5765664), (5756376, 'b', 5765664), (5756400, 'b', 5765664), (5756424, 'b', 5765664), (5756452, 'b', 5765664), (5756476, 'b', 5765664), (5756500, 'b', 5765664), (5756564, 'bne', 5756696), (5756696, 'b', 5765664), (5756752, 'bne', 5756884), (5756884, 'b', 5765664), (5756936, 'bne', 5757068), (5757068, 'b', 5765664), (5757120, 'bne', 5757252), (5757252, 'b', 5765664), (5757324, 'bne', 5757456), (5757456, 'b', 5765664), (5757516, 'bne', 5757648), (5757648, 'b', 5765664), (5757700, 'bne', 5757832), (5757832, 'b', 5765664), (5757892, 'bne', 5758024), (5758024, 'b', 5765664), (5758076, 'bne', 5758208), (5758208, 'b', 5765664), (5758260, 'bne', 5758392), (5758392, 'b', 5765664), (5758444, 'bne', 5758576), (5758576, 'b', 5765664), (5758628, 'bne', 5758760), (5758760, 'b', 5765664), (5758812, 'bne', 5758944), (5758944, 'b', 5765664), (5758996, 'bne', 5759128), (5759128, 'b', 5765664), (5759180, 'bne', 5759312), (5759312, 'b', 5765664), (5759364, 'bne', 5759496), (5759496, 'b', 5765664), (5759548, 'bne', 5759680), (5759680, 'b', 5765664), (5759732, 'bne', 5759824), (5759824, 'b', 5765664), (5759876, 'bne', 5759992), (5759992, 'b', 5765664), (5760044, 'bne', 5760152), (5760152, 'b', 5765664), (5760204, 'bne', 5760312), (5760312, 'b', 5765664), (5760336, 'b', 5765664), (5760360, 'b', 5765664), (5760384, 'b', 5765664), (5760408, 'b', 5765664), (5760460, 'bne', 5760568), (5760568, 'b', 5765664), (5760584, 'beq', 5760628), (5760600, 'bne', 5760628), (5760616, 'b', 5760640), (5760676, 'bne', 5760784), (5760784, 'b', 5765664), (5760840, 'bne', 5760948), (5760948, 'b', 5765664), (5761004, 'bne', 5761112), (5761112, 'b', 5765664), (5761168, 'bne', 5761280), (5761280, 'b', 5765664), (5761304, 'b', 5765664), (5761328, 'b', 5765664), (5761352, 'b', 5765664), (5761376, 'b', 5765664), (5761400, 'b', 5765664), (5761444, 'beq', 5761496), (5761460, 'bne', 5761496), (5761492, 'b', 5761516), (5761516, 'b', 5765664), (5761560, 'bne', 5761668), (5761668, 'b', 5765664), (5761720, 'bne', 5762772), (5761740, 'bne', 5761752), (5761824, 'beq', 5762648), (5761852, 'bne', 5762204), (5761868, 'beq', 5762028), (5761888, 'beq', 5762028), (5761908, 'bne', 5762028), (5761932, 'bne', 5762028), (5761948, 'beq', 5762028), (5761964, 'beq', 5762028), (5761988, 'beq', 5762024), (5762000, 'beq', 5762024), (5762012, 'beq', 5762024), (5762024, 'b', 5762028), (5762040, 'bne', 5762192), (5762052, 'bne', 5762192), (5762072, 'beq', 5762192), (5762096, 'bne', 5762192), (5762112, 'beq', 5762192), (5762128, 'beq', 5762192), (5762152, 'beq', 5762188), (5762164, 'beq', 5762188), (5762176, 'beq', 5762188), (5762188, 'b', 5762192), (5762192, 'b', 5762296), (5762216, 'beq', 5762292), (5762232, 'beq', 5762268), (5762248, 'beq', 5762268), (5762264, 'bne', 5762288), (5762288, 'b', 5762292), (5762292, 'b', 5762296), (5762308, 'bne', 5762512), (5762348, 'beq', 5762508), (5762368, 'beq', 5762508), (5762388, 'bne', 5762508), (5762412, 'bne', 5762508), (5762428, 'beq', 5762508), (5762444, 'beq', 5762508), (5762468, 'beq', 5762504), (5762480, 'beq', 5762504), (5762492, 'beq', 5762504), (5762504, 'b', 5762508), (5762508, 'b', 5762512), (5762524, 'beq', 5762632), (5762536, 'beq', 5762552), (5762548, 'bne', 5762564), (5762560, 'b', 5762600), (5762572, 'beq', 5762588), (5762584, 'bne', 5762596), (5762596, 'b', 5762600), (5762624, 'b', 5762644), (5762644, 'b', 5762648), (5762772, 'b', 5765664), (5762820, 'bne', 5763516), (5762840, 'bne', 5762852), (5762900, 'beq', 5763140), (5762920, 'beq', 5763140), (5762940, 'bne', 5763140), (5762952, 'bne', 5763004), (5762968, 'beq', 5763004), (5762984, 'beq', 5763004), (5763000, 'bne', 5763140), (5763024, 'bne', 5763140), (5763040, 'beq', 5763140), (5763056, 'beq', 5763140), (5763072, 'beq', 5763140), (5763088, 'beq', 5763140), (5763104, 'beq', 5763140), (5763124, 'b', 5763404), (5763176, 'beq', 5763400), (5763196, 'beq', 5763400), (5763216, 'bne', 5763400), (5763228, 'bne', 5763280), (5763244, 'beq', 5763280), (5763260, 'beq', 5763280), (5763276, 'bne', 5763400), (5763300, 'bne', 5763400), (5763316, 'beq', 5763400), (5763332, 'beq', 5763400), (5763348, 'beq', 5763400), (5763364, 'beq', 5763400), (5763380, 'beq', 5763400), (5763400, 'b', 5763404), (5763516, 'b', 5765664), (5763540, 'b', 5765664), (5763880, 'bpl', 5763920), (5763912, 'b', 5764032), (5763956, 'beq', 5764008), (5763972, 'bne', 5764008), (5764004, 'b', 5764028), (5764028, 'b', 5764032), (5764032, 'b', 5765664), (5764060, 'b', 5765664), (5764084, 'b', 5765664), (5764132, 'bne', 5764232), (5764232, 'b', 5765664), (5764276, 'bne', 5764384), (5764384, 'b', 5765664), (5764424, 'bne', 5764496), (5764496, 'b', 5765664), (5764520, 'b', 5765664), (5764720, 'b', 5765664), (5764744, 'b', 5765664), (5764768, 'b', 5765664), (5764824, 'bne', 5764980), (5764848, 'beq', 5764976), (5764976, 'b', 5764980), (5764980, 'b', 5765664), (5765032, 'bne', 5765324), (5765044, 'bne', 5765180), (5765172, 'b', 5765320), (5765188, 'bne', 5765316), (5765316, 'b', 5765320), (5765320, 'b', 5765324), (5765324, 'b', 5765664), (5765380, 'bne', 5765488), (5765488, 'b', 5765664), (5765540, 'bne', 5765648), (5765648, 'b', 5765664), (5765652, 'b', 5770088), (5765672, 'beq', 5767368), (5765744, 'beq', 5765912), (5765760, 'beq', 5765912), (5765772, 'beq', 5765912), (5765788, 'beq', 5765912), (5765804, 'beq', 5765840), (5765820, 'beq', 5765840), (5765836, 'bne', 5765864), (5765876, 'beq', 5765896), (5765892, 'bne', 5765908), (5765908, 'b', 5765912), (5765924, 'beq', 5765956), (5765940, 'beq', 5765956), (5765980, 'beq', 5766140), (5766000, 'beq', 5766116), (5766016, 'beq', 5766052), (5766032, 'beq', 5766052), (5766048, 'bne', 5766068), (5766080, 'beq', 5766100), (5766096, 'bne', 5766112), (5766112, 'b', 5766116), (5766152, 'beq', 5766424), (5766164, 'beq', 5766424), (5766180, 'beq', 5766424), (5766220, 'beq', 5766420), (5766236, 'beq', 5766256), (5766252, 'bne', 5766272), (5766268, 'b', 5766320), (5766284, 'beq', 5766304), (5766300, 'bne', 5766316), (5766316, 'b', 5766320), (5766332, 'beq', 5766352), (5766348, 'bne', 5766368), (5766364, 'b', 5766416), (5766380, 'beq', 5766400), (5766396, 'bne', 5766412), (5766412, 'b', 5766416), (5766416, 'b', 5766420), (5766420, 'b', 5766424), (5766436, 'beq', 5767344), (5766452, 'beq', 5767344), (5766464, 'beq', 5767344), (5766480, 'beq', 5767344), (5766496, 'beq', 5767344), (5766544, 'blt', 5766568), (5766576, 'beq', 5766720), (5766616, 'bne', 5766684), (5766632, 'beq', 5766696), (5766648, 'beq', 5766696), (5766664, 'beq', 5766696), (5766680, 'beq', 5766696), (5766692, 'b', 5766720), (5766712, 'b', 5766520), (5766732, 'beq', 5767340), (5766772, 'blt', 5766796), (5766804, 'beq', 5767336), (5766844, 'bne', 5766884), (5766860, 'beq', 5766884), (5766876, 'bne', 5766884), (5766880, 'b', 5767336), (5766896, 'bne', 5766904), (5766900, 'b', 5767336), (5766920, 'bne', 5767184), (5766940, 'beq', 5767184), (5766956, 'bne', 5766976), (5766972, 'beq', 5767184), (5766988, 'beq', 5767024), (5767004, 'beq', 5767024), (5767020, 'bne', 5767184), (5767052, 'beq', 5767072), (5767068, 'bne', 5767088), (5767084, 'b', 5767136), (5767100, 'beq', 5767120), (5767116, 'bne', 5767132), (5767132, 'b', 5767136), (5767148, 'beq', 5767168), (5767164, 'bne', 5767180), (5767180, 'b', 5767316), (5767196, 'beq', 5767248), (5767212, 'beq', 5767232), (5767228, 'bne', 5767248), (5767244, 'b', 5767312), (5767260, 'beq', 5767308), (5767276, 'beq', 5767296), (5767292, 'bne', 5767308), (5767308, 'b', 5767312), (5767312, 'b', 5767336), (5767332, 'b', 5766748), (5767336, 'b', 5767340), (5767340, 'b', 5767344), (5767344, 'b', 5767372), (5767368, 'b', 5767372), (5767384, 'bne', 5767908), (5767472, 'beq', 5767492), (5767488, 'bne', 5767904), (5767532, 'beq', 5767628), (5767668, 'beq', 5767764), (5767804, 'beq', 5767900), (5767900, 'b', 5767904), (5767904, 'b', 5768264), (5767920, 'beq', 5768260), (5767936, 'beq', 5768260), (5767956, 'beq', 5768060), (5768024, 'b', 5768136), (5768148, 'beq', 5768256), (5768256, 'b', 5768260), (5768260, 'b', 5768264), (5768300, 'bne', 5768552), (5768320, 'bne', 5768360), (5768340, 'beq', 5768552), (5768356, 'ble', 5768552), (5768380, 'beq', 5768392), (5768436, 'beq', 5768548), (5768548, 'b', 5768552), (5768588, 'bne', 5768708), (5768604, 'bne', 5768708), (5768744, 'bne', 5768856), (5768764, 'beq', 5768856), (5768868, 'beq', 5769984), (5768880, 'beq', 5769984), (5768904, 'ble', 5769696), (5768940, 'bne', 5768956), (5768944, 'b', 5769696), (5768968, 'bne', 5769112), (5769012, 'bge', 5769028), (5769024, 'b', 5769036), (5769088, 'b', 5769676), (5769124, 'bne', 5769672), (5769280, 'beq', 5769376), (5769416, 'beq', 5769512), (5769552, 'beq', 5769648), (5769668, 'b', 5769696), (5769672, 'b', 5769696), (5769688, 'b', 5768896), (5769704, 'bne', 5769724), (5769720, 'beq', 5769980), (5769732, 'bne', 5769752), (5769748, 'beq', 5769980), (5769860, 'beq', 5769976), (5769976, 'b', 5769980), (5769980, 'b', 5770088), (5769992, 'beq', 5770008), (5770004, 'bne', 5770084), (5770084, 'b', 5770088)],
        semantics=('[World fillTile:atPos:withType:dataA:dataB:placedByClient:saveDict:placedByBlockhead:placedByClientName:] (imp 0x0057c11c, 4785w): **the giant fill** - objc **x68** + tileAtWorldPositionLoaded x19 + makeIntpair x11 + tileIsSolid x8 + **tileIsAirOrSnow x6** + consts **0x422 (1058!)/0x43f/0x423 (1059)/0x12e (302)/0x119 (281)/0x12f (303)/0x7d00 (32000!)/0x820 (2080)** + 0x10/0x64: the complete tile-write pipeline (type dispatch + dataA/dataB + owner + save-dict; the 1058/1059 pair and 32000/2080 constants are the placement-rule codes).\n'),
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
        'batch': 'World mutation core (E100): the fill/remove/paint/place engines, the day cycle and the sun arc; 36 bodies',
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
                        default=NATIVE / 'world_mutation.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale world_mutation.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
