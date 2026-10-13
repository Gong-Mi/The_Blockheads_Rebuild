#!/usr/bin/env python3
"""Hash-gated recovery of the World input router and touch family (E104).

The World input entry points: the 6150w tap router (census-grade), the
pinch/pan translation trio, the touch forwarders into the UI manager and
the gesture gates that delegate to the active blockhead:
17 bodies, 7282 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/WORLD_INPUT.md for the prose and boundaries.
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
    'bl 0x58353c': 0x0058353c,
    'bl 0x5ab510': 0x005ab510,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl method.Vector.Vector_float__float__float__float_': 0x004d0d08,
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl method.Vector2.operator_Vector2_': 0x004d0418,
    'bl method.Vector2.operator__Vector2_': 0x004d04b4,
    'bl method.Vector2.operator_float_': 0x004d0368,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl sym.GLKMathUnproject': 0x0020ca1c,
    'bl sym.imp.__wrap_fmodf': 0x001c3d4c,
    'bl sym.itemTypeIsColumn_ItemType_': 0x005b291c,
    'bl sym.itemTypeIsHangable_ItemType_': 0x005b23b8,
    'bl sym.itemTypeIsInteractionObject_ItemType_': 0x005b2ad4,
    'bl sym.itemTypeIsPlacableOnBackWall_ItemType_': 0x005b2ca0,
    'bl sym.itemTypeIsStairs_ItemType_': 0x005b2b0c,
    'bl sym.itemTypeIsWorkbench_ItemType_': 0x005b2aa0,
    'bl sym.linearInterpolate_float__float__float_': 0x00582a14,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.reverseLinearInterpolate_float__float__float_': 0x005ac12c,
    'bl sym.tileAtWorldPosition_int__int__MacroTile__World_': 0x00a16e68,
    'bl sym.tileIsHalfDepth_Tile__World__intpair_': 0x00a14450,
    'bl sym.tileIsPaintable_Tile__intpair__World__DynamicObject_objcproto21PathUserDynamicObject_': 0x00a118e4,
    'bl sym.tileIsSolid_Tile_': 0x00a1179c,
    'bl sym.worldIndexAtWorldPos_intpair__World_': 0x00a15838,
}

SPECS = [
    dict(
        name='wi_00',
        method='World -[tap:]',
        types='v16@0:4{CGPoint=ff}8',
        start=5948320,
        end=5972920,
        disasm='disasm_worldtileloader_wi_00.txt',
        base_add=5948356,
        base_literal=5952308,
        boundary='ARM.exidx end 0x005b23b8 (listing bound); next ObjC IMP 0x005b30c8 World -[touchIsInUI:]',
        selectors={
                 0x5ad348: (15197316, 'tap:'),
                 0x5adb2c: (15195544, 'instance'),
                 0x5adb30: (15195660, 'multiSoundNamed:'),
                 0x5adb38: (15196888, 'playAtPosition:'),
                 0x5adb54: (15195552, 'dataWithBytes:length:'),
                 0x5adb58: (15195632, 'appendBytes:length:'),
                 0x5adb5c: (15195644, 'sendDataToServer:reliable:'),
                 0x5ae050: (15197320, 'fishingRod'),
                 0x5ae054: (15196444, 'activeBlockhead'),
                 0x5ae05c: (15197324, 'stopFishing'),
                 0x5ae060: (15196268, 'regenerating'),
                 0x5ae064: (15196320, 'onTradeMission'),
                 0x5ae3a0: (15197328, 'checkForHarmableDynamicObjectUnderTap:ignoreLocalBlockheads:ignoreAllBlockheads:'),
                 0x5ae3a4: (15197332, 'checkForBoatUnderTap:'),
                 0x5ae3ac: (15197336, 'checkForTrainCarUnderTap:'),
                 0x5ae3b0: (15197340, 'isVisible'),
                 0x5ae3b4: (15197344, 'currentItem'),
                 0x5ae3b8: (15196312, 'itemType'),
                 0x5b02c8: (15196444, 'activeBlockhead'),
                 0x5b0c68: (15196312, 'itemType'),
                 0x5b0c6c: (15197348, 'canDigBackWallforTile:atPos:withItem:includeActions:'),
                 0x5b0c84: (15196416, 'workbenchAtPos:'),
                 0x5b1018: (15196944, 'type'),
                 0x5b101c: (15197356, 'setDisplayed:'),
                 0x5b1020: (15196628, 'addBlockheadUI'),
                 0x5b1028: (15197352, 'setWorkbench:blockhead:craftableItemObject:'),
                 0x5b1034: (15195544, 'instance'),
                 0x5b1038: (15195660, 'multiSoundNamed:'),
                 0x5b1040: (15196888, 'playAtPosition:'),
                 0x5b11c0: (15197304, 'currentInteractionTypeForTile:atPos:pickupRejectedDueToInventoryFull:includeActions:faceIndex:allowProtectedActions:'),
                 0x5b135c: (15197360, 'displayOwnershipAreas'),
                 0x5b1364: (15197308, 'tileIsProtectedAtPos:againstBlockhead:'),
                 0x5b1510: (15197364, 'displayTip:withTimeOut:displayEvenIfDisabled:tipColor:'),
                 0x5b15b8: (15197368, 'rideObject'),
                 0x5b15bc: (15197372, 'stopRiding'),
                 0x5b15c0: (15196300, 'uniqueID'),
                 0x5b15c8: (15197376, 'hasCancelableActionAtGoalPos:orWithInteractionObjectID:goalInteraction:craftCountOrExtraData:'),
                 0x5b1744: (15197300, 'cancelAnyActionAtGoalPos:orWithInteractionObjectID:goalInteraction:craftCountOrExtraData:'),
                 0x5b17b0: (15197380, 'goalInteractionForNPCChaseForNPC:withItemType:'),
                 0x5b17b4: (15197344, 'currentItem'),
                 0x5b1874: (15196576, 'displayed'),
                 0x5b1878: (15197384, 'wearUI'),
                 0x5b1994: (15197388, 'displayDismountUI'),
                 0x5b19f0: (15197392, 'isInJetPackFreeFlightMode'),
                 0x5b1a44: (15197396, 'canBeFedByBlockhead:'),
                 0x5b1a48: (15197400, 'cantBeFedTipStringForBlockhead:'),
                 0x5b1bc8: (15197404, 'canBeCapturedByBlockhead:withItemType:'),
                 0x5b1bcc: (15195596, 'isKindOfClass:'),
                 0x5b1bd0: (15195592, 'class'),
                 0x5b1dd0: (15197408, 'captureRequiredItemType'),
                 0x5b1dd4: (15197412, 'cantBeCapturedTipStringForBlockhead:withItemType:'),
                 0x5b1de4: (15197416, 'canBeMilkedByBlockhead:'),
                 0x5b20fc: (15197420, 'canBeShavedByBlockhead:'),
                 0x5b2100: (15197424, 'cantBeMilkedTipStringForBlockhead:'),
                 0x5b2104: (15197428, 'cantBeShavedTipStringForBlockhead:'),
                 0x5b22e8: (15197432, 'inspectNPCTapped:'),
                 0x5b22f4: (15196444, 'activeBlockhead'),
                 0x5b22fc: (15196416, 'workbenchAtPos:'),
                 0x5b2304: (15195544, 'instance'),
                 0x5b2308: (15195660, 'multiSoundNamed:'),
                 0x5b2310: (15196888, 'playAtPosition:'),
                 0x5b2314: (15197356, 'setDisplayed:'),
                 0x5b231c: (15197368, 'rideObject'),
                 0x5b2320: (15197392, 'isInJetPackFreeFlightMode'),
                 0x5b2324: (15197440, 'waitingForFillRequestAtPos:'),
                 0x5b233c: (15196436, 'paintingAtPos:'),
                 0x5b2340: (15196440, 'paintingTapped:'),
                 0x5b2344: (15197312, 'queueActionWithGoalPos:goalInteraction:pathType:interactionObjectID:craftableItemObject:craftCountOrExtraData:isAI:'),
                 0x5b2358: (15197448, 'displayInventoryFullPopUpForPos:'),
                 0x5b2360: (15196428, 'interactionObjectAtPos:'),
                 0x5b2364: (15196300, 'uniqueID'),
                 0x5b236c: (15197376, 'hasCancelableActionAtGoalPos:orWithInteractionObjectID:goalInteraction:craftCountOrExtraData:'),
                 0x5b2370: (15196432, 'interactionObjectTapped:hasCancel:'),
                 0x5b2378: (15197300, 'cancelAnyActionAtGoalPos:orWithInteractionObjectID:goalInteraction:craftCountOrExtraData:'),
                 0x5b2380: (15197444, 'workbenchTapped:hasCancel:'),
                 0x5b2388: (15196576, 'displayed'),
                 0x5b238c: (15197452, 'craftProgressUI'),
                 0x5b2390: (15197456, 'isCraftingAtAnyWorkbench'),
                 0x5b2398: (15197436, 'ridableObjectTapped:hasCancel:'),
                 0x5b23a0: (15197372, 'stopRiding'),
                 0x5b23a4: (15197384, 'wearUI'),
                 0x5b23a8: (15197388, 'displayDismountUI'),
        },
        imports={
                 0x5adb34: (16232392, '__CFConstantStringClassReference'),
                 0x5adb60: (16230696, '__CFConstantStringClassReference'),
                 0x5ae044: (16232408, '__CFConstantStringClassReference'),
                 0x5ae04c: (17151904, 'objc_msgSend'),
                 0x5aff4c: (17151904, 'objc_msgSend'),
                 0x5b103c: (16232408, '__CFConstantStringClassReference'),
                 0x5b11bc: (16232392, '__CFConstantStringClassReference'),
                 0x5b13c8: (16232424, '__CFConstantStringClassReference'),
                 0x5b13cc: (16232440, '__CFConstantStringClassReference'),
                 0x5b1de0: (17151904, 'objc_msgSend'),
                 0x5b22f0: (17151904, 'objc_msgSend'),
                 0x5b230c: (16232392, '__CFConstantStringClassReference'),
                 0x5b2318: (16232408, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5ad338: (17156668, 'OBJC_IVAR_$_World.unableToCraftBlockheadDueToWaitingForServer', 3064),
                 0x5ad33c: (17156492, 'OBJC_IVAR_$_World.pauseIdleTimer', 3264),
                 0x5ad340: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x5ad354: (17156600, 'OBJC_IVAR_$_World.tapModelviewMatrix', 320),
                 0x5ad358: (17156604, 'OBJC_IVAR_$_World.tapProjectionMatrix', 256),
                 0x5ad35c: (17156140, 'OBJC_IVAR_$_World.tapViewport', 384),
                 0x5adb1c: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
                 0x5adb3c: (17156648, 'OBJC_IVAR_$_World.repairMode', 3413),
                 0x5adb40: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5adb44: (17156652, 'OBJC_IVAR_$_World.renderRepairModeConfirm', 3414),
                 0x5adb48: (17156656, 'OBJC_IVAR_$_World.repairModeConfirmPos', 3416),
                 0x5ae048: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x5ae058: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5ae06c: (17156340, 'OBJC_IVAR_$_World.macroTiles', 412),
                 0x5ae39c: (17155936, 'OBJC_IVAR_$_World.pvpEnabled', 3268),
                 0x5aff50: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
                 0x5b0230: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
                 0x5b0234: (17156340, 'OBJC_IVAR_$_World.macroTiles', 412),
                 0x5b02c4: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5b1024: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x5b13c4: (17156060, 'OBJC_IVAR_$_World.customRules', 160),
                 0x5b22ec: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x5b22f8: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5b232c: (17156324, 'OBJC_IVAR_$_World.isMod', 3210),
                 0x5b2330: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x5b2334: (17155972, 'OBJC_IVAR_$_World.client', 960),
        },
        classes={
                 0x5adb24: (15245280, 'OBJC_CLASS_$_MJSoundManager'),
                 0x5adb4c: (15245284, 'OBJC_CLASS_$_NSMutableData'),
                 0x5b102c: (15245280, 'OBJC_CLASS_$_MJSoundManager'),
                 0x5b1508: (15245420, 'OBJC_CLASS_$_TipManager'),
                 0x5b1bd4: (15245480, 'OBJC_CLASS_$_NPC'),
                 0x5b2300: (15245280, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(5948320, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5972916, 'adceq lr, sl, r4, ror 12')],
        calls=[(5948524, 'bl loc.imp.objc_msgSend'), (5948628, 'bl 0x58353c'), (5949484, 'bl sym.GLKMathUnproject'), (5949576, 'bl 0x58353c'), (5950432, 'bl sym.GLKMathUnproject'), (5950492, 'bl sym.reverseLinearInterpolate_float__float__float_'), (5950532, 'bl sym.linearInterpolate_float__float__float_'), (5950572, 'bl sym.linearInterpolate_float__float__float_'), (5950784, 'bl loc.imp.objc_msgSend'), (5950808, 'bl loc.imp.objc_msgSend'), (5950852, 'bl method.Vector2.Vector2_float__float_'), (5950880, 'bl loc.imp.objc_msgSend'), (5951092, 'bl sym.makeIntpair_int__int_'), (5951108, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (5951188, 'bl loc.imp.objc_msgSend'), (5951220, 'bl loc.imp.objc_msgSend'), (5951268, 'bl loc.imp.objc_msgSend'), (5951292, 'bl loc.imp.objc_msgSend'), (5951316, 'bl loc.imp.objc_msgSend'), (5951360, 'bl method.Vector2.Vector2_float__float_'), (5951388, 'bl loc.imp.objc_msgSend'), (5951432, 'bl loc.imp.objc_msgSend'), (5951456, 'bl loc.imp.objc_msgSend'), (5951504, 'bl method.Vector2.Vector2_float__float_'), (5951532, 'bl loc.imp.objc_msgSend'), (5951664, 'bl sym.makeIntpair_int__int_'), (5951716, 'bl loc.imp.objc_msgSend'), (5951740, 'bl loc.imp.objc_msgSend'), (5951788, 'bl method.Vector2.Vector2_float__float_'), (5951816, 'bl loc.imp.objc_msgSend'), (5951968, 'blx lr'), (5951992, 'blx r2'), (5952048, 'blx r2'), (5952096, 'blx r2'), (5952152, 'blx r2'), (5952200, 'bl loc.imp.objc_msgSend'), (5952224, 'bl loc.imp.objc_msgSend'), (5952272, 'bl method.Vector2.Vector2_float__float_'), (5952300, 'bl loc.imp.objc_msgSend'), (5952408, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (5952464, 'bl sym.tileIsSolid_Tile_'), (5952504, 'bl sym.reverseLinearInterpolate_float__float__float_'), (5952532, 'bl sym.linearInterpolate_float__float__float_'), (5952552, 'bl sym.linearInterpolate_float__float__float_'), (5952628, 'bl method.Vector2.Vector2_float__float_'), (5952716, 'bl loc.imp.objc_msgSend'), (5952764, 'bl method.Vector2.Vector2_float__float_'), (5952792, 'bl loc.imp.objc_msgSend'), (5952884, 'bl method.Vector2.Vector2_float__float_'), (5952912, 'bl loc.imp.objc_msgSend'), (5952960, 'blx r2'), (5953084, 'blx lr'), (5953100, 'blx r2'), (5953164, 'blx r2'), (5953168, 'bl sym.itemTypeIsHangable_ItemType_'), (5953224, 'blx r2'), (5953228, 'bl sym.itemTypeIsColumn_ItemType_'), (5953284, 'blx r2'), (5953436, 'blx r2'), (5953580, 'blx r2'), (5953632, 'blx r2'), (5953748, 'bl sym.reverseLinearInterpolate_float__float__float_'), (5953788, 'bl sym.linearInterpolate_float__float__float_'), (5953880, 'bl sym.linearInterpolate_float__float__float_'), (5954000, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (5954012, 'bl sym.tileIsSolid_Tile_'), (5954052, 'bl sym.makeIntpair_int__int_'), (5954104, 'bl loc.imp.objc_msgSend'), (5954132, 'bl sym.tileIsPaintable_Tile__intpair__World__DynamicObject_objcproto21PathUserDynamicObject_'), (5954224, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (5954236, 'bl sym.tileIsSolid_Tile_'), (5954500, 'bl sym.reverseLinearInterpolate_float__float__float_'), (5954540, 'bl sym.linearInterpolate_float__float__float_'), (5954632, 'bl sym.linearInterpolate_float__float__float_'), (5954752, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (5954764, 'bl sym.tileIsSolid_Tile_'), (5954808, 'bl sym.makeIntpair_int__int_'), (5954860, 'bl loc.imp.objc_msgSend'), (5954888, 'bl sym.tileIsPaintable_Tile__intpair__World__DynamicObject_objcproto21PathUserDynamicObject_'), (5954980, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (5954992, 'bl sym.tileIsSolid_Tile_'), (5955184, 'bl sym.reverseLinearInterpolate_float__float__float_'), (5955224, 'bl sym.linearInterpolate_float__float__float_'), (5955316, 'bl sym.linearInterpolate_float__float__float_'), (5955436, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (5955448, 'bl sym.tileIsSolid_Tile_'), (5955488, 'bl sym.makeIntpair_int__int_'), (5955540, 'bl loc.imp.objc_msgSend'), (5955568, 'bl sym.tileIsPaintable_Tile__intpair__World__DynamicObject_objcproto21PathUserDynamicObject_'), (5955788, 'bl sym.reverseLinearInterpolate_float__float__float_'), (5955828, 'bl sym.linearInterpolate_float__float__float_'), (5955920, 'bl sym.linearInterpolate_float__float__float_'), (5956040, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (5956052, 'bl sym.tileIsSolid_Tile_'), (5956092, 'bl sym.makeIntpair_int__int_'), (5956144, 'bl loc.imp.objc_msgSend'), (5956172, 'bl sym.tileIsPaintable_Tile__intpair__World__DynamicObject_objcproto21PathUserDynamicObject_'), (5956320, 'bl sym.reverseLinearInterpolate_float__float__float_'), (5956360, 'bl sym.linearInterpolate_float__float__float_'), (5956400, 'bl sym.linearInterpolate_float__float__float_'), (5956676, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (5956704, 'bl sym.tileIsSolid_Tile_'), (5956776, 'blx r2'), (5956828, 'blx r2'), (5956912, 'bl sym.reverseLinearInterpolate_float__float__float_'), (5956952, 'bl sym.linearInterpolate_float__float__float_'), (5957056, 'bl sym.linearInterpolate_float__float__float_'), (5957176, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (5957188, 'bl sym.tileIsSolid_Tile_'), (5957232, 'bl sym.makeIntpair_int__int_'), (5957284, 'bl loc.imp.objc_msgSend'), (5957312, 'bl sym.tileIsPaintable_Tile__intpair__World__DynamicObject_objcproto21PathUserDynamicObject_'), (5957404, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (5957416, 'bl sym.tileIsSolid_Tile_'), (5957592, 'bl sym.reverseLinearInterpolate_float__float__float_'), (5957632, 'bl sym.linearInterpolate_float__float__float_'), (5957736, 'bl sym.linearInterpolate_float__float__float_'), (5957856, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (5957868, 'bl sym.tileIsSolid_Tile_'), (5957908, 'bl sym.makeIntpair_int__int_'), (5957960, 'bl loc.imp.objc_msgSend'), (5957988, 'bl sym.tileIsPaintable_Tile__intpair__World__DynamicObject_objcproto21PathUserDynamicObject_'), (5958080, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (5958092, 'bl sym.tileIsSolid_Tile_'), (5958280, 'bl sym.reverseLinearInterpolate_float__float__float_'), (5958320, 'bl sym.linearInterpolate_float__float__float_'), (5958424, 'bl sym.linearInterpolate_float__float__float_'), (5958544, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (5958556, 'bl sym.tileIsSolid_Tile_'), (5958600, 'bl sym.makeIntpair_int__int_'), (5958652, 'bl loc.imp.objc_msgSend'), (5958680, 'bl sym.tileIsPaintable_Tile__intpair__World__DynamicObject_objcproto21PathUserDynamicObject_'), (5958844, 'bl sym.reverseLinearInterpolate_float__float__float_'), (5958884, 'bl sym.linearInterpolate_float__float__float_'), (5958988, 'bl sym.linearInterpolate_float__float__float_'), (5959108, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (5959120, 'bl sym.tileIsSolid_Tile_'), (5959164, 'bl sym.makeIntpair_int__int_'), (5959216, 'bl loc.imp.objc_msgSend'), (5959244, 'bl sym.tileIsPaintable_Tile__intpair__World__DynamicObject_objcproto21PathUserDynamicObject_'), (5959376, 'bl sym.makeIntpair_int__int_'), (5959396, 'bl sym.tileIsHalfDepth_Tile__World__intpair_'), (5959564, 'blx r2'), (5959568, 'bl sym.itemTypeIsWorkbench_ItemType_'), (5959624, 'blx r2'), (5959628, 'bl sym.itemTypeIsInteractionObject_ItemType_'), (5959684, 'blx r2'), (5959748, 'blx r3'), (5959804, 'blx r2'), (5959856, 'blx r2'), (5959860, 'bl sym.itemTypeIsStairs_ItemType_'), (5959916, 'blx r2'), (5960068, 'bl sym.reverseLinearInterpolate_float__float__float_'), (5960108, 'bl sym.linearInterpolate_float__float__float_'), (5960148, 'bl sym.linearInterpolate_float__float__float_'), (5960372, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (5960400, 'bl sym.tileIsSolid_Tile_'), (5960536, 'blx r2'), (5960588, 'blx r2'), (5960672, 'bl sym.reverseLinearInterpolate_float__float__float_'), (5960712, 'bl sym.linearInterpolate_float__float__float_'), (5960800, 'bl sym.linearInterpolate_float__float__float_'), (5960896, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (5960928, 'bl sym.makeIntpair_int__int_'), (5960976, 'bl loc.imp.objc_msgSend'), (5961004, 'bl sym.tileIsPaintable_Tile__intpair__World__DynamicObject_objcproto21PathUserDynamicObject_'), (5961096, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (5961108, 'bl sym.tileIsSolid_Tile_'), (5961340, 'bl sym.reverseLinearInterpolate_float__float__float_'), (5961380, 'bl sym.linearInterpolate_float__float__float_'), (5961468, 'bl sym.linearInterpolate_float__float__float_'), (5961564, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (5961592, 'bl sym.makeIntpair_int__int_'), (5961640, 'bl loc.imp.objc_msgSend'), (5961668, 'bl sym.tileIsPaintable_Tile__intpair__World__DynamicObject_objcproto21PathUserDynamicObject_'), (5961760, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (5961772, 'bl sym.tileIsSolid_Tile_'), (5961992, 'bl sym.reverseLinearInterpolate_float__float__float_'), (5962032, 'bl sym.linearInterpolate_float__float__float_'), (5962120, 'bl sym.linearInterpolate_float__float__float_'), (5962216, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (5962248, 'bl sym.makeIntpair_int__int_'), (5962296, 'bl loc.imp.objc_msgSend'), (5962324, 'bl sym.tileIsPaintable_Tile__intpair__World__DynamicObject_objcproto21PathUserDynamicObject_'), (5962468, 'bl sym.reverseLinearInterpolate_float__float__float_'), (5962508, 'bl sym.linearInterpolate_float__float__float_'), (5962596, 'bl sym.linearInterpolate_float__float__float_'), (5962692, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (5962724, 'bl sym.makeIntpair_int__int_'), (5962772, 'bl loc.imp.objc_msgSend'), (5962800, 'bl sym.tileIsPaintable_Tile__intpair__World__DynamicObject_objcproto21PathUserDynamicObject_'), (5962936, 'bl sym.makeIntpair_int__int_'), (5962956, 'bl sym.tileIsHalfDepth_Tile__World__intpair_'), (5963168, 'blx r2'), (5963172, 'bl sym.itemTypeIsPlacableOnBackWall_ItemType_'), (5963228, 'blx r2'), (5963280, 'blx r2'), (5963332, 'bl sym.makeIntpair_int__int_'), (5963392, 'bl loc.imp.objc_msgSend'), (5963764, 'bl sym.makeIntpair_int__int_'), (5963792, 'bl loc.imp.objc_msgSend'), (5963856, 'blx r2'), (5964000, 'bl loc.imp.objc_msgSend'), (5964024, 'bl loc.imp.objc_msgSend'), (5964068, 'bl method.Vector2.Vector2_float__float_'), (5964096, 'bl loc.imp.objc_msgSend'), (5964132, 'bl loc.imp.objc_msgSend'), (5964196, 'bl sym.makeIntpair_int__int_'), (5964224, 'bl loc.imp.objc_msgSend'), (5964268, 'blx lr'), (5964304, 'blx r3'), (5964328, 'blx r3'), (5964376, 'bl loc.imp.objc_msgSend'), (5964400, 'bl loc.imp.objc_msgSend'), (5964444, 'bl method.Vector2.Vector2_float__float_'), (5964472, 'bl loc.imp.objc_msgSend'), (5964552, 'bl sym.makeIntpair_int__int_'), (5964628, 'bl loc.imp.objc_msgSend'), (5964640, 'bl 0x5ab510'), (5964680, 'bl loc.imp.objc_msgSend'), (5964708, 'bl sym.makeIntpair_int__int_'), (5964748, 'bl loc.imp.objc_msgSend'), (5964812, 'bl sym.makeIntpair_int__int_'), (5964892, 'bl loc.imp.objc_msgSend'), (5965108, 'bl loc.imp.objc_msgSend'), (5965160, 'bl method.Vector.Vector_float__float__float__float_'), (5965236, 'bl loc.imp.objc_msgSend'), (5965392, 'blx r2'), (5965448, 'blx r2'), (5965484, 'bl sym.makeIntpair_int__int_'), (5965512, 'bl loc.imp.objc_msgSend'), (5965580, 'bl loc.imp.objc_msgSend'), (5965632, 'bl sym.makeIntpair_int__int_'), (5965660, 'bl loc.imp.objc_msgSend'), (5965728, 'bl loc.imp.objc_msgSend'), (5965864, 'blx r6'), (5965880, 'blx r2'), (5965928, 'blx ip'), (5965964, 'blx ip'), (5966036, 'blx r3'), (5966132, 'blx ip'), (5966148, 'blx r2'), (5966256, 'blx lr'), (5966280, 'blx r3'), (5966348, 'blx r2'), (5966396, 'blx r2'), (5966452, 'blx r2'), (5966532, 'blx r3'), (5966604, 'blx r3'), (5966688, 'bl loc.imp.objc_msgSend'), (5966736, 'bl method.Vector.Vector_float__float__float__float_'), (5966812, 'bl loc.imp.objc_msgSend'), (5966848, 'bl loc.imp.objc_msgSend'), (5966872, 'bl loc.imp.objc_msgSend'), (5966916, 'bl method.Vector2.Vector2_float__float_'), (5966944, 'bl loc.imp.objc_msgSend'), (5967072, 'blx ip'), (5967108, 'blx ip'), (5967200, 'blx ip'), (5967232, 'blx r3'), (5967312, 'blx r2'), (5967376, 'blx r3'), (5967408, 'blx r3'), (5967512, 'blx lr'), (5967548, 'blx ip'), (5967632, 'bl loc.imp.objc_msgSend'), (5967680, 'bl method.Vector.Vector_float__float__float__float_'), (5967756, 'bl loc.imp.objc_msgSend'), (5967792, 'bl loc.imp.objc_msgSend'), (5967816, 'bl loc.imp.objc_msgSend'), (5967860, 'bl method.Vector2.Vector2_float__float_'), (5967888, 'bl loc.imp.objc_msgSend'), (5967992, 'blx r2'), (5968052, 'blx r3'), (5968120, 'blx r3'), (5968184, 'blx r3'), (5968240, 'blx r2'), (5968300, 'blx r3'), (5968376, 'blx r3'), (5968468, 'bl loc.imp.objc_msgSend'), (5968516, 'bl method.Vector.Vector_float__float__float__float_'), (5968592, 'bl loc.imp.objc_msgSend'), (5968628, 'bl loc.imp.objc_msgSend'), (5968652, 'bl loc.imp.objc_msgSend'), (5968696, 'bl method.Vector2.Vector2_float__float_'), (5968724, 'bl loc.imp.objc_msgSend'), (5968824, 'blx r3'), (5968876, 'bl sym.makeIntpair_int__int_'), (5968920, 'bl loc.imp.objc_msgSend'), (5969008, 'bl loc.imp.objc_msgSend'), (5969056, 'bl loc.imp.objc_msgSend'), (5969080, 'bl loc.imp.objc_msgSend'), (5969124, 'bl method.Vector2.Vector2_float__float_'), (5969152, 'bl loc.imp.objc_msgSend'), (5969204, 'bl loc.imp.objc_msgSend'), (5969228, 'bl loc.imp.objc_msgSend'), (5969276, 'bl method.Vector2.Vector2_float__float_'), (5969304, 'bl loc.imp.objc_msgSend'), (5969408, 'blx r3'), (5969504, 'blx ip'), (5969520, 'blx r2'), (5969628, 'blx lr'), (5969652, 'blx r3'), (5969720, 'blx r2'), (5969776, 'blx r2'), (5969832, 'blx r2'), (5969916, 'blx r2'), (5970012, 'blx ip'), (5970028, 'blx r2'), (5970072, 'bl sym.makeIntpair_int__int_'), (5970100, 'bl loc.imp.objc_msgSend'), (5970168, 'bl loc.imp.objc_msgSend'), (5970216, 'bl sym.makeIntpair_int__int_'), (5970244, 'bl loc.imp.objc_msgSend'), (5970312, 'bl loc.imp.objc_msgSend'), (5970404, 'blx ip'), (5970448, 'bl sym.makeIntpair_int__int_'), (5970480, 'bl loc.imp.objc_msgSend'), (5970604, 'bl sym.makeIntpair_int__int_'), (5970632, 'bl loc.imp.objc_msgSend'), (5970728, 'bl sym.makeIntpair_int__int_'), (5970756, 'bl loc.imp.objc_msgSend'), (5970824, 'bl loc.imp.objc_msgSend'), (5970876, 'blx lr'), (5970988, 'bl sym.makeIntpair_int__int_'), (5971016, 'bl loc.imp.objc_msgSend'), (5971068, 'bl sym.makeIntpair_int__int_'), (5971096, 'bl loc.imp.objc_msgSend'), (5971164, 'bl loc.imp.objc_msgSend'), (5971212, 'bl sym.makeIntpair_int__int_'), (5971240, 'bl loc.imp.objc_msgSend'), (5971308, 'bl loc.imp.objc_msgSend'), (5971396, 'blx ip'), (5971680, 'bl sym.makeIntpair_int__int_'), (5971708, 'bl loc.imp.objc_msgSend'), (5971800, 'blx r3'), (5971856, 'bl sym.makeIntpair_int__int_'), (5971960, 'bl loc.imp.objc_msgSend'), (5972008, 'bl loc.imp.objc_msgSend'), (5972032, 'bl loc.imp.objc_msgSend'), (5972076, 'bl method.Vector2.Vector2_float__float_'), (5972104, 'bl loc.imp.objc_msgSend'), (5972184, 'bl sym.makeIntpair_int__int_'), (5972212, 'bl loc.imp.objc_msgSend'), (5972272, 'bl loc.imp.objc_msgSend'), (5972296, 'bl loc.imp.objc_msgSend'), (5972340, 'bl method.Vector2.Vector2_float__float_'), (5972368, 'bl loc.imp.objc_msgSend'), (5972464, 'blx ip'), (5972480, 'blx r2'), (5972536, 'blx r2'), (5972656, 'blx lr'), (5972680, 'blx r3')],
        branches=[(5948452, 'beq', 5948464), (5948456, 'b', 5972704), (5948544, 'bne', 5972704), (5949496, 'bne', 5949504), (5949500, 'b', 5972704), (5950444, 'bne', 5950452), (5950448, 'b', 5972704), (5950600, 'bpl', 5950676), (5950672, 'b', 5950692), (5950748, 'ble', 5950888), (5950884, 'b', 5972704), (5950920, 'beq', 5951876), (5950960, 'beq', 5951824), (5950996, 'beq', 5951572), (5951036, 'bne', 5951400), (5951076, 'bne', 5951400), (5951392, 'b', 5951536), (5951568, 'b', 5951820), (5951820, 'b', 5951872), (5951860, 'beq', 5951868), (5951864, 'b', 5951868), (5951868, 'b', 5951872), (5951872, 'b', 5972704), (5952004, 'beq', 5952056), (5952052, 'b', 5972704), (5952108, 'bne', 5952168), (5952164, 'beq', 5952356), (5952304, 'b', 5972704), (5952440, 'beq', 5963488), (5952456, 'ble', 5963484), (5952476, 'bne', 5963484), (5952812, 'bne', 5952920), (5952972, 'bne', 5952984), (5953120, 'beq', 5953356), (5953180, 'bne', 5953244), (5953240, 'beq', 5953356), (5953292, 'beq', 5953356), (5953308, 'bne', 5953352), (5953324, 'bne', 5953352), (5953340, 'bne', 5953352), (5953352, 'b', 5953356), (5953376, 'bne', 5953508), (5953392, 'beq', 5953448), (5953444, 'beq', 5953464), (5953460, 'bne', 5953508), (5953476, 'bne', 5953504), (5953492, 'bne', 5953504), (5953504, 'b', 5953508), (5953520, 'bne', 5956248), (5953536, 'beq', 5953644), (5953588, 'beq', 5953660), (5953640, 'beq', 5953660), (5953656, 'beq', 5956248), (5953672, 'bne', 5955096), (5953708, 'bpl', 5954424), (5953816, 'bpl', 5954328), (5953848, 'ble', 5954328), (5954024, 'beq', 5954324), (5954144, 'beq', 5954324), (5954168, 'beq', 5954264), (5954248, 'beq', 5954260), (5954260, 'b', 5954264), (5954276, 'bne', 5954320), (5954320, 'b', 5954324), (5954324, 'b', 5954328), (5954328, 'b', 5955092), (5954456, 'ble', 5955088), (5954568, 'bpl', 5955084), (5954600, 'ble', 5955084), (5954776, 'beq', 5955080), (5954900, 'beq', 5955080), (5954924, 'beq', 5955020), (5955004, 'beq', 5955016), (5955016, 'b', 5955020), (5955032, 'bne', 5955076), (5955076, 'b', 5955080), (5955080, 'b', 5955084), (5955084, 'b', 5955088), (5955088, 'b', 5955092), (5955092, 'b', 5955096), (5955108, 'bne', 5956244), (5955144, 'bpl', 5955696), (5955252, 'bpl', 5955644), (5955284, 'ble', 5955644), (5955460, 'beq', 5955640), (5955580, 'beq', 5955640), (5955596, 'bne', 5955624), (5955640, 'b', 5955644), (5955644, 'b', 5956240), (5955708, 'bne', 5956236), (5955744, 'ble', 5956236), (5955856, 'bpl', 5956232), (5955888, 'ble', 5956232), (5956064, 'beq', 5956228), (5956184, 'beq', 5956228), (5956228, 'b', 5956232), (5956232, 'b', 5956236), (5956236, 'b', 5956240), (5956240, 'b', 5956244), (5956244, 'b', 5956248), (5956260, 'bne', 5959996), (5956276, 'bne', 5959996), (5956428, 'bpl', 5956560), (5956500, 'b', 5956576), (5956696, 'beq', 5959992), (5956716, 'bne', 5959992), (5956732, 'beq', 5959320), (5956784, 'beq', 5956840), (5956836, 'bne', 5959320), (5956872, 'bpl', 5957516), (5956992, 'bpl', 5957508), (5957024, 'ble', 5957508), (5957200, 'beq', 5957504), (5957324, 'beq', 5957504), (5957348, 'beq', 5957444), (5957428, 'beq', 5957440), (5957440, 'b', 5957444), (5957456, 'bne', 5957500), (5957500, 'b', 5957504), (5957504, 'b', 5957508), (5957508, 'b', 5958192), (5957548, 'ble', 5958188), (5957672, 'bpl', 5958184), (5957704, 'ble', 5958184), (5957880, 'beq', 5958180), (5958000, 'beq', 5958180), (5958024, 'beq', 5958120), (5958104, 'beq', 5958116), (5958116, 'b', 5958120), (5958132, 'bne', 5958176), (5958176, 'b', 5958180), (5958180, 'b', 5958184), (5958184, 'b', 5958188), (5958188, 'b', 5958192), (5958204, 'bne', 5959316), (5958240, 'bpl', 5958768), (5958360, 'bpl', 5958740), (5958392, 'ble', 5958740), (5958568, 'beq', 5958736), (5958692, 'beq', 5958736), (5958736, 'b', 5958740), (5958740, 'b', 5959312), (5958800, 'ble', 5959308), (5958924, 'bpl', 5959304), (5958956, 'ble', 5959304), (5959132, 'beq', 5959300), (5959256, 'beq', 5959300), (5959300, 'b', 5959304), (5959304, 'b', 5959308), (5959308, 'b', 5959312), (5959312, 'b', 5959316), (5959316, 'b', 5959320), (5959332, 'bne', 5959988), (5959408, 'bne', 5959444), (5959424, 'bne', 5959444), (5959440, 'beq', 5959508), (5959496, 'b', 5959984), (5959520, 'beq', 5959980), (5959580, 'bne', 5959928), (5959640, 'bne', 5959928), (5959692, 'beq', 5959928), (5959760, 'beq', 5959928), (5959812, 'beq', 5959928), (5959872, 'bne', 5959928), (5959924, 'bne', 5959980), (5959980, 'b', 5959984), (5959984, 'b', 5959988), (5959988, 'b', 5959992), (5959992, 'b', 5959996), (5960008, 'bne', 5963480), (5960024, 'bne', 5963480), (5960176, 'bpl', 5960256), (5960248, 'b', 5960272), (5960392, 'beq', 5963476), (5960412, 'bne', 5963476), (5960428, 'beq', 5962880), (5960444, 'beq', 5960480), (5960460, 'beq', 5960480), (5960476, 'bne', 5962880), (5960492, 'beq', 5962876), (5960544, 'beq', 5960600), (5960596, 'bne', 5962876), (5960632, 'bpl', 5961264), (5960752, 'bpl', 5961232), (5960784, 'ble', 5961232), (5961016, 'beq', 5961228), (5961040, 'beq', 5961168), (5961120, 'bne', 5961156), (5961136, 'beq', 5961164), (5961152, 'beq', 5961164), (5961164, 'b', 5961168), (5961180, 'bne', 5961224), (5961224, 'b', 5961228), (5961228, 'b', 5961232), (5961232, 'b', 5961904), (5961296, 'ble', 5961900), (5961420, 'bpl', 5961896), (5961452, 'ble', 5961896), (5961680, 'beq', 5961892), (5961704, 'beq', 5961832), (5961784, 'bne', 5961820), (5961800, 'beq', 5961828), (5961816, 'beq', 5961828), (5961828, 'b', 5961832), (5961844, 'bne', 5961888), (5961888, 'b', 5961892), (5961892, 'b', 5961896), (5961896, 'b', 5961900), (5961900, 'b', 5961904), (5961916, 'bne', 5962872), (5961952, 'bpl', 5962392), (5962072, 'bpl', 5962384), (5962104, 'ble', 5962384), (5962336, 'beq', 5962380), (5962380, 'b', 5962384), (5962384, 'b', 5962868), (5962424, 'ble', 5962864), (5962548, 'bpl', 5962860), (5962580, 'ble', 5962860), (5962812, 'beq', 5962856), (5962856, 'b', 5962860), (5962860, 'b', 5962864), (5962864, 'b', 5962868), (5962868, 'b', 5962872), (5962872, 'b', 5962876), (5962876, 'b', 5962880), (5962892, 'bne', 5963472), (5962968, 'bne', 5963004), (5962984, 'bne', 5963004), (5963000, 'beq', 5963008), (5963004, 'b', 5963468), (5963020, 'beq', 5963096), (5963076, 'b', 5963464), (5963108, 'beq', 5963460), (5963124, 'beq', 5963460), (5963184, 'bne', 5963408), (5963236, 'beq', 5963408), (5963288, 'beq', 5963408), (5963404, 'beq', 5963460), (5963460, 'b', 5963464), (5963464, 'b', 5963468), (5963468, 'b', 5963472), (5963472, 'b', 5963476), (5963476, 'b', 5963480), (5963480, 'b', 5963484), (5963484, 'b', 5963488), (5963536, 'blt', 5963608), (5963592, 'b', 5963676), (5963616, 'bge', 5963672), (5963672, 'b', 5963676), (5963688, 'bne', 5964492), (5963812, 'beq', 5964344), (5963864, 'bne', 5964344), (5964332, 'b', 5964476), (5964476, 'b', 5972700), (5964504, 'beq', 5972696), (5964652, 'beq', 5965248), (5964768, 'beq', 5965244), (5964908, 'bne', 5965240), (5964956, 'beq', 5965048), (5964992, 'beq', 5965032), (5965028, 'bne', 5965048), (5965240, 'b', 5965244), (5965244, 'b', 5965248), (5965268, 'beq', 5965312), (5965284, 'beq', 5965304), (5965300, 'bne', 5965312), (5965324, 'beq', 5969356), (5965340, 'beq', 5969356), (5965404, 'bne', 5965460), (5965452, 'b', 5969332), (5965600, 'beq', 5965744), (5965736, 'b', 5969328), (5965980, 'beq', 5966472), (5966048, 'beq', 5966356), (5966160, 'beq', 5966288), (5966284, 'b', 5966352), (5966352, 'b', 5972704), (5966408, 'beq', 5966464), (5966456, 'b', 5972704), (5966464, 'b', 5966468), (5966468, 'b', 5966472), (5966480, 'bne', 5966984), (5966544, 'bne', 5966984), (5966624, 'beq', 5966816), (5966948, 'b', 5969324), (5966992, 'bne', 5967124), (5967120, 'beq', 5967424), (5967244, 'beq', 5967940), (5967256, 'beq', 5967940), (5967268, 'beq', 5967940), (5967320, 'beq', 5967940), (5967420, 'bne', 5967940), (5967568, 'beq', 5967760), (5967892, 'b', 5969320), (5967948, 'bne', 5968744), (5968000, 'bne', 5968068), (5968064, 'beq', 5968200), (5968132, 'bne', 5968744), (5968196, 'bne', 5968744), (5968248, 'bne', 5968328), (5968308, 'b', 5968384), (5968404, 'beq', 5968596), (5968728, 'b', 5969316), (5968752, 'bne', 5968848), (5968828, 'b', 5969312), (5969020, 'beq', 5969172), (5969156, 'b', 5969308), (5969308, 'b', 5969312), (5969312, 'b', 5969316), (5969316, 'b', 5969320), (5969320, 'b', 5969324), (5969324, 'b', 5969328), (5969328, 'b', 5969332), (5969332, 'b', 5972692), (5969420, 'beq', 5969736), (5969532, 'beq', 5969660), (5969656, 'b', 5969724), (5969724, 'b', 5972704), (5969788, 'beq', 5969848), (5969836, 'b', 5972704), (5969848, 'b', 5969852), (5969864, 'beq', 5970420), (5969928, 'bne', 5970044), (5970032, 'b', 5970412), (5970188, 'beq', 5970328), (5970320, 'b', 5970408), (5970408, 'b', 5970412), (5970412, 'b', 5972688), (5970492, 'beq', 5970512), (5970496, 'b', 5972704), (5970528, 'bne', 5970904), (5970652, 'beq', 5970880), (5970880, 'b', 5972384), (5970912, 'bne', 5971432), (5971036, 'beq', 5971404), (5971184, 'beq', 5971320), (5971316, 'b', 5971400), (5971400, 'b', 5971404), (5971404, 'b', 5972380), (5971440, 'bne', 5971476), (5971456, 'bne', 5971476), (5971516, 'beq', 5971812), (5971556, 'bne', 5971600), (5971596, 'beq', 5971812), (5971608, 'bne', 5971812), (5971728, 'beq', 5971808), (5971808, 'b', 5971812), (5971824, 'bne', 5972376), (5971972, 'beq', 5972240), (5972120, 'beq', 5972216), (5972216, 'b', 5972372), (5972372, 'b', 5972376), (5972376, 'b', 5972380), (5972380, 'b', 5972384), (5972492, 'beq', 5972684), (5972548, 'bne', 5972684), (5972560, 'beq', 5972684), (5972684, 'b', 5972688), (5972688, 'b', 5972692), (5972692, 'b', 5972696), (5972696, 'b', 5972700), (5972700, 'b', 5972704)],
        semantics=('[World tap:] (imp 0x005ac3a0, 6150w): the world touch router - census-grade reading (call histogram + constants + structure): 353 call rows - objc_msgSend x99 + blx-register x44 + makeIntpair x36 + linearInterpolate x32 + tileAtWorldPositionLoaded x21 + Vector2 ctor x17 + tileIsSolid x17 + reverseLinearInterpolate x16 + tileIsPaintable x12 + GLKMathUnproject x2 (screen-to-world unprojection) + tileIsHalfDepth x2; constants 0x3f800000 (1.0f), 0xbf000000 (-0.5f) and the immediates 0xa/0x4b/0x43f/0x142; not a per-instruction walkthrough.\n'),
    ),
    dict(
        name='wi_01',
        method='World -[startPinchOrPan]',
        types='v8@0:4',
        start=5582376,
        end=5582528,
        disasm='disasm_worldtileloader_wi_01.txt',
        base_add=5582388,
        base_literal=5582524,
        boundary='ARM.exidx end 0x00552ec0 (listing bound); next ObjC IMP 0x00552ec0 World -[updateTranslationDueToPinchOrPan:]',
        selectors={},
        imports={},
        ivars={
                 0x552eb0: (17155860, 'OBJC_IVAR_$_World.accurateTranslation', 624),
                 0x552eb4: (17155864, 'OBJC_IVAR_$_World.lastPinchPanTranslation', 3356),
                 0x552eb8: (17155868, 'OBJC_IVAR_$_World.touchStartTranslation', 3348),
        },
        classes={},
        instructions=[(5582376, 'push {fp, lr}'), (5582524, 'ldrhteq ip, [r0], r8')],
        calls=[],
        branches=[],
        semantics=('[World startPinchOrPan] (imp 0x00552e28, 38w): the pinch/pan start snapshot - copies the 8-byte Vector2 translation fields through the ivar-offset slot chain ffffcc20/cc24/cc28 (accurateTranslation / lastPinchPanTranslation / touchStartTranslation); no calls.\n'),
    ),
    dict(
        name='wi_02',
        method='World -[updateTranslationDueToPinchOrPan:]',
        types='v16@0:4{Vector2=[2f]}8',
        start=5582528,
        end=5583312,
        disasm='disasm_worldtileloader_wi_02.txt',
        base_add=5582544,
        base_literal=5583304,
        boundary='ARM.exidx end 0x005531d0 (listing bound); next ObjC IMP 0x005531d0 World -[setTranslation:]',
        selectors={
                 0x5531c4: (15195540, 'setTranslation:'),
        },
        imports={},
        ivars={
                 0x5531a0: (17155868, 'OBJC_IVAR_$_World.touchStartTranslation', 3348),
                 0x5531a8: (17155872, 'OBJC_IVAR_$_World.pinchScale', 400),
                 0x5531b0: (17155876, 'OBJC_IVAR_$_World.windowInfo', 152),
                 0x5531bc: (17155864, 'OBJC_IVAR_$_World.lastPinchPanTranslation', 3356),
                 0x5531c0: (17155860, 'OBJC_IVAR_$_World.accurateTranslation', 624),
        },
        classes={},
        instructions=[(5582528, 'push {r4, r5, r6, sl, fp, lr}'), (5583308, 'andeq r0, r0, r0')],
        calls=[(5582688, 'bl method.Vector2.operator_float__'), (5582708, 'bl method.Vector2.operator_float__'), (5582772, 'bl method.Vector2.operator_float__'), (5582816, 'bl method.Vector2.operator_float__'), (5582836, 'bl method.Vector2.operator_float__'), (5582952, 'bl method.Vector2.operator_float__'), (5582968, 'bl method.Vector2.Vector2_float__float_'), (5582992, 'bl method.Vector2.operator_Vector2_'), (5583024, 'bl method.Vector2.Vector2_float__float_'), (5583040, 'bl method.Vector2.operator_float_'), (5583064, 'bl method.Vector2.operator_Vector2_'), (5583128, 'bl method.Vector2.operator__Vector2_'), (5583224, 'bl method.Vector2.operator_Vector2_'), (5583252, 'bl loc.imp.objc_msgSend')],
        branches=[(5582748, 'ble', 5582768), (5582876, 'bpl', 5582896)],
        semantics=('[World updateTranslationDueToPinchOrPan:] (imp 0x00552ec0, 196w): the pinch/pan delta applicator - windowInfo scale (vldr [r0,0xc]) x pinchScale, Vector2 arithmetic (operator float* x6, operator+ x2, operator- x1, operator*(0.5f) x1), delta clamp against the window bound (vcvt.f32.s32 + vcmpe, ble guards); constants 0x400 (1024) and 0x3ccdcccd; writes the translation pair and calls setTranslation: at 0x553194 via objc_msgSend; 14 calls.\n'),
    ),
    dict(
        name='wi_03',
        method='World -[setTranslation:]',
        types='v16@0:4{Vector2=[2f]}8',
        start=5583312,
        end=5584548,
        disasm='disasm_worldtileloader_wi_03.txt',
        base_add=5583328,
        base_literal=5584544,
        boundary='ARM.exidx end 0x005536a4 (listing bound); next ObjC IMP 0x005536a4 World -[translation]',
        selectors={
                 0x553698: (15195544, 'instance'),
                 0x55369c: (15195548, 'setListenerPosition:zoom:'),
        },
        imports={},
        ivars={
                 0x553668: (17155860, 'OBJC_IVAR_$_World.accurateTranslation', 624),
                 0x553670: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
                 0x553674: (17155884, 'OBJC_IVAR_$_World.translationGoal', 632),
                 0x553688: (17155872, 'OBJC_IVAR_$_World.pinchScale', 400),
                 0x55368c: (17155888, 'OBJC_IVAR_$_World.roundedTranslation', 616),
        },
        classes={
                 0x553694: (15245280, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(5583312, 'push {r4, r5, r6, sl, fp, lr}'), (5584544, 'adcseq ip, r0, ip, lsl 18')],
        calls=[(5583420, 'bl method.Vector2.operator_float__'), (5583556, 'bl method.Vector2.operator_float__'), (5583600, 'bl method.Vector2.operator_float__'), (5583724, 'bl method.Vector2.operator_float__'), (5583772, 'bl method.Vector2.operator_float__'), (5583868, 'bl method.Vector2.operator_float__'), (5583912, 'bl method.Vector2.operator_float__'), (5584008, 'bl method.Vector2.operator_float__'), (5584120, 'bl method.Vector2.operator_float__'), (5584136, 'bl method.Vector2.operator_float__'), (5584180, 'bl sym.imp.__wrap_fmodf'), (5584236, 'bl method.Vector2.operator_float__'), (5584252, 'bl method.Vector2.operator_float__'), (5584268, 'bl method.Vector2.operator_float__'), (5584304, 'bl sym.imp.__wrap_fmodf'), (5584340, 'bl method.Vector2.operator_float__'), (5584372, 'bl loc.imp.objc_msgSend'), (5584464, 'bl loc.imp.objc_msgSend')],
        branches=[(5583472, 'blt', 5583748), (5583644, 'blt', 5583744), (5583744, 'b', 5584036), (5583788, 'bpl', 5584032), (5583928, 'bpl', 5584028), (5584028, 'b', 5584032), (5584032, 'b', 5584036), (5584092, 'bpl', 5584112)],
        semantics=('[World setTranslation:] (imp 0x005531d0, 309w): the translation setter - __wrap_fmodf wrapping of both components over worldWidthMacro (x2), roundedTranslation recompute, then [MJSoundManager instance] setListenerPosition:zoom: (0x5535f4/0x553650 objc_msgSend); 18 calls (Vector2 operator float* x10 + fmodf x2 + msgSend x2).\n'),
    ),
    dict(
        name='wi_04',
        method='World -[translation]',
        types='{Vector2=[2f]}8@0:4',
        start=5584548,
        end=5584620,
        disasm='disasm_worldtileloader_wi_04.txt',
        base_add=5584556,
        base_literal=5584616,
        boundary='ARM.exidx end 0x005536ec (listing bound); next ObjC IMP 0x005536ec World -[summaryNetDataForAdmin:mod:owner:cloudMode:]',
        selectors={},
        imports={},
        ivars={
                 0x5536e4: (17155860, 'OBJC_IVAR_$_World.accurateTranslation', 624),
        },
        classes={},
        instructions=[(5584548, 'sub sp, sp, 8'), (5584616, 'adcseq ip, r0, r0, asr 8')],
        calls=[],
        branches=[],
        semantics=('[World translation] (imp 0x005536a4, 18w): bare ivar getter - returns the address of the accurateTranslation 8-byte vector (self + ivar offset).\n'),
    ),
    dict(
        name='wi_05',
        method='World -[touchIsInUI:]',
        types='c16@0:4{CGPoint=ff}8',
        start=5976264,
        end=5976504,
        disasm='disasm_worldtileloader_wi_05.txt',
        base_add=5976280,
        base_literal=5976500,
        boundary='ARM.exidx end 0x005b31b8 (listing bound); next ObjC IMP 0x005b31b8 World -[startTouch:tapCount:index:]',
        selectors={
                 0x5b31a4: (15197460, 'panBlockingUIDisplayed'),
                 0x5b31b0: (15197464, 'touchIsInUI:'),
        },
        imports={
                 0x5b31a0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5b31a8: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
        },
        classes={},
        instructions=[(5976264, 'push {r4, r5, fp, lr}'), (5976500, 'adceq ip, sl, r4, lsl sl')],
        calls=[(5976344, 'blx lr'), (5976432, 'bl loc.imp.objc_msgSend')],
        branches=[(5976356, 'beq', 5976372), (5976368, 'b', 5976468), (5976444, 'beq', 5976460), (5976456, 'b', 5976468)],
        semantics=('[World touchIsInUI:] (imp 0x005b30c8, 60w): UI hit test - returns 1 immediately when panBlockingUIDisplayed (0x5b3118), else forwards touchIsInUI: to the uiManager via objc_msgSend (0x5b3170); two boolean returns (movw 1 / movw 0).\n'),
    ),
    dict(
        name='wi_06',
        method='World -[moveTouch:index:]',
        types='v20@0:4{CGPoint=ff}8i16',
        start=5976696,
        end=5976840,
        disasm='disasm_worldtileloader_wi_06.txt',
        base_add=5976744,
        base_literal=5976832,
        boundary='ARM.exidx end 0x005b3308 (listing bound); next ObjC IMP 0x005b3308 World -[doEndTouch:wasCancelled:index:]',
        selectors={
                 0x5b3304: (15197472, 'moveTouch:index:'),
        },
        imports={},
        ivars={
                 0x5b32fc: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
        },
        classes={},
        instructions=[(5976696, 'push {fp, lr}'), (5976836, 'invalid')],
        calls=[(5976816, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[World moveTouch:index:] (imp 0x005b3278, 36w): forwards moveTouch:index: to the uiManager (objc_msgSend 0x5b32f0) - pure routing.\n'),
    ),
    dict(
        name='wi_07',
        method='World -[doEndTouch:wasCancelled:index:]',
        types='v24@0:4{CGPoint=ff}8c16i20',
        start=5976840,
        end=5977004,
        disasm='disasm_worldtileloader_wi_07.txt',
        base_add=5976896,
        base_literal=5976996,
        boundary='ARM.exidx end 0x005b33ac (listing bound); next ObjC IMP 0x005b33ac World -[cancelTouch:index:]',
        selectors={
                 0x5b33a8: (15197476, 'endTouch:wasCancelled:index:'),
        },
        imports={},
        ivars={
                 0x5b33a0: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
        },
        classes={},
        instructions=[(5976840, 'push {r4, sl, fp, lr}'), (5977000, 'invalid')],
        calls=[(5976980, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[World doEndTouch:wasCancelled:index:] (imp 0x005b3308, 41w): forwards endTouch:wasCancelled:index: to the uiManager (0x5b3394) - pure routing.\n'),
    ),
    dict(
        name='wi_08',
        method='World -[cancelTouch:index:]',
        types='v20@0:4{CGPoint=ff}8i16',
        start=5977004,
        end=5977136,
        disasm='disasm_worldtileloader_wi_08.txt',
        base_add=5977072,
        base_literal=5977132,
        boundary='ARM.exidx end 0x005b34b4; body trimmed at the next IMP 0x005b3430 World -[endTouch:index:]',
        selectors={
                 0x5b3428: (15197480, 'doEndTouch:wasCancelled:index:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(5977004, 'push {fp, lr}'), (5977132, 'invalid')],
        calls=[(5977116, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[World cancelTouch:index:] (imp 0x005b33ac, 33w): forwards to doEndTouch:wasCancelled:index: with wasCancelled=1 (0x5b341c).\n'),
    ),
    dict(
        name='wi_09',
        method='World -[endTouch:index:]',
        types='v20@0:4{CGPoint=ff}8i16',
        start=5977136,
        end=5977268,
        disasm='disasm_worldtileloader_wi_09.txt',
        base_add=5977204,
        base_literal=5977264,
        boundary='ARM.exidx end 0x005b34b4 (listing bound); next ObjC IMP 0x005b34b4 World -[swipeGesture]',
        selectors={
                 0x5b34ac: (15197480, 'doEndTouch:wasCancelled:index:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(5977136, 'push {fp, lr}'), (5977264, 'adceq ip, sl, r8, ror r6')],
        calls=[(5977248, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[World endTouch:index:] (imp 0x005b3430, 33w): forwards to doEndTouch:wasCancelled:index: with wasCancelled=0 (0x5b34a0).\n'),
    ),
    dict(
        name='wi_10',
        method='World -[swipeGesture]',
        types='v8@0:4',
        start=5977268,
        end=5977408,
        disasm='disasm_worldtileloader_wi_10.txt',
        base_add=5977284,
        base_literal=5977404,
        boundary='ARM.exidx end 0x005b3540 (listing bound); next ObjC IMP 0x005b3540 World -[unmodifiedGroundLevelForX:]',
        selectors={
                 0x5b3530: (15197484, 'swipeUpGesture'),
                 0x5b3534: (15196444, 'activeBlockhead'),
        },
        imports={
                 0x5b352c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5b3538: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={},
        instructions=[(5977268, 'push {r4, r5, fp, lr}'), (5977404, 'adceq ip, sl, r8, lsr 12')],
        calls=[(5977360, 'blx r3'), (5977376, 'blx r2')],
        branches=[],
        semantics=('[World swipeGesture] (imp 0x005b34b4, 35w): delegates to the active blockhead - [activeBlockhead swipeUpGesture] via the dynamicWorld lookup (blx x2).\n'),
    ),
    dict(
        name='wi_11',
        method='World -[requiresSwipeEvents]',
        types='c8@0:4',
        start=6027624,
        end=6027768,
        disasm='disasm_worldtileloader_wi_11.txt',
        base_add=6027640,
        base_literal=6027764,
        boundary='ARM.exidx end 0x005bf9f8 (listing bound); next ObjC IMP 0x005bf9f8 World -[allowsPanning]',
        selectors={
                 0x5bf9e8: (15197740, 'requiresSwipeEvents'),
                 0x5bf9ec: (15196444, 'activeBlockhead'),
        },
        imports={
                 0x5bf9e4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5bf9f0: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={},
        instructions=[(6027624, 'push {r4, r5, fp, lr}'), (6027764, 'adceq r0, sl, r4, ror r1')],
        calls=[(6027716, 'blx r3'), (6027732, 'blx r2')],
        branches=[],
        semantics=('[World requiresSwipeEvents] (imp 0x005bf968, 36w): delegates to the active blockhead requiresSwipeEvents (blx x2).\n'),
    ),
    dict(
        name='wi_12',
        method='World -[allowsPanning]',
        types='c8@0:4',
        start=6027768,
        end=6028124,
        disasm='disasm_worldtileloader_wi_12.txt',
        base_add=6027784,
        base_literal=6028120,
        boundary='ARM.exidx end 0x005bfb5c (listing bound); next ObjC IMP 0x005bfb5c World -[requiresDirectionalSwipes]',
        selectors={
                 0x5bfb48: (15196444, 'activeBlockhead'),
                 0x5bfb50: (15197744, 'allowsPanning'),
                 0x5bfb54: (15197748, 'takingPhoto'),
        },
        imports={
                 0x5bfb44: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5bfb4c: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={},
        instructions=[(6027768, 'push {r4, r5, fp, lr}'), (6028120, 'adceq r0, sl, r4, ror 1')],
        calls=[(6027860, 'blx lr'), (6027976, 'blx lr'), (6027992, 'blx r2'), (6028056, 'blx r2')],
        branches=[(6027880, 'beq', 6028080), (6028012, 'bne', 6028080)],
        semantics=('[World allowsPanning] (imp 0x005bf9f8, 89w): pan gate - returns 0 while takingPhoto (0x5bfa54) or when the active blockhead allowsPanning is false (0x5bfad8); movw 1/0 constants.\n'),
    ),
    dict(
        name='wi_13',
        method='World -[allowsRotation]',
        types='c8@0:4',
        start=6027392,
        end=6027624,
        disasm='disasm_worldtileloader_wi_13.txt',
        base_add=6027408,
        base_literal=6027620,
        boundary='ARM.exidx end 0x005bf968 (listing bound); next ObjC IMP 0x005bf968 World -[requiresSwipeEvents]',
        selectors={
                 0x5bf954: (15196624, 'requiresMotionEvents'),
                 0x5bf958: (15196444, 'activeBlockhead'),
        },
        imports={
                 0x5bf950: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5bf95c: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5bf960: (17156304, 'OBJC_IVAR_$_World.dpadControl', 3372),
        },
        classes={},
        instructions=[(6027392, 'push {r4, r5, r6, sl, fp, lr}'), (6027620, 'adceq r0, sl, ip, asr r2')],
        calls=[(6027496, 'blx ip'), (6027512, 'blx r2')],
        branches=[(6027532, 'beq', 6027580)],
        semantics=('[World allowsRotation] (imp 0x005bf880, 58w): rotation gate - requiresMotionEvents from the blockhead (blx x2) plus the dpadControl flag; returns the sxtb boolean (movw 1/0).\n'),
    ),
    dict(
        name='wi_14',
        method='World -[requiresDirectionalSwipes]',
        types='c8@0:4',
        start=6028124,
        end=6028308,
        disasm='disasm_worldtileloader_wi_14.txt',
        base_add=6028140,
        base_literal=6028304,
        boundary='ARM.exidx end 0x005bfc14 (listing bound); next ObjC IMP 0x005bfc14 World -[directionalSwipe:]',
        selectors={
                 0x5bfc00: (15197752, 'isCasting'),
                 0x5bfc04: (15197320, 'fishingRod'),
                 0x5bfc08: (15196444, 'activeBlockhead'),
        },
        imports={
                 0x5bfbfc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5bfc0c: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={},
        instructions=[(6028124, 'push {r4, r5, r6, r7, fp, lr}'), (6028304, 'adceq pc, sb, r0, lsl 31')],
        calls=[(6028236, 'blx r3'), (6028252, 'blx r2'), (6028268, 'blx r2')],
        branches=[],
        semantics=('[World requiresDirectionalSwipes] (imp 0x005bfb5c, 46w): directional-swipe gate - reads isCasting / fishingRod / activeBlockhead (three blx message sends); returns sxtb.\n'),
    ),
    dict(
        name='wi_15',
        method='World -[directionalSwipe:]',
        types='v16@0:4{Vector2=[2f]}8',
        start=6028308,
        end=6028464,
        disasm='disasm_worldtileloader_wi_15.txt',
        base_add=6028348,
        base_literal=6028448,
        boundary='ARM.exidx end 0x005bfcb0 (listing bound); next ObjC IMP 0x005bfcb0 World -[clientConnected:]',
        selectors={
                 0x5bfca4: (15196444, 'activeBlockhead'),
                 0x5bfca8: (15197320, 'fishingRod'),
                 0x5bfcac: (15197756, 'directionalSwipe:'),
        },
        imports={},
        ivars={
                 0x5bfc9c: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={},
        instructions=[(6028308, 'push {fp, lr}'), (6028460, 'invalid')],
        calls=[(6028376, 'bl loc.imp.objc_msgSend'), (6028392, 'bl loc.imp.objc_msgSend'), (6028432, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[World directionalSwipe:] (imp 0x005bfc14, 39w): forwards directionalSwipe: to the active blockhead / fishingRod pair (3 objc_msgSend: receiver lookups + the forwarded call).\n'),
    ),
    dict(
        name='wi_16',
        method='World -[unmodifiedGroundLevelForX:]',
        types='i12@0:4i8',
        start=5977408,
        end=5977668,
        disasm='disasm_worldtileloader_wi_16.txt',
        base_add=5977424,
        base_literal=5977664,
        boundary='ARM.exidx end 0x005b3644 (listing bound); next ObjC IMP 0x005b3644 World -[savePhysicalBlockForMacroTile:sendReliably:dontSend:onlySaveIfClientsNeedIt:]',
        selectors={
                 0x5b3638: (15197488, 'unmodifiedGroundLevelForX:'),
        },
        imports={
                 0x5b3634: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5b3630: (17156104, 'OBJC_IVAR_$_World.worldTileLoader', 420),
                 0x5b363c: (17156024, 'OBJC_IVAR_$_World.clientTileLoader', 972),
        },
        classes={},
        instructions=[(5977408, 'push {fp, lr}'), (5977664, 'umlaleq ip, sl, ip, r5')],
        calls=[(5977548, 'blx r3'), (5977628, 'blx r3')],
        branches=[(5977476, 'beq', 5977560), (5977556, 'b', 5977636)],
        semantics=('[World unmodifiedGroundLevelForX:] (imp 0x005b3540, 65w): ground level with the client/server loader fallback - worldTileLoader (ffffcd14) path at 0x5b35cc, else the clientTileLoader path at 0x5b361c; movw 0 guard.\n'),
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
        'batch': 'World input router (E104): the 6150w tap census and the touch/pinch/gesture gates; 17 bodies',
        'claim': ('a census-plus-targeted static map of the World input entry points; the per-branch interaction dispatch inside tap: is read at histogram level, and the UI-manager / blockhead message contracts are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'world_input.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale world_input.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
