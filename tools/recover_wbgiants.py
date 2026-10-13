#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The electricity line: the Workbench twin giants (the class closure): the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 11150 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/WORKBENCH_GIANTS.md for the prose and boundaries.
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
    'bl 0xae3c5c': 0x00ae3c5c,
    'bl 0xaf9850': 0x00af9850,
    'bl 0xaf98c4': 0x00af98c4,
    'bl 0xaf9c5c': 0x00af9c5c,
    'bl 0xaf9ff4': 0x00af9ff4,
    'bl 0xafa040': 0x00afa040,
    'bl 0xafa228': 0x00afa228,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector.Vector_float__float__float__float_': 0x004d0d08,
    'bl method.Vector.operator_Vector_': 0x004d6538,
    'bl method.Vector.operator_float__': 0x004b5c08,
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl method.Vector2.operator_Vector2_': 0x004d0418,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl sym.UIGraphicsBeginImageContextWithOptions': 0x002558d4,
    'bl sym.UIGraphicsEndImageContext': 0x00255b6c,
    'bl sym.UIGraphicsGetImageFromCurrentImageContext': 0x00255dd0,
    'bl sym.Vector::operator_Vector_': 0x0058198c,
    'bl sym.clamp_float__float__float_': 0x004be068,
    'bl sym.drawShaderQuad': 0x007c43dc,
    'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_': 0x00d948fc,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__modsi3': 0x001c3020,
    'bl sym.imp.__wrap_fmodf': 0x001c3d4c,
    'bl sym.imp.__wrap_glBindTexture': 0x001c2ad4,
    'bl sym.imp.__wrap_glEnableVertexAttribArray': 0x001c2d5c,
    'bl sym.imp.__wrap_glUniform1f': 0x001c3fb0,
    'bl sym.imp.__wrap_glUniform1i': 0x001c2de0,
    'bl sym.imp.__wrap_glUniform4f': 0x001c3d64,
    'bl sym.imp.__wrap_glUniformMatrix4fv': 0x001c2dd4,
    'bl sym.imp.__wrap_glUseProgram': 0x001c2d38,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.itemTypeIsPainting_ItemType_': 0x005b902c,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileAtWorldPosition_int__int__MacroTile__World_': 0x00a16e68,
    'bl sym.tileIsBurnable_Tile__DynamicWorld__intpair_': 0x00a14180,
    'bl sym.tileIsWater_Tile_': 0x00a11690,
    'bl sym.updateQuadBufferTexCoords_float__int__float__float__float__float_': 0x00d91b30,
    'bl sym.updateQuadBufferVertsAndMatrix_float__int___GLKMatrix4__float__float__float__float_': 0x00d91c6c,
}

SPECS = [
    dict(
        name='wg_update',
        method='Workbench -[update:accurateDT:isSimulation:]',
        types='v20@0:4f8f12c16',
        start=11463192,
        end=11473392,
        disasm='disasm_worldtileloader_wg_update.txt',
        base_add=11463208,
        base_literal=11467056,
        boundary='ARM.exidx end 0x00af11f0 (listing bound); next ObjC IMP 0x00af11f0 Workbench -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        selectors={
                 0xaef93c: (15228948, 'needsRemoved'),
                 0xaef944: (15228704, 'release'),
                 0xaef95c: (15228872, 'objectType'),
                 0xaef960: (15228876, 'dynamicWorldChangedAtPos:objectType:'),
                 0xaef978: (15229084, 'hasCoffeeEnergy'),
                 0xaefd28: (15228680, 'macroTiles'),
                 0xaefd30: (15229088, 'updateHasFuel'),
                 0xaf01d8: (15229092, 'placeFireAtPosition:'),
                 0xaf01e4: (15229096, 'combinedLightForSolarPanel'),
                 0xaf0570: (15229100, 'findAndSubtractAllPowerUpTo:forUser:'),
                 0xaf078c: (15229104, 'isNet'),
                 0xaf0bcc: (15229108, 'paused'),
                 0xaf0bd0: (15229112, 'shouldContinueSimulating'),
                 0xaf0bd4: (15229116, 'unableToWorkReason'),
                 0xaf1134: (15228704, 'release'),
                 0xaf1148: (15228872, 'objectType'),
                 0xaf114c: (15228876, 'dynamicWorldChangedAtPos:objectType:'),
                 0xaf1164: (15229100, 'findAndSubtractAllPowerUpTo:forUser:'),
                 0xaf116c: (15229104, 'isNet'),
                 0xaf1170: (15229108, 'paused'),
                 0xaf1174: (15229112, 'shouldContinueSimulating'),
                 0xaf1178: (15229116, 'unableToWorkReason'),
                 0xaf1184: (15228780, 'craftableItem'),
                 0xaf118c: (15229120, 'isCraftingAtAnyWorkbench'),
                 0xaf1190: (15229124, 'interactionWorkbench'),
                 0xaf11ac: (15229128, 'doubleTimeUnlocked'),
                 0xaf11b8: (15229132, 'craftCompleted'),
                 0xaf11bc: (15229136, 'activeBlockhead'),
                 0xaf11cc: (15229140, 'setCraftingTimeRemaining:fractionComplete:totalCraftTime:remainingNumberToCraft:'),
                 0xaf11dc: (15229028, 'abortCraft'),
                 0xaf11e4: (15229144, 'isAddingFuelToAnyWorkbench'),
        },
        imports={
                 0xaef938: (17151904, 'objc_msgSend'),
                 0xaf112c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xaef934: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0xaef940: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0xaef948: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0xaef950: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xaef954: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xaef958: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xaef964: (17165444, 'OBJC_IVAR_$_Workbench.currentFuelBlockhead', 108),
                 0xaef96c: (17165396, 'OBJC_IVAR_$_Workbench.isInUseFuel', 112),
                 0xaefd1c: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xaefd20: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xaefd24: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xaefd2c: (17165368, 'OBJC_IVAR_$_Workbench.hasFuel', 220),
                 0xaefd34: (17165376, 'OBJC_IVAR_$_Workbench.fuelFraction', 212),
                 0xaefd3c: (17165384, 'OBJC_IVAR_$_Workbench.fireSpreadTimer', 208),
                 0xaf01dc: (17165380, 'OBJC_IVAR_$_Workbench.availableElectricity', 222),
                 0xaf01e0: (17165364, 'OBJC_IVAR_$_Workbench.fuelCounter', 216),
                 0xaf065c: (17165464, 'OBJC_IVAR_$_Workbench.timeSinceFoundElectricty', 320),
                 0xaf0784: (17165468, 'OBJC_IVAR_$_Workbench.particleCreateTimerSteamEngine', 280),
                 0xaf0bdc: (17165344, 'OBJC_IVAR_$_Workbench.requiresElectricity', 224),
                 0xaf1130: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0xaf1138: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0xaf113c: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xaf1140: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xaf1144: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xaf1150: (17165444, 'OBJC_IVAR_$_Workbench.currentFuelBlockhead', 108),
                 0xaf1154: (17165396, 'OBJC_IVAR_$_Workbench.isInUseFuel', 112),
                 0xaf1158: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xaf115c: (17165380, 'OBJC_IVAR_$_Workbench.availableElectricity', 222),
                 0xaf1160: (17165364, 'OBJC_IVAR_$_Workbench.fuelCounter', 216),
                 0xaf1168: (17165368, 'OBJC_IVAR_$_Workbench.hasFuel', 220),
                 0xaf117c: (17165344, 'OBJC_IVAR_$_Workbench.requiresElectricity', 224),
                 0xaf1188: (17165428, 'OBJC_IVAR_$_Workbench.craftingItemObject', 180),
                 0xaf1194: (17165404, 'OBJC_IVAR_$_Workbench.hurrying', 200),
                 0xaf1198: (17165352, 'OBJC_IVAR_$_Workbench.requiresFuel', 221),
                 0xaf119c: (17165416, 'OBJC_IVAR_$_Workbench.craftProgressCount', 188),
                 0xaf11a0: (17165408, 'OBJC_IVAR_$_Workbench.hurrySeconds', 196),
                 0xaf11a4: (17165440, 'OBJC_IVAR_$_Workbench.count', 228),
                 0xaf11b0: (17165432, 'OBJC_IVAR_$_Workbench.countCreated', 236),
                 0xaf11c0: (17165460, 'OBJC_IVAR_$_Workbench.fractionComplete', 264),
                 0xaf11d0: (17165436, 'OBJC_IVAR_$_Workbench.countLeft', 232),
                 0xaf11d4: (17165472, 'OBJC_IVAR_$_Workbench.craftProgressUI', 184),
        },
        classes={},
        instructions=[(11463192, 'push {r4, r5, r6, sl, fp, lr}'), (11468292, 'add lr, pc, lr'), (11473388, 'andeq r0, r0, r0')],
        calls=[(11463344, 'blx r2'), (11463540, 'bl loc.imp.objc_msgSend'), (11463576, 'bl loc.imp.objc_msgSend'), (11463612, 'blx r3'), (11463700, 'blx r2'), (11463764, 'bl loc.imp.objc_msgSend'), (11463900, 'bl loc.imp.objc_msgSend'), (11463936, 'bl loc.imp.objc_msgSend'), (11464016, 'blx r2'), (11464228, 'blx r2'), (11464272, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (11464284, 'bl sym.tileIsWater_Tile_'), (11464488, 'bl loc.imp.objc_msgSend'), (11464524, 'bl loc.imp.objc_msgSend'), (11464568, 'blx ip'), (11464692, 'bl 0xae3c5c'), (11464772, 'bl 0xae3c5c'), (11464868, 'bl sym.makeIntpair_int__int_'), (11465000, 'bl sym.makeIntpair_int__int_'), (11465096, 'bl sym.makeIntpair_int__int_'), (11465172, 'bl sym.makeIntpair_int__int_'), (11465276, 'blx r2'), (11465320, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (11465400, 'bl sym.tileIsBurnable_Tile__DynamicWorld__intpair_'), (11465476, 'bl loc.imp.objc_msgSend'), (11465764, 'blx r3'), (11465956, 'bl loc.imp.objc_msgSend'), (11465992, 'bl loc.imp.objc_msgSend'), (11466344, 'blx ip'), (11466536, 'bl loc.imp.objc_msgSend'), (11466572, 'bl loc.imp.objc_msgSend'), (11467352, 'bl loc.imp.objc_msgSend'), (11467388, 'bl loc.imp.objc_msgSend'), (11467432, 'blx ip'), (11467508, 'bl sym.clamp_float__float__float_'), (11467692, 'blx r2'), (11467804, 'blx r2'), (11467892, 'blx r2'), (11467968, 'blx r2'), (11468444, 'bl loc.imp.objc_msgSend'), (11468480, 'bl loc.imp.objc_msgSend'), (11468548, 'blx r2'), (11468684, 'blx r2'), (11468760, 'blx r2'), (11468836, 'blx r2'), (11469556, 'blx ip'), (11469720, 'bl loc.imp.objc_msgSend'), (11469756, 'bl loc.imp.objc_msgSend'), (11469932, 'blx r2'), (11470008, 'blx r2'), (11470096, 'blx r2'), (11470184, 'bl loc.imp.objc_msgSend_stret'), (11470224, 'bl sym.imp.memset'), (11470288, 'blx r2'), (11470364, 'blx r2'), (11470420, 'blx r2'), (11470620, 'bl loc.imp.objc_msgSend'), (11470876, 'blx r2'), (11471084, 'bl loc.imp.objc_msgSend'), (11471252, 'blx r2'), (11471392, 'bl loc.imp.objc_msgSend'), (11471444, 'bl sym.imp.__wrap_fmodf'), (11471540, 'blx r2'), (11471664, 'bl loc.imp.objc_msgSend'), (11471992, 'blx ip'), (11472080, 'bl loc.imp.objc_msgSend'), (11472116, 'bl loc.imp.objc_msgSend'), (11472260, 'blx r2'), (11472336, 'blx r2'), (11472456, 'bl loc.imp.objc_msgSend'), (11472548, 'bl loc.imp.objc_msgSend'), (11472584, 'bl loc.imp.objc_msgSend'), (11472752, 'blx r2'), (11472828, 'blx r2'), (11472904, 'blx r2'), (11473024, 'bl loc.imp.objc_msgSend'), (11473116, 'bl loc.imp.objc_msgSend'), (11473152, 'bl loc.imp.objc_msgSend')],
        branches=[(11463276, 'beq', 11463284), (11463280, 'b', 11473188), (11463356, 'beq', 11463640), (11463712, 'beq', 11463940), (11464028, 'beq', 11464048), (11464080, 'bne', 11467560), (11464116, 'bne', 11465508), (11464296, 'beq', 11464576), (11464332, 'beq', 11464572), (11464572, 'b', 11464576), (11464688, 'bhi', 11465488), (11464812, 'ble', 11464892), (11464888, 'b', 11465200), (11464908, 'ble', 11465024), (11464944, 'beq', 11465020), (11465020, 'b', 11465196), (11465040, 'ble', 11465120), (11465116, 'b', 11465192), (11465192, 'b', 11465196), (11465196, 'b', 11465200), (11465340, 'beq', 11465484), (11465412, 'beq', 11465484), (11465484, 'b', 11465488), (11465488, 'b', 11467556), (11465540, 'bne', 11466036), (11465576, 'bge', 11466028), (11465656, 'ble', 11466024), (11465808, 'ble', 11466020), (11466020, 'b', 11466024), (11466024, 'b', 11466028), (11466028, 'b', 11467552), (11466068, 'bne', 11466688), (11466104, 'bge', 11466684), (11466184, 'ble', 11466680), (11466360, 'ble', 11466628), (11466624, 'b', 11466676), (11466676, 'b', 11466680), (11466680, 'b', 11466684), (11466684, 'b', 11467548), (11466720, 'bne', 11467544), (11466760, 'ble', 11467436), (11466796, 'bge', 11467436), (11466832, 'bne', 11467436), (11466836, 'b', 11466840), (11466884, 'ble', 11466932), (11466940, 'beq', 11467132), (11467052, 'b', 11466840), (11467180, 'ble', 11467224), (11467544, 'b', 11467548), (11467548, 'b', 11467552), (11467552, 'b', 11467556), (11467556, 'b', 11467560), (11467592, 'beq', 11468552), (11467628, 'beq', 11468552), (11467704, 'bne', 11468552), (11467740, 'beq', 11468212), (11467816, 'bne', 11468212), (11467828, 'beq', 11467908), (11467904, 'beq', 11468212), (11467976, 'bne', 11468212), (11468028, 'bne', 11468100), (11468056, 'b', 11468164), (11468132, 'bne', 11468160), (11468160, 'b', 11468164), (11468260, 'blt', 11468508), (11468584, 'beq', 11469796), (11468620, 'beq', 11469796), (11468696, 'bne', 11469796), (11468772, 'bne', 11469796), (11468844, 'bne', 11469796), (11468904, 'beq', 11468980), (11468940, 'beq', 11468980), (11468976, 'bne', 11468988), (11469020, 'bne', 11469048), (11469132, 'blt', 11469792), (11469216, 'blt', 11469296), (11469260, 'b', 11469328), (11469364, 'bge', 11469788), (11469436, 'bne', 11469480), (11469572, 'ble', 11469784), (11469784, 'b', 11469788), (11469788, 'b', 11469792), (11469792, 'b', 11469796), (11469828, 'beq', 11472124), (11469868, 'beq', 11472124), (11469944, 'bne', 11472124), (11470020, 'bne', 11472124), (11470032, 'beq', 11470112), (11470108, 'beq', 11472124), (11470168, 'beq', 11470196), (11470188, 'b', 11470228), (11470300, 'beq', 11470380), (11470376, 'beq', 11470436), (11470424, 'b', 11473188), (11470468, 'beq', 11472120), (11470504, 'beq', 11470744), (11470720, 'b', 11471004), (11470776, 'bne', 11470816), (11470812, 'bne', 11471000), (11470884, 'bne', 11471000), (11470920, 'bgt', 11470960), (11470956, 'bne', 11471000), (11471000, 'b', 11471004), (11471208, 'bgt', 11471256), (11471288, 'beq', 11472000), (11471568, 'bne', 11471996), (11471804, 'bge', 11471840), (11471816, 'b', 11471848), (11471996, 'b', 11472000), (11472120, 'b', 11472124), (11472156, 'beq', 11472616), (11472196, 'beq', 11472616), (11472272, 'bne', 11472616), (11472348, 'bne', 11472612), (11472612, 'b', 11472616), (11472648, 'beq', 11473188), (11472688, 'beq', 11473188), (11472764, 'bne', 11473188), (11472840, 'beq', 11472920), (11472916, 'beq', 11473184), (11473180, 'b', 11473188), (11473184, 'b', 11473188)],
        semantics=("[Workbench update:accurateDT:isSimulation:] (imp 0x00aeea18, 2550w): the workbench's per-tick simulation. Census (78 calls): **30 objc_msgSend** (the workbench interactions) + **`makeIntpair` x4** + `tileAtWorldPosition` x2 + the local helper 0xae3c5c x2 + **`tileIsWater`** (steam/water interaction) + **`tileIsBurnable(Tile*, DynamicWorld*, intpair)`** (the furnace's neighbour-burnable check - the fire-feeding contract) + `clamp_float` + `__wrap_fmodf` (the coordinate wrap) + one stret + memset; the state rides the fffff120/14c/150 family.\n"),
    ),
    dict(
        name='wg_draw',
        method='Workbench -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        types='v156@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76i140i144i148i152',
        start=11473392,
        end=11507792,
        disasm='disasm_worldtileloader_wg_draw.txt',
        base_add=11473448,
        base_literal=11477400,
        boundary='ARM.exidx end 0x00af9850 (listing bound); next ObjC IMP 0x00afa7e8 Workbench -[title]',
        selectors={
                 0xaf2344: (15229148, 'sound'),
                 0xaf234c: (15229064, 'multiSoundNamed:'),
                 0xaf2350: (15228960, 'instance'),
                 0xaf2a2c: (15229152, 'setLooping:'),
                 0xaf2a34: (15229156, 'playAtPosition:'),
                 0xaf2a38: (15228852, 'stop'),
                 0xaf32e4: (15229164, 'isPlaying'),
                 0xaf32ec: (15229160, 'soundNamed:'),
                 0xaf32f0: (15229168, 'hasFinishedPlaying'),
                 0xaf3308: (15229172, 'dayColor'),
                 0xaf3944: (15229176, 'addParticleAtPos:velocity:color:gravityType:life:scale:'),
                 0xaf44c0: (15228960, 'instance'),
                 0xaf71a0: (15229180, 'energyFraction'),
                 0xaf80a4: (15229172, 'dayColor'),
                 0xaf823c: (15229164, 'isPlaying'),
                 0xaf8248: (15229160, 'soundNamed:'),
                 0xaf824c: (15228960, 'instance'),
                 0xaf857c: (15229176, 'addParticleAtPos:velocity:color:gravityType:life:scale:'),
                 0xaf8580: (15229168, 'hasFinishedPlaying'),
                 0xaf858c: (15229156, 'playAtPosition:'),
                 0xaf85a0: (15228780, 'craftableItem'),
                 0xaf85ac: (15228668, 'shaderNamed:attributes:uniforms:'),
                 0xaf85c0: (15228664, 'arrayWithObjects:'),
                 0xaf85e0: (15229188, 'imageWithData:'),
                 0xaf8bb4: (15229184, 'outputImageData'),
                 0xaf8bb8: (15229192, 'size'),
                 0xaf8cb4: (15229196, 'drawInRect:'),
                 0xaf8cbc: (15229200, 'initWithUIImage:'),
                 0xaf8cc0: (15228712, 'alloc'),
                 0xaf8ccc: (15229204, 'worldWidthMacro'),
                 0xaf8d00: (15228680, 'macroTiles'),
                 0xaf9814: (15229172, 'dayColor'),
                 0xaf981c: (15228780, 'craftableItem'),
                 0xaf9824: (15228704, 'release'),
                 0xaf982c: (15228736, 'intValue'),
                 0xaf9830: (15228864, 'objectAtIndex:'),
                 0xaf9834: (15229212, 'uniformLocations'),
                 0xaf9838: (15229208, 'program'),
                 0xaf983c: (15229216, 'name'),
                 0xaf9848: (15229224, 'maxT'),
                 0xaf984c: (15229220, 'maxS'),
        },
        imports={
                 0xaf2340: (17151904, 'objc_msgSend'),
                 0xaf2348: (16366760, '__CFConstantStringClassReference'),
                 0xaf2358: (16366776, '__CFConstantStringClassReference'),
                 0xaf235c: (16366792, '__CFConstantStringClassReference'),
                 0xaf290c: (16366808, '__CFConstantStringClassReference'),
                 0xaf29c4: (16366824, '__CFConstantStringClassReference'),
                 0xaf2a20: (16366840, '__CFConstantStringClassReference'),
                 0xaf2a24: (16366856, '__CFConstantStringClassReference'),
                 0xaf2a3c: (16366872, '__CFConstantStringClassReference'),
                 0xaf2f6c: (16366888, '__CFConstantStringClassReference'),
                 0xaf2f70: (16366904, '__CFConstantStringClassReference'),
                 0xaf31b4: (16366920, '__CFConstantStringClassReference'),
                 0xaf32e8: (16366936, '__CFConstantStringClassReference'),
                 0xaf719c: (17151904, 'objc_msgSend'),
                 0xaf8244: (16366936, '__CFConstantStringClassReference'),
                 0xaf85a8: (16366952, '__CFConstantStringClassReference'),
                 0xaf85b0: (16365928, '__CFConstantStringClassReference'),
                 0xaf85b4: (16365944, '__CFConstantStringClassReference'),
                 0xaf85b8: (16365992, '__CFConstantStringClassReference'),
                 0xaf85bc: (16366968, '__CFConstantStringClassReference'),
                 0xaf85c8: (16365896, '__CFConstantStringClassReference'),
                 0xaf85cc: (16365912, '__CFConstantStringClassReference'),
                 0xaf8cfc: (17151904, 'objc_msgSend'),
                 0xaf9808: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xaf232c: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xaf2330: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0xaf2334: (17165380, 'OBJC_IVAR_$_Workbench.availableElectricity', 222),
                 0xaf2338: (17165452, 'OBJC_IVAR_$_Workbench.sound', 288),
                 0xaf233c: (17165476, 'OBJC_IVAR_$_Workbench.paused', 292),
                 0xaf2a30: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xaf32e0: (17165468, 'OBJC_IVAR_$_Workbench.particleCreateTimerSteamEngine', 280),
                 0xaf32f8: (17165480, 'OBJC_IVAR_$_Workbench.particleCreateTimerRefinery', 284),
                 0xaf32fc: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xaf3300: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xaf44c4: (17165484, 'OBJC_IVAR_$_Workbench.animationLoopTimer', 244),
                 0xaf44c8: (17165356, 'OBJC_IVAR_$_Workbench.animationLoopIndex', 240),
                 0xaf44cc: (17165488, 'OBJC_IVAR_$_Workbench.savedDrawBuffer', 296),
                 0xaf44d0: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12),
                 0xaf44d4: (17165492, 'OBJC_IVAR_$_Workbench.savedDrawBufferIndex', 300),
                 0xaf44d8: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xaf44dc: (17165368, 'OBJC_IVAR_$_Workbench.hasFuel', 220),
                 0xaf44e0: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xaf44e8: (17165376, 'OBJC_IVAR_$_Workbench.fuelFraction', 212),
                 0xaf4e88: (17165348, 'OBJC_IVAR_$_Workbench.level', 176),
                 0xaf52dc: (17165496, 'OBJC_IVAR_$_Workbench.lastRenderDisplayedHadFuel', 309),
                 0xaf57b4: (17165500, 'OBJC_IVAR_$_Workbench.lastRenderedIndicatorFractionRounded', 304),
                 0xaf6174: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0xaf6178: (17165380, 'OBJC_IVAR_$_Workbench.availableElectricity', 222),
                 0xaf617c: (17165504, 'OBJC_IVAR_$_Workbench.lastRenderDisplayedInUse', 308),
                 0xaf6180: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xaf6184: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xaf65d4: (17165488, 'OBJC_IVAR_$_Workbench.savedDrawBuffer', 296),
                 0xaf65dc: (17165492, 'OBJC_IVAR_$_Workbench.savedDrawBufferIndex', 300),
                 0xaf65e0: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12),
                 0xaf65e4: (17165508, 'OBJC_IVAR_$_Workbench.rotationAnimationTimer', 248),
                 0xaf7964: (17165500, 'OBJC_IVAR_$_Workbench.lastRenderedIndicatorFractionRounded', 304),
                 0xaf7ed8: (17165468, 'OBJC_IVAR_$_Workbench.particleCreateTimerSteamEngine', 280),
                 0xaf7edc: (17165476, 'OBJC_IVAR_$_Workbench.paused', 292),
                 0xaf7ee0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xaf7ee4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xaf8240: (17165452, 'OBJC_IVAR_$_Workbench.sound', 288),
                 0xaf8588: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xaf8590: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xaf8594: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0xaf8598: (17165416, 'OBJC_IVAR_$_Workbench.craftProgressCount', 188),
                 0xaf859c: (17165428, 'OBJC_IVAR_$_Workbench.craftingItemObject', 180),
                 0xaf85a4: (17165512, 'OBJC_IVAR_$_Workbench.paintingShader', 312),
                 0xaf85d0: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0xaf85d4: (17165516, 'OBJC_IVAR_$_Workbench.paintingTexture', 316),
                 0xaf9810: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xaf9818: (17165428, 'OBJC_IVAR_$_Workbench.craftingItemObject', 180),
                 0xaf9820: (17165516, 'OBJC_IVAR_$_Workbench.paintingTexture', 316),
                 0xaf9828: (17165512, 'OBJC_IVAR_$_Workbench.paintingShader', 312),
                 0xaf9840: (17165460, 'OBJC_IVAR_$_Workbench.fractionComplete', 264),
        },
        classes={
                 0xaf2354: (15249668, 'OBJC_CLASS_$_MJSoundManager'),
                 0xaf393c: (15249672, 'OBJC_CLASS_$_ParticleEmitter'),
                 0xaf8250: (15249668, 'OBJC_CLASS_$_MJSoundManager'),
                 0xaf8574: (15249672, 'OBJC_CLASS_$_ParticleEmitter'),
                 0xaf85c4: (15249612, 'OBJC_CLASS_$_NSArray'),
                 0xaf8bb0: (15249676, 'OBJC_CLASS_$_UIImage'),
                 0xaf8cc4: (15249680, 'OBJC_CLASS_$_CPTexture2D'),
        },
        instructions=[(11473392, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11488872, 'invalid'), (11484340, 'bl 0xaf9850'), (11503492, 'bl 0xafa040'), (11507788, 'invalid')],
        calls=[(11474668, 'blx r2'), (11474688, 'blx r3'), (11474704, 'blx r2'), (11474880, 'blx r2'), (11474900, 'blx r3'), (11474916, 'blx r2'), (11475092, 'blx r2'), (11475112, 'blx r3'), (11475128, 'blx r2'), (11475304, 'blx r2'), (11475324, 'blx r3'), (11475340, 'blx r2'), (11475516, 'blx r2'), (11475536, 'blx r3'), (11475552, 'blx r2'), (11475728, 'blx r2'), (11475748, 'blx r3'), (11475764, 'blx r2'), (11475900, 'blx r2'), (11475920, 'blx r3'), (11475936, 'blx r2'), (11476040, 'bl loc.imp.objc_msgSend'), (11476116, 'bl loc.imp.objc_msgSend'), (11476240, 'blx r3'), (11476828, 'blx r2'), (11476848, 'blx r3'), (11476864, 'blx r2'), (11477040, 'blx r2'), (11477060, 'blx r3'), (11477076, 'blx r2'), (11477332, 'blx r2'), (11477352, 'blx r3'), (11477368, 'blx r2'), (11477588, 'blx r2'), (11477608, 'blx r3'), (11477624, 'blx r2'), (11477720, 'bl loc.imp.objc_msgSend'), (11477796, 'bl loc.imp.objc_msgSend'), (11477984, 'blx r3'), (11478348, 'blx r6'), (11478368, 'blx r3'), (11478424, 'blx ip'), (11478504, 'blx r2'), (11478600, 'bl loc.imp.objc_msgSend'), (11478980, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11479048, 'bl 0xae3c5c'), (11479212, 'bl method.Vector.Vector_float__float__float_'), (11479300, 'bl loc.imp.objc_msgSend_stret'), (11479344, 'bl sym.imp.memset'), (11479856, 'bl method.Vector.Vector_float__float__float_'), (11479864, 'bl method.Vector.operator_float__'), (11479940, 'bl method.Vector.operator_float__'), (11479984, 'bl method.Vector.operator_float__'), (11480044, 'bl method.Vector.operator_float__'), (11480088, 'bl method.Vector.operator_float__'), (11480148, 'bl method.Vector.operator_float__'), (11480216, 'bl method.Vector.Vector_float__float__float_'), (11480260, 'bl method.Vector.Vector_float__float__float__float_'), (11480312, 'bl sym.Vector::operator_Vector_'), (11480372, 'bl method.Vector.Vector_float__float__float__float_'), (11480424, 'bl sym.Vector::operator_Vector_'), (11480496, 'bl loc.imp.objc_msgSend'), (11480540, 'bl 0xae3c5c'), (11480600, 'bl 0xae3c5c'), (11480668, 'bl method.Vector.Vector_float__float__float_'), (11480928, 'bl loc.imp.objc_msgSend'), (11481288, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11481428, 'bl method.Vector.Vector_float__float__float_'), (11481516, 'bl loc.imp.objc_msgSend_stret'), (11481584, 'bl sym.imp.memset'), (11482100, 'bl method.Vector.Vector_float__float__float_'), (11482108, 'bl method.Vector.operator_float__'), (11482184, 'bl method.Vector.operator_float__'), (11482228, 'bl method.Vector.operator_float__'), (11482288, 'bl method.Vector.operator_float__'), (11482332, 'bl method.Vector.operator_float__'), (11482392, 'bl method.Vector.operator_float__'), (11482464, 'bl method.Vector.Vector_float__float__float_'), (11482532, 'bl method.Vector.Vector_float__float__float__float_'), (11482540, 'bl method.Vector.operator_float__'), (11482556, 'bl method.Vector.operator_float__'), (11482572, 'bl method.Vector.operator_float__'), (11482608, 'bl method.Vector.Vector_float__float__float__float_'), (11482652, 'bl sym.Vector::operator_Vector_'), (11482720, 'bl loc.imp.objc_msgSend'), (11482728, 'bl 0xae3c5c'), (11482796, 'bl method.Vector.Vector_float__float__float_'), (11482844, 'bl method.Vector.operator_Vector_'), (11482848, 'bl 0xae3c5c'), (11482896, 'bl 0xae3c5c'), (11482944, 'bl method.Vector.Vector_float__float__float_'), (11483176, 'bl loc.imp.objc_msgSend'), (11483912, 'bl sym.imp.__modsi3'), (11483932, 'bl sym.imp.__aeabi_idiv'), (11484176, 'bl sym.updateQuadBufferTexCoords_float__int__float__float__float__float_'), (11484260, 'bl method.Vector2.operator_float__'), (11484304, 'bl method.Vector2.operator_float__'), (11484340, 'bl 0xaf9850'), (11485176, 'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_'), (11485640, 'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_'), (11486120, 'bl sym.imp.__modsi3'), (11486140, 'bl sym.imp.__aeabi_idiv'), (11486388, 'bl sym.updateQuadBufferTexCoords_float__int__float__float__float__float_'), (11486792, 'bl method.Vector2.operator_float__'), (11486836, 'bl method.Vector2.operator_float__'), (11486872, 'bl 0xaf9850'), (11487684, 'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_'), (11487876, 'bl method.Vector2.operator_float__'), (11487912, 'bl method.Vector2.operator_float__'), (11487952, 'bl 0xaf9850'), (11488856, 'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_'), (11489428, 'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_'), (11489992, 'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_'), (11490432, 'bl method.Vector2.operator_float__'), (11490488, 'bl method.Vector2.operator_float__'), (11490528, 'bl 0xaf9850'), (11490632, 'bl method.Vector2.operator_float__'), (11490676, 'bl method.Vector2.operator_float__'), (11490728, 'bl 0xaf9850'), (11491208, 'bl 0xaf98c4'), (11491244, 'bl sym.imp.memcpy'), (11492040, 'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_'), (11492172, 'bl method.Vector2.operator_float__'), (11492208, 'bl method.Vector2.operator_float__'), (11492248, 'bl 0xaf9850'), (11492620, 'bl 0xaf9c5c'), (11493208, 'bl sym.updateQuadBufferVertsAndMatrix_float__int___GLKMatrix4__float__float__float__float_'), (11493736, 'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_'), (11493880, 'blx r3'), (11494028, 'bl method.Vector2.operator_float__'), (11494064, 'bl method.Vector2.operator_float__'), (11494104, 'bl 0xaf9850'), (11494860, 'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_'), (11495028, 'blx r2'), (11495108, 'bl loc.imp.objc_msgSend'), (11495204, 'bl method.Vector2.operator_float__'), (11495240, 'bl method.Vector2.operator_float__'), (11495280, 'bl 0xaf9850'), (11495652, 'bl 0xaf9c5c'), (11496236, 'bl sym.updateQuadBufferVertsAndMatrix_float__int___GLKMatrix4__float__float__float__float_'), (11496308, 'blx r3'), (11496456, 'bl method.Vector2.operator_float__'), (11496492, 'bl method.Vector2.operator_float__'), (11496528, 'bl 0xaf9850'), (11497288, 'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_'), (11497524, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11497552, 'bl 0xae3c5c'), (11497624, 'bl 0xae3c5c'), (11497696, 'bl 0xae3c5c'), (11497788, 'bl method.Vector.Vector_float__float__float_'), (11497876, 'bl loc.imp.objc_msgSend_stret'), (11497924, 'bl sym.imp.memset'), (11498520, 'bl method.Vector.Vector_float__float__float_'), (11498528, 'bl method.Vector.operator_float__'), (11498592, 'bl method.Vector.operator_float__'), (11498624, 'bl method.Vector.operator_float__'), (11498672, 'bl method.Vector.operator_float__'), (11498704, 'bl method.Vector.operator_float__'), (11498752, 'bl method.Vector.operator_float__'), (11498808, 'bl method.Vector.Vector_float__float__float_'), (11498852, 'bl method.Vector.Vector_float__float__float__float_'), (11498900, 'bl sym.Vector::operator_Vector_'), (11498936, 'bl loc.imp.objc_msgSend'), (11498984, 'bl 0xae3c5c'), (11499036, 'bl 0xae3c5c'), (11499088, 'bl method.Vector.Vector_float__float__float_'), (11499320, 'bl loc.imp.objc_msgSend'), (11499352, 'blx r3'), (11499372, 'blx r3'), (11499428, 'blx ip'), (11499508, 'blx r2'), (11499604, 'bl loc.imp.objc_msgSend'), (11499868, 'bl loc.imp.objc_msgSend_stret'), (11499924, 'bl sym.imp.memset'), (11499936, 'bl sym.itemTypeIsPainting_ItemType_'), (11500248, 'blx ip'), (11500312, 'blx r5'), (11500356, 'blx lr'), (11500540, 'blx r2'), (11500584, 'blx r3'), (11500672, 'bl loc.imp.objc_msgSend_stret'), (11500716, 'bl sym.imp.memset'), (11500792, 'bl sym.UIGraphicsBeginImageContextWithOptions'), (11500844, 'bl 0xaf9ff4'), (11500900, 'bl loc.imp.objc_msgSend'), (11500904, 'bl sym.UIGraphicsGetImageFromCurrentImageContext'), (11500916, 'bl sym.UIGraphicsEndImageContext'), (11500992, 'blx r2'), (11501016, 'blx ip'), (11501144, 'bl loc.imp.objc_msgSend'), (11501168, 'bl sym.imp.__aeabi_idiv'), (11501236, 'bl loc.imp.objc_msgSend'), (11501384, 'bl loc.imp.objc_msgSend'), (11501400, 'bl sym.imp.__aeabi_idiv'), (11501468, 'bl loc.imp.objc_msgSend'), (11501604, 'bl loc.imp.objc_msgSend'), (11501628, 'bl sym.imp.__aeabi_idiv'), (11501696, 'bl loc.imp.objc_msgSend'), (11501832, 'bl loc.imp.objc_msgSend'), (11501848, 'bl sym.imp.__aeabi_idiv'), (11501916, 'bl loc.imp.objc_msgSend'), (11502244, 'bl method.Vector2.Vector2_float__float_'), (11502280, 'bl method.Vector2.operator_Vector2_'), (11502288, 'bl method.Vector2.operator_float__'), (11502348, 'bl loc.imp.objc_msgSend'), (11502372, 'bl sym.imp.__aeabi_idiv'), (11502464, 'bl loc.imp.objc_msgSend'), (11502496, 'bl method.Vector2.operator_float__'), (11502544, 'bl method.Vector2.operator_float__'), (11502608, 'bl loc.imp.objc_msgSend'), (11502624, 'bl sym.imp.__aeabi_idiv'), (11502716, 'bl loc.imp.objc_msgSend'), (11502748, 'bl method.Vector2.operator_float__'), (11502884, 'blx r2'), (11502932, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (11503492, 'bl 0xafa040'), (11503840, 'bl 0xaf98c4'), (11504216, 'bl 0xafa040'), (11504284, 'blx r2'), (11504288, 'bl sym.imp.__wrap_glUseProgram'), (11504420, 'blx r6'), (11504440, 'blx r3'), (11504456, 'blx r2'), (11504464, 'bl sym.imp.__wrap_glUniform1i'), (11504472, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (11504552, 'bl loc.imp.objc_msgSend_stret'), (11504600, 'bl sym.imp.memset'), (11505116, 'bl method.Vector.Vector_float__float__float_'), (11505124, 'bl method.Vector.operator_float__'), (11505184, 'bl method.Vector.operator_float__'), (11505216, 'bl method.Vector.operator_float__'), (11505264, 'bl method.Vector.operator_float__'), (11505296, 'bl method.Vector.operator_float__'), (11505344, 'bl method.Vector.operator_float__'), (11505396, 'bl method.Vector.Vector_float__float__float_'), (11505444, 'bl loc.imp.objc_msgSend'), (11505464, 'bl loc.imp.objc_msgSend'), (11505480, 'bl loc.imp.objc_msgSend'), (11505496, 'bl method.Vector.operator_float__'), (11505512, 'bl method.Vector.operator_float__'), (11505528, 'bl method.Vector.operator_float__'), (11505560, 'bl sym.imp.__wrap_glUniform4f'), (11506348, 'bl 0xafa228'), (11506484, 'blx r3'), (11506504, 'blx r3'), (11506520, 'blx r2'), (11506552, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (11506672, 'blx r2'), (11506692, 'blx r3'), (11506708, 'blx r2'), (11506740, 'bl sym.imp.__wrap_glUniform1f'), (11506820, 'blx r3'), (11506840, 'bl sym.imp.__wrap_glBindTexture'), (11506940, 'bl loc.imp.objc_msgSend_stret'), (11506980, 'bl sym.imp.memset'), (11507412, 'blx lr'), (11507468, 'blx ip'), (11507544, 'bl sym.drawShaderQuad'), (11507668, 'blx r3')],
        branches=[(11474076, 'beq', 11474360), (11474116, 'beq', 11474360), (11474156, 'beq', 11474360), (11474196, 'beq', 11474360), (11474236, 'beq', 11474360), (11474276, 'beq', 11474360), (11474316, 'beq', 11474360), (11474356, 'bne', 11476280), (11474396, 'beq', 11476124), (11474436, 'blt', 11476124), (11474480, 'bne', 11476120), (11474520, 'bne', 11476120), (11474560, 'bne', 11474736), (11474732, 'b', 11475984), (11474772, 'bne', 11474948), (11474944, 'b', 11475980), (11474984, 'bne', 11475160), (11475156, 'b', 11475976), (11475196, 'bne', 11475372), (11475368, 'b', 11475972), (11475408, 'bne', 11475584), (11475580, 'b', 11475968), (11475620, 'bne', 11475796), (11475792, 'b', 11475964), (11475964, 'b', 11475968), (11475968, 'b', 11475972), (11475972, 'b', 11475976), (11475976, 'b', 11475980), (11475980, 'b', 11475984), (11476120, 'b', 11476276), (11476164, 'beq', 11476272), (11476272, 'b', 11476276), (11476276, 'b', 11478028), (11476316, 'beq', 11476560), (11476356, 'beq', 11476560), (11476396, 'beq', 11476560), (11476436, 'beq', 11476560), (11476476, 'beq', 11476560), (11476516, 'beq', 11476560), (11476556, 'bne', 11478024), (11476596, 'beq', 11477868), (11476640, 'bne', 11477800), (11476680, 'bne', 11477800), (11476720, 'bne', 11476896), (11476892, 'b', 11477664), (11476932, 'bne', 11477108), (11477104, 'b', 11477660), (11477144, 'beq', 11477228), (11477184, 'beq', 11477228), (11477224, 'bne', 11477404), (11477396, 'b', 11477656), (11477440, 'beq', 11477484), (11477480, 'bne', 11477652), (11477652, 'b', 11477656), (11477656, 'b', 11477660), (11477660, 'b', 11477664), (11477800, 'b', 11478020), (11477908, 'beq', 11478016), (11478016, 'b', 11478020), (11478020, 'b', 11478024), (11478024, 'b', 11478028), (11478076, 'ble', 11478608), (11478116, 'bne', 11478608), (11478188, 'bpl', 11478236), (11478436, 'beq', 11478520), (11478516, 'beq', 11478604), (11478604, 'b', 11478608), (11478644, 'bne', 11480948), (11478692, 'beq', 11478760), (11478864, 'ble', 11480936), (11479004, 'beq', 11480932), (11479280, 'beq', 11479312), (11479304, 'b', 11479348), (11479468, 'bpl', 11479496), (11479488, 'b', 11479512), (11479560, 'bpl', 11479640), (11479580, 'b', 11479656), (11479704, 'ble', 11479776), (11480328, 'beq', 11480464), (11480932, 'b', 11480936), (11480936, 'b', 11483192), (11480984, 'bne', 11483188), (11481024, 'beq', 11483188), (11481080, 'ble', 11483188), (11481172, 'ble', 11483184), (11481312, 'beq', 11483180), (11481496, 'beq', 11481552), (11481520, 'b', 11481588), (11481708, 'bpl', 11481736), (11481728, 'b', 11481752), (11481800, 'bpl', 11481884), (11481820, 'b', 11481900), (11481948, 'ble', 11482020), (11483180, 'b', 11483184), (11483184, 'b', 11483188), (11483188, 'b', 11483192), (11483292, 'ble', 11483496), (11483404, 'blt', 11483448), (11483448, 'b', 11483248), (11483536, 'beq', 11497356), (11483584, 'beq', 11497356), (11483656, 'bne', 11497356), (11483728, 'ble', 11497356), (11483768, 'bne', 11485712), (11483784, 'beq', 11485648), (11484216, 'beq', 11485184), (11485180, 'b', 11485644), (11485644, 'b', 11485648), (11485648, 'b', 11497352), (11485748, 'beq', 11485792), (11485788, 'bne', 11486496), (11485804, 'beq', 11486392), (11485864, 'bhi', 11485988), (11485920, 'b', 11485992), (11485936, 'b', 11485992), (11485952, 'b', 11485992), (11485968, 'b', 11485992), (11485984, 'b', 11485992), (11485988, 'b', 11485992), (11486392, 'b', 11497348), (11486532, 'beq', 11486696), (11486572, 'beq', 11486696), (11486612, 'beq', 11486696), (11486652, 'beq', 11486696), (11486692, 'bne', 11490016), (11486708, 'beq', 11490004), (11486748, 'beq', 11488912), (11487724, 'bne', 11488864), (11487832, 'beq', 11488860), (11488860, 'b', 11488864), (11488864, 'b', 11490000), (11488948, 'beq', 11489432), (11489468, 'bne', 11489996), (11489508, 'beq', 11489996), (11489996, 'b', 11490000), (11490000, 'b', 11490004), (11490004, 'b', 11497344), (11490052, 'beq', 11490256), (11490092, 'beq', 11490256), (11490132, 'beq', 11490256), (11490172, 'beq', 11490256), (11490212, 'beq', 11490256), (11490252, 'bne', 11493772), (11490292, 'beq', 11493220), (11490332, 'blt', 11493220), (11490372, 'bne', 11492044), (11490580, 'bne', 11491296), (11491248, 'b', 11491356), (11491332, 'beq', 11491340), (11491336, 'b', 11491340), (11491352, 'b', 11491356), (11492080, 'bne', 11493212), (11493212, 'b', 11493744), (11493256, 'beq', 11493740), (11493740, 'b', 11493744), (11493744, 'b', 11497340), (11493808, 'bne', 11494932), (11493956, 'beq', 11494864), (11494864, 'b', 11497336), (11494968, 'bne', 11497332), (11495064, 'ble', 11496240), (11496384, 'beq', 11497328), (11497292, 'b', 11497328), (11497328, 'b', 11497332), (11497332, 'b', 11497336), (11497336, 'b', 11497340), (11497340, 'b', 11497344), (11497344, 'b', 11497348), (11497348, 'b', 11497352), (11497352, 'b', 11497356), (11497404, 'ble', 11499616), (11497444, 'bne', 11499616), (11497548, 'beq', 11499612), (11497856, 'beq', 11497892), (11497880, 'b', 11497928), (11498048, 'bpl', 11498076), (11498068, 'b', 11498092), (11498140, 'bpl', 11498188), (11498160, 'b', 11498204), (11498252, 'ble', 11498324), (11499440, 'beq', 11499524), (11499520, 'beq', 11499608), (11499608, 'b', 11499612), (11499612, 'b', 11499616), (11499652, 'bne', 11507708), (11499696, 'beq', 11507552), (11499744, 'ble', 11507552), (11499788, 'beq', 11507552), (11499852, 'beq', 11499896), (11499872, 'b', 11499928), (11499948, 'beq', 11507552), (11499992, 'bne', 11500384), (11500424, 'bne', 11501044), (11500608, 'bne', 11500920), (11500652, 'beq', 11500684), (11500676, 'b', 11500720), (11501180, 'blt', 11501288), (11501268, 'b', 11501504), (11501412, 'bge', 11501500), (11501500, 'b', 11501504), (11501640, 'blt', 11501736), (11501728, 'b', 11501952), (11501860, 'bge', 11501948), (11501948, 'b', 11501952), (11501996, 'blt', 11502136), (11502044, 'bgt', 11502136), (11502088, 'blt', 11502136), (11502132, 'ble', 11502164), (11502136, 'b', 11507708), (11502396, 'ble', 11502520), (11502516, 'b', 11502772), (11502648, 'bpl', 11502768), (11502768, 'b', 11502772), (11502956, 'bne', 11503076), (11502960, 'b', 11507708), (11504536, 'beq', 11504572), (11504556, 'b', 11504604), (11504724, 'bpl', 11504744), (11504740, 'b', 11504756), (11504800, 'bpl', 11504912), (11504816, 'b', 11504924), (11504968, 'ble', 11505040), (11506920, 'beq', 11506948), (11506944, 'b', 11506984), (11507004, 'bhi', 11507260), (11507076, 'b', 11507264), (11507092, 'b', 11507264), (11507124, 'b', 11507264), (11507156, 'b', 11507264), (11507184, 'b', 11507264), (11507208, 'b', 11507264), (11507232, 'b', 11507264), (11507252, 'b', 11507264), (11507260, 'b', 11507264), (11507548, 'b', 11507704), (11507592, 'beq', 11507700), (11507700, 'b', 11507704), (11507704, 'b', 11507708)],
        semantics=('[Workbench draw:...] (imp 0x00af11f0, 8600w): the workbench render - the second-largest body in the project. Census (259 calls): **`fillQuadBuffer(...)` x10** (the E41/E44/E73 quad-emit family) + the quad-buffer API pair **`updateQuadBufferTexCoords(float*, int, f,f,f,f)` x2 + `updateQuadBufferVertsAndMatrix(float*, int, _GLKMatrix4*, f,f,f,f)` x2** + **`itemTypeIsPainting(ItemType)`** (the painting-aware draw!); 30x Vector::operator float* + 22x Vector2 + 15x Vector3 ctors (5 four-float) + the helper 0xae3c5c x11 + objc x29 + stret x7 + memset x7 + memcpy + idiv x8 + modsi3 x2; the float pool pins the sprite fractions **-0.99 (x8), -0.98, 0.9 (x2), 0.2, -1.4, -0.2** and the crafted-item sizing triple **0.8078 / 0.8549 / 0.8863**.\n'),
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
        'batch': 'Workbench twin giants closure (E80): the update and draw censuses; 2 bodies',
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
                        default=NATIVE / 'workbench_giants.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale workbench_giants.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
