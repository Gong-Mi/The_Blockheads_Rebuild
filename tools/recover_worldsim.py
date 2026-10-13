#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The World simulation core: the tick giant, the render-prep giant, the simulation
pump, the event filter and the GPU-owning teardown: the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 22239 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/WORLD_SIMULATION.md for the prose and boundaries.
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
    'bl 0x564c54': 0x00564c54,
    'bl 0x582eb4': 0x00582eb4,
    'bl 0x583288': 0x00583288,
    'bl 0x58353c': 0x0058353c,
    'bl 0x58b764': 0x0058b764,
    'bl 0x58b7b4': 0x0058b7b4,
    'bl 0x58b99c': 0x0058b99c,
    'bl 0x58bbd8': 0x0058bbd8,
    'bl 0x58c198': 0x0058c198,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.operator_float__': 0x004b5c08,
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl method.Vector2.length___const': 0x0057509c,
    'bl method.Vector2.normal__': 0x00575108,
    'bl method.Vector2.operator_Vector2_': 0x004d0418,
    'bl method.Vector2.operator__Vector2_': 0x004d04b4,
    'bl method.Vector2.operator_float_': 0x004d0368,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl sym.absoluteSeasonFraction_double_': 0x00a149f8,
    'bl sym.baseTemperatureForWorldPos_intpair__float__float__float__World_': 0x00a14f28,
    'bl sym.clamp_float__float__float_': 0x004be068,
    'bl sym.getWorldUpVectorForX_float__World_': 0x00a148b0,
    'bl sym.imp.NSLog': 0x001c2a5c,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__aeabi_uidiv': 0x001c3710,
    'bl sym.imp.__umodsi3': 0x001c2f9c,
    'bl sym.imp.__wrap_fmodf': 0x001c3d4c,
    'bl sym.imp.__wrap_free': 0x001c2e64,
    'bl sym.imp.__wrap_glDeleteTextures': 0x001c2cf0,
    'bl sym.imp.cos': 0x001c2948,
    'bl sym.imp.floor': 0x001c323c,
    'bl sym.imp.fmod': 0x001c3f8c,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.itemTypeIsSolid_ItemType_': 0x004daf58,
    'bl sym.itemTypeIsSowable_ItemType_': 0x0056871c,
    'bl sym.linearInterpolate_float__float__float_': 0x00582a14,
    'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_': 0x00a16ccc,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.polarToRectangular_double__double_': 0x00582e00,
    'bl sym.recalculateDrawBlockLightingForTile_int__int__MacroTile__World_': 0x00a18f68,
    'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_': 0x00a1915c,
    'bl sym.seasonForWorldX_int__double__World_': 0x00a14a48,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
}

SPECS = [
    dict(
        name='ws_00',
        method='World -[setServer:]',
        types='v12@0:4@8',
        start=5655652,
        end=5656364,
        disasm='disasm_worldtileloader_ws_00.txt',
        base_add=5655668,
        base_literal=5656360,
        boundary='ARM.exidx end 0x00564f2c (listing bound); next ObjC IMP 0x00564f2c World -[deleteTimers]',
        selectors={
                 0x564f00: (15195732, 'retain'),
                 0x564f08: (15195860, 'autorelease'),
                 0x564f0c: (15195892, 'init'),
                 0x564f10: (15195752, 'alloc'),
                 0x564f18: (15196192, 'setServer:'),
                 0x564f20: (15196188, 'setServer:serverClients:'),
        },
        imports={
                 0x564efc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x564ef8: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x564f04: (17155964, 'OBJC_IVAR_$_World.serverClients', 956),
                 0x564f1c: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x564f24: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={
                 0x564f14: (15245288, 'OBJC_CLASS_$_NSMutableDictionary'),
        },
        instructions=[(5655652, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5656360, 'adceq sl, pc, r8, ror lr')],
        calls=[(5655828, 'blx r3'), (5655876, 'blx ip'), (5655932, 'blx lr'), (5656052, 'blx r2'), (5656068, 'blx r2'), (5656244, 'blx r4'), (5656300, 'blx lr')],
        branches=[(5655720, 'bne', 5655728), (5655724, 'b', 5656304), (5655980, 'beq', 5656092)],
        semantics=('[World setServer:] (imp 0x00564c64, 178w): the server hook - objc x6 + ivar x4 + the 0x5-family consts.\n'),
    ),
    dict(
        name='ws_01',
        method='World -[deleteTimers]',
        types='v8@0:4',
        start=5656364,
        end=5656792,
        disasm='disasm_worldtileloader_ws_01.txt',
        base_add=5656380,
        base_literal=5656788,
        boundary='ARM.exidx end 0x005650d8 (listing bound); next ObjC IMP 0x005650d8 World -[dealloc]',
        selectors={
                 0x5650b8: (15196200, 'deleteTimers'),
                 0x5650c4: (15195860, 'autorelease'),
                 0x5650c8: (15196204, 'dismissWithClickedButtonIndex:animated:'),
                 0x5650d0: (15196196, 'stopObservingMotionEvents'),
        },
        imports={
                 0x5650b4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5650bc: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x5650c0: (17156348, 'OBJC_IVAR_$_World.reportAlertView', 3424),
                 0x5650cc: (17156024, 'OBJC_IVAR_$_World.clientTileLoader', 972),
        },
        classes={},
        instructions=[(5656364, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5656788, 'invalid')],
        calls=[(5656552, 'blx ip'), (5656588, 'blx r3'), (5656636, 'blx ip'), (5656672, 'blx r3'), (5656744, 'blx r4')],
        branches=[],
        semantics=('[World deleteTimers] (imp 0x00564f2c, 107w): the timer teardown - objc x4 + ivar x3.\n'),
    ),
    dict(
        name='ws_02',
        method='World -[dealloc]',
        types='v8@0:4',
        start=5656792,
        end=5663048,
        disasm='disasm_worldtileloader_ws_02.txt',
        base_add=5656808,
        base_literal=5660620,
        boundary='ARM.exidx end 0x00566948 (listing bound); next ObjC IMP 0x00566948 World -[startObservingMotionEvents]',
        selectors={
                 0x565fd8: (15196208, 'finishBulkDatabaseUpdate'),
                 0x565fe0: (15195768, 'release'),
                 0x565fec: (15196200, 'deleteTimers'),
                 0x56602c: (15196196, 'stopObservingMotionEvents'),
                 0x566068: (15196212, 'setNeedsToExit:'),
                 0x566890: (15195768, 'release'),
                 0x5668a4: (15196228, 'dealloc'),
                 0x5668d4: (15196224, 'cancel'),
                 0x566930: (15195860, 'autorelease'),
                 0x566934: (15196220, 'setDelegate:'),
                 0x566938: (15196216, 'textFieldAtIndex:'),
        },
        imports={
                 0x565fd0: (16231288, '__CFConstantStringClassReference'),
                 0x565fd4: (17151904, 'objc_msgSend'),
                 0x56688c: (17151904, 'objc_msgSend'),
                 0x5668a0: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0x565fdc: (17156032, 'OBJC_IVAR_$_World.foundItemsList', 3376),
                 0x565fe4: (17156044, 'OBJC_IVAR_$_World.tutorial', 232),
                 0x565fe8: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x565ff0: (17156144, 'OBJC_IVAR_$_World.weather', 156),
                 0x565ff4: (17156264, 'OBJC_IVAR_$_World.portalChestManager', 3336),
                 0x565ff8: (17156332, 'OBJC_IVAR_$_World.freeClientLightBlockIndices', 496),
                 0x565ffc: (17155964, 'OBJC_IVAR_$_World.serverClients', 956),
                 0x566000: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x566004: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x566008: (17156028, 'OBJC_IVAR_$_World.clientPassword', 3292),
                 0x56600c: (17155932, 'OBJC_IVAR_$_World.serverPassword', 3288),
                 0x566010: (17156020, 'OBJC_IVAR_$_World.creationDate', 452),
                 0x566014: (17156016, 'OBJC_IVAR_$_World.maxPlayers', 448),
                 0x566018: (17156012, 'OBJC_IVAR_$_World.hostPort', 444),
                 0x56601c: (17156352, 'OBJC_IVAR_$_World.zoomPlayerCycleCounts', 3340),
                 0x566020: (17156356, 'OBJC_IVAR_$_World.mutedPlayers', 3284),
                 0x566024: (17156308, 'OBJC_IVAR_$_World.saveQueue', 3188),
                 0x566028: (17156336, 'OBJC_IVAR_$_World.motionManager', 4),
                 0x566030: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
                 0x566038: (17156340, 'OBJC_IVAR_$_World.macroTiles', 412),
                 0x56603c: (17156292, 'OBJC_IVAR_$_World.netEventsMessageToDisplayOnceLoaded', 3152),
                 0x566040: (17156360, 'OBJC_IVAR_$_World.awayClientSimulationEvents', 3148),
                 0x566044: (17156224, 'OBJC_IVAR_$_World.skyPixelData', 912),
                 0x566048: (17156228, 'OBJC_IVAR_$_World.mapPixelData', 3184),
                 0x56604c: (17155892, 'OBJC_IVAR_$_World.worldName', 440),
                 0x566050: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x566054: (17156252, 'OBJC_IVAR_$_World.projectileManager', 3204),
                 0x566058: (17156256, 'OBJC_IVAR_$_World.pathQueue', 428),
                 0x56605c: (17156260, 'OBJC_IVAR_$_World.pathCreator', 424),
                 0x566060: (17156024, 'OBJC_IVAR_$_World.clientTileLoader', 972),
                 0x566064: (17156104, 'OBJC_IVAR_$_World.worldTileLoader', 420),
                 0x566894: (17156364, 'OBJC_IVAR_$_World.usedPhysicalBlocks', 456),
                 0x566898: (17156368, 'OBJC_IVAR_$_World.freePhysicalBlocks', 476),
                 0x56689c: (17156240, 'OBJC_IVAR_$_World.numDrawBlocks', 508),
                 0x5668ac: (17156076, 'OBJC_IVAR_$_World.databaseEnvironment', 3392),
                 0x5668b0: (17156080, 'OBJC_IVAR_$_World.blockDatabase', 3404),
                 0x5668b4: (17156072, 'OBJC_IVAR_$_World.dynamicObjectDatabase', 3400),
                 0x5668b8: (17156056, 'OBJC_IVAR_$_World.mainDatabase', 3396),
                 0x5668bc: (17155952, 'OBJC_IVAR_$_World.customRulesDict', 224),
                 0x5668c0: (17156372, 'OBJC_IVAR_$_World.ownershipAreaRenderer', 3332),
                 0x5668c4: (17155948, 'OBJC_IVAR_$_World.ownershipSignPositions', 3324),
                 0x5668c8: (17155940, 'OBJC_IVAR_$_World.worldPriceMultipliers', 3240),
                 0x5668cc: (17156376, 'OBJC_IVAR_$_World.globalPrices', 3236),
                 0x5668d0: (17156380, 'OBJC_IVAR_$_World.sendPricesConnection', 3220),
                 0x5668d8: (17155900, 'OBJC_IVAR_$_World.saveID', 436),
                 0x5668dc: (17156088, 'OBJC_IVAR_$_World.multiplayerLoadDict', 952),
                 0x5668e0: (17156040, 'OBJC_IVAR_$_World.distanceOrderedFoodTypes', 948),
                 0x5668e4: (17156384, 'OBJC_IVAR_$_World.clientTCMinedIndices', 3180),
                 0x5668e8: (17156048, 'OBJC_IVAR_$_World.circumNavigateBooleans', 3084),
                 0x5668ec: (17156000, 'OBJC_IVAR_$_World.portalScreenshotData', 3076),
                 0x5668f0: (17156232, 'OBJC_IVAR_$_World.dayColorCloudyImageData', 908),
                 0x5668f4: (17156236, 'OBJC_IVAR_$_World.dayColorImageData', 904),
                 0x5668f8: (17156148, 'OBJC_IVAR_$_World.weatherNoiseFunction', 656),
                 0x5668fc: (17156156, 'OBJC_IVAR_$_World.lightsShader', 612),
                 0x566900: (17156200, 'OBJC_IVAR_$_World.starShader', 600),
                 0x566904: (17156212, 'OBJC_IVAR_$_World.blackCubeShader', 596),
                 0x566908: (17156216, 'OBJC_IVAR_$_World.blackTileShader', 592),
                 0x56690c: (17156220, 'OBJC_IVAR_$_World.buttonShader', 580),
                 0x566910: (17156168, 'OBJC_IVAR_$_World.blockTransparentShader', 576),
                 0x566914: (17156172, 'OBJC_IVAR_$_World.blockShader', 572),
                 0x566918: (17156124, 'OBJC_IVAR_$_World.skyShader', 568),
                 0x56691c: (17156196, 'OBJC_IVAR_$_World.buttonTexture', 536),
                 0x566920: (17156116, 'OBJC_IVAR_$_World.skyTexture', 528),
                 0x566924: (17156388, 'OBJC_IVAR_$_World.tileButtonIndices', 520),
                 0x566928: (17156392, 'OBJC_IVAR_$_World.reportedPlayerName', 3432),
                 0x56692c: (17156396, 'OBJC_IVAR_$_World.messageEntryAlertView', 3436),
                 0x56693c: (17156244, 'OBJC_IVAR_$_World.drawBlocks', 504),
                 0x566940: (17156248, 'OBJC_IVAR_$_World.drawBlockIndices', 500),
        },
        classes={
                 0x5668a8: (15252576, 'OBJC_CLASS_$_World'),
        },
        instructions=[(5656792, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5663044, 'andeq r0, r0, r0')],
        calls=[(5656860, 'blx ip'), (5656876, 'bl sym.imp.NSLog'), (5657220, 'blx r3'), (5657256, 'blx r3'), (5657292, 'blx r3'), (5657328, 'blx r3'), (5657364, 'blx r3'), (5657400, 'blx r3'), (5657436, 'blx r3'), (5657472, 'blx r3'), (5657508, 'blx r3'), (5657544, 'blx r3'), (5657580, 'blx r3'), (5657616, 'blx r3'), (5657652, 'blx r3'), (5657688, 'blx r3'), (5657724, 'blx r3'), (5657760, 'blx r3'), (5657796, 'blx r3'), (5657832, 'blx r3'), (5657868, 'blx r3'), (5657904, 'blx r3'), (5658080, 'blx ip'), (5658416, 'blx r3'), (5658452, 'blx r3'), (5658488, 'blx r3'), (5658524, 'blx r3'), (5658560, 'blx r3'), (5658596, 'blx r3'), (5658632, 'blx r3'), (5658692, 'blx lr'), (5658728, 'blx r3'), (5658764, 'blx r3'), (5658800, 'blx r3'), (5658836, 'blx r3'), (5658860, 'bl sym.imp.__wrap_free'), (5659292, 'bl sym.imp.__wrap_free'), (5659348, 'bl sym.imp.__wrap_free'), (5659356, 'bl sym.imp.__wrap_free'), (5659840, 'bl sym.imp.__wrap_free'), (5659896, 'bl sym.imp.__wrap_free'), (5659904, 'bl sym.imp.__wrap_free'), (5660188, 'bl sym.imp.__wrap_free'), (5660240, 'bl sym.imp.__wrap_free'), (5660252, 'bl sym.imp.__wrap_free'), (5660264, 'bl sym.imp.__wrap_free'), (5660276, 'bl sym.imp.__wrap_free'), (5660308, 'bl sym.imp.__wrap_glDeleteTextures'), (5660340, 'bl sym.imp.__wrap_free'), (5660372, 'bl sym.imp.__wrap_free'), (5660404, 'bl sym.imp.__wrap_free'), (5660436, 'bl sym.imp.__wrap_free'), (5660468, 'bl sym.imp.__wrap_free'), (5660500, 'bl sym.imp.__wrap_free'), (5660532, 'bl sym.imp.__wrap_free'), (5660564, 'bl sym.imp.__wrap_free'), (5660596, 'bl sym.imp.__wrap_free'), (5660808, 'bl sym.imp.__wrap_free'), (5660840, 'bl sym.imp.__wrap_free'), (5661292, 'blx r3'), (5661312, 'blx r3'), (5661352, 'blx r3'), (5661388, 'blx r3'), (5661460, 'blx r4'), (5661496, 'blx r3'), (5661532, 'blx r3'), (5661568, 'blx r3'), (5661604, 'blx r3'), (5661640, 'blx r3'), (5661676, 'blx r3'), (5661712, 'blx r3'), (5661748, 'blx r3'), (5661784, 'blx r3'), (5661820, 'blx r3'), (5661856, 'blx r3'), (5661892, 'blx r3'), (5661928, 'blx r3'), (5661964, 'blx r3'), (5662000, 'blx r3'), (5662036, 'blx r3'), (5662072, 'blx r3'), (5662096, 'bl sym.imp.__wrap_free'), (5662376, 'blx lr'), (5662412, 'blx r3'), (5662448, 'blx r3'), (5662484, 'blx r3'), (5662520, 'blx r3'), (5662556, 'blx r3'), (5662592, 'blx r3'), (5662628, 'blx r3'), (5662664, 'blx r3'), (5662700, 'blx r3'), (5662736, 'blx r3'), (5662772, 'blx r3'), (5662808, 'blx r3'), (5662848, 'blx r2')],
        branches=[(5657984, 'bge', 5658144), (5658140, 'b', 5657936), (5659164, 'beq', 5659420), (5659212, 'bge', 5659340), (5659252, 'beq', 5659320), (5659320, 'b', 5659324), (5659336, 'b', 5659204), (5659416, 'b', 5659016), (5659712, 'beq', 5659968), (5659760, 'bge', 5659888), (5659800, 'beq', 5659868), (5659868, 'b', 5659872), (5659884, 'b', 5659752), (5659964, 'b', 5659564), (5660012, 'bge', 5660780), (5660084, 'bge', 5660232), (5660096, 'beq', 5660212), (5660108, 'beq', 5660212), (5660120, 'beq', 5660212), (5660140, 'bge', 5660208), (5660204, 'b', 5660132), (5660208, 'b', 5660212), (5660212, 'b', 5660216), (5660228, 'b', 5660076), (5660292, 'beq', 5660312), (5660328, 'beq', 5660344), (5660360, 'beq', 5660376), (5660392, 'beq', 5660408), (5660424, 'beq', 5660440), (5660456, 'beq', 5660472), (5660488, 'beq', 5660504), (5660520, 'beq', 5660536), (5660552, 'beq', 5660568), (5660584, 'beq', 5660600), (5660600, 'b', 5660604), (5660616, 'b', 5659976)],
        semantics=('[World dealloc] (imp 0x005650d8, 1564w): the giant teardown - **`__wrap_free` x24** + NSLog + **`__wrap_glDeleteTextures`** (the world owns GPU textures - the only glDeleteTextures of the simulation family) + ivar x68 + const 0x14/0x1f8 (504).\n'),
    ),
    dict(
        name='ws_03',
        method='World -[startSimulatingIfNeeded]',
        types='c8@0:4',
        start=5664356,
        end=5666876,
        disasm='disasm_worldtileloader_ws_03.txt',
        base_add=5664372,
        base_literal=5666872,
        boundary='ARM.exidx end 0x0056783c (listing bound); next ObjC IMP 0x0056783c World -[isSimulating]',
        selectors={
                 0x567798: (15195848, 'intValue'),
                 0x56779c: (15195928, 'valueForKey:'),
                 0x5677a4: (15195924, 'stringByAppendingString:'),
                 0x5677a8: (15195920, 'worldName'),
                 0x5677ac: (15195916, 'standardUserDefaults'),
                 0x5677c8: (15195844, 'timeIntervalSinceReferenceDate'),
                 0x5677cc: (15195728, 'date'),
                 0x5677d4: (15195620, 'countByEnumeratingWithState:objects:count:'),
                 0x5677d8: (15195692, 'blockheads'),
                 0x5677e0: (15196264, 'asleep'),
                 0x5677e4: (15196268, 'regenerating'),
                 0x5677e8: (15196272, 'hasActions'),
                 0x5677ec: (15196276, 'actionCount'),
                 0x5677f0: (15196280, 'shouldContinueSimulating'),
                 0x5677fc: (15196288, 'setStopAllParticles:'),
                 0x567800: (15195544, 'instance'),
                 0x567808: (15196284, 'setDontPlayAnySounds:'),
                 0x567810: (15195676, 'setPaused:'),
                 0x567818: (15195892, 'init'),
                 0x56781c: (15195752, 'alloc'),
        },
        imports={
                 0x567790: (16231304, '__CFConstantStringClassReference'),
                 0x567794: (17151904, 'objc_msgSend'),
                 0x5677a0: (16229592, '__CFConstantStringClassReference'),
                 0x567834: (16231320, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5677b4: (17156412, 'OBJC_IVAR_$_World.isSimulating', 3140),
                 0x5677b8: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5677bc: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x5677c0: (17156044, 'OBJC_IVAR_$_World.tutorial', 232),
                 0x5677c4: (17156068, 'OBJC_IVAR_$_World.lastUpdateTime', 3112),
                 0x5677dc: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5677f4: (17156416, 'OBJC_IVAR_$_World.totalNumberOfActionsToSimulate', 3128),
                 0x567814: (17156420, 'OBJC_IVAR_$_World.simulationEvents', 3144),
                 0x567828: (17156424, 'OBJC_IVAR_$_World.simulationProgress', 3136),
                 0x56782c: (17156428, 'OBJC_IVAR_$_World.totalTimeToSimulate', 3132),
                 0x567830: (17156432, 'OBJC_IVAR_$_World.timeLeftToSimulate', 3120),
        },
        classes={
                 0x5677b0: (15245352, 'OBJC_CLASS_$_NSUserDefaults'),
                 0x5677d0: (15245312, 'OBJC_CLASS_$_NSDate'),
                 0x567804: (15245388, 'OBJC_CLASS_$_ParticleEmitter'),
                 0x56780c: (15245280, 'OBJC_CLASS_$_MJSoundManager'),
                 0x567820: (15245288, 'OBJC_CLASS_$_NSMutableDictionary'),
        },
        instructions=[(5664356, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5666872, 'adceq r8, pc, r8, ror ip')],
        calls=[(5664548, 'blx ip'), (5664580, 'blx r3'), (5664612, 'blx r3'), (5664644, 'blx r3'), (5664660, 'blx r2'), (5664676, 'bl sym.imp.NSLog'), (5664704, 'bl sym.imp.NSLog'), (5665068, 'blx r3'), (5665084, 'blx r2'), (5665284, 'blx r2'), (5665332, 'bl sym.imp.memset'), (5665380, 'blx lr'), (5665480, 'bl sym.imp.objc_enumerationMutation'), (5665552, 'blx r2'), (5665628, 'blx r2'), (5665704, 'blx r2'), (5665768, 'blx r2'), (5665824, 'blx r2'), (5665948, 'blx ip'), (5666172, 'blx r2'), (5666196, 'blx r3'), (5666228, 'blx r3'), (5666252, 'blx r3'), (5666600, 'blx r2'), (5666616, 'blx r2'), (5666680, 'blx lr')],
        branches=[(5664688, 'ble', 5664720), (5664716, 'b', 5666692), (5664752, 'beq', 5664768), (5664764, 'b', 5666692), (5664804, 'bne', 5664848), (5664844, 'beq', 5664860), (5664856, 'b', 5666692), (5664896, 'beq', 5664912), (5664908, 'b', 5666692), (5664960, 'bpl', 5664976), (5664972, 'b', 5666692), (5665144, 'bpl', 5665160), (5665156, 'b', 5666692), (5665392, 'beq', 5665972), (5665472, 'beq', 5665484), (5665564, 'beq', 5665588), (5665640, 'beq', 5665664), (5665716, 'beq', 5665784), (5665836, 'beq', 5665848), (5665848, 'b', 5665852), (5665876, 'blo', 5665436), (5665968, 'bne', 5665436), (5665972, 'b', 5665976), (5666016, 'bne', 5666032), (5666028, 'b', 5666692), (5666296, 'bpl', 5666312), (5666308, 'b', 5666328)],
        semantics=('[World startSimulatingIfNeeded] (imp 0x00566e64, 630w): the simulation start - NSLog x2 + memset + **fast enumeration** + sel x20 + consts 0x10/0x20 + the **0x15180 (86400 = one day in seconds!)** data cell.\n'),
    ),
    dict(
        name='ws_04',
        method='World -[addSimulationEventOfType:forBlockhead:extraData:]',
        types='v20@0:4i8@12@16',
        start=5666936,
        end=5670684,
        disasm='disasm_worldtileloader_ws_04.txt',
        base_add=5666952,
        base_literal=5670680,
        boundary='ARM.exidx end 0x0056871c (listing bound); next ObjC IMP 0x0056884c World -[continueSimulate]',
        selectors={
                 0x5686a8: (15196280, 'shouldContinueSimulating'),
                 0x5686ac: (15196292, 'isClientBlockheadBeingControlledByServer'),
                 0x5686b0: (15195624, 'objectForKey:'),
                 0x5686b4: (15196304, 'numberWithUnsignedLong:'),
                 0x5686c4: (15196300, 'uniqueID'),
                 0x5686c8: (15195584, 'setObject:forKey:'),
                 0x5686d4: (15195684, 'dictionary'),
                 0x5686d8: (15196044, 'name'),
                 0x5686e4: (15195892, 'init'),
                 0x5686e8: (15195752, 'alloc'),
                 0x5686ec: (15196296, 'clientID'),
                 0x5686f8: (15195572, 'numberWithInt:'),
                 0x568700: (15195848, 'intValue'),
                 0x568710: (15196312, 'itemType'),
                 0x568714: (15196308, 'craftableItem'),
        },
        imports={
                 0x5686a4: (17151904, 'objc_msgSend'),
                 0x5686dc: (16231336, '__CFConstantStringClassReference'),
                 0x5686fc: (16231400, '__CFConstantStringClassReference'),
                 0x568704: (16231352, '__CFConstantStringClassReference'),
                 0x568708: (16231384, '__CFConstantStringClassReference'),
                 0x56870c: (16231368, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5686b8: (17156420, 'OBJC_IVAR_$_World.simulationEvents', 3144),
                 0x5686e0: (17156360, 'OBJC_IVAR_$_World.awayClientSimulationEvents', 3148),
        },
        classes={
                 0x5686c0: (15245292, 'OBJC_CLASS_$_NSNumber'),
                 0x5686cc: (15245288, 'OBJC_CLASS_$_NSMutableDictionary'),
        },
        instructions=[(5666936, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5670680, 'adceq r8, pc, r4, ror 4')],
        calls=[(5667008, 'blx r4'), (5667092, 'blx r2'), (5667216, 'blx r2'), (5667232, 'blx r2'), (5667308, 'blx r3'), (5667428, 'blx lr'), (5667460, 'blx r3'), (5667584, 'blx r5'), (5667644, 'blx r3'), (5667680, 'blx ip'), (5667788, 'bl loc.imp.objc_msgSend'), (5667828, 'blx r3'), (5667860, 'blx r3'), (5667964, 'bl loc.imp.objc_msgSend'), (5668000, 'bl loc.imp.objc_msgSend'), (5668040, 'bl loc.imp.objc_msgSend'), (5668096, 'bl loc.imp.objc_msgSend'), (5668136, 'blx r3'), (5668172, 'blx ip'), (5668300, 'bl loc.imp.objc_msgSend'), (5668340, 'blx r3'), (5668372, 'blx r3'), (5668476, 'bl loc.imp.objc_msgSend'), (5668512, 'bl loc.imp.objc_msgSend'), (5668552, 'bl loc.imp.objc_msgSend'), (5668628, 'bl loc.imp.objc_msgSend'), (5668668, 'blx r3'), (5668704, 'blx ip'), (5668804, 'blx lr'), (5668836, 'blx r3'), (5668960, 'blx r5'), (5669016, 'blx r3'), (5669052, 'blx ip'), (5669128, 'bl loc.imp.objc_msgSend_stret'), (5669164, 'bl sym.imp.memset'), (5669288, 'blx ip'), (5669328, 'blx r3'), (5669352, 'blx r2'), (5669408, 'blx r3'), (5669456, 'blx ip'), (5669604, 'blx r5'), (5669644, 'blx ip'), (5669684, 'blx r3'), (5669708, 'blx r2'), (5669760, 'blx r3'), (5669808, 'blx ip'), (5669868, 'blx r2'), (5669880, 'bl sym.itemTypeIsSolid_ItemType_'), (5669940, 'bl sym.itemTypeIsSowable_ItemType_'), (5670096, 'blx r7'), (5670120, 'blx r2'), (5670172, 'blx r3'), (5670220, 'blx ip'), (5670304, 'blx ip'), (5670460, 'blx r7'), (5670476, 'blx r2'), (5670504, 'blx r3'), (5670540, 'blx ip')],
        branches=[(5667024, 'bne', 5667044), (5667036, 'bne', 5667044), (5667040, 'b', 5670556), (5667104, 'beq', 5668180), (5667144, 'bne', 5667256), (5667320, 'bne', 5667328), (5667324, 'b', 5670556), (5667480, 'bne', 5667684), (5667880, 'bne', 5668176), (5668176, 'b', 5668712), (5668392, 'bne', 5668708), (5668708, 'b', 5668712), (5668856, 'bne', 5669056), (5669064, 'bne', 5669464), (5669112, 'beq', 5669136), (5669132, 'b', 5669168), (5669460, 'b', 5670556), (5669472, 'bne', 5669816), (5669812, 'b', 5670552), (5669824, 'bne', 5670228), (5669912, 'beq', 5669936), (5669932, 'b', 5669976), (5669952, 'beq', 5669972), (5669972, 'b', 5669976), (5670224, 'b', 5670548), (5670236, 'bne', 5670312), (5670308, 'b', 5670544), (5670544, 'b', 5670548), (5670548, 'b', 5670552), (5670552, 'b', 5670556)],
        semantics=('[World addSimulationEventOfType:forBlockhead:extraData:] (imp 0x00567878, 937w): the event adder - objc x10 + **`itemTypeIsSolid(ItemType)` + `itemTypeIsSowable(ItemType)`** (the event filter gate!) + memset + const 0x7c (124).\n'),
    ),
    dict(
        name='ws_05',
        method='World -[continueSimulate]',
        types='c8@0:4',
        start=5670988,
        end=5681784,
        disasm='disasm_worldtileloader_ws_05.txt',
        base_add=5671008,
        base_literal=5674072,
        boundary='ARM.exidx end 0x0056b278 (listing bound); next ObjC IMP 0x0056b278 World -[finishSimulating]',
        selectors={
                 0x569468: (15195604, 'count'),
                 0x56946c: (15195692, 'blockheads'),
                 0x569474: (15195620, 'countByEnumeratingWithState:objects:count:'),
                 0x569a5c: (15196264, 'asleep'),
                 0x569a60: (15196316, 'meditating'),
                 0x569a64: (15196268, 'regenerating'),
                 0x569a68: (15196320, 'onTradeMission'),
                 0x569a70: (15196324, 'cancelSimulateDueToCollapse'),
                 0x569a74: (15196272, 'hasActions'),
                 0x569a78: (15196328, 'currentInteractionRequiresHumanInput'),
                 0x569a7c: (15196276, 'actionCount'),
                 0x56a020: (15196280, 'shouldContinueSimulating'),
                 0x56a264: (15196332, 'finishSimulating'),
                 0x56a270: (15196336, 'simulate:'),
                 0x56a27c: (15196344, 'decommisionAllBlocksBlockToSavePhyscialBlock:'),
                 0x56a280: (15196340, 'saveAll'),
                 0x56a284: (15196348, 'pathUsers'),
                 0x56a288: (15196352, 'pathNeedsRecalculated'),
                 0x56a778: (15196356, 'infoForPathRecalculation'),
                 0x56a77c: (15195848, 'intValue'),
                 0x56a784: (15195624, 'objectForKey:'),
                 0x56a794: (15195800, 'objectAtIndex:'),
                 0x56a79c: (15196360, 'removeObjectAtIndex:'),
                 0x56aa4c: (15196372, 'inProgress'),
                 0x56aa54: (15196368, 'setPathNeedsRecalculated:'),
                 0x56aabc: (15195700, 'addObject:'),
                 0x56aac0: (15196364, 'setWaitingForPathToPos:'),
                 0x56aac4: (15196376, 'hasPath'),
                 0x56aac8: (15196380, 'pathUser'),
                 0x56aacc: (15196384, 'pathType'),
                 0x56aad0: (15196388, 'abortPath'),
                 0x56aad4: (15196392, 'createPathWithDict:'),
                 0x56aad8: (15195860, 'autorelease'),
                 0x56aadc: (15195732, 'retain'),
                 0x56b034: (15196396, 'updatePath'),
                 0x56b1e4: (15195620, 'countByEnumeratingWithState:objects:count:'),
                 0x56b1e8: (15196332, 'finishSimulating'),
                 0x56b1ec: (15196344, 'decommisionAllBlocksBlockToSavePhyscialBlock:'),
                 0x56b1f0: (15196340, 'saveAll'),
                 0x56b1f4: (15195624, 'objectForKey:'),
                 0x56b200: (15196372, 'inProgress'),
                 0x56b208: (15196376, 'hasPath'),
                 0x56b20c: (15196380, 'pathUser'),
                 0x56b210: (15196384, 'pathType'),
                 0x56b214: (15196400, 'path'),
                 0x56b218: (15196412, 'goalInteraction'),
                 0x56b21c: (15196408, 'goalY'),
                 0x56b220: (15196404, 'goalX'),
                 0x56b234: (15196436, 'paintingAtPos:'),
                 0x56b238: (15196420, 'extraData'),
                 0x56b23c: (15196440, 'paintingTapped:'),
                 0x56b244: (15196444, 'activeBlockhead'),
                 0x56b248: (15196448, 'setInventoryUIToExpanded:'),
                 0x56b24c: (15196424, 'setPath:type:goalInteraction:extraData:'),
                 0x56b254: (15196428, 'interactionObjectAtPos:'),
                 0x56b25c: (15196432, 'interactionObjectTapped:hasCancel:'),
                 0x56b264: (15196416, 'workbenchAtPos:'),
                 0x56b26c: (15196452, 'setNoLongerWaitingForPath'),
                 0x56b270: (15196456, 'setHasPath:'),
        },
        imports={
                 0x569464: (17151904, 'objc_msgSend'),
                 0x56a780: (16231432, '__CFConstantStringClassReference'),
                 0x56a788: (16231416, '__CFConstantStringClassReference'),
                 0x56a790: (16231448, '__CFConstantStringClassReference'),
                 0x56a798: (16231464, '__CFConstantStringClassReference'),
                 0x56b1dc: (17151904, 'objc_msgSend'),
                 0x56b1fc: (16231448, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x56945c: (17156412, 'OBJC_IVAR_$_World.isSimulating', 3140),
                 0x569460: (17156432, 'OBJC_IVAR_$_World.timeLeftToSimulate', 3120),
                 0x569470: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x569a6c: (17155960, 'OBJC_IVAR_$_World.fastForward', 934),
                 0x56a024: (17156428, 'OBJC_IVAR_$_World.totalTimeToSimulate', 3132),
                 0x56a028: (17156416, 'OBJC_IVAR_$_World.totalNumberOfActionsToSimulate', 3128),
                 0x56a02c: (17156424, 'OBJC_IVAR_$_World.simulationProgress', 3136),
                 0x56a268: (17156060, 'OBJC_IVAR_$_World.customRules', 160),
                 0x56a26c: (17156364, 'OBJC_IVAR_$_World.usedPhysicalBlocks', 456),
                 0x56a274: (17155920, 'OBJC_IVAR_$_World.noRainTimer', 940),
                 0x56a278: (17155924, 'OBJC_IVAR_$_World.worldTime', 648),
                 0x56a78c: (17156256, 'OBJC_IVAR_$_World.pathQueue', 428),
                 0x56aa50: (17156260, 'OBJC_IVAR_$_World.pathCreator', 424),
                 0x56b1d4: (17156412, 'OBJC_IVAR_$_World.isSimulating', 3140),
                 0x56b1d8: (17156432, 'OBJC_IVAR_$_World.timeLeftToSimulate', 3120),
                 0x56b1e0: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x56b1f8: (17156256, 'OBJC_IVAR_$_World.pathQueue', 428),
                 0x56b204: (17156260, 'OBJC_IVAR_$_World.pathCreator', 424),
                 0x56b224: (17156324, 'OBJC_IVAR_$_World.isMod', 3210),
                 0x56b228: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x56b22c: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x56b240: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
        },
        classes={},
        instructions=[(5670988, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5681780, 'andeq r0, r0, r0')],
        calls=[(5671272, 'blx lr'), (5671312, 'blx r3'), (5671404, 'bl sym.imp.memset'), (5671452, 'blx lr'), (5671552, 'bl sym.imp.objc_enumerationMutation'), (5671624, 'blx r2'), (5671680, 'blx r2'), (5671736, 'blx r2'), (5671792, 'blx r2'), (5671928, 'blx ip'), (5672408, 'blx r2'), (5672456, 'bl sym.imp.memset'), (5672504, 'blx lr'), (5672604, 'bl sym.imp.objc_enumerationMutation'), (5672676, 'blx r2'), (5672732, 'blx r2'), (5672808, 'blx r2'), (5672884, 'blx r2'), (5672940, 'blx r2'), (5673004, 'blx r2'), (5673060, 'blx r2'), (5673188, 'blx ip'), (5673956, 'blx r3'), (5674332, 'blx r3'), (5674472, 'blx lr'), (5674500, 'blx r3'), (5674620, 'blx r2'), (5674644, 'bl sym.imp.memset'), (5674692, 'blx lr'), (5674792, 'bl sym.imp.objc_enumerationMutation'), (5674864, 'blx r2'), (5674932, 'blx r3'), (5675044, 'blx r4'), (5675060, 'blx r2'), (5675096, 'blx r3'), (5675112, 'blx r2'), (5675136, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5675240, 'blx r2'), (5675356, 'blx lr'), (5675384, 'blx r3'), (5675464, 'blx lr'), (5675500, 'blx r3'), (5675584, 'blx r3'), (5675768, 'bl loc.imp.objc_msgSend'), (5675820, 'bl loc.imp.objc_msgSend'), (5675844, 'bl loc.imp.objc_msgSend'), (5675884, 'bl loc.imp.objc_msgSend'), (5675900, 'bl loc.imp.objc_msgSend'), (5675924, 'bl sym.makeIntpair_int__int_'), (5675952, 'bl loc.imp.objc_msgSend'), (5675980, 'blx r3'), (5676016, 'blx r3'), (5676092, 'blx r2'), (5676168, 'blx r2'), (5676284, 'blx r2'), (5676320, 'blx r3'), (5676336, 'blx r2'), (5676412, 'blx r2'), (5676528, 'blx ip'), (5676616, 'blx r2'), (5676692, 'blx r2'), (5676768, 'blx r2'), (5676964, 'blx r3'), (5676980, 'blx r2'), (5676996, 'blx r2'), (5677040, 'blx r3'), (5677080, 'blx ip'), (5677176, 'blx r3'), (5677260, 'blx r3'), (5677356, 'blx r3'), (5677492, 'blx r2'), (5677632, 'blx lr'), (5677660, 'blx r3'), (5677772, 'blx r2'), (5677848, 'blx r2'), (5677980, 'blx r6'), (5678020, 'blx r3'), (5678060, 'blx r3'), (5678140, 'blx r2'), (5678260, 'blx r4'), (5678300, 'blx r3'), (5678340, 'blx r3'), (5678420, 'bl sym.makeIntpair_int__int_'), (5678448, 'bl loc.imp.objc_msgSend'), (5678532, 'bl sym.makeIntpair_int__int_'), (5678560, 'bl loc.imp.objc_msgSend'), (5678656, 'blx r3'), (5678808, 'blx r6'), (5678856, 'blx ip'), (5678904, 'blx ip'), (5678956, 'blx r4'), (5679068, 'blx r2'), (5679148, 'bl sym.makeIntpair_int__int_'), (5679176, 'bl loc.imp.objc_msgSend'), (5679260, 'bl sym.makeIntpair_int__int_'), (5679288, 'bl loc.imp.objc_msgSend'), (5679384, 'blx r3'), (5679536, 'blx r6'), (5679584, 'blx ip'), (5679632, 'blx ip'), (5679684, 'blx r4'), (5679788, 'blx ip'), (5680024, 'blx r2'), (5680104, 'bl sym.makeIntpair_int__int_'), (5680132, 'bl loc.imp.objc_msgSend'), (5680228, 'blx r3'), (5680312, 'blx r3'), (5680396, 'blx r2'), (5680508, 'blx ip'), (5680664, 'blx r6'), (5680712, 'blx ip'), (5680760, 'blx ip'), (5680812, 'blx r4'), (5680920, 'bl sym.imp.memset'), (5680984, 'blx lr'), (5681084, 'bl sym.imp.objc_enumerationMutation'), (5681176, 'blx lr'), (5681308, 'blx ip'), (5681392, 'blx r2'), (5681476, 'blx ip'), (5681572, 'blx r2')],
        branches=[(5671052, 'bne', 5671068), (5671064, 'b', 5681608), (5671128, 'bpl', 5671144), (5671140, 'b', 5671156), (5671320, 'bls', 5671960), (5671464, 'beq', 5671952), (5671544, 'beq', 5671556), (5671636, 'bne', 5671820), (5671692, 'bne', 5671820), (5671748, 'bne', 5671816), (5671804, 'bne', 5671816), (5671816, 'b', 5671828), (5671828, 'b', 5671832), (5671856, 'blo', 5671508), (5671948, 'bne', 5671508), (5671952, 'b', 5671956), (5671956, 'b', 5671960), (5671968, 'beq', 5672060), (5671980, 'beq', 5672060), (5672016, 'bne', 5672052), (5672052, 'b', 5672132), (5672092, 'beq', 5672128), (5672128, 'b', 5672132), (5672164, 'beq', 5672232), (5672228, 'b', 5672276), (5672516, 'beq', 5673212), (5672596, 'beq', 5672608), (5672688, 'bne', 5673088), (5672744, 'beq', 5672768), (5672820, 'beq', 5672844), (5672896, 'beq', 5673020), (5672952, 'bne', 5673020), (5673072, 'beq', 5673084), (5673084, 'b', 5673088), (5673088, 'b', 5673092), (5673116, 'blo', 5672560), (5673208, 'bne', 5672560), (5673212, 'b', 5673216), (5673224, 'ble', 5673892), (5673296, 'bgt', 5673352), (5673348, 'bpl', 5673608), (5673468, 'bpl', 5673484), (5673480, 'b', 5673492), (5673540, 'bpl', 5673556), (5673552, 'b', 5673564), (5673604, 'b', 5673888), (5673736, 'bpl', 5673752), (5673748, 'b', 5673764), (5673816, 'bpl', 5673832), (5673828, 'b', 5673844), (5673888, 'b', 5673892), (5673900, 'bne', 5673972), (5673968, 'b', 5681608), (5674020, 'beq', 5674164), (5674056, 'bne', 5674104), (5674068, 'b', 5674160), (5674136, 'bne', 5674156), (5674156, 'b', 5674160), (5674160, 'b', 5674164), (5674396, 'bls', 5674504), (5674704, 'beq', 5676552), (5674784, 'beq', 5674796), (5674876, 'beq', 5676428), (5674952, 'beq', 5676424), (5675156, 'beq', 5676420), (5675252, 'bhs', 5675648), (5675396, 'bne', 5675592), (5675512, 'bne', 5675592), (5675588, 'b', 5675648), (5675592, 'b', 5675596), (5675608, 'b', 5675172), (5676028, 'bne', 5676108), (5676104, 'beq', 5676416), (5676180, 'bne', 5676416), (5676348, 'bne', 5676416), (5676416, 'b', 5676420), (5676420, 'b', 5676424), (5676424, 'b', 5676428), (5676428, 'b', 5676432), (5676456, 'blo', 5674748), (5676548, 'bne', 5674748), (5676552, 'b', 5676556), (5676628, 'bne', 5677104), (5676704, 'bne', 5677104), (5676776, 'bls', 5677084), (5677084, 'b', 5677712), (5677280, 'beq', 5677400), (5677376, 'bne', 5677400), (5677408, 'beq', 5677708), (5677556, 'bls', 5677664), (5677664, 'b', 5677188), (5677708, 'b', 5677712), (5677784, 'bne', 5681480), (5677860, 'beq', 5681480), (5678076, 'beq', 5678160), (5678348, 'bne', 5679008), (5678468, 'bne', 5678568), (5678580, 'beq', 5678964), (5678668, 'beq', 5678960), (5678960, 'b', 5678964), (5678964, 'b', 5680824), (5679076, 'bne', 5679840), (5679196, 'bne', 5679296), (5679308, 'beq', 5679796), (5679396, 'beq', 5679704), (5679688, 'b', 5679792), (5679792, 'b', 5679796), (5679796, 'b', 5680820), (5679880, 'beq', 5680328), (5679920, 'bne', 5679964), (5679960, 'beq', 5680328), (5680032, 'bne', 5680328), (5680152, 'beq', 5680324), (5680240, 'bne', 5680320), (5680320, 'b', 5680324), (5680324, 'b', 5680328), (5680408, 'bne', 5680512), (5680424, 'beq', 5680512), (5680524, 'bne', 5680816), (5680816, 'b', 5680820), (5680820, 'b', 5680824), (5680996, 'beq', 5681332), (5681076, 'beq', 5681088), (5681188, 'bne', 5681208), (5681200, 'b', 5681336), (5681208, 'b', 5681212), (5681236, 'blo', 5681040), (5681328, 'bne', 5681040), (5681332, 'b', 5681336), (5681348, 'bne', 5681396), (5681528, 'bpl', 5681576)],
        semantics=('[World continueSimulate] (imp 0x0056884c, 2699w): the simulation pump - objc x11 + makeIntpair x6 + **fast enumeration x4** + memset x4 + tileAtWorldPositionLoaded + sel x59 + consts 0x10/0x20/0x14/0x1e (30): the per-tick world sweep.\n'),
    ),
    dict(
        name='ws_06',
        method='World -[finishSimulating]',
        types='v8@0:4',
        start=5681784,
        end=5682804,
        disasm='disasm_worldtileloader_ws_06.txt',
        base_add=5681800,
        base_literal=5682800,
        boundary='ARM.exidx end 0x0056b674 (listing bound); next ObjC IMP 0x0056b674 World -[welcomeBackMessageForInfoDict:]',
        selectors={
                 0x56b61c: (15196464, 'pauseButtonTapped'),
                 0x56b620: (15195676, 'setPaused:'),
                 0x56b62c: (15195768, 'release'),
                 0x56b630: (15196140, 'showWelcomeBackPopupWithMessage:'),
                 0x56b634: (15196460, 'welcomeBackMessageForInfoDict:'),
                 0x56b63c: (15196288, 'setStopAllParticles:'),
                 0x56b640: (15195544, 'instance'),
                 0x56b648: (15196284, 'setDontPlayAnySounds:'),
                 0x56b654: (15195844, 'timeIntervalSinceReferenceDate'),
                 0x56b658: (15195728, 'date'),
                 0x56b66c: (15196332, 'finishSimulating'),
        },
        imports={
                 0x56b618: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x56b624: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x56b628: (17156420, 'OBJC_IVAR_$_World.simulationEvents', 3144),
                 0x56b650: (17156068, 'OBJC_IVAR_$_World.lastUpdateTime', 3112),
                 0x56b660: (17156412, 'OBJC_IVAR_$_World.isSimulating', 3140),
                 0x56b664: (17156432, 'OBJC_IVAR_$_World.timeLeftToSimulate', 3120),
                 0x56b668: (17156424, 'OBJC_IVAR_$_World.simulationProgress', 3136),
        },
        classes={
                 0x56b644: (15245388, 'OBJC_CLASS_$_ParticleEmitter'),
                 0x56b64c: (15245280, 'OBJC_CLASS_$_MJSoundManager'),
                 0x56b65c: (15245312, 'OBJC_CLASS_$_NSDate'),
        },
        instructions=[(5681784, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5682800, 'adceq r4, pc, r4, ror 16')],
        calls=[(5682216, 'blx ip'), (5682316, 'blx lr'), (5682332, 'blx r2'), (5682384, 'blx r2'), (5682408, 'blx r3'), (5682440, 'blx r3'), (5682464, 'blx r3'), (5682536, 'blx r3'), (5682568, 'blx r3'), (5682604, 'blx r3'), (5682672, 'blx r4'), (5682692, 'blx r2')],
        branches=[],
        semantics=('[World finishSimulating] (imp 0x0056b278, 255w): the simulation end - sel x11 + memset + the 0x15180 (86400) data cell shared with the start family.\n'),
    ),
    dict(
        name='ws_07',
        method='World -[simulationProgress]',
        types='f8@0:4',
        start=5692728,
        end=5692792,
        disasm='disasm_worldtileloader_ws_07.txt',
        base_add=5692752,
        base_literal=5692788,
        boundary='ARM.exidx end 0x0056dd78 (listing bound); next ObjC IMP 0x0056dd78 World -[update:accurateDT:pinchScale:dragInProgress:]',
        selectors={},
        imports={},
        ivars={
                 0x56dd70: (17156424, 'OBJC_IVAR_$_World.simulationProgress', 3136),
        },
        classes={},
        instructions=[(5692728, 'sub sp, sp, 8'), (5692788, 'umlaleq r1, pc, ip, sp')],
        calls=[],
        branches=[],
        semantics=('[World simulationProgress] (imp 0x0056dd38, 16w): the progress accessor (ivar x1).\n'),
    ),
    dict(
        name='ws_08',
        method='World -[update:accurateDT:pinchScale:dragInProgress:]',
        types='v28@0:4f8f12d16c24',
        start=5692792,
        end=5722268,
        disasm='disasm_worldtileloader_ws_08.txt',
        base_add=5692820,
        base_literal=5695808,
        boundary='ARM.exidx end 0x0057509c (listing bound); next ObjC IMP 0x005751f8 World -[decommisionAllBlocksBlockToSavePhyscialBlock:]',
        selectors={
                 0x56e950: (15196480, 'continueSimulate'),
                 0x56ee7c: (15195616, 'gameBlockingUIDisplayed'),
                 0x56ee88: (15195620, 'countByEnumeratingWithState:objects:count:'),
                 0x56ee8c: (15196348, 'pathUsers'),
                 0x56ee94: (15196352, 'pathNeedsRecalculated'),
                 0x56ee98: (15196356, 'infoForPathRecalculation'),
                 0x56ee9c: (15195848, 'intValue'),
                 0x56eea4: (15195624, 'objectForKey:'),
                 0x56f1b8: (15195604, 'count'),
                 0x56f1c4: (15195800, 'objectAtIndex:'),
                 0x56f1cc: (15196360, 'removeObjectAtIndex:'),
                 0x56f1d0: (15196372, 'inProgress'),
                 0x56f1d8: (15196368, 'setPathNeedsRecalculated:'),
                 0x56f1e0: (15195700, 'addObject:'),
                 0x56f1e4: (15196364, 'setWaitingForPathToPos:'),
                 0x56f1e8: (15196376, 'hasPath'),
                 0x56f1ec: (15196380, 'pathUser'),
                 0x56f1f0: (15196384, 'pathType'),
                 0x56f1f4: (15196388, 'abortPath'),
                 0x56f74c: (15196392, 'createPathWithDict:'),
                 0x56f750: (15195860, 'autorelease'),
                 0x56f754: (15195732, 'retain'),
                 0x56f758: (15196396, 'updatePath'),
                 0x56f75c: (15196400, 'path'),
                 0x56fb44: (15196412, 'goalInteraction'),
                 0x56fb48: (15196408, 'goalY'),
                 0x56fb4c: (15196404, 'goalX'),
                 0x56fb54: (15196416, 'workbenchAtPos:'),
                 0x56fc7c: (15196420, 'extraData'),
                 0x56fc80: (15196424, 'setPath:type:goalInteraction:extraData:'),
                 0x56fc88: (15196428, 'interactionObjectAtPos:'),
                 0x56fc90: (15196432, 'interactionObjectTapped:hasCancel:'),
                 0x56fca0: (15196436, 'paintingAtPos:'),
                 0x56fca4: (15196440, 'paintingTapped:'),
                 0x56fca8: (15196444, 'activeBlockhead'),
                 0x56fcac: (15196448, 'setInventoryUIToExpanded:'),
                 0x5707ac: (15196452, 'setNoLongerWaitingForPath'),
                 0x5707b0: (15196456, 'setHasPath:'),
                 0x5707b8: (15195844, 'timeIntervalSinceReferenceDate'),
                 0x5707bc: (15195728, 'date'),
                 0x5707c4: (15196484, 'updateIdleTimerDisabled'),
                 0x5707cc: (15196488, 'isCloudGame'),
                 0x5707e0: (15196492, 'showLowCreditWarningWithMinutes:'),
                 0x570e84: (15195688, 'array'),
                 0x570f90: (15195672, 'connected'),
                 0x570f94: (15195624, 'objectForKey:'),
                 0x570ff0: (15196500, 'getIndexes:maxCount:inIndexRange:'),
                 0x570ff4: (15196496, 'requestedBlockIndices'),
                 0x571000: (15196508, 'loadPhysicalBlockForMacroTile:atX:y:loadSurroundingBlocks:createIfNotCreated:'),
                 0x571004: (15196504, 'createIfNotCreatedForBlockRequest:'),
                 0x571278: (15196512, 'sendBlockToClientWithoutSavingForBlock:pos:sendToClient:server:sendDynamicObjects:reliable:'),
                 0x57127c: (15195640, 'sendNetworkData:toPeers:reliable:'),
                 0x571280: (15196516, 'arrayWithObject:'),
                 0x571288: (15195632, 'appendBytes:length:'),
                 0x57128c: (15195552, 'dataWithBytes:length:'),
                 0x571294: (15196520, 'removeBlockRequest:'),
                 0x571298: (15196524, 'requestsHeartBeat'),
                 0x57129c: (15195636, 'heartbeatData'),
                 0x5712a0: (15196536, 'setTimeSinceLastHeartbeatRequest:'),
                 0x5712a4: (15196532, 'setRequestsHeartBeat:'),
                 0x5712a8: (15196528, 'setHasEverRequestedHeartbeat:'),
                 0x5712ac: (15196540, 'isControllingBlockheadsForClientPlayer:'),
                 0x5712b0: (15195700, 'addObject:'),
                 0x5712b4: (15195620, 'countByEnumeratingWithState:objects:count:'),
                 0x5712bc: (15196544, 'lightBlockIndex'),
                 0x571b2c: (15196552, 'clientFinishedAwaySimulation:'),
                 0x571b30: (15196548, 'removeDynamicObjectsBelongingToClient:'),
                 0x571b38: (15195736, 'removeObjectForKey:'),
                 0x571b3c: (15196176, 'addIndex:'),
                 0x571b44: (15195604, 'count'),
                 0x571b48: (15196556, 'sendPlayerChangedNotifcationToDelegate'),
                 0x571b54: (15196560, 'connectionToServerLostShouldRetry:'),
                 0x571fc0: (15196564, 'connectionToServerOK'),
                 0x571fcc: (15195644, 'sendDataToServer:reliable:'),
                 0x571fd0: (15195612, 'appendData:'),
                 0x571fd4: (15195608, 'gzipDeflate'),
                 0x572320: (15196568, 'secondaryTouchCancelled'),
                 0x572488: (15196576, 'displayed'),
                 0x57248c: (15196572, 'tradePortalUI'),
                 0x57258c: (15195768, 'release'),
                 0x5725a0: (15195616, 'gameBlockingUIDisplayed'),
                 0x572830: (15196580, 'dataWithJSONObject:options:error:'),
                 0x57283c: (15195924, 'stringByAppendingString:'),
                 0x57284c: (15195584, 'setObject:forKey:'),
                 0x572854: (15195684, 'dictionary'),
                 0x572ad0: (15196584, 'localizedDescription'),
                 0x572ad4: (15195732, 'retain'),
                 0x572ad8: (15196616, 'connectionWithRequest:delegate:'),
                 0x572ae0: (15196612, 'setHTTPBody:'),
                 0x572ae8: (15196608, 'setValue:forHTTPHeaderField:'),
                 0x572af0: (15195708, 'stringWithFormat:'),
                 0x572af4: (15195652, 'length'),
                 0x572c4c: (15196604, 'setHTTPMethod:'),
                 0x572c8c: (15196600, 'requestWithURL:cachePolicy:timeoutInterval:'),
                 0x572c90: (15196596, 'URLWithString:'),
                 0x572c9c: (15196592, 'stringFromMD5'),
                 0x572ca0: (15195860, 'autorelease'),
                 0x572ca4: (15196588, 'initWithData:encoding:'),
                 0x572ca8: (15195752, 'alloc'),
                 0x572ec0: (15195892, 'init'),
                 0x573018: (15195628, 'paused'),
                 0x57301c: (15195624, 'objectForKey:'),
                 0x573334: (15195620, 'countByEnumeratingWithState:objects:count:'),
                 0x57333c: (15196620, 'distanceTravelledThisDPadMovementSinceLastRequest'),
                 0x573340: (15196444, 'activeBlockhead'),
                 0x573550: (15196624, 'requiresMotionEvents'),
                 0x573798: (15196628, 'addBlockheadUI'),
                 0x57379c: (15196632, 'center:'),
                 0x5737a4: (15196636, 'blockheadUI'),
                 0x5737a8: (15196640, 'regenerateUI'),
                 0x5737ac: (15196644, 'cameraPos'),
                 0x57416c: (15195540, 'setTranslation:'),
                 0x574b54: (15196576, 'displayed'),
                 0x574b58: (15196572, 'tradePortalUI'),
                 0x574b60: (15196648, 'updateTradePricesIfNeeded'),
                 0x574b64: (15195604, 'count'),
                 0x574b68: (15196652, 'allBlockheadsIncludingNet'),
                 0x574dec: (15196264, 'asleep'),
                 0x574df0: (15196316, 'meditating'),
                 0x574df4: (15196268, 'regenerating'),
                 0x574df8: (15196320, 'onTradeMission'),
                 0x574efc: (15196656, 'isIdle'),
                 0x574ff4: (15196444, 'activeBlockhead'),
                 0x575004: (15196624, 'requiresMotionEvents'),
                 0x57500c: (15196660, 'beingControlledByDPad'),
                 0x575014: (15196464, 'pauseButtonTapped'),
                 0x575018: (15195680, 'sendHeartbeatData'),
                 0x57501c: (15195664, 'play'),
                 0x575024: (15195660, 'multiSoundNamed:'),
                 0x575028: (15195544, 'instance'),
                 0x575048: (15196664, 'update:'),
                 0x575060: (15196692, 'setMotion:'),
                 0x575064: (15196668, 'motionShouldBeDiscreteValues'),
                 0x575068: (15196696, 'motionFractions'),
                 0x57506c: (15196672, 'dpad'),
                 0x575080: (15196676, 'leftPressed'),
                 0x575084: (15196680, 'rightPressed'),
                 0x575088: (15196684, 'downPressed'),
                 0x57508c: (15196688, 'upPressed'),
                 0x575094: (15196700, 'update:accurateDT:'),
        },
        imports={
                 0x56e94c: (17151904, 'objc_msgSend'),
                 0x56eea0: (16231432, '__CFConstantStringClassReference'),
                 0x56eea8: (16231416, '__CFConstantStringClassReference'),
                 0x56f1c0: (16231448, '__CFConstantStringClassReference'),
                 0x56f1c8: (16231464, '__CFConstantStringClassReference'),
                 0x5707c8: (17151904, 'objc_msgSend'),
                 0x57259c: (17151904, 'objc_msgSend'),
                 0x572838: (16231944, '__CFConstantStringClassReference'),
                 0x572840: (16231928, '__CFConstantStringClassReference'),
                 0x572848: (16231912, '__CFConstantStringClassReference'),
                 0x572850: (16231896, '__CFConstantStringClassReference'),
                 0x57285c: (16231880, '__CFConstantStringClassReference'),
                 0x572acc: (16231960, '__CFConstantStringClassReference'),
                 0x572ae4: (16232072, '__CFConstantStringClassReference'),
                 0x572aec: (16232056, '__CFConstantStringClassReference'),
                 0x572afc: (16232040, '__CFConstantStringClassReference'),
                 0x572b00: (16231992, '__CFConstantStringClassReference'),
                 0x572b04: (16232024, '__CFConstantStringClassReference'),
                 0x572c44: (16232008, '__CFConstantStringClassReference'),
                 0x572c48: (16231976, '__CFConstantStringClassReference'),
                 0x572eb8: (16232088, '__CFConstantStringClassReference'),
                 0x574b50: (17151904, 'objc_msgSend'),
                 0x574fe4: (17151904, 'objc_msgSend'),
                 0x575020: (16228936, '__CFConstantStringClassReference'),
                 0x575030: (16228920, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x56e944: (17156412, 'OBJC_IVAR_$_World.isSimulating', 3140),
                 0x56e948: (17156436, 'OBJC_IVAR_$_World.dragInProgress', 108),
                 0x56ee80: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x56ee84: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x56ee90: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x56f1bc: (17156256, 'OBJC_IVAR_$_World.pathQueue', 428),
                 0x56f1d4: (17156260, 'OBJC_IVAR_$_World.pathCreator', 424),
                 0x56fc94: (17156324, 'OBJC_IVAR_$_World.isMod', 3210),
                 0x56fc98: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5707b4: (17156068, 'OBJC_IVAR_$_World.lastUpdateTime', 3112),
                 0x5707d0: (17155988, 'OBJC_IVAR_$_World.clientsideCredit', 3300),
                 0x5707d4: (17155992, 'OBJC_IVAR_$_World.clientAddedCreditTimer', 3304),
                 0x5707d8: (17156440, 'OBJC_IVAR_$_World.hasShown1MinuteCreditWarning', 3308),
                 0x5707dc: (17156444, 'OBJC_IVAR_$_World.clientSideCreditWarningDelay', 3312),
                 0x5707e8: (17156448, 'OBJC_IVAR_$_World.hasShown10MinuteCreditWarning', 3309),
                 0x570c6c: (17156452, 'OBJC_IVAR_$_World.hasShown1HourCreditWarning', 3310),
                 0x570c70: (17155964, 'OBJC_IVAR_$_World.serverClients', 956),
                 0x570ff8: (17156340, 'OBJC_IVAR_$_World.macroTiles', 412),
                 0x570ffc: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
                 0x57126c: (17156104, 'OBJC_IVAR_$_World.worldTileLoader', 420),
                 0x571274: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x5712b8: (17156364, 'OBJC_IVAR_$_World.usedPhysicalBlocks', 456),
                 0x571b34: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x571b40: (17156332, 'OBJC_IVAR_$_World.freeClientLightBlockIndices', 496),
                 0x571b4c: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x571b50: (17155976, 'OBJC_IVAR_$_World.clientLastGotHeartbeatCounter', 1004),
                 0x571fbc: (17156456, 'OBJC_IVAR_$_World.connectionToServerLost', 968),
                 0x571fc4: (17156460, 'OBJC_IVAR_$_World.sendHeartbeatRequestTimer', 1000),
                 0x571fc8: (17156060, 'OBJC_IVAR_$_World.customRules', 160),
                 0x572324: (17155896, 'OBJC_IVAR_$_World.expertMode', 228),
                 0x572480: (17156464, 'OBJC_IVAR_$_World.unsentMultiplayerTradeTransactions', 3244),
                 0x572484: (17156468, 'OBJC_IVAR_$_World.multiplayerServerSendTradeTransactionTimer', 3256),
                 0x572490: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x572590: (17156472, 'OBJC_IVAR_$_World.unsentGlobalTradeTransactions', 3248),
                 0x572594: (17156380, 'OBJC_IVAR_$_World.sendPricesConnection', 3220),
                 0x572598: (17156476, 'OBJC_IVAR_$_World.sendTradeTransactionTimer', 3252),
                 0x572844: (17155900, 'OBJC_IVAR_$_World.saveID', 436),
                 0x572ebc: (17156480, 'OBJC_IVAR_$_World.sendPricesRecieveData', 3224),
                 0x573014: (17155964, 'OBJC_IVAR_$_World.serverClients', 956),
                 0x573338: (17155984, 'OBJC_IVAR_$_World.serverReportsAllPaused', 3088),
                 0x573344: (17155860, 'OBJC_IVAR_$_World.accurateTranslation', 624),
                 0x573554: (17156436, 'OBJC_IVAR_$_World.dragInProgress', 108),
                 0x573558: (17156484, 'OBJC_IVAR_$_World.followingBlockhead', 3345),
                 0x57355c: (17155980, 'OBJC_IVAR_$_World.hideUIType', 3068),
                 0x57378c: (17155884, 'OBJC_IVAR_$_World.translationGoal', 632),
                 0x573794: (17155872, 'OBJC_IVAR_$_World.pinchScale', 400),
                 0x5737a0: (17155912, 'OBJC_IVAR_$_World.startPortalPos', 144),
                 0x5737b0: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x573ee8: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
                 0x5743f8: (17156488, 'OBJC_IVAR_$_World.translatingToGoal', 640),
                 0x574b5c: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x574b6c: (17155960, 'OBJC_IVAR_$_World.fastForward', 934),
                 0x574f00: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x574fe8: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x574fec: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x574ff0: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x574ff8: (17156060, 'OBJC_IVAR_$_World.customRules', 160),
                 0x574ffc: (17156340, 'OBJC_IVAR_$_World.macroTiles', 412),
                 0x575000: (17156364, 'OBJC_IVAR_$_World.usedPhysicalBlocks', 456),
                 0x575008: (17155960, 'OBJC_IVAR_$_World.fastForward', 934),
                 0x575010: (17156492, 'OBJC_IVAR_$_World.pauseIdleTimer', 3264),
                 0x575034: (17156496, 'OBJC_IVAR_$_World.saveCount', 936),
                 0x575038: (17156500, 'OBJC_IVAR_$_World.needsToDoPortalScreenshot', 3073),
                 0x57503c: (17155920, 'OBJC_IVAR_$_World.noRainTimer', 940),
                 0x575040: (17155924, 'OBJC_IVAR_$_World.worldTime', 648),
                 0x575044: (17156024, 'OBJC_IVAR_$_World.clientTileLoader', 972),
                 0x57504c: (17156252, 'OBJC_IVAR_$_World.projectileManager', 3204),
                 0x575050: (17156304, 'OBJC_IVAR_$_World.dpadControl', 3372),
                 0x575058: (17156504, 'OBJC_IVAR_$_World.moveLeftRightFraction', 116),
                 0x57505c: (17156508, 'OBJC_IVAR_$_World.moveUpDownFraction', 120),
                 0x575070: (17156512, 'OBJC_IVAR_$_World.xSmooth', 124),
        },
        classes={
                 0x5707c0: (15245312, 'OBJC_CLASS_$_NSDate'),
                 0x570e88: (15245300, 'OBJC_CLASS_$_NSMutableArray'),
                 0x571284: (15245308, 'OBJC_CLASS_$_NSArray'),
                 0x571290: (15245284, 'OBJC_CLASS_$_NSMutableData'),
                 0x571fd8: (15245320, 'OBJC_CLASS_$_NSData'),
                 0x572834: (15245444, 'OBJC_CLASS_$_NSJSONSerialization'),
                 0x572858: (15245288, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x572adc: (15245456, 'OBJC_CLASS_$_NSURLConnection'),
                 0x572af8: (15245304, 'OBJC_CLASS_$_NSString'),
                 0x572c94: (15245452, 'OBJC_CLASS_$_NSURL'),
                 0x572c98: (15245448, 'OBJC_CLASS_$_NSMutableURLRequest'),
                 0x57502c: (15245280, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(5692792, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5722264, 'adceq fp, lr, r8, asr r2')],
        calls=[(5692984, 'blx r3'), (5693116, 'blx r2'), (5693204, 'blx r2'), (5693376, 'blx r2'), (5693400, 'bl sym.imp.memset'), (5693448, 'blx lr'), (5693548, 'bl sym.imp.objc_enumerationMutation'), (5693620, 'blx r2'), (5693688, 'blx r3'), (5693800, 'blx r4'), (5693816, 'blx r2'), (5693852, 'blx r3'), (5693868, 'blx r2'), (5693892, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5693996, 'blx r2'), (5694112, 'blx lr'), (5694140, 'blx r3'), (5694220, 'blx lr'), (5694256, 'blx r3'), (5694340, 'blx r3'), (5694488, 'bl loc.imp.objc_msgSend'), (5694540, 'bl loc.imp.objc_msgSend'), (5694564, 'bl loc.imp.objc_msgSend'), (5694604, 'bl loc.imp.objc_msgSend'), (5694620, 'bl loc.imp.objc_msgSend'), (5694644, 'bl sym.makeIntpair_int__int_'), (5694672, 'bl loc.imp.objc_msgSend'), (5694700, 'blx r3'), (5694736, 'blx r3'), (5694812, 'blx r2'), (5694888, 'blx r2'), (5695004, 'blx r2'), (5695040, 'blx r3'), (5695056, 'blx r2'), (5695132, 'blx r2'), (5695248, 'blx ip'), (5695336, 'blx r2'), (5695412, 'blx r2'), (5695488, 'blx r2'), (5695684, 'blx r3'), (5695700, 'blx r2'), (5695716, 'blx r2'), (5695760, 'blx r3'), (5695800, 'blx ip'), (5695888, 'blx r2'), (5695952, 'blx r2'), (5696028, 'blx r2'), (5696160, 'blx r6'), (5696200, 'blx r3'), (5696240, 'blx r3'), (5696320, 'blx r2'), (5696440, 'blx r4'), (5696480, 'blx r3'), (5696520, 'blx r3'), (5696600, 'bl sym.makeIntpair_int__int_'), (5696628, 'bl loc.imp.objc_msgSend'), (5696712, 'bl sym.makeIntpair_int__int_'), (5696740, 'bl loc.imp.objc_msgSend'), (5696836, 'blx r3'), (5696988, 'blx r6'), (5697036, 'blx ip'), (5697084, 'blx ip'), (5697136, 'blx r4'), (5697256, 'blx r2'), (5697336, 'bl sym.makeIntpair_int__int_'), (5697364, 'bl loc.imp.objc_msgSend'), (5697448, 'bl sym.makeIntpair_int__int_'), (5697476, 'bl loc.imp.objc_msgSend'), (5697572, 'blx r3'), (5697724, 'blx r6'), (5697772, 'blx ip'), (5697820, 'blx ip'), (5697872, 'blx r4'), (5697964, 'blx ip'), (5698224, 'blx r2'), (5698304, 'bl sym.makeIntpair_int__int_'), (5698332, 'bl loc.imp.objc_msgSend'), (5698428, 'blx r3'), (5698512, 'blx r3'), (5698596, 'blx r2'), (5698708, 'blx ip'), (5698864, 'blx r6'), (5698912, 'blx ip'), (5698960, 'blx ip'), (5699012, 'blx r4'), (5699120, 'bl sym.imp.memset'), (5699184, 'blx lr'), (5699284, 'bl sym.imp.objc_enumerationMutation'), (5699376, 'blx lr'), (5699524, 'blx ip'), (5699608, 'blx r2'), (5699692, 'blx ip'), (5699820, 'blx ip'), (5699852, 'blx r3'), (5699868, 'blx r2'), (5699968, 'blx r2'), (5700116, 'blx r2'), (5700384, 'blx r3'), (5700692, 'blx r3'), (5701048, 'blx r3'), (5701200, 'blx r2'), (5701328, 'blx r2'), (5701352, 'bl sym.imp.memset'), (5701416, 'blx lr'), (5701516, 'bl sym.imp.objc_enumerationMutation'), (5701636, 'blx ip'), (5701660, 'blx r2'), (5701768, 'blx r4'), (5701808, 'blx lr'), (5701960, 'bl sym.imp.__umodsi3'), (5701992, 'bl sym.imp.__aeabi_uidiv'), (5702144, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (5702280, 'blx lr'), (5702348, 'blx r5'), (5702492, 'bl sym.makeIntpair_int__int_'), (5702580, 'bl loc.imp.objc_msgSend'), (5702832, 'blx ip'), (5702876, 'blx ip'), (5702924, 'blx ip'), (5702992, 'blx ip'), (5703040, 'blx lr'), (5703092, 'blx r3'), (5703152, 'blx r2'), (5703392, 'blx r3'), (5703420, 'blx r3'), (5703452, 'blx r3'), (5703500, 'blx r2'), (5703540, 'blx r3'), (5703588, 'blx lr'), (5703712, 'blx r3'), (5703784, 'blx r3'), (5703892, 'blx ip'), (5704000, 'bl sym.imp.memset'), (5704048, 'blx lr'), (5704148, 'bl sym.imp.objc_enumerationMutation'), (5704308, 'blx r4'), (5704324, 'blx r2'), (5704720, 'bl sym.imp.__wrap_free'), (5704980, 'blx r8'), (5705020, 'blx ip'), (5705060, 'blx ip'), (5705100, 'blx ip'), (5705200, 'blx ip'), (5705268, 'blx r2'), (5705340, 'blx r2'), (5705608, 'blx ip'), (5705704, 'blx ip'), (5705812, 'blx r3'), (5706200, 'blx r7'), (5706216, 'blx r2'), (5706264, 'blx ip'), (5706292, 'blx r3'), (5706340, 'blx lr'), (5706556, 'blx r4'), (5706608, 'blx lr'), (5706736, 'blx r2'), (5706836, 'blx ip'), (5707092, 'blx ip'), (5707108, 'blx r2'), (5707196, 'blx ip'), (5707224, 'bl 0x55468c'), (5707392, 'blx lr'), (5707420, 'blx r3'), (5707468, 'blx lr'), (5707504, 'blx r3'), (5707684, 'blx r2'), (5707840, 'blx r2'), (5707936, 'blx ip'), (5707952, 'blx r2'), (5708256, 'blx r2'), (5708316, 'blx ip'), (5708372, 'blx ip'), (5708412, 'blx r3'), (5708432, 'blx r3'), (5708492, 'blx r4'), (5708560, 'blx r2'), (5708580, 'bl sym.imp.NSLog'), (5709184, 'blx ip'), (5709208, 'blx ip'), (5709224, 'blx r2'), (5709252, 'blx r3'), (5709276, 'blx r2'), (5709328, 'blx r3'), (5709376, 'blx ip'), (5709404, 'blx r3'), (5709432, 'blx ip'), (5709460, 'blx ip'), (5709488, 'blx ip'), (5709532, 'blx r3'), (5709568, 'blx ip'), (5709604, 'blx ip'), (5709628, 'blx r3'), (5709668, 'blx lr'), (5709684, 'blx r2'), (5709748, 'bl sym.imp.NSLog'), (5709868, 'blx r2'), (5709884, 'blx r2'), (5710008, 'blx ip'), (5710184, 'blx r2'), (5710288, 'bl sym.imp.memset'), (5710352, 'blx lr'), (5710452, 'bl sym.imp.objc_enumerationMutation'), (5710572, 'blx ip'), (5710596, 'blx r2'), (5710736, 'blx ip'), (5710828, 'blx r2'), (5711056, 'blx r2'), (5711188, 'blx r3'), (5711236, 'bl loc.imp.objc_msgSend_stret'), (5711300, 'bl sym.imp.memset'), (5711320, 'bl method.Vector2.operator_Vector2_'), (5711424, 'blx ip'), (5711440, 'blx r2'), (5711696, 'blx r3'), (5711868, 'bl method.Vector2.Vector2_float__float_'), (5711892, 'bl method.Vector2.operator_Vector2_'), (5712040, 'blx r3'), (5712136, 'blx ip'), (5712152, 'blx r2'), (5712280, 'blx ip'), (5712364, 'bl loc.imp.objc_msgSend_stret'), (5712404, 'bl sym.imp.memset'), (5712556, 'bl method.Vector2.Vector2_float__float_'), (5712728, 'blx ip'), (5712744, 'blx r2'), (5712872, 'blx ip'), (5712956, 'bl loc.imp.objc_msgSend_stret'), (5713008, 'bl sym.imp.memset'), (5713148, 'blx ip'), (5713164, 'blx r2'), (5713292, 'blx ip'), (5713372, 'bl loc.imp.objc_msgSend_stret'), (5713408, 'bl sym.imp.memset'), (5713536, 'blx r3'), (5713584, 'bl loc.imp.objc_msgSend_stret'), (5713636, 'bl sym.imp.memset'), (5713724, 'bl method.Vector2.operator_float__'), (5713760, 'bl method.Vector2.operator_float__'), (5713812, 'bl sym.imp.__aeabi_idiv'), (5713916, 'bl method.Vector2.operator_float__'), (5714004, 'bl method.Vector2.operator_float__'), (5714040, 'bl method.Vector2.operator_float__'), (5714096, 'bl sym.imp.__aeabi_idiv'), (5714200, 'bl method.Vector2.operator_float__'), (5714292, 'bl method.Vector2.operator__Vector2_'), (5714300, 'bl method.Vector2.length___const'), (5714384, 'bl method.Vector2.normal__'), (5714404, 'bl method.Vector2.operator_float_'), (5714424, 'bl method.Vector2.operator__Vector2_'), (5714468, 'bl loc.imp.objc_msgSend'), (5714524, 'bl method.Vector2.operator_float__'), (5714560, 'bl method.Vector2.operator_float__'), (5714612, 'bl sym.imp.__aeabi_idiv'), (5714716, 'bl method.Vector2.operator_float__'), (5714812, 'bl method.Vector2.operator_float__'), (5714848, 'bl method.Vector2.operator_float__'), (5714904, 'bl sym.imp.__aeabi_idiv'), (5715008, 'bl method.Vector2.operator_float__'), (5715136, 'bl method.Vector2.operator__Vector2_'), (5715156, 'bl method.Vector2.operator_float_'), (5715176, 'bl method.Vector2.operator_float_'), (5715196, 'bl method.Vector2.operator_Vector2_'), (5715272, 'bl loc.imp.objc_msgSend'), (5715404, 'bl method.Vector2.operator__Vector2_'), (5715412, 'bl method.Vector2.length___const'), (5715496, 'bl method.Vector2.normal__'), (5715516, 'bl method.Vector2.operator_float_'), (5715536, 'bl method.Vector2.operator__Vector2_'), (5715580, 'bl loc.imp.objc_msgSend'), (5715636, 'bl method.Vector2.operator_float__'), (5715672, 'bl method.Vector2.operator_float__'), (5715724, 'bl sym.imp.__aeabi_idiv'), (5715828, 'bl method.Vector2.operator_float__'), (5715964, 'bl method.Vector2.operator_float__'), (5716000, 'bl method.Vector2.operator_float__'), (5716056, 'bl sym.imp.__aeabi_idiv'), (5716160, 'bl method.Vector2.operator_float__'), (5716300, 'bl method.Vector2.operator__Vector2_'), (5716320, 'bl method.Vector2.operator_float_'), (5716340, 'bl method.Vector2.operator_float_'), (5716360, 'bl method.Vector2.operator_Vector2_'), (5716436, 'bl loc.imp.objc_msgSend'), (5716456, 'bl method.Vector2.operator_float__'), (5716492, 'bl method.Vector2.operator_float__'), (5716592, 'bl method.Vector2.operator_float__'), (5716628, 'bl method.Vector2.operator_float__'), (5716844, 'bl loc.imp.objc_msgSend'), (5716968, 'blx ip'), (5716984, 'blx r2'), (5717040, 'blx r2'), (5717172, 'blx lr'), (5717212, 'blx r3'), (5717312, 'bl sym.imp.memset'), (5717360, 'blx lr'), (5717464, 'bl sym.imp.objc_enumerationMutation'), (5717536, 'blx r2'), (5717592, 'blx r2'), (5717648, 'blx r2'), (5717704, 'blx r2'), (5717804, 'blx r2'), (5717936, 'blx ip'), (5718104, 'blx ip'), (5718120, 'blx r2'), (5718216, 'blx ip'), (5718232, 'blx r2'), (5718368, 'blx r2'), (5718672, 'blx r8'), (5718692, 'blx r3'), (5718708, 'blx r2'), (5718756, 'blx ip'), (5718956, 'blx r6'), (5718976, 'blx r3'), (5718992, 'blx r2'), (5719012, 'blx r2'), (5720112, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (5720260, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (5720304, 'bl sym.recalculateDrawBlockLightingForTile_int__int__MacroTile__World_'), (5720516, 'blx r5'), (5720552, 'blx r3'), (5720568, 'blx r2'), (5720700, 'blx ip'), (5720716, 'blx r2'), (5720760, 'bl method.Vector2.Vector2_float__float_'), (5720852, 'blx lr'), (5720868, 'blx r2'), (5720888, 'bl method.Vector2.operator_float__'), (5721024, 'blx ip'), (5721040, 'blx r2'), (5721060, 'bl method.Vector2.operator_float__'), (5721164, 'blx ip'), (5721180, 'blx r2'), (5721200, 'bl method.Vector2.operator_float__'), (5721304, 'blx ip'), (5721320, 'blx r2'), (5721340, 'bl method.Vector2.operator_float__'), (5721404, 'bl loc.imp.objc_msgSend'), (5721444, 'bl loc.imp.objc_msgSend'), (5721528, 'blx r3'), (5721572, 'bl loc.imp.objc_msgSend_stret'), (5721628, 'bl sym.imp.memset'), (5721692, 'bl method.Vector2.operator_float__'), (5721760, 'bl method.Vector2.operator_float__'), (5721804, 'bl loc.imp.objc_msgSend'), (5721844, 'bl loc.imp.objc_msgSend'), (5721900, 'bl loc.imp.objc_msgSend'), (5721960, 'bl method.Vector2.Vector2_float__float_'), (5721988, 'bl loc.imp.objc_msgSend'), (5722072, 'blx ip')],
        branches=[(5692928, 'beq', 5693144), (5693040, 'beq', 5693064), (5693072, 'beq', 5693140), (5693136, 'b', 5693000), (5693140, 'b', 5722076), (5693216, 'beq', 5693260), (5693256, 'beq', 5699700), (5693460, 'beq', 5695272), (5693540, 'beq', 5693552), (5693632, 'beq', 5695148), (5693708, 'beq', 5695144), (5693912, 'beq', 5695140), (5694008, 'bhs', 5694368), (5694152, 'bne', 5694348), (5694268, 'bne', 5694348), (5694344, 'b', 5694368), (5694348, 'b', 5694352), (5694364, 'b', 5693928), (5694748, 'bne', 5694828), (5694824, 'beq', 5695136), (5694900, 'bne', 5695136), (5695068, 'bne', 5695136), (5695136, 'b', 5695140), (5695140, 'b', 5695144), (5695144, 'b', 5695148), (5695148, 'b', 5695152), (5695176, 'blo', 5693504), (5695268, 'bne', 5693504), (5695272, 'b', 5695276), (5695348, 'bne', 5695828), (5695424, 'bne', 5695828), (5695496, 'bls', 5695804), (5695804, 'b', 5695892), (5695964, 'bne', 5699696), (5696040, 'beq', 5699696), (5696256, 'beq', 5696340), (5696528, 'bne', 5697196), (5696648, 'bne', 5696748), (5696760, 'beq', 5697144), (5696848, 'beq', 5697140), (5697140, 'b', 5697144), (5697144, 'b', 5699024), (5697264, 'bne', 5698040), (5697384, 'bne', 5697484), (5697496, 'beq', 5697972), (5697584, 'beq', 5697880), (5697876, 'b', 5697968), (5697968, 'b', 5697972), (5697972, 'b', 5699020), (5698080, 'beq', 5698528), (5698120, 'bne', 5698164), (5698160, 'beq', 5698528), (5698232, 'bne', 5698528), (5698352, 'beq', 5698524), (5698440, 'bne', 5698520), (5698520, 'b', 5698524), (5698524, 'b', 5698528), (5698608, 'bne', 5698712), (5698624, 'beq', 5698712), (5698724, 'bne', 5699016), (5699016, 'b', 5699020), (5699020, 'b', 5699024), (5699196, 'beq', 5699548), (5699276, 'beq', 5699288), (5699388, 'bne', 5699424), (5699400, 'b', 5699552), (5699424, 'b', 5699428), (5699452, 'blo', 5699240), (5699544, 'bne', 5699240), (5699548, 'b', 5699552), (5699564, 'bne', 5699612), (5699696, 'b', 5699700), (5699924, 'beq', 5701100), (5699980, 'beq', 5701100), (5700128, 'bne', 5701096), (5700180, 'bpl', 5700440), (5700216, 'bne', 5700416), (5700296, 'ble', 5700412), (5700412, 'b', 5700416), (5700416, 'b', 5701092), (5700488, 'bpl', 5700796), (5700524, 'bne', 5700724), (5700604, 'ble', 5700720), (5700720, 'b', 5700724), (5700724, 'b', 5701088), (5700844, 'bpl', 5701084), (5700880, 'bne', 5701080), (5700960, 'ble', 5701076), (5701076, 'b', 5701080), (5701080, 'b', 5701084), (5701084, 'b', 5701088), (5701088, 'b', 5701092), (5701092, 'b', 5701096), (5701096, 'b', 5701100), (5701136, 'beq', 5705356), (5701208, 'bls', 5705356), (5701428, 'beq', 5703916), (5701508, 'beq', 5701520), (5701672, 'beq', 5703664), (5701840, 'bhs', 5703112), (5702072, 'beq', 5702092), (5702088, 'bne', 5702368), (5702164, 'beq', 5702364), (5702364, 'b', 5702368), (5702380, 'beq', 5702596), (5702396, 'beq', 5702596), (5702412, 'bne', 5702596), (5702608, 'bne', 5703044), (5703108, 'b', 5701828), (5703164, 'beq', 5703592), (5703592, 'b', 5703792), (5703732, 'bne', 5703788), (5703788, 'b', 5703792), (5703792, 'b', 5703796), (5703820, 'blo', 5701472), (5703912, 'bne', 5701472), (5703916, 'b', 5703920), (5704060, 'beq', 5705224), (5704140, 'beq', 5704152), (5704624, 'beq', 5704820), (5704680, 'beq', 5704748), (5704748, 'b', 5704752), (5704808, 'b', 5704476), (5705128, 'blo', 5704104), (5705220, 'bne', 5704104), (5705224, 'b', 5705228), (5705276, 'bls', 5705344), (5705344, 'b', 5706852), (5705392, 'beq', 5706848), (5705472, 'ble', 5705736), (5705524, 'ble', 5705624), (5705612, 'b', 5722076), (5705708, 'b', 5705840), (5705904, 'bhi', 5706844), (5705940, 'beq', 5706436), (5706344, 'b', 5706612), (5706752, 'beq', 5706840), (5706840, 'b', 5706844), (5706844, 'b', 5706848), (5706848, 'b', 5706852), (5706888, 'beq', 5707564), (5706928, 'beq', 5707564), (5707008, 'bgt', 5707124), (5707120, 'bne', 5707560), (5707560, 'b', 5707564), (5707600, 'beq', 5710076), (5707640, 'bne', 5710072), (5707696, 'beq', 5710068), (5707776, 'bgt', 5707968), (5707852, 'bne', 5707968), (5707964, 'bne', 5710064), (5708000, 'bne', 5709916), (5708512, 'bne', 5708636), (5708584, 'b', 5709912), (5709732, 'bne', 5709800), (5709752, 'b', 5709908), (5709908, 'b', 5709912), (5709912, 'b', 5709916), (5710064, 'b', 5710068), (5710068, 'b', 5710072), (5710072, 'b', 5710076), (5710120, 'beq', 5710768), (5710192, 'bls', 5710768), (5710364, 'beq', 5710760), (5710444, 'beq', 5710456), (5710608, 'bne', 5710636), (5710620, 'b', 5710764), (5710636, 'b', 5710640), (5710664, 'blo', 5710408), (5710756, 'bne', 5710408), (5710760, 'b', 5710764), (5710764, 'b', 5710768), (5710840, 'beq', 5710996), (5710856, 'beq', 5710996), (5710896, 'beq', 5710972), (5710932, 'bne', 5710972), (5710968, 'beq', 5710996), (5710972, 'b', 5722076), (5711068, 'bne', 5716888), (5711216, 'beq', 5711268), (5711240, 'b', 5711304), (5711460, 'beq', 5711496), (5711528, 'bne', 5715300), (5711564, 'bne', 5711712), (5711580, 'bne', 5711712), (5711620, 'beq', 5711712), (5711708, 'bne', 5715300), (5711748, 'bne', 5711968), (5711916, 'b', 5713672), (5712052, 'bne', 5712648), (5712164, 'beq', 5712432), (5712336, 'beq', 5712372), (5712368, 'b', 5712408), (5712428, 'b', 5712584), (5712584, 'b', 5713668), (5712756, 'beq', 5713068), (5712928, 'beq', 5712976), (5712960, 'b', 5713012), (5713032, 'b', 5713664), (5713176, 'beq', 5713436), (5713348, 'beq', 5713380), (5713376, 'b', 5713412), (5713432, 'b', 5713660), (5713564, 'beq', 5713604), (5713588, 'b', 5713640), (5713660, 'b', 5713664), (5713664, 'b', 5713668), (5713668, 'b', 5713672), (5713836, 'ble', 5713952), (5713936, 'b', 5714224), (5714120, 'bpl', 5714220), (5714220, 'b', 5714224), (5714328, 'ble', 5714472), (5714636, 'ble', 5714760), (5714736, 'b', 5715032), (5714928, 'bpl', 5715028), (5715028, 'b', 5715032), (5715276, 'b', 5716884), (5715332, 'beq', 5716880), (5715440, 'ble', 5715584), (5715748, 'ble', 5715912), (5715848, 'b', 5716184), (5716080, 'bpl', 5716180), (5716180, 'b', 5716184), (5716536, 'bpl', 5716876), (5716564, 'ble', 5716876), (5716672, 'bpl', 5716872), (5716700, 'ble', 5716872), (5716872, 'b', 5716876), (5716876, 'b', 5716880), (5716880, 'b', 5716884), (5716884, 'b', 5716888), (5716996, 'beq', 5717044), (5717220, 'bls', 5717968), (5717372, 'beq', 5717960), (5717456, 'beq', 5717468), (5717548, 'bne', 5717756), (5717604, 'bne', 5717756), (5717660, 'bne', 5717728), (5717716, 'bne', 5717728), (5717728, 'b', 5717764), (5717816, 'bne', 5717828), (5717828, 'b', 5717832), (5717856, 'blo', 5717420), (5717956, 'bne', 5717420), (5717960, 'b', 5717964), (5717964, 'b', 5717968), (5718004, 'bne', 5718432), (5718020, 'beq', 5718388), (5718132, 'bne', 5718388), (5718244, 'bne', 5718388), (5718324, 'ble', 5718372), (5718372, 'b', 5718428), (5718428, 'b', 5718432), (5718468, 'bne', 5719044), (5718484, 'beq', 5718772), (5718500, 'beq', 5718772), (5718536, 'bne', 5718760), (5718760, 'b', 5719020), (5718804, 'beq', 5719016), (5719016, 'b', 5719020), (5719020, 'b', 5719088), (5719056, 'beq', 5719076), (5719072, 'bne', 5719084), (5719084, 'b', 5719088), (5719172, 'ble', 5719276), (5719240, 'bhi', 5719276), (5719288, 'beq', 5719328), (5719380, 'beq', 5719532), (5719416, 'bne', 5719468), (5719432, 'b', 5719528), (5719500, 'bne', 5719524), (5719524, 'b', 5719528), (5719528, 'b', 5719532), (5719648, 'ble', 5719668), (5719704, 'beq', 5720392), (5720008, 'beq', 5720388), (5720132, 'beq', 5720320), (5720148, 'beq', 5720320), (5720164, 'beq', 5720320), (5720320, 'b', 5720324), (5720380, 'b', 5719860), (5720388, 'b', 5720392), (5720580, 'beq', 5721996), (5720616, 'beq', 5721860), (5720728, 'beq', 5721452), (5720880, 'beq', 5720944), (5720908, 'b', 5721084), (5721052, 'beq', 5721080), (5721080, 'b', 5721084), (5721192, 'beq', 5721224), (5721220, 'b', 5721364), (5721332, 'beq', 5721360), (5721360, 'b', 5721364), (5721448, 'b', 5721848), (5721556, 'beq', 5721600), (5721576, 'b', 5721632), (5721848, 'b', 5721992), (5721992, 'b', 5721996)],
        semantics=('[World update:accurateDT:pinchScale:dragInProgress:] (imp 0x0056dd78, 7369w): **the tick giant** - **operator float* x28** + operator float* (Vector) x6 + objc x23 + memset x12 + makeIntpair x7 + **fast enumeration x6** + **`__aeabi_idiv` x6** + Vector2 ops x6 + sel x140 + the timing pool **0x258 (600!)/0xe10 (3600!)/0x5a (90)/0xf (15)/0x3c (60)/0x2e (46)/0x27 (39)/0x44 (68)** + 0x10/0x20/0xa/0x14/0x18/0x40/0x1e: the per-frame world update with the minute/hour timing table.\n'),
    ),
    dict(
        name='ws_09',
        method='World -[preRenderUpdate:fastSlowDT:cameraZ:projectionMatrix:]',
        types='v84@0:4f8f12f16(_GLKMatrix4={?=ffffffffffffffff}[16f])20',
        start=5782608,
        end=5814116,
        disasm='disasm_worldtileloader_ws_09.txt',
        base_add=5782652,
        base_literal=5785440,
        boundary='ARM.exidx end 0x0058b764 (listing bound); next ObjC IMP 0x0058c350 World -[lightPositionTop]',
        selectors={
                 0x58479c: (15195844, 'timeIntervalSinceReferenceDate'),
                 0x586708: (15196996, 'getWeatherFractionForPos:'),
                 0x586714: (15197088, 'maxOfRockAndDirtHeightForX:'),
                 0x587bc0: (15197092, 'isPlayingMP3'),
                 0x587bc4: (15195544, 'instance'),
                 0x587cd4: (15197096, 'playMP3IfSafe:'),
                 0x587cdc: (15196032, 'stringByAppendingPathComponent:'),
                 0x587ce4: (15196028, 'resourcePath'),
                 0x587ce8: (15196024, 'mainBundle'),
                 0x587e04: (15197100, 'update:rainFraction:snowFraction:'),
                 0x587e10: (15197104, 'updateRainSoundWithRainFraction:undergroundMix:position:'),
                 0x587e1c: (15195748, 'data'),
                 0x587e20: (15197084, 'width'),
                 0x5888a0: (15197108, 'getTreeLifeFractionForPos:'),
                 0x588b3c: (15197088, 'maxOfRockAndDirtHeightForX:'),
                 0x588f04: (15197112, 'updateBirdSoundWithBirdFraction:dayNightMix:undergroundMix:dt:playPosition:'),
                 0x588f08: (15197116, 'pauseUI'),
                 0x589060: (15195620, 'countByEnumeratingWithState:objects:count:'),
                 0x589064: (15195692, 'blockheads'),
                 0x589068: (15197120, 'death'),
                 0x58906c: (15196268, 'regenerating'),
                 0x589074: (15196476, 'isEqualToString:'),
                 0x58907c: (15197124, 'lastPlayedMP3Path'),
                 0x589490: (15197128, 'fadeOutMP3PlaybackWithStop:'),
                 0x589bac: (15197092, 'isPlayingMP3'),
                 0x589bb0: (15195544, 'instance'),
                 0x589bbc: (15197096, 'playMP3IfSafe:'),
                 0x589bc4: (15196032, 'stringByAppendingPathComponent:'),
                 0x589bcc: (15196028, 'resourcePath'),
                 0x589bd0: (15196024, 'mainBundle'),
                 0x589be0: (15197132, 'energy'),
                 0x58b734: (15197136, 'waitingForBlocksCount'),
                 0x58b738: (15196508, 'loadPhysicalBlockForMacroTile:atX:y:loadSurroundingBlocks:createIfNotCreated:'),
                 0x58b73c: (15197140, 'loadDynamicObjectsIfNotAlreadyLoadedForMacroTile:includeSurfaceBlocks:'),
                 0x58b740: (15195988, 'worldWidthMacro'),
                 0x58b744: (15197144, 'reasignDrawBlock:toXPos:yPos:world:'),
                 0x58b74c: (15197148, 'reloadDynamicObjectStaticGemometryForMacroTile:'),
                 0x58b750: (15197152, 'reloadDynamicObjectStaticCylindersForMacroTile:'),
                 0x58b754: (15197156, 'reloadDynamicObjectQuadsForMacroTile:'),
                 0x58b758: (15197160, 'reloadDodoEggQuadsForMacroTile:'),
                 0x58b75c: (15197164, 'reloadDynamicObjectItemQuadsForMacroTile:'),
                 0x58b760: (15197168, 'reloadLightGlowQuadsForMacroTile:'),
        },
        imports={
                 0x584798: (17151904, 'objc_msgSend'),
                 0x586710: (17151904, 'objc_msgSend'),
                 0x587cd8: (16232248, '__CFConstantStringClassReference'),
                 0x587ce0: (16229880, '__CFConstantStringClassReference'),
                 0x588b38: (17151904, 'objc_msgSend'),
                 0x589078: (16232264, '__CFConstantStringClassReference'),
                 0x589904: (16232280, '__CFConstantStringClassReference'),
                 0x589aa8: (16232296, '__CFConstantStringClassReference'),
                 0x589bc0: (16232312, '__CFConstantStringClassReference'),
                 0x589bc8: (16229880, '__CFConstantStringClassReference'),
                 0x589bd8: (16232328, '__CFConstantStringClassReference'),
                 0x589be4: (16232344, '__CFConstantStringClassReference'),
                 0x589be8: (16232360, '__CFConstantStringClassReference'),
                 0x58b70c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x584764: (17156520, 'OBJC_IVAR_$_World.backgroundYOffset', 884),
                 0x58476c: (17155924, 'OBJC_IVAR_$_World.worldTime', 648),
                 0x584770: (17156524, 'OBJC_IVAR_$_World.sunDirection', 660),
                 0x584774: (17155888, 'OBJC_IVAR_$_World.roundedTranslation', 616),
                 0x584778: (17156528, 'OBJC_IVAR_$_World.relativeSunDirection', 676),
                 0x584784: (17156104, 'OBJC_IVAR_$_World.worldTileLoader', 420),
                 0x58478c: (17156532, 'OBJC_IVAR_$_World.rainFractionNotIncludingSnow', 924),
                 0x584790: (17156536, 'OBJC_IVAR_$_World.rainFraction', 920),
                 0x584794: (17156540, 'OBJC_IVAR_$_World.cloudFraction', 928),
                 0x5847a4: (17156544, 'OBJC_IVAR_$_World.weatherFraction', 916),
                 0x5866fc: (17156548, 'OBJC_IVAR_$_World.starsMvpMatrix', 816),
                 0x586700: (17156552, 'OBJC_IVAR_$_World.timeOfDayFraction', 880),
                 0x586704: (17155888, 'OBJC_IVAR_$_World.roundedTranslation', 616),
                 0x58670c: (17156104, 'OBJC_IVAR_$_World.worldTileLoader', 420),
                 0x586718: (17156024, 'OBJC_IVAR_$_World.clientTileLoader', 972),
                 0x58671c: (17156544, 'OBJC_IVAR_$_World.weatherFraction', 916),
                 0x58672c: (17156540, 'OBJC_IVAR_$_World.cloudFraction', 928),
                 0x586730: (17156536, 'OBJC_IVAR_$_World.rainFraction', 920),
                 0x586738: (17155924, 'OBJC_IVAR_$_World.worldTime', 648),
                 0x587a98: (17155980, 'OBJC_IVAR_$_World.hideUIType', 3068),
                 0x587a9c: (17156532, 'OBJC_IVAR_$_World.rainFractionNotIncludingSnow', 924),
                 0x587aa0: (17156556, 'OBJC_IVAR_$_World.lastMusicPlayTime', 3096),
                 0x587bdc: (17155960, 'OBJC_IVAR_$_World.fastForward', 934),
                 0x587cd0: (17155960, 'OBJC_IVAR_$_World.fastForward', 934),
                 0x587e08: (17156144, 'OBJC_IVAR_$_World.weather', 156),
                 0x587e14: (17156236, 'OBJC_IVAR_$_World.dayColorImageData', 904),
                 0x587e24: (17156232, 'OBJC_IVAR_$_World.dayColorCloudyImageData', 908),
                 0x587e2c: (17156516, 'OBJC_IVAR_$_World.dayColor', 888),
                 0x587e30: (17156060, 'OBJC_IVAR_$_World.customRules', 160),
                 0x587e34: (17156544, 'OBJC_IVAR_$_World.weatherFraction', 916),
                 0x587e38: (17156560, 'OBJC_IVAR_$_World.isHeadingTowardsMIdday', 3260),
                 0x587e3c: (17156552, 'OBJC_IVAR_$_World.timeOfDayFraction', 880),
                 0x587e48: (17155888, 'OBJC_IVAR_$_World.roundedTranslation', 616),
                 0x588898: (17155888, 'OBJC_IVAR_$_World.roundedTranslation', 616),
                 0x58889c: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5888a4: (17156104, 'OBJC_IVAR_$_World.worldTileLoader', 420),
                 0x588b40: (17156024, 'OBJC_IVAR_$_World.clientTileLoader', 972),
                 0x588f0c: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x589070: (17156564, 'OBJC_IVAR_$_World.hasPlayedDyingSong', 3261),
                 0x589bb8: (17156556, 'OBJC_IVAR_$_World.lastMusicPlayTime', 3096),
                 0x589bdc: (17156552, 'OBJC_IVAR_$_World.timeOfDayFraction', 880),
                 0x58a838: (17156568, 'OBJC_IVAR_$_World.waterAnimationTimer', 1012),
                 0x58a83c: (17156572, 'OBJC_IVAR_$_World.waterAnimationIndex', 1008),
                 0x58a840: (17156576, 'OBJC_IVAR_$_World.slowAnimationTimer', 1020),
                 0x58a844: (17156580, 'OBJC_IVAR_$_World.slowAnimationIndex', 1016),
                 0x58a848: (17156584, 'OBJC_IVAR_$_World.sunMvpMatrix', 688),
                 0x58b070: (17156588, 'OBJC_IVAR_$_World.moonMvpMatrix', 752),
                 0x58b074: (17155872, 'OBJC_IVAR_$_World.pinchScale', 400),
                 0x58b078: (17155876, 'OBJC_IVAR_$_World.windowInfo', 152),
                 0x58b588: (17155888, 'OBJC_IVAR_$_World.roundedTranslation', 616),
                 0x58b5a8: (17155888, 'OBJC_IVAR_$_World.roundedTranslation', 616),
                 0x58b710: (17156024, 'OBJC_IVAR_$_World.clientTileLoader', 972),
                 0x58b714: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x58b718: (17155872, 'OBJC_IVAR_$_World.pinchScale', 400),
                 0x58b71c: (17156244, 'OBJC_IVAR_$_World.drawBlocks', 504),
                 0x58b720: (17156592, 'OBJC_IVAR_$_World.updateGeometryDrawBlockIndex', 512),
                 0x58b724: (17156240, 'OBJC_IVAR_$_World.numDrawBlocks', 508),
                 0x58b728: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
                 0x58b72c: (17156340, 'OBJC_IVAR_$_World.macroTiles', 412),
                 0x58b730: (17155972, 'OBJC_IVAR_$_World.client', 960),
        },
        classes={
                 0x5847a0: (15245312, 'OBJC_CLASS_$_NSDate'),
                 0x587bc8: (15245280, 'OBJC_CLASS_$_MJSoundManager'),
                 0x587cec: (15245376, 'OBJC_CLASS_$_NSBundle'),
                 0x589bb4: (15245280, 'OBJC_CLASS_$_MJSoundManager'),
                 0x589bd4: (15245376, 'OBJC_CLASS_$_NSBundle'),
                 0x58b748: (15245460, 'OBJC_CLASS_$_WorldHelper'),
        },
        instructions=[(5782608, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5814112, 'invalid')],
        calls=[(5783096, 'bl sym.absoluteSeasonFraction_double_'), (5783176, 'bl sym.imp.fmod'), (5783232, 'bl sym.imp.cos'), (5783376, 'bl sym.polarToRectangular_double__double_'), (5783468, 'bl method.Vector2.operator_float__'), (5783496, 'bl sym.getWorldUpVectorForX_float__World_'), (5783524, 'bl method.Vector.operator_float__'), (5783544, 'bl method.Vector.operator_float__'), (5783616, 'bl 0x582eb4'), (5783940, 'bl method.Vector.operator_float__'), (5783976, 'bl method.Vector.operator_float__'), (5784012, 'bl method.Vector.operator_float__'), (5784032, 'bl 0x58353c'), (5784396, 'bl 0x583288'), (5784488, 'bl sym.absoluteSeasonFraction_double_'), (5784568, 'bl sym.imp.__wrap_fmodf'), (5784620, 'bl sym.imp.cos'), (5784716, 'bl sym.polarToRectangular_double__double_'), (5784980, 'bl method.Vector.operator_float__'), (5784996, 'bl method.Vector.operator_float__'), (5785012, 'bl method.Vector.operator_float__'), (5785036, 'bl 0x58353c'), (5785356, 'bl 0x583288'), (5785412, 'bl method.Vector.operator_float__'), (5785552, 'bl method.Vector.operator_float__'), (5785604, 'bl method.Vector.operator_float__'), (5785800, 'bl method.Vector.operator_float__'), (5785944, 'bl 0x58b764'), (5786072, 'bl 0x582eb4'), (5786872, 'bl 0x58b7b4'), (5787228, 'bl 0x582eb4'), (5787784, 'bl 0x58b7b4'), (5788112, 'bl sym.polarToRectangular_double__double_'), (5788188, 'bl 0x58b99c'), (5788204, 'bl method.Vector.operator_float__'), (5788224, 'bl method.Vector.operator_float__'), (5788296, 'bl 0x582eb4'), (5789224, 'bl 0x58bbd8'), (5789400, 'bl method.Vector.operator_float__'), (5789420, 'bl method.Vector.operator_float__'), (5789440, 'bl method.Vector.operator_float__'), (5789516, 'bl 0x582eb4'), (5790340, 'bl 0x58bbd8'), (5790712, 'bl 0x58c198'), (5791768, 'bl 0x58bbd8'), (5792008, 'bl method.Vector2.operator_float__'), (5792048, 'bl method.Vector2.operator_float__'), (5792076, 'bl sym.makeIntpair_int__int_'), (5792108, 'bl loc.imp.objc_msgSend'), (5792220, 'blx ip'), (5792432, 'bl method.Vector2.operator_float__'), (5792500, 'blx ip'), (5792584, 'bl method.Vector2.operator_float__'), (5792652, 'blx ip'), (5792700, 'bl method.Vector2.operator_float__'), (5792964, 'bl method.Vector2.operator_float__'), (5793036, 'bl method.Vector2.operator_float__'), (5793328, 'bl sym.clamp_float__float__float_'), (5793704, 'bl method.Vector2.operator_float__'), (5793764, 'bl sym.seasonForWorldX_int__double__World_'), (5793796, 'bl method.Vector2.operator_float__'), (5793836, 'bl sym.makeIntpair_int__int_'), (5793936, 'bl sym.baseTemperatureForWorldPos_intpair__float__float__float__World_'), (5794024, 'bl sym.clamp_float__float__float_'), (5794068, 'bl method.Vector2.operator_float__'), (5794152, 'bl method.Vector2.operator_float__'), (5794192, 'bl method.Vector2.operator_float__'), (5794220, 'bl sym.makeIntpair_int__int_'), (5794320, 'bl sym.baseTemperatureForWorldPos_intpair__float__float__float__World_'), (5794408, 'bl sym.clamp_float__float__float_'), (5794500, 'bl sym.clamp_float__float__float_'), (5794972, 'blx ip'), (5794988, 'blx r2'), (5795244, 'blx r2'), (5795276, 'blx r2'), (5795292, 'blx r2'), (5795312, 'blx r3'), (5795332, 'blx r3'), (5795364, 'blx r3'), (5795556, 'blx ip'), (5795692, 'bl method.Vector2.operator_float__'), (5795712, 'bl method.Vector2.Vector2_float__float_'), (5795780, 'bl loc.imp.objc_msgSend'), (5795952, 'bl loc.imp.objc_msgSend'), (5795996, 'bl loc.imp.objc_msgSend'), (5796128, 'bl sym.linearInterpolate_float__float__float_'), (5796212, 'bl sym.linearInterpolate_float__float__float_'), (5796312, 'bl sym.linearInterpolate_float__float__float_'), (5796448, 'bl loc.imp.objc_msgSend'), (5796496, 'bl loc.imp.objc_msgSend'), (5796628, 'bl sym.linearInterpolate_float__float__float_'), (5796712, 'bl sym.linearInterpolate_float__float__float_'), (5796812, 'bl sym.linearInterpolate_float__float__float_'), (5796900, 'bl sym.linearInterpolate_float__float__float_'), (5796944, 'bl method.Vector.operator_float__'), (5797016, 'bl sym.linearInterpolate_float__float__float_'), (5797060, 'bl method.Vector.operator_float__'), (5797132, 'bl sym.linearInterpolate_float__float__float_'), (5797176, 'bl method.Vector.operator_float__'), (5797248, 'bl sym.linearInterpolate_float__float__float_'), (5797304, 'bl method.Vector.operator_float__'), (5797448, 'bl method.Vector.operator_float__'), (5797560, 'bl method.Vector.operator_float__'), (5797672, 'bl method.Vector.operator_float__'), (5798020, 'bl sym.clamp_float__float__float_'), (5798096, 'bl method.Vector2.operator_float__'), (5798148, 'bl method.Vector2.operator_float__'), (5798176, 'bl sym.makeIntpair_int__int_'), (5798252, 'bl loc.imp.objc_msgSend_stret'), (5798288, 'bl sym.imp.memset'), (5798296, 'bl method.Vector.operator_float__'), (5798324, 'bl method.Vector.operator_float__'), (5798756, 'bl method.Vector2.operator_float__'), (5798824, 'blx ip'), (5798940, 'bl method.Vector2.operator_float__'), (5799008, 'blx ip'), (5799056, 'bl method.Vector2.operator_float__'), (5799256, 'bl method.Vector2.operator_float__'), (5799328, 'bl method.Vector2.operator_float__'), (5799648, 'bl method.Vector.operator_float__'), (5799664, 'bl method.Vector.operator_float__'), (5799680, 'bl method.Vector2.Vector2_float__float_'), (5799772, 'bl loc.imp.objc_msgSend'), (5799896, 'blx r3'), (5800148, 'bl sym.imp.memset'), (5800188, 'blx r3'), (5800232, 'blx lr'), (5800340, 'bl sym.imp.objc_enumerationMutation'), (5800428, 'blx r2'), (5800500, 'blx r2'), (5800636, 'blx ip'), (5800780, 'blx ip'), (5800796, 'blx r2'), (5801028, 'blx r2'), (5801044, 'blx r2'), (5801076, 'blx r2'), (5801092, 'blx r2'), (5801112, 'blx r3'), (5801132, 'blx r3'), (5801164, 'blx r3'), (5801260, 'blx lr'), (5801284, 'blx r3'), (5801620, 'blx r2'), (5801636, 'blx r2'), (5801668, 'blx r2'), (5801684, 'blx r2'), (5801704, 'blx r3'), (5801724, 'blx r3'), (5801756, 'blx r3'), (5801980, 'blx r3'), (5802012, 'blx r2'), (5802028, 'blx r2'), (5802048, 'blx r3'), (5802068, 'blx r3'), (5802100, 'blx r3'), (5802376, 'blx ip'), (5802392, 'blx r2'), (5802408, 'bl 0x564c54'), (5802680, 'blx r2'), (5802712, 'blx r2'), (5802728, 'blx r2'), (5802748, 'blx r3'), (5802768, 'blx r3'), (5802800, 'blx r3'), (5803020, 'blx r2'), (5803052, 'blx r2'), (5803068, 'blx r2'), (5803088, 'blx r3'), (5803108, 'blx r3'), (5803140, 'blx r3'), (5803348, 'blx ip'), (5803364, 'blx r2'), (5803380, 'bl 0x564c54'), (5803652, 'blx r2'), (5803684, 'blx r2'), (5803700, 'blx r2'), (5803720, 'blx r3'), (5803740, 'blx r3'), (5803772, 'blx r3'), (5803992, 'blx r2'), (5804024, 'blx r2'), (5804040, 'blx r2'), (5804060, 'blx r3'), (5804080, 'blx r3'), (5804112, 'blx r3'), (5804352, 'blx ip'), (5804368, 'blx r2'), (5804384, 'bl 0x564c54'), (5804548, 'bl sym.imp.memset'), (5804588, 'blx r3'), (5804632, 'blx lr'), (5804740, 'bl sym.imp.objc_enumerationMutation'), (5804824, 'blx r2'), (5805060, 'blx r2'), (5805092, 'blx r2'), (5805108, 'blx r2'), (5805128, 'blx r3'), (5805148, 'blx r3'), (5805180, 'blx r3'), (5805312, 'blx ip'), (5805536, 'blx ip'), (5805552, 'blx r2'), (5805568, 'bl 0x564c54'), (5805716, 'bl sym.imp.memset'), (5805756, 'blx r3'), (5805800, 'blx lr'), (5805904, 'bl sym.imp.objc_enumerationMutation'), (5805988, 'blx r2'), (5806212, 'blx r2'), (5806244, 'blx r2'), (5806260, 'blx r2'), (5806280, 'blx r3'), (5806300, 'blx r3'), (5806332, 'blx r3'), (5806452, 'blx ip'), (5808084, 'bl 0x58bbd8'), (5809188, 'bl 0x58bbd8'), (5809288, 'bl sym.imp.memcpy'), (5809392, 'bl sym.clamp_float__float__float_'), (5809548, 'bl sym.clamp_float__float__float_'), (5809600, 'bl method.Vector2.operator_float__'), (5809664, 'bl sym.imp.floor'), (5809708, 'bl method.Vector2.operator_float__'), (5809788, 'bl sym.imp.floor'), (5809832, 'bl method.Vector2.operator_float__'), (5809896, 'bl sym.imp.floor'), (5809940, 'bl method.Vector2.operator_float__'), (5810012, 'bl sym.imp.floor'), (5810760, 'blx r2'), (5810944, 'blx lr'), (5811128, 'blx ip'), (5811428, 'blx r3'), (5811436, 'bl sym.imp.__aeabi_idiv'), (5811512, 'blx r2'), (5811616, 'blx r2'), (5811632, 'bl sym.imp.__aeabi_idiv'), (5811708, 'blx r2'), (5811840, 'blx r3'), (5811848, 'bl sym.imp.__aeabi_idiv'), (5811924, 'blx r2'), (5812016, 'blx r2'), (5812032, 'bl sym.imp.__aeabi_idiv'), (5812108, 'blx r2'), (5812316, 'blx lr'), (5812484, 'blx lr'), (5812656, 'blx r3'), (5812844, 'blx r3'), (5813032, 'blx r3'), (5813220, 'blx r3'), (5813408, 'blx r3'), (5813596, 'blx r3')],
        branches=[(5784152, 'b', 5784192), (5785432, 'bpl', 5785616), (5785436, 'b', 5785524), (5785572, 'ble', 5785616), (5789064, 'b', 5789104), (5791492, 'b', 5791500), (5792368, 'beq', 5792524), (5792520, 'b', 5792672), (5792740, 'bpl', 5792764), (5792760, 'b', 5792780), (5792848, 'bpl', 5792880), (5792876, 'b', 5792896), (5792988, 'ble', 5793180), (5793112, 'bpl', 5793136), (5793132, 'b', 5793152), (5793220, 'ble', 5795384), (5793408, 'ble', 5795380), (5793508, 'bpl', 5793604), (5793528, 'b', 5793620), (5794108, 'ble', 5794540), (5794644, 'bne', 5795376), (5794712, 'ble', 5795372), (5794732, 'bpl', 5795372), (5794756, 'bpl', 5795372), (5794760, 'b', 5794772), (5794816, 'ble', 5795372), (5794864, 'ble', 5795372), (5795000, 'bne', 5795368), (5795040, 'bne', 5795368), (5795368, 'b', 5795372), (5795372, 'b', 5795376), (5795376, 'b', 5795380), (5795380, 'b', 5795384), (5795588, 'bne', 5795784), (5795868, 'bpl', 5796344), (5795872, 'b', 5795888), (5796384, 'ble', 5796844), (5797356, 'beq', 5797696), (5797824, 'bpl', 5799780), (5797864, 'bne', 5799780), (5798216, 'beq', 5798260), (5798256, 'b', 5798292), (5798316, 'ble', 5799776), (5798372, 'bpl', 5798400), (5798392, 'b', 5798416), (5798528, 'bpl', 5798568), (5798548, 'b', 5798584), (5798692, 'beq', 5798880), (5798844, 'b', 5799028), (5799096, 'bpl', 5799160), (5799116, 'b', 5799176), (5799280, 'ble', 5799540), (5799404, 'bpl', 5799500), (5799424, 'b', 5799516), (5799776, 'b', 5799780), (5799816, 'bne', 5806512), (5799908, 'bne', 5806512), (5799948, 'bne', 5806512), (5800016, 'ble', 5806512), (5800244, 'beq', 5800660), (5800332, 'beq', 5800344), (5800452, 'ble', 5800528), (5800512, 'bne', 5800528), (5800528, 'b', 5800532), (5800556, 'blo', 5800296), (5800656, 'bne', 5800296), (5800660, 'b', 5800664), (5800676, 'bne', 5801292), (5800808, 'beq', 5801288), (5801176, 'beq', 5801288), (5801288, 'b', 5801292), (5801304, 'beq', 5802152), (5801344, 'bne', 5802152), (5801768, 'bne', 5802132), (5802132, 'b', 5806508), (5802172, 'blt', 5803172), (5802220, 'bpl', 5803172), (5802268, 'bpl', 5803172), (5802404, 'bne', 5803152), (5802452, 'ble', 5803148), (5802476, 'ble', 5802820), (5802804, 'b', 5803144), (5803144, 'b', 5803148), (5803148, 'b', 5803152), (5803152, 'b', 5806504), (5803192, 'blt', 5804176), (5803240, 'bpl', 5804176), (5803376, 'bne', 5804124), (5803424, 'ble', 5804120), (5803448, 'ble', 5803792), (5803776, 'b', 5804116), (5804116, 'b', 5804120), (5804120, 'b', 5804124), (5804124, 'b', 5806500), (5804196, 'bhi', 5805360), (5804244, 'ble', 5805360), (5804380, 'bne', 5805348), (5804416, 'ble', 5805344), (5804644, 'beq', 5805336), (5804732, 'beq', 5804744), (5804844, 'bpl', 5805204), (5805196, 'b', 5805340), (5805204, 'b', 5805208), (5805232, 'blo', 5804696), (5805332, 'bne', 5804696), (5805336, 'b', 5805340), (5805340, 'b', 5805344), (5805344, 'b', 5805348), (5805348, 'b', 5806496), (5805380, 'bhi', 5806492), (5805428, 'ble', 5806492), (5805564, 'bne', 5806488), (5805600, 'ble', 5806484), (5805812, 'beq', 5806476), (5805896, 'beq', 5805908), (5806008, 'ble', 5806352), (5806336, 'b', 5806480), (5806352, 'b', 5806356), (5806380, 'blo', 5805860), (5806472, 'bne', 5805860), (5806476, 'b', 5806480), (5806480, 'b', 5806484), (5806484, 'b', 5806488), (5806488, 'b', 5806492), (5806492, 'b', 5806496), (5806496, 'b', 5806500), (5806500, 'b', 5806504), (5806504, 'b', 5806508), (5806508, 'b', 5806512), (5806604, 'ble', 5806764), (5806712, 'blt', 5806756), (5806756, 'b', 5806560), (5806864, 'ble', 5807088), (5806972, 'blt', 5807016), (5807016, 'b', 5806820), (5810052, 'b', 5810064), (5810080, 'bge', 5813676), (5810096, 'blt', 5813648), (5810112, 'bge', 5813648), (5810152, 'bge', 5813644), (5810176, 'bge', 5810260), (5810228, 'b', 5810360), (5810304, 'blt', 5810356), (5810356, 'b', 5810360), (5810548, 'bne', 5812360), (5810568, 'bne', 5812360), (5810588, 'bne', 5811140), (5810644, 'beq', 5810788), (5810692, 'ble', 5810788), (5810768, 'blt', 5810784), (5810784, 'b', 5810788), (5810800, 'beq', 5811136), (5811012, 'beq', 5811132), (5811132, 'b', 5811136), (5811136, 'b', 5811140), (5811156, 'beq', 5812356), (5811224, 'bge', 5812208), (5811332, 'blt', 5812168), (5811352, 'bge', 5812168), (5811448, 'blt', 5811544), (5811528, 'b', 5811756), (5811644, 'bge', 5811728), (5811724, 'b', 5811748), (5811764, 'blt', 5812168), (5811860, 'blt', 5811944), (5811940, 'b', 5812156), (5812044, 'bge', 5812128), (5812124, 'b', 5812148), (5812164, 'bgt', 5812184), (5812180, 'b', 5812208), (5812184, 'b', 5812188), (5812204, 'b', 5811180), (5812224, 'beq', 5812348), (5812332, 'b', 5812352), (5812348, 'b', 5812352), (5812352, 'b', 5812356), (5812356, 'b', 5812360), (5812504, 'beq', 5812676), (5812528, 'beq', 5812676), (5812692, 'beq', 5812864), (5812716, 'beq', 5812864), (5812880, 'beq', 5813052), (5812904, 'beq', 5813052), (5813068, 'beq', 5813240), (5813092, 'beq', 5813240), (5813256, 'beq', 5813428), (5813280, 'beq', 5813428), (5813444, 'beq', 5813616), (5813468, 'beq', 5813616), (5813616, 'b', 5813620), (5813636, 'b', 5810136), (5813644, 'b', 5813648), (5813648, 'b', 5813652), (5813668, 'b', 5810064), (5813716, 'beq', 5813888), (5813804, 'beq', 5813888), (5813980, 'blt', 5814020)],
        semantics=('[World preRenderUpdate:fastSlowDT:cameraZ:projectionMatrix:] (imp 0x00583c50, 7877w): **the render-prep giant** - **operator float* x28 + operator float* (Vector) x25** + **linearInterpolate x10 + clamp_float x7** + the helpers 0x582eb4 x5 / 0x58bbd8 x5 + makeIntpair x4 + memset x4 + objc x7 + consts 0x3f80 (1.0f)/0x200 (512)/0x140 (320)/0x1f8 (504)/0x40/0x14/0xff/0x7f/0x20/0xa + **3 out-of-window calls** (external helpers): the camera interpolation core (10 lerps per frame for the smooth camera!).\n'),
    ),
    dict(
        name='ws_10',
        method='World -[pauseUpdates]',
        types='v8@0:4',
        start=5947812,
        end=5948240,
        disasm='disasm_worldtileloader_ws_10.txt',
        base_add=5947828,
        base_literal=5948236,
        boundary='ARM.exidx end 0x005ac350 (listing bound); next ObjC IMP 0x005ac350 World -[resetPauseIdleTimer]',
        selectors={
                 0x5ac330: (15195604, 'count'),
                 0x5ac33c: (15195676, 'setPaused:'),
                 0x5ac344: (15195680, 'sendHeartbeatData'),
        },
        imports={
                 0x5ac32c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5ac328: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x5ac334: (17155964, 'OBJC_IVAR_$_World.serverClients', 956),
                 0x5ac338: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5ac348: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={},
        instructions=[(5947812, 'push {r4, r5, fp, lr}'), (5948236, 'adceq r3, fp, r8, lsr sb')],
        calls=[(5947940, 'blx r2'), (5948072, 'blx ip'), (5948168, 'blx ip'), (5948188, 'blx r2')],
        branches=[(5947876, 'beq', 5947952), (5947948, 'bhi', 5948076), (5947988, 'bne', 5948076)],
        semantics=('[World pauseUpdates] (imp 0x005ac1a4, 107w): the pause toggle - objc x3 + sel x3.\n'),
    ),
    dict(
        name='ws_11',
        method='World -[preUpdate:]',
        types='v12@0:4f8',
        start=6060228,
        end=6062228,
        disasm='disasm_worldtileloader_ws_11.txt',
        base_add=6060244,
        base_literal=6062224,
        boundary='ARM.exidx end 0x005c8094 (listing bound); next ObjC IMP 0x005c8094 World -[showBlockheadAvailablePrompt:forBlockhead:]',
        selectors={
                 0x5c8028: (15197980, 'startBulkDatabaseUpdate'),
                 0x5c8030: (15197984, 'serverMigrationComplete'),
                 0x5c8034: (15197988, 'startBulkTransaction'),
                 0x5c8038: (15197992, 'decommissionOldBlocks'),
                 0x5c803c: (15198012, 'lightBlockMigrationComplete'),
                 0x5c8044: (15198008, 'convertLightBlocks'),
                 0x5c8048: (15198004, 'saveAndSendOnlyBlocksThatNeedToBeSent'),
                 0x5c8050: (15198000, 'sendLightblocksToClients'),
                 0x5c8054: (15197996, 'startBulkLightBlockTransaction'),
                 0x5c805c: (15198016, 'finishBulkLightBlockTransaction'),
                 0x5c8060: (15198020, 'removeLightBlockFiles'),
                 0x5c8068: (15198024, 'convertWorld'),
                 0x5c806c: (15196208, 'finishBulkDatabaseUpdate'),
                 0x5c8070: (15196340, 'saveAll'),
                 0x5c8074: (15198028, 'appDatabaseEnvironment'),
                 0x5c807c: (15198032, 'finishBulkTransaction'),
                 0x5c8080: (15198036, 'removeWorldFiles'),
                 0x5c8084: (15196664, 'update:'),
                 0x5c8088: (15195544, 'instance'),
        },
        imports={
                 0x5c8024: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5c8020: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x5c802c: (17156008, 'OBJC_IVAR_$_World.databaseConvertor', 3408),
                 0x5c8040: (17156724, 'OBJC_IVAR_$_World.lightblockSaveCounter', 3388),
                 0x5c804c: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5c8058: (17156104, 'OBJC_IVAR_$_World.worldTileLoader', 420),
                 0x5c8064: (17156700, 'OBJC_IVAR_$_World.saveCounter', 3384),
        },
        classes={
                 0x5c808c: (15245420, 'OBJC_CLASS_$_TipManager'),
        },
        instructions=[(6060228, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6062224, 'adceq r8, sb, r8, lsl r2')],
        calls=[(6060312, 'blx lr'), (6060448, 'blx r2'), (6060524, 'blx r2'), (6060584, 'blx r3'), (6060784, 'blx r2'), (6060820, 'blx r3'), (6060856, 'blx r3'), (6060892, 'blx r3'), (6060980, 'blx r2'), (6061112, 'blx r2'), (6061188, 'blx r2'), (6061320, 'blx lr'), (6061552, 'blx r3'), (6061568, 'blx r2'), (6061600, 'blx r3'), (6061620, 'blx r2'), (6061772, 'blx r3'), (6061900, 'blx r2'), (6061984, 'blx ip'), (6062000, 'blx r2'), (6062076, 'blx ip'), (6062100, 'blx r3')],
        branches=[(6060344, 'beq', 6060528), (6060384, 'beq', 6060528), (6060460, 'bne', 6060528), (6060616, 'beq', 6061200), (6061020, 'blt', 6061196), (6061124, 'beq', 6061192), (6061192, 'b', 6061196), (6061196, 'b', 6061200), (6061396, 'blt', 6062008), (6061656, 'beq', 6061828), (6061696, 'beq', 6061828), (6061792, 'beq', 6061816), (6061836, 'beq', 6061904)],
        semantics=('[World preUpdate:] (imp 0x005c78c4, 500w): the pre-update hook - sel x19 + objc x22 + consts 0x64 (100)/0xb (11).\n'),
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
        'batch': 'World simulation core (E101): the tick and render-prep giants, the simulate pump; 12 bodies',
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
                        default=NATIVE / 'world_simulation.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale world_simulation.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
