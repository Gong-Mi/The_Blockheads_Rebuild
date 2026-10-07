#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The electricity line: the SteamTrain core cluster (the train itself): the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 4243 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/STEAMTRAIN_CORE.md for the prose and boundaries.
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
    'bl 0xd18e60': 0x00d18e60,
    'bl 0xd1972c': 0x00d1972c,
    'bl 0xd1ba7c': 0x00d1ba7c,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl method.Vector2.operator_Vector2_': 0x004d0418,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__aeabi_memcpy': 0x001c3c08,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.texCoordsForImageIndex_int_': 0x004d6820,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileIsSolid_Tile_': 0x00a1179c,
}

SPECS = [
    dict(
        name='st_loadderived',
        method='SteamTrain -[loadDerivedStuff]',
        types='v8@0:4',
        start=13725872,
        end=13729404,
        disasm='disasm_worldtileloader_st_loadderived.txt',
        base_add=13725892,
        base_literal=13729400,
        boundary='ARM.exidx end 0x00d17e7c (listing bound); next ObjC IMP 0x00d17e7c SteamTrain -[objectType]',
        selectors={
                 0xd17e14: (15238464, 'loadDerivedStuff'),
                 0xd17e24: (15238456, 'initWithWidth:height:depth:centerX:centerY:centerZ:topMinS:topMaxS:topMinT:topMaxT:sideMinS:sideMaxS:sideMinT:sideMaxT:calculateNormals:'),
                 0xd17e28: (15238452, 'alloc'),
                 0xd17e44: (15238460, 'initPyramidWithWidth:height:depth:centerX:centerY:centerZ:topMinS:topMaxS:topMinT:topMaxT:sideMinS:sideMaxS:sideMinT:sideMaxT:calculateNormals:topScale:rightScale:'),
        },
        imports={
                 0xd17e10: (17151900, 'objc_msgSendSuper2'),
                 0xd17e20: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd17e1c: (17168256, 'OBJC_IVAR_$_SteamTrain.doorCube', 240),
                 0xd17e30: (17168260, 'OBJC_IVAR_$_SteamTrain.roofPoleCube', 236),
                 0xd17e34: (17168264, 'OBJC_IVAR_$_SteamTrain.roofCube', 232),
                 0xd17e38: (17168268, 'OBJC_IVAR_$_SteamTrain.backWallCube', 228),
                 0xd17e3c: (17168272, 'OBJC_IVAR_$_SteamTrain.driverCabCube', 220),
                 0xd17e40: (17168276, 'OBJC_IVAR_$_SteamTrain.chimneyCube', 224),
                 0xd17e48: (17168280, 'OBJC_IVAR_$_SteamTrain.frontGrillCube', 216),
                 0xd17e4c: (17168284, 'OBJC_IVAR_$_SteamTrain.boilerCube', 208),
                 0xd17e50: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xd17e54: (17161200, 'OBJC_IVAR_$_TrainCar.leftWheelPos', 96),
                 0xd17e5c: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xd17e60: (17161204, 'OBJC_IVAR_$_TrainCar.rightWheelPos', 104),
                 0xd17e64: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xd17e68: (17168288, 'OBJC_IVAR_$_SteamTrain.rightStationSearchTilePos', 292),
                 0xd17e6c: (17168292, 'OBJC_IVAR_$_SteamTrain.leftStationSearchTilePos', 284),
                 0xd17e70: (17168296, 'OBJC_IVAR_$_SteamTrain.serachingForRightStationName', 281),
                 0xd17e74: (17168300, 'OBJC_IVAR_$_SteamTrain.serachingForLeftStationName', 280),
        },
        classes={
                 0xd17e18: (15253264, 'OBJC_CLASS_$_SteamTrain'),
                 0xd17e2c: (15251184, 'OBJC_CLASS_$_DrawCube'),
        },
        instructions=[(13725872, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13725916, 'bl sym.texCoordsForImageIndex_int_'), (13726072, 'vadd.f32 s2, s2, s4'), (13726824, 'blx r2'), (13727124, 'ldr lr, [sp, 0x78]'), (13729400, 'eorseq r8, r4, r8, lsr 20')],
        calls=[(13725916, 'bl sym.texCoordsForImageIndex_int_'), (13726056, 'blx lr'), (13726272, 'blx lr'), (13726304, 'bl sym.texCoordsForImageIndex_int_'), (13726824, 'blx r2'), (13727128, 'blx lr'), (13727180, 'blx ip'), (13727412, 'blx lr'), (13727464, 'blx ip'), (13727684, 'blx lr'), (13727736, 'blx ip'), (13727956, 'blx lr'), (13728008, 'blx ip'), (13728228, 'blx lr'), (13728280, 'blx ip'), (13728492, 'blx lr'), (13728544, 'blx ip'), (13728764, 'blx lr'), (13728824, 'blx r3'), (13728928, 'bl method.Vector2.Vector2_float__float_'), (13728948, 'bl method.Vector2.operator_Vector2_'), (13729044, 'bl method.Vector2.Vector2_float__float_'), (13729064, 'bl method.Vector2.operator_Vector2_')],
        branches=[(13726940, 'b', 13727000), (13729120, 'bne', 13729284)],
        semantics=("[SteamTrain loadDerivedStuff] (imp 0x00d170b0, 883w): builds the train's derived geometry. `texCoordsForImageIndex(int)` (C symbol @0xd170dc) with image index **0x243 (579)** supplies the sprite UVs; the quad-corner arithmetic follows (the vadd.f32 pair-folds @0xd17178-0xd171a8: corner = origin + size on both axes) and a packed ~13-float argument frame feeds the geometry append (blx @0xd17468, then the second append @0xd17594 with the same 0x30/0x34/0x38 tail slots). The float pool at 0xd174e0..0xd17514 carries the geometry constants (0x3f99999a=1.2f, 0x3f4ccccd=0.8f, 0x3f800000=1.0f, 0x3fc00000=1.5f, 0x3fa66666=1.3f, ...); the fffffca8/fc9c/fca0/fca4 ivar cells thread the state.\n"),
    ),
    dict(
        name='st_ctor_pos',
        method='SteamTrain -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:placedByClient:]',
        types='@36@0:4@8@12{?=ii}16@24@28@32',
        start=13729432,
        end=13731892,
        disasm='disasm_worldtileloader_st_ctor_pos.txt',
        base_add=13729448,
        base_literal=13731888,
        boundary='ARM.exidx end 0x00d18834 (listing bound); next ObjC IMP 0x00d18834 SteamTrain -[initWithWorld:dynamicWorld:saveDict:cache:]',
        selectors={
                 0xd187d0: (15238468, 'initWithWorld:dynamicWorld:atPosition:cache:saveDict:placedByClient:'),
                 0xd187e8: (15238480, 'boolValue'),
                 0xd187f0: (15238472, 'objectForKey:'),
                 0xd187f4: (15238476, 'floatValue'),
                 0xd1880c: (15238484, 'checkForTrainCarUnderTap:'),
                 0xd18810: (15238488, 'engineCar'),
                 0xd18814: (15238492, 'connectsToOtherCars'),
                 0xd18818: (15238504, 'setEngineCar:'),
                 0xd18820: (15238508, 'setLeftCar:'),
                 0xd18824: (15238496, 'retain'),
                 0xd1882c: (15238500, 'setRightCar:'),
        },
        imports={
                 0xd187e4: (17151904, 'objc_msgSend'),
                 0xd187ec: (16441064, '__CFConstantStringClassReference'),
                 0xd187f8: (16441048, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xd187d4: (17168304, 'OBJC_IVAR_$_SteamTrain.fuelCounter', 264),
                 0xd187d8: (17168308, 'OBJC_IVAR_$_SteamTrain.hasFuel', 268),
                 0xd187dc: (17168312, 'OBJC_IVAR_$_SteamTrain.fuelFraction', 260),
                 0xd187e0: (17168316, 'OBJC_IVAR_$_SteamTrain.goingRight', 252),
                 0xd187fc: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xd18800: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xd18804: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xd1881c: (17161212, 'OBJC_IVAR_$_TrainCar.rightCar', 168),
                 0xd18828: (17161216, 'OBJC_IVAR_$_TrainCar.leftCar', 172),
        },
        classes={
                 0xd187c8: (15253264, 'OBJC_CLASS_$_SteamTrain'),
        },
        instructions=[(13729432, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13729640, 'bl loc.imp.objc_msgSendSuper2'), (13729748, 'strb ip, [r5]'), (13729816, 'ldr r0, [0x00d187d8]'), (13730060, 'cmp r0, 2'), (13731888, 'eorseq r7, r4, r4, asr 24')],
        calls=[(13729640, 'bl loc.imp.objc_msgSendSuper2'), (13729944, 'blx r4'), (13729960, 'blx r2'), (13730008, 'blx r3'), (13730024, 'blx r2'), (13730124, 'bl sym.makeIntpair_int__int_'), (13730176, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13730228, 'bl sym.tileIsSolid_Tile_'), (13730304, 'bl sym.makeIntpair_int__int_'), (13730372, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13730468, 'bl sym.makeIntpair_int__int_'), (13730536, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13730608, 'bl sym.makeIntpair_int__int_'), (13730660, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13730712, 'bl sym.tileIsSolid_Tile_'), (13730752, 'bl sym.makeIntpair_int__int_'), (13730820, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13730880, 'bl sym.makeIntpair_int__int_'), (13730948, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13731100, 'bl method.Vector2.Vector2_float__float_'), (13731128, 'bl loc.imp.objc_msgSend'), (13731204, 'blx r3'), (13731260, 'blx r2'), (13731388, 'blx r3'), (13731456, 'blx ip'), (13731496, 'blx ip'), (13731612, 'blx r4'), (13731680, 'blx ip'), (13731720, 'blx ip')],
        branches=[(13729668, 'bne', 13729684), (13729680, 'b', 13731772), (13729812, 'beq', 13730048), (13730064, 'bge', 13731764), (13730196, 'beq', 13731744), (13730220, 'beq', 13730576), (13730240, 'beq', 13730408), (13730392, 'beq', 13730404), (13730404, 'b', 13730572), (13730556, 'beq', 13730568), (13730568, 'b', 13730572), (13730572, 'b', 13730576), (13730584, 'beq', 13731740), (13730680, 'beq', 13731736), (13730704, 'beq', 13730988), (13730724, 'beq', 13730856), (13730840, 'beq', 13730852), (13730852, 'b', 13730984), (13730968, 'beq', 13730980), (13730980, 'b', 13730984), (13730984, 'b', 13730988), (13730996, 'beq', 13731732), (13731148, 'beq', 13731728), (13731216, 'bne', 13731728), (13731272, 'beq', 13731728), (13731284, 'bne', 13731528), (13731524, 'b', 13731724), (13731724, 'b', 13731728), (13731728, 'b', 13731732), (13731732, 'b', 13731736), (13731736, 'b', 13731740), (13731740, 'b', 13731744), (13731744, 'b', 13731748), (13731760, 'b', 13730056)],
        semantics=("[SteamTrain initWithWorld:dynamicWorld:atPosition:cache:saveDict:placedByClient:] (imp 0x00d17e98, 615w): the placed ctor - super2 (@0xd17f68) then the **fffffcbc/fcc0/fcc4/fcc8 ivar-cell byte writes** (strb 1 = the derived flags @0xd17fd4/0xd17ff4); the saveDict decode chain runs the fffe28a5c/fff4e3f4/ffe28a54/ffe28a58/fff4e3e4 pulls (@0xd18018+); the `cmp r0, 2` loop (@0xd1810c: `for i in 0..2`) builds the train's consist (the cars); nil-arm via the fffe2c41c check.\n"),
    ),
    dict(
        name='st_ctor_net',
        method='SteamTrain -[initWithWorld:dynamicWorld:cache:netData:]',
        types='@24@0:4@8@12@16@20',
        start=13732612,
        end=13733472,
        disasm='disasm_worldtileloader_st_ctor_net.txt',
        base_add=13732628,
        base_literal=13733468,
        boundary='ARM.exidx end 0x00d18e60 (listing bound); next ObjC IMP 0x00d18e84 SteamTrain -[getSaveDict]',
        selectors={
                 0xd18e18: (15238516, 'initWithWorld:dynamicWorld:cache:netData:'),
                 0xd18e24: (15238524, 'length'),
                 0xd18e3c: (15238520, 'getBytes:length:'),
                 0xd18e44: (15238496, 'retain'),
                 0xd18e4c: (15238472, 'objectForKey:'),
                 0xd18e50: (15238532, 'gzipInflate'),
                 0xd18e58: (15238528, 'subdataWithRange:'),
        },
        imports={
                 0xd18e14: (17151900, 'objc_msgSendSuper2'),
                 0xd18e20: (17151904, 'objc_msgSend'),
                 0xd18e48: (16441112, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xd18e28: (17168320, 'OBJC_IVAR_$_SteamTrain.stopped', 325),
                 0xd18e2c: (17168316, 'OBJC_IVAR_$_SteamTrain.goingRight', 252),
                 0xd18e30: (17168312, 'OBJC_IVAR_$_SteamTrain.fuelFraction', 260),
                 0xd18e38: (17168308, 'OBJC_IVAR_$_SteamTrain.hasFuel', 268),
                 0xd18e40: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
        },
        classes={
                 0xd18e1c: (15253264, 'OBJC_CLASS_$_SteamTrain'),
        },
        instructions=[(13732612, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13732764, 'blx r6'), (13732996, 'vdiv.f32 s0, s0, s2'), (13733056, 'ldr r4, [lr]'), (13733468, 'ldrsbteq r6, [r4], -r8')],
        calls=[(13732764, 'blx r6'), (13732952, 'blx r7'), (13733084, 'blx r4'), (13733156, 'bl loc.imp.objc_msgSend'), (13733224, 'bl loc.imp.objc_msgSend'), (13733248, 'blx r2'), (13733252, 'bl 0xd18e60'), (13733336, 'blx r3'), (13733352, 'blx r2')],
        branches=[(13732792, 'bne', 13732808), (13732804, 'b', 13733384), (13733092, 'bls', 13733376)],
        semantics=('[SteamTrain initWithWorld:dynamicWorld:cache:netData:] (imp 0x00d18b04, 215w): the netData ctor - super2 (@0xd18b9c) + the fffffcc4..fccc ivar reads; the net position is dequantized (`vcvt.f32.s32` + `vdiv.f32` @0xd18c7c-0xd18c84) and the decoded bytes written through the fffe28a84 chain (@0xd18c5c-0xd18cc0); nil-arm as above.\n'),
    ),
    dict(
        name='st_creationnetdata',
        method='SteamTrain -[creationNetDataForClient:]',
        types='@12@0:4@8',
        start=13734280,
        end=13735724,
        disasm='disasm_worldtileloader_st_creationnetdata.txt',
        base_add=13734296,
        base_literal=13735720,
        boundary='ARM.exidx end 0x00d1972c (listing bound); next ObjC IMP 0x00d19898 SteamTrain -[dealloc]',
        selectors={
                 0xd196c4: (15238552, 'trainCarCreationNetData'),
                 0xd196f8: (15238560, 'dictionary'),
                 0xd19700: (15238556, 'dataWithBytes:length:'),
                 0xd1970c: (15238544, 'setObject:forKey:'),
                 0xd19720: (15238568, 'appendData:'),
                 0xd19724: (15238564, 'gzipDeflate'),
        },
        imports={
                 0xd196f4: (17151904, 'objc_msgSend'),
                 0xd19708: (16441128, '__CFConstantStringClassReference'),
                 0xd19714: (16441144, '__CFConstantStringClassReference'),
                 0xd1971c: (16441112, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xd196c8: (17168324, 'OBJC_IVAR_$_SteamTrain.stopAtGoalPos', 324),
                 0xd196cc: (17168328, 'OBJC_IVAR_$_SteamTrain.rightStationGoalPos', 308),
                 0xd196d0: (17168332, 'OBJC_IVAR_$_SteamTrain.leftStationGoalPos', 300),
                 0xd196d4: (17168320, 'OBJC_IVAR_$_SteamTrain.stopped', 325),
                 0xd196d8: (17168316, 'OBJC_IVAR_$_SteamTrain.goingRight', 252),
                 0xd196dc: (17168308, 'OBJC_IVAR_$_SteamTrain.hasFuel', 268),
                 0xd196e0: (17168312, 'OBJC_IVAR_$_SteamTrain.fuelFraction', 260),
                 0xd196e8: (17168336, 'OBJC_IVAR_$_SteamTrain.stationGoalPos', 316),
                 0xd196ec: (17168340, 'OBJC_IVAR_$_SteamTrain.sendWhistle', 269),
                 0xd196f0: (17168344, 'OBJC_IVAR_$_SteamTrain.leftStationName', 272),
                 0xd19710: (17168348, 'OBJC_IVAR_$_SteamTrain.rightStationName', 276),
                 0xd19718: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
        },
        classes={
                 0xd196fc: (15251196, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0xd19704: (15251192, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(13734280, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13734408, 'bl sym.imp.memset'), (13734524, 'bl sym.imp.__aeabi_memcpy'), (13734576, 'strh r0, [fp, -0x48]'), (13734704, 'strb r2, [fp, -0x43]'), (13735720, 'eorseq r6, r4, r4, asr sb')],
        calls=[(13734372, 'bl loc.imp.objc_msgSend_stret'), (13734408, 'bl sym.imp.memset'), (13734524, 'bl sym.imp.__aeabi_memcpy'), (13735092, 'blx r5'), (13735128, 'blx r3'), (13735252, 'blx ip'), (13735380, 'blx ip'), (13735508, 'blx ip'), (13735516, 'bl 0xd1972c'), (13735576, 'blx lr'), (13735604, 'blx r3')],
        branches=[(13734356, 'beq', 13734380), (13734376, 'b', 13734412), (13734820, 'beq', 13734884), (13734876, 'b', 13734896), (13734928, 'beq', 13734972), (13735164, 'beq', 13735256), (13735292, 'beq', 13735384), (13735420, 'beq', 13735512)],
        semantics=('[SteamTrain creationNetDataForClient:] (imp 0x00d19188, 361w): packs the creation record - a **0x68 (104)-byte stret** zeroed (`memset 0x68` @0xd19208) then filled by **__aeabi_memcpy** (@0xd1927c) from the ivar fields; the position is quantized (`vmul.f32` + `vcvt.s32.f32` @0xd192a4-0xd192b0) into the record; the flag bytes are booleanized (`ldrsb; cmp; movne 1; moveq 0` @0xd192e8-0xd19330) - the wire record for the client (paired with the E40-family net receive).\n'),
    ),
    dict(
        name='st_dealloc',
        method='SteamTrain -[dealloc]',
        types='v8@0:4',
        start=13736088,
        end=13736836,
        disasm='disasm_worldtileloader_st_dealloc.txt',
        base_add=13736104,
        base_literal=13736832,
        boundary='ARM.exidx end 0x00d19b84 (listing bound); next ObjC IMP 0x00d19b84 SteamTrain -[remoteUpdate:]',
        selectors={
                 0xd19b40: (15238580, 'dealloc'),
                 0xd19b4c: (15238576, 'stop'),
                 0xd19b58: (15238572, 'release'),
        },
        imports={
                 0xd19b3c: (17151900, 'objc_msgSendSuper2'),
                 0xd19b48: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd19b50: (17168352, 'OBJC_IVAR_$_SteamTrain.railSound', 248),
                 0xd19b54: (17168356, 'OBJC_IVAR_$_SteamTrain.steamSound', 244),
                 0xd19b5c: (17168256, 'OBJC_IVAR_$_SteamTrain.doorCube', 240),
                 0xd19b60: (17168260, 'OBJC_IVAR_$_SteamTrain.roofPoleCube', 236),
                 0xd19b64: (17168264, 'OBJC_IVAR_$_SteamTrain.roofCube', 232),
                 0xd19b68: (17168268, 'OBJC_IVAR_$_SteamTrain.backWallCube', 228),
                 0xd19b6c: (17168276, 'OBJC_IVAR_$_SteamTrain.chimneyCube', 224),
                 0xd19b70: (17168272, 'OBJC_IVAR_$_SteamTrain.driverCabCube', 220),
                 0xd19b74: (17168280, 'OBJC_IVAR_$_SteamTrain.frontGrillCube', 216),
                 0xd19b78: (17168360, 'OBJC_IVAR_$_SteamTrain.wheelRodCube', 212),
                 0xd19b7c: (17168284, 'OBJC_IVAR_$_SteamTrain.boilerCube', 208),
        },
        classes={
                 0xd19b44: (15253264, 'OBJC_CLASS_$_SteamTrain'),
        },
        instructions=[(13736088, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13736280, 'ldr r0, [r0, r2]'), (13736352, 'blx r5'), (13736832, 'eorseq r6, r4, r4, asr 4')],
        calls=[(13736352, 'blx r5'), (13736388, 'blx r3'), (13736424, 'blx r3'), (13736460, 'blx r3'), (13736496, 'blx r3'), (13736532, 'blx r3'), (13736568, 'blx r3'), (13736604, 'blx r3'), (13736640, 'blx r3'), (13736676, 'blx r3'), (13736712, 'blx r3'), (13736752, 'blx r2')],
        branches=[],
        semantics=('[SteamTrain dealloc] (imp 0x00d19898, 187w): the ivar-cell read wall enumerates the **fffffc8c..fca8** cells (@0xd198f4-0xd19958, twelve+ cells - an ivar oracle for the class) then the ffe28abc/ffe28ac0 chain runs the cache removals; no branches.\n'),
    ),
    dict(
        name='st_remoteupdate',
        method='SteamTrain -[remoteUpdate:]',
        types='v12@0:4@8',
        start=13736836,
        end=13739280,
        disasm='disasm_worldtileloader_st_remoteupdate.txt',
        base_add=13736852,
        base_literal=13739276,
        boundary='ARM.exidx end 0x00d1a510 (listing bound); next ObjC IMP 0x00d1a510 SteamTrain -[updateSearchForStations]',
        selectors={
                 0xd1a474: (15238584, 'remoteUpdate:'),
                 0xd1a484: (15238520, 'getBytes:length:'),
                 0xd1a490: (15238588, 'isNet'),
                 0xd1a494: (15238592, 'updateHasFuel'),
                 0xd1a4b4: (15238604, 'isPlaying'),
                 0xd1a4bc: (15238600, 'soundNamed:'),
                 0xd1a4c0: (15238596, 'instance'),
                 0xd1a4c8: (15238608, 'hasFinishedPlaying'),
                 0xd1a4d4: (15238612, 'playAtPosition:'),
                 0xd1a4dc: (15238524, 'length'),
                 0xd1a4ec: (15238572, 'release'),
                 0xd1a4f4: (15238528, 'subdataWithRange:'),
                 0xd1a4f8: (15238496, 'retain'),
                 0xd1a500: (15238472, 'objectForKey:'),
                 0xd1a508: (15238532, 'gzipInflate'),
        },
        imports={
                 0xd1a470: (17151900, 'objc_msgSendSuper2'),
                 0xd1a480: (17151904, 'objc_msgSend'),
                 0xd1a4b8: (16441160, '__CFConstantStringClassReference'),
                 0xd1a4fc: (16441144, '__CFConstantStringClassReference'),
                 0xd1a504: (16441128, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xd1a47c: (17168312, 'OBJC_IVAR_$_SteamTrain.fuelFraction', 260),
                 0xd1a488: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xd1a48c: (17161220, 'OBJC_IVAR_$_TrainCar.riders', 76),
                 0xd1a498: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xd1a49c: (17168336, 'OBJC_IVAR_$_SteamTrain.stationGoalPos', 316),
                 0xd1a4a0: (17168320, 'OBJC_IVAR_$_SteamTrain.stopped', 325),
                 0xd1a4a4: (17168316, 'OBJC_IVAR_$_SteamTrain.goingRight', 252),
                 0xd1a4a8: (17168324, 'OBJC_IVAR_$_SteamTrain.stopAtGoalPos', 324),
                 0xd1a4ac: (17168328, 'OBJC_IVAR_$_SteamTrain.rightStationGoalPos', 308),
                 0xd1a4b0: (17168332, 'OBJC_IVAR_$_SteamTrain.leftStationGoalPos', 300),
                 0xd1a4cc: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xd1a4d8: (17168340, 'OBJC_IVAR_$_SteamTrain.sendWhistle', 269),
                 0xd1a4e0: (17168364, 'OBJC_IVAR_$_SteamTrain.needsToUpdateChoiceUI', 326),
                 0xd1a4e8: (17168344, 'OBJC_IVAR_$_SteamTrain.leftStationName', 272),
                 0xd1a4f0: (17168348, 'OBJC_IVAR_$_SteamTrain.rightStationName', 276),
        },
        classes={
                 0xd1a478: (15253264, 'OBJC_CLASS_$_SteamTrain'),
                 0xd1a4c4: (15251200, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(13736836, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13737032, 'vdiv.f32 s0, s0, s2'), (13737072, 'vcmpe.f32 s0, s4'), (13737284, 'cmp r0, 0'), (13737400, 'cmp r0, 0'), (13739276, 'eorseq r5, r4, r8, asr pc')],
        calls=[(13736928, 'blx lr'), (13737012, 'blx ip'), (13737392, 'blx r2'), (13737548, 'blx r2'), (13737720, 'blx r2'), (13738032, 'bl sym.makeIntpair_int__int_'), (13738100, 'bl sym.makeIntpair_int__int_'), (13738236, 'blx r5'), (13738256, 'blx r3'), (13738280, 'blx r2'), (13738336, 'blx r2'), (13738440, 'bl loc.imp.objc_msgSend'), (13738640, 'bl loc.imp.objc_msgSend'), (13738704, 'bl loc.imp.objc_msgSend'), (13738748, 'bl loc.imp.objc_msgSend'), (13738816, 'bl loc.imp.objc_msgSend'), (13738840, 'blx r2'), (13738892, 'blx r2'), (13738896, 'bl 0xd18e60'), (13739012, 'blx r3'), (13739028, 'blx r2'), (13739072, 'blx r3'), (13739088, 'blx r2')],
        branches=[(13737080, 'bgt', 13737248), (13737132, 'bmi', 13737248), (13737144, 'bne', 13737192), (13737188, 'bgt', 13737248), (13737200, 'ble', 13737620), (13737244, 'bpl', 13737620), (13737288, 'beq', 13737464), (13737328, 'beq', 13737460), (13737404, 'bne', 13737460), (13737448, 'bpl', 13737460), (13737460, 'b', 13737464), (13737472, 'bne', 13737616), (13737576, 'bne', 13737612), (13737612, 'b', 13737616), (13737616, 'b', 13737620), (13737656, 'beq', 13737952), (13737732, 'beq', 13737952), (13737864, 'beq', 13737916), (13737900, 'b', 13737948), (13737948, 'b', 13737952), (13737984, 'beq', 13738124), (13738132, 'beq', 13738536), (13738292, 'beq', 13738352), (13738348, 'beq', 13738532), (13738468, 'bne', 13738528), (13738528, 'b', 13738532), (13738532, 'b', 13738536), (13738848, 'bls', 13739112)],
        semantics=('[SteamTrain remoteUpdate:] (imp 0x00d19b84, 611w): applies a network update - the position is dequantized (`vcvt.f32.s32; vdiv.f32` @0xd19c40-0xd19c48) and range-checked with the float compares (`vcmpe; bgt/bmi/bpl` @0xd19c70-0xd19d1c: the movement bounds, with the `ldrsh == 0` / `<= 0` edge arms); the ffffcacc world flag gates @0xd19d44; the ffffe110 + ffe28ac8 chain calls the per-blockhead notify (@0xd19d50-0xd19db8); the `out=1` record notes an out-register.\n'),
    ),
    dict(
        name='st_searchstations',
        method='SteamTrain -[updateSearchForStations]',
        types='v8@0:4',
        start=13739280,
        end=13744764,
        disasm='disasm_worldtileloader_st_searchstations.txt',
        base_add=13739296,
        base_literal=13742972,
        boundary='ARM.exidx end 0x00d1ba7c (listing bound); next ObjC IMP 0x00d1bab8 SteamTrain -[update:accurateDT:isSimulation:]',
        selectors={
                 0xd1b6f4: (15238616, 'worldWidthMacro'),
                 0xd1b904: (15238620, 'interactionObjectAtPos:'),
                 0xd1b9f4: (15238624, 'interactionObjectType'),
                 0xd1ba18: (15238572, 'release'),
                 0xd1ba20: (15238616, 'worldWidthMacro'),
                 0xd1ba28: (15238620, 'interactionObjectAtPos:'),
                 0xd1ba4c: (15238624, 'interactionObjectType'),
                 0xd1ba54: (15238496, 'retain'),
                 0xd1ba58: (15238628, 'title'),
        },
        imports={
                 0xd1b9f0: (17151904, 'objc_msgSend'),
                 0xd1ba14: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd1b380: (17168300, 'OBJC_IVAR_$_SteamTrain.serachingForLeftStationName', 280),
                 0xd1b384: (17168292, 'OBJC_IVAR_$_SteamTrain.leftStationSearchTilePos', 284),
                 0xd1b388: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xd1b6ec: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xd1b8fc: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xd1b9f8: (17168332, 'OBJC_IVAR_$_SteamTrain.leftStationGoalPos', 300),
                 0xd1b9fc: (17168300, 'OBJC_IVAR_$_SteamTrain.serachingForLeftStationName', 280),
                 0xd1ba00: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xd1ba04: (17168292, 'OBJC_IVAR_$_SteamTrain.leftStationSearchTilePos', 284),
                 0xd1ba08: (17168364, 'OBJC_IVAR_$_SteamTrain.needsToUpdateChoiceUI', 326),
                 0xd1ba0c: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xd1ba10: (17168344, 'OBJC_IVAR_$_SteamTrain.leftStationName', 272),
                 0xd1ba1c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xd1ba24: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xd1ba2c: (17168296, 'OBJC_IVAR_$_SteamTrain.serachingForRightStationName', 281),
                 0xd1ba30: (17168288, 'OBJC_IVAR_$_SteamTrain.rightStationSearchTilePos', 292),
                 0xd1ba34: (17168348, 'OBJC_IVAR_$_SteamTrain.rightStationName', 276),
                 0xd1ba50: (17168328, 'OBJC_IVAR_$_SteamTrain.rightStationGoalPos', 308),
        },
        classes={},
        instructions=[(13739280, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13739340, 'beq 0xd1af78'), (13739364, 'bge 0xd1af74'), (13739508, 'cmp r0, 0x62'), (13739672, 'cmp r0, 0x62'), (13739872, 'cmp r0, 0x30'), (13744760, 'eorseq r4, r4, r8, lsr 29')],
        calls=[(13739420, 'bl sym.makeIntpair_int__int_'), (13739472, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13739572, 'bl sym.makeIntpair_int__int_'), (13739640, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13739736, 'bl sym.makeIntpair_int__int_'), (13739804, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13739968, 'bl loc.imp.objc_msgSend'), (13739992, 'bl sym.imp.__aeabi_idiv'), (13740088, 'bl loc.imp.objc_msgSend'), (13740208, 'bl loc.imp.objc_msgSend'), (13740224, 'bl sym.imp.__aeabi_idiv'), (13740320, 'bl loc.imp.objc_msgSend'), (13740404, 'bl 0xd1ba7c'), (13740500, 'bl loc.imp.objc_msgSend'), (13740564, 'blx r2'), (13740752, 'blx r6'), (13740772, 'blx r2'), (13740788, 'blx r2'), (13741064, 'bl loc.imp.objc_msgSend'), (13741088, 'bl sym.imp.__aeabi_idiv'), (13741184, 'bl loc.imp.objc_msgSend'), (13741304, 'bl loc.imp.objc_msgSend'), (13741320, 'bl sym.imp.__aeabi_idiv'), (13741416, 'bl loc.imp.objc_msgSend'), (13741500, 'bl 0xd1ba7c'), (13741640, 'blx r4'), (13741848, 'blx r4'), (13742056, 'bl sym.makeIntpair_int__int_'), (13742108, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13742208, 'bl sym.makeIntpair_int__int_'), (13742276, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13742356, 'bl sym.makeIntpair_int__int_'), (13742424, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13742588, 'bl loc.imp.objc_msgSend'), (13742612, 'bl sym.imp.__aeabi_idiv'), (13742708, 'bl loc.imp.objc_msgSend'), (13742828, 'bl loc.imp.objc_msgSend'), (13742844, 'bl sym.imp.__aeabi_idiv'), (13742940, 'bl loc.imp.objc_msgSend'), (13743040, 'bl 0xd1ba7c'), (13743136, 'bl loc.imp.objc_msgSend'), (13743200, 'blx r2'), (13743388, 'blx r6'), (13743408, 'blx r2'), (13743424, 'blx r2'), (13743700, 'bl loc.imp.objc_msgSend'), (13743724, 'bl sym.imp.__aeabi_idiv'), (13743820, 'bl loc.imp.objc_msgSend'), (13743952, 'bl loc.imp.objc_msgSend'), (13743968, 'bl sym.imp.__aeabi_idiv'), (13744064, 'bl loc.imp.objc_msgSend'), (13744160, 'bl 0xd1ba7c'), (13744300, 'blx r4'), (13744520, 'blx r4')],
        branches=[(13739340, 'beq', 13741944), (13739364, 'bge', 13741940), (13739492, 'bne', 13739500), (13739496, 'b', 13741940), (13739512, 'beq', 13739836), (13739660, 'beq', 13739812), (13739676, 'beq', 13739812), (13739824, 'bne', 13739832), (13739828, 'b', 13741940), (13739832, 'b', 13739836), (13739836, 'b', 13739840), (13739852, 'bne', 13741720), (13739876, 'bne', 13740928), (13740004, 'blt', 13740120), (13740116, 'b', 13740400), (13740236, 'bge', 13740352), (13740348, 'b', 13740392), (13740412, 'ble', 13740928), (13740520, 'beq', 13740920), (13740576, 'bne', 13740916), (13740916, 'b', 13740924), (13740920, 'b', 13741940), (13740924, 'b', 13740928), (13740936, 'bne', 13741716), (13741100, 'blt', 13741216), (13741212, 'b', 13741496), (13741332, 'bge', 13741448), (13741444, 'b', 13741488), (13741508, 'ble', 13741712), (13741712, 'b', 13741716), (13741716, 'b', 13741920), (13741920, 'b', 13741924), (13741936, 'b', 13739356), (13741940, 'b', 13741944), (13741976, 'beq', 13744616), (13742000, 'bge', 13744612), (13742128, 'bne', 13742136), (13742132, 'b', 13744612), (13742148, 'beq', 13742456), (13742296, 'beq', 13742432), (13742444, 'bne', 13742452), (13742448, 'b', 13744612), (13742452, 'b', 13742456), (13742456, 'b', 13742460), (13742472, 'bne', 13744392), (13742496, 'bne', 13743564), (13742624, 'blt', 13742740), (13742736, 'b', 13743036), (13742856, 'bge', 13742988), (13742968, 'b', 13743028), (13743048, 'ble', 13743564), (13743156, 'beq', 13743556), (13743212, 'bne', 13743552), (13743552, 'b', 13743560), (13743556, 'b', 13744612), (13743560, 'b', 13743564), (13743572, 'bne', 13744376), (13743736, 'blt', 13743864), (13743848, 'b', 13744156), (13743980, 'bge', 13744108), (13744092, 'b', 13744148), (13744168, 'ble', 13744372), (13744372, 'b', 13744376), (13744376, 'b', 13744592), (13744592, 'b', 13744596), (13744608, 'b', 13741992), (13744612, 'b', 13744616)],
        semantics=("[SteamTrain updateSearchForStations] (imp 0x00d1a510, 1371w): the station search along the track. Gate: the fffffcb8 flag must be non-zero (@0xd1a540-0xd1a54c) else exit 0xd1af78. Loop: `if (step >= 8) return` (@0xd1a560-0xd1a564: **8 probe steps**); per step `makeIntpair` (@0xd1a59c) + `tileAtWorldPositionLoaded(int,int,World*)` (@0xd1a5d0) probes; the tile byte at **+0xb compared with 0x62 ('b' = the station/rail marker)** (@0xd1a5f4, @0xd1a698); the ±1 neighbour probes (y-1 / x+1 / x-1 directions @0xd1a618-0xd1a6d8) continue the search; the tile+3 == 0x30 ('0') branch (@0xd1a760) open the station-side arm. All probes use the fffffcb0/ffffc8a0 world-chain cells.\n"),
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
        'batch': 'SteamTrain core cluster (E69): loadDerivedStuff, the two ctors, creationNetDataForClient:, dealloc, remoteUpdate: and updateSearchForStations; 7 bodies',
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
                        default=NATIVE / 'steamtrain_core.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale steamtrain_core.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
