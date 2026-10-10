#!/usr/bin/env python3
"""Hash-gated recovery of the World camera/zoom/motion line (E107).

The World camera line: the net-blockhead zoom request chain, the
zoom-to-workbench open flow and the motion-to-camera calibration
pipeline:
9 bodies, 2503 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/WORLD_ZOOM.md for the prose and boundaries.
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
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector.cross_Vector_': 0x005be888,
    'bl method.Vector.multiplyMatrix_float_': 0x005bf378,
    'bl method.Vector.normal__': 0x005be75c,
    'bl method.Vector.normalize__': 0x005bf2b4,
    'bl method.Vector.operator_float__': 0x004b5c08,
    'bl sym.clamp_float__float__float_': 0x004be068,
    'bl sym.imp.__umodsi3': 0x001c2f9c,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
}

SPECS = [
    dict(
        name='wz_00',
        method='World -[zoomToActiveNetBlockheadForPlayer:]',
        types='v12@0:4@8',
        start=6048808,
        end=6051316,
        disasm='disasm_worldtileloader_wz_00.txt',
        base_add=6048824,
        base_literal=6051312,
        boundary='ARM.exidx end 0x005c55f4 (listing bound); next ObjC IMP 0x005c55f4 World -[getBlockheadZoomPosForClient:requesterClient:cycleIndex:]',
        selectors={
                 0x5c556c: (15195624, 'objectForKey:'),
                 0x5c5574: (15197936, 'integerValue'),
                 0x5c5578: (15195892, 'init'),
                 0x5c557c: (15195752, 'alloc'),
                 0x5c5588: (15195584, 'setObject:forKey:'),
                 0x5c558c: (15195572, 'numberWithInt:'),
                 0x5c55a0: (15197948, 'dictionaryWithObject:forKey:'),
                 0x5c55a4: (15195644, 'sendDataToServer:reliable:'),
                 0x5c55a8: (15195612, 'appendData:'),
                 0x5c55ac: (15195552, 'dataWithBytes:length:'),
                 0x5c55b4: (15195620, 'countByEnumeratingWithState:objects:count:'),
                 0x5c55b8: (15196652, 'allBlockheadsIncludingNet'),
                 0x5c55c0: (15195688, 'array'),
                 0x5c55c8: (15196476, 'isEqualToString:'),
                 0x5c55cc: (15196296, 'clientID'),
                 0x5c55d0: (15197584, 'pos'),
                 0x5c55d4: (15197940, 'tileIsLitForClient:atPos:tile:'),
                 0x5c55dc: (15195700, 'addObject:'),
                 0x5c55e0: (15195604, 'count'),
                 0x5c55e4: (15195800, 'objectAtIndex:'),
                 0x5c55e8: (15197944, 'zoomToPos:pinchZoom:'),
        },
        imports={
                 0x5c5568: (17151904, 'objc_msgSend'),
                 0x5c5598: (16232936, '__CFConstantStringClassReference'),
                 0x5c559c: (16229192, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5c5564: (17156720, 'OBJC_IVAR_$_World.clientZoomRequestSent', 3344),
                 0x5c5570: (17156352, 'OBJC_IVAR_$_World.zoomPlayerCycleCounts', 3340),
                 0x5c5584: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x5c5594: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5c55bc: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={
                 0x5c5580: (15245288, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x5c5590: (15245292, 'OBJC_CLASS_$_NSNumber'),
                 0x5c55b0: (15245284, 'OBJC_CLASS_$_NSMutableData'),
                 0x5c55c4: (15245300, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(6048808, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6051312, 'invalid')],
        calls=[(6048984, 'blx r3'), (6049048, 'blx r2'), (6049164, 'blx r2'), (6049180, 'blx r2'), (6049324, 'blx r3'), (6049372, 'blx ip'), (6049544, 'blx r2'), (6049584, 'blx r3'), (6049608, 'bl sym.imp.memset'), (6049656, 'blx lr'), (6049756, 'bl sym.imp.objc_enumerationMutation'), (6049848, 'blx ip'), (6049868, 'blx r3'), (6049936, 'bl loc.imp.objc_msgSend_stret'), (6049972, 'bl sym.imp.memset'), (6050032, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6050080, 'bl loc.imp.objc_msgSend'), (6050144, 'blx r3'), (6050252, 'blx ip'), (6050320, 'blx r2'), (6050416, 'blx r3'), (6050436, 'bl sym.imp.__umodsi3'), (6050464, 'blx r3'), (6050524, 'bl loc.imp.objc_msgSend_stret'), (6050560, 'bl sym.imp.memset'), (6050604, 'bl loc.imp.objc_msgSend'), (6050784, 'blx r6'), (6050832, 'blx r3'), (6050868, 'blx ip'), (6050876, 'bl 0x55468c'), (6051048, 'blx r7'), (6051076, 'blx r3'), (6051152, 'blx r4')],
        branches=[(6048856, 'beq', 6048896), (6048892, 'beq', 6048900), (6048896, 'b', 6051164), (6049004, 'beq', 6049056), (6049092, 'bne', 6049204), (6049404, 'beq', 6050612), (6049668, 'beq', 6050276), (6049748, 'beq', 6049760), (6049880, 'beq', 6050152), (6049920, 'beq', 6049944), (6049940, 'b', 6049976), (6050092, 'beq', 6050148), (6050148, 'b', 6050152), (6050152, 'b', 6050156), (6050180, 'blo', 6049712), (6050272, 'bne', 6049712), (6050276, 'b', 6050280), (6050328, 'bls', 6050608), (6050508, 'beq', 6050532), (6050528, 'b', 6050564), (6050608, 'b', 6051164), (6050648, 'beq', 6051160), (6050896, 'beq', 6051156), (6051156, 'b', 6051160), (6051160, 'b', 6051164)],
        semantics=('[World zoomToActiveNetBlockheadForPlayer:] (imp 0x005c4c28, 627w): the net-blockhead zoom request router - the client half builds a dictionaryWithObject:forKey: (numberWithInt: cycle count) and calls sendDataToServer:reliable: with the appendData:/dataWithBytes:length: packet; the server half walks allBlockheadsIncludingNet (fast enumeration + objc_enumerationMutation), matches clientID, checks tileIsLitForClient:atPos:tile: visibility, and zooms via zoomToPos:pinchZoom:; guards clientZoomRequestSent / zoomPlayerCycleCounts (__umodsi3 cycle wrap); constants 0x10/0x20/0x1b; helper 0x55468c (the E103 body-boundary helper).\n'),
    ),
    dict(
        name='wz_01',
        method='World -[getBlockheadZoomPosForClient:requesterClient:cycleIndex:]',
        types='{?=ii}20@0:4@8@12i16',
        start=6051316,
        end=6052876,
        disasm='disasm_worldtileloader_wz_01.txt',
        base_add=6051332,
        base_literal=6052872,
        boundary='ARM.exidx end 0x005c5c0c (listing bound); next ObjC IMP 0x005c5c0c World -[remoteZoomRequestReturnedWithSuccess:point:]',
        selectors={
                 0x5c5bcc: (15195620, 'countByEnumeratingWithState:objects:count:'),
                 0x5c5bd0: (15196652, 'allBlockheadsIncludingNet'),
                 0x5c5bd8: (15195688, 'array'),
                 0x5c5be0: (15196476, 'isEqualToString:'),
                 0x5c5be4: (15196296, 'clientID'),
                 0x5c5bec: (15195704, 'localPlayerID'),
                 0x5c5bf0: (15197584, 'pos'),
                 0x5c5bf4: (15197940, 'tileIsLitForClient:atPos:tile:'),
                 0x5c5bfc: (15195700, 'addObject:'),
                 0x5c5c00: (15195604, 'count'),
                 0x5c5c04: (15195800, 'objectAtIndex:'),
        },
        imports={
                 0x5c5bc8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5c5bd4: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5c5be8: (17155916, 'OBJC_IVAR_$_World.server', 964),
        },
        classes={
                 0x5c5bdc: (15245300, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(6051316, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6052872, 'adceq sl, sb, r8, ror 9')],
        calls=[(6051384, 'bl sym.makeIntpair_int__int_'), (6051540, 'blx r2'), (6051580, 'blx r3'), (6051604, 'bl sym.imp.memset'), (6051652, 'blx lr'), (6051752, 'bl sym.imp.objc_enumerationMutation'), (6051844, 'blx ip'), (6051864, 'blx r3'), (6051972, 'blx r3'), (6052068, 'blx ip'), (6052088, 'blx r3'), (6052156, 'bl loc.imp.objc_msgSend_stret'), (6052192, 'bl sym.imp.memset'), (6052252, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6052300, 'bl loc.imp.objc_msgSend'), (6052364, 'blx r3'), (6052472, 'blx ip'), (6052540, 'blx r2'), (6052636, 'blx r3'), (6052656, 'bl sym.imp.__umodsi3'), (6052684, 'blx r3'), (6052736, 'bl loc.imp.objc_msgSend_stret'), (6052772, 'bl sym.imp.memset')],
        branches=[(6051400, 'beq', 6052800), (6051664, 'beq', 6052496), (6051744, 'beq', 6051756), (6051876, 'bne', 6052104), (6051916, 'beq', 6052372), (6051984, 'bne', 6052372), (6052100, 'beq', 6052372), (6052140, 'beq', 6052164), (6052160, 'b', 6052196), (6052312, 'beq', 6052368), (6052368, 'b', 6052372), (6052372, 'b', 6052376), (6052400, 'blo', 6051708), (6052492, 'bne', 6051708), (6052496, 'b', 6052500), (6052548, 'bls', 6052796), (6052720, 'beq', 6052744), (6052740, 'b', 6052776), (6052796, 'b', 6052800)],
        semantics=('[World getBlockheadZoomPosForClient:requesterClient:cycleIndex:] (imp 0x005c55f4, 390w): the server-side zoom-position picker - walks allBlockheadsIncludingNet, filters by clientID match + tileIsLitForClient:atPos:tile: and builds an NSMutableArray; indexes by cycleIndex % count (__umodsi3) and returns the pos (makeIntpair + tileAtWorldPositionLoaded); constants 0x10/0x20.\n'),
    ),
    dict(
        name='wz_02',
        method='World -[zoomToPortalAtPosition:]',
        types='v16@0:4{?=ii}8',
        start=6065816,
        end=6067068,
        disasm='disasm_worldtileloader_wz_02.txt',
        base_add=6065832,
        base_literal=6067064,
        boundary='ARM.exidx end 0x005c937c (listing bound); next ObjC IMP 0x005c937c World -[fireProjectileFrom:to:at:fireItemType:firer:]',
        selectors={
                 0x5c933c: (15196416, 'workbenchAtPos:'),
                 0x5c9340: (15197944, 'zoomToPos:pinchZoom:'),
                 0x5c934c: (15196444, 'activeBlockhead'),
                 0x5c9350: (15197356, 'setDisplayed:'),
                 0x5c9354: (15196628, 'addBlockheadUI'),
                 0x5c935c: (15197352, 'setWorkbench:blockhead:craftableItemObject:'),
                 0x5c9360: (15196488, 'isCloudGame'),
                 0x5c9364: (15198072, 'numberOfCraftableItems'),
                 0x5c9368: (15197544, 'setSelectedIndex:'),
                 0x5c936c: (15197548, 'craftUI'),
                 0x5c9370: (15197596, 'setWorkbench:blockhead:'),
        },
        imports={
                 0x5c9348: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5c9334: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5c9358: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
        },
        classes={},
        instructions=[(6065816, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6067064, 'adceq r6, sb, r4, asr 24')],
        calls=[(6065924, 'bl loc.imp.objc_msgSend'), (6066020, 'blx r3'), (6066108, 'blx lr'), (6066140, 'blx r3'), (6066260, 'blx lr'), (6066320, 'blx r3'), (6066468, 'blx lr'), (6066524, 'blx lr'), (6066560, 'blx ip'), (6066596, 'blx r3'), (6066620, 'blx r3'), (6066752, 'blx lr'), (6066784, 'blx lr'), (6066820, 'blx r3'), (6066844, 'blx r3'), (6066876, 'bl sym.makeIntpair_int__int_'), (6066920, 'bl loc.imp.objc_msgSend'), (6066984, 'bl loc.imp.objc_msgSend')],
        branches=[(6065944, 'beq', 6066928), (6066032, 'beq', 6066628), (6066180, 'ble', 6066324), (6066624, 'b', 6066848), (6066924, 'b', 6066988)],
        semantics=('[World zoomToPortalAtPosition:] (imp 0x005c8e98, 313w): the zoom-to-workbench-and-open flow - workbenchAtPos: lookup, activeBlockhead, zoomToPos:pinchZoom:, then the UI half (setDisplayed:/addBlockheadUI/setWorkbench:blockhead:craftableItemObject:/numberOfCraftableItems/setSelectedIndex:/craftUI) gated by isCloudGame; makeIntpair.\n'),
    ),
    dict(
        name='wz_03',
        method='World -[remoteZoomRequestReturnedWithSuccess:point:]',
        types='v20@0:4c8{?=ii}12',
        start=6052876,
        end=6053088,
        disasm='disasm_worldtileloader_wz_03.txt',
        base_add=6052892,
        base_literal=6053084,
        boundary='ARM.exidx end 0x005c5ce0 (listing bound); next ObjC IMP 0x005c5ce0 World -[zoomToPoint:]',
        selectors={
                 0x5c5cd4: (15197944, 'zoomToPos:pinchZoom:'),
        },
        imports={},
        ivars={
                 0x5c5cd0: (17156720, 'OBJC_IVAR_$_World.clientZoomRequestSent', 3344),
        },
        classes={},
        instructions=[(6052876, 'push {fp, lr}'), (6053084, 'invalid')],
        calls=[(6053028, 'bl loc.imp.objc_msgSend')],
        branches=[(6052932, 'beq', 6053032), (6052968, 'beq', 6053032)],
        semantics=('[World remoteZoomRequestReturnedWithSuccess:point:] (imp 0x005c5c0c, 53w): the zoom-request response - on success (and not already cleared) zooms via zoomToPos:pinchZoom:; two-branch guard on clientZoomRequestSent.\n'),
    ),
    dict(
        name='wz_04',
        method='World -[activeBlockheadPos]',
        types='{?=ii}8@0:4',
        start=6054060,
        end=6054356,
        disasm='disasm_worldtileloader_wz_04.txt',
        base_add=6054076,
        base_literal=6054352,
        boundary='ARM.exidx end 0x005c61d4 (listing bound); next ObjC IMP 0x005c61d4 World -[serverFillReply:]',
        selectors={
                 0x5c61c0: (15196444, 'activeBlockhead'),
                 0x5c61cc: (15197584, 'pos'),
        },
        imports={
                 0x5c61bc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5c61c4: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5c61c8: (17155912, 'OBJC_IVAR_$_World.startPortalPos', 144),
        },
        classes={},
        instructions=[(6054060, 'push {r4, r5, fp, lr}'), (6054352, 'adceq sb, sb, r0, lsr sl')],
        calls=[(6054156, 'blx lr'), (6054280, 'bl loc.imp.objc_msgSend_stret'), (6054316, 'bl sym.imp.memset')],
        branches=[(6054176, 'bne', 6054228), (6054224, 'b', 6054324), (6054264, 'beq', 6054288), (6054284, 'b', 6054320), (6054320, 'b', 6054324)],
        semantics=('[World activeBlockheadPos] (imp 0x005c60ac, 74w): the camera anchor - activeBlockhead pos via stret, falling back to startPortalPos.\n'),
    ),
    dict(
        name='wz_05',
        method='World -[acceleration:]',
        types='v24@0:4{Vector=[4f]}8',
        start=6023576,
        end=6025908,
        disasm='disasm_worldtileloader_wz_05.txt',
        base_add=6023592,
        base_literal=6025904,
        boundary='ARM.exidx end 0x005bf2b4 (listing bound); next ObjC IMP 0x005bf528 World -[motionUpdatePingAccelerometer]',
        selectors={
                 0x5bf25c: (15196172, 'statusBarOrientation'),
                 0x5bf260: (15196168, 'sharedApplication'),
                 0x5bf268: (15196624, 'requiresMotionEvents'),
                 0x5bf26c: (15196444, 'activeBlockhead'),
                 0x5bf290: (15197716, 'endCalibration'),
        },
        imports={
                 0x5bf258: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5bf254: (17156320, 'OBJC_IVAR_$_World.interfaceOrientation', 8),
                 0x5bf270: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5bf274: (17156684, 'OBJC_IVAR_$_World.hasCalibrated', 25),
                 0x5bf278: (17156692, 'OBJC_IVAR_$_World.forcedCalibrationTimer', 112),
                 0x5bf27c: (17156696, 'OBJC_IVAR_$_World.calibrating', 24),
                 0x5bf284: (17156680, 'OBJC_IVAR_$_World.longTermAveragedAcceleration', 28),
                 0x5bf298: (17156688, 'OBJC_IVAR_$_World.calibrationMatrix', 44),
                 0x5bf29c: (17156508, 'OBJC_IVAR_$_World.moveUpDownFraction', 120),
                 0x5bf2a0: (17156504, 'OBJC_IVAR_$_World.moveLeftRightFraction', 116),
                 0x5bf2ac: (17156512, 'OBJC_IVAR_$_World.xSmooth', 124),
        },
        classes={
                 0x5bf264: (15245432, 'OBJC_CLASS_$_UIApplication'),
        },
        instructions=[(6023576, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6025904, 'adceq r1, sl, r4, asr 2')],
        calls=[(6023704, 'blx r6'), (6023720, 'blx r2'), (6023808, 'bl method.Vector.operator_float__'), (6023828, 'bl method.Vector.operator_float__'), (6023848, 'bl method.Vector.operator_float__'), (6023876, 'bl method.Vector.operator_float__'), (6023968, 'blx ip'), (6023984, 'blx r2'), (6024156, 'bl method.Vector.operator_float__'), (6024176, 'bl method.Vector.operator_float__'), (6024224, 'bl method.Vector.Vector_float__float__float_'), (6024248, 'bl method.Vector.normal__'), (6024356, 'bl method.Vector.operator_float__'), (6024376, 'bl method.Vector.operator_float__'), (6024424, 'bl method.Vector.Vector_float__float__float_'), (6024448, 'bl method.Vector.normal__'), (6024476, 'bl method.Vector.operator_float__'), (6024504, 'bl method.Vector.operator_float__'), (6024556, 'bl method.Vector.operator_float__'), (6024592, 'bl method.Vector.operator_float__'), (6024620, 'bl method.Vector.operator_float__'), (6024672, 'bl method.Vector.operator_float__'), (6024708, 'bl method.Vector.normalize__'), (6024872, 'blx r2'), (6024936, 'bl method.Vector.operator_float__'), (6024956, 'bl method.Vector.operator_float__'), (6025004, 'bl method.Vector.Vector_float__float__float_'), (6025028, 'bl method.Vector.normal__'), (6025108, 'bl method.Vector.operator_float__'), (6025132, 'bl method.Vector.operator_float__'), (6025188, 'bl method.Vector.multiplyMatrix_float_'), (6025228, 'bl method.Vector.operator_float__'), (6025476, 'bl method.Vector.operator_float__'), (6025768, 'bl sym.clamp_float__float__float_')],
        branches=[(6023764, 'beq', 6023804), (6023800, 'bne', 6023888), (6023996, 'beq', 6024088), (6024032, 'bne', 6024768), (6024084, 'bpl', 6024768), (6024120, 'bne', 6024352), (6024348, 'b', 6024760), (6024760, 'b', 6024880), (6024800, 'beq', 6024876), (6024876, 'b', 6024880), (6024912, 'beq', 6025804), (6025064, 'beq', 6025104), (6025100, 'bne', 6025144), (6025328, 'ble', 6025344), (6025340, 'b', 6025416), (6025364, 'bpl', 6025400), (6025380, 'b', 6025408), (6025568, 'beq', 6025608), (6025604, 'bne', 6025620)],
        semantics=('[World acceleration:] (imp 0x005be998, 583w): the motion-to-camera pipeline - UIApplication statusBarOrientation -> interfaceOrientation, requiresMotionEvents gate, longTermAveragedAcceleration smoothing, calibrationMatrix multiply (Vector::multiplyMatrix), then moveUpDownFraction / moveLeftRightFraction derivation with Vector::normal/normalize + clamp_float; state hasCalibrated/calibrating/forcedCalibrationTimer/xSmooth; Vector ops x30; constants from the 0x5bee3c/0x5bf0a8/0x5bf0ac pools.\n'),
    ),
    dict(
        name='wz_06',
        method='World -[motionUpdatePingAccelerometer]',
        types='v8@0:4',
        start=6026536,
        end=6027064,
        disasm='disasm_worldtileloader_wz_06.txt',
        base_add=6026552,
        base_literal=6027060,
        boundary='ARM.exidx end 0x005bf738 (listing bound); next ObjC IMP 0x005bf738 World -[motionUpdatePingDeviceMotion]',
        selectors={
                 0x5bf71c: (15197724, 'acceleration'),
                 0x5bf724: (15197720, 'accelerometerData'),
                 0x5bf72c: (15197728, 'acceleration:'),
        },
        imports={
                 0x5bf720: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5bf728: (17156336, 'OBJC_IVAR_$_World.motionManager', 4),
        },
        classes={},
        instructions=[(6026536, 'push {r4, r5, fp, lr}'), (6027060, 'invalid')],
        calls=[(6026632, 'blx lr'), (6026692, 'bl loc.imp.objc_msgSend_stret'), (6026728, 'bl sym.imp.memset'), (6026796, 'bl loc.imp.objc_msgSend_stret'), (6026832, 'bl sym.imp.memset'), (6026900, 'bl loc.imp.objc_msgSend_stret'), (6026936, 'bl sym.imp.memset'), (6026972, 'bl method.Vector.Vector_float__float__float_'), (6027024, 'bl loc.imp.objc_msgSend')],
        branches=[(6026676, 'beq', 6026700), (6026696, 'b', 6026732), (6026780, 'beq', 6026804), (6026800, 'b', 6026836), (6026884, 'beq', 6026908), (6026904, 'b', 6026940)],
        semantics=('[World motionUpdatePingAccelerometer] (imp 0x005bf528, 132w): the accelerometer ping - reads motionManager accelerometerData (0x18 = 24-byte struct), wraps into Vector(...) and forwards to acceleration:.\n'),
    ),
    dict(
        name='wz_07',
        method='World -[motionUpdatePingDeviceMotion]',
        types='v8@0:4',
        start=6027064,
        end=6027392,
        disasm='disasm_worldtileloader_wz_07.txt',
        base_add=6027080,
        base_literal=6027388,
        boundary='ARM.exidx end 0x005bf880 (listing bound); next ObjC IMP 0x005bf880 World -[allowsRotation]',
        selectors={
                 0x5bf864: (15197736, 'gravity'),
                 0x5bf86c: (15197732, 'deviceMotion'),
                 0x5bf874: (15197728, 'acceleration:'),
        },
        imports={
                 0x5bf868: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5bf870: (17156336, 'OBJC_IVAR_$_World.motionManager', 4),
        },
        classes={},
        instructions=[(6027064, 'push {r4, r5, fp, lr}'), (6027388, 'adceq r0, sl, r4, lsr 7')],
        calls=[(6027156, 'blx lr'), (6027208, 'bl loc.imp.objc_msgSend_stret'), (6027244, 'bl sym.imp.memset'), (6027300, 'bl method.Vector.Vector_float__float__float_'), (6027352, 'bl loc.imp.objc_msgSend')],
        branches=[(6027192, 'beq', 6027216), (6027212, 'b', 6027248)],
        semantics=('[World motionUpdatePingDeviceMotion] (imp 0x005bf738, 82w): the device-motion ping - reads motionManager gravity (0x18), wraps into Vector(...) and forwards to acceleration:.\n'),
    ),
    dict(
        name='wz_08',
        method='World -[endCalibration]',
        types='v8@0:4',
        start=6022008,
        end=6023004,
        disasm='disasm_worldtileloader_wz_08.txt',
        base_add=6022024,
        base_literal=6023000,
        boundary='ARM.exidx end 0x005be75c (listing bound); next ObjC IMP 0x005be998 World -[acceleration:]',
        selectors={},
        imports={},
        ivars={
                 0x5be744: (17156320, 'OBJC_IVAR_$_World.interfaceOrientation', 8),
                 0x5be74c: (17156680, 'OBJC_IVAR_$_World.longTermAveragedAcceleration', 28),
                 0x5be750: (17156684, 'OBJC_IVAR_$_World.hasCalibrated', 25),
                 0x5be754: (17156688, 'OBJC_IVAR_$_World.calibrationMatrix', 44),
        },
        classes={},
        instructions=[(6022008, 'push {r4, r5, fp, lr}'), (6023000, 'adceq r1, sl, r4, ror 14')],
        calls=[(6022060, 'bl method.Vector.operator_float__'), (6022100, 'bl method.Vector.operator_float__'), (6022152, 'bl method.Vector.Vector_float__float__float_'), (6022176, 'bl method.Vector.normal__'), (6022256, 'bl method.Vector.operator_float__'), (6022280, 'bl method.Vector.operator_float__'), (6022316, 'bl method.Vector.Vector_float__float__float_'), (6022388, 'bl method.Vector.cross_Vector_'), (6022396, 'bl method.Vector.operator_float__'), (6022440, 'bl method.Vector.operator_float__'), (6022484, 'bl method.Vector.operator_float__'), (6022556, 'bl method.Vector.operator_float__'), (6022600, 'bl method.Vector.operator_float__'), (6022644, 'bl method.Vector.operator_float__'), (6022716, 'bl method.Vector.operator_float__'), (6022760, 'bl method.Vector.operator_float__'), (6022804, 'bl method.Vector.operator_float__')],
        branches=[(6022212, 'beq', 6022252), (6022248, 'bne', 6022292)],
        semantics=('[World endCalibration] (imp 0x005be378, 249w): the calibration basis builder - Vector::cross (cross_Vector_) + Vector::normal from longTermAveragedAcceleration and the interface orientation, stores calibrationMatrix and sets hasCalibrated; Vector ops x15.\n'),
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
        'batch': 'World camera/zoom/motion line (E107): the net-blockhead zoom trio and the motion-to-camera pipeline; 9 bodies',
        'claim': ('a fully-read static map of the World camera/zoom/motion line; the motionManager and UIApplication contracts and the lane-level calibration constants are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'world_zoom.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale world_zoom.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
