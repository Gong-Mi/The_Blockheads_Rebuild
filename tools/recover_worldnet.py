#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The World net/admin core: the admin summary, the heartbeat family, the
welcome-back builder, the unique-ID grant and the remote quartet: the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 8016 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/WORLD_NET.md for the prose and boundaries.
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
    'bl 0x56da94': 0x0056da94,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl sym.imp.NSLog': 0x001c2a5c,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
}

SPECS = [
    dict(
        name='wn_00',
        method='World -[summaryNetDataForAdmin:mod:owner:cloudMode:]',
        types='@24@0:4c8c12c16i20',
        start=5584620,
        end=5588620,
        disasm='disasm_worldtileloader_wn_00.txt',
        base_add=5584636,
        base_literal=5588616,
        boundary='ARM.exidx end 0x0055468c (listing bound); next ObjC IMP 0x005547f8 World -[heartbeatData]',
        selectors={
                 0x5545c8: (15195580, 'dictionaryWithObjectsAndKeys:'),
                 0x5545cc: (15195572, 'numberWithInt:'),
                 0x5545d8: (15195576, 'numberWithBool:'),
                 0x5545f4: (15195564, 'numberWithFloat:'),
                 0x5545f8: (15195568, 'credit'),
                 0x554604: (15195560, 'numberWithDouble:'),
                 0x55460c: (15195556, 'numberWithUnsignedInt:'),
                 0x554618: (15195552, 'dataWithBytes:length:'),
                 0x554624: (15195584, 'setObject:forKey:'),
                 0x554628: (15195596, 'isKindOfClass:'),
                 0x55462c: (15195592, 'class'),
                 0x554634: (15195588, 'match'),
                 0x554640: (15195600, 'privacy'),
                 0x55466c: (15195604, 'count'),
                 0x554680: (15195612, 'appendData:'),
                 0x554684: (15195608, 'gzipDeflate'),
        },
        imports={
                 0x55458c: (16228520, '__CFConstantStringClassReference'),
                 0x554590: (16228536, '__CFConstantStringClassReference'),
                 0x554594: (16228552, '__CFConstantStringClassReference'),
                 0x554598: (16228568, '__CFConstantStringClassReference'),
                 0x55459c: (16228584, '__CFConstantStringClassReference'),
                 0x5545a0: (16228600, '__CFConstantStringClassReference'),
                 0x5545a4: (16228616, '__CFConstantStringClassReference'),
                 0x5545a8: (16228632, '__CFConstantStringClassReference'),
                 0x5545ac: (16228648, '__CFConstantStringClassReference'),
                 0x5545b0: (16228664, '__CFConstantStringClassReference'),
                 0x5545b4: (16228680, '__CFConstantStringClassReference'),
                 0x5545b8: (16228696, '__CFConstantStringClassReference'),
                 0x5545bc: (16228712, '__CFConstantStringClassReference'),
                 0x5545c0: (16228728, '__CFConstantStringClassReference'),
                 0x5545c4: (17151904, 'objc_msgSend'),
                 0x554620: (16228744, '__CFConstantStringClassReference'),
                 0x55463c: (16228760, '__CFConstantStringClassReference'),
                 0x554644: (16228776, '__CFConstantStringClassReference'),
                 0x554648: (16228792, '__CFConstantStringClassReference'),
                 0x55464c: (16228808, '__CFConstantStringClassReference'),
                 0x554650: (16228824, '__CFConstantStringClassReference'),
                 0x554658: (16228840, '__CFConstantStringClassReference'),
                 0x554660: (16228856, '__CFConstantStringClassReference'),
                 0x554668: (16228872, '__CFConstantStringClassReference'),
                 0x554674: (16228888, '__CFConstantStringClassReference'),
                 0x55467c: (16228904, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5545d4: (17155892, 'OBJC_IVAR_$_World.worldName', 440),
                 0x5545dc: (17155896, 'OBJC_IVAR_$_World.expertMode', 228),
                 0x5545e0: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
                 0x5545e4: (17155900, 'OBJC_IVAR_$_World.saveID', 436),
                 0x5545e8: (17155904, 'OBJC_IVAR_$_World.portalLevel', 3276),
                 0x5545ec: (17155908, 'OBJC_IVAR_$_World.highestPoint', 3164),
                 0x5545f0: (17155912, 'OBJC_IVAR_$_World.startPortalPos', 144),
                 0x5545fc: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x554600: (17155920, 'OBJC_IVAR_$_World.noRainTimer', 940),
                 0x554608: (17155924, 'OBJC_IVAR_$_World.worldTime', 648),
                 0x554610: (17155928, 'OBJC_IVAR_$_World.randomSeed', 432),
                 0x554638: (17155932, 'OBJC_IVAR_$_World.serverPassword', 3288),
                 0x554654: (17155936, 'OBJC_IVAR_$_World.pvpEnabled', 3268),
                 0x55465c: (17155940, 'OBJC_IVAR_$_World.worldPriceMultipliers', 3240),
                 0x554664: (17155944, 'OBJC_IVAR_$_World.welcomeMessage', 3272),
                 0x554670: (17155948, 'OBJC_IVAR_$_World.ownershipSignPositions', 3324),
                 0x554678: (17155952, 'OBJC_IVAR_$_World.customRulesDict', 224),
        },
        classes={
                 0x5545d0: (15245292, 'OBJC_CLASS_$_NSNumber'),
                 0x554614: (15245288, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x55461c: (15245284, 'OBJC_CLASS_$_NSMutableData'),
                 0x554630: (15245296, 'OBJC_CLASS_$_BHNetServerMatch'),
        },
        instructions=[(5584620, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5588616, 'ldrshteq ip, [r0], r0')],
        calls=[(5585260, 'blx r4'), (5585328, 'blx r3'), (5585384, 'blx lr'), (5585440, 'blx lr'), (5585496, 'blx r3'), (5585528, 'blx r3'), (5585584, 'blx r3'), (5585640, 'blx r3'), (5585696, 'blx r3'), (5585752, 'blx r3'), (5585808, 'blx r3'), (5585888, 'blx ip'), (5585944, 'blx r3'), (5586008, 'blx ip'), (5586260, 'blx ip'), (5586392, 'blx ip'), (5586428, 'blx ip'), (5586576, 'blx r5'), (5586608, 'blx r2'), (5586640, 'blx r3'), (5586832, 'blx ip'), (5586848, 'blx r2'), (5586880, 'blx r3'), (5586916, 'blx ip'), (5587036, 'blx ip'), (5587172, 'blx lr'), (5587208, 'blx ip'), (5587348, 'blx lr'), (5587384, 'blx ip'), (5587496, 'blx lr'), (5587532, 'blx ip'), (5587672, 'blx lr'), (5587708, 'blx ip'), (5587836, 'blx ip'), (5587964, 'blx ip'), (5588028, 'blx r2'), (5588124, 'blx ip'), (5588252, 'blx ip'), (5588260, 'bl 0x55468c'), (5588320, 'blx lr'), (5588348, 'blx r3')],
        branches=[(5586276, 'beq', 5587048), (5586460, 'beq', 5587044), (5586652, 'beq', 5587044), (5586948, 'beq', 5587040), (5587040, 'b', 5587044), (5587044, 'b', 5587048), (5587056, 'bne', 5587072), (5587068, 'beq', 5587212), (5587220, 'bne', 5587248), (5587232, 'bne', 5587248), (5587244, 'beq', 5587388), (5587396, 'beq', 5587536), (5587568, 'bne', 5587712), (5587748, 'beq', 5587840), (5587876, 'beq', 5587968), (5588036, 'bls', 5588128), (5588164, 'beq', 5588256)],
        semantics=('[World summaryNetDataForAdmin:mod:owner:cloudMode:] (imp 0x005536ec, 1000w): the admin summary builder - 41 calls (objc-heavy NSDictionary packing) + imp x26 (the selector-constant pool) + the 0x55468c helper + sel x16.\n'),
    ),
    dict(
        name='wn_01',
        method='World -[heartbeatData]',
        types='@8@0:4',
        start=5588984,
        end=5590268,
        disasm='disasm_worldtileloader_wn_01.txt',
        base_add=5589000,
        base_literal=5590264,
        boundary='ARM.exidx end 0x00554cfc (listing bound); next ObjC IMP 0x00554cfc World -[sendHeartbeatData]',
        selectors={
                 0x554cc0: (15195568, 'credit'),
                 0x554cc8: (15195616, 'gameBlockingUIDisplayed'),
                 0x554cdc: (15195620, 'countByEnumeratingWithState:objects:count:'),
                 0x554ce4: (15195628, 'paused'),
                 0x554ce8: (15195624, 'objectForKey:'),
                 0x554cec: (15195632, 'appendBytes:length:'),
                 0x554cf0: (15195552, 'dataWithBytes:length:'),
        },
        imports={
                 0x554cbc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x554cb8: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x554cc4: (17155936, 'OBJC_IVAR_$_World.pvpEnabled', 3268),
                 0x554ccc: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x554cd0: (17155960, 'OBJC_IVAR_$_World.fastForward', 934),
                 0x554cd4: (17155920, 'OBJC_IVAR_$_World.noRainTimer', 940),
                 0x554cd8: (17155924, 'OBJC_IVAR_$_World.worldTime', 648),
                 0x554ce0: (17155964, 'OBJC_IVAR_$_World.serverClients', 956),
        },
        classes={
                 0x554cf4: (15245284, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(5588984, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5590264, 'adcseq fp, r0, r4, ror 5')],
        calls=[(5589240, 'blx lr'), (5589340, 'blx lr'), (5589444, 'blx r2'), (5589556, 'bl sym.imp.memset'), (5589620, 'blx lr'), (5589720, 'bl sym.imp.objc_enumerationMutation'), (5589840, 'blx ip'), (5589864, 'blx r2'), (5589992, 'blx ip'), (5590140, 'blx r4'), (5590184, 'blx ip')],
        branches=[(5589380, 'beq', 5590032), (5589460, 'beq', 5590024), (5589632, 'beq', 5590016), (5589712, 'beq', 5589724), (5589876, 'bne', 5589892), (5589888, 'b', 5590020), (5589892, 'b', 5589896), (5589920, 'blo', 5589676), (5590012, 'bne', 5589676), (5590016, 'b', 5590020), (5590020, 'b', 5590024)],
        semantics=('[World heartbeatData] (imp 0x005547f8, 321w): the heartbeat dict - memset + fast enumeration + consts 0x10/0x20/0x17 (23 - the heartbeat type code).\n'),
    ),
    dict(
        name='wn_02',
        method='World -[sendHeartbeatData]',
        types='v8@0:4',
        start=5590268,
        end=5590788,
        disasm='disasm_worldtileloader_wn_02.txt',
        base_add=5590284,
        base_literal=5590784,
        boundary='ARM.exidx end 0x00554f04 (listing bound); next ObjC IMP 0x00554f04 World -[heartbeatDataRecieved:fromPeer:]',
        selectors={
                 0x554ee0: (15195636, 'heartbeatData'),
                 0x554ee4: (15195604, 'count'),
                 0x554ef0: (15195644, 'sendDataToServer:reliable:'),
                 0x554ef8: (15195648, 'sendUpdatedFoundItemsListToServer'),
                 0x554efc: (15195640, 'sendNetworkData:toPeers:reliable:'),
        },
        imports={
                 0x554edc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x554ed8: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x554ee8: (17155964, 'OBJC_IVAR_$_World.serverClients', 956),
                 0x554eec: (17155968, 'OBJC_IVAR_$_World.foundItemsListNeedsToBeSentToServer', 3380),
                 0x554ef4: (17155972, 'OBJC_IVAR_$_World.client', 960),
        },
        classes={},
        instructions=[(5590268, 'push {r4, sl, fp, lr}'), (5590784, 'adcseq sl, r0, r0, ror 27')],
        calls=[(5590344, 'blx lr'), (5590444, 'blx r2'), (5590548, 'blx lr'), (5590656, 'blx lr'), (5590728, 'blx r2')],
        branches=[(5590380, 'beq', 5590556), (5590452, 'bls', 5590556), (5590552, 'b', 5590736), (5590684, 'beq', 5590732), (5590732, 'b', 5590736)],
        semantics=('[World sendHeartbeatData] (imp 0x00554cfc, 130w): the heartbeat sender (no external calls - pure message packing).\n'),
    ),
    dict(
        name='wn_03',
        method='World -[heartbeatDataRecieved:fromPeer:]',
        types='v16@0:4@8@12',
        start=5590788,
        end=5592412,
        disasm='disasm_worldtileloader_wn_03.txt',
        base_add=5590804,
        base_literal=5592408,
        boundary='ARM.exidx end 0x0055555c (listing bound); next ObjC IMP 0x0055555c World -[worldInfoForiCloudSave]',
        selectors={
                 0x5554f0: (15195652, 'length'),
                 0x5554f4: (15195656, 'getBytes:length:'),
                 0x5554fc: (15195628, 'paused'),
                 0x555500: (15195624, 'objectForKey:'),
                 0x555508: (15195672, 'connected'),
                 0x55550c: (15195680, 'sendHeartbeatData'),
                 0x555510: (15195676, 'setPaused:'),
                 0x555530: (15195664, 'play'),
                 0x555538: (15195668, 'soundNamed:'),
                 0x55553c: (15195544, 'instance'),
                 0x555548: (15195660, 'multiSoundNamed:'),
        },
        imports={
                 0x5554ec: (17151904, 'objc_msgSend'),
                 0x555534: (16228936, '__CFConstantStringClassReference'),
                 0x555544: (16228920, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5554f8: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x555504: (17155964, 'OBJC_IVAR_$_World.serverClients', 956),
                 0x555514: (17155936, 'OBJC_IVAR_$_World.pvpEnabled', 3268),
                 0x555518: (17155924, 'OBJC_IVAR_$_World.worldTime', 648),
                 0x55551c: (17155976, 'OBJC_IVAR_$_World.clientLastGotHeartbeatCounter', 1004),
                 0x555520: (17155980, 'OBJC_IVAR_$_World.hideUIType', 3068),
                 0x555524: (17155960, 'OBJC_IVAR_$_World.fastForward', 934),
                 0x555528: (17155984, 'OBJC_IVAR_$_World.serverReportsAllPaused', 3088),
                 0x55552c: (17155920, 'OBJC_IVAR_$_World.noRainTimer', 940),
                 0x55554c: (17155988, 'OBJC_IVAR_$_World.clientsideCredit', 3300),
                 0x555554: (17155992, 'OBJC_IVAR_$_World.clientAddedCreditTimer', 3304),
        },
        classes={
                 0x555540: (15245280, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(5590788, 'push {r4, r5, r6, sl, fp, lr}'), (5592408, 'ldrsbteq sl, [r0], r8')],
        calls=[(5590860, 'blx lr'), (5590996, 'blx lr'), (5591016, 'blx r2'), (5591592, 'blx r5'), (5591612, 'blx r3'), (5591628, 'blx r2'), (5591736, 'blx r5'), (5591756, 'blx r3'), (5591772, 'blx r2'), (5592092, 'blx ip'), (5592116, 'blx r2'), (5592176, 'blx r2'), (5592264, 'blx ip'), (5592284, 'blx r2')],
        branches=[(5590880, 'bhs', 5590896), (5590892, 'b', 5590904), (5591024, 'bhs', 5591036), (5591072, 'beq', 5592004), (5591084, 'beq', 5591124), (5591120, 'b', 5591156), (5591256, 'ble', 5591332), (5591292, 'beq', 5591332), (5591432, 'beq', 5591780), (5591488, 'beq', 5591636), (5591632, 'b', 5591776), (5591776, 'b', 5591780), (5591820, 'ble', 5591900), (5591860, 'bhi', 5591896), (5591896, 'b', 5591996), (5591956, 'ble', 5591992), (5591992, 'b', 5591996), (5591996, 'b', 5592292), (5592132, 'beq', 5592288), (5592188, 'beq', 5592288), (5592288, 'b', 5592292)],
        semantics=('[World heartbeatDataRecieved:fromPeer:] (imp 0x00554f04, 406w): the heartbeat receiver - consts 0x10/0x3c (60) + br x21 (the peer dispatch table).\n'),
    ),
    dict(
        name='wn_04',
        method='World -[worldInfoForiCloudSave]',
        types='@8@0:4',
        start=5592412,
        end=5593732,
        disasm='disasm_worldtileloader_wn_04.txt',
        base_add=5592428,
        base_literal=5593728,
        boundary='ARM.exidx end 0x00555a84 (listing bound); next ObjC IMP 0x00555a84 World -[saveAll]',
        selectors={
                 0x555a30: (15195620, 'countByEnumeratingWithState:objects:count:'),
                 0x555a34: (15195692, 'blockheads'),
                 0x555a3c: (15195688, 'array'),
                 0x555a48: (15195584, 'setObject:forKey:'),
                 0x555a4c: (15195572, 'numberWithInt:'),
                 0x555a58: (15195684, 'dictionary'),
                 0x555a60: (15195700, 'addObject:'),
                 0x555a64: (15195696, 'previewData'),
                 0x555a74: (15195708, 'stringWithFormat:'),
                 0x555a78: (15195704, 'localPlayerID'),
        },
        imports={
                 0x555a2c: (17151904, 'objc_msgSend'),
                 0x555a44: (16228648, '__CFConstantStringClassReference'),
                 0x555a6c: (16228968, '__CFConstantStringClassReference'),
                 0x555a70: (16228952, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x555a38: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x555a50: (17155904, 'OBJC_IVAR_$_World.portalLevel', 3276),
                 0x555a68: (17155972, 'OBJC_IVAR_$_World.client', 960),
        },
        classes={
                 0x555a40: (15245300, 'OBJC_CLASS_$_NSMutableArray'),
                 0x555a54: (15245292, 'OBJC_CLASS_$_NSNumber'),
                 0x555a5c: (15245288, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x555a7c: (15245304, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(5592412, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5593728, 'adcseq sl, r0, r0, lsl 11')],
        calls=[(5592700, 'blx r2'), (5592764, 'blx r3'), (5592800, 'blx ip'), (5592832, 'blx r3'), (5592856, 'bl sym.imp.memset'), (5592892, 'blx r3'), (5592936, 'blx lr'), (5593036, 'bl sym.imp.objc_enumerationMutation'), (5593136, 'blx ip'), (5593168, 'blx r3'), (5593268, 'blx ip'), (5593484, 'blx r5'), (5593520, 'blx ip'), (5593556, 'blx ip'), (5593628, 'blx ip')],
        branches=[(5592948, 'beq', 5593292), (5593028, 'beq', 5593040), (5593196, 'blo', 5592992), (5593288, 'bne', 5592992), (5593292, 'b', 5593296), (5593332, 'beq', 5593564), (5593560, 'b', 5593632)],
        semantics=('[World worldInfoForiCloudSave] (imp 0x0055555c, 330w): the iCloud save info - memset + fast enumeration + consts 0x20/0x10.\n'),
    ),
    dict(
        name='wn_05',
        method='World -[fileWriteFailed:]',
        types='v12@0:4@8',
        start=5602260,
        end=5602368,
        disasm='disasm_worldtileloader_wn_05.txt',
        base_add=5602276,
        base_literal=5602364,
        boundary='ARM.exidx end 0x00557c40 (listing bound); next ObjC IMP 0x00557c40 World -[loadGame]',
        selectors={
                 0x557c34: (15195792, 'fileWriteFailed:'),
        },
        imports={
                 0x557c30: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(5602260, 'push {r4, sl, fp, lr}'), (5602364, 'adcseq r7, r0, r8, lsl 30')],
        calls=[(5602340, 'blx ip')],
        branches=[],
        semantics=('[World fileWriteFailed:] (imp 0x00557bd4, 27w): the write-failure hook (cell 0xffed2e68).\n'),
    ),
    dict(
        name='wn_06',
        method='World -[welcomeBackMessageForInfoDict:]',
        types='@12@0:4@8',
        start=5682804,
        end=5692052,
        disasm='disasm_worldtileloader_wn_06.txt',
        base_add=5682824,
        base_literal=5686872,
        boundary='ARM.exidx end 0x0056da94 (listing bound); next ObjC IMP 0x0056dbd8 World -[welcomeBackEventsMessageForClientID:]',
        selectors={
                 0x56c660: (15195604, 'count'),
                 0x56c664: (15195620, 'countByEnumeratingWithState:objects:count:'),
                 0x56c66c: (15195624, 'objectForKey:'),
                 0x56c670: (15195572, 'numberWithInt:'),
                 0x56c678: (15195716, 'dictionaryWithDictionary:'),
                 0x56c684: (15195708, 'stringWithFormat:'),
                 0x56c68c: (15196468, 'capitalizedString'),
                 0x56d088: (15195848, 'intValue'),
                 0x56d364: (15195736, 'removeObjectForKey:'),
                 0x56d368: (15195584, 'setObject:forKey:'),
                 0x56d36c: (15196472, 'lowercaseString'),
                 0x56da24: (15195604, 'count'),
                 0x56da28: (15195620, 'countByEnumeratingWithState:objects:count:'),
                 0x56da2c: (15195624, 'objectForKey:'),
                 0x56da34: (15195708, 'stringWithFormat:'),
                 0x56da44: (15195848, 'intValue'),
                 0x56da48: (15196472, 'lowercaseString'),
                 0x56da60: (15196476, 'isEqualToString:'),
        },
        imports={
                 0x56c65c: (17151904, 'objc_msgSend'),
                 0x56c668: (16231480, '__CFConstantStringClassReference'),
                 0x56c680: (16231496, '__CFConstantStringClassReference'),
                 0x56c880: (16231336, '__CFConstantStringClassReference'),
                 0x56c9f8: (16231512, '__CFConstantStringClassReference'),
                 0x56c9fc: (16231528, '__CFConstantStringClassReference'),
                 0x56cda4: (16231544, '__CFConstantStringClassReference'),
                 0x56cf90: (16231560, '__CFConstantStringClassReference'),
                 0x56cf94: (16231576, '__CFConstantStringClassReference'),
                 0x56cff8: (16231592, '__CFConstantStringClassReference'),
                 0x56d07c: (16231608, '__CFConstantStringClassReference'),
                 0x56d080: (16231624, '__CFConstantStringClassReference'),
                 0x56d084: (16231640, '__CFConstantStringClassReference'),
                 0x56d584: (16231656, '__CFConstantStringClassReference'),
                 0x56d850: (16231672, '__CFConstantStringClassReference'),
                 0x56da20: (17151904, 'objc_msgSend'),
                 0x56da30: (16231496, '__CFConstantStringClassReference'),
                 0x56da3c: (16231528, '__CFConstantStringClassReference'),
                 0x56da40: (16231544, '__CFConstantStringClassReference'),
                 0x56da4c: (16231656, '__CFConstantStringClassReference'),
                 0x56da50: (16231672, '__CFConstantStringClassReference'),
                 0x56da54: (16231688, '__CFConstantStringClassReference'),
                 0x56da58: (16231704, '__CFConstantStringClassReference'),
                 0x56da5c: (16231352, '__CFConstantStringClassReference'),
                 0x56da64: (16229528, '__CFConstantStringClassReference'),
                 0x56da68: (16231736, '__CFConstantStringClassReference'),
                 0x56da6c: (16231720, '__CFConstantStringClassReference'),
                 0x56da70: (16231384, '__CFConstantStringClassReference'),
                 0x56da74: (16231784, '__CFConstantStringClassReference'),
                 0x56da78: (16231800, '__CFConstantStringClassReference'),
                 0x56da7c: (16231768, '__CFConstantStringClassReference'),
                 0x56da80: (16231752, '__CFConstantStringClassReference'),
                 0x56da84: (16231816, '__CFConstantStringClassReference'),
                 0x56da88: (16231832, '__CFConstantStringClassReference'),
                 0x56da8c: (16231864, '__CFConstantStringClassReference'),
                 0x56da90: (16231848, '__CFConstantStringClassReference'),
        },
        ivars={},
        classes={
                 0x56c674: (15245292, 'OBJC_CLASS_$_NSNumber'),
                 0x56c67c: (15245288, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x56c688: (15245304, 'OBJC_CLASS_$_NSString'),
                 0x56da38: (15245304, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(5682804, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5692048, 'invalid')],
        calls=[(5682868, 'blx ip'), (5682984, 'bl sym.imp.memset'), (5683032, 'blx lr'), (5683132, 'bl sym.imp.objc_enumerationMutation'), (5683444, 'blx ip'), (5683472, 'blx r3'), (5683488, 'blx r2'), (5683552, 'blx r5'), (5683596, 'blx ip'), (5683628, 'blx r3'), (5683672, 'blx ip'), (5683704, 'blx r3'), (5683748, 'blx ip'), (5683780, 'blx r3'), (5683844, 'blx r4'), (5683876, 'blx r3'), (5683908, 'blx r3'), (5683952, 'blx ip'), (5683984, 'blx r3'), (5684028, 'blx ip'), (5684060, 'blx r3'), (5684192, 'bl sym.imp.memset'), (5684240, 'blx lr'), (5684340, 'bl sym.imp.objc_enumerationMutation'), (5684468, 'blx ip'), (5684564, 'blx ip'), (5684676, 'blx ip'), (5684884, 'blx ip'), (5684980, 'blx ip'), (5685212, 'blx ip'), (5685300, 'blx ip'), (5685388, 'blx ip'), (5685540, 'blx ip'), (5685628, 'blx ip'), (5685768, 'bl sym.imp.memset'), (5685816, 'blx lr'), (5685916, 'bl sym.imp.objc_enumerationMutation'), (5686012, 'blx lr'), (5686052, 'blx r3'), (5686120, 'blx r3'), (5686152, 'blx r3'), (5686228, 'blx r3'), (5686320, 'blx ip'), (5686368, 'blx ip'), (5686420, 'blx r3'), (5686452, 'blx r3'), (5686472, 'bl 0x56da94'), (5686520, 'blx r3'), (5686584, 'blx r2'), (5686660, 'blx r2'), (5686764, 'blx ip'), (5686860, 'blx ip'), (5687012, 'blx ip'), (5687136, 'blx ip'), (5687216, 'blx r2'), (5687300, 'blx r2'), (5687412, 'blx ip'), (5687512, 'blx ip'), (5687608, 'blx ip'), (5687660, 'blx r2'), (5687788, 'blx ip'), (5687892, 'blx ip'), (5687952, 'blx r2'), (5688068, 'bl sym.imp.memset'), (5688116, 'blx lr'), (5688216, 'bl sym.imp.objc_enumerationMutation'), (5688316, 'blx ip'), (5688340, 'blx r2'), (5688372, 'blx r3'), (5688392, 'bl 0x56da94'), (5688440, 'blx r3'), (5688528, 'blx r2'), (5688632, 'blx ip'), (5688728, 'blx ip'), (5688828, 'blx ip'), (5688952, 'blx ip'), (5689124, 'blx ip'), (5689220, 'blx ip'), (5689324, 'blx ip'), (5689456, 'blx ip'), (5689568, 'blx ip'), (5689712, 'bl sym.imp.memset'), (5689760, 'blx lr'), (5689860, 'bl sym.imp.objc_enumerationMutation'), (5690040, 'blx r8'), (5690064, 'blx r2'), (5690144, 'blx ip'), (5690284, 'blx ip'), (5690456, 'blx ip'), (5690528, 'blx r2'), (5690640, 'blx ip'), (5690744, 'blx ip'), (5690884, 'blx ip'), (5691040, 'blx ip'), (5691136, 'blx ip'), (5691248, 'blx ip'), (5691344, 'blx ip'), (5691460, 'blx ip'), (5691560, 'blx ip'), (5691684, 'blx ip'), (5691772, 'blx ip'), (5691888, 'blx ip')],
        branches=[(5682876, 'bne', 5682892), (5682888, 'b', 5691924), (5683044, 'beq', 5691912), (5683124, 'beq', 5683136), (5684092, 'beq', 5684996), (5684252, 'beq', 5684700), (5684332, 'beq', 5684344), (5684380, 'beq', 5684480), (5684476, 'b', 5684572), (5684604, 'blo', 5684296), (5684696, 'bne', 5684296), (5684700, 'b', 5684704), (5684716, 'bne', 5684800), (5684732, 'bne', 5684800), (5684748, 'bne', 5684800), (5684764, 'bne', 5684800), (5684780, 'bne', 5684800), (5684796, 'beq', 5684896), (5684892, 'b', 5684988), (5685008, 'beq', 5685648), (5685020, 'beq', 5685400), (5685036, 'bne', 5685088), (5685052, 'bne', 5685088), (5685068, 'bne', 5685088), (5685084, 'beq', 5685312), (5685100, 'bne', 5685224), (5685116, 'bne', 5685224), (5685132, 'bne', 5685224), (5685220, 'b', 5685308), (5685308, 'b', 5685396), (5685396, 'b', 5685640), (5685412, 'bne', 5685464), (5685428, 'bne', 5685464), (5685444, 'bne', 5685464), (5685460, 'beq', 5685552), (5685548, 'b', 5685636), (5685636, 'b', 5685640), (5685660, 'beq', 5687912), (5685828, 'beq', 5687160), (5685908, 'beq', 5685920), (5686072, 'beq', 5686376), (5686176, 'bgt', 5686236), (5686232, 'b', 5686372), (5686372, 'b', 5686376), (5686540, 'beq', 5686928), (5686592, 'bhi', 5686680), (5686608, 'bne', 5686680), (5686676, 'beq', 5686776), (5686772, 'b', 5686868), (5686868, 'b', 5687020), (5687064, 'blo', 5685872), (5687156, 'bne', 5685872), (5687160, 'b', 5687164), (5687172, 'beq', 5687620), (5687224, 'bhi', 5687260), (5687240, 'bne', 5687260), (5687256, 'beq', 5687524), (5687308, 'bhi', 5687428), (5687324, 'bne', 5687428), (5687420, 'b', 5687520), (5687520, 'b', 5687616), (5687616, 'b', 5687904), (5687668, 'bhi', 5687704), (5687684, 'bne', 5687704), (5687700, 'beq', 5687808), (5687796, 'b', 5687900), (5687900, 'b', 5687904), (5687960, 'bls', 5689588), (5688128, 'beq', 5688976), (5688208, 'beq', 5688220), (5688460, 'beq', 5688744), (5688476, 'bne', 5688548), (5688544, 'beq', 5688644), (5688640, 'b', 5688736), (5688736, 'b', 5688836), (5688880, 'blo', 5688172), (5688972, 'bne', 5688172), (5688976, 'b', 5688980), (5688988, 'beq', 5689340), (5689004, 'bne', 5689024), (5689020, 'beq', 5689240), (5689036, 'bne', 5689136), (5689132, 'b', 5689228), (5689228, 'b', 5689332), (5689332, 'b', 5689580), (5689352, 'bne', 5689372), (5689368, 'beq', 5689484), (5689464, 'b', 5689576), (5689576, 'b', 5689580), (5689600, 'beq', 5691580), (5689772, 'beq', 5690908), (5689852, 'beq', 5689864), (5690156, 'beq', 5690224), (5690208, 'b', 5690364), (5690296, 'beq', 5690360), (5690360, 'b', 5690364), (5690476, 'beq', 5690760), (5690544, 'bne', 5690660), (5690656, 'b', 5690752), (5690752, 'b', 5690768), (5690812, 'blo', 5689816), (5690904, 'bne', 5689816), (5690908, 'b', 5690912), (5690920, 'beq', 5691360), (5690936, 'beq', 5691148), (5690952, 'beq', 5691052), (5691048, 'b', 5691144), (5691144, 'b', 5691356), (5691160, 'beq', 5691260), (5691256, 'b', 5691352), (5691352, 'b', 5691356), (5691356, 'b', 5691572), (5691372, 'beq', 5691476), (5691468, 'b', 5691568), (5691568, 'b', 5691572), (5691592, 'beq', 5691788), (5691604, 'beq', 5691696), (5691692, 'b', 5691780), (5691788, 'b', 5691792), (5691816, 'blo', 5683088), (5691908, 'bne', 5683088), (5691912, 'b', 5691916)],
        semantics=('[World welcomeBackMessageForInfoDict:] (imp 0x0056b674, 2312w): the welcome-back builder - memset x5 + **fast enumeration x5** + the helper 0x56da94 x2 + sel x18 + consts 0x10/0x20 + br x122: the reconnect-state message (what changed while you were away).\n'),
    ),
    dict(
        name='wn_07',
        method='World -[welcomeBackEventsMessageForClientID:]',
        types='@12@0:4@8',
        start=5692376,
        end=5692556,
        disasm='disasm_worldtileloader_wn_07.txt',
        base_add=5692392,
        base_literal=5692552,
        boundary='ARM.exidx end 0x0056dc8c (listing bound); next ObjC IMP 0x0056dc8c World -[setNetEventsMessageToDisplayOnceLoaded:]',
        selectors={
                 0x56dc7c: (15196460, 'welcomeBackMessageForInfoDict:'),
                 0x56dc80: (15195624, 'objectForKey:'),
        },
        imports={
                 0x56dc78: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x56dc84: (17156360, 'OBJC_IVAR_$_World.awayClientSimulationEvents', 3148),
        },
        classes={},
        instructions=[(5692376, 'push {r4, r5, r6, sl, fp, lr}'), (5692552, 'adceq r1, pc, r4, lsl 30')],
        calls=[(5692492, 'blx ip'), (5692524, 'blx r3')],
        branches=[],
        semantics=('[World welcomeBackEventsMessageForClientID:] (imp 0x0056dbd8, 45w): the events-message hook.\n'),
    ),
    dict(
        name='wn_08',
        method='World -[setNetEventsMessageToDisplayOnceLoaded:]',
        types='v12@0:4@8',
        start=5692556,
        end=5692728,
        disasm='disasm_worldtileloader_wn_08.txt',
        base_add=5692572,
        base_literal=5692724,
        boundary='ARM.exidx end 0x0056dd38 (listing bound); next ObjC IMP 0x0056dd38 World -[simulationProgress]',
        selectors={
                 0x56dd2c: (15195732, 'retain'),
                 0x56dd30: (15195768, 'release'),
        },
        imports={
                 0x56dd28: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x56dd24: (17156292, 'OBJC_IVAR_$_World.netEventsMessageToDisplayOnceLoaded', 3152),
        },
        classes={},
        instructions=[(5692556, 'push {r4, r5, r6, sl, fp, lr}'), (5692724, 'adceq r1, pc, r0, asr lr')],
        calls=[(5692656, 'blx lr'), (5692676, 'blx r2')],
        branches=[],
        semantics=('[World setNetEventsMessageToDisplayOnceLoaded:] (imp 0x0056dc8c, 43w): the deferred-events setter.\n'),
    ),
    dict(
        name='wn_09',
        method='World -[requestUniqueIDFromServerWithDict:]',
        types='v12@0:4@8',
        start=6004240,
        end=6004756,
        disasm='disasm_worldtileloader_wn_09.txt',
        base_add=6004256,
        base_literal=6004752,
        boundary='ARM.exidx end 0x005ba014 (listing bound); next ObjC IMP 0x005ba014 World -[uniqueIDReturnedFromServer:]',
        selectors={
                 0x5b9ff0: (15195892, 'init'),
                 0x5b9ff4: (15195752, 'alloc'),
                 0x5b9ffc: (15195644, 'sendDataToServer:reliable:'),
                 0x5ba004: (15195552, 'dataWithBytes:length:'),
                 0x5ba00c: (15195700, 'addObject:'),
        },
        imports={
                 0x5b9fec: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5b9fe8: (17156672, 'OBJC_IVAR_$_World.dynamicObjectIDRequestInfoDicts', 980),
                 0x5ba000: (17155972, 'OBJC_IVAR_$_World.client', 960),
        },
        classes={
                 0x5b9ff8: (15245300, 'OBJC_CLASS_$_NSMutableArray'),
                 0x5ba008: (15245284, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(6004240, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6004752, 'adceq r5, sl, ip, asr 25')],
        calls=[(6004380, 'blx r2'), (6004396, 'blx r2'), (6004604, 'blx r7'), (6004648, 'blx ip'), (6004700, 'blx lr')],
        branches=[(6004308, 'bne', 6004420)],
        semantics=('[World requestUniqueIDFromServerWithDict:] (imp 0x005b9e10, 129w): the unique-ID requester (5 calls - the client->server ask).\n'),
    ),
    dict(
        name='wn_10',
        method='World -[uniqueIDReturnedFromServer:]',
        types='v16@0:4Q8',
        start=6004756,
        end=6010420,
        disasm='disasm_worldtileloader_wn_10.txt',
        base_add=6004772,
        base_literal=6008848,
        boundary='ARM.exidx end 0x005bb634 (listing bound); next ObjC IMP 0x005bb634 World -[teleportToWorkbench:withBlockhead:craftableItemObject:]',
        selectors={
                 0x5bb018: (15195604, 'count'),
                 0x5bb028: (15195624, 'objectForKey:'),
                 0x5bb030: (15195848, 'intValue'),
                 0x5bb03c: (15196360, 'removeObjectAtIndex:'),
                 0x5bb0f0: (15195860, 'autorelease'),
                 0x5bb0f4: (15195732, 'retain'),
                 0x5bb0f8: (15195800, 'objectAtIndex:'),
                 0x5bb1b0: (15196308, 'craftableItem'),
                 0x5bb1b4: (15196476, 'isEqualToString:'),
                 0x5bb1b8: (15196592, 'stringFromMD5'),
                 0x5bb1c0: (15195708, 'stringWithFormat:'),
                 0x5bb1c8: (15196780, 'amountString'),
                 0x5bb1cc: (15195544, 'instance'),
                 0x5bb1d4: (15196772, 'amount'),
                 0x5bb58c: (15196764, 'worldUI'),
                 0x5bb590: (15196768, 'setCountWatcher:'),
                 0x5bb59c: (15195604, 'count'),
                 0x5bb5a0: (15195692, 'blockheads'),
                 0x5bb5ac: (15197604, 'reportAchievementWithIdentifier:'),
                 0x5bb5c0: (15197568, 'displayInterstitialForTag:'),
                 0x5bb5cc: (15197608, 'loadNewBlockheadAtPos:craftableItemObject:uniqueID:'),
                 0x5bb5d0: (15197612, 'setActiveBlockhead:dontFollow:'),
                 0x5bb5d4: (15196444, 'activeBlockhead'),
                 0x5bb5d8: (15196764, 'worldUI'),
                 0x5bb5e0: (15197692, 'selectBlockheadButtonAtIndex:'),
                 0x5bb5e4: (15196828, 'updateiCloudRecentConnectionList'),
                 0x5bb5e8: (15197688, 'subtractItemsFromInventoryOfType:count:dataB:'),
                 0x5bb5f4: (15195544, 'instance'),
                 0x5bb5f8: (15196768, 'setCountWatcher:'),
                 0x5bb5fc: (15196476, 'isEqualToString:'),
                 0x5bb600: (15196592, 'stringFromMD5'),
                 0x5bb608: (15195708, 'stringWithFormat:'),
                 0x5bb610: (15196772, 'amount'),
                 0x5bb61c: (15196776, 'modify:modifyString:'),
                 0x5bb620: (15196780, 'amountString'),
                 0x5bb624: (15197584, 'pos'),
                 0x5bb62c: (15196876, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
        },
        imports={
                 0x5bb014: (17151904, 'objc_msgSend'),
                 0x5bb020: (16232696, '__CFConstantStringClassReference'),
                 0x5bb024: (16232520, '__CFConstantStringClassReference'),
                 0x5bb02c: (16232712, '__CFConstantStringClassReference'),
                 0x5bb034: (16232552, '__CFConstantStringClassReference'),
                 0x5bb038: (16232536, '__CFConstantStringClassReference'),
                 0x5bb1bc: (16232120, '__CFConstantStringClassReference'),
                 0x5bb598: (17151904, 'objc_msgSend'),
                 0x5bb5a8: (16232648, '__CFConstantStringClassReference'),
                 0x5bb5b0: (16232632, '__CFConstantStringClassReference'),
                 0x5bb5b4: (16232616, '__CFConstantStringClassReference'),
                 0x5bb5b8: (16232600, '__CFConstantStringClassReference'),
                 0x5bb5bc: (16232728, '__CFConstantStringClassReference'),
                 0x5bb604: (16232120, '__CFConstantStringClassReference'),
                 0x5bb618: (16232104, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5bb01c: (17156672, 'OBJC_IVAR_$_World.dynamicObjectIDRequestInfoDicts', 980),
                 0x5bb0fc: (17156668, 'OBJC_IVAR_$_World.unableToCraftBlockheadDueToWaitingForServer', 3064),
                 0x5bb468: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x5bb5a4: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5bb5dc: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
        },
        classes={
                 0x5bb1c4: (15245304, 'OBJC_CLASS_$_NSString'),
                 0x5bb1d0: (15245464, 'OBJC_CLASS_$_CrystalManager'),
                 0x5bb5ec: (15245464, 'OBJC_CLASS_$_CrystalManager'),
                 0x5bb614: (15245304, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(6004756, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6010416, 'invalid')],
        calls=[(6004840, 'blx lr'), (6004864, 'bl sym.imp.NSLog'), (6005148, 'blx ip'), (6005164, 'blx r2'), (6005180, 'blx r2'), (6005224, 'blx r3'), (6005248, 'blx r3'), (6005264, 'blx r2'), (6005292, 'blx r3'), (6005308, 'blx r2'), (6005336, 'blx r3'), (6005364, 'blx r3'), (6005448, 'bl loc.imp.objc_msgSend_stret'), (6005484, 'bl sym.imp.memset'), (6005756, 'blx sl'), (6005772, 'blx r2'), (6005808, 'blx r3'), (6005824, 'blx r2'), (6005864, 'blx lr'), (6005880, 'blx r2'), (6005912, 'blx r3'), (6006008, 'blx lr'), (6006024, 'blx r2'), (6006136, 'bl loc.imp.objc_msgSend'), (6006184, 'bl loc.imp.objc_msgSend'), (6006216, 'bl loc.imp.objc_msgSend'), (6006388, 'bl loc.imp.objc_msgSend'), (6006404, 'bl loc.imp.objc_msgSend'), (6006488, 'bl loc.imp.objc_msgSend'), (6006504, 'bl loc.imp.objc_msgSend'), (6006532, 'bl loc.imp.objc_msgSend'), (6006564, 'bl loc.imp.objc_msgSend'), (6006588, 'bl loc.imp.objc_msgSend'), (6006604, 'bl loc.imp.objc_msgSend'), (6006672, 'blx ip'), (6006688, 'blx r2'), (6006720, 'blx r3'), (6006816, 'blx lr'), (6006832, 'blx r2'), (6006988, 'blx ip'), (6007028, 'blx r3'), (6007220, 'bl loc.imp.objc_msgSend_stret'), (6007256, 'bl sym.imp.memset'), (6007408, 'bl loc.imp.objc_msgSend'), (6007560, 'bl loc.imp.objc_msgSend_stret'), (6007596, 'bl sym.imp.memset'), (6007748, 'bl loc.imp.objc_msgSend'), (6007880, 'bl loc.imp.objc_msgSend'), (6007928, 'bl loc.imp.objc_msgSend'), (6007960, 'bl loc.imp.objc_msgSend'), (6008144, 'bl loc.imp.objc_msgSend'), (6008160, 'bl loc.imp.objc_msgSend'), (6008244, 'bl loc.imp.objc_msgSend'), (6008260, 'bl loc.imp.objc_msgSend'), (6008288, 'bl loc.imp.objc_msgSend'), (6008324, 'bl loc.imp.objc_msgSend'), (6008348, 'bl loc.imp.objc_msgSend'), (6008364, 'bl loc.imp.objc_msgSend'), (6008432, 'blx ip'), (6008448, 'blx r2'), (6008480, 'blx r3'), (6008576, 'blx lr'), (6008592, 'blx r2'), (6008752, 'blx ip'), (6008768, 'blx r2'), (6008840, 'blx ip'), (6008976, 'blx ip'), (6008992, 'blx r2'), (6009064, 'blx ip'), (6009168, 'blx ip'), (6009184, 'blx r2'), (6009256, 'blx ip'), (6009384, 'blx ip'), (6009400, 'blx r2'), (6009472, 'blx ip'), (6009584, 'blx ip'), (6009704, 'bl loc.imp.objc_msgSend'), (6009856, 'blx r7'), (6009904, 'blx ip'), (6009920, 'blx r2'), (6009948, 'blx r3'), (6010088, 'blx r6'), (6010136, 'blx ip'), (6010176, 'blx ip'), (6010240, 'blx r2')],
        branches=[(6004848, 'bne', 6004872), (6004868, 'b', 6010244), (6005392, 'beq', 6009492), (6005432, 'beq', 6005456), (6005452, 'b', 6005488), (6005512, 'bge', 6008672), (6005548, 'bne', 6006864), (6005924, 'beq', 6006040), (6006036, 'bne', 6006048), (6006084, 'ble', 6006092), (6006088, 'b', 6010244), (6006244, 'ble', 6006860), (6006732, 'beq', 6006848), (6006844, 'bne', 6006856), (6006856, 'b', 6006860), (6006860, 'b', 6008652), (6007052, 'ble', 6008648), (6007076, 'bge', 6007452), (6007112, 'beq', 6007432), (6007164, 'bge', 6007428), (6007204, 'beq', 6007228), (6007224, 'b', 6007260), (6007424, 'b', 6007128), (6007428, 'b', 6007432), (6007432, 'b', 6007436), (6007448, 'b', 6007064), (6007504, 'bge', 6007768), (6007544, 'beq', 6007568), (6007564, 'b', 6007600), (6007764, 'b', 6007460), (6007788, 'bge', 6008644), (6007824, 'bne', 6008624), (6008000, 'bgt', 6008620), (6008492, 'beq', 6008608), (6008604, 'bne', 6008616), (6008616, 'b', 6008620), (6008620, 'b', 6008624), (6008624, 'b', 6008628), (6008640, 'b', 6007776), (6008644, 'b', 6010244), (6008648, 'b', 6008652), (6008652, 'b', 6008656), (6008668, 'b', 6005500), (6008776, 'bne', 6008896), (6008844, 'b', 6009488), (6009000, 'bne', 6009088), (6009068, 'b', 6009484), (6009192, 'bne', 6009304), (6009260, 'b', 6009480), (6009408, 'bne', 6009476), (6009476, 'b', 6009480), (6009480, 'b', 6009484), (6009484, 'b', 6009488), (6009488, 'b', 6009492), (6009500, 'beq', 6009592), (6009720, 'beq', 6009964), (6009952, 'b', 6010180)],
        semantics=('[World uniqueIDReturnedFromServer:] (imp 0x005ba014, 1416w): the unique-ID grant handler - objc x25 + stret x3 + memset x3 + NSLog + sel x37 + **consts 0x7c (124)/0xc350 (50000!)** + br x57: the per-object ID assignment with the 50000-object ceiling.\n'),
    ),
    dict(
        name='wn_11',
        method='World -[clientConnected:]',
        types='c12@0:4@8',
        start=6028464,
        end=6029732,
        disasm='disasm_worldtileloader_wn_11.txt',
        base_add=6028480,
        base_literal=6029728,
        boundary='ARM.exidx end 0x005c01a4 (listing bound); next ObjC IMP 0x005c01a4 World -[clientDisconnected:wasKick:]',
        selectors={
                 0x5c013c: (15195624, 'objectForKey:'),
                 0x5c0148: (15197760, 'lastIndex'),
                 0x5c0154: (15197764, 'removeIndex:'),
                 0x5c015c: (15195752, 'alloc'),
                 0x5c0168: (15196124, 'lightBlockDatabase'),
                 0x5c016c: (15197768, 'initWithClientID:server:lightBlockIndex:lightBlockDatabase:'),
                 0x5c0170: (15195860, 'autorelease'),
                 0x5c0174: (15195584, 'setObject:forKey:'),
                 0x5c0178: (15197772, 'unarchiveLightBlocksForClient:'),
                 0x5c0180: (15197776, 'clientConnected:'),
                 0x5c0188: (15196096, 'fullyLoadIfNeededAroundPos:clientLightBlockIndex:forBlockhead:'),
                 0x5c0190: (15195672, 'connected'),
                 0x5c0198: (15197780, 'clientReconnected'),
                 0x5c019c: (15196544, 'lightBlockIndex'),
        },
        imports={
                 0x5c0138: (17151904, 'objc_msgSend'),
                 0x5c018c: (16232760, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5c0140: (17155964, 'OBJC_IVAR_$_World.serverClients', 956),
                 0x5c014c: (17156332, 'OBJC_IVAR_$_World.freeClientLightBlockIndices', 496),
                 0x5c0160: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x5c0164: (17156104, 'OBJC_IVAR_$_World.worldTileLoader', 420),
                 0x5c017c: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5c0184: (17155912, 'OBJC_IVAR_$_World.startPortalPos', 144),
        },
        classes={
                 0x5c0158: (15245512, 'OBJC_CLASS_$_ServerClient'),
        },
        instructions=[(6028464, 'push {r4, r5, fp, lr}'), (6029728, 'adceq pc, sb, ip, lsr 28')],
        calls=[(6028568, 'blx lr'), (6028656, 'blx r3'), (6028692, 'bl sym.imp.NSLog'), (6028760, 'bl loc.imp.objc_msgSend'), (6028784, 'bl loc.imp.objc_msgSend'), (6028872, 'bl loc.imp.objc_msgSend'), (6028916, 'bl loc.imp.objc_msgSend'), (6028932, 'bl loc.imp.objc_msgSend'), (6028996, 'bl loc.imp.objc_msgSend'), (6029032, 'bl loc.imp.objc_msgSend'), (6029076, 'bl loc.imp.objc_msgSend'), (6029164, 'bl loc.imp.objc_msgSend'), (6029272, 'blx ip'), (6029288, 'blx r2'), (6029376, 'bl loc.imp.objc_msgSend'), (6029392, 'bl loc.imp.objc_msgSend'), (6029436, 'bl loc.imp.objc_msgSend'), (6029524, 'bl loc.imp.objc_msgSend'), (6029540, 'bl loc.imp.objc_msgSend'), (6029584, 'bl loc.imp.objc_msgSend')],
        branches=[(6028580, 'bne', 6029184), (6028676, 'bne', 6028700), (6028696, 'b', 6029180), (6029176, 'b', 6029612), (6029180, 'b', 6029604), (6029300, 'bne', 6029600), (6029596, 'b', 6029612), (6029600, 'b', 6029604)],
        semantics=('[World clientConnected:] (imp 0x005bfcb0, 317w): the client-accept hook - objc x15 + NSLog + sel x14 + **the 0x7fffffff (INT_MAX) sentinel cell** (initial/unbounded ID state).\n'),
    ),
    dict(
        name='wn_12',
        method='World -[clientDisconnected:wasKick:]',
        types='v16@0:4@8c12',
        start=6029732,
        end=6030704,
        disasm='disasm_worldtileloader_wn_12.txt',
        base_add=6029748,
        base_literal=6030700,
        boundary='ARM.exidx end 0x005c0570 (listing bound); next ObjC IMP 0x005c0570 World -[requestForBlock:fromClient:]',
        selectors={
                 0x5c0534: (15195624, 'objectForKey:'),
                 0x5c0544: (15197784, 'stopAllBlockheadActionsForClientDueToKick:'),
                 0x5c054c: (15195672, 'connected'),
                 0x5c0550: (15197788, 'clientDisconnected:simulate:'),
                 0x5c0554: (15195736, 'removeObjectForKey:'),
                 0x5c055c: (15197792, 'setConnected:'),
                 0x5c0564: (15197796, 'preUpdate:'),
        },
        imports={
                 0x5c0530: (17151904, 'objc_msgSend'),
                 0x5c053c: (16232776, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5c0538: (17155964, 'OBJC_IVAR_$_World.serverClients', 956),
                 0x5c0540: (17155892, 'OBJC_IVAR_$_World.worldName', 440),
                 0x5c0548: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5c0558: (17156360, 'OBJC_IVAR_$_World.awayClientSimulationEvents', 3148),
                 0x5c0568: (17156700, 'OBJC_IVAR_$_World.saveCounter', 3384),
        },
        classes={},
        instructions=[(6029732, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6030700, 'adceq pc, sb, r8, lsr sb')],
        calls=[(6029812, 'bl sym.imp.NSLog'), (6029884, 'blx r3'), (6029972, 'blx r3'), (6030048, 'blx r2'), (6030224, 'blx sl'), (6030292, 'blx lr'), (6030332, 'blx ip'), (6030356, 'blx r3'), (6030476, 'blx lr'), (6030544, 'blx lr'), (6030628, 'blx r3')],
        branches=[(6029900, 'beq', 6029976), (6029988, 'beq', 6030364), (6030004, 'beq', 6030364), (6030060, 'beq', 6030364), (6030360, 'b', 6030552), (6030372, 'beq', 6030548), (6030548, 'b', 6030552)],
        semantics=('[World clientDisconnected:wasKick:] (imp 0x005c01a4, 243w): the client-drop hook - NSLog + **const 0x3e7 (999)** (the kick code!) + br x7.\n'),
    ),
    dict(
        name='wn_13',
        method='World -[requestForBlock:fromClient:]',
        types='v20@0:4{ClientMacroBlockRequest=iC[3C]}8@16',
        start=6030704,
        end=6031000,
        disasm='disasm_worldtileloader_wn_13.txt',
        base_add=6030720,
        base_literal=6030996,
        boundary='ARM.exidx end 0x005c0698 (listing bound); next ObjC IMP 0x005c0698 World -[remoteBlockRemoved:byClient:]',
        selectors={
                 0x5c0680: (15195672, 'connected'),
                 0x5c0684: (15195624, 'objectForKey:'),
                 0x5c0690: (15197800, 'requestForBlock:'),
        },
        imports={
                 0x5c067c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5c0688: (17155964, 'OBJC_IVAR_$_World.serverClients', 956),
        },
        classes={},
        instructions=[(6030704, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6030996, 'adceq pc, sb, ip, ror 10')],
        calls=[(6030828, 'blx r4'), (6030844, 'blx r2'), (6030920, 'bl loc.imp.objc_msgSend'), (6030960, 'bl loc.imp.objc_msgSend')],
        branches=[(6030856, 'beq', 6030964)],
        semantics=('[World requestForBlock:fromClient:] (imp 0x005c0570, 74w): the block-request handler.\n'),
    ),
    dict(
        name='wn_14',
        method='World -[remoteBlockRemoved:byClient:]',
        types='v16@0:4i8@12',
        start=6031000,
        end=6031296,
        disasm='disasm_worldtileloader_wn_14.txt',
        base_add=6031016,
        base_literal=6031292,
        boundary='ARM.exidx end 0x005c07c0 (listing bound); next ObjC IMP 0x005c07c0 World -[peersInterestedInMacroIndex:]',
        selectors={
                 0x5c07ac: (15195672, 'connected'),
                 0x5c07b0: (15195624, 'objectForKey:'),
                 0x5c07b8: (15197804, 'blockRemoved:'),
        },
        imports={
                 0x5c07a8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5c07b4: (17155964, 'OBJC_IVAR_$_World.serverClients', 956),
        },
        classes={},
        instructions=[(6031000, 'push {r4, r5, r6, r7, fp, lr}'), (6031292, 'adceq pc, sb, r4, asr 8')],
        calls=[(6031120, 'blx lr'), (6031136, 'blx r2'), (6031240, 'blx ip'), (6031260, 'blx r3')],
        branches=[(6031148, 'beq', 6031264)],
        semantics=('[World remoteBlockRemoved:byClient:] (imp 0x005c0698, 74w): the block-removed notice.\n'),
    ),
    dict(
        name='wn_15',
        method='World -[peersInterestedInMacroIndex:]',
        types='@12@0:4i8',
        start=6031296,
        end=6032204,
        disasm='disasm_worldtileloader_wn_15.txt',
        base_add=6031312,
        base_literal=6032200,
        boundary='ARM.exidx end 0x005c0b4c (listing bound); next ObjC IMP 0x005c0b4c World -[remoteCreate:forObjectsOfType:clientID:]',
        selectors={
                 0x5c0b28: (15195620, 'countByEnumeratingWithState:objects:count:'),
                 0x5c0b30: (15195688, 'array'),
                 0x5c0b38: (15197492, 'blockIsWired:'),
                 0x5c0b3c: (15195624, 'objectForKey:'),
                 0x5c0b40: (15195672, 'connected'),
                 0x5c0b44: (15195700, 'addObject:'),
        },
        imports={
                 0x5c0b24: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5c0b20: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x5c0b2c: (17155964, 'OBJC_IVAR_$_World.serverClients', 956),
        },
        classes={
                 0x5c0b34: (15245300, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(6031296, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6032200, 'adceq pc, sb, ip, lsl r3')],
        calls=[(6031496, 'blx r2'), (6031520, 'bl sym.imp.memset'), (6031584, 'blx lr'), (6031684, 'bl sym.imp.objc_enumerationMutation'), (6031804, 'blx ip'), (6031824, 'blx r3'), (6031928, 'blx ip'), (6031944, 'blx r2'), (6032008, 'blx r3'), (6032112, 'blx ip')],
        branches=[(6031364, 'bne', 6031380), (6031376, 'b', 6032148), (6031596, 'beq', 6032136), (6031676, 'beq', 6031688), (6031836, 'beq', 6032012), (6031956, 'beq', 6032012), (6032012, 'b', 6032016), (6032040, 'blo', 6031640), (6032132, 'bne', 6031640), (6032136, 'b', 6032140)],
        semantics=('[World peersInterestedInMacroIndex:] (imp 0x005c07c0, 227w): the interest resolver - memset + fast enumeration + consts 0x10/0x20 + br x10 (which peers watch this macro tile).\n'),
    ),
    dict(
        name='wn_16',
        method='World -[remoteCreate:forObjectsOfType:clientID:]',
        types='v20@0:4@8i12@16',
        start=6032204,
        end=6033236,
        disasm='disasm_worldtileloader_wn_16.txt',
        base_add=6032220,
        base_literal=6033232,
        boundary='ARM.exidx end 0x005c0f54 (listing bound); next ObjC IMP 0x005c0f54 World -[remoteUpdate:forObjectsOfType:fromClient:]',
        selectors={
                 0x5c0f20: (15195892, 'init'),
                 0x5c0f24: (15195752, 'alloc'),
                 0x5c0f2c: (15195624, 'objectForKey:'),
                 0x5c0f30: (15195584, 'setObject:forKey:'),
                 0x5c0f34: (15195684, 'dictionary'),
                 0x5c0f38: (15195572, 'numberWithInt:'),
                 0x5c0f40: (15195688, 'array'),
                 0x5c0f48: (15197808, 'addObjectsFromArray:'),
                 0x5c0f4c: (15196080, 'remoteCreate:forObjectsOfType:clientID:'),
        },
        imports={
                 0x5c0f1c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5c0f14: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5c0f18: (17156276, 'OBJC_IVAR_$_World.initialCreateObjects', 984),
        },
        classes={
                 0x5c0f28: (15245288, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x5c0f3c: (15245292, 'OBJC_CLASS_$_NSNumber'),
                 0x5c0f44: (15245300, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(6032204, 'push {r4, r5, r6, sl, fp, lr}'), (6033232, 'umlaleq lr, sb, r0, pc')],
        calls=[(6032372, 'blx ip'), (6032488, 'blx r2'), (6032504, 'blx r2'), (6032612, 'blx r3'), (6032716, 'blx lr'), (6032764, 'blx lr'), (6032860, 'blx lr'), (6032892, 'blx r3'), (6033016, 'blx r5'), (6033072, 'blx r3'), (6033108, 'blx ip'), (6033160, 'blx r3')],
        branches=[(6032284, 'beq', 6032380), (6032376, 'b', 6033164), (6032416, 'bne', 6032528), (6032632, 'bne', 6032768), (6032912, 'bne', 6033112)],
        semantics=('[World remoteCreate:forObjectsOfType:clientID:] (imp 0x005c0b4c, 258w): the remote-create dispatcher (no external calls - message packing; the quartet leader).\n'),
    ),
    dict(
        name='wn_17',
        method='World -[remoteUpdate:forObjectsOfType:fromClient:]',
        types='v20@0:4@8i12@16',
        start=6033236,
        end=6034072,
        disasm='disasm_worldtileloader_wn_17.txt',
        base_add=6033252,
        base_literal=6034068,
        boundary='ARM.exidx end 0x005c1298 (listing bound); next ObjC IMP 0x005c1298 World -[remoteCreationDataUpdate:forObjectsOfType:fromClient:]',
        selectors={
                 0x5c1268: (15195892, 'init'),
                 0x5c126c: (15195752, 'alloc'),
                 0x5c1274: (15195624, 'objectForKey:'),
                 0x5c1278: (15195572, 'numberWithInt:'),
                 0x5c1280: (15195584, 'setObject:forKey:'),
                 0x5c1284: (15195688, 'array'),
                 0x5c128c: (15197808, 'addObjectsFromArray:'),
                 0x5c1290: (15196084, 'remoteUpdate:forObjectsOfType:fromClient:'),
        },
        imports={
                 0x5c1264: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5c125c: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5c1260: (17156280, 'OBJC_IVAR_$_World.initialUpdateObjects', 988),
        },
        classes={
                 0x5c1270: (15245288, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x5c127c: (15245292, 'OBJC_CLASS_$_NSNumber'),
                 0x5c1288: (15245300, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(6033236, 'push {r4, r5, r6, r7, fp, lr}'), (6034068, 'adceq lr, sb, r8, lsl 23')],
        calls=[(6033404, 'blx ip'), (6033520, 'blx r2'), (6033536, 'blx r2'), (6033672, 'blx lr'), (6033704, 'blx r3'), (6033840, 'blx r6'), (6033912, 'blx ip'), (6033948, 'blx ip'), (6034000, 'blx r3')],
        branches=[(6033316, 'beq', 6033412), (6033408, 'b', 6034004), (6033448, 'bne', 6033560), (6033724, 'bne', 6033952)],
        semantics=('[World remoteUpdate:forObjectsOfType:fromClient:] (imp 0x005c0f54, 209w): the remote-update dispatcher (same shape as remoteCreate - the quartet).\n'),
    ),
    dict(
        name='wn_18',
        method='World -[remoteCreationDataUpdate:forObjectsOfType:fromClient:]',
        types='v20@0:4@8i12@16',
        start=6034072,
        end=6034908,
        disasm='disasm_worldtileloader_wn_18.txt',
        base_add=6034088,
        base_literal=6034904,
        boundary='ARM.exidx end 0x005c15dc (listing bound); next ObjC IMP 0x005c15dc World -[remoteRemove:forObjectsOfType:fromClient:]',
        selectors={
                 0x5c15ac: (15195892, 'init'),
                 0x5c15b0: (15195752, 'alloc'),
                 0x5c15b8: (15195624, 'objectForKey:'),
                 0x5c15bc: (15195572, 'numberWithInt:'),
                 0x5c15c4: (15195584, 'setObject:forKey:'),
                 0x5c15c8: (15195688, 'array'),
                 0x5c15d0: (15197808, 'addObjectsFromArray:'),
                 0x5c15d4: (15196088, 'remoteCreationDataUpdate:forObjectsOfType:fromClient:'),
        },
        imports={
                 0x5c15a8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5c15a0: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5c15a4: (17156284, 'OBJC_IVAR_$_World.initialCreationDataUpdateObjects', 992),
        },
        classes={
                 0x5c15b4: (15245288, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x5c15c0: (15245292, 'OBJC_CLASS_$_NSNumber'),
                 0x5c15cc: (15245300, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(6034072, 'push {r4, r5, r6, r7, fp, lr}'), (6034904, 'adceq lr, sb, r4, asr 16')],
        calls=[(6034240, 'blx ip'), (6034356, 'blx r2'), (6034372, 'blx r2'), (6034508, 'blx lr'), (6034540, 'blx r3'), (6034676, 'blx r6'), (6034748, 'blx ip'), (6034784, 'blx ip'), (6034836, 'blx r3')],
        branches=[(6034152, 'beq', 6034248), (6034244, 'b', 6034840), (6034284, 'bne', 6034396), (6034560, 'bne', 6034788)],
        semantics=('[World remoteCreationDataUpdate:forObjectsOfType:fromClient:] (imp 0x005c1298, 209w): the creation-data dispatcher (quartet).\n'),
    ),
    dict(
        name='wn_19',
        method='World -[remoteRemove:forObjectsOfType:fromClient:]',
        types='v20@0:4@8i12@16',
        start=6034908,
        end=6035744,
        disasm='disasm_worldtileloader_wn_19.txt',
        base_add=6034924,
        base_literal=6035740,
        boundary='ARM.exidx end 0x005c1920 (listing bound); next ObjC IMP 0x005c1920 World -[connectionToServerLost]',
        selectors={
                 0x5c18f0: (15195892, 'init'),
                 0x5c18f4: (15195752, 'alloc'),
                 0x5c18fc: (15195624, 'objectForKey:'),
                 0x5c1900: (15195572, 'numberWithInt:'),
                 0x5c1908: (15195584, 'setObject:forKey:'),
                 0x5c190c: (15195688, 'array'),
                 0x5c1914: (15197808, 'addObjectsFromArray:'),
                 0x5c1918: (15196092, 'remoteRemove:forObjectsOfType:fromClient:'),
        },
        imports={
                 0x5c18ec: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5c18e4: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5c18e8: (17156288, 'OBJC_IVAR_$_World.initialRemoveObjects', 996),
        },
        classes={
                 0x5c18f8: (15245288, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x5c1904: (15245292, 'OBJC_CLASS_$_NSNumber'),
                 0x5c1910: (15245300, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(6034908, 'push {r4, r5, r6, r7, fp, lr}'), (6035740, 'adceq lr, sb, r0, lsl 10')],
        calls=[(6035076, 'blx ip'), (6035192, 'blx r2'), (6035208, 'blx r2'), (6035344, 'blx lr'), (6035376, 'blx r3'), (6035512, 'blx r6'), (6035584, 'blx ip'), (6035620, 'blx ip'), (6035672, 'blx r3')],
        branches=[(6034988, 'beq', 6035084), (6035080, 'b', 6035676), (6035120, 'bne', 6035232), (6035396, 'bne', 6035624)],
        semantics=('[World remoteRemove:forObjectsOfType:fromClient:] (imp 0x005c15dc, 209w): the remote-remove dispatcher (quartet).\n'),
    ),
    dict(
        name='wn_20',
        method='World -[connectionToServerLost]',
        types='v8@0:4',
        start=6035744,
        end=6035892,
        disasm='disasm_worldtileloader_wn_20.txt',
        base_add=6035760,
        base_literal=6035888,
        boundary='ARM.exidx end 0x005c19b4 (listing bound); next ObjC IMP 0x005c19b4 World -[currentTipText]',
        selectors={
                 0x5c19a8: (15197812, 'connectionToServerLost'),
        },
        imports={
                 0x5c19a4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5c19a0: (17156456, 'OBJC_IVAR_$_World.connectionToServerLost', 968),
                 0x5c19ac: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={},
        instructions=[(6035744, 'push {r4, r5, fp, lr}'), (6035888, 'invalid')],
        calls=[(6035836, 'blx lr')],
        branches=[],
        semantics=('[World connectionToServerLost] (imp 0x005c1920, 37w): the connection-loss hook.\n'),
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
        'batch': 'World net/admin core (E103): the ID grant, the heartbeat family and the remote quartet; 21 bodies',
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
                        default=NATIVE / 'world_net.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale world_net.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
