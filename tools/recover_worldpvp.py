#!/usr/bin/env python3
"""Hash-gated recovery of the World PVP, projectile and tips line (E112).

The World PVP/projectile/tips line: the damage wire pair, the
projectile fire/request pair, the PVP toggle and the shared tip
notification channel:
11 bodies, 1782 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/WORLD_PVP.md for the prose and boundaries.
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
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector_float__float__float__float_': 0x004d0d08,
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl sym.imp.NSLog': 0x001c2a5c,
    'bl sym.imp.__wrap_malloc': 0x001c2e58,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
}

SPECS = [
    dict(
        name='wp_00',
        method='World -[remoteBlockheadDamageRequest:requestedByClientName:]',
        types='v16@0:4@8@12',
        start=6069076,
        end=6070360,
        disasm='disasm_worldtileloader_wp_00.txt',
        base_add=6069092,
        base_literal=6070356,
        boundary='ARM.exidx end 0x005ca058 (listing bound); next ObjC IMP 0x005ca058 World -[sendNetDataForElectricityParticlePathIfRequired:size:ignoreClient:]',
        selectors={
                 0x5ca01c: (15195656, 'getBytes:length:'),
                 0x5ca024: (15195620, 'countByEnumeratingWithState:objects:count:'),
                 0x5ca028: (15196652, 'allBlockheadsIncludingNet'),
                 0x5ca030: (15196300, 'uniqueID'),
                 0x5ca038: (15198080, 'isSimulating'),
                 0x5ca03c: (15196292, 'isClientBlockheadBeingControlledByServer'),
                 0x5ca040: (15198084, 'sufferDamage:isSimulation:recoil:'),
                 0x5ca048: (15198088, 'playerNameForPlayerWithIDIncludingOldPlayers:'),
                 0x5ca04c: (15196296, 'clientID'),
                 0x5ca050: (15196044, 'name'),
        },
        imports={
                 0x5ca018: (17151904, 'objc_msgSend'),
                 0x5ca044: (16232968, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5ca014: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x5ca020: (17155936, 'OBJC_IVAR_$_World.pvpEnabled', 3268),
                 0x5ca02c: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={},
        instructions=[(6069076, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6070356, 'adceq r5, sb, r8, lsl 31')],
        calls=[(6069176, 'blx r6'), (6069360, 'bl sym.imp.memset'), (6069396, 'blx r3'), (6069440, 'blx lr'), (6069540, 'bl sym.imp.objc_enumerationMutation'), (6069576, 'bl loc.imp.objc_msgSend'), (6069680, 'blx r3'), (6069744, 'blx r2'), (6069876, 'blx r5'), (6070028, 'blx r2'), (6070084, 'blx r3'), (6070116, 'blx r3'), (6070144, 'bl sym.imp.NSLog'), (6070252, 'blx ip')],
        branches=[(6069208, 'beq', 6069248), (6069244, 'beq', 6070284), (6069452, 'beq', 6070276), (6069532, 'beq', 6069544), (6069604, 'bne', 6070152), (6069608, 'b', 6069612), (6069700, 'bne', 6069768), (6069892, 'beq', 6070148), (6069932, 'beq', 6070148), (6070148, 'b', 6070280), (6070152, 'b', 6070156), (6070180, 'blo', 6069496), (6070272, 'bne', 6069496), (6070276, 'b', 6070280), (6070280, 'b', 6070284)],
        semantics=('[World remoteBlockheadDamageRequest:requestedByClientName:] (imp 0x005c9b54, 321w): the server-side damage intake - getBytes:length: decode, then the allBlockheadsIncludingNet walk (uniqueID / isSimulating / isClientBlockheadBeingControlledByServer gates) delivering sufferDamage:isSimulation:recoil: to the target blockhead and resolving playerNameForPlayerWithIDIncludingOldPlayers:; pvpEnabled ivar; NSLog x1; constants 0x10/0x20.\n'),
    ),
    dict(
        name='wp_01',
        method='World -[sendAndDisplayAirTimeTipWithDistance:]',
        types='v12@0:4f8',
        start=6074508,
        end=6075728,
        disasm='disasm_worldtileloader_wp_01.txt',
        base_add=6074524,
        base_literal=6075724,
        boundary='ARM.exidx end 0x005cb550 (listing bound); next ObjC IMP 0x005cb550 World -[setPVPEnabled:displayNotifciation:]',
        selectors={
                 0x5cb50c: (15195708, 'stringWithFormat:'),
                 0x5cb51c: (15195544, 'instance'),
                 0x5cb520: (15197364, 'displayTip:withTimeOut:displayEvenIfDisabled:tipColor:'),
                 0x5cb52c: (15195552, 'dataWithBytes:length:'),
                 0x5cb534: (15198100, 'localPlayerName'),
                 0x5cb538: (15195612, 'appendData:'),
                 0x5cb53c: (15198104, 'dataUsingEncoding:'),
                 0x5cb544: (15195640, 'sendNetworkData:toPeers:reliable:'),
                 0x5cb548: (15195644, 'sendDataToServer:reliable:'),
        },
        imports={
                 0x5cb510: (16233000, '__CFConstantStringClassReference'),
                 0x5cb514: (16232984, '__CFConstantStringClassReference'),
                 0x5cb528: (17151904, 'objc_msgSend'),
                 0x5cb540: (16233016, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5cb500: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x5cb524: (17155972, 'OBJC_IVAR_$_World.client', 960),
        },
        classes={
                 0x5cb504: (15245304, 'OBJC_CLASS_$_NSString'),
                 0x5cb518: (15245420, 'OBJC_CLASS_$_TipManager'),
                 0x5cb530: (15245284, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(6074508, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6075724, 'adceq r4, sb, r0, asr sl')],
        calls=[(6074660, 'bl loc.imp.objc_msgSend'), (6074688, 'bl loc.imp.objc_msgSend'), (6074732, 'bl method.Vector.Vector_float__float__float__float_'), (6074808, 'bl loc.imp.objc_msgSend'), (6074984, 'blx lr'), (6075096, 'blx r2'), (6075168, 'blx r2'), (6075328, 'blx ip'), (6075372, 'blx r3'), (6075404, 'blx r3'), (6075528, 'blx ip'), (6075632, 'blx lr')],
        branches=[(6074840, 'bne', 6074884), (6074880, 'beq', 6075640), (6075032, 'beq', 6075108), (6075104, 'b', 6075176), (6075436, 'beq', 6075536), (6075532, 'b', 6075636), (6075636, 'b', 6075640)],
        semantics=('[World sendAndDisplayAirTimeTipWithDistance:] (imp 0x005cb08c, 305w): the air-time tip - stringWithFormat: text + TipManager displayTip:withTimeOut:displayEvenIfDisabled:tipColor: locally, then the dataUsingEncoding:/dataWithBytes:length: packet broadcast via sendNetworkData:toPeers:reliable: / sendDataToServer:reliable:; localPlayerName; constants 0xa (10) / 1.0f / 0x2d (45).\n'),
    ),
    dict(
        name='wp_02',
        method='World -[setPVPEnabled:displayNotifciation:]',
        types='v16@0:4c8c12',
        start=6075728,
        end=6076720,
        disasm='disasm_worldtileloader_wp_02.txt',
        base_add=6075744,
        base_literal=6076716,
        boundary='ARM.exidx end 0x005cb930 (listing bound); next ObjC IMP 0x005cb930 World -[sendSetPVPEnabledToServer:]',
        selectors={
                 0x5cb904: (15195544, 'instance'),
                 0x5cb908: (15197364, 'displayTip:withTimeOut:displayEvenIfDisabled:tipColor:'),
                 0x5cb914: (15195612, 'appendData:'),
                 0x5cb918: (15198104, 'dataUsingEncoding:'),
                 0x5cb91c: (15195552, 'dataWithBytes:length:'),
                 0x5cb924: (15195640, 'sendNetworkData:toPeers:reliable:'),
                 0x5cb928: (15195644, 'sendDataToServer:reliable:'),
        },
        imports={
                 0x5cb8f8: (16233032, '__CFConstantStringClassReference'),
                 0x5cb8fc: (16233048, '__CFConstantStringClassReference'),
                 0x5cb910: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5cb8ec: (17155936, 'OBJC_IVAR_$_World.pvpEnabled', 3268),
                 0x5cb8f0: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x5cb90c: (17155972, 'OBJC_IVAR_$_World.client', 960),
        },
        classes={
                 0x5cb900: (15245420, 'OBJC_CLASS_$_TipManager'),
                 0x5cb920: (15245284, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(6075728, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6076716, 'adceq r4, sb, ip, lsl 11')],
        calls=[(6075980, 'bl loc.imp.objc_msgSend'), (6076024, 'bl method.Vector.Vector_float__float__float__float_'), (6076100, 'bl loc.imp.objc_msgSend'), (6076324, 'blx r6'), (6076368, 'blx r3'), (6076400, 'blx r3'), (6076524, 'blx ip'), (6076628, 'blx lr')],
        branches=[(6075800, 'beq', 6076644), (6075844, 'beq', 6076640), (6076132, 'bne', 6076176), (6076172, 'beq', 6076636), (6076432, 'beq', 6076532), (6076528, 'b', 6076632), (6076632, 'b', 6076636), (6076636, 'b', 6076640), (6076640, 'b', 6076644)],
        semantics=('[World setPVPEnabled:displayNotifciation:] (imp 0x005cb550, 248w): the PVP toggle - updates pvpEnabled, shows the notification tip via TipManager displayTip:... (0xa/1.0f/0x2d) and broadcasts the state packet (NSMutableData + sendDataToServer:reliable: / sendNetworkData:toPeers:reliable:).\n'),
    ),
    dict(
        name='wp_03',
        method='World -[sendDamage:forNetBlockhead:recoil:]',
        types='v20@0:4f8@12c16',
        start=6068188,
        end=6069076,
        disasm='disasm_worldtileloader_wp_03.txt',
        base_add=6068204,
        base_literal=6069072,
        boundary='ARM.exidx end 0x005c9b54 (listing bound); next ObjC IMP 0x005c9b54 World -[remoteBlockheadDamageRequest:requestedByClientName:]',
        selectors={
                 0x5c9b28: (15195632, 'appendBytes:length:'),
                 0x5c9b2c: (15195552, 'dataWithBytes:length:'),
                 0x5c9b34: (15196300, 'uniqueID'),
                 0x5c9b3c: (15195640, 'sendNetworkData:toPeers:reliable:'),
                 0x5c9b40: (15196516, 'arrayWithObject:'),
                 0x5c9b44: (15196296, 'clientID'),
                 0x5c9b4c: (15195644, 'sendDataToServer:reliable:'),
        },
        imports={
                 0x5c9b24: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5c9b1c: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5c9b20: (17155916, 'OBJC_IVAR_$_World.server', 964),
        },
        classes={
                 0x5c9b30: (15245284, 'OBJC_CLASS_$_NSMutableData'),
                 0x5c9b48: (15245308, 'OBJC_CLASS_$_NSArray'),
        },
        instructions=[(6068188, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6069072, 'adceq r6, sb, r0, lsl 6')],
        calls=[(6068520, 'bl loc.imp.objc_msgSend'), (6068604, 'blx ip'), (6068648, 'blx ip'), (6068772, 'blx ip'), (6068924, 'blx r5'), (6068956, 'blx r3'), (6069004, 'blx lr')],
        branches=[(6068256, 'bpl', 6068264), (6068260, 'b', 6069012), (6068300, 'bne', 6068344), (6068340, 'beq', 6069012), (6068680, 'beq', 6068780), (6068776, 'b', 6069008), (6069008, 'b', 6069012)],
        semantics=('[World sendDamage:forNetBlockhead:recoil:] (imp 0x005c97dc, 222w): the damage sender - NSMutableData appendBytes:/dataWithBytes:length: packet with uniqueID/clientID (arrayWithObject:), routed server-side via sendNetworkData:toPeers:reliable: or client-side via sendDataToServer:reliable:; constants 0x10/0x2a (42).\n'),
    ),
    dict(
        name='wp_04',
        method='World -[fireProjectileFrom:to:at:fireItemType:firer:]',
        types='v36@0:4{Vector2=[2f]}8{Vector2=[2f]}16@24i28@32',
        start=6067068,
        end=6067952,
        disasm='disasm_worldtileloader_wp_04.txt',
        base_add=6067084,
        base_literal=6067948,
        boundary='ARM.exidx end 0x005c96f0 (listing bound); next ObjC IMP 0x005c96f0 World -[remoteProjectileRequest:]',
        selectors={
                 0x5c96cc: (15198076, 'fireProjectileFrom:to:at:fireItemType:firer:'),
                 0x5c96d8: (15195632, 'appendBytes:length:'),
                 0x5c96dc: (15195552, 'dataWithBytes:length:'),
                 0x5c96e4: (15195640, 'sendNetworkData:toPeers:reliable:'),
                 0x5c96e8: (15195644, 'sendDataToServer:reliable:'),
        },
        imports={
                 0x5c96d4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5c96c0: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5c96c4: (17156252, 'OBJC_IVAR_$_World.projectileManager', 3204),
                 0x5c96d0: (17155916, 'OBJC_IVAR_$_World.server', 964),
        },
        classes={
                 0x5c96e0: (15245284, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(6067068, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6067948, 'adceq r6, sb, r0, ror 14')],
        calls=[(6067308, 'bl loc.imp.objc_msgSend'), (6067388, 'bl method.Vector2.operator_float__'), (6067408, 'bl method.Vector2.operator_float__'), (6067428, 'bl method.Vector2.operator_float__'), (6067448, 'bl method.Vector2.operator_float__'), (6067616, 'blx ip'), (6067660, 'blx ip'), (6067784, 'blx ip'), (6067888, 'blx lr')],
        branches=[(6067340, 'bne', 6067384), (6067380, 'beq', 6067896), (6067692, 'beq', 6067792), (6067788, 'b', 6067892), (6067892, 'b', 6067896)],
        semantics=('[World fireProjectileFrom:to:at:fireItemType:firer:] (imp 0x005c937c, 221w): the projectile fire entry - Vector2 operator float* x4 reading the from/to/at vectors, packet build (dataWithBytes:length:) and send (sendNetworkData:toPeers:reliable: / sendDataToServer:reliable:); projectileManager ivar; constants 0x14 (20) / 0x29 (41).\n'),
    ),
    dict(
        name='wp_05',
        method='World -[remoteTipNotification:]',
        types='v12@0:4@8',
        start=6077072,
        end=6077488,
        disasm='disasm_worldtileloader_wp_05.txt',
        base_add=6077116,
        base_literal=6077448,
        boundary='ARM.exidx end 0x005cbc30 (listing bound); next ObjC IMP 0x005cbc30 World -[updateTradePricesIfNeeded]',
        selectors={
                 0x5cbc04: (15195652, 'length'),
                 0x5cbc0c: (15195656, 'getBytes:length:'),
                 0x5cbc14: (15195752, 'alloc'),
                 0x5cbc18: (15198116, 'initWithBytes:length:encoding:'),
                 0x5cbc1c: (15195860, 'autorelease'),
                 0x5cbc24: (15195544, 'instance'),
                 0x5cbc28: (15197364, 'displayTip:withTimeOut:displayEvenIfDisabled:tipColor:'),
        },
        imports={},
        ivars={},
        classes={
                 0x5cbc10: (15245304, 'OBJC_CLASS_$_NSString'),
                 0x5cbc20: (15245420, 'OBJC_CLASS_$_TipManager'),
        },
        instructions=[(6077072, 'push {r4, sl, fp, lr}'), (6077484, 'andeq r0, r0, r0')],
        calls=[(6077156, 'bl loc.imp.objc_msgSend'), (6077164, 'bl sym.imp.__wrap_malloc'), (6077208, 'bl loc.imp.objc_msgSend'), (6077232, 'bl loc.imp.objc_msgSend'), (6077268, 'bl loc.imp.objc_msgSend'), (6077284, 'bl loc.imp.objc_msgSend'), (6077312, 'bl loc.imp.objc_msgSend'), (6077356, 'bl method.Vector.Vector_float__float__float__float_'), (6077432, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[World remoteTipNotification:] (imp 0x005cba90, 104w): the tip receiver - getBytes:length: + initWithBytes:length:encoding: (__wrap_malloc buffer) then TipManager displayTip:withTimeOut:displayEvenIfDisabled:tipColor:; 0xa/1.0f.\n'),
    ),
    dict(
        name='wp_06',
        method='World -[sendSetPVPEnabledToServer:]',
        types='v12@0:4c8',
        start=6076720,
        end=6077072,
        disasm='disasm_worldtileloader_wp_06.txt',
        base_add=6076736,
        base_literal=6077068,
        boundary='ARM.exidx end 0x005cba90 (listing bound); next ObjC IMP 0x005cba90 World -[remoteTipNotification:]',
        selectors={
                 0x5cba84: (15198112, 'setPVPEnabled:displayNotifciation:'),
                 0x5cba88: (15198108, 'sendChatMessage:sendToClients:'),
        },
        imports={
                 0x5cba74: (16233064, '__CFConstantStringClassReference'),
                 0x5cba78: (16233080, '__CFConstantStringClassReference'),
                 0x5cba80: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5cba70: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5cba7c: (17155916, 'OBJC_IVAR_$_World.server', 964),
        },
        classes={},
        instructions=[(6076720, 'push {r4, r5, fp, lr}'), (6077068, 'adceq r4, sb, ip, lsr 3')],
        calls=[(6076908, 'blx ip'), (6077024, 'blx ip')],
        branches=[(6076832, 'beq', 6076916), (6076912, 'b', 6077032), (6076952, 'beq', 6077028), (6077028, 'b', 6077032)],
        semantics=('[World sendSetPVPEnabledToServer:] (imp 0x005cb930, 88w): the client-side PVP toggle - forwards setPVPEnabled:displayNotifciation: through the server and announces via sendChatMessage:sendToClients:.\n'),
    ),
    dict(
        name='wp_07',
        method='World -[remoteProjectileRequest:]',
        types='v12@0:4@8',
        start=6067952,
        end=6068188,
        disasm='disasm_worldtileloader_wp_07.txt',
        base_add=6067984,
        base_literal=6068176,
        boundary='ARM.exidx end 0x005c97dc (listing bound); next ObjC IMP 0x005c97dc World -[sendDamage:forNetBlockhead:recoil:]',
        selectors={
                 0x5c97cc: (15195656, 'getBytes:length:'),
                 0x5c97d8: (15198076, 'fireProjectileFrom:to:at:fireItemType:firer:'),
        },
        imports={},
        ivars={
                 0x5c97d4: (17156252, 'OBJC_IVAR_$_World.projectileManager', 3204),
        },
        classes={},
        instructions=[(6067952, 'push {r4, r5, fp, lr}'), (6068184, 'invalid')],
        calls=[(6068028, 'bl loc.imp.objc_msgSend'), (6068076, 'bl method.Vector2.Vector2_float__float_'), (6068092, 'bl method.Vector2.Vector2_float__float_'), (6068160, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[World remoteProjectileRequest:] (imp 0x005c96f0, 59w): the projectile request intake - getBytes:length: decode into two Vector2s (ctor x2) and the fireProjectileFrom:to:at:fireItemType:firer: call into projectileManager.\n'),
    ),
    dict(
        name='wp_08',
        method='World -[currentTipText]',
        types='@8@0:4',
        start=6035892,
        end=6036312,
        disasm='disasm_worldtileloader_wp_08.txt',
        base_add=6035908,
        base_literal=6036308,
        boundary='ARM.exidx end 0x005c1b58 (listing bound); next ObjC IMP 0x005c1b58 World -[currentTipColor]',
        selectors={
                 0x5c1b38: (15197816, 'currentTip'),
                 0x5c1b3c: (15195544, 'instance'),
                 0x5c1b44: (15197820, 'currentTipText'),
                 0x5c1b48: (15196444, 'activeBlockhead'),
        },
        imports={
                 0x5c1b34: (17151904, 'objc_msgSend'),
                 0x5c1b50: (16232792, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5c1b30: (17156648, 'OBJC_IVAR_$_World.repairMode', 3413),
                 0x5c1b4c: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={
                 0x5c1b40: (15245420, 'OBJC_CLASS_$_TipManager'),
        },
        instructions=[(6035892, 'push {r4, r5, fp, lr}'), (6036308, 'adceq lr, sb, r8, lsr 2')],
        calls=[(6036056, 'blx lr'), (6036072, 'blx r2'), (6036200, 'blx lr'), (6036216, 'blx r2')],
        branches=[(6035952, 'beq', 6035976), (6035972, 'b', 6036260), (6036092, 'beq', 6036108), (6036104, 'b', 6036260), (6036236, 'beq', 6036252), (6036248, 'b', 6036260)],
        semantics=('[World currentTipText] (imp 0x005c19b4, 105w): the tip-text getter - repairMode branch + TipManager currentTip + activeBlockhead.\n'),
    ),
    dict(
        name='wp_09',
        method='World -[currentTipColor]',
        types='{Vector=[4f]}8@0:4',
        start=6036312,
        end=6036688,
        disasm='disasm_worldtileloader_wp_09.txt',
        base_add=6036328,
        base_literal=6036684,
        boundary='ARM.exidx end 0x005c1cd0 (listing bound); next ObjC IMP 0x005c1cd0 World -[abortInProgressPathIfForBlockhead:]',
        selectors={
                 0x5c1cbc: (15197816, 'currentTip'),
                 0x5c1cc0: (15195544, 'instance'),
                 0x5c1cc8: (15197824, 'tipColor'),
        },
        imports={
                 0x5c1cb8: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0x5c1cc4: (15245420, 'OBJC_CLASS_$_TipManager'),
        },
        instructions=[(6036312, 'push {r4, r5, r6, r7, fp, lr}'), (6036684, 'adceq sp, sb, r4, lsl 31')],
        calls=[(6036416, 'blx lr'), (6036432, 'blx r2'), (6036520, 'blx r3'), (6036564, 'bl loc.imp.objc_msgSend_stret'), (6036600, 'bl sym.imp.memset'), (6036648, 'bl method.Vector.Vector_float__float__float__float_')],
        branches=[(6036452, 'beq', 6036608), (6036548, 'beq', 6036572), (6036568, 'b', 6036604), (6036604, 'b', 6036656)],
        semantics=('[World currentTipColor] (imp 0x005c1b58, 94w): the tip-color getter - TipManager tipColor via stret (memset + Vector ctor); constant 0x10.\n'),
    ),
    dict(
        name='wp_10',
        method='World -[pvpEnabled]',
        types='c8@0:4',
        start=6091572,
        end=6091632,
        disasm='disasm_worldtileloader_wp_10.txt',
        base_add=6091580,
        base_literal=6091628,
        boundary='ARM.exidx end 0x005cf370 (listing bound); next ObjC IMP 0x005cf370 World -[welcomeMessageDictRecieved:fromClient:]',
        selectors={},
        imports={},
        ivars={
                 0x5cf368: (17155936, 'OBJC_IVAR_$_World.pvpEnabled', 3268),
        },
        classes={},
        instructions=[(6091572, 'sub sp, sp, 8'), (6091628, 'invalid')],
        calls=[],
        branches=[],
        semantics=('[World pvpEnabled] (imp 0x005cf334, 15w): bare ivar getter.\n'),
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
        'batch': 'World PVP, projectile and tips line (E112): the damage, projectile and notification family; 11 bodies',
        'claim': ('a fully-read static map of the World PVP/projectile/tips line; the TipManager / blockhead sufferDamage: contracts and the wire field layouts are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'world_pvp.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale world_pvp.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
