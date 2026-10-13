#!/usr/bin/env python3
"""Hash-gated recovery of the World administration and moderation line (E109).

The World admin/moderation line: the custom-rules sync loop, the
BlockAlertView kick/ban/report alerts and the per-save mute list:
9 bodies, 2575 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/WORLD_ADMIN.md for the prose and boundaries.
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
    'bl 0x559f78': 0x00559f78,
    'bl 0x5d7794': 0x005d7794,
    'bl sym.imp.NSLog': 0x001c2a5c,
    'bl sym.imp.NSSearchPathForDirectoriesInDomains': 0x001c3f20,
    'bl sym.imp.__stack_chk_fail': 0x001c28b8,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
}

SPECS = [
    dict(
        name='wa_00',
        method='World -[verifyClientCustomRulesData:]',
        types='c12@0:4@8',
        start=6123700,
        end=6125460,
        disasm='disasm_worldtileloader_wa_00.txt',
        base_add=6123716,
        base_literal=6125456,
        boundary='ARM.exidx end 0x005d7794 (listing bound); next ObjC IMP 0x005d790c World -[timeCrystalCloseButtonTapped]',
        selectors={
                 0x5d7774: (15196836, 'gzipInflate'),
                 0x5d777c: (15195652, 'length'),
                 0x5d7788: (15195656, 'getBytes:length:'),
        },
        imports={
                 0x5d7770: (17151904, 'objc_msgSend'),
                 0x5d7778: (17151968, '__stack_chk_guard'),
        },
        ivars={
                 0x5d7780: (17155896, 'OBJC_IVAR_$_World.expertMode', 228),
                 0x5d7784: (17156060, 'OBJC_IVAR_$_World.customRules', 160),
        },
        classes={},
        instructions=[(6123700, 'push {r4, r5, fp, lr}'), (6125456, 'adceq r8, r8, r8, lsr 20')],
        calls=[(6123784, 'blx lr'), (6123848, 'blx r2'), (6123908, 'bl 0x5d7794'), (6123980, 'blx r3'), (6124116, 'blx lr'), (6125420, 'bl sym.imp.__stack_chk_fail')],
        branches=[(6123804, 'beq', 6123860), (6123856, 'bne', 6123872), (6123868, 'b', 6125368), (6124008, 'bhs', 6124024), (6124020, 'b', 6124032), (6124148, 'beq', 6124164), (6124160, 'b', 6125368), (6124200, 'beq', 6124216), (6124212, 'b', 6125368), (6124252, 'beq', 6124268), (6124264, 'b', 6125368), (6124304, 'beq', 6124320), (6124316, 'b', 6125368), (6124356, 'beq', 6124372), (6124368, 'b', 6125368), (6124408, 'beq', 6124424), (6124420, 'b', 6125368), (6124460, 'beq', 6124476), (6124472, 'b', 6125368), (6124512, 'beq', 6124528), (6124524, 'b', 6125368), (6124564, 'beq', 6124580), (6124576, 'b', 6125368), (6124616, 'beq', 6124632), (6124628, 'b', 6125368), (6124668, 'beq', 6124684), (6124680, 'b', 6125368), (6124720, 'beq', 6124736), (6124732, 'b', 6125368), (6124772, 'beq', 6124788), (6124784, 'b', 6125368), (6124824, 'beq', 6124840), (6124836, 'b', 6125368), (6124876, 'beq', 6124892), (6124888, 'b', 6125368), (6124928, 'beq', 6124944), (6124940, 'b', 6125368), (6124980, 'beq', 6124996), (6124992, 'b', 6125368), (6125032, 'beq', 6125048), (6125044, 'b', 6125368), (6125084, 'beq', 6125100), (6125096, 'b', 6125368), (6125136, 'beq', 6125152), (6125148, 'b', 6125368), (6125172, 'bge', 6125360), (6125240, 'beq', 6125256), (6125252, 'b', 6125368), (6125324, 'beq', 6125340), (6125336, 'b', 6125368), (6125340, 'b', 6125344), (6125356, 'b', 6125164), (6125400, 'bne', 6125420)],
        semantics=('[World verifyClientCustomRulesData:] (imp 0x005d70b4, 440w): the custom-rules payload verifier - gzipInflate + length/getBytes:length: decode of the client payload applied under the expertMode gate (customRules); a long chain of early-out guards (nine bailouts to 0x5d7738); helper 0x5d7794; stack-check pair; constant 0x40.\n'),
    ),
    dict(
        name='wa_01',
        method='World -[customRuleDictRecievedFromNet:]',
        types='v12@0:4@8',
        start=6118160,
        end=6119296,
        disasm='disasm_worldtileloader_wa_01.txt',
        base_add=6118176,
        base_literal=6119292,
        boundary='ARM.exidx end 0x005d5f80 (listing bound); next ObjC IMP 0x005d5f80 World -[setCustomSlotAtIndex:toItemType:count:]',
        selectors={
                 0x5d5f4c: (15195620, 'countByEnumeratingWithState:objects:count:'),
                 0x5d5f58: (15196476, 'isEqualToString:'),
                 0x5d5f5c: (15195584, 'setObject:forKey:'),
                 0x5d5f60: (15195624, 'objectForKey:'),
                 0x5d5f68: (15198340, 'arrayWithArray:'),
                 0x5d5f70: (15195824, 'customRulesChanged'),
        },
        imports={
                 0x5d5f48: (17151904, 'objc_msgSend'),
                 0x5d5f50: (17151968, '__stack_chk_guard'),
                 0x5d5f54: (16233864, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5d5f64: (17155952, 'OBJC_IVAR_$_World.customRulesDict', 224),
                 0x5d5f74: (17155896, 'OBJC_IVAR_$_World.expertMode', 228),
                 0x5d5f78: (17156060, 'OBJC_IVAR_$_World.customRules', 160),
        },
        classes={
                 0x5d5f6c: (15245300, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(6118160, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6119292, 'adceq sb, r8, ip, asr 31')],
        calls=[(6118280, 'bl sym.imp.memset'), (6118328, 'blx lr'), (6118428, 'bl sym.imp.objc_enumerationMutation'), (6118520, 'blx lr'), (6118652, 'blx r5'), (6118684, 'blx r3'), (6118732, 'blx lr'), (6118836, 'blx ip'), (6118884, 'blx ip'), (6118988, 'blx ip'), (6119116, 'bl 0x559f78'), (6119184, 'bl sym.imp.memcpy'), (6119204, 'blx r2'), (6119236, 'bl sym.imp.__stack_chk_fail')],
        branches=[(6118340, 'beq', 6119012), (6118420, 'beq', 6118432), (6118532, 'beq', 6118740), (6118736, 'b', 6118888), (6118888, 'b', 6118892), (6118916, 'blo', 6118384), (6119008, 'bne', 6118384), (6119012, 'b', 6119016), (6119224, 'bne', 6119236)],
        semantics=('[World customRuleDictRecievedFromNet:] (imp 0x005d5b10, 284w): the custom-rules intake - fast enumeration + objc_enumerationMutation over the received dictionary, isEqualToString:/setObject:forKey: key merge into customRulesDict, arrayWithArray: copy (memcpy) and the customRulesChanged notification behind the expertMode gate; helper 0x559f78; constants 0x10/0x20/0x40.\n'),
    ),
    dict(
        name='wa_02',
        method='World -[setCustomRule:forOptionNamed:]',
        types='v16@0:4@8@12',
        start=6117136,
        end=6118160,
        disasm='disasm_worldtileloader_wa_02.txt',
        base_add=6117152,
        base_literal=6118156,
        boundary='ARM.exidx end 0x005d5b10 (listing bound); next ObjC IMP 0x005d5b10 World -[customRuleDictRecievedFromNet:]',
        selectors={
                 0x5d5ae0: (15195584, 'setObject:forKey:'),
                 0x5d5ae4: (15195644, 'sendDataToServer:reliable:'),
                 0x5d5ae8: (15195612, 'appendData:'),
                 0x5d5aec: (15195608, 'gzipDeflate'),
                 0x5d5af0: (15196864, 'dataWithPropertyList:format:options:error:'),
                 0x5d5af8: (15195580, 'dictionaryWithObjectsAndKeys:'),
                 0x5d5b00: (15195552, 'dataWithBytes:length:'),
                 0x5d5b08: (15195824, 'customRulesChanged'),
        },
        imports={
                 0x5d5ac8: (17151968, '__stack_chk_guard'),
                 0x5d5adc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5d5ac4: (17156328, 'OBJC_IVAR_$_World.isAdmin', 3209),
                 0x5d5acc: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5d5ad0: (17155896, 'OBJC_IVAR_$_World.expertMode', 228),
                 0x5d5ad4: (17155952, 'OBJC_IVAR_$_World.customRulesDict', 224),
                 0x5d5ad8: (17156060, 'OBJC_IVAR_$_World.customRules', 160),
        },
        classes={
                 0x5d5af4: (15245468, 'OBJC_CLASS_$_NSPropertyListSerialization'),
                 0x5d5afc: (15245328, 'OBJC_CLASS_$_NSDictionary'),
                 0x5d5b04: (15245284, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(6117136, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6118156, 'adceq sl, r8, ip, asr 7')],
        calls=[(6117320, 'blx ip'), (6117404, 'bl 0x559f78'), (6117452, 'bl sym.imp.memcpy'), (6117796, 'blx ip'), (6117848, 'blx r4'), (6117904, 'blx lr'), (6117920, 'blx r2'), (6117948, 'blx r3'), (6117996, 'blx lr'), (6118040, 'blx r2'), (6118080, 'bl sym.imp.__stack_chk_fail')],
        branches=[(6117220, 'beq', 6118044), (6117484, 'beq', 6118000), (6117500, 'beq', 6118000), (6117516, 'beq', 6118000), (6118068, 'bne', 6118080)],
        semantics=('[World setCustomRule:forOptionNamed:] (imp 0x005d5710, 256w): the admin rule setter - dictionaryWithObjectsAndKeys: + NSPropertyListSerialization dataWithPropertyList:format:options:error: (plist serialize), gzipDeflate + appendData:/dataWithBytes:length: packing and sendDataToServer:reliable:; local apply + customRulesChanged behind the isAdmin/client gate (expertMode); constants 0x40/0x64/0x42.\n'),
    ),
    dict(
        name='wa_03',
        method='World -[kickOrBanPlayerFromButtonIsBan:withName:]',
        types='v16@0:4c8@12',
        start=6095888,
        end=6097100,
        disasm='disasm_worldtileloader_wa_03.txt',
        base_add=6095904,
        base_literal=6097096,
        boundary='ARM.exidx end 0x005d08cc (listing bound); next ObjC IMP 0x005d0c5c World -[banPlayerWithNameFromPlayerButton:]',
        selectors={
                 0x5d0870: (15198252, 'show'),
                 0x5d0874: (15198248, 'setDestructiveButtonWithTitle:block:'),
                 0x5d0878: (17111424, 'ELF'),
                 0x5d088c: (15195708, 'stringWithFormat:'),
                 0x5d0890: (15198232, 'uppercaseString'),
                 0x5d089c: (15198240, 'setCancelButtonWithTitle:block:'),
                 0x5d08a0: (17111392, 'ELF'),
                 0x5d08a8: (15198236, 'initWithTitle:message:'),
                 0x5d08b4: (15195752, 'alloc'),
                 0x5d08bc: (15196464, 'pauseButtonTapped'),
        },
        imports={
                 0x5d086c: (17151904, 'objc_msgSend'),
                 0x5d0884: (17151928, '_NSConcreteStackBlock'),
                 0x5d0888: (16231496, '__CFConstantStringClassReference'),
                 0x5d0898: (16233384, '__CFConstantStringClassReference'),
                 0x5d08ac: (16233368, '__CFConstantStringClassReference'),
                 0x5d08b0: (16233352, '__CFConstantStringClassReference'),
                 0x5d08c0: (16233320, '__CFConstantStringClassReference'),
                 0x5d08c4: (16233336, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5d0868: (17156744, 'OBJC_IVAR_$_World.kickbanAlertView', 3428),
        },
        classes={
                 0x5d0894: (15245304, 'OBJC_CLASS_$_NSString'),
                 0x5d08b8: (15245532, 'OBJC_CLASS_$_BlockAlertView'),
        },
        instructions=[(6095888, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6097096, 'adceq pc, r8, ip, asr 13')],
        calls=[(6096432, 'blx r2'), (6096464, 'blx r3'), (6096504, 'blx lr'), (6096552, 'blx ip'), (6096596, 'blx lr'), (6096632, 'blx ip'), (6096744, 'blx r5'), (6096792, 'blx r2'), (6096836, 'blx lr'), (6096952, 'blx r6'), (6096988, 'blx r3')],
        branches=[(6095960, 'bne', 6096992)],
        semantics=('[World kickOrBanPlayerFromButtonIsBan:withName:] (imp 0x005d0410, 303w): the kick/ban confirmation - BlockAlertView initWithTitle:message: + setDestructiveButtonWithTitle:block: + setCancelButtonWithTitle:block: (two _NSConcreteStackBlock literals), uppercaseString + stringWithFormat: title build; kickbanAlertView slot.\n'),
    ),
    dict(
        name='wa_04',
        method='World -[setPlayerMuted:withID:]',
        types='v16@0:4c8@12',
        start=6094500,
        end=6095148,
        disasm='disasm_worldtileloader_wa_04.txt',
        base_add=6094516,
        base_literal=6095144,
        boundary='ARM.exidx end 0x005d012c (listing bound); next ObjC IMP 0x005d0410 World -[kickOrBanPlayerFromButtonIsBan:withName:]',
        selectors={
                 0x5d00f4: (15198216, 'initMuteList'),
                 0x5d00f8: (15198224, 'removeObject:'),
                 0x5d0100: (15198220, 'containsObject:'),
                 0x5d0104: (15195700, 'addObject:'),
                 0x5d0108: (15197220, 'addOperationWithBlock:'),
                 0x5d010c: (17111360, 'ELF'),
                 0x5d0120: (15198228, 'userMuteChanged:'),
        },
        imports={
                 0x5d00f0: (17151904, 'objc_msgSend'),
                 0x5d0118: (17151928, '_NSConcreteStackBlock'),
        },
        ivars={
                 0x5d00fc: (17156356, 'OBJC_IVAR_$_World.mutedPlayers', 3284),
                 0x5d011c: (17156308, 'OBJC_IVAR_$_World.saveQueue', 3188),
                 0x5d0124: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={},
        instructions=[(6094500, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6095144, 'adceq pc, r8, r8, lsr ip')],
        calls=[(6094564, 'blx lr'), (6094648, 'blx r3'), (6094732, 'blx r3'), (6094808, 'blx r3'), (6094984, 'blx sl'), (6095076, 'blx r5')],
        branches=[(6094576, 'beq', 6094740), (6094660, 'bne', 6094736), (6094736, 'b', 6094812)],
        semantics=('[World setPlayerMuted:withID:] (imp 0x005cfea4, 162w): the mute toggle - initMuteList lazy init, containsObject:/addObject:/removeObject: on mutedPlayers, then the saveQueue addOperationWithBlock: persist and the userMuteChanged: notification.\n'),
    ),
    dict(
        name='wa_05',
        method='World -[initMuteList]',
        types='v8@0:4',
        start=6093448,
        end=6094336,
        disasm='disasm_worldtileloader_wa_05.txt',
        base_add=6093464,
        base_literal=6094332,
        boundary='ARM.exidx end 0x005cfe00 (listing bound); next ObjC IMP 0x005cfe00 World -[playerIsMuted:]',
        selectors={
                 0x5cfdcc: (15195704, 'localPlayerID'),
                 0x5cfdd0: (15195812, 'dataWithContentsOfFile:'),
                 0x5cfddc: (15195708, 'stringWithFormat:'),
                 0x5cfde4: (15195800, 'objectAtIndex:'),
                 0x5cfdec: (15198212, 'initWithArray:'),
                 0x5cfdf0: (15195752, 'alloc'),
                 0x5cfdf8: (15195892, 'init'),
        },
        imports={
                 0x5cfdc4: (16229608, '__CFConstantStringClassReference'),
                 0x5cfdc8: (17151904, 'objc_msgSend'),
                 0x5cfdd8: (16233304, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5cfdbc: (17156356, 'OBJC_IVAR_$_World.mutedPlayers', 3284),
                 0x5cfdc0: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5cfde0: (17155900, 'OBJC_IVAR_$_World.saveID', 436),
        },
        classes={
                 0x5cfdd4: (15245320, 'OBJC_CLASS_$_NSData'),
                 0x5cfde8: (15245304, 'OBJC_CLASS_$_NSString'),
                 0x5cfdf4: (15245300, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(6093448, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6094332, 'adceq r0, sb, r4, asr r0')],
        calls=[(6093628, 'blx r2'), (6093672, 'bl sym.imp.NSSearchPathForDirectoriesInDomains'), (6093804, 'blx r3'), (6093896, 'blx r6'), (6093936, 'blx ip'), (6093964, 'bl 0x559f54'), (6094060, 'blx r2'), (6094080, 'blx r3'), (6094220, 'blx r2'), (6094236, 'blx r2')],
        branches=[(6093512, 'bne', 6094112), (6093564, 'beq', 6093636), (6093956, 'beq', 6094108), (6093984, 'beq', 6094104), (6094104, 'b', 6094108), (6094108, 'b', 6094112), (6094148, 'bne', 6094260)],
        semantics=('[World initMuteList] (imp 0x005cfa88, 222w): the mute-list loader - path via NSSearchPathForDirectoriesInDomains + stringWithFormat: (saveID/client scoped), dataWithContentsOfFile: + initWithArray: into mutedPlayers; helper 0x559f54; constant 0xe.\n'),
    ),
    dict(
        name='wa_06',
        method='World -[reportUserWithName:reporterName:reporterMessage:reportedAvatarImagePath:]',
        types='v24@0:4@8@12@16@20',
        start=6098516,
        end=6099928,
        disasm='disasm_worldtileloader_wa_06.txt',
        base_add=6098532,
        base_literal=6099924,
        boundary='ARM.exidx end 0x005d13d8 (listing bound); next ObjC IMP 0x005d13d8 World -[newServerPasswordSet:]',
        selectors={
                 0x5d1378: (15195740, 'isCloudMatch'),
                 0x5d137c: (15198100, 'localPlayerName'),
                 0x5d138c: (15195652, 'length'),
                 0x5d1394: (15195708, 'stringWithFormat:'),
                 0x5d13a8: (15198260, 'stringByReplacingOccurrencesOfString:withString:'),
                 0x5d13b0: (15195584, 'setObject:forKey:'),
                 0x5d13b4: (15195684, 'dictionary'),
                 0x5d13bc: (15195552, 'dataWithBytes:length:'),
                 0x5d13c8: (15195644, 'sendDataToServer:reliable:'),
                 0x5d13cc: (15195612, 'appendData:'),
                 0x5d13d0: (15195608, 'gzipDeflate'),
        },
        imports={
                 0x5d1374: (17151904, 'objc_msgSend'),
                 0x5d1380: (16233528, '__CFConstantStringClassReference'),
                 0x5d1384: (16233480, '__CFConstantStringClassReference'),
                 0x5d1388: (16231704, '__CFConstantStringClassReference'),
                 0x5d1390: (16233448, '__CFConstantStringClassReference'),
                 0x5d139c: (16233464, '__CFConstantStringClassReference'),
                 0x5d13a0: (16233496, '__CFConstantStringClassReference'),
                 0x5d13a4: (16233512, '__CFConstantStringClassReference'),
                 0x5d13ac: (16233416, '__CFConstantStringClassReference'),
                 0x5d13c4: (16233432, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5d136c: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5d1370: (17155916, 'OBJC_IVAR_$_World.server', 964),
        },
        classes={
                 0x5d1398: (15245304, 'OBJC_CLASS_$_NSString'),
                 0x5d13b8: (15245288, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x5d13c0: (15245284, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(6098516, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6099924, 'adceq lr, r8, r8, lsl 25')],
        calls=[(6098756, 'blx r7'), (6098792, 'blx r3'), (6098836, 'blx ip'), (6098920, 'blx ip'), (6098928, 'bl 0x55468c'), (6099020, 'blx r2'), (6099048, 'blx r3'), (6099096, 'blx lr'), (6099204, 'blx r2'), (6099292, 'blx r2'), (6099380, 'blx ip'), (6099484, 'blx r2'), (6099584, 'blx r4'), (6099640, 'bl sym.imp.NSLog'), (6099744, 'blx r2'), (6099800, 'bl sym.imp.NSLog')],
        branches=[(6098604, 'beq', 6099104), (6098852, 'beq', 6098924), (6099100, 'b', 6099812), (6099140, 'beq', 6099808), (6099216, 'beq', 6099648), (6099248, 'beq', 6099388), (6099300, 'bls', 6099388), (6099408, 'beq', 6099424), (6099420, 'b', 6099492), (6099644, 'b', 6099804), (6099668, 'beq', 6099684), (6099680, 'b', 6099752), (6099804, 'b', 6099808), (6099808, 'b', 6099812)],
        semantics=('[World reportUserWithName:reporterName:reporterMessage:reportedAvatarImagePath:] (imp 0x005d0e54, 353w): the abuse-report sender - builds the payload dictionary (localPlayerName + stringByReplacingOccurrencesOfString:withString: sanitize + isCloudMatch branch), NSMutableData appendData:/dataWithBytes:length: + gzipDeflate packing and sendDataToServer:reliable:; NSLog x2; helper 0x55468c; constant 0x37 (55).\n'),
    ),
    dict(
        name='wa_07',
        method='World -[reportButtonTappedForPlayer:]',
        types='v12@0:4@8',
        start=6103436,
        end=6104392,
        disasm='disasm_worldtileloader_wa_07.txt',
        base_add=6103452,
        base_literal=6104388,
        boundary='ARM.exidx end 0x005d2548 (listing bound); next ObjC IMP 0x005d2ab8 World -[canAddWorldCredit]',
        selectors={
                 0x5d24f4: (15198252, 'show'),
                 0x5d24fc: (15198248, 'setDestructiveButtonWithTitle:block:'),
                 0x5d2500: (17111520, 'ELF'),
                 0x5d2514: (15198240, 'setCancelButtonWithTitle:block:'),
                 0x5d2518: (17111488, 'ELF'),
                 0x5d2528: (15198236, 'initWithTitle:message:'),
                 0x5d252c: (15195752, 'alloc'),
                 0x5d2534: (15196464, 'pauseButtonTapped'),
                 0x5d253c: (15195732, 'retain'),
                 0x5d2540: (15195768, 'release'),
        },
        imports={
                 0x5d24f0: (17151904, 'objc_msgSend'),
                 0x5d24f8: (16233688, '__CFConstantStringClassReference'),
                 0x5d250c: (17151928, '_NSConcreteStackBlock'),
                 0x5d2510: (16233384, '__CFConstantStringClassReference'),
                 0x5d2520: (16233640, '__CFConstantStringClassReference'),
                 0x5d2524: (16233672, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5d24ec: (17156348, 'OBJC_IVAR_$_World.reportAlertView', 3424),
                 0x5d2538: (17156392, 'OBJC_IVAR_$_World.reportedPlayerName', 3432),
        },
        classes={
                 0x5d2530: (15245532, 'OBJC_CLASS_$_BlockAlertView'),
        },
        instructions=[(6103436, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6104388, 'adceq sp, r8, r0, asr sb')],
        calls=[(6103928, 'blx r2'), (6103948, 'blx r2'), (6103988, 'blx r3'), (6104020, 'blx r3'), (6104044, 'blx ip'), (6104156, 'blx r5'), (6104252, 'blx r5'), (6104288, 'blx r3')],
        branches=[(6103504, 'bne', 6104292)],
        semantics=('[World reportButtonTappedForPlayer:] (imp 0x005d218c, 239w): the report button - BlockAlertView destructive/cancel block pair with the reportedPlayerName capture; reportAlertView slot.\n'),
    ),
    dict(
        name='wa_08',
        method='World -[alertView:didDismissWithButtonIndex:]',
        types='v16@0:4@8i12',
        start=6101668,
        end=6102932,
        disasm='disasm_worldtileloader_wa_08.txt',
        base_add=6101684,
        base_literal=6102928,
        boundary='ARM.exidx end 0x005d1f94 (listing bound); next ObjC IMP 0x005d2098 World -[textFieldShouldReturn:]',
        selectors={
                 0x5d1f40: (15198272, 'reportUserWithName:reporterName:reporterMessage:reportedAvatarImagePath:'),
                 0x5d1f48: (15198268, 'text'),
                 0x5d1f4c: (15196216, 'textFieldAtIndex:'),
                 0x5d1f50: (15198252, 'show'),
                 0x5d1f58: (15198276, 'addButtonWithTitle:block:'),
                 0x5d1f5c: (17111456, 'ELF'),
                 0x5d1f70: (15198236, 'initWithTitle:message:'),
                 0x5d1f74: (15195752, 'alloc'),
                 0x5d1f80: (15195708, 'stringWithFormat:'),
                 0x5d1f88: (15195860, 'autorelease'),
                 0x5d1f8c: (15196220, 'setDelegate:'),
        },
        imports={
                 0x5d1f3c: (17151904, 'objc_msgSend'),
                 0x5d1f54: (16233656, '__CFConstantStringClassReference'),
                 0x5d1f68: (17151928, '_NSConcreteStackBlock'),
                 0x5d1f6c: (16233640, '__CFConstantStringClassReference'),
                 0x5d1f7c: (16233624, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5d1f34: (17156396, 'OBJC_IVAR_$_World.messageEntryAlertView', 3436),
                 0x5d1f38: (17156348, 'OBJC_IVAR_$_World.reportAlertView', 3424),
                 0x5d1f44: (17156392, 'OBJC_IVAR_$_World.reportedPlayerName', 3432),
        },
        classes={
                 0x5d1f78: (15245532, 'OBJC_CLASS_$_BlockAlertView'),
                 0x5d1f84: (15245304, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(6101668, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6102928, 'adceq lr, r8, r8, lsr r0')],
        calls=[(6101888, 'blx r3'), (6101912, 'blx r2'), (6101988, 'blx r4'), (6102372, 'blx ip'), (6102408, 'blx r3'), (6102432, 'blx ip'), (6102544, 'blx r5'), (6102580, 'blx r3'), (6102700, 'blx r3'), (6102720, 'blx r3'), (6102760, 'blx r3'), (6102796, 'blx r3')],
        branches=[(6101740, 'bne', 6102828), (6101752, 'bne', 6102588), (6102020, 'bne', 6102584), (6102584, 'b', 6102588)],
        semantics=('[World alertView:didDismissWithButtonIndex:] (imp 0x005d1aa4, 316w): the alert router - handles the message-entry textFieldAtIndex:/text and calls reportUserWithName:reporterName:reporterMessage:reportedAvatarImagePath:, rebuilding the confirm alert (addButtonWithTitle:block: + setDelegate:); messageEntryAlertView/reportAlertView/reportedPlayerName slots.\n'),
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
        'batch': 'World administration and moderation line (E109): custom rules, kick/ban, mute list and the report flow; 9 bodies',
        'claim': ('a fully-read static map of the World admin/moderation line; the BlockAlertView / NSPropertyListSerialization contracts and the server-side moderation endpoints are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'world_admin.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale world_admin.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
