#!/usr/bin/env python3
"""Hash-gated recovery of the World closure sweep part 2 (E115).

The World accessor tail: the bare getters/setters, the struct copiers
and the boolean -UIDisplayed flag reads that close the class:
72 bodies, 1204 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/WORLD_CLOSE2.md for the prose and boundaries.
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
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.objc_copyStruct': 0x001c2888,
}

SPECS = [
    dict(
        name='wy_00',
        method='World -[pinchScale]',
        types='d8@0:4',
        start=6136536,
        end=6136636,
        disasm='disasm_worldtileloader_wy_00.txt',
        base_add=6136568,
        base_literal=6136632,
        boundary='ARM.exidx end 0x005da33c (listing bound); next ObjC IMP 0x005da33c World -[setPinchScale:]',
        selectors={},
        imports={},
        ivars={
                 0x5da334: (17155872, 'OBJC_IVAR_$_World.pinchScale', 400),
        },
        classes={},
        instructions=[(6136536, 'push {fp, lr}'), (6136632, 'invalid')],
        calls=[(6136608, 'bl sym.imp.objc_copyStruct')],
        branches=[],
        semantics=('[World -[pinchScale]] (imp 0x005da2d8, 25w): 8-byte struct getter - objc_copyStruct into the pinchScale pair.\n'),
    ),
    dict(
        name='wy_01',
        method='World -[stopFollowingOrTranslatingToGoal]',
        types='v8@0:4',
        start=6020668,
        end=6020764,
        disasm='disasm_worldtileloader_wy_01.txt',
        base_add=6020680,
        base_literal=6020760,
        boundary='ARM.exidx end 0x005bde9c (listing bound); next ObjC IMP 0x005bde9c World -[updateIdleTimerDisabled]',
        selectors={},
        imports={},
        ivars={
                 0x5bde90: (17156484, 'OBJC_IVAR_$_World.followingBlockhead', 3345),
                 0x5bde94: (17156488, 'OBJC_IVAR_$_World.translatingToGoal', 640),
        },
        classes={},
        instructions=[(6020668, 'push {fp, lr}'), (6020760, 'adceq r1, sl, r4, lsr 25')],
        calls=[],
        branches=[],
        semantics=('[World -[stopFollowingOrTranslatingToGoal]] (imp 0x005bde3c, 24w): clears the follow/translate state pair (followingBlockhead + translatingToGoal written off).\n'),
    ),
    dict(
        name='wy_02',
        method='World -[dayColor]',
        types='{Vector=[4f]}8@0:4',
        start=6134664,
        end=6134760,
        disasm='disasm_worldtileloader_wy_02.txt',
        base_add=6134680,
        base_literal=6134756,
        boundary='ARM.exidx end 0x005d9be8 (listing bound); next ObjC IMP 0x005d9be8 World -[translatingToGoal]',
        selectors={},
        imports={},
        ivars={
                 0x5d9be0: (17156516, 'OBJC_IVAR_$_World.dayColor', 888),
        },
        classes={},
        instructions=[(6134664, 'push {r4, r5, fp, lr}'), (6134756, 'adceq r5, r8, r4, asr pc')],
        calls=[(6134740, 'bl sym.imp.objc_copyStruct')],
        branches=[],
        semantics=('[World -[dayColor]] (imp 0x005d9b88, 24w): 8-byte struct getter (objc_copyStruct) for dayColor.\n'),
    ),
    dict(
        name='wy_03',
        method='World -[startPortalPos]',
        types='{?=ii}8@0:4',
        start=6135076,
        end=6135172,
        disasm='disasm_worldtileloader_wy_03.txt',
        base_add=6135092,
        base_literal=6135168,
        boundary='ARM.exidx end 0x005d9d84 (listing bound); next ObjC IMP 0x005d9d84 World -[serverClients]',
        selectors={},
        imports={},
        ivars={
                 0x5d9d7c: (17155912, 'OBJC_IVAR_$_World.startPortalPos', 144),
        },
        classes={},
        instructions=[(6135076, 'push {r4, r5, fp, lr}'), (6135168, 'invalid')],
        calls=[(6135152, 'bl sym.imp.objc_copyStruct')],
        branches=[],
        semantics=('[World -[startPortalPos]] (imp 0x005d9d24, 24w): 8-byte struct getter (objc_copyStruct) for startPortalPos.\n'),
    ),
    dict(
        name='wy_04',
        method='World -[roundedTranslation]',
        types='{Vector2=[2f]}8@0:4',
        start=6136804,
        end=6136900,
        disasm='disasm_worldtileloader_wy_04.txt',
        base_add=6136820,
        base_literal=6136896,
        boundary='ARM.exidx end 0x005da444 (listing bound); next ObjC IMP 0x005da444 World -[isHeadingTowardsMIdday]',
        selectors={},
        imports={},
        ivars={
                 0x5da43c: (17155888, 'OBJC_IVAR_$_World.roundedTranslation', 616),
        },
        classes={},
        instructions=[(6136804, 'push {r4, r5, fp, lr}'), (6136896, 'invalid')],
        calls=[(6136880, 'bl sym.imp.objc_copyStruct')],
        branches=[],
        semantics=('[World -[roundedTranslation]] (imp 0x005da3e4, 24w): 8-byte struct getter (objc_copyStruct) for roundedTranslation.\n'),
    ),
    dict(
        name='wy_05',
        method='World -[windStrength]',
        types='f8@0:4',
        start=6125936,
        end=6126024,
        disasm='disasm_worldtileloader_wy_05.txt',
        base_add=6125968,
        base_literal=6126016,
        boundary='ARM.exidx end 0x005d79c8 (listing bound); next ObjC IMP 0x005d79c8 World -[setDpadControl:]',
        selectors={
                 0x5d79c4: (15197240, 'windStrength'),
        },
        imports={},
        ivars={
                 0x5d79bc: (17156144, 'OBJC_IVAR_$_World.weather', 156),
        },
        classes={},
        instructions=[(6125936, 'push {fp, lr}'), (6126020, 'invalid')],
        calls=[(6125992, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[World -[windStrength]] (imp 0x005d7970, 22w): delegate read - [weather windStrength] via the weather ivar, returning the float.\n'),
    ),
    dict(
        name='wy_06',
        method='World -[tutorialActive]',
        types='c8@0:4',
        start=6090156,
        end=6090240,
        disasm='disasm_worldtileloader_wy_06.txt',
        base_add=6090164,
        base_literal=6090236,
        boundary='ARM.exidx end 0x005cee00 (listing bound); next ObjC IMP 0x005cee00 World -[showDieConfirmationForBlockhead:]',
        selectors={},
        imports={},
        ivars={
                 0x5cedf8: (17156044, 'OBJC_IVAR_$_World.tutorial', 232),
        },
        classes={},
        instructions=[(6090156, 'sub sp, sp, 8'), (6090236, 'adceq r0, sb, r8, lsr sp')],
        calls=[],
        branches=[],
        semantics=('[World -[tutorialActive]] (imp 0x005cedac, 21w): reads the tutorial ivar (BOOL accessor on the tutorial pointer).\n'),
    ),
    dict(
        name='wy_07',
        method='World -[dieConfirmationConfirmed:]',
        types='v12@0:4@8',
        start=6090348,
        end=6090428,
        disasm='disasm_worldtileloader_wy_07.txt',
        base_add=6090364,
        base_literal=6090424,
        boundary='ARM.exidx end 0x005ceebc (listing bound); next ObjC IMP 0x005ceebc World -[startImagePickerWithDelegate:forRect:cropSize:]',
        selectors={
                 0x5ceeb4: (15198168, 'dieForGood'),
        },
        imports={
                 0x5ceeb0: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(6090348, 'push {fp, lr}'), (6090424, 'adceq r0, sb, r0, ror ip')],
        calls=[(6090404, 'blx ip')],
        branches=[],
        semantics=('[World -[dieConfirmationConfirmed:]] (imp 0x005cee6c, 20w): one objc_msgSend dispatch forwarding the confirmation value.\n'),
    ),
    dict(
        name='wy_08',
        method='World -[customRules]',
        types='{CustomRules=CcccIcccccccccccccccc[8c][8S]cccccc[3C]cccccc}8@0:4',
        start=6116740,
        end=6116816,
        disasm='disasm_worldtileloader_wy_08.txt',
        base_add=6116756,
        base_literal=6116812,
        boundary='ARM.exidx end 0x005d55d0 (listing bound); next ObjC IMP 0x005d55d0 World -[customRulesDict]',
        selectors={},
        imports={},
        ivars={
                 0x5d55c8: (17156060, 'OBJC_IVAR_$_World.customRules', 160),
        },
        classes={},
        instructions=[(6116740, 'push {fp, lr}'), (6116812, 'adceq sl, r8, r8, asr r5')],
        calls=[(6116796, 'bl sym.imp.memcpy')],
        branches=[],
        semantics=('[World -[customRules]] (imp 0x005d5584, 19w): struct getter - memcpy of the customRules struct.\n'),
    ),
    dict(
        name='wy_09',
        method='World -[highestPoint]',
        types='{?=ii}8@0:4',
        start=6057648,
        end=6057720,
        disasm='disasm_worldtileloader_wy_09.txt',
        base_add=6057656,
        base_literal=6057716,
        boundary='ARM.exidx end 0x005c6ef8 (listing bound); next ObjC IMP 0x005c6ef8 World -[decommissionOldBlocks]',
        selectors={},
        imports={},
        ivars={
                 0x5c6ef0: (17155908, 'OBJC_IVAR_$_World.highestPoint', 3164),
        },
        classes={},
        instructions=[(6057648, 'sub sp, sp, 8'), (6057716, 'adceq r8, sb, r4, lsr ip')],
        calls=[],
        branches=[],
        semantics=('[World -[highestPoint]] (imp 0x005c6eb0, 18w): bare ivar getter (highestPoint).\n'),
    ),
    dict(
        name='wy_10',
        method='World -[weatherFraction]',
        types='f8@0:4',
        start=6134448,
        end=6134520,
        disasm='disasm_worldtileloader_wy_10.txt',
        base_add=6134472,
        base_literal=6134516,
        boundary='ARM.exidx end 0x005d9b88; body trimmed at the next IMP 0x005d9af8 World -[rainFraction]',
        selectors={},
        imports={},
        ivars={
                 0x5d9af0: (17156544, 'OBJC_IVAR_$_World.weatherFraction', 916),
        },
        classes={},
        instructions=[(6134448, 'sub sp, sp, 0xc'), (6134516, 'adceq r6, r8, r4, lsr 32')],
        calls=[],
        branches=[],
        semantics=('[World -[weatherFraction]] (imp 0x005d9ab0, 18w): bare ivar getter (weatherFraction).\n'),
    ),
    dict(
        name='wy_11',
        method='World -[rainFraction]',
        types='f8@0:4',
        start=6134520,
        end=6134592,
        disasm='disasm_worldtileloader_wy_11.txt',
        base_add=6134544,
        base_literal=6134588,
        boundary='ARM.exidx end 0x005d9b88; body trimmed at the next IMP 0x005d9b40 World -[rainFractionNotIncludingSnow]',
        selectors={},
        imports={},
        ivars={
                 0x5d9b38: (17156536, 'OBJC_IVAR_$_World.rainFraction', 920),
        },
        classes={},
        instructions=[(6134520, 'sub sp, sp, 0xc'), (6134588, 'invalid')],
        calls=[],
        branches=[],
        semantics=('[World -[rainFraction]] (imp 0x005d9af8, 18w): bare ivar getter (rainFraction).\n'),
    ),
    dict(
        name='wy_12',
        method='World -[rainFractionNotIncludingSnow]',
        types='f8@0:4',
        start=6134592,
        end=6134664,
        disasm='disasm_worldtileloader_wy_12.txt',
        base_add=6134616,
        base_literal=6134660,
        boundary='ARM.exidx end 0x005d9b88 (listing bound); next ObjC IMP 0x005d9b88 World -[dayColor]',
        selectors={},
        imports={},
        ivars={
                 0x5d9b80: (17156532, 'OBJC_IVAR_$_World.rainFractionNotIncludingSnow', 924),
        },
        classes={},
        instructions=[(6134592, 'sub sp, sp, 0xc'), (6134660, 'umlaleq r5, r8, r4, pc')],
        calls=[],
        branches=[],
        semantics=('[World -[rainFractionNotIncludingSnow]] (imp 0x005d9b40, 18w): bare ivar getter (rainFractionNotIncludingSnow).\n'),
    ),
    dict(
        name='wy_13',
        method='World -[macroTiles]',
        types='^{MacroTile=CCC^{PhysicalBlock}^{DrawBlock}@f}8@0:4',
        start=6133916,
        end=6133984,
        disasm='disasm_worldtileloader_wy_13.txt',
        base_add=6133940,
        base_literal=6133980,
        boundary='ARM.exidx end 0x005d9968; body trimmed at the next IMP 0x005d98e0 World -[dynamicWorld]',
        selectors={},
        imports={},
        ivars={
                 0x5d98d8: (17156340, 'OBJC_IVAR_$_World.macroTiles', 412),
        },
        classes={},
        instructions=[(6133916, 'sub sp, sp, 0xc'), (6133980, 'adceq r6, r8, r8, lsr r2')],
        calls=[],
        branches=[],
        semantics=('[World -[macroTiles]] (imp 0x005d989c, 17w): bare ivar getter (macroTiles).\n'),
    ),
    dict(
        name='wy_14',
        method='World -[dynamicWorld]',
        types='@8@0:4',
        start=6133984,
        end=6134052,
        disasm='disasm_worldtileloader_wy_14.txt',
        base_add=6134008,
        base_literal=6134048,
        boundary='ARM.exidx end 0x005d9968; body trimmed at the next IMP 0x005d9924 World -[saveID]',
        selectors={},
        imports={},
        ivars={
                 0x5d991c: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={},
        instructions=[(6133984, 'sub sp, sp, 0xc'), (6134048, 'invalid')],
        calls=[],
        branches=[],
        semantics=('[World -[dynamicWorld]] (imp 0x005d98e0, 17w): bare ivar getter (dynamicWorld).\n'),
    ),
    dict(
        name='wy_15',
        method='World -[saveID]',
        types='@8@0:4',
        start=6134052,
        end=6134120,
        disasm='disasm_worldtileloader_wy_15.txt',
        base_add=6134076,
        base_literal=6134116,
        boundary='ARM.exidx end 0x005d9968 (listing bound); next ObjC IMP 0x005d9968 World -[randomSeed]',
        selectors={},
        imports={},
        ivars={
                 0x5d9960: (17155900, 'OBJC_IVAR_$_World.saveID', 436),
        },
        classes={},
        instructions=[(6134052, 'sub sp, sp, 0xc'), (6134116, 'invalid')],
        calls=[],
        branches=[],
        semantics=('[World -[saveID]] (imp 0x005d9924, 17w): bare ivar getter (saveID).\n'),
    ),
    dict(
        name='wy_16',
        method='World -[setTranslatingToGoal:]',
        types='v12@0:4c8',
        start=6134820,
        end=6134888,
        disasm='disasm_worldtileloader_wy_16.txt',
        base_add=6134848,
        base_literal=6134884,
        boundary='ARM.exidx end 0x005d9c68 (listing bound); next ObjC IMP 0x005d9c68 World -[loadComplete]',
        selectors={},
        imports={},
        ivars={
                 0x5d9c60: (17156488, 'OBJC_IVAR_$_World.translatingToGoal', 640),
        },
        classes={},
        instructions=[(6134820, 'sub sp, sp, 0xc'), (6134884, 'adceq r5, r8, ip, lsr 29')],
        calls=[],
        branches=[],
        semantics=('[World -[setTranslatingToGoal:]] (imp 0x005d9c24, 17w): bare ivar setter (translatingToGoal).\n'),
    ),
    dict(
        name='wy_17',
        method='World -[windowInfo]',
        types='^{WindowInfo=ffffffff}8@0:4',
        start=6135008,
        end=6135076,
        disasm='disasm_worldtileloader_wy_17.txt',
        base_add=6135032,
        base_literal=6135072,
        boundary='ARM.exidx end 0x005d9d24 (listing bound); next ObjC IMP 0x005d9d24 World -[startPortalPos]',
        selectors={},
        imports={},
        ivars={
                 0x5d9d1c: (17155876, 'OBJC_IVAR_$_World.windowInfo', 152),
        },
        classes={},
        instructions=[(6135008, 'sub sp, sp, 0xc'), (6135072, 'invalid')],
        calls=[],
        branches=[],
        semantics=('[World -[windowInfo]] (imp 0x005d9ce0, 17w): bare ivar getter (windowInfo).\n'),
    ),
    dict(
        name='wy_18',
        method='World -[serverClients]',
        types='@8@0:4',
        start=6135172,
        end=6135240,
        disasm='disasm_worldtileloader_wy_18.txt',
        base_add=6135196,
        base_literal=6135236,
        boundary='ARM.exidx end 0x005d9e50; body trimmed at the next IMP 0x005d9dc8 World -[server]',
        selectors={},
        imports={},
        ivars={
                 0x5d9dc0: (17155964, 'OBJC_IVAR_$_World.serverClients', 956),
        },
        classes={},
        instructions=[(6135172, 'sub sp, sp, 0xc'), (6135236, 'adceq r5, r8, r0, asr sp')],
        calls=[],
        branches=[],
        semantics=('[World -[serverClients]] (imp 0x005d9d84, 17w): bare ivar getter (serverClients).\n'),
    ),
    dict(
        name='wy_19',
        method='World -[server]',
        types='@8@0:4',
        start=6135240,
        end=6135308,
        disasm='disasm_worldtileloader_wy_19.txt',
        base_add=6135264,
        base_literal=6135304,
        boundary='ARM.exidx end 0x005d9e50; body trimmed at the next IMP 0x005d9e0c World -[client]',
        selectors={},
        imports={},
        ivars={
                 0x5d9e04: (17155916, 'OBJC_IVAR_$_World.server', 964),
        },
        classes={},
        instructions=[(6135240, 'sub sp, sp, 0xc'), (6135304, 'adceq r5, r8, ip, lsl 26')],
        calls=[],
        branches=[],
        semantics=('[World -[server]] (imp 0x005d9dc8, 17w): bare ivar getter (server).\n'),
    ),
    dict(
        name='wy_20',
        method='World -[client]',
        types='@8@0:4',
        start=6135308,
        end=6135376,
        disasm='disasm_worldtileloader_wy_20.txt',
        base_add=6135332,
        base_literal=6135372,
        boundary='ARM.exidx end 0x005d9e50 (listing bound); next ObjC IMP 0x005d9e50 World -[fastForward]',
        selectors={},
        imports={},
        ivars={
                 0x5d9e48: (17155972, 'OBJC_IVAR_$_World.client', 960),
        },
        classes={},
        instructions=[(6135308, 'sub sp, sp, 0xc'), (6135372, 'adceq r5, r8, r8, asr 25')],
        calls=[],
        branches=[],
        semantics=('[World -[client]] (imp 0x005d9e0c, 17w): bare ivar getter (client).\n'),
    ),
    dict(
        name='wy_21',
        method='World -[worldName]',
        types='@8@0:4',
        start=6135496,
        end=6135564,
        disasm='disasm_worldtileloader_wy_21.txt',
        base_add=6135520,
        base_literal=6135560,
        boundary='ARM.exidx end 0x005d9f0c (listing bound); next ObjC IMP 0x005d9f0c World -[isAdmin]',
        selectors={},
        imports={},
        ivars={
                 0x5d9f04: (17155892, 'OBJC_IVAR_$_World.worldName', 440),
        },
        classes={},
        instructions=[(6135496, 'sub sp, sp, 0xc'), (6135560, 'adceq r5, r8, ip, lsl 24')],
        calls=[],
        branches=[],
        semantics=('[World -[worldName]] (imp 0x005d9ec8, 17w): bare ivar getter (worldName).\n'),
    ),
    dict(
        name='wy_22',
        method='World -[setIsAdmin:]',
        types='v12@0:4c8',
        start=6135624,
        end=6135692,
        disasm='disasm_worldtileloader_wy_22.txt',
        base_add=6135652,
        base_literal=6135688,
        boundary='ARM.exidx end 0x005d9f8c (listing bound); next ObjC IMP 0x005d9f8c World -[isMod]',
        selectors={},
        imports={},
        ivars={
                 0x5d9f84: (17156328, 'OBJC_IVAR_$_World.isAdmin', 3209),
        },
        classes={},
        instructions=[(6135624, 'sub sp, sp, 0xc'), (6135688, 'adceq r5, r8, r8, lsl 23')],
        calls=[],
        branches=[],
        semantics=('[World -[setIsAdmin:]] (imp 0x005d9f48, 17w): bare ivar setter (isAdmin).\n'),
    ),
    dict(
        name='wy_23',
        method='World -[setIsMod:]',
        types='v12@0:4c8',
        start=6135752,
        end=6135820,
        disasm='disasm_worldtileloader_wy_23.txt',
        base_add=6135780,
        base_literal=6135816,
        boundary='ARM.exidx end 0x005da00c (listing bound); next ObjC IMP 0x005da00c World -[isOwner]',
        selectors={},
        imports={},
        ivars={
                 0x5da004: (17156324, 'OBJC_IVAR_$_World.isMod', 3210),
        },
        classes={},
        instructions=[(6135752, 'sub sp, sp, 0xc'), (6135816, 'adceq r5, r8, r8, lsl 22')],
        calls=[],
        branches=[],
        semantics=('[World -[setIsMod:]] (imp 0x005d9fc8, 17w): bare ivar setter (isMod).\n'),
    ),
    dict(
        name='wy_24',
        method='World -[setIsOwner:]',
        types='v12@0:4c8',
        start=6135880,
        end=6135948,
        disasm='disasm_worldtileloader_wy_24.txt',
        base_add=6135908,
        base_literal=6135944,
        boundary='ARM.exidx end 0x005da08c (listing bound); next ObjC IMP 0x005da08c World -[cloudMode]',
        selectors={},
        imports={},
        ivars={
                 0x5da084: (17156036, 'OBJC_IVAR_$_World.isOwner', 3208),
        },
        classes={},
        instructions=[(6135880, 'sub sp, sp, 0xc'), (6135944, 'adceq r5, r8, r8, lsl 21')],
        calls=[],
        branches=[],
        semantics=('[World -[setIsOwner:]] (imp 0x005da048, 17w): bare ivar setter (isOwner).\n'),
    ),
    dict(
        name='wy_25',
        method='World -[setCloudMode:]',
        types='v12@0:4i8',
        start=6136008,
        end=6136076,
        disasm='disasm_worldtileloader_wy_25.txt',
        base_add=6136036,
        base_literal=6136072,
        boundary='ARM.exidx end 0x005da194; body trimmed at the next IMP 0x005da10c World -[globalPrices]',
        selectors={},
        imports={},
        ivars={
                 0x5da104: (17156316, 'OBJC_IVAR_$_World.cloudMode', 3212),
        },
        classes={},
        instructions=[(6136008, 'sub sp, sp, 0xc'), (6136072, 'adceq r5, r8, r8, lsl 20')],
        calls=[],
        branches=[],
        semantics=('[World -[setCloudMode:]] (imp 0x005da0c8, 17w): bare ivar setter (cloudMode).\n'),
    ),
    dict(
        name='wy_26',
        method='World -[portalChestManager]',
        types='@8@0:4',
        start=6136272,
        end=6136340,
        disasm='disasm_worldtileloader_wy_26.txt',
        base_add=6136296,
        base_literal=6136336,
        boundary='ARM.exidx end 0x005da214 (listing bound); next ObjC IMP 0x005da214 World -[followingBlockhead]',
        selectors={},
        imports={},
        ivars={
                 0x5da20c: (17156264, 'OBJC_IVAR_$_World.portalChestManager', 3336),
        },
        classes={},
        instructions=[(6136272, 'sub sp, sp, 0xc'), (6136336, 'adceq r5, r8, r4, lsl 18')],
        calls=[],
        branches=[],
        semantics=('[World -[portalChestManager]] (imp 0x005da1d0, 17w): bare ivar getter (portalChestManager).\n'),
    ),
    dict(
        name='wy_27',
        method='World -[setFollowingBlockhead:]',
        types='v12@0:4c8',
        start=6136400,
        end=6136468,
        disasm='disasm_worldtileloader_wy_27.txt',
        base_add=6136428,
        base_literal=6136464,
        boundary='ARM.exidx end 0x005da2d8; body trimmed at the next IMP 0x005da294 World -[tutorial]',
        selectors={},
        imports={},
        ivars={
                 0x5da28c: (17156484, 'OBJC_IVAR_$_World.followingBlockhead', 3345),
        },
        classes={},
        instructions=[(6136400, 'sub sp, sp, 0xc'), (6136464, 'adceq r5, r8, r0, lsl 17')],
        calls=[],
        branches=[],
        semantics=('[World -[setFollowingBlockhead:]] (imp 0x005da250, 17w): bare ivar setter (followingBlockhead).\n'),
    ),
    dict(
        name='wy_28',
        method='World -[tutorial]',
        types='@8@0:4',
        start=6136468,
        end=6136536,
        disasm='disasm_worldtileloader_wy_28.txt',
        base_add=6136492,
        base_literal=6136532,
        boundary='ARM.exidx end 0x005da2d8 (listing bound); next ObjC IMP 0x005da2d8 World -[pinchScale]',
        selectors={},
        imports={},
        ivars={
                 0x5da2d0: (17156044, 'OBJC_IVAR_$_World.tutorial', 232),
        },
        classes={},
        instructions=[(6136468, 'sub sp, sp, 0xc'), (6136532, 'adceq r5, r8, r0, asr 16')],
        calls=[],
        branches=[],
        semantics=('[World -[tutorial]] (imp 0x005da294, 17w): bare ivar getter (tutorial).\n'),
    ),
    dict(
        name='wy_29',
        method='World -[cloudInterface]',
        types='@8@0:4',
        start=6136960,
        end=6137028,
        disasm='disasm_worldtileloader_wy_29.txt',
        base_add=6136984,
        base_literal=6137024,
        boundary='ARM.exidx end 0x005da508; body trimmed at the next IMP 0x005da4c4 World -[setCloudInterface:]',
        selectors={},
        imports={},
        ivars={
                 0x5da4bc: (17156748, 'OBJC_IVAR_$_World.cloudInterface', 236),
        },
        classes={},
        instructions=[(6136960, 'sub sp, sp, 0xc'), (6137024, 'adceq r5, r8, r4, asr r6')],
        calls=[],
        branches=[],
        semantics=('[World -[cloudInterface]] (imp 0x005da480, 17w): bare ivar getter (cloudInterface).\n'),
    ),
    dict(
        name='wy_30',
        method='World -[setCloudInterface:]',
        types='v12@0:4@8',
        start=6137028,
        end=6137096,
        disasm='disasm_worldtileloader_wy_30.txt',
        base_add=6137056,
        base_literal=6137092,
        boundary='ARM.exidx end 0x005da508 (listing bound); next ObjC IMP 0x005da508 World -[saveDisabled]',
        selectors={},
        imports={},
        ivars={
                 0x5da500: (17156748, 'OBJC_IVAR_$_World.cloudInterface', 236),
        },
        classes={},
        instructions=[(6137028, 'sub sp, sp, 0xc'), (6137092, 'adceq r5, r8, ip, lsl 12')],
        calls=[],
        branches=[],
        semantics=('[World -[setCloudInterface:]] (imp 0x005da4c4, 17w): bare ivar setter (cloudInterface).\n'),
    ),
    dict(
        name='wy_31',
        method='World -[setSaveDisabled:]',
        types='v12@0:4c8',
        start=6137156,
        end=6137224,
        disasm='disasm_worldtileloader_wy_31.txt',
        base_add=6137184,
        base_literal=6137220,
        boundary='ARM.exidx end 0x005da588 (listing bound); next ObjC IMP 0x005da588 World -[slowAnimationIndex]',
        selectors={},
        imports={},
        ivars={
                 0x5da580: (17156752, 'OBJC_IVAR_$_World.saveDisabled', 3316),
        },
        classes={},
        instructions=[(6137156, 'sub sp, sp, 0xc'), (6137220, 'adceq r5, r8, ip, lsl 11')],
        calls=[],
        branches=[],
        semantics=('[World -[setSaveDisabled:]] (imp 0x005da544, 17w): bare ivar setter (saveDisabled).\n'),
    ),
    dict(
        name='wy_32',
        method='World -[uiManager]',
        types='@8@0:4',
        start=6137404,
        end=6137472,
        disasm='disasm_worldtileloader_wy_32.txt',
        base_add=6137428,
        base_literal=6137468,
        boundary='ARM.exidx end 0x005da744; body trimmed at the next IMP 0x005da680 World -[foundItemsList]',
        selectors={},
        imports={},
        ivars={
                 0x5da678: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
        },
        classes={},
        instructions=[(6137404, 'sub sp, sp, 0xc'), (6137468, 'umlaleq r5, r8, r8, r4')],
        calls=[],
        branches=[],
        semantics=('[World -[uiManager]] (imp 0x005da63c, 17w): bare ivar getter (uiManager).\n'),
    ),
    dict(
        name='wy_33',
        method='World -[foundItemsList]',
        types='@8@0:4',
        start=6137472,
        end=6137540,
        disasm='disasm_worldtileloader_wy_33.txt',
        base_add=6137496,
        base_literal=6137536,
        boundary='ARM.exidx end 0x005da744; body trimmed at the next IMP 0x005da6c4 World -[delegate]',
        selectors={},
        imports={},
        ivars={
                 0x5da6bc: (17156032, 'OBJC_IVAR_$_World.foundItemsList', 3376),
        },
        classes={},
        instructions=[(6137472, 'sub sp, sp, 0xc'), (6137536, 'adceq r5, r8, r4, asr r4')],
        calls=[],
        branches=[],
        semantics=('[World -[foundItemsList]] (imp 0x005da680, 17w): bare ivar getter (foundItemsList).\n'),
    ),
    dict(
        name='wy_34',
        method='World -[doPortalShotNextFrame]',
        types='v8@0:4',
        start=6131344,
        end=6131408,
        disasm='disasm_worldtileloader_wy_34.txt',
        base_add=6131352,
        base_literal=6131404,
        boundary='ARM.exidx end 0x005d8f0c; body trimmed at the next IMP 0x005d8ed0 World -[hasFinishedDatabaseMigrationTo17]',
        selectors={},
        imports={},
        ivars={
                 0x5d8ec8: (17156500, 'OBJC_IVAR_$_World.needsToDoPortalScreenshot', 3073),
        },
        classes={},
        instructions=[(6131344, 'sub sp, sp, 8'), (6131404, 'adceq r6, r8, r4, asr ip')],
        calls=[],
        branches=[],
        semantics=('[World -[doPortalShotNextFrame]] (imp 0x005d8e90, 16w): fires the needsToDoPortalScreenshot flag (bare setter).\n'),
    ),
    dict(
        name='wy_35',
        method='World -[delegate]',
        types='@8@0:4',
        start=6137540,
        end=6137604,
        disasm='disasm_worldtileloader_wy_35.txt',
        base_add=6137564,
        base_literal=6137600,
        boundary='ARM.exidx end 0x005da744; body trimmed at the next IMP 0x005da704 World -[setDelegate:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6137540, 'sub sp, sp, 0xc'), (6137600, 'adceq r5, r8, r0, lsl r4')],
        calls=[],
        branches=[],
        semantics=('[World -[delegate]] (imp 0x005da6c4, 16w): bare delegate getter (the delegate slot is not dynsym-named in the World ivar table).\n'),
    ),
    dict(
        name='wy_36',
        method='World -[setDelegate:]',
        types='v12@0:4@8',
        start=6137604,
        end=6137668,
        disasm='disasm_worldtileloader_wy_36.txt',
        base_add=6137632,
        base_literal=6137664,
        boundary='ARM.exidx end 0x005da744 (listing bound); next ObjC IMP 0x005da744 World -[workbenchChoiceUIDisplayed]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6137604, 'sub sp, sp, 0xc'), (6137664, 'adceq r5, r8, ip, asr 7')],
        calls=[],
        branches=[],
        semantics=('[World -[setDelegate:]] (imp 0x005da704, 16w): bare delegate setter (the delegate slot is not dynsym-named in the World ivar table).\n'),
    ),
    dict(
        name='wy_37',
        method='World -[distanceOrderedFoodTypes]',
        types='^i8@0:4',
        start=6020464,
        end=6020524,
        disasm='disasm_worldtileloader_wy_37.txt',
        base_add=6020472,
        base_literal=6020520,
        boundary='ARM.exidx end 0x005bddac (listing bound); next ObjC IMP 0x005bddac World -[worldUIDragging]',
        selectors={},
        imports={},
        ivars={
                 0x5bdda4: (17156040, 'OBJC_IVAR_$_World.distanceOrderedFoodTypes', 948),
        },
        classes={},
        instructions=[(6020464, 'sub sp, sp, 8'), (6020520, 'adceq r1, sl, r4, ror sp')],
        calls=[],
        branches=[],
        semantics=('[World -[distanceOrderedFoodTypes]] (imp 0x005bdd70, 15w): bare ivar getter (distanceOrderedFoodTypes).\n'),
    ),
    dict(
        name='wy_38',
        method='World -[welcomeMessage]',
        types='@8@0:4',
        start=6093388,
        end=6093448,
        disasm='disasm_worldtileloader_wy_38.txt',
        base_add=6093396,
        base_literal=6093444,
        boundary='ARM.exidx end 0x005cfa88 (listing bound); next ObjC IMP 0x005cfa88 World -[initMuteList]',
        selectors={},
        imports={},
        ivars={
                 0x5cfa80: (17155944, 'OBJC_IVAR_$_World.welcomeMessage', 3272),
        },
        classes={},
        instructions=[(6093388, 'sub sp, sp, 8'), (6093444, 'umlaleq r0, sb, r8, r0')],
        calls=[],
        branches=[],
        semantics=('[World -[welcomeMessage]] (imp 0x005cfa4c, 15w): bare ivar getter (welcomeMessage).\n'),
    ),
    dict(
        name='wy_39',
        method='World -[serverPassword]',
        types='@8@0:4',
        start=6100772,
        end=6100832,
        disasm='disasm_worldtileloader_wy_39.txt',
        base_add=6100780,
        base_literal=6100828,
        boundary='ARM.exidx end 0x005d179c; body trimmed at the next IMP 0x005d1760 World -[clientPassword]',
        selectors={},
        imports={},
        ivars={
                 0x5d1758: (17155932, 'OBJC_IVAR_$_World.serverPassword', 3288),
        },
        classes={},
        instructions=[(6100772, 'sub sp, sp, 8'), (6100828, 'adceq lr, r8, r0, asr 7')],
        calls=[],
        branches=[],
        semantics=('[World -[serverPassword]] (imp 0x005d1724, 15w): bare ivar getter (serverPassword).\n'),
    ),
    dict(
        name='wy_40',
        method='World -[clientPassword]',
        types='@8@0:4',
        start=6100832,
        end=6100892,
        disasm='disasm_worldtileloader_wy_40.txt',
        base_add=6100840,
        base_literal=6100888,
        boundary='ARM.exidx end 0x005d179c (listing bound); next ObjC IMP 0x005d179c World -[sendNewPrivacySettingToServer:]',
        selectors={},
        imports={},
        ivars={
                 0x5d1794: (17156028, 'OBJC_IVAR_$_World.clientPassword', 3292),
        },
        classes={},
        instructions=[(6100832, 'sub sp, sp, 8'), (6100888, 'adceq lr, r8, r4, lsl 7')],
        calls=[],
        branches=[],
        semantics=('[World -[clientPassword]] (imp 0x005d1760, 15w): bare ivar getter (clientPassword).\n'),
    ),
    dict(
        name='wy_41',
        method='World -[serverPrivacySetting]',
        types='I8@0:4',
        start=6101608,
        end=6101668,
        disasm='disasm_worldtileloader_wy_41.txt',
        base_add=6101616,
        base_literal=6101664,
        boundary='ARM.exidx end 0x005d1aa4 (listing bound); next ObjC IMP 0x005d1aa4 World -[alertView:didDismissWithButtonIndex:]',
        selectors={},
        imports={},
        ivars={
                 0x5d1a9c: (17156092, 'OBJC_IVAR_$_World.serverPrivacySetting', 3296),
        },
        classes={},
        instructions=[(6101608, 'sub sp, sp, 8'), (6101664, 'adceq lr, r8, ip, ror r0')],
        calls=[],
        branches=[],
        semantics=('[World -[serverPrivacySetting]] (imp 0x005d1a68, 15w): bare ivar getter (serverPrivacySetting).\n'),
    ),
    dict(
        name='wy_42',
        method='World -[customRulesDict]',
        types='@8@0:4',
        start=6116816,
        end=6116876,
        disasm='disasm_worldtileloader_wy_42.txt',
        base_add=6116824,
        base_literal=6116872,
        boundary='ARM.exidx end 0x005d560c (listing bound); next ObjC IMP 0x005d560c World -[customRuleForOptionNamed:]',
        selectors={},
        imports={},
        ivars={
                 0x5d5604: (17155952, 'OBJC_IVAR_$_World.customRulesDict', 224),
        },
        classes={},
        instructions=[(6116816, 'sub sp, sp, 8'), (6116872, 'adceq sl, r8, r4, lsl r5')],
        calls=[],
        branches=[],
        semantics=('[World -[customRulesDict]] (imp 0x005d55d0, 15w): bare ivar getter (customRulesDict).\n'),
    ),
    dict(
        name='wy_43',
        method='World -[dpadControl]',
        types='c8@0:4',
        start=6126432,
        end=6126492,
        disasm='disasm_worldtileloader_wy_43.txt',
        base_add=6126440,
        base_literal=6126488,
        boundary='ARM.exidx end 0x005d7b9c (listing bound); next ObjC IMP 0x005d7b9c World -[setDpadDirectControlDisabled:]',
        selectors={},
        imports={},
        ivars={
                 0x5d7b94: (17156304, 'OBJC_IVAR_$_World.dpadControl', 3372),
        },
        classes={},
        instructions=[(6126432, 'sub sp, sp, 8'), (6126488, 'adceq r7, r8, r4, lsl 31')],
        calls=[],
        branches=[],
        semantics=('[World -[dpadControl]] (imp 0x005d7b60, 15w): bare ivar getter (dpadControl).\n'),
    ),
    dict(
        name='wy_44',
        method='World -[dpadDirectControlDisabled]',
        types='c8@0:4',
        start=6126764,
        end=6126824,
        disasm='disasm_worldtileloader_wy_44.txt',
        base_add=6126772,
        base_literal=6126820,
        boundary='ARM.exidx end 0x005d7ce8 (listing bound); next ObjC IMP 0x005d7ce8 World -[addItemsFromServerFoundItemsList:]',
        selectors={},
        imports={},
        ivars={
                 0x5d7ce0: (17156300, 'OBJC_IVAR_$_World.dpadDirectControlDisabled', 3373),
        },
        classes={},
        instructions=[(6126764, 'sub sp, sp, 8'), (6126820, 'adceq r7, r8, r8, lsr lr')],
        calls=[],
        branches=[],
        semantics=('[World -[dpadDirectControlDisabled]] (imp 0x005d7cac, 15w): bare ivar getter (dpadDirectControlDisabled).\n'),
    ),
    dict(
        name='wy_45',
        method='World -[hasFinishedDatabaseMigrationTo17]',
        types='c8@0:4',
        start=6131408,
        end=6131468,
        disasm='disasm_worldtileloader_wy_45.txt',
        base_add=6131416,
        base_literal=6131464,
        boundary='ARM.exidx end 0x005d8f0c (listing bound); next ObjC IMP 0x005d8f0c World -[archiveLightBlocksForClient:]',
        selectors={},
        imports={},
        ivars={
                 0x5d8f04: (17156004, 'OBJC_IVAR_$_World.hasFinishedDatabaseMigrationTo17', 3412),
        },
        classes={},
        instructions=[(6131408, 'sub sp, sp, 8'), (6131464, 'adceq r6, r8, r4, lsl ip')],
        calls=[],
        branches=[],
        semantics=('[World -[hasFinishedDatabaseMigrationTo17]] (imp 0x005d8ed0, 15w): bare ivar getter (hasFinishedDatabaseMigrationTo17).\n'),
    ),
    dict(
        name='wy_46',
        method='World -[expertMode]',
        types='c8@0:4',
        start=6133856,
        end=6133916,
        disasm='disasm_worldtileloader_wy_46.txt',
        base_add=6133864,
        base_literal=6133912,
        boundary='ARM.exidx end 0x005d989c (listing bound); next ObjC IMP 0x005d989c World -[macroTiles]',
        selectors={},
        imports={},
        ivars={
                 0x5d9894: (17155896, 'OBJC_IVAR_$_World.expertMode', 228),
        },
        classes={},
        instructions=[(6133856, 'sub sp, sp, 8'), (6133912, 'adceq r6, r8, r4, lsl 5')],
        calls=[],
        branches=[],
        semantics=('[World -[expertMode]] (imp 0x005d9860, 15w): bare ivar getter (expertMode).\n'),
    ),
    dict(
        name='wy_47',
        method='World -[randomSeed]',
        types='I8@0:4',
        start=6134120,
        end=6134180,
        disasm='disasm_worldtileloader_wy_47.txt',
        base_add=6134144,
        base_literal=6134176,
        boundary='ARM.exidx end 0x005d99a4 (listing bound); next ObjC IMP 0x005d99a4 World -[worldTime]',
        selectors={},
        imports={},
        ivars={
                 0x5d999c: (17155928, 'OBJC_IVAR_$_World.randomSeed', 432),
        },
        classes={},
        instructions=[(6134120, 'sub sp, sp, 8'), (6134176, 'adceq r6, r8, ip, ror 2')],
        calls=[],
        branches=[],
        semantics=('[World -[randomSeed]] (imp 0x005d9968, 15w): bare ivar getter (randomSeed).\n'),
    ),
    dict(
        name='wy_48',
        method='World -[isAdmin]',
        types='c8@0:4',
        start=6135564,
        end=6135624,
        disasm='disasm_worldtileloader_wy_48.txt',
        base_add=6135572,
        base_literal=6135620,
        boundary='ARM.exidx end 0x005d9f48 (listing bound); next ObjC IMP 0x005d9f48 World -[setIsAdmin:]',
        selectors={},
        imports={},
        ivars={
                 0x5d9f40: (17156328, 'OBJC_IVAR_$_World.isAdmin', 3209),
        },
        classes={},
        instructions=[(6135564, 'sub sp, sp, 8'), (6135620, 'invalid')],
        calls=[],
        branches=[],
        semantics=('[World -[isAdmin]] (imp 0x005d9f0c, 15w): bare ivar getter (isAdmin).\n'),
    ),
    dict(
        name='wy_49',
        method='World -[isMod]',
        types='c8@0:4',
        start=6135692,
        end=6135752,
        disasm='disasm_worldtileloader_wy_49.txt',
        base_add=6135700,
        base_literal=6135748,
        boundary='ARM.exidx end 0x005d9fc8 (listing bound); next ObjC IMP 0x005d9fc8 World -[setIsMod:]',
        selectors={},
        imports={},
        ivars={
                 0x5d9fc0: (17156324, 'OBJC_IVAR_$_World.isMod', 3210),
        },
        classes={},
        instructions=[(6135692, 'sub sp, sp, 8'), (6135748, 'adceq r5, r8, r8, asr fp')],
        calls=[],
        branches=[],
        semantics=('[World -[isMod]] (imp 0x005d9f8c, 15w): bare ivar getter (isMod).\n'),
    ),
    dict(
        name='wy_50',
        method='World -[isOwner]',
        types='c8@0:4',
        start=6135820,
        end=6135880,
        disasm='disasm_worldtileloader_wy_50.txt',
        base_add=6135828,
        base_literal=6135876,
        boundary='ARM.exidx end 0x005da048 (listing bound); next ObjC IMP 0x005da048 World -[setIsOwner:]',
        selectors={},
        imports={},
        ivars={
                 0x5da040: (17156036, 'OBJC_IVAR_$_World.isOwner', 3208),
        },
        classes={},
        instructions=[(6135820, 'sub sp, sp, 8'), (6135876, 'invalid')],
        calls=[],
        branches=[],
        semantics=('[World -[isOwner]] (imp 0x005da00c, 15w): bare ivar getter (isOwner).\n'),
    ),
    dict(
        name='wy_51',
        method='World -[cloudMode]',
        types='i8@0:4',
        start=6135948,
        end=6136008,
        disasm='disasm_worldtileloader_wy_51.txt',
        base_add=6135972,
        base_literal=6136004,
        boundary='ARM.exidx end 0x005da0c8 (listing bound); next ObjC IMP 0x005da0c8 World -[setCloudMode:]',
        selectors={},
        imports={},
        ivars={
                 0x5da0c0: (17156316, 'OBJC_IVAR_$_World.cloudMode', 3212),
        },
        classes={},
        instructions=[(6135948, 'sub sp, sp, 8'), (6136004, 'adceq r5, r8, r8, asr 20')],
        calls=[],
        branches=[],
        semantics=('[World -[cloudMode]] (imp 0x005da08c, 15w): bare ivar getter (cloudMode).\n'),
    ),
    dict(
        name='wy_52',
        method='World -[serverMinorVersion]',
        types='i8@0:4',
        start=6136212,
        end=6136272,
        disasm='disasm_worldtileloader_wy_52.txt',
        base_add=6136236,
        base_literal=6136268,
        boundary='ARM.exidx end 0x005da1d0 (listing bound); next ObjC IMP 0x005da1d0 World -[portalChestManager]',
        selectors={},
        imports={},
        ivars={
                 0x5da1c8: (17156096, 'OBJC_IVAR_$_World.serverMinorVersion', 3280),
        },
        classes={},
        instructions=[(6136212, 'sub sp, sp, 8'), (6136268, 'adceq r5, r8, r0, asr 18')],
        calls=[],
        branches=[],
        semantics=('[World -[serverMinorVersion]] (imp 0x005da194, 15w): bare ivar getter (serverMinorVersion).\n'),
    ),
    dict(
        name='wy_53',
        method='World -[followingBlockhead]',
        types='c8@0:4',
        start=6136340,
        end=6136400,
        disasm='disasm_worldtileloader_wy_53.txt',
        base_add=6136348,
        base_literal=6136396,
        boundary='ARM.exidx end 0x005da250 (listing bound); next ObjC IMP 0x005da250 World -[setFollowingBlockhead:]',
        selectors={},
        imports={},
        ivars={
                 0x5da248: (17156484, 'OBJC_IVAR_$_World.followingBlockhead', 3345),
        },
        classes={},
        instructions=[(6136340, 'sub sp, sp, 8'), (6136396, 'invalid')],
        calls=[],
        branches=[],
        semantics=('[World -[followingBlockhead]] (imp 0x005da214, 15w): bare ivar getter (followingBlockhead).\n'),
    ),
    dict(
        name='wy_54',
        method='World -[dragInProgress]',
        types='c8@0:4',
        start=6136744,
        end=6136804,
        disasm='disasm_worldtileloader_wy_54.txt',
        base_add=6136752,
        base_literal=6136800,
        boundary='ARM.exidx end 0x005da3e4 (listing bound); next ObjC IMP 0x005da3e4 World -[roundedTranslation]',
        selectors={},
        imports={},
        ivars={
                 0x5da3dc: (17156436, 'OBJC_IVAR_$_World.dragInProgress', 108),
        },
        classes={},
        instructions=[(6136744, 'sub sp, sp, 8'), (6136800, 'adceq r5, r8, ip, lsr r7')],
        calls=[],
        branches=[],
        semantics=('[World -[dragInProgress]] (imp 0x005da3a8, 15w): bare ivar getter (dragInProgress).\n'),
    ),
    dict(
        name='wy_55',
        method='World -[saveDisabled]',
        types='c8@0:4',
        start=6137096,
        end=6137156,
        disasm='disasm_worldtileloader_wy_55.txt',
        base_add=6137104,
        base_literal=6137152,
        boundary='ARM.exidx end 0x005da544 (listing bound); next ObjC IMP 0x005da544 World -[setSaveDisabled:]',
        selectors={},
        imports={},
        ivars={
                 0x5da53c: (17156752, 'OBJC_IVAR_$_World.saveDisabled', 3316),
        },
        classes={},
        instructions=[(6137096, 'sub sp, sp, 8'), (6137152, 'invalid')],
        calls=[],
        branches=[],
        semantics=('[World -[saveDisabled]] (imp 0x005da508, 15w): bare ivar getter (saveDisabled).\n'),
    ),
    dict(
        name='wy_56',
        method='World -[slowAnimationIndex]',
        types='i8@0:4',
        start=6137224,
        end=6137284,
        disasm='disasm_worldtileloader_wy_56.txt',
        base_add=6137248,
        base_literal=6137280,
        boundary='ARM.exidx end 0x005da63c; body trimmed at the next IMP 0x005da5c4 World -[waterAnimationIndex]',
        selectors={},
        imports={},
        ivars={
                 0x5da5bc: (17156580, 'OBJC_IVAR_$_World.slowAnimationIndex', 1016),
        },
        classes={},
        instructions=[(6137224, 'sub sp, sp, 8'), (6137280, 'adceq r5, r8, ip, asr 10')],
        calls=[],
        branches=[],
        semantics=('[World -[slowAnimationIndex]] (imp 0x005da588, 15w): bare ivar getter (slowAnimationIndex).\n'),
    ),
    dict(
        name='wy_57',
        method='World -[waterAnimationIndex]',
        types='i8@0:4',
        start=6137284,
        end=6137344,
        disasm='disasm_worldtileloader_wy_57.txt',
        base_add=6137308,
        base_literal=6137340,
        boundary='ARM.exidx end 0x005da63c; body trimmed at the next IMP 0x005da600 World -[hasJustTakenPhoto]',
        selectors={},
        imports={},
        ivars={
                 0x5da5f8: (17156572, 'OBJC_IVAR_$_World.waterAnimationIndex', 1008),
        },
        classes={},
        instructions=[(6137284, 'sub sp, sp, 8'), (6137340, 'adceq r5, r8, r0, lsl r5')],
        calls=[],
        branches=[],
        semantics=('[World -[waterAnimationIndex]] (imp 0x005da5c4, 15w): bare ivar getter (waterAnimationIndex).\n'),
    ),
    dict(
        name='wy_58',
        method='World -[workbenchChoiceUIDisplayed]',
        types='c8@0:4',
        start=6137668,
        end=6137728,
        disasm='disasm_worldtileloader_wy_58.txt',
        base_add=6137676,
        base_literal=6137724,
        boundary='ARM.exidx end 0x005daa8c; body trimmed at the next IMP 0x005da780 World -[newBlockheadUIDisplayed]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6137668, 'sub sp, sp, 8'), (6137724, 'adceq r5, r8, r0, lsr 7')],
        calls=[],
        branches=[],
        semantics=('[World -[workbenchChoiceUIDisplayed]] (imp 0x005da744, 15w): BOOL byte-flag getter - ldrsb r0,[self+offset] with the offset carried by its pool slot (a compile-time BOOL ivar not named in the World dynsym table).\n'),
    ),
    dict(
        name='wy_59',
        method='World -[newBlockheadUIDisplayed]',
        types='c8@0:4',
        start=6137728,
        end=6137788,
        disasm='disasm_worldtileloader_wy_59.txt',
        base_add=6137736,
        base_literal=6137784,
        boundary='ARM.exidx end 0x005daa8c; body trimmed at the next IMP 0x005da7bc World -[paintMixUIDisplayed]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6137728, 'sub sp, sp, 8'), (6137784, 'adceq r5, r8, r4, ror 6')],
        calls=[],
        branches=[],
        semantics=('[World -[newBlockheadUIDisplayed]] (imp 0x005da780, 15w): BOOL byte-flag getter - ldrsb r0,[self+offset] with the offset carried by its pool slot (a compile-time BOOL ivar not named in the World dynsym table).\n'),
    ),
    dict(
        name='wy_60',
        method='World -[paintMixUIDisplayed]',
        types='c8@0:4',
        start=6137788,
        end=6137848,
        disasm='disasm_worldtileloader_wy_60.txt',
        base_add=6137796,
        base_literal=6137844,
        boundary='ARM.exidx end 0x005daa8c; body trimmed at the next IMP 0x005da7f8 World -[addFuelUIDisplayed]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6137788, 'sub sp, sp, 8'), (6137844, 'adceq r5, r8, r8, lsr 6')],
        calls=[],
        branches=[],
        semantics=('[World -[paintMixUIDisplayed]] (imp 0x005da7bc, 15w): BOOL byte-flag getter - ldrsb r0,[self+offset] with the offset carried by its pool slot (a compile-time BOOL ivar not named in the World dynsym table).\n'),
    ),
    dict(
        name='wy_61',
        method='World -[addFuelUIDisplayed]',
        types='c8@0:4',
        start=6137848,
        end=6137908,
        disasm='disasm_worldtileloader_wy_61.txt',
        base_add=6137856,
        base_literal=6137904,
        boundary='ARM.exidx end 0x005daa8c; body trimmed at the next IMP 0x005da834 World -[jetPackUIDisplayed]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6137848, 'sub sp, sp, 8'), (6137904, 'adceq r5, r8, ip, ror 5')],
        calls=[],
        branches=[],
        semantics=('[World -[addFuelUIDisplayed]] (imp 0x005da7f8, 15w): BOOL byte-flag getter - ldrsb r0,[self+offset] with the offset carried by its pool slot (a compile-time BOOL ivar not named in the World dynsym table).\n'),
    ),
    dict(
        name='wy_62',
        method='World -[jetPackUIDisplayed]',
        types='c8@0:4',
        start=6137908,
        end=6137968,
        disasm='disasm_worldtileloader_wy_62.txt',
        base_add=6137916,
        base_literal=6137964,
        boundary='ARM.exidx end 0x005daa8c; body trimmed at the next IMP 0x005da870 World -[sleepProgressUIDisplayed]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6137908, 'sub sp, sp, 8'), (6137964, 'invalid')],
        calls=[],
        branches=[],
        semantics=('[World -[jetPackUIDisplayed]] (imp 0x005da834, 15w): BOOL byte-flag getter - ldrsb r0,[self+offset] with the offset carried by its pool slot (a compile-time BOOL ivar not named in the World dynsym table).\n'),
    ),
    dict(
        name='wy_63',
        method='World -[sleepProgressUIDisplayed]',
        types='c8@0:4',
        start=6137968,
        end=6138028,
        disasm='disasm_worldtileloader_wy_63.txt',
        base_add=6137976,
        base_literal=6138024,
        boundary='ARM.exidx end 0x005daa8c; body trimmed at the next IMP 0x005da8ac World -[regenerateUIDisplayed]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6137968, 'sub sp, sp, 8'), (6138024, 'adceq r5, r8, r4, ror r2')],
        calls=[],
        branches=[],
        semantics=('[World -[sleepProgressUIDisplayed]] (imp 0x005da870, 15w): BOOL byte-flag getter - ldrsb r0,[self+offset] with the offset carried by its pool slot (a compile-time BOOL ivar not named in the World dynsym table).\n'),
    ),
    dict(
        name='wy_64',
        method='World -[regenerateUIDisplayed]',
        types='c8@0:4',
        start=6138028,
        end=6138088,
        disasm='disasm_worldtileloader_wy_64.txt',
        base_add=6138036,
        base_literal=6138084,
        boundary='ARM.exidx end 0x005daa8c; body trimmed at the next IMP 0x005da8e8 World -[hungerUIDisplayed]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6138028, 'sub sp, sp, 8'), (6138084, 'adceq r5, r8, r8, lsr r2')],
        calls=[],
        branches=[],
        semantics=('[World -[regenerateUIDisplayed]] (imp 0x005da8ac, 15w): BOOL byte-flag getter - ldrsb r0,[self+offset] with the offset carried by its pool slot (a compile-time BOOL ivar not named in the World dynsym table).\n'),
    ),
    dict(
        name='wy_65',
        method='World -[hungerUIDisplayed]',
        types='c8@0:4',
        start=6138088,
        end=6138148,
        disasm='disasm_worldtileloader_wy_65.txt',
        base_add=6138096,
        base_literal=6138144,
        boundary='ARM.exidx end 0x005daa8c; body trimmed at the next IMP 0x005da924 World -[wearUIDisplayed]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6138088, 'sub sp, sp, 8'), (6138144, 'invalid')],
        calls=[],
        branches=[],
        semantics=('[World -[hungerUIDisplayed]] (imp 0x005da8e8, 15w): BOOL byte-flag getter - ldrsb r0,[self+offset] with the offset carried by its pool slot (a compile-time BOOL ivar not named in the World dynsym table).\n'),
    ),
    dict(
        name='wy_66',
        method='World -[wearUIDisplayed]',
        types='c8@0:4',
        start=6138148,
        end=6138208,
        disasm='disasm_worldtileloader_wy_66.txt',
        base_add=6138156,
        base_literal=6138204,
        boundary='ARM.exidx end 0x005daa8c; body trimmed at the next IMP 0x005da960 World -[popUpUIDisplayed]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6138148, 'sub sp, sp, 8'), (6138204, 'adceq r5, r8, r0, asr 3')],
        calls=[],
        branches=[],
        semantics=('[World -[wearUIDisplayed]] (imp 0x005da924, 15w): BOOL byte-flag getter - ldrsb r0,[self+offset] with the offset carried by its pool slot (a compile-time BOOL ivar not named in the World dynsym table).\n'),
    ),
    dict(
        name='wy_67',
        method='World -[popUpUIDisplayed]',
        types='c8@0:4',
        start=6138208,
        end=6138268,
        disasm='disasm_worldtileloader_wy_67.txt',
        base_add=6138216,
        base_literal=6138264,
        boundary='ARM.exidx end 0x005daa8c; body trimmed at the next IMP 0x005da99c World -[tradingPostSellUIDisplayed]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6138208, 'sub sp, sp, 8'), (6138264, 'adceq r5, r8, r4, lsl 3')],
        calls=[],
        branches=[],
        semantics=('[World -[popUpUIDisplayed]] (imp 0x005da960, 15w): BOOL byte-flag getter - ldrsb r0,[self+offset] with the offset carried by its pool slot (a compile-time BOOL ivar not named in the World dynsym table).\n'),
    ),
    dict(
        name='wy_68',
        method='World -[tradingPostSellUIDisplayed]',
        types='c8@0:4',
        start=6138268,
        end=6138328,
        disasm='disasm_worldtileloader_wy_68.txt',
        base_add=6138276,
        base_literal=6138324,
        boundary='ARM.exidx end 0x005daa8c; body trimmed at the next IMP 0x005da9d8 World -[tradingPostBuyUIDisplayed]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6138268, 'sub sp, sp, 8'), (6138324, 'adceq r5, r8, r8, asr 2')],
        calls=[],
        branches=[],
        semantics=('[World -[tradingPostSellUIDisplayed]] (imp 0x005da99c, 15w): BOOL byte-flag getter - ldrsb r0,[self+offset] with the offset carried by its pool slot (a compile-time BOOL ivar not named in the World dynsym table).\n'),
    ),
    dict(
        name='wy_69',
        method='World -[tradingPostBuyUIDisplayed]',
        types='c8@0:4',
        start=6138328,
        end=6138388,
        disasm='disasm_worldtileloader_wy_69.txt',
        base_add=6138336,
        base_literal=6138384,
        boundary='ARM.exidx end 0x005daa8c; body trimmed at the next IMP 0x005daa14 World -[ownershipSignUIDisplayed]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6138328, 'sub sp, sp, 8'), (6138384, 'adceq r5, r8, ip, lsl 2')],
        calls=[],
        branches=[],
        semantics=('[World -[tradingPostBuyUIDisplayed]] (imp 0x005da9d8, 15w): BOOL byte-flag getter - ldrsb r0,[self+offset] with the offset carried by its pool slot (a compile-time BOOL ivar not named in the World dynsym table).\n'),
    ),
    dict(
        name='wy_70',
        method='World -[workbenchProgressBarUIDisplayed]',
        types='c8@0:4',
        start=6138448,
        end=6138508,
        disasm='disasm_worldtileloader_wy_70.txt',
        base_add=6138456,
        base_literal=6138504,
        boundary='ARM.exidx end 0x005daa8c (listing bound); next ObjC IMP 0x005daa8c World -[.cxx_destruct]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6138448, 'sub sp, sp, 8'), (6138504, 'umlaleq r5, r8, r4, r0')],
        calls=[],
        branches=[],
        semantics=('[World -[workbenchProgressBarUIDisplayed]] (imp 0x005daa50, 15w): BOOL byte-flag getter - ldrsb r0,[self+offset] with the offset carried by its pool slot (a compile-time BOOL ivar not named in the World dynsym table).\n'),
    ),
    dict(
        name='wy_71',
        method='World -[usedPhysicalBlocks]',
        types='^{unordered_set<PhysicalBlock *, std::__1::hash<PhysicalBlock *>, std::__1::equal_to<PhysicalBlock *>, std::__1::allocator<PhysicalBlock *> >={__hash_table<PhysicalBlock *, std::__1::hash<PhysicalBlock *>, std::__1::equal_to<PhysicalBlock *>, std::__1::allocator<PhysicalBlock *> >={unique_ptr<std::__1::__hash_node<PhysicalBlock *, void *> *[], std::__1::__bucket_list_deallocator<std::__1::allocator<std::__1::__hash_node<PhysicalBlock *, void *> *> > >={__compressed_pair<std::__1::__hash_node<PhysicalBlock *, void *> **, std::__1::__bucket_list_deallocator<std::__1::allocator<std::__1::__hash_node<PhysicalBlock *, void *> *> > >=^^{__hash_node<PhysicalBlock *, void *>}{__bucket_list_deallocator<std::__1::allocator<std::__1::__hash_node<PhysicalBlock *, void *> *> >={__compressed_pair<unsigned long, std::__1::allocator<std::__1::__hash_node<PhysicalBlock *, void *> *> >=L}}}}{__compressed_pair<std::__1::__hash_node_base<std::__1::__hash_node<PhysicalBlock *, void *> *>, std::__1::allocator<std::__1::__hash_node<PhysicalBlock *, void *> > >={__hash_node_base<std::__1::__hash_node<PhysicalBlock *, void *> *>=^{__hash_node<PhysicalBlock *, void *>}}}{__compressed_pair<unsigned long, std::__1::hash<PhysicalBlock *> >=L}{__compressed_pair<float, std::__1::equal_to<PhysicalBlock *> >=f}}}8@0:4',
        start=6131288,
        end=6131344,
        disasm='disasm_worldtileloader_wy_71.txt',
        base_add=6131296,
        base_literal=6131340,
        boundary='ARM.exidx end 0x005d8f0c; body trimmed at the next IMP 0x005d8e90 World -[doPortalShotNextFrame]',
        selectors={},
        imports={},
        ivars={
                 0x5d8e88: (17156364, 'OBJC_IVAR_$_World.usedPhysicalBlocks', 456),
        },
        classes={},
        instructions=[(6131288, 'sub sp, sp, 8'), (6131340, 'adceq r6, r8, ip, lsl 25')],
        calls=[],
        branches=[],
        semantics=('[World -[usedPhysicalBlocks]] (imp 0x005d8e58, 14w): bare ivar getter (usedPhysicalBlocks).\n'),
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
        'batch': 'World closure sweep part 2 (E115): the accessor tail that closes the class; 72 bodies',
        'claim': ('the World accessor tail; the -UIDisplayed offset slots are not dynsym-named and are recorded as-is'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'world_close2.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale world_close2.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
