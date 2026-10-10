#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The animals line: DonkeyLike, the animal base class: the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 18480 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/DONKEYLIKE.md for the prose and boundaries.
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
    'bl 0x11c7524': 0x011c7524,
    'bl 0xab1cdc': 0x00ab1cdc,
    'bl 0xab9de8': 0x00ab9de8,
    'bl 0xac2748': 0x00ac2748,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector__': 0x004bed60,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector.Vector_float__float__float__float_': 0x004d0d08,
    'bl method.Vector.operator_Vector_': 0x004d6538,
    'bl method.Vector.operator_float__': 0x004b5c08,
    'bl method.Vector2.Vector2__': 0x004d5170,
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl method.Vector2.operator_Vector2_': 0x004d0418,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl sym.Vector::operator_Vector_': 0x0058198c,
    'bl sym.clamp_float__float__float_': 0x004be068,
    'bl sym.contentsTypeForPlantType_PlantType__bool_': 0x00a653d8,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__wrap_fmodf': 0x001c3d4c,
    'bl sym.imp.__wrap_glBindTexture': 0x001c2ad4,
    'bl sym.imp.__wrap_glDisableVertexAttribArray': 0x001c3d58,
    'bl sym.imp.__wrap_glEnableVertexAttribArray': 0x001c2d5c,
    'bl sym.imp.__wrap_glUniform1i': 0x001c2de0,
    'bl sym.imp.__wrap_glUniform4f': 0x001c3d64,
    'bl sym.imp.__wrap_glUniformMatrix4fv': 0x001c2dd4,
    'bl sym.imp.__wrap_glUseProgram': 0x001c2d38,
    'bl sym.imp.cosf': 0x001c2b58,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.sinf': 0x001c2b34,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileAtWorldPosition_int__int__MacroTile__World_': 0x00a16e68,
    'bl sym.tileContainsGate_Tile_': 0x00a127cc,
    'bl sym.tileIsAirWaterOrSnow_Tile_': 0x00a126dc,
    'bl sym.tileIsSolid_Tile_': 0x00a1179c,
    'bl sym.tileIsWater_Tile_': 0x00a11690,
}

SPECS = [
    dict(
        name='dl_00',
        method='DonkeyLike -[loadDerivedStuff]',
        types='v8@0:4',
        start=11208464,
        end=11209384,
        disasm='disasm_worldtileloader_dl_00.txt',
        base_add=11208480,
        base_literal=11209380,
        boundary='ARM.exidx end 0x00ab0aa8 (listing bound); next ObjC IMP 0x00ab0aa8 DonkeyLike -[foodPlantType]',
        selectors={
                 0xab0a74: (15227320, 'shaderNamed:attributes:uniforms:'),
                 0xab0a88: (15227316, 'arrayWithObjects:'),
        },
        imports={
                 0xab0a6c: (16365224, '__CFConstantStringClassReference'),
                 0xab0a70: (17151904, 'objc_msgSend'),
                 0xab0a78: (16365288, '__CFConstantStringClassReference'),
                 0xab0a7c: (16365304, '__CFConstantStringClassReference'),
                 0xab0a80: (16365320, '__CFConstantStringClassReference'),
                 0xab0a84: (16365336, '__CFConstantStringClassReference'),
                 0xab0a90: (16365240, '__CFConstantStringClassReference'),
                 0xab0a94: (16365256, '__CFConstantStringClassReference'),
                 0xab0a98: (16365272, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xab0a54: (17164984, 'OBJC_IVAR_$_DonkeyLike.remoteStopPos', 828),
                 0xab0a58: (17164988, 'OBJC_IVAR_$_DonkeyLike.munchMotionRandomSpeed', 800),
                 0xab0a5c: (17164992, 'OBJC_IVAR_$_DonkeyLike.randomTimeBetweenDirectionChanges', 300),
                 0xab0a60: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xab0a64: (17164996, 'OBJC_IVAR_$_DonkeyLike.backPos', 272),
                 0xab0a68: (17158188, 'OBJC_IVAR_$_DonkeyLike.shader', 208),
                 0xab0a9c: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0xab0aa0: (17158180, 'OBJC_IVAR_$_DonkeyLike.bodyColor', 808),
        },
        classes={
                 0xab0a8c: (15249364, 'OBJC_CLASS_$_NSArray'),
        },
        instructions=[(11208464, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11209380, 'subseq pc, sl, ip, asr 7')],
        calls=[(11208556, 'bl method.Vector.Vector_float__float__float_'), (11209000, 'blx sl'), (11209064, 'blx r5'), (11209108, 'blx lr'), (11209268, 'bl sym.makeIntpair_int__int_')],
        branches=[],
        semantics=('[DonkeyLike loadDerivedStuff] (imp 0x00ab0710, 230w): the derived loader - Vector(float,float,float) + makeIntpair (the part derivation).\n'),
    ),
    dict(
        name='dl_01',
        method='DonkeyLike -[foodPlantType]',
        types='i8@0:4',
        start=11209384,
        end=11209412,
        disasm='disasm_worldtileloader_dl_01.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00ab0ac4 (listing bound); next ObjC IMP 0x00ab0ac4 DonkeyLike -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11209384, 'sub sp, sp, 8'), (11209408, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DonkeyLike foodPlantType] (imp 0x00ab0aa8, 7w): the food plant type constant.\n'),
    ),
    dict(
        name='dl_02',
        method='DonkeyLike -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:]',
        types='@44@0:4@8@12{?=ii}16@24@28c32c36@40',
        start=11209412,
        end=11209788,
        disasm='disasm_worldtileloader_dl_02.txt',
        base_add=11209428,
        base_literal=11209784,
        boundary='ARM.exidx end 0x00ab0c3c (listing bound); next ObjC IMP 0x00ab0c3c DonkeyLike -[initWithWorld:dynamicWorld:saveDict:cache:]',
        selectors={
                 0xab0c2c: (15227324, 'initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:'),
                 0xab0c34: (15227328, 'loadDerivedStuff'),
        },
        imports={
                 0xab0c30: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0xab0c24: (15253100, 'OBJC_CLASS_$_DonkeyLike'),
        },
        instructions=[(11209412, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11209784, 'subseq pc, sl, r8, lsl r0')],
        calls=[(11209656, 'bl loc.imp.objc_msgSendSuper2'), (11209740, 'blx r2')],
        branches=[(11209684, 'bne', 11209700), (11209696, 'b', 11209752)],
        semantics=('[DonkeyLike initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:was...] (imp 0x00ab0ac4, 94w): the placed ctor (super2).\n'),
    ),
    dict(
        name='dl_03',
        method='DonkeyLike -[initWithWorld:dynamicWorld:cache:netData:]',
        types='@24@0:4@8@12@16@20',
        start=11210084,
        end=11210416,
        disasm='disasm_worldtileloader_dl_03.txt',
        base_add=11210100,
        base_literal=11210412,
        boundary='ARM.exidx end 0x00ab0eb0 (listing bound); next ObjC IMP 0x00ab0eb0 DonkeyLike -[donkeyLikeCreationNetDataForClient:]',
        selectors={
                 0xab0e98: (15227336, 'initWithWorld:dynamicWorld:cache:netData:'),
                 0xab0ea4: (15227340, 'remoteCreationDataUpdate:'),
                 0xab0ea8: (15227328, 'loadDerivedStuff'),
        },
        imports={
                 0xab0e94: (17151900, 'objc_msgSendSuper2'),
                 0xab0ea0: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0xab0e9c: (15253100, 'OBJC_CLASS_$_DonkeyLike'),
        },
        instructions=[(11210084, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11210412, 'subseq lr, sl, r8, ror sp')],
        calls=[(11210236, 'blx r6'), (11210340, 'blx ip'), (11210364, 'blx r3')],
        branches=[(11210264, 'bne', 11210280), (11210276, 'b', 11210376)],
        semantics=('[DonkeyLike initWithWorld:dynamicWorld:cache:netData:] (imp 0x00ab0d64, 83w): the netData ctor.\n'),
    ),
    dict(
        name='dl_04',
        method='DonkeyLike -[donkeyLikeCreationNetDataForClient:]',
        types='{DonkeyLikeCreationNetData={NPCCreationNetData={DynamicObjectNetData=QIIC[7C]}QQQSSCCCCssSsC[7C]}{DonkeyLikeUpdateNetData={NPCUpdateNetData={DynamicObjectNetData=QIIC[7C]}}sssCC}}12@0:4@8',
        start=11210416,
        end=11210760,
        disasm='disasm_worldtileloader_dl_04.txt',
        base_add=11210432,
        base_literal=11210756,
        boundary='ARM.exidx end 0x00ab1008 (listing bound); next ObjC IMP 0x00ab1008 DonkeyLike -[donkeyLikeUpdateNetDataForClient:]',
        selectors={
                 0xab0ffc: (15227344, 'npcCreationNetDataForClient:'),
                 0xab1000: (15227348, 'donkeyLikeUpdateNetDataForClient:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(11210416, 'push {r4, sl, fp, lr}'), (11210756, 'subseq lr, sl, ip, lsr 24')],
        calls=[(11210516, 'bl loc.imp.objc_msgSend_stret'), (11210552, 'bl sym.imp.memset'), (11210600, 'bl sym.imp.memcpy'), (11210672, 'bl loc.imp.objc_msgSend_stret'), (11210708, 'bl sym.imp.memset'), (11210736, 'bl sym.imp.memcpy')],
        branches=[(11210496, 'beq', 11210524), (11210520, 'b', 11210556), (11210652, 'beq', 11210680), (11210676, 'b', 11210712)],
        semantics=('[DonkeyLike donkeyLikeCreationNetDataForClient:] (imp 0x00ab0eb0, 86w): the creation record - stret x2 + memset x2 + memcpy x2 (consts 0x48/0x20 = the record sizes!).\n'),
    ),
    dict(
        name='dl_05',
        method='DonkeyLike -[donkeyLikeUpdateNetDataForClient:]',
        types='{DonkeyLikeUpdateNetData={NPCUpdateNetData={DynamicObjectNetData=QIIC[7C]}}sssCC}12@0:4@8',
        start=11210760,
        end=11211212,
        disasm='disasm_worldtileloader_dl_05.txt',
        base_add=11210776,
        base_literal=11211208,
        boundary='ARM.exidx end 0x00ab11cc (listing bound); next ObjC IMP 0x00ab11cc DonkeyLike -[creationNetDataForClient:]',
        selectors={
                 0xab11ac: (15227352, 'npcUpdateNetDataForClient:'),
        },
        imports={},
        ivars={
                 0xab11b0: (17165000, 'OBJC_IVAR_$_DonkeyLike.lastSendContainedMovement', 836),
                 0xab11b4: (17165004, 'OBJC_IVAR_$_DonkeyLike.targetXSpeed', 280),
                 0xab11c0: (17165008, 'OBJC_IVAR_$_DonkeyLike.jumpActionSendValue', 325),
                 0xab11c4: (17165012, 'OBJC_IVAR_$_DonkeyLike.randomGoalRotation', 304),
        },
        classes={},
        instructions=[(11210760, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11211208, 'ldrsbeq lr, [sl], -0xa4')],
        calls=[(11210860, 'bl loc.imp.objc_msgSend_stret'), (11210896, 'bl sym.imp.memset')],
        branches=[(11210840, 'beq', 11210868), (11210864, 'b', 11210900)],
        semantics=('[DonkeyLike donkeyLikeUpdateNetDataForClient:] (imp 0x00ab1008, 113w): the update record - stret + memset (const 0x18 = 24-byte record).\n'),
    ),
    dict(
        name='dl_06',
        method='DonkeyLike -[creationNetDataForClient:]',
        types='@12@0:4@8',
        start=11211212,
        end=11211504,
        disasm='disasm_worldtileloader_dl_06.txt',
        base_add=11211228,
        base_literal=11211500,
        boundary='ARM.exidx end 0x00ab12f0 (listing bound); next ObjC IMP 0x00ab12f0 DonkeyLike -[updateNetDataForClient:]',
        selectors={
                 0xab12d8: (15227356, 'donkeyLikeCreationNetDataForClient:'),
                 0xab12e0: (15227364, 'appendNPCCreationDataToData:'),
                 0xab12e4: (15227360, 'dataWithBytes:length:'),
        },
        imports={
                 0xab12dc: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0xab12e8: (15249368, 'OBJC_CLASS_$_NSData'),
        },
        instructions=[(11211212, 'push {r4, r5, fp, lr}'), (11211500, 'subseq lr, sl, r0, lsl sb')],
        calls=[(11211308, 'bl loc.imp.objc_msgSend_stret'), (11211344, 'bl sym.imp.memset'), (11211432, 'blx ip'), (11211460, 'blx r3')],
        branches=[(11211288, 'beq', 11211316), (11211312, 'b', 11211348)],
        semantics=('[DonkeyLike creationNetDataForClient:] (imp 0x00ab11cc, 73w): the base creation record.\n'),
    ),
    dict(
        name='dl_07',
        method='DonkeyLike -[updateNetDataForClient:]',
        types='@12@0:4@8',
        start=11211504,
        end=11211740,
        disasm='disasm_worldtileloader_dl_07.txt',
        base_add=11211520,
        base_literal=11211736,
        boundary='ARM.exidx end 0x00ab13dc (listing bound); next ObjC IMP 0x00ab13dc DonkeyLike -[creationDataStructSize]',
        selectors={
                 0xab13c8: (15227348, 'donkeyLikeUpdateNetDataForClient:'),
                 0xab13d0: (15227360, 'dataWithBytes:length:'),
        },
        imports={
                 0xab13cc: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0xab13d4: (15249368, 'OBJC_CLASS_$_NSData'),
        },
        instructions=[(11211504, 'push {fp, lr}'), (11211736, 'subseq lr, sl, ip, ror 15')],
        calls=[(11211600, 'bl loc.imp.objc_msgSend_stret'), (11211636, 'bl sym.imp.memset'), (11211700, 'blx ip')],
        branches=[(11211580, 'beq', 11211608), (11211604, 'b', 11211640)],
        semantics=('[DonkeyLike updateNetDataForClient:] (imp 0x00ab12f0, 59w): the base net update.\n'),
    ),
    dict(
        name='dl_08',
        method='DonkeyLike -[creationDataStructSize]',
        types='L8@0:4',
        start=11211740,
        end=11211768,
        disasm='disasm_worldtileloader_dl_08.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00ab13f8 (listing bound); next ObjC IMP 0x00ab13f8 DonkeyLike -[dealloc]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11211740, 'sub sp, sp, 8'), (11211764, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DonkeyLike creationDataStructSize] (imp 0x00ab13dc, 7w): the struct size constant.\n'),
    ),
    dict(
        name='dl_09',
        method='DonkeyLike -[dealloc]',
        types='v8@0:4',
        start=11211768,
        end=11211972,
        disasm='disasm_worldtileloader_dl_09.txt',
        base_add=11211784,
        base_literal=11211968,
        boundary='ARM.exidx end 0x00ab14c4 (listing bound); next ObjC IMP 0x00ab14c4 DonkeyLike -[doDonkeyLikeRemoteUpdate:]',
        selectors={
                 0xab14ac: (15227372, 'dealloc'),
                 0xab14b8: (15227368, 'autorelease'),
        },
        imports={
                 0xab14a8: (17151900, 'objc_msgSendSuper2'),
                 0xab14b4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xab14bc: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
        },
        classes={
                 0xab14b0: (15253100, 'OBJC_CLASS_$_DonkeyLike'),
        },
        instructions=[(11211768, 'push {r4, r5, r6, r7, fp, lr}'), (11211968, 'subseq lr, sl, r4, ror 13')],
        calls=[(11211884, 'blx r5'), (11211932, 'blx ip')],
        branches=[],
        semantics=('[DonkeyLike dealloc] (imp 0x00ab13f8, 51w): teardown.\n'),
    ),
    dict(
        name='dl_10',
        method='DonkeyLike -[doDonkeyLikeRemoteUpdate:]',
        types='v40@0:4{DonkeyLikeUpdateNetData={NPCUpdateNetData={DynamicObjectNetData=QIIC[7C]}}sssCC}8',
        start=11211972,
        end=11214044,
        disasm='disasm_worldtileloader_dl_10.txt',
        base_add=11211988,
        base_literal=11214040,
        boundary='ARM.exidx end 0x00ab1cdc (listing bound); next ObjC IMP 0x00ab1d18 DonkeyLike -[remoteUpdate:]',
        selectors={
                 0xab1c7c: (15227376, 'isNet'),
                 0xab1c94: (15227380, 'worldWidthMacro'),
                 0xab1cac: (15227384, 'updatePosition:'),
                 0xab1ccc: (15227388, 'playAtPosition:'),
        },
        imports={
                 0xab1c78: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xab1c6c: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xab1c70: (17164984, 'OBJC_IVAR_$_DonkeyLike.remoteStopPos', 828),
                 0xab1c74: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0xab1c80: (17165004, 'OBJC_IVAR_$_DonkeyLike.targetXSpeed', 280),
                 0xab1c88: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xab1c90: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xab1ca4: (17164996, 'OBJC_IVAR_$_DonkeyLike.backPos', 272),
                 0xab1ca8: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xab1cb4: (17165016, 'OBJC_IVAR_$_DonkeyLike.jumpActionQueued', 296),
                 0xab1cbc: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0xab1cc0: (17158236, 'OBJC_IVAR_$_DonkeyLike.babySound', 244),
                 0xab1cc4: (17158232, 'OBJC_IVAR_$_DonkeyLike.adultSound', 248),
                 0xab1cd0: (17165008, 'OBJC_IVAR_$_DonkeyLike.jumpActionSendValue', 325),
                 0xab1cd4: (17165012, 'OBJC_IVAR_$_DonkeyLike.randomGoalRotation', 304),
        },
        classes={},
        instructions=[(11211972, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11214040, 'subseq lr, sl, r8, lsl r6')],
        calls=[(11212100, 'bl sym.makeIntpair_int__int_'), (11212300, 'blx r2'), (11212400, 'bl sym.makeIntpair_int__int_'), (11212588, 'bl loc.imp.objc_msgSend'), (11212612, 'bl sym.imp.__aeabi_idiv'), (11212708, 'bl loc.imp.objc_msgSend'), (11212828, 'bl loc.imp.objc_msgSend'), (11212844, 'bl sym.imp.__aeabi_idiv'), (11212940, 'bl loc.imp.objc_msgSend'), (11213032, 'bl 0xab1cdc'), (11213080, 'bl 0xab1cdc'), (11213192, 'bl loc.imp.objc_msgSend'), (11213288, 'bl method.Vector2.Vector2_float__float_'), (11213348, 'bl 0xab1cdc'), (11213792, 'bl loc.imp.objc_msgSend')],
        branches=[(11212156, 'beq', 11212200), (11212196, 'beq', 11212316), (11212236, 'beq', 11213924), (11212312, 'beq', 11213924), (11212456, 'bpl', 11212500), (11212624, 'blt', 11212740), (11212736, 'b', 11213020), (11212856, 'bge', 11212972), (11212968, 'b', 11213012), (11213040, 'bgt', 11213092), (11213088, 'ble', 11213344), (11213336, 'b', 11213556), (11213356, 'ble', 11213552), (11213432, 'bne', 11213492), (11213488, 'bpl', 11213548), (11213548, 'b', 11213552), (11213552, 'b', 11213556), (11213564, 'beq', 11213868), (11213608, 'bne', 11213796), (11213660, 'ble', 11213700), (11213696, 'b', 11213732), (11213828, 'bne', 11213864), (11213864, 'b', 11213868)],
        semantics=('[DonkeyLike doDonkeyLikeRemoteUpdate:] (imp 0x00ab14c4, 533w): the remote update - objc x6 + the helper 0xab1cdc x3 + makeIntpair x2 + `__aeabi_idiv` x2 + Vector2 + consts 0xff/0x384.\n'),
    ),
    dict(
        name='dl_11',
        method='DonkeyLike -[remoteUpdate:]',
        types='v12@0:4@8',
        start=11214104,
        end=11214468,
        disasm='disasm_worldtileloader_dl_11.txt',
        base_add=11214120,
        base_literal=11214464,
        boundary='ARM.exidx end 0x00ab1e84 (listing bound); next ObjC IMP 0x00ab1e84 DonkeyLike -[remoteCreationDataUpdate:]',
        selectors={
                 0xab1e68: (15227392, 'remoteUpdate:'),
                 0xab1e74: (15227396, 'getBytes:length:'),
                 0xab1e7c: (15227400, 'doDonkeyLikeRemoteUpdate:'),
        },
        imports={
                 0xab1e64: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0xab1e70: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
        },
        classes={
                 0xab1e6c: (15253100, 'OBJC_CLASS_$_DonkeyLike'),
        },
        instructions=[(11214104, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11214464, 'subseq sp, sl, r4, asr 27')],
        calls=[(11214196, 'blx lr'), (11214276, 'bl loc.imp.objc_msgSend'), (11214424, 'bl loc.imp.objc_msgSend')],
        branches=[(11214232, 'bne', 11214428)],
        semantics=('[DonkeyLike remoteUpdate:] (imp 0x00ab1d18, 91w): the net update forwarder (objc x2).\n'),
    ),
    dict(
        name='dl_12',
        method='DonkeyLike -[remoteCreationDataUpdate:]',
        types='v12@0:4@8',
        start=11214468,
        end=11214788,
        disasm='disasm_worldtileloader_dl_12.txt',
        base_add=11214484,
        base_literal=11214784,
        boundary='ARM.exidx end 0x00ab1fc4 (listing bound); next ObjC IMP 0x00ab1fc4 DonkeyLike -[blockheadCanRide:usingItem:]',
        selectors={
                 0xab1fac: (15227340, 'remoteCreationDataUpdate:'),
                 0xab1fb4: (15227396, 'getBytes:length:'),
                 0xab1fbc: (15227400, 'doDonkeyLikeRemoteUpdate:'),
        },
        imports={
                 0xab1fa8: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={},
        classes={
                 0xab1fb0: (15253100, 'OBJC_CLASS_$_DonkeyLike'),
        },
        instructions=[(11214468, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11214784, 'subseq sp, sl, r8, asr ip')],
        calls=[(11214556, 'blx lr'), (11214600, 'bl loc.imp.objc_msgSend'), (11214748, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[DonkeyLike remoteCreationDataUpdate] (imp 0x00ab1e84, 80w): the remote creation update.\n'),
    ),
    dict(
        name='dl_13',
        method='DonkeyLike -[blockheadCanRide:usingItem:]',
        types='c16@0:4@8i12',
        start=11214788,
        end=11215152,
        disasm='disasm_worldtileloader_dl_13.txt',
        base_add=11214804,
        base_literal=11215148,
        boundary='ARM.exidx end 0x00ab2130 (listing bound); next ObjC IMP 0x00ab2130 DonkeyLike -[update:accurateDT:isSimulation:]',
        selectors={
                 0xab2120: (15227404, 'belongsToPlayerWithBlockhead:'),
        },
        imports={
                 0xab211c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xab2114: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0xab2118: (17157392, 'OBJC_IVAR_$_NPC.beingControlled', 128),
                 0xab2124: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0xab2128: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
        },
        classes={},
        instructions=[(11214788, 'push {r4, r5, fp, lr}'), (11215148, 'subseq sp, sl, r8, lsl fp')],
        calls=[(11214984, 'blx r3')],
        branches=[(11214880, 'ble', 11215100), (11214924, 'bne', 11215100), (11215004, 'beq', 11215100), (11215048, 'bne', 11215100)],
        semantics=('[DonkeyLike blockheadCanRide:usingItem:] (imp 0x00ab1fc4, 91w): the ride gate with const **0x384 (900)** (the same family constant).\n'),
    ),
    dict(
        name='dl_14',
        method='DonkeyLike -[update:accurateDT:isSimulation:]',
        types='v20@0:4f8f12c16',
        start=11215152,
        end=11247080,
        disasm='disasm_worldtileloader_dl_14.txt',
        base_add=11215172,
        base_literal=11219184,
        boundary='ARM.exidx end 0x00ab9de8 (listing bound); next ObjC IMP 0x00ab9df8 DonkeyLike -[setupMatrices:dt:]',
        selectors={
                 0xab30f8: (15227408, 'update:accurateDT:isSimulation:'),
                 0xab3204: (15227412, 'createItemDropsForDeath'),
                 0xab35d8: (15227380, 'worldWidthMacro'),
                 0xab40e0: (15227416, 'blockheadOccupiesTileAtPos:ignoreBlockhead:'),
                 0xab40e8: (15227420, 'npcExistsAtPos:ignoreNPC:'),
                 0xab4af8: (15227424, 'flies'),
                 0xab4afc: (15227432, 'hitWithForce:blockhead:'),
                 0xab4b00: (15227428, 'maxHealth'),
                 0xab4c8c: (15227436, 'checkCurrentPositionForFood'),
                 0xab4c90: (15227384, 'updatePosition:'),
                 0xab4d8c: (15227440, 'canMate'),
                 0xab4d90: (15227444, 'npcCloseEnoughToBreedWithNPC:'),
                 0xab4d94: (15227448, 'mateWithNPC:'),
                 0xab4f2c: (15227452, 'foodPlantType'),
                 0xab4f34: (15227456, 'getPlantAtPos:'),
                 0xab4f38: (15227460, 'plantType'),
                 0xab4f3c: (15227464, 'availableFood'),
                 0xab50c8: (15227468, 'setAvailableFood:'),
                 0xab51cc: (15227472, 'objectType'),
                 0xab51d0: (15227476, 'dynamicWorldChangedAtPos:objectType:'),
                 0xab58ec: (15227380, 'worldWidthMacro'),
                 0xab74c8: (15227424, 'flies'),
                 0xab778c: (15227376, 'isNet'),
                 0xab7794: (15227480, 'activeBlockhead'),
                 0xab77ac: (15227380, 'worldWidthMacro'),
                 0xab80ac: (15227484, 'jumps'),
                 0xab80b0: (15227488, 'fastForward'),
                 0xab80b8: (15227492, 'canJumpMultipleTilesWhileFlying'),
                 0xab8898: (15227496, 'npcType'),
                 0xab88a4: (15227500, 'generateBreedForChild'),
                 0xab88a8: (15227504, 'numberWithInt:'),
                 0xab8920: (15227508, 'dictionaryWithObjectsAndKeys:'),
                 0xab8928: (15227512, 'loadNPCAtPosition:type:saveDict:isAdult:wasPlaced:placedByClient:'),
                 0xab8938: (15227516, 'instance'),
                 0xab893c: (15227520, 'multiSoundNamed:'),
                 0xab8944: (15227388, 'playAtPosition:'),
                 0xab8a50: (15227388, 'playAtPosition:'),
                 0xab8a58: (15227524, 'playAtPosition:afterDelay:'),
                 0xab8a68: (15227472, 'objectType'),
                 0xab8a6c: (15227476, 'dynamicWorldChangedAtPos:objectType:'),
                 0xab929c: (15227416, 'blockheadOccupiesTileAtPos:ignoreBlockhead:'),
                 0xab933c: (15227420, 'npcExistsAtPos:ignoreNPC:'),
                 0xab97c8: (15227380, 'worldWidthMacro'),
                 0xab9d98: (15227380, 'worldWidthMacro'),
        },
        imports={
                 0xab30f4: (17151900, 'objc_msgSendSuper2'),
                 0xab3200: (17151904, 'objc_msgSend'),
                 0xab74c4: (17151904, 'objc_msgSend'),
                 0xab8924: (16365352, '__CFConstantStringClassReference'),
                 0xab8940: (16365368, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xab3100: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0xab31ec: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0xab31f0: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0xab31f4: (17165020, 'OBJC_IVAR_$_DonkeyLike.deathTimer', 308),
                 0xab31f8: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xab31fc: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0xab335c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xab3360: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xab3364: (17165024, 'OBJC_IVAR_$_DonkeyLike.ySpeed', 292),
                 0xab3368: (17158240, 'OBJC_IVAR_$_DonkeyLike.actualXSpeed', 284),
                 0xab3454: (17165028, 'OBJC_IVAR_$_DonkeyLike.bobTimer', 312),
                 0xab3458: (17157392, 'OBJC_IVAR_$_NPC.beingControlled', 128),
                 0xab35d0: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xab3d10: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0xab40d8: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xab4af4: (17165032, 'OBJC_IVAR_$_DonkeyLike.fallTimer', 320),
                 0xab4d98: (17157268, 'OBJC_IVAR_$_NPC.fullness', 68),
                 0xab51c0: (17157292, 'OBJC_IVAR_$_NPC.layCooldownTimer', 84),
                 0xab51c4: (17157264, 'OBJC_IVAR_$_NPC.layTimer', 80),
                 0xab5334: (17164996, 'OBJC_IVAR_$_DonkeyLike.backPos', 272),
                 0xab5338: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xab5494: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xab58e4: (17158240, 'OBJC_IVAR_$_DonkeyLike.actualXSpeed', 284),
                 0xab60c8: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xab72d8: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xab72dc: (17164996, 'OBJC_IVAR_$_DonkeyLike.backPos', 272),
                 0xab74b4: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xab74b8: (17165036, 'OBJC_IVAR_$_DonkeyLike.inWater', 317),
                 0xab74bc: (17158244, 'OBJC_IVAR_$_DonkeyLike.falling', 316),
                 0xab74c0: (17165024, 'OBJC_IVAR_$_DonkeyLike.ySpeed', 292),
                 0xab7784: (17165040, 'OBJC_IVAR_$_DonkeyLike.hasHadExtraMidAirJump', 324),
                 0xab7788: (17158240, 'OBJC_IVAR_$_DonkeyLike.actualXSpeed', 284),
                 0xab7790: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0xab7798: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xab779c: (17157392, 'OBJC_IVAR_$_NPC.beingControlled', 128),
                 0xab77a0: (17165004, 'OBJC_IVAR_$_DonkeyLike.targetXSpeed', 280),
                 0xab77a4: (17164984, 'OBJC_IVAR_$_DonkeyLike.remoteStopPos', 828),
                 0xab7e10: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xab7fb4: (17165032, 'OBJC_IVAR_$_DonkeyLike.fallTimer', 320),
                 0xab7fb8: (17165016, 'OBJC_IVAR_$_DonkeyLike.jumpActionQueued', 296),
                 0xab80a8: (17165016, 'OBJC_IVAR_$_DonkeyLike.jumpActionQueued', 296),
                 0xab80b4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xab8790: (17157264, 'OBJC_IVAR_$_NPC.layTimer', 80),
                 0xab892c: (17157268, 'OBJC_IVAR_$_NPC.fullness', 68),
                 0xab8a54: (17158236, 'OBJC_IVAR_$_DonkeyLike.babySound', 244),
                 0xab8a5c: (17157280, 'OBJC_IVAR_$_NPC.hasBred', 100),
                 0xab8a64: (17157292, 'OBJC_IVAR_$_NPC.layCooldownTimer', 84),
                 0xab8b70: (17164992, 'OBJC_IVAR_$_DonkeyLike.randomTimeBetweenDirectionChanges', 300),
                 0xab8b74: (17165044, 'OBJC_IVAR_$_DonkeyLike.goalX', 288),
                 0xab8e30: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0xab8e38: (17165008, 'OBJC_IVAR_$_DonkeyLike.jumpActionSendValue', 325),
                 0xab8f08: (17158232, 'OBJC_IVAR_$_DonkeyLike.adultSound', 248),
                 0xab9344: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xab9848: (17165004, 'OBJC_IVAR_$_DonkeyLike.targetXSpeed', 280),
                 0xab9b8c: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xab9b90: (17165012, 'OBJC_IVAR_$_DonkeyLike.randomGoalRotation', 304),
                 0xab9d80: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xab9d84: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xab9d88: (17158240, 'OBJC_IVAR_$_DonkeyLike.actualXSpeed', 284),
                 0xab9d90: (17157392, 'OBJC_IVAR_$_NPC.beingControlled', 128),
                 0xab9d9c: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0xab9da0: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xab9da8: (17158244, 'OBJC_IVAR_$_DonkeyLike.falling', 316),
                 0xab9dac: (17165004, 'OBJC_IVAR_$_DonkeyLike.targetXSpeed', 280),
                 0xab9db0: (17165044, 'OBJC_IVAR_$_DonkeyLike.goalX', 288),
                 0xab9db4: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xab9db8: (17165012, 'OBJC_IVAR_$_DonkeyLike.randomGoalRotation', 304),
                 0xab9dcc: (17158304, 'OBJC_IVAR_$_DonkeyLike.munchMotionTimer', 796),
                 0xab9dd0: (17164988, 'OBJC_IVAR_$_DonkeyLike.munchMotionRandomSpeed', 800),
                 0xab9dd4: (17165048, 'OBJC_IVAR_$_DonkeyLike.munchMotionRandomSpeedChangeTimer', 804),
                 0xab9dd8: (17165052, 'OBJC_IVAR_$_DonkeyLike.munchHeadDownTimer', 784),
                 0xab9ddc: (17165056, 'OBJC_IVAR_$_DonkeyLike.targetHeadDownFraction', 792),
                 0xab9de4: (17158312, 'OBJC_IVAR_$_DonkeyLike.headDownFraction', 788),
        },
        classes={
                 0xab30fc: (15253100, 'OBJC_CLASS_$_DonkeyLike'),
                 0xab889c: (15249372, 'OBJC_CLASS_$_NSDictionary'),
                 0xab88a0: (15249376, 'OBJC_CLASS_$_NSNumber'),
                 0xab8934: (15249380, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(11215152, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11247076, 'invalid')],
        calls=[(11215312, 'blx lr'), (11215672, 'blx r2'), (11215964, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11215976, 'bl sym.tileIsWater_Tile_'), (11216116, 'bl sym.imp.sinf'), (11216356, 'bl sym.tileIsWater_Tile_'), (11216420, 'bl sym.imp.__aeabi_idiv'), (11216504, 'bl method.Vector2.operator_float__'), (11216588, 'bl loc.imp.objc_msgSend'), (11216632, 'bl method.Vector2.operator_float__'), (11216764, 'bl method.Vector2.Vector2_float__float_'), (11216784, 'bl method.Vector2.operator_Vector2_'), (11216832, 'bl method.Vector2.operator_float__'), (11216868, 'bl method.Vector2.operator_float__'), (11216892, 'bl sym.makeIntpair_int__int_'), (11216964, 'bl loc.imp.objc_msgSend'), (11216988, 'bl sym.imp.__aeabi_idiv'), (11217084, 'bl loc.imp.objc_msgSend'), (11217204, 'bl loc.imp.objc_msgSend'), (11217220, 'bl sym.imp.__aeabi_idiv'), (11217316, 'bl loc.imp.objc_msgSend'), (11217524, 'bl method.Vector2.operator_float__'), (11217568, 'bl method.Vector2.operator_float__'), (11217640, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11217692, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11217704, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (11217724, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (11217828, 'bl loc.imp.objc_msgSend'), (11217852, 'bl sym.imp.__aeabi_idiv'), (11217948, 'bl loc.imp.objc_msgSend'), (11218068, 'bl loc.imp.objc_msgSend'), (11218084, 'bl sym.imp.__aeabi_idiv'), (11218180, 'bl loc.imp.objc_msgSend'), (11218316, 'bl sym.tileContainsGate_Tile_'), (11218336, 'bl sym.tileContainsGate_Tile_'), (11218440, 'bl loc.imp.objc_msgSend'), (11218464, 'bl sym.imp.__aeabi_idiv'), (11218560, 'bl loc.imp.objc_msgSend'), (11218680, 'bl loc.imp.objc_msgSend'), (11218696, 'bl sym.imp.__aeabi_idiv'), (11218792, 'bl loc.imp.objc_msgSend'), (11218908, 'bl method.Vector2.operator_float__'), (11218952, 'bl method.Vector2.operator_float__'), (11219032, 'bl loc.imp.objc_msgSend'), (11219056, 'bl sym.imp.__aeabi_idiv'), (11219152, 'bl loc.imp.objc_msgSend'), (11219292, 'bl loc.imp.objc_msgSend'), (11219308, 'bl sym.imp.__aeabi_idiv'), (11219404, 'bl loc.imp.objc_msgSend'), (11219652, 'bl loc.imp.objc_msgSend'), (11219676, 'bl sym.imp.__aeabi_idiv'), (11219772, 'bl loc.imp.objc_msgSend'), (11219908, 'bl loc.imp.objc_msgSend'), (11219924, 'bl sym.imp.__aeabi_idiv'), (11220020, 'bl loc.imp.objc_msgSend'), (11220256, 'bl loc.imp.objc_msgSend'), (11220372, 'bl loc.imp.objc_msgSend'), (11220528, 'bl method.Vector2.operator_float__'), (11220576, 'bl method.Vector2.operator_float__'), (11220600, 'bl sym.makeIntpair_int__int_'), (11220668, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11220720, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11220732, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (11220752, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (11220856, 'bl loc.imp.objc_msgSend'), (11220880, 'bl sym.imp.__aeabi_idiv'), (11220976, 'bl loc.imp.objc_msgSend'), (11221104, 'bl loc.imp.objc_msgSend'), (11221120, 'bl sym.imp.__aeabi_idiv'), (11221216, 'bl loc.imp.objc_msgSend'), (11221372, 'bl sym.tileContainsGate_Tile_'), (11221392, 'bl sym.tileContainsGate_Tile_'), (11221452, 'bl method.Vector2.operator_float__'), (11221488, 'bl method.Vector2.operator_float__'), (11221760, 'bl method.Vector2.operator_float__'), (11221864, 'blx r2'), (11222020, 'blx r3'), (11222092, 'blx ip'), (11222260, 'bl loc.imp.objc_msgSend'), (11222280, 'blx r2'), (11222400, 'bl loc.imp.objc_msgSend'), (11222420, 'blx r2'), (11222500, 'blx r2'), (11222596, 'blx r3'), (11222672, 'blx r3'), (11222708, 'blx ip'), (11222872, 'blx r3'), (11222884, 'bl sym.contentsTypeForPlantType_PlantType__bool_'), (11222984, 'bl loc.imp.objc_msgSend'), (11223060, 'blx r3'), (11223092, 'blx r3'), (11223172, 'blx r3'), (11223460, 'blx ip'), (11223500, 'blx r3'), (11223644, 'bl 0xab9de8'), (11223784, 'bl loc.imp.objc_msgSend'), (11223820, 'bl loc.imp.objc_msgSend'), (11223908, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11223940, 'bl method.Vector2.operator_float__'), (11223980, 'bl method.Vector2.operator_float__'), (11224032, 'bl method.Vector2.operator_float__'), (11224076, 'bl method.Vector2.operator_float__'), (11224132, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11224144, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (11224188, 'bl method.Vector2.operator_float__'), (11224248, 'bl method.Vector2.operator_float__'), (11224288, 'bl method.Vector2.operator_float__'), (11224356, 'bl method.Vector2.operator_float__'), (11224412, 'bl method.Vector2.operator_float__'), (11224480, 'bl method.Vector2.operator_float__'), (11224528, 'bl method.Vector2.operator_float__'), (11224568, 'bl method.Vector2.operator_float__'), (11224620, 'bl method.Vector2.operator_float__'), (11224660, 'bl method.Vector2.operator_float__'), (11224720, 'bl method.Vector2.operator_float__'), (11224796, 'bl method.Vector2.operator_float__'), (11224864, 'bl method.Vector2.operator_float__'), (11224904, 'bl method.Vector2.operator_float__'), (11224956, 'bl method.Vector2.operator_float__'), (11224996, 'bl method.Vector2.operator_float__'), (11225064, 'bl method.Vector2.operator_float__'), (11225120, 'bl method.Vector2.operator_float__'), (11225188, 'bl method.Vector2.operator_float__'), (11225236, 'bl method.Vector2.operator_float__'), (11225276, 'bl method.Vector2.operator_float__'), (11225328, 'bl method.Vector2.operator_float__'), (11225368, 'bl method.Vector2.operator_float__'), (11225496, 'bl method.Vector2.operator_float__'), (11225536, 'bl method.Vector2.operator_float__'), (11225596, 'bl loc.imp.objc_msgSend'), (11225620, 'bl sym.imp.__aeabi_idiv'), (11225696, 'bl method.Vector2.operator_float__'), (11225736, 'bl method.Vector2.operator_float__'), (11225796, 'bl loc.imp.objc_msgSend'), (11225912, 'bl method.Vector2.operator_float__'), (11225952, 'bl method.Vector2.operator_float__'), (11226012, 'bl loc.imp.objc_msgSend'), (11226028, 'bl sym.imp.__aeabi_idiv'), (11226104, 'bl method.Vector2.operator_float__'), (11226144, 'bl method.Vector2.operator_float__'), (11226204, 'bl loc.imp.objc_msgSend'), (11226292, 'bl method.Vector2.operator_float__'), (11226332, 'bl method.Vector2.operator_float__'), (11226432, 'bl method.Vector2.operator_float__'), (11226488, 'bl method.Vector2.operator_float__'), (11226576, 'bl method.Vector2.operator_float__'), (11226616, 'bl method.Vector2.operator_float__'), (11226676, 'bl loc.imp.objc_msgSend'), (11226700, 'bl sym.imp.__aeabi_idiv'), (11226776, 'bl method.Vector2.operator_float__'), (11226816, 'bl method.Vector2.operator_float__'), (11226876, 'bl loc.imp.objc_msgSend'), (11226996, 'bl method.Vector2.operator_float__'), (11227036, 'bl method.Vector2.operator_float__'), (11227096, 'bl loc.imp.objc_msgSend'), (11227112, 'bl sym.imp.__aeabi_idiv'), (11227188, 'bl method.Vector2.operator_float__'), (11227228, 'bl method.Vector2.operator_float__'), (11227288, 'bl loc.imp.objc_msgSend'), (11227364, 'bl method.Vector2.operator_float__'), (11227404, 'bl method.Vector2.operator_float__'), (11227504, 'bl method.Vector2.operator_float__'), (11227560, 'bl method.Vector2.operator_float__'), (11227656, 'bl method.Vector2.operator_float__'), (11227732, 'bl loc.imp.objc_msgSend'), (11227756, 'bl sym.imp.__aeabi_idiv'), (11227832, 'bl method.Vector2.operator_float__'), (11227908, 'bl loc.imp.objc_msgSend'), (11228016, 'bl method.Vector2.operator_float__'), (11228092, 'bl loc.imp.objc_msgSend'), (11228108, 'bl sym.imp.__aeabi_idiv'), (11228184, 'bl method.Vector2.operator_float__'), (11228260, 'bl loc.imp.objc_msgSend'), (11228336, 'bl method.Vector2.operator_float__'), (11228516, 'bl method.Vector2.operator_float__'), (11228556, 'bl method.Vector2.operator_float__'), (11228632, 'bl loc.imp.objc_msgSend'), (11228656, 'bl sym.imp.__aeabi_idiv'), (11228732, 'bl method.Vector2.operator_float__'), (11228808, 'bl loc.imp.objc_msgSend'), (11228908, 'bl method.Vector2.operator_float__'), (11228984, 'bl loc.imp.objc_msgSend'), (11229000, 'bl sym.imp.__aeabi_idiv'), (11229076, 'bl method.Vector2.operator_float__'), (11229152, 'bl loc.imp.objc_msgSend'), (11229224, 'bl method.Vector2.operator_float__'), (11229392, 'bl method.Vector2.operator_float__'), (11229520, 'bl method.Vector2.operator_float__'), (11229556, 'bl method.Vector2.operator_float__'), (11229628, 'bl loc.imp.objc_msgSend'), (11229652, 'bl sym.imp.__aeabi_idiv'), (11229724, 'bl method.Vector2.operator_float__'), (11229796, 'bl loc.imp.objc_msgSend'), (11229892, 'bl method.Vector2.operator_float__'), (11229964, 'bl loc.imp.objc_msgSend'), (11229980, 'bl sym.imp.__aeabi_idiv'), (11230052, 'bl method.Vector2.operator_float__'), (11230124, 'bl loc.imp.objc_msgSend'), (11230196, 'bl method.Vector2.operator_float__'), (11230344, 'bl method.Vector2.operator_float__'), (11230416, 'bl method.Vector2.operator_float__'), (11230452, 'bl method.Vector2.operator_float__'), (11230504, 'bl loc.imp.objc_msgSend'), (11230528, 'bl sym.imp.__aeabi_idiv'), (11230600, 'bl method.Vector2.operator_float__'), (11230636, 'bl method.Vector2.operator_float__'), (11230688, 'bl loc.imp.objc_msgSend'), (11230788, 'bl method.Vector2.operator_float__'), (11230824, 'bl method.Vector2.operator_float__'), (11230876, 'bl loc.imp.objc_msgSend'), (11230892, 'bl sym.imp.__aeabi_idiv'), (11230964, 'bl method.Vector2.operator_float__'), (11231000, 'bl method.Vector2.operator_float__'), (11231052, 'bl loc.imp.objc_msgSend'), (11231120, 'bl method.Vector2.operator_float__'), (11231156, 'bl method.Vector2.operator_float__'), (11231248, 'bl method.Vector2.operator_float__'), (11231292, 'bl method.Vector2.operator_float__'), (11231328, 'bl method.Vector2.operator_float__'), (11231376, 'bl method.Vector2.operator_float__'), (11231412, 'bl method.Vector2.operator_float__'), (11231488, 'bl method.Vector2.operator_float__'), (11231524, 'bl method.Vector2.operator_float__'), (11231576, 'bl loc.imp.objc_msgSend'), (11231600, 'bl sym.imp.__aeabi_idiv'), (11231672, 'bl method.Vector2.operator_float__'), (11231708, 'bl method.Vector2.operator_float__'), (11231760, 'bl loc.imp.objc_msgSend'), (11231860, 'bl method.Vector2.operator_float__'), (11231896, 'bl method.Vector2.operator_float__'), (11231948, 'bl loc.imp.objc_msgSend'), (11231964, 'bl sym.imp.__aeabi_idiv'), (11232036, 'bl method.Vector2.operator_float__'), (11232072, 'bl method.Vector2.operator_float__'), (11232124, 'bl loc.imp.objc_msgSend'), (11232200, 'bl method.Vector2.operator_float__'), (11232236, 'bl method.Vector2.operator_float__'), (11232328, 'bl method.Vector2.operator_float__'), (11232372, 'bl method.Vector2.operator_float__'), (11232408, 'bl method.Vector2.operator_float__'), (11232456, 'bl method.Vector2.operator_float__'), (11232492, 'bl method.Vector2.operator_float__'), (11232576, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (11232668, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11232680, 'bl sym.tileIsWater_Tile_'), (11232900, 'blx r2'), (11233052, 'bl sym.tileIsSolid_Tile_'), (11233144, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11233156, 'bl sym.tileIsWater_Tile_'), (11233244, 'bl sym.clamp_float__float__float_'), (11233384, 'bl 0x11c7524'), (11233416, 'bl method.Vector2.operator_float__'), (11233556, 'bl sym.clamp_float__float__float_'), (11233852, 'bl sym.tileIsWater_Tile_'), (11233968, 'bl sym.imp.__aeabi_idiv'), (11234096, 'blx r2'), (11234176, 'blx r2'), (11234420, 'bl loc.imp.objc_msgSend'), (11234444, 'bl sym.imp.__aeabi_idiv'), (11234552, 'bl loc.imp.objc_msgSend'), (11234688, 'bl loc.imp.objc_msgSend'), (11234704, 'bl sym.imp.__aeabi_idiv'), (11234812, 'bl loc.imp.objc_msgSend'), (11235212, 'blx r2'), (11235444, 'blx r2'), (11235624, 'blx r3'), (11235720, 'blx r3'), (11235852, 'blx r2'), (11236408, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11236420, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (11236480, 'bl sym.tileContainsGate_Tile_'), (11236560, 'bl sym.tileIsSolid_Tile_'), (11236660, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11236672, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (11236732, 'bl sym.tileContainsGate_Tile_'), (11236924, 'bl sym.tileIsWater_Tile_'), (11237592, 'bl loc.imp.objc_msgSend'), (11237648, 'bl loc.imp.objc_msgSend'), (11237680, 'bl loc.imp.objc_msgSend'), (11237732, 'bl loc.imp.objc_msgSend'), (11237792, 'bl loc.imp.objc_msgSend'), (11237888, 'bl loc.imp.objc_msgSend'), (11237912, 'bl loc.imp.objc_msgSend'), (11237976, 'bl loc.imp.objc_msgSend'), (11238080, 'bl loc.imp.objc_msgSend'), (11238216, 'bl loc.imp.objc_msgSend'), (11238252, 'bl loc.imp.objc_msgSend'), (11238468, 'bl loc.imp.objc_msgSend'), (11238492, 'bl sym.imp.__aeabi_idiv'), (11238600, 'bl loc.imp.objc_msgSend'), (11238772, 'bl loc.imp.objc_msgSend'), (11238788, 'bl sym.imp.__aeabi_idiv'), (11238896, 'bl loc.imp.objc_msgSend'), (11239064, 'bl 0xab9de8'), (11239220, 'bl 0xab9de8'), (11239448, 'bl loc.imp.objc_msgSend'), (11239508, 'bl 0xab9de8'), (11239612, 'bl 0xab9de8'), (11239732, 'bl 0xab9de8'), (11239868, 'bl 0xab9de8'), (11239988, 'bl 0xab9de8'), (11240252, 'bl loc.imp.objc_msgSend'), (11240368, 'bl loc.imp.objc_msgSend'), (11240484, 'bl loc.imp.objc_msgSend'), (11240508, 'bl sym.imp.__aeabi_idiv'), (11240616, 'bl loc.imp.objc_msgSend'), (11240752, 'bl loc.imp.objc_msgSend'), (11240768, 'bl sym.imp.__aeabi_idiv'), (11240876, 'bl loc.imp.objc_msgSend'), (11240988, 'bl 0xab9de8'), (11241196, 'bl loc.imp.objc_msgSend'), (11241220, 'bl sym.imp.__aeabi_idiv'), (11241328, 'bl loc.imp.objc_msgSend'), (11241468, 'bl loc.imp.objc_msgSend'), (11241484, 'bl sym.imp.__aeabi_idiv'), (11241592, 'bl loc.imp.objc_msgSend'), (11241900, 'bl loc.imp.objc_msgSend'), (11241924, 'bl sym.imp.__aeabi_idiv'), (11242032, 'bl loc.imp.objc_msgSend'), (11242196, 'bl loc.imp.objc_msgSend'), (11242212, 'bl sym.imp.__aeabi_idiv'), (11242320, 'bl loc.imp.objc_msgSend'), (11242608, 'bl 0xab9de8'), (11242812, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11242824, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (11242972, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11242984, 'bl sym.tileIsSolid_Tile_'), (11243192, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11243204, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (11243388, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11243400, 'bl sym.tileIsSolid_Tile_'), (11243760, 'bl loc.imp.objc_msgSend'), (11243784, 'bl sym.imp.__aeabi_idiv'), (11243892, 'bl loc.imp.objc_msgSend'), (11244028, 'bl loc.imp.objc_msgSend'), (11244044, 'bl sym.imp.__aeabi_idiv'), (11244152, 'bl loc.imp.objc_msgSend'), (11244472, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11244484, 'bl sym.tileIsSolid_Tile_'), (11244636, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11244648, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (11244668, 'bl sym.tileContainsGate_Tile_'), (11244768, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11244780, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (11244800, 'bl sym.tileContainsGate_Tile_'), (11244900, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11244912, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (11244932, 'bl sym.tileIsWater_Tile_'), (11245028, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11245120, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11245132, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (11245152, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (11245252, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11245264, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (11245364, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11245376, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (11245744, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11245756, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (11246136, 'bl 0xab9de8'), (11246228, 'bl 0xab9de8'), (11246628, 'bl 0xab9de8')],
        branches=[(11215348, 'beq', 11215356), (11215352, 'b', 11246968), (11215388, 'bpl', 11215404), (11215400, 'b', 11215412), (11215460, 'beq', 11215776), (11215540, 'blt', 11215748), (11215576, 'bne', 11215708), (11215628, 'ble', 11215676), (11215748, 'b', 11246968), (11215988, 'beq', 11216168), (11216176, 'beq', 11216480), (11216256, 'bne', 11216320), (11216368, 'beq', 11216476), (11216476, 'b', 11216480), (11216520, 'bpl', 11216652), (11217000, 'blt', 11217116), (11217112, 'b', 11217400), (11217232, 'bge', 11217352), (11217344, 'b', 11217392), (11217408, 'bne', 11217452), (11217448, 'beq', 11223832), (11217452, 'b', 11217456), (11217496, 'ble', 11217592), (11217588, 'b', 11217456), (11217716, 'beq', 11218352), (11217736, 'beq', 11218352), (11217864, 'blt', 11217980), (11217976, 'b', 11218260), (11218096, 'bge', 11218212), (11218208, 'b', 11218252), (11218268, 'beq', 11222316), (11218308, 'bne', 11222316), (11218328, 'bne', 11218352), (11218348, 'beq', 11222316), (11218476, 'blt', 11218592), (11218588, 'b', 11218872), (11218708, 'bge', 11218824), (11218820, 'b', 11218864), (11218880, 'beq', 11220504), (11219068, 'blt', 11219204), (11219180, 'b', 11219512), (11219320, 'bge', 11219464), (11219432, 'b', 11219504), (11219520, 'ble', 11219564), (11219560, 'bgt', 11220160), (11219688, 'blt', 11219820), (11219800, 'b', 11220108), (11219936, 'bge', 11220060), (11220048, 'b', 11220100), (11220116, 'bge', 11220500), (11220156, 'bpl', 11220500), (11220268, 'bne', 11220448), (11220384, 'bne', 11220448), (11220428, 'b', 11220496), (11220496, 'b', 11220500), (11220500, 'b', 11220504), (11220744, 'beq', 11221408), (11220764, 'beq', 11221408), (11220892, 'blt', 11221016), (11221004, 'b', 11221316), (11221132, 'bge', 11221268), (11221244, 'b', 11221308), (11221324, 'beq', 11222176), (11221364, 'bne', 11222176), (11221384, 'bne', 11221408), (11221404, 'beq', 11222176), (11221444, 'beq', 11222168), (11221536, 'ble', 11221580), (11221576, 'bgt', 11221660), (11221616, 'bge', 11222164), (11221656, 'bpl', 11222164), (11221696, 'bpl', 11222124), (11221820, 'ble', 11222120), (11221876, 'bne', 11222120), (11222120, 'b', 11222124), (11222164, 'b', 11222168), (11222168, 'b', 11222284), (11222284, 'b', 11222424), (11222456, 'bne', 11223828), (11222512, 'beq', 11222720), (11222616, 'beq', 11222716), (11222716, 'b', 11222720), (11222772, 'bpl', 11223508), (11222788, 'beq', 11223508), (11222804, 'beq', 11223508), (11222896, 'bne', 11223508), (11223004, 'beq', 11223504), (11223104, 'bne', 11223504), (11223212, 'bpl', 11223304), (11223228, 'b', 11223316), (11223504, 'b', 11223508), (11223560, 'ble', 11223824), (11223600, 'bhi', 11223824), (11223640, 'bhi', 11223824), (11223824, 'b', 11223828), (11223828, 'b', 11223832), (11224004, 'ble', 11224840), (11224160, 'bne', 11224224), (11224220, 'ble', 11224820), (11224328, 'ble', 11224428), (11224592, 'bpl', 11224684), (11224676, 'b', 11224816), (11224692, 'bne', 11224812), (11224748, 'bpl', 11224812), (11224812, 'b', 11224816), (11224816, 'b', 11224820), (11224820, 'b', 11225392), (11224928, 'bpl', 11225388), (11225036, 'bpl', 11225136), (11225300, 'ble', 11225384), (11225384, 'b', 11225388), (11225388, 'b', 11225392), (11225400, 'beq', 11227604), (11225440, 'ble', 11226524), (11225648, 'blt', 11225860), (11225840, 'b', 11226376), (11226056, 'bpl', 11226268), (11226248, 'b', 11226360), (11226404, 'bpl', 11226504), (11226504, 'b', 11227580), (11226728, 'blt', 11226944), (11226920, 'b', 11227448), (11227140, 'bpl', 11227340), (11227332, 'b', 11227432), (11227476, 'ble', 11227576), (11227576, 'b', 11227580), (11227580, 'b', 11232516), (11227784, 'blt', 11227964), (11227952, 'b', 11228408), (11228136, 'bpl', 11228312), (11228304, 'b', 11228392), (11228436, 'ble', 11229428), (11228684, 'blt', 11228856), (11228852, 'b', 11229296), (11229028, 'bpl', 11229200), (11229196, 'b', 11229280), (11229316, 'bpl', 11229408), (11229408, 'b', 11230364), (11229444, 'bpl', 11230360), (11229676, 'blt', 11229840), (11229832, 'b', 11230256), (11230004, 'bpl', 11230172), (11230160, 'b', 11230248), (11230272, 'ble', 11230356), (11230356, 'b', 11230360), (11230360, 'b', 11230364), (11230552, 'blt', 11230736), (11230724, 'b', 11231184), (11230916, 'bpl', 11231096), (11231088, 'b', 11231176), (11231196, 'ble', 11231436), (11231348, 'bpl', 11231424), (11231424, 'b', 11232512), (11231624, 'blt', 11231808), (11231796, 'b', 11232264), (11231988, 'bpl', 11232176), (11232160, 'b', 11232256), (11232276, 'bpl', 11232508), (11232428, 'ble', 11232504), (11232504, 'b', 11232508), (11232508, 'b', 11232512), (11232512, 'b', 11232516), (11232588, 'beq', 11233048), (11232692, 'beq', 11232844), (11232836, 'b', 11233040), (11232912, 'beq', 11232932), (11233040, 'b', 11233692), (11233064, 'beq', 11233688), (11233168, 'beq', 11233392), (11233360, 'b', 11233684), (11233480, 'ble', 11233680), (11233680, 'b', 11233684), (11233684, 'b', 11233688), (11233688, 'b', 11233692), (11233724, 'bne', 11233848), (11233820, 'b', 11234036), (11233864, 'beq', 11234032), (11234032, 'b', 11234036), (11234108, 'bne', 11234284), (11234204, 'beq', 11234284), (11234240, 'beq', 11234284), (11234316, 'beq', 11234972), (11234456, 'blt', 11234588), (11234580, 'b', 11234920), (11234716, 'bge', 11234852), (11234840, 'b', 11234912), (11234928, 'bne', 11234972), (11235004, 'beq', 11235328), (11235040, 'bne', 11235328), (11235076, 'bne', 11235116), (11235112, 'beq', 11235228), (11235148, 'beq', 11235328), (11235224, 'bne', 11235328), (11235264, 'bpl', 11235328), (11235308, 'b', 11235368), (11235400, 'beq', 11235460), (11235456, 'beq', 11236188), (11235492, 'beq', 11236188), (11235644, 'beq', 11235788), (11235740, 'bne', 11235788), (11235808, 'beq', 11235948), (11235864, 'bne', 11235948), (11235900, 'beq', 11235948), (11235936, 'beq', 11235948), (11235956, 'beq', 11236184), (11235992, 'beq', 11236064), (11236048, 'b', 11236084), (11236080, 'b', 11236084), (11236144, 'beq', 11236180), (11236180, 'b', 11236184), (11236184, 'b', 11236188), (11236268, 'ble', 11236980), (11236432, 'beq', 11236556), (11236472, 'bne', 11236496), (11236492, 'bne', 11236556), (11236528, 'b', 11236976), (11236572, 'beq', 11236972), (11236684, 'beq', 11236968), (11236724, 'bne', 11236748), (11236744, 'bne', 11236968), (11236896, 'bne', 11236964), (11236964, 'b', 11236968), (11236968, 'b', 11236972), (11236972, 'b', 11236976), (11236976, 'b', 11236980), (11237012, 'beq', 11237300), (11237048, 'bne', 11237300), (11237168, 'bpl', 11237184), (11237180, 'b', 11237192), (11237248, 'b', 11237332), (11237364, 'bne', 11243492), (11237400, 'bne', 11238264), (11237440, 'ble', 11238260), (11237508, 'bhi', 11238256), (11237812, 'beq', 11238084), (11238256, 'b', 11238260), (11238260, 'b', 11238264), (11238296, 'bne', 11243488), (11238364, 'bhi', 11243484), (11238504, 'blt', 11238672), (11238628, 'b', 11239000), (11238800, 'bge', 11238932), (11238924, 'b', 11238992), (11239008, 'beq', 11239064), (11239060, 'bpl', 11243484), (11239156, 'ble', 11239456), (11239256, 'ble', 11239452), (11239308, 'ble', 11239356), (11239344, 'b', 11239388), (11239452, 'b', 11239456), (11239504, 'bpl', 11239612), (11239588, 'b', 11239692), (11239864, 'ble', 11239928), (11239924, 'b', 11240100), (11239984, 'bge', 11240056), (11240044, 'b', 11240096), (11240096, 'b', 11240100), (11240152, 'bpl', 11242496), (11240264, 'bne', 11240384), (11240380, 'beq', 11242496), (11240520, 'blt', 11240652), (11240644, 'b', 11240976), (11240780, 'bge', 11240908), (11240904, 'b', 11240968), (11240984, 'bne', 11242492), (11241000, 'ble', 11241048), (11241040, 'b', 11241084), (11241232, 'blt', 11241368), (11241356, 'b', 11241712), (11241496, 'bge', 11241644), (11241620, 'b', 11241704), (11241720, 'ble', 11241800), (11241756, 'b', 11242488), (11241936, 'blt', 11242096), (11242060, 'b', 11242440), (11242224, 'bge', 11242372), (11242348, 'b', 11242432), (11242448, 'bge', 11242484), (11242484, 'b', 11242488), (11242488, 'b', 11242492), (11242492, 'b', 11242496), (11242604, 'beq', 11243480), (11242728, 'ble', 11243068), (11242836, 'beq', 11242896), (11242888, 'b', 11243052), (11242996, 'beq', 11243048), (11243048, 'b', 11243052), (11243052, 'b', 11243476), (11243108, 'bpl', 11243472), (11243216, 'beq', 11243312), (11243268, 'b', 11243468), (11243412, 'beq', 11243464), (11243464, 'b', 11243468), (11243468, 'b', 11243472), (11243472, 'b', 11243476), (11243476, 'b', 11243480), (11243480, 'b', 11243484), (11243484, 'b', 11243488), (11243488, 'b', 11243492), (11243524, 'bne', 11245912), (11243564, 'bne', 11245912), (11243620, 'ble', 11245912), (11243656, 'bne', 11244396), (11243796, 'blt', 11243928), (11243920, 'b', 11244260), (11244056, 'bge', 11244192), (11244180, 'b', 11244252), (11244268, 'bne', 11244392), (11244340, 'b', 11246968), (11244392, 'b', 11244396), (11244496, 'beq', 11245908), (11244660, 'beq', 11245904), (11244680, 'bne', 11245904), (11244792, 'beq', 11245900), (11244812, 'bne', 11245900), (11244924, 'bne', 11244948), (11244944, 'beq', 11245896), (11245144, 'beq', 11245660), (11245164, 'beq', 11245660), (11245276, 'beq', 11245520), (11245388, 'bne', 11245508), (11245468, 'bne', 11245504), (11245504, 'b', 11245508), (11245508, 'b', 11245636), (11245596, 'bne', 11245632), (11245632, 'b', 11245636), (11245636, 'b', 11245892), (11245768, 'beq', 11245888), (11245848, 'bne', 11245884), (11245884, 'b', 11245888), (11245888, 'b', 11245892), (11245892, 'b', 11245896), (11245896, 'b', 11245900), (11245900, 'b', 11245904), (11245904, 'b', 11245908), (11245908, 'b', 11245912), (11246016, 'ble', 11246068), (11246132, 'bhi', 11246292), (11246344, 'bgt', 11246432), (11246380, 'bne', 11246432), (11246396, 'beq', 11246484), (11246412, 'beq', 11246484), (11246428, 'beq', 11246484), (11246472, 'b', 11246748), (11246548, 'bpl', 11246744), (11246744, 'b', 11246748), (11246884, 'bpl', 11246904), (11246896, 'b', 11246912)],
        semantics=("[DonkeyLike update:accurateDT:isSimulation:] (imp 0x00ab2130, 7986w): the animal tick - the 114 Vector `operator float*` calls + objc x98 + **`__aeabi_idiv` x40** + **`tileIsAirWaterOrSnow` x18** (the pathing probes over air/water/snow!) + `tileAtWorldPositionLoaded` x24 + consts 0x384 (900)/0xff/**0x1518 (5400)**/0x28/0xa/0x10: the animal's movement/AI substrate checks.\n"),
    ),
    dict(
        name='dl_15',
        method='DonkeyLike -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        types='v156@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76i140i144i148i152',
        start=11257096,
        end=11282248,
        disasm='disasm_worldtileloader_dl_15.txt',
        base_add=11257136,
        base_literal=11261152,
        boundary='ARM.exidx end 0x00ac2748 (listing bound); next ObjC IMP 0x00ac2d08 DonkeyLike -[drawSubClassStuff:projectionMatrix:modelViewMatrix:]',
        selectors={
                 0xabd70c: (15227380, 'worldWidthMacro'),
                 0xabdd00: (15227532, 'macroTiles'),
                 0xabdd08: (15227536, 'dayColor'),
                 0xabdd0c: (15227540, 'paused'),
                 0xabdd3c: (15227516, 'instance'),
                 0xabdd44: (15227544, 'addParticleAtPos:velocity:color:gravityType:life:scale:'),
                 0xabdd50: (15227520, 'multiSoundNamed:'),
                 0xabdd58: (15227388, 'playAtPosition:'),
                 0xabdd5c: (15227552, 'program'),
                 0xabdd64: (15227548, 'setupMatrices:dt:'),
                 0xabdd6c: (15227564, 'intValue'),
                 0xabdd70: (15227560, 'objectAtIndex:'),
                 0xabdd74: (15227556, 'uniformLocations'),
                 0xabdd8c: (15227568, 'name'),
                 0xabdd94: (15227572, 'draw'),
                 0xac2744: (15227576, 'drawSubClassStuff:projectionMatrix:modelViewMatrix:'),
        },
        imports={
                 0xabdcfc: (17151904, 'objc_msgSend'),
                 0xabdd54: (16365384, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xabd700: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xabd708: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xabd72c: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xabdd04: (17157400, 'OBJC_IVAR_$_NPC.visible', 57),
                 0xabdd10: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0xabdd14: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0xabdd18: (17158244, 'OBJC_IVAR_$_DonkeyLike.falling', 316),
                 0xabdd1c: (17158288, 'OBJC_IVAR_$_DonkeyLike.walkTimer', 264),
                 0xabdd24: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0xabdd28: (17158240, 'OBJC_IVAR_$_DonkeyLike.actualXSpeed', 284),
                 0xabdd30: (17165036, 'OBJC_IVAR_$_DonkeyLike.inWater', 317),
                 0xabdd60: (17158188, 'OBJC_IVAR_$_DonkeyLike.shader', 208),
                 0xabdd78: (17158184, 'OBJC_IVAR_$_DonkeyLike.useColoredShader', 824),
                 0xabdd7c: (17158180, 'OBJC_IVAR_$_DonkeyLike.bodyColor', 808),
                 0xabdd80: (17158252, 'OBJC_IVAR_$_DonkeyLike.bodyMatrix', 336),
                 0xabdd88: (17158172, 'OBJC_IVAR_$_DonkeyLike.bodyTexture', 212),
                 0xabdd90: (17158212, 'OBJC_IVAR_$_DonkeyLike.bodyCube', 228),
                 0xabdd98: (17158308, 'OBJC_IVAR_$_DonkeyLike.neckMatrix', 400),
                 0xac04c0: (17158168, 'OBJC_IVAR_$_DonkeyLike.neckTexture', 216),
                 0xac04c4: (17158200, 'OBJC_IVAR_$_DonkeyLike.neckCube', 232),
                 0xac04c8: (17158316, 'OBJC_IVAR_$_DonkeyLike.headMatrix', 464),
                 0xac04cc: (17158164, 'OBJC_IVAR_$_DonkeyLike.headTexture', 220),
                 0xac04d0: (17158204, 'OBJC_IVAR_$_DonkeyLike.headCube', 236),
                 0xac04d4: (17158248, 'OBJC_IVAR_$_DonkeyLike.leftArmMatrix', 528),
                 0xac04d8: (17158160, 'OBJC_IVAR_$_DonkeyLike.legTexture', 224),
                 0xac04dc: (17158196, 'OBJC_IVAR_$_DonkeyLike.legCube', 240),
                 0xac04e0: (17158256, 'OBJC_IVAR_$_DonkeyLike.rightArmMatrix', 592),
                 0xac04e4: (17158260, 'OBJC_IVAR_$_DonkeyLike.leftLegMatrix', 656),
                 0xac2740: (17158264, 'OBJC_IVAR_$_DonkeyLike.rightLegMatrix', 720),
        },
        classes={
                 0xabdd34: (15249384, 'OBJC_CLASS_$_ParticleEmitter'),
                 0xabdd48: (15249380, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(11257096, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11282244, 'invalid')],
        calls=[(11257976, 'bl loc.imp.objc_msgSend'), (11258000, 'bl sym.imp.__aeabi_idiv'), (11258072, 'bl loc.imp.objc_msgSend'), (11258208, 'bl loc.imp.objc_msgSend'), (11258224, 'bl sym.imp.__aeabi_idiv'), (11258296, 'bl loc.imp.objc_msgSend'), (11258440, 'bl loc.imp.objc_msgSend'), (11258464, 'bl sym.imp.__aeabi_idiv'), (11258536, 'bl loc.imp.objc_msgSend'), (11258672, 'bl loc.imp.objc_msgSend'), (11258688, 'bl sym.imp.__aeabi_idiv'), (11258760, 'bl loc.imp.objc_msgSend'), (11259080, 'bl method.Vector2.operator_float__'), (11259148, 'bl loc.imp.objc_msgSend'), (11259172, 'bl sym.imp.__aeabi_idiv'), (11259272, 'bl loc.imp.objc_msgSend'), (11259308, 'bl method.Vector2.operator_float__'), (11259364, 'bl method.Vector2.operator_float__'), (11259436, 'bl loc.imp.objc_msgSend'), (11259452, 'bl sym.imp.__aeabi_idiv'), (11259552, 'bl loc.imp.objc_msgSend'), (11259588, 'bl method.Vector2.operator_float__'), (11259736, 'blx r2'), (11259784, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (11259988, 'bl loc.imp.objc_msgSend_stret'), (11260028, 'bl sym.imp.memset'), (11260508, 'bl method.Vector.Vector_float__float__float_'), (11260528, 'bl method.Vector.operator_float__'), (11260600, 'bl method.Vector.operator_float__'), (11260652, 'bl method.Vector.operator_float__'), (11260724, 'bl method.Vector.operator_float__'), (11260776, 'bl method.Vector.operator_float__'), (11260848, 'bl method.Vector.operator_float__'), (11260920, 'bl method.Vector.Vector_float__float__float_'), (11260940, 'bl method.Vector.operator_float__'), (11261060, 'bl method.Vector.operator_float__'), (11261088, 'bl method.Vector.operator_float__'), (11261208, 'bl method.Vector.operator_float__'), (11261236, 'bl method.Vector.operator_float__'), (11261360, 'bl method.Vector.operator_float__'), (11261440, 'blx r3'), (11262040, 'bl sym.imp.__wrap_fmodf'), (11262084, 'bl sym.imp.__wrap_fmodf'), (11262168, 'bl method.Vector.Vector_float__float__float__float_'), (11262184, 'bl method.Vector.operator_float__'), (11262200, 'bl method.Vector.operator_float__'), (11262216, 'bl method.Vector.operator_float__'), (11262252, 'bl method.Vector.Vector_float__float__float__float_'), (11262312, 'bl sym.Vector::operator_Vector_'), (11262444, 'bl method.Vector2.operator_float__'), (11262508, 'bl method.Vector.Vector_float__float__float_'), (11262584, 'bl loc.imp.objc_msgSend'), (11262592, 'bl 0xab9de8'), (11262644, 'bl 0xab9de8'), (11262712, 'bl method.Vector.Vector_float__float__float_'), (11262776, 'bl method.Vector.operator_Vector_'), (11262780, 'bl 0xab9de8'), (11262828, 'bl 0xab9de8'), (11262888, 'bl method.Vector.Vector_float__float__float_'), (11263188, 'bl loc.imp.objc_msgSend'), (11263432, 'bl sym.imp.__wrap_fmodf'), (11263476, 'bl sym.imp.__wrap_fmodf'), (11263532, 'bl loc.imp.objc_msgSend'), (11263556, 'bl loc.imp.objc_msgSend'), (11263620, 'bl loc.imp.objc_msgSend'), (11263812, 'bl loc.imp.objc_msgSend'), (11263852, 'blx r3'), (11263856, 'bl sym.imp.__wrap_glUseProgram'), (11263988, 'blx r6'), (11264008, 'blx r3'), (11264024, 'blx r2'), (11264032, 'bl sym.imp.__wrap_glUniform1i'), (11264040, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (11264176, 'blx r6'), (11264196, 'blx r3'), (11264212, 'blx r2'), (11264228, 'bl method.Vector.operator_float__'), (11264256, 'bl method.Vector.operator_float__'), (11264284, 'bl method.Vector.operator_float__'), (11264348, 'bl sym.imp.__wrap_glUniform4f'), (11264508, 'blx r2'), (11264528, 'blx r3'), (11264544, 'blx r2'), (11264576, 'bl method.Vector.operator_float__'), (11264620, 'bl method.Vector.operator_float__'), (11264664, 'bl method.Vector.operator_float__'), (11264728, 'bl sym.imp.__wrap_glUniform4f'), (11265752, 'bl 0xac2748'), (11266668, 'bl 0xac2748'), (11266720, 'bl loc.imp.objc_msgSend'), (11266756, 'bl loc.imp.objc_msgSend'), (11266780, 'bl loc.imp.objc_msgSend'), (11266800, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (11266836, 'bl loc.imp.objc_msgSend'), (11266864, 'bl loc.imp.objc_msgSend'), (11266880, 'bl loc.imp.objc_msgSend'), (11266896, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (11266944, 'bl loc.imp.objc_msgSend'), (11266972, 'bl sym.imp.__wrap_glBindTexture'), (11267020, 'bl loc.imp.objc_msgSend'), (11267892, 'bl 0xac2748'), (11268996, 'bl 0xac2748'), (11269164, 'bl loc.imp.objc_msgSend'), (11269184, 'bl loc.imp.objc_msgSend'), (11269200, 'bl loc.imp.objc_msgSend'), (11269216, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (11269252, 'bl loc.imp.objc_msgSend'), (11269272, 'bl loc.imp.objc_msgSend'), (11269288, 'bl loc.imp.objc_msgSend'), (11269304, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (11269344, 'bl loc.imp.objc_msgSend'), (11269364, 'bl sym.imp.__wrap_glBindTexture'), (11269404, 'bl loc.imp.objc_msgSend'), (11270276, 'bl 0xac2748'), (11271380, 'bl 0xac2748'), (11271548, 'bl loc.imp.objc_msgSend'), (11271568, 'bl loc.imp.objc_msgSend'), (11271584, 'bl loc.imp.objc_msgSend'), (11271600, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (11271636, 'bl loc.imp.objc_msgSend'), (11271656, 'bl loc.imp.objc_msgSend'), (11271672, 'bl loc.imp.objc_msgSend'), (11271688, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (11271728, 'bl loc.imp.objc_msgSend'), (11271748, 'bl sym.imp.__wrap_glBindTexture'), (11271788, 'bl loc.imp.objc_msgSend'), (11272660, 'bl 0xac2748'), (11273808, 'bl 0xac2748'), (11273976, 'bl loc.imp.objc_msgSend'), (11273996, 'bl loc.imp.objc_msgSend'), (11274012, 'bl loc.imp.objc_msgSend'), (11274028, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (11274064, 'bl loc.imp.objc_msgSend'), (11274084, 'bl loc.imp.objc_msgSend'), (11274100, 'bl loc.imp.objc_msgSend'), (11274116, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (11274164, 'bl loc.imp.objc_msgSend'), (11274184, 'bl sym.imp.__wrap_glBindTexture'), (11274232, 'bl loc.imp.objc_msgSend'), (11275104, 'bl 0xac2748'), (11276208, 'bl 0xac2748'), (11276376, 'bl loc.imp.objc_msgSend'), (11276396, 'bl loc.imp.objc_msgSend'), (11276412, 'bl loc.imp.objc_msgSend'), (11276428, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (11276464, 'bl loc.imp.objc_msgSend'), (11276484, 'bl loc.imp.objc_msgSend'), (11276500, 'bl loc.imp.objc_msgSend'), (11276516, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (11276552, 'bl loc.imp.objc_msgSend'), (11277424, 'bl 0xac2748'), (11278528, 'bl 0xac2748'), (11278696, 'bl loc.imp.objc_msgSend'), (11278716, 'bl loc.imp.objc_msgSend'), (11278732, 'bl loc.imp.objc_msgSend'), (11278748, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (11278784, 'bl loc.imp.objc_msgSend'), (11278804, 'bl loc.imp.objc_msgSend'), (11278820, 'bl loc.imp.objc_msgSend'), (11278836, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (11278872, 'bl loc.imp.objc_msgSend'), (11278892, 'bl sym.imp.__wrap_glBindTexture'), (11278928, 'bl loc.imp.objc_msgSend'), (11279800, 'bl 0xac2748'), (11280904, 'bl 0xac2748'), (11281072, 'bl loc.imp.objc_msgSend'), (11281092, 'bl loc.imp.objc_msgSend'), (11281108, 'bl loc.imp.objc_msgSend'), (11281124, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (11281160, 'bl loc.imp.objc_msgSend'), (11281180, 'bl loc.imp.objc_msgSend'), (11281196, 'bl loc.imp.objc_msgSend'), (11281212, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (11281248, 'bl loc.imp.objc_msgSend'), (11282220, 'bl loc.imp.objc_msgSend'), (11282228, 'bl sym.imp.__wrap_glDisableVertexAttribArray')],
        branches=[(11258012, 'blt', 11258112), (11258108, 'b', 11258336), (11258236, 'bge', 11258332), (11258332, 'b', 11258336), (11258476, 'blt', 11258576), (11258572, 'b', 11258800), (11258700, 'bge', 11258796), (11258796, 'b', 11258800), (11258844, 'blt', 11258992), (11258892, 'bgt', 11258992), (11258940, 'blt', 11258992), (11258988, 'ble', 11258996), (11258992, 'b', 11282232), (11259200, 'ble', 11259336), (11259332, 'b', 11259616), (11259480, 'bpl', 11259612), (11259612, 'b', 11259616), (11259812, 'beq', 11259836), (11259832, 'bne', 11259876), (11259872, 'b', 11282232), (11259968, 'beq', 11259996), (11259992, 'b', 11260032), (11260164, 'bpl', 11260188), (11260184, 'b', 11260204), (11260252, 'bpl', 11260276), (11260272, 'b', 11260292), (11260340, 'ble', 11260412), (11260980, 'bpl', 11261008), (11261000, 'b', 11261024), (11261128, 'bpl', 11261156), (11261148, 'b', 11261172), (11261276, 'bpl', 11261308), (11261296, 'b', 11261324), (11261452, 'bne', 11263672), (11261492, 'bne', 11263668), (11261568, 'beq', 11261756), (11261692, 'b', 11261956), (11261812, 'ble', 11261952), (11261952, 'b', 11261956), (11261992, 'beq', 11263628), (11262060, 'ble', 11263628), (11262104, 'bpl', 11263628), (11262548, 'bge', 11263388), (11263212, 'b', 11262536), (11263452, 'ble', 11263624), (11263496, 'bpl', 11263624), (11263624, 'b', 11263628), (11263668, 'b', 11263672), (11264388, 'beq', 11264732), (11273404, 'b', 11273448)],
        semantics=('[DonkeyLike draw:...] (imp 0x00abc508, 6656w): the animal render - objc x73 + Vector float* x21 + **`glUniformMatrix4fv` x14** + the helper 0xac2748 x14 + `__aeabi_idiv` x6 + consts 0x10/0x400/0xff/0x3f80 (1.0f)/0xcecd/0xdadc/**0xde1 (GL_TEXTURE_2D)**: the body-part render.\n'),
    ),
    dict(
        name='dl_16',
        method='DonkeyLike -[maxHealth]',
        types='S8@0:4',
        start=11284208,
        end=11284240,
        disasm='disasm_worldtileloader_dl_16.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00ac2f10 (listing bound); next ObjC IMP 0x00ac2f10 DonkeyLike -[tapIsWithinBodyRadius:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11284208, 'sub sp, sp, 8'), (11284236, 'andeq r0, r0, r0')],
        calls=[],
        branches=[],
        semantics=('[DonkeyLike maxHealth] (imp 0x00ac2ef0, 8w): the health cap.\n'),
    ),
    dict(
        name='dl_17',
        method='DonkeyLike -[tapIsWithinBodyRadius:]',
        types='c16@0:4{Vector2=[2f]}8',
        start=11284240,
        end=11285996,
        disasm='disasm_worldtileloader_dl_17.txt',
        base_add=11284256,
        base_literal=11285992,
        boundary='ARM.exidx end 0x00ac35ec (listing bound); next ObjC IMP 0x00ac35ec DonkeyLike -[die:]',
        selectors={
                 0xac35c8: (15227380, 'worldWidthMacro'),
        },
        imports={},
        ivars={
                 0xac35b4: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0xac35b8: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xac35bc: (17165060, 'OBJC_IVAR_$_DonkeyLike.bodyRotation', 256),
                 0xac35c0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(11284240, 'push {fp, lr}'), (11285992, 'subseq ip, sb, ip, asr 23')],
        calls=[(11284328, 'bl method.Vector2.operator_float__'), (11284368, 'bl method.Vector2.operator_float__'), (11284412, 'bl method.Vector2.operator_float__'), (11284452, 'bl method.Vector2.operator_float__'), (11284560, 'bl method.Vector2.operator_float__'), (11284652, 'bl method.Vector2.operator_float__'), (11284708, 'bl method.Vector2.operator_float__'), (11284760, 'bl method.Vector2.operator_float__'), (11284860, 'bl method.Vector2.operator_float__'), (11284916, 'bl loc.imp.objc_msgSend'), (11284940, 'bl sym.imp.__aeabi_idiv'), (11284984, 'bl method.Vector2.operator_float__'), (11285040, 'bl loc.imp.objc_msgSend'), (11285104, 'bl method.Vector2.operator_float__'), (11285160, 'bl loc.imp.objc_msgSend'), (11285176, 'bl sym.imp.__aeabi_idiv'), (11285220, 'bl method.Vector2.operator_float__'), (11285276, 'bl loc.imp.objc_msgSend'), (11285332, 'bl method.Vector2.operator_float__'), (11285400, 'bl method.Vector2.operator_float__'), (11285456, 'bl loc.imp.objc_msgSend'), (11285480, 'bl sym.imp.__aeabi_idiv'), (11285524, 'bl method.Vector2.operator_float__'), (11285580, 'bl loc.imp.objc_msgSend'), (11285644, 'bl method.Vector2.operator_float__'), (11285700, 'bl loc.imp.objc_msgSend'), (11285716, 'bl sym.imp.__aeabi_idiv'), (11285760, 'bl method.Vector2.operator_float__'), (11285816, 'bl loc.imp.objc_msgSend'), (11285860, 'bl method.Vector2.operator_float__')],
        branches=[(11284308, 'beq', 11284324), (11284320, 'b', 11285928), (11284404, 'ble', 11285920), (11284492, 'bpl', 11285920), (11284532, 'ble', 11284684), (11284680, 'b', 11284836), (11284964, 'blt', 11285080), (11285076, 'b', 11285360), (11285200, 'bpl', 11285328), (11285312, 'b', 11285352), (11285372, 'ble', 11285916), (11285504, 'blt', 11285620), (11285616, 'b', 11285888), (11285740, 'bpl', 11285856), (11285852, 'b', 11285880), (11285900, 'bpl', 11285916), (11285912, 'b', 11285928), (11285916, 'b', 11285920)],
        semantics=('[DonkeyLike tapIsWithinBodyRadius:] (imp 0x00ac2f10, 439w): the tap hit test - Vector float* x18 + objc x8 + `__aeabi_idiv` x4.\n'),
    ),
    dict(
        name='dl_18',
        method='DonkeyLike -[die:]',
        types='v12@0:4@8',
        start=11285996,
        end=11286556,
        disasm='disasm_worldtileloader_dl_18.txt',
        base_add=11286012,
        base_literal=11286552,
        boundary='ARM.exidx end 0x00ac381c (listing bound); next ObjC IMP 0x00ac381c DonkeyLike -[reactToBeingHit]',
        selectors={
                 0xac3800: (15227580, 'die:'),
                 0xac3810: (15227524, 'playAtPosition:afterDelay:'),
        },
        imports={
                 0xac37fc: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0xac37e8: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0xac37f0: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0xac37f4: (17158236, 'OBJC_IVAR_$_DonkeyLike.babySound', 244),
                 0xac37f8: (17158232, 'OBJC_IVAR_$_DonkeyLike.adultSound', 248),
                 0xac3808: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xac3814: (17158228, 'OBJC_IVAR_$_DonkeyLike.deathSound', 252),
        },
        classes={
                 0xac3804: (15253100, 'OBJC_CLASS_$_DonkeyLike'),
        },
        instructions=[(11285996, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11286552, 'ldrsheq ip, [sb], -0x40')],
        calls=[(11286344, 'bl loc.imp.objc_msgSend'), (11286444, 'bl loc.imp.objc_msgSend'), (11286488, 'blx r3')],
        branches=[(11286060, 'bne', 11286496), (11286112, 'ble', 11286152), (11286148, 'b', 11286184), (11286492, 'b', 11286496)],
        semantics=('[DonkeyLike die:] (imp 0x00ac35ec, 140w): the death handler.\n'),
    ),
    dict(
        name='dl_19',
        method='DonkeyLike -[reactToBeingHit]',
        types='v8@0:4',
        start=11286556,
        end=11286924,
        disasm='disasm_worldtileloader_dl_19.txt',
        base_add=11286572,
        base_literal=11286920,
        boundary='ARM.exidx end 0x00ac398c (listing bound); next ObjC IMP 0x00ac398c DonkeyLike -[hitWithForce:blockhead:]',
        selectors={
                 0xac3964: (15227484, 'jumps'),
                 0xac3984: (15227524, 'playAtPosition:afterDelay:'),
        },
        imports={
                 0xac3960: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xac3968: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xac3970: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0xac3974: (17158236, 'OBJC_IVAR_$_DonkeyLike.babySound', 244),
                 0xac3978: (17158232, 'OBJC_IVAR_$_DonkeyLike.adultSound', 248),
                 0xac397c: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={},
        instructions=[(11286556, 'push {fp, lr}'), (11286920, 'subseq ip, sb, r0, asr 5')],
        calls=[(11286612, 'blx r3'), (11286868, 'bl loc.imp.objc_msgSend')],
        branches=[(11286624, 'beq', 11286664), (11286660, 'bne', 11286872), (11286712, 'ble', 11286752), (11286748, 'b', 11286784)],
        semantics=('[DonkeyLike reactToBeingHit] (imp 0x00ac381c, 92w): the hit reaction.\n'),
    ),
    dict(
        name='dl_20',
        method='DonkeyLike -[hitWithForce:blockhead:]',
        types='v16@0:4i8@12',
        start=11286924,
        end=11289184,
        disasm='disasm_worldtileloader_dl_20.txt',
        base_add=11286940,
        base_literal=11289180,
        boundary='ARM.exidx end 0x00ac4260 (listing bound); next ObjC IMP 0x00ac4260 DonkeyLike -[renderPos]',
        selectors={
                 0xac41fc: (15227432, 'hitWithForce:blockhead:'),
                 0xac4230: (15227380, 'worldWidthMacro'),
        },
        imports={
                 0xac41f8: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0xac4204: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0xac4208: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xac420c: (17157392, 'OBJC_IVAR_$_NPC.beingControlled', 128),
                 0xac4210: (17165008, 'OBJC_IVAR_$_DonkeyLike.jumpActionSendValue', 325),
                 0xac4214: (17165016, 'OBJC_IVAR_$_DonkeyLike.jumpActionQueued', 296),
                 0xac4218: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xac421c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xac4220: (17165004, 'OBJC_IVAR_$_DonkeyLike.targetXSpeed', 280),
                 0xac4224: (17164992, 'OBJC_IVAR_$_DonkeyLike.randomTimeBetweenDirectionChanges', 300),
                 0xac4240: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0xac4254: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xac4258: (17165044, 'OBJC_IVAR_$_DonkeyLike.goalX', 288),
        },
        classes={
                 0xac4200: (15253100, 'OBJC_CLASS_$_DonkeyLike'),
        },
        instructions=[(11286924, 'push {r4, r5, r6, sl, fp, lr}'), (11289180, 'subseq ip, sb, r0, asr r1')],
        calls=[(11287024, 'blx r4'), (11287264, 'bl 0xab9de8'), (11287392, 'bl sym.makeIntpair_int__int_'), (11287444, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11287496, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11287508, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (11287528, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (11287632, 'bl loc.imp.objc_msgSend'), (11287656, 'bl sym.imp.__aeabi_idiv'), (11287752, 'bl loc.imp.objc_msgSend'), (11287872, 'bl loc.imp.objc_msgSend'), (11287888, 'bl sym.imp.__aeabi_idiv'), (11287984, 'bl loc.imp.objc_msgSend'), (11288120, 'bl sym.tileContainsGate_Tile_'), (11288140, 'bl sym.tileContainsGate_Tile_'), (11288216, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11288228, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (11288248, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (11288352, 'bl loc.imp.objc_msgSend'), (11288376, 'bl sym.imp.__aeabi_idiv'), (11288472, 'bl loc.imp.objc_msgSend'), (11288592, 'bl loc.imp.objc_msgSend'), (11288608, 'bl sym.imp.__aeabi_idiv'), (11288704, 'bl loc.imp.objc_msgSend'), (11288840, 'bl sym.tileContainsGate_Tile_'), (11288860, 'bl sym.tileContainsGate_Tile_')],
        branches=[(11287060, 'bne', 11289072), (11287096, 'bne', 11289072), (11287188, 'bne', 11289068), (11287520, 'beq', 11288156), (11287540, 'beq', 11288156), (11287668, 'blt', 11287784), (11287780, 'b', 11288064), (11287900, 'bge', 11288016), (11288012, 'b', 11288056), (11288072, 'beq', 11288928), (11288112, 'bne', 11288928), (11288132, 'bne', 11288156), (11288152, 'beq', 11288928), (11288240, 'beq', 11288876), (11288260, 'beq', 11288876), (11288388, 'blt', 11288504), (11288500, 'b', 11288784), (11288620, 'bge', 11288736), (11288732, 'b', 11288776), (11288792, 'beq', 11288924), (11288832, 'bne', 11288924), (11288852, 'bne', 11288876), (11288872, 'beq', 11288924), (11288924, 'b', 11288928), (11289068, 'b', 11289072)],
        semantics=('[DonkeyLike hitWithForce:blockhead:] (imp 0x00ac398c, 565w): the knockback - objc x8 + **`tileIsAirWaterOrSnow` x4** + **`tileContainsGate(Tile*)` x4** (!) + `tileAtWorldPositionLoaded` x3 + `__aeabi_idiv` x4 + the helper 0xab9de8: the hit resolves through gates (the animal can be knocked through/into gates).\n'),
    ),
    dict(
        name='dl_21',
        method='DonkeyLike -[renderPos]',
        types='{Vector2=[2f]}8@0:4',
        start=11289184,
        end=11289556,
        disasm='disasm_worldtileloader_dl_21.txt',
        base_add=11289216,
        base_literal=11289304,
        boundary='ARM.exidx end 0x00ac43d4 (listing bound); next ObjC IMP 0x00ac42e0 DonkeyLike -[riderPosForBlockhead:]',
        selectors={},
        imports={},
        ivars={
                 0xac42d4: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xac43c8: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xac43d0: (17165064, 'OBJC_IVAR_$_DonkeyLike.yOffset', 268),
        },
        classes={},
        instructions=[(11289184, 'push {fp, lr}'), (11289552, 'invalid')],
        calls=[(11289268, 'bl method.Vector2.Vector2_float__float_'), (11289288, 'bl method.Vector2.operator_Vector2_'), (11289440, 'bl method.Vector2.Vector2_float__float_'), (11289460, 'bl method.Vector2.operator_Vector2_'), (11289468, 'bl method.Vector2.operator_float__'), (11289488, 'bl method.Vector2.operator_float__'), (11289520, 'bl method.Vector.Vector_float__float__float_')],
        branches=[],
        semantics=('[DonkeyLike renderPos] (imp 0x00ac4260, 32w): the render position.\n'),
    ),
    dict(
        name='dl_22',
        method='DonkeyLike -[riderPosForBlockhead:]',
        types='{Vector=[4f]}12@0:4@8',
        start=11289312,
        end=11289556,
        disasm='disasm_worldtileloader_dl_22.txt',
        base_add=11289348,
        base_literal=11289548,
        boundary='ARM.exidx end 0x00ac43d4 (listing bound); next ObjC IMP 0x00ac43d4 DonkeyLike -[setTargetVelocity:]',
        selectors={},
        imports={},
        ivars={
                 0xac43c8: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xac43d0: (17165064, 'OBJC_IVAR_$_DonkeyLike.yOffset', 268),
        },
        classes={},
        instructions=[(11289312, 'push {fp, lr}'), (11289552, 'invalid')],
        calls=[(11289440, 'bl method.Vector2.Vector2_float__float_'), (11289460, 'bl method.Vector2.operator_Vector2_'), (11289468, 'bl method.Vector2.operator_float__'), (11289488, 'bl method.Vector2.operator_float__'), (11289520, 'bl method.Vector.Vector_float__float__float_')],
        branches=[],
        semantics=('[DonkeyLike riderPosForBlockhead:] (imp 0x00ac42e0, 61w): the rider position.\n'),
    ),
    dict(
        name='dl_23',
        method='DonkeyLike -[setTargetVelocity:]',
        types='v16@0:4{Vector2=[2f]}8',
        start=11289556,
        end=11289980,
        disasm='disasm_worldtileloader_dl_23.txt',
        base_add=11289572,
        base_literal=11289976,
        boundary='ARM.exidx end 0x00ac457c (listing bound); next ObjC IMP 0x00ac457c DonkeyLike -[maxVelocity]',
        selectors={
                 0xac4564: (15227376, 'isNet'),
                 0xac4570: (15227584, 'maxVelocity'),
        },
        imports={
                 0xac4560: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xac455c: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0xac4568: (17165004, 'OBJC_IVAR_$_DonkeyLike.targetXSpeed', 280),
                 0xac456c: (17165000, 'OBJC_IVAR_$_DonkeyLike.lastSendContainedMovement', 836),
                 0xac4574: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
        },
        classes={},
        instructions=[(11289556, 'push {r4, sl, fp, lr}'), (11289976, 'subseq fp, sb, r8, lsl 14')],
        calls=[(11289692, 'blx r2'), (11289712, 'bl method.Vector2.operator_float__'), (11289796, 'blx lr')],
        branches=[(11289628, 'beq', 11289940), (11289704, 'bne', 11289940), (11289900, 'beq', 11289936), (11289936, 'b', 11289940)],
        semantics=('[DonkeyLike setTargetVelocity:] (imp 0x00ac43d4, 106w): the velocity setter.\n'),
    ),
    dict(
        name='dl_24',
        method='DonkeyLike -[maxVelocity]',
        types='f8@0:4',
        start=11289980,
        end=11290024,
        disasm='disasm_worldtileloader_dl_24.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00ac45a8 (listing bound); next ObjC IMP 0x00ac45a8 DonkeyLike -[addRider:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11289980, 'sub sp, sp, 0x10'), (11290020, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DonkeyLike maxVelocity] (imp 0x00ac457c, 11w): the speed cap.\n'),
    ),
    dict(
        name='dl_25',
        method='DonkeyLike -[addRider:]',
        types='v12@0:4@8',
        start=11290024,
        end=11290340,
        disasm='disasm_worldtileloader_dl_25.txt',
        base_add=11290040,
        base_literal=11290336,
        boundary='ARM.exidx end 0x00ac46e4 (listing bound); next ObjC IMP 0x00ac46e4 DonkeyLike -[removeRider:]',
        selectors={
                 0xac46c0: (15227588, 'addRider:'),
        },
        imports={
                 0xac46bc: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0xac46c8: (17157392, 'OBJC_IVAR_$_NPC.beingControlled', 128),
                 0xac46cc: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xac46d4: (17158240, 'OBJC_IVAR_$_DonkeyLike.actualXSpeed', 284),
                 0xac46d8: (17165004, 'OBJC_IVAR_$_DonkeyLike.targetXSpeed', 280),
                 0xac46dc: (17165012, 'OBJC_IVAR_$_DonkeyLike.randomGoalRotation', 304),
        },
        classes={
                 0xac46c4: (15253100, 'OBJC_CLASS_$_DonkeyLike'),
        },
        instructions=[(11290024, 'push {r4, r5, fp, lr}'), (11290336, 'subseq fp, sb, r4, lsr r5')],
        calls=[(11290116, 'blx lr')],
        branches=[(11290152, 'bne', 11290252), (11290248, 'b', 11290292)],
        semantics=('[DonkeyLike addRider:] (imp 0x00ac45a8, 79w): the rider attach.\n'),
    ),
    dict(
        name='dl_26',
        method='DonkeyLike -[removeRider:]',
        types='v12@0:4@8',
        start=11290340,
        end=11290588,
        disasm='disasm_worldtileloader_dl_26.txt',
        base_add=11290356,
        base_literal=11290584,
        boundary='ARM.exidx end 0x00ac47dc (listing bound); next ObjC IMP 0x00ac47dc DonkeyLike -[swipeUpGesture]',
        selectors={
                 0xac47c4: (15227592, 'removeRider:'),
        },
        imports={
                 0xac47c0: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0xac47bc: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0xac47d0: (17158240, 'OBJC_IVAR_$_DonkeyLike.actualXSpeed', 284),
                 0xac47d4: (17165004, 'OBJC_IVAR_$_DonkeyLike.targetXSpeed', 280),
        },
        classes={
                 0xac47c8: (15253100, 'OBJC_CLASS_$_DonkeyLike'),
        },
        instructions=[(11290340, 'push {fp, lr}'), (11290584, 'ldrsheq fp, [sb], -0x38')],
        calls=[(11290480, 'blx r3')],
        branches=[(11290408, 'bne', 11290548)],
        semantics=('[DonkeyLike removeRider:] (imp 0x00ac46e4, 62w): the rider detach.\n'),
    ),
    dict(
        name='dl_27',
        method='DonkeyLike -[swipeUpGesture]',
        types='v8@0:4',
        start=11290588,
        end=11290712,
        disasm='disasm_worldtileloader_dl_27.txt',
        base_add=11290600,
        base_literal=11290708,
        boundary='ARM.exidx end 0x00ac4858 (listing bound); next ObjC IMP 0x00ac4858 DonkeyLike -[riderBodyYRotationForBlockhead:]',
        selectors={},
        imports={},
        ivars={
                 0xac4848: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xac484c: (17165008, 'OBJC_IVAR_$_DonkeyLike.jumpActionSendValue', 325),
                 0xac4850: (17165016, 'OBJC_IVAR_$_DonkeyLike.jumpActionQueued', 296),
        },
        classes={},
        instructions=[(11290588, 'push {r4, lr}'), (11290708, 'subseq fp, sb, r4, lsl 6')],
        calls=[],
        branches=[],
        semantics=('[DonkeyLike swipeUpGesture] (imp 0x00ac47dc, 31w): the swipe gesture hook.\n'),
    ),
    dict(
        name='dl_28',
        method='DonkeyLike -[riderBodyYRotationForBlockhead:]',
        types='f12@0:4@8',
        start=11290712,
        end=11290780,
        disasm='disasm_worldtileloader_dl_28.txt',
        base_add=11290740,
        base_literal=11290776,
        boundary='ARM.exidx end 0x00ac489c (listing bound); next ObjC IMP 0x00ac489c DonkeyLike -[riderBodyZRotationForBlockhead:]',
        selectors={},
        imports={},
        ivars={
                 0xac4894: (17165060, 'OBJC_IVAR_$_DonkeyLike.bodyRotation', 256),
        },
        classes={},
        instructions=[(11290712, 'sub sp, sp, 0xc'), (11290776, 'subseq fp, sb, r8, ror r2')],
        calls=[],
        branches=[],
        semantics=('[DonkeyLike riderBodyYRotationForBlockhead:] (imp 0x00ac4858, 17w): the rider Y rotation.\n'),
    ),
    dict(
        name='dl_29',
        method='DonkeyLike -[riderBodyZRotationForBlockhead:]',
        types='f12@0:4@8',
        start=11290780,
        end=11290832,
        disasm='disasm_worldtileloader_dl_29.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00ac48d0 (listing bound); next ObjC IMP 0x00ac48d0 DonkeyLike -[cameraPosForBlockhead:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11290780, 'sub sp, sp, 0x14'), (11290828, 'andeq r0, r0, r0')],
        calls=[],
        branches=[],
        semantics=('[DonkeyLike riderBodyZRotationForBlockhead:] (imp 0x00ac489c, 13w): the rider Z rotation.\n'),
    ),
    dict(
        name='dl_30',
        method='DonkeyLike -[cameraPosForBlockhead:]',
        types='{Vector2=[2f]}12@0:4@8',
        start=11290832,
        end=11291268,
        disasm='disasm_worldtileloader_dl_30.txt',
        base_add=11290848,
        base_literal=11291264,
        boundary='ARM.exidx end 0x00ac4a84 (listing bound); next ObjC IMP 0x00ac4a84 DonkeyLike -[worldChanged:]',
        selectors={
                 0xac4a68: (15227596, 'renderPos'),
                 0xac4a78: (15227600, 'windowInfo'),
        },
        imports={},
        ivars={
                 0xac4a6c: (17165004, 'OBJC_IVAR_$_DonkeyLike.targetXSpeed', 280),
                 0xac4a74: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(11290832, 'push {r4, sl, fp, lr}'), (11291264, 'subseq fp, sb, ip, lsl 4')],
        calls=[(11290916, 'bl loc.imp.objc_msgSend_stret'), (11290952, 'bl sym.imp.memset'), (11291044, 'bl loc.imp.objc_msgSend'), (11291124, 'bl loc.imp.objc_msgSend'), (11291180, 'bl method.Vector2.Vector2_float__float_'), (11291200, 'bl method.Vector2.operator_Vector2_')],
        branches=[(11290900, 'beq', 11290924), (11290920, 'b', 11290956)],
        semantics=('[DonkeyLike cameraPosForBlockhead:] (imp 0x00ac48d0, 109w): the camera accessor - the stret read + Vector2 math.\n'),
    ),
    dict(
        name='dl_31',
        method='DonkeyLike -[worldChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=11291268,
        end=11291292,
        disasm='disasm_worldtileloader_dl_31.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00ac4a9c (listing bound); next ObjC IMP 0x00ac4a9c DonkeyLike -[jumpsOnSwipe]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11291268, 'sub sp, sp, 0xc'), (11291288, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DonkeyLike worldChanged:] (imp 0x00ac4a84, 6w): the worldChanged hook (empty).\n'),
    ),
    dict(
        name='dl_32',
        method='DonkeyLike -[jumpsOnSwipe]',
        types='c8@0:4',
        start=11291292,
        end=11291320,
        disasm='disasm_worldtileloader_dl_32.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00ac4ab8 (listing bound); next ObjC IMP 0x00ac4ab8 DonkeyLike -[rideDirection]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11291292, 'sub sp, sp, 8'), (11291316, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DonkeyLike jumpsOnSwipe] (imp 0x00ac4a9c, 7w): the swipe-jump flag.\n'),
    ),
    dict(
        name='dl_33',
        method='DonkeyLike -[rideDirection]',
        types='i8@0:4',
        start=11291320,
        end=11291560,
        disasm='disasm_worldtileloader_dl_33.txt',
        base_add=11291328,
        base_literal=11291556,
        boundary='ARM.exidx end 0x00ac4ba8 (listing bound); next ObjC IMP 0x00ac4ba8 DonkeyLike -[requiresFuel]',
        selectors={},
        imports={},
        ivars={
                 0xac4b9c: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0xac4ba0: (17165004, 'OBJC_IVAR_$_DonkeyLike.targetXSpeed', 280),
        },
        classes={},
        instructions=[(11291320, 'sub sp, sp, 0x1c'), (11291556, 'subseq fp, sb, ip, lsr 32')],
        calls=[],
        branches=[(11291376, 'beq', 11291528), (11291428, 'ble', 11291444), (11291440, 'b', 11291516), (11291524, 'b', 11291536)],
        semantics=('[DonkeyLike rideDirection] (imp 0x00ac4ab8, 60w): the ride direction.\n'),
    ),
    dict(
        name='dl_34',
        method='DonkeyLike -[requiresFuel]',
        types='c8@0:4',
        start=11291560,
        end=11291616,
        disasm='disasm_worldtileloader_dl_34.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00ac4be0 (listing bound); next ObjC IMP 0x00ac4bc4 DonkeyLike -[actsAsInteractionObject]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11291560, 'sub sp, sp, 8'), (11291612, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DonkeyLike requiresFuel] (imp 0x00ac4ba8, 7w): the fuel flag.\n'),
    ),
    dict(
        name='dl_35',
        method='DonkeyLike -[actsAsInteractionObject]',
        types='@8@0:4',
        start=11291588,
        end=11291616,
        disasm='disasm_worldtileloader_dl_35.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00ac4be0 (listing bound); next ObjC IMP 0x00ac4be0 DonkeyLike -[blockheadUnloaded:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11291588, 'sub sp, sp, 8'), (11291612, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DonkeyLike actsAsInteractionObject] (imp 0x00ac4bc4, 7w): the interaction-object flag.\n'),
    ),
    dict(
        name='dl_36',
        method='DonkeyLike -[blockheadUnloaded:]',
        types='v12@0:4@8',
        start=11291616,
        end=11291864,
        disasm='disasm_worldtileloader_dl_36.txt',
        base_add=11291632,
        base_literal=11291860,
        boundary='ARM.exidx end 0x00ac4cd8 (listing bound); next ObjC IMP 0x00ac4cd8 DonkeyLike -[reactToBeingFed]',
        selectors={
                 0xac4ccc: (15227604, 'blockheadUnloaded:'),
        },
        imports={
                 0xac4cc8: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0xac4cb8: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0xac4cc0: (17165004, 'OBJC_IVAR_$_DonkeyLike.targetXSpeed', 280),
                 0xac4cc4: (17158240, 'OBJC_IVAR_$_DonkeyLike.actualXSpeed', 284),
        },
        classes={
                 0xac4cd0: (15253100, 'OBJC_CLASS_$_DonkeyLike'),
        },
        instructions=[(11291616, 'push {fp, lr}'), (11291860, 'ldrsheq sl, [sb], -0xec')],
        calls=[(11291820, 'blx r3')],
        branches=[(11291684, 'bne', 11291752)],
        semantics=('[DonkeyLike blockheadUnloaded:] (imp 0x00ac4be0, 62w): the owner unload hook.\n'),
    ),
    dict(
        name='dl_37',
        method='DonkeyLike -[reactToBeingFed]',
        types='v8@0:4',
        start=11291864,
        end=11292548,
        disasm='disasm_worldtileloader_dl_37.txt',
        base_add=11291880,
        base_literal=11292544,
        boundary='ARM.exidx end 0x00ac4f84 (listing bound); next ObjC IMP 0x00ac4f84 DonkeyLike -[jumps]',
        selectors={
                 0xac4f38: (15227608, 'reactToBeingFed'),
                 0xac4f50: (15227516, 'instance'),
                 0xac4f54: (15227520, 'multiSoundNamed:'),
                 0xac4f60: (15227524, 'playAtPosition:afterDelay:'),
        },
        imports={
                 0xac4f34: (17151900, 'objc_msgSendSuper2'),
                 0xac4f58: (16365400, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xac4f44: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0xac4f5c: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xac4f64: (17158236, 'OBJC_IVAR_$_DonkeyLike.babySound', 244),
                 0xac4f68: (17158232, 'OBJC_IVAR_$_DonkeyLike.adultSound', 248),
                 0xac4f70: (17158288, 'OBJC_IVAR_$_DonkeyLike.walkTimer', 264),
                 0xac4f74: (17165012, 'OBJC_IVAR_$_DonkeyLike.randomGoalRotation', 304),
                 0xac4f78: (17165016, 'OBJC_IVAR_$_DonkeyLike.jumpActionQueued', 296),
        },
        classes={
                 0xac4f3c: (15253100, 'OBJC_CLASS_$_DonkeyLike'),
                 0xac4f48: (15249380, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(11291864, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11292544, 'subseq sl, sb, r4, lsl 28')],
        calls=[(11291948, 'blx ip'), (11292020, 'bl loc.imp.objc_msgSend'), (11292044, 'bl loc.imp.objc_msgSend'), (11292124, 'bl loc.imp.objc_msgSend'), (11292388, 'bl loc.imp.objc_msgSend')],
        branches=[(11292160, 'ble', 11292200), (11292196, 'b', 11292232)],
        semantics=('[DonkeyLike reactToBeingFed] (imp 0x00ac4cd8, 171w): the feeding reaction - objc x4 + consts 0x384/0x3333/0x4000 (the fed state values).\n'),
    ),
    dict(
        name='dl_38',
        method='DonkeyLike -[jumps]',
        types='c8@0:4',
        start=11292548,
        end=11292660,
        disasm='disasm_worldtileloader_dl_38.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00ac4ff4 (listing bound); next ObjC IMP 0x00ac4fa0 DonkeyLike -[flies]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11292548, 'sub sp, sp, 8'), (11292656, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DonkeyLike jumps] (imp 0x00ac4f84, 28w): the jump flag.\n'),
    ),
    dict(
        name='dl_39',
        method='DonkeyLike -[flies]',
        types='c8@0:4',
        start=11292576,
        end=11292660,
        disasm='disasm_worldtileloader_dl_39.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00ac4ff4 (listing bound); next ObjC IMP 0x00ac4fbc DonkeyLike -[canJumpMultipleTilesWhileFlying]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11292576, 'sub sp, sp, 8'), (11292656, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DonkeyLike flies] (imp 0x00ac4fa0, 21w): the flight flag.\n'),
    ),
    dict(
        name='dl_40',
        method='DonkeyLike -[canJumpMultipleTilesWhileFlying]',
        types='c8@0:4',
        start=11292604,
        end=11292660,
        disasm='disasm_worldtileloader_dl_40.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00ac4ff4 (listing bound); next ObjC IMP 0x00ac4fd8 DonkeyLike -[generateBreedForChild]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11292604, 'sub sp, sp, 8'), (11292656, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DonkeyLike canJumpMultipleTilesWhileFlying] (imp 0x00ac4fbc, 14w): the flight-jump predicate.\n'),
    ),
    dict(
        name='dl_41',
        method='DonkeyLike -[generateBreedForChild]',
        types='i8@0:4',
        start=11292632,
        end=11292660,
        disasm='disasm_worldtileloader_dl_41.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00ac4ff4 (listing bound); next ObjC IMP 0x00ac4ff4 DonkeyLike -[canBeCapturedByBlockhead:withItemType:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11292632, 'sub sp, sp, 8'), (11292656, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DonkeyLike generateBreedForChild] (imp 0x00ac4fd8, 7w): the breed hook (base constant).\n'),
    ),
    dict(
        name='dl_42',
        method='DonkeyLike -[canBeCapturedByBlockhead:withItemType:]',
        types='c16@0:4@8i12',
        start=11292660,
        end=11292888,
        disasm='disasm_worldtileloader_dl_42.txt',
        base_add=11292676,
        base_literal=11292884,
        boundary='ARM.exidx end 0x00ac50d8 (listing bound); next ObjC IMP 0x00ac50d8 DonkeyLike -[cantBeCapturedTipStringForBlockhead:withItemType:]',
        selectors={
                 0xac50cc: (15227612, 'tamed'),
                 0xac50d0: (15227404, 'belongsToPlayerWithBlockhead:'),
        },
        imports={
                 0xac50c8: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(11292660, 'push {fp, lr}'), (11292884, 'subseq sl, sb, r8, ror 21')],
        calls=[(11292756, 'blx r2'), (11292820, 'blx r3')],
        branches=[(11292712, 'bne', 11292852), (11292768, 'beq', 11292836), (11292832, 'beq', 11292848), (11292844, 'b', 11292860), (11292848, 'b', 11292852)],
        semantics=('[DonkeyLike canBeCapturedByBlockhead:withItemType:] (imp 0x00ac4ff4, 57w): the capture gate.\n'),
    ),
    dict(
        name='dl_43',
        method='DonkeyLike -[cantBeCapturedTipStringForBlockhead:withItemType:]',
        types='@16@0:4@8i12',
        start=11292888,
        end=11293248,
        disasm='disasm_worldtileloader_dl_43.txt',
        base_add=11292904,
        base_literal=11293244,
        boundary='ARM.exidx end 0x00ac5240 (listing bound); next ObjC IMP 0x00ac5240 DonkeyLike -[galloping]',
        selectors={
                 0xac5224: (15227612, 'tamed'),
                 0xac5228: (15227404, 'belongsToPlayerWithBlockhead:'),
                 0xac5230: (15227620, 'stringWithFormat:'),
                 0xac5234: (15227616, 'speciesName'),
        },
        imports={
                 0xac5220: (17151904, 'objc_msgSend'),
                 0xac522c: (16365416, '__CFConstantStringClassReference'),
        },
        ivars={},
        classes={
                 0xac5238: (15249388, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(11292888, 'push {r4, r5, fp, lr}'), (11293244, 'subseq sl, sb, r4, lsl 20')],
        calls=[(11292984, 'blx r2'), (11293048, 'blx r3'), (11293144, 'blx r2'), (11293180, 'blx ip')],
        branches=[(11292940, 'bne', 11293196), (11292996, 'beq', 11293192), (11293060, 'bne', 11293192), (11293188, 'b', 11293204), (11293192, 'b', 11293196)],
        semantics=('[DonkeyLike cantBeCapturedTipStringForBlockhead:withItemType:] (imp 0x00ac50d8, 90w): the capture tip string.\n'),
    ),
    dict(
        name='dl_44',
        method='DonkeyLike -[galloping]',
        types='c8@0:4',
        start=11293248,
        end=11293276,
        disasm='disasm_worldtileloader_dl_44.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00ac525c (listing bound); next ObjC IMP 0x00ac525c DonkeyLike -[.cxx_construct]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11293248, 'sub sp, sp, 8'), (11293272, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DonkeyLike galloping] (imp 0x00ac5240, 7w): the gallop flag.\n'),
    ),
    dict(
        name='dl_45',
        method='DonkeyLike -[.cxx_construct]',
        types='@8@0:4',
        start=11293276,
        end=11294276,
        disasm='disasm_worldtileloader_dl_45.txt',
        base_add=11293292,
        base_literal=11293396,
        boundary='ARM.exidx end 0x00ac5644 (listing bound); next ObjC IMP 0x00ac5644 InventoryItem -[initWithType:dataA:dataB:subItems:dynamicObjectSaveDict:]',
        selectors={},
        imports={},
        ivars={
                 0xac52cc: (17158180, 'OBJC_IVAR_$_DonkeyLike.bodyColor', 808),
                 0xac52d0: (17164996, 'OBJC_IVAR_$_DonkeyLike.backPos', 272),
        },
        classes={},
        instructions=[(11293276, 'push {fp, lr}'), (11294272, 'cmnmi pc, 0')],
        calls=[(11293328, 'bl method.Vector2.Vector2__'), (11293364, 'bl method.Vector.Vector__'), (11293468, 'bl sym.imp.cosf'), (11293488, 'bl sym.imp.sinf'), (11293676, 'bl sym.imp.cosf'), (11293696, 'bl sym.imp.sinf'), (11293884, 'bl sym.imp.cosf'), (11293904, 'bl sym.imp.sinf'), (11294108, 'bl sym.clamp_float__float__float_'), (11294152, 'bl sym.clamp_float__float__float_'), (11294196, 'bl sym.clamp_float__float__float_'), (11294240, 'bl sym.clamp_float__float__float_')],
        branches=[],
        semantics=('[DonkeyLike .cxx_construct] (imp 0x00ac525c, 250w): the C++ member init - **`clamp_float` x4 + `cosf` x3 + `sinf` x3** (!): the orientation vectors are constructed with trig (the facing basis).\n'),
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
        'batch': 'DonkeyLike (E97): the animal base class - the mega tick, the render, the knockback and the lifecycle; 46 bodies',
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
                        default=NATIVE / 'donkeylike.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale donkeylike.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
