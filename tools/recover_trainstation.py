#!/usr/bin/env python3
"""Hash-gated recovery of the TrainStation (E155).

The rail station object lands: the batch sweeps the station surface:
27 bodies, {total} instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/TRAINSTATION.md for the prose and boundaries.
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
    'bl 0xb3945c': 0x00b3945c,
    'bl 0xb39960': 0x00b39960,
    'bl 0xb3a218': 0x00b3a218,
    'bl 0xb3a244': 0x00b3a244,
    'bl 0xb3dcf4': 0x00b3dcf4,
    'bl 0xb3dedc': 0x00b3dedc,
    'bl 0xb3e49c': 0x00b3e49c,
    'bl 0xb3e510': 0x00b3e510,
    'bl 0xb3f7b4': 0x00b3f7b4,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.operator_float__': 0x004b5c08,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl method.constructor.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl sym.drawShaderQuad': 0x007c43dc,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__wrap_glActiveTexture': 0x001c2dc8,
    'bl sym.imp.__wrap_glBindTexture': 0x001c2ad4,
    'bl sym.imp.__wrap_glDisable': 0x001c2c48,
    'bl sym.imp.__wrap_glDisableVertexAttribArray': 0x001c3d58,
    'bl sym.imp.__wrap_glEnable': 0x001c2b04,
    'bl sym.imp.__wrap_glEnableVertexAttribArray': 0x001c2d5c,
    'bl sym.imp.__wrap_glUniform1i': 0x001c2de0,
    'bl sym.imp.__wrap_glUniform4f': 0x001c3d64,
    'bl sym.imp.__wrap_glUniformMatrix4fv': 0x001c2dd4,
    'bl sym.imp.__wrap_glUseProgram': 0x001c2d38,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.popDepthMaskState': 0x007c57ec,
    'bl sym.pushDepthMaskState': 0x007c55e4,
    'bl sym.texCoordsForImageIndex_int_': 0x004d6820,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileAtWorldPosition_int__int__MacroTile__World_': 0x00a16e68,
    'bl sym.tileIsSolid_Tile_': 0x00a1179c,
    'bl sym.tileTexCoordsForItemType_ItemType__signed_char_': 0x005f0450,
}

SPECS = [
    dict(
        name='ts_00',
        method='TrainStation -[canBeUsedByBlockhead:]',
        types='c12@0:4@8',
        start=11794416,
        end=11794896,
        disasm='disasm_worldtileloader_ts_00.txt',
        base_add=11794432,
        base_literal=11794892,
        boundary='ARM.exidx end 0x00b3f9d0 (listing bound); next ObjC IMP 0x00b3f9d0 TrainStation -[interactionRenderItemType]',
        selectors={
                 0xb3f9a8: (15230324, 'isAdmin'),
                 0xb3f9b0: (15230328, 'isClientBlockheadBeingControlledByServer'),
                 0xb3f9b8: (15230332, 'canBeUsedByBlockhead:'),
                 0xb3f9c4: (15230304, 'isEqualToString:'),
                 0xb3f9c8: (15230336, 'localNetID'),
        },
        imports={
                 0xb3f9a4: (17151904, 'objc_msgSend'),
                 0xb3f9b4: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0xb3f9ac: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xb3f9c0: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
        },
        classes={
                 0xb3f9bc: (15253132, 'OBJC_CLASS_$_TrainStation'),
        },
        instructions=[(11794416, 'push {r4, sl, fp, lr}'), (11794892, 'subseq r0, r2, ip, ror 5')],
        calls=[(11794496, 'blx ip'), (11794552, 'blx r2'), (11794648, 'blx r3'), (11794788, 'blx lr'), (11794824, 'blx r3')],
        branches=[(11794508, 'beq', 11794580), (11794564, 'bne', 11794580), (11794576, 'b', 11794840), (11794672, 'beq', 11794832), (11794712, 'beq', 11794832)],
        semantics=('TrainStation -[canBeUsedByBlockhead:] @0x00b3f7f0 (120 words, 5 branches, 5 indirect sends, no bl): fast path returns YES only when both [self->world isAdmin] (cell 0xb3f9ac, ivar world@4) is true and [blockhead isClientBlockheadBeingControlledByServer] (0xb3f878) is false; every other path calls super via objc_msgSendSuper2(&super{self,TrainStation class 0x00e8be8c}, @selector(canBeUsedByBlockhead:)) and then returns YES when self->ownerID@36 is nil (0xb3f910) or when [ownerID isEqualToString:[blockhead localNetID]] (0xb3f964 -> 0xb3f988); char result via sxtb. Selectors: isAdmin, isClientBlockheadBeingControlledByServer, canBeUsedByBlockhead:, isEqualToString:, localNetID; ivar cells world@4 and ownerID@36 both resolve to the class_metadata offsets.'),
    ),
    dict(
        name='ts_01',
        method='TrainStation -[creationNetDataForClient:]',
        types='@12@0:4@8',
        start=11769316,
        end=11770208,
        disasm='disasm_worldtileloader_ts_01.txt',
        base_add=11769332,
        base_literal=11770204,
        boundary='ARM.exidx end 0x00b39960 (listing bound); next ObjC IMP 0x00b39acc TrainStation -[remoteUpdate:]',
        selectors={
                 0xb39920: (15230180, 'interactionObjectCreationNetData'),
                 0xb3992c: (15230188, 'dictionary'),
                 0xb39934: (15230184, 'dataWithBytes:length:'),
                 0xb39940: (15230172, 'setObject:forKey:'),
                 0xb39954: (15230196, 'appendData:'),
                 0xb39958: (15230192, 'gzipDeflate'),
        },
        imports={
                 0xb39928: (17151904, 'objc_msgSend'),
                 0xb3993c: (16373256, '__CFConstantStringClassReference'),
                 0xb39948: (16373288, '__CFConstantStringClassReference'),
                 0xb39950: (16373304, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xb39924: (17165800, 'OBJC_IVAR_$_TrainStation.text', 128),
                 0xb39944: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
                 0xb3994c: (17156788, 'OBJC_IVAR_$_InteractionObject.ownerName', 84),
        },
        classes={
                 0xb39930: (15249832, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0xb39938: (15249828, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(11769316, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11770204, 'ldrsheq r6, [r2], -0x48')],
        calls=[(11769408, 'bl loc.imp.objc_msgSend_stret'), (11769444, 'bl sym.imp.memset'), (11769576, 'bl sym.imp.memcpy'), (11769616, 'blx ip'), (11769652, 'blx r3'), (11769776, 'blx ip'), (11769904, 'blx ip'), (11770032, 'blx ip'), (11770040, 'bl 0xb39960'), (11770100, 'blx lr'), (11770128, 'blx r3')],
        branches=[(11769392, 'beq', 11769416), (11769412, 'b', 11769448), (11769688, 'beq', 11769780), (11769816, 'beq', 11769908), (11769944, 'beq', 11770036)],
        semantics=('TrainStation -[creationNetDataForClient:] @0xb395e4 (223 words, 5 branches, 11 calls): builds the net creation blob = <0x28-byte InteractionObjectNetData> + gzip(plist tail). [self interactionObjectCreationNetData] is called with a hidden stret buffer at sp+0x70 (0x28 = 40 bytes) and memset to 0 when self is nil (0xb39648); the record is memcpy\'d to a local, wrapped by [NSMutableData dataWithBytes:length:0x28], then an NSMutableDictionary is filled only for non-nil fields - text@128 under key "text" (CFString cell 0xf9d608), ownerID@36 under "ownerID" (0xf9d628), ownerName@84 (InteractionObject) under "ownerName" (0xf9d638) - serialized by the local plist writer 0xb39960 (dataWithPropertyList:format:options:error: path) and appended via [plistData gzipDeflate] + [data appendData:]; the (client) argument is spilled at fp-0x24 and never read.'),
    ),
    dict(
        name='ts_02',
        method='TrainStation -[dealloc]',
        types='v8@0:4',
        start=11771376,
        end=11771744,
        disasm='disasm_worldtileloader_ts_02.txt',
        base_add=11771392,
        base_literal=11771740,
        boundary='ARM.exidx end 0x00b39f60 (listing bound); next ObjC IMP 0x00b39f60 TrainStation -[updateBitmapString]',
        selectors={
                 0xb39f3c: (15230212, 'dealloc'),
                 0xb39f48: (15230208, 'release'),
        },
        imports={
                 0xb39f38: (17151900, 'objc_msgSendSuper2'),
                 0xb39f44: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xb39f4c: (17165800, 'OBJC_IVAR_$_TrainStation.text', 128),
                 0xb39f50: (17165804, 'OBJC_IVAR_$_TrainStation.bitmapString', 120),
                 0xb39f54: (17165780, 'OBJC_IVAR_$_TrainStation.poleDrawCube', 116),
                 0xb39f58: (17165784, 'OBJC_IVAR_$_TrainStation.platformBlock', 112),
        },
        classes={
                 0xb39f40: (15253132, 'OBJC_CLASS_$_TrainStation'),
        },
        instructions=[(11771376, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11771740, 'subseq r5, r2, ip, ror 25')],
        calls=[(11771544, 'blx r5'), (11771580, 'blx r3'), (11771616, 'blx r3'), (11771652, 'blx r3'), (11771692, 'blx r2')],
        branches=[],
        semantics=('TrainStation -[dealloc] @0xb39df0 (92 words, 0 branches, 5 indirect calls): releases exactly four object ivars in order platformBlock@112, poleDrawCube@116, bitmapString@120, text@128 (each via the two-stage Apportable ivar cell + objc_msgSend release) and then objc_msgSendSuper2({self, TrainStation class}, @selector(dealloc)); cubeShader@100, signShader@104 and tileDestructTexture@108 are NOT released (observed asymmetry with the shaders/texture created in initSubDerivedItems). No autorelease; no branches; frame sub sp,#0x38 with fp = sp+0x18.'),
    ),
    dict(
        name='ts_03',
        method='TrainStation -[destroyItemType]',
        types='i8@0:4',
        start=11792764,
        end=11792792,
        disasm='disasm_worldtileloader_ts_03.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00b3f198 (listing bound); next ObjC IMP 0x00b3f198 TrainStation -[worldChanged:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11792764, 'sub sp, sp, 8'), (11792788, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('TrainStation -[destroyItemType] @0x00b3f17c (7 words, 0 calls/branches): constant getter - movw r2,#0xc8 then mov r0,r2 returns ItemType 200 = TrainStation (reference label of the pinned enum snapshot) - i.e. the item dropped when the station is destroyed; self/_cmd only spilled, no cell access.'),
    ),
    dict(
        name='ts_04',
        method='TrainStation -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        types='v156@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76i140i144i148i152',
        start=11772592,
        end=11787508,
        disasm='disasm_worldtileloader_ts_04.txt',
        base_add=11772628,
        base_literal=11776264,
        boundary='ARM.exidx end 0x00b3dcf4 (listing bound); next ObjC IMP 0x00b3e6c8 TrainStation -[freeblockCreationItemType]',
        selectors={
                 0xb3b118: (15230228, 'worldWidthMacro'),
                 0xb3b150: (15230232, 'macroTiles'),
                 0xb3b154: (15230236, 'dayColor'),
                 0xb3b158: (15230240, 'name'),
                 0xb3b164: (15230244, 'program'),
                 0xb3b16c: (15230256, 'intValue'),
                 0xb3b170: (15230252, 'objectAtIndex:'),
                 0xb3b174: (15230248, 'uniformLocations'),
                 0xb3b180: (15230260, 'roundedTranslation'),
                 0xb3b190: (15230264, 'draw'),
                 0xb3c758: (15230244, 'program'),
                 0xb3dccc: (15230256, 'intValue'),
                 0xb3dcd0: (15230252, 'objectAtIndex:'),
                 0xb3dcd4: (15230248, 'uniformLocations'),
                 0xb3dcd8: (15230240, 'name'),
                 0xb3dcec: (15230268, 'setColor:'),
                 0xb3dcf0: (15230272, 'renderWithProjectionMatrix:modelViewMatrix:'),
        },
        imports={
                 0xb3b14c: (17151904, 'objc_msgSend'),
                 0xb3dcc8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xb3b10c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xb3b114: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xb3b138: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xb3b15c: (17156844, 'OBJC_IVAR_$_InteractionObject.texture', 64),
                 0xb3b160: (17165796, 'OBJC_IVAR_$_TrainStation.tileDestructTexture', 108),
                 0xb3b168: (17165792, 'OBJC_IVAR_$_TrainStation.cubeShader', 100),
                 0xb3b18c: (17165784, 'OBJC_IVAR_$_TrainStation.platformBlock', 112),
                 0xb3bef8: (17165780, 'OBJC_IVAR_$_TrainStation.poleDrawCube', 116),
                 0xb3c754: (17165788, 'OBJC_IVAR_$_TrainStation.signShader', 104),
                 0xb3dcdc: (17156844, 'OBJC_IVAR_$_InteractionObject.texture', 64),
                 0xb3dce0: (17165804, 'OBJC_IVAR_$_TrainStation.bitmapString', 120),
                 0xb3dce4: (17165788, 'OBJC_IVAR_$_TrainStation.signShader', 104),
        },
        classes={},
        instructions=[(11772592, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11787504, 'invalid')],
        calls=[(11773288, 'bl loc.imp.objc_msgSend'), (11773312, 'bl sym.imp.__aeabi_idiv'), (11773380, 'bl loc.imp.objc_msgSend'), (11773500, 'bl loc.imp.objc_msgSend'), (11773516, 'bl sym.imp.__aeabi_idiv'), (11773584, 'bl loc.imp.objc_msgSend'), (11773708, 'bl loc.imp.objc_msgSend'), (11773732, 'bl sym.imp.__aeabi_idiv'), (11773800, 'bl loc.imp.objc_msgSend'), (11773920, 'bl loc.imp.objc_msgSend'), (11773936, 'bl sym.imp.__aeabi_idiv'), (11774004, 'bl loc.imp.objc_msgSend'), (11774276, 'bl method.Vector2.operator_float__'), (11774340, 'bl loc.imp.objc_msgSend'), (11774364, 'bl sym.imp.__aeabi_idiv'), (11774456, 'bl loc.imp.objc_msgSend'), (11774492, 'bl method.Vector2.operator_float__'), (11774544, 'bl method.Vector2.operator_float__'), (11774612, 'bl loc.imp.objc_msgSend'), (11774628, 'bl sym.imp.__aeabi_idiv'), (11774720, 'bl loc.imp.objc_msgSend'), (11774756, 'bl method.Vector2.operator_float__'), (11774892, 'blx r2'), (11774936, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (11775040, 'bl loc.imp.objc_msgSend_stret'), (11775080, 'bl sym.imp.memset'), (11775156, 'blx r3'), (11775176, 'bl sym.imp.__wrap_glBindTexture'), (11775184, 'bl sym.imp.__wrap_glActiveTexture'), (11775260, 'blx r3'), (11775280, 'bl sym.imp.__wrap_glBindTexture'), (11775288, 'bl sym.imp.__wrap_glEnable'), (11775296, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (11775360, 'blx r2'), (11775364, 'bl sym.imp.__wrap_glUseProgram'), (11775492, 'blx r6'), (11775512, 'blx r3'), (11775528, 'blx r2'), (11775536, 'bl sym.imp.__wrap_glUniform1i'), (11775664, 'blx r6'), (11775684, 'blx r3'), (11775700, 'blx r2'), (11775708, 'bl sym.imp.__wrap_glUniform1i'), (11776176, 'bl method.constructor.Vector.Vector_float__float__float_'), (11776256, 'bl loc.imp.objc_msgSend_stret'), (11776432, 'bl sym.imp.memset'), (11776488, 'bl method.Vector.operator_float__'), (11776556, 'bl method.Vector.operator_float__'), (11776624, 'bl method.Vector.operator_float__'), (11776680, 'bl method.constructor.Vector.Vector_float__float__float_'), (11776696, 'bl method.Vector.operator_float__'), (11776716, 'bl method.Vector.operator_float__'), (11776748, 'bl method.Vector.operator_float__'), (11776768, 'bl method.Vector.operator_float__'), (11776800, 'bl method.Vector.operator_float__'), (11776820, 'bl method.Vector.operator_float__'), (11776876, 'bl method.constructor.Vector.Vector_float__float__float_'), (11776932, 'bl loc.imp.objc_msgSend'), (11776968, 'bl loc.imp.objc_msgSend'), (11776992, 'bl loc.imp.objc_msgSend'), (11777008, 'bl method.Vector.operator_float__'), (11777024, 'bl method.Vector.operator_float__'), (11777040, 'bl method.Vector.operator_float__'), (11777080, 'bl sym.imp.__wrap_glUniform4f'), (11777112, 'bl loc.imp.objc_msgSend'), (11777132, 'bl loc.imp.objc_msgSend'), (11777148, 'bl loc.imp.objc_msgSend'), (11777164, 'bl method.Vector.operator_float__'), (11777180, 'bl method.Vector.operator_float__'), (11777196, 'bl method.Vector.operator_float__'), (11777228, 'bl sym.imp.__wrap_glUniform4f'), (11777260, 'bl loc.imp.objc_msgSend'), (11777280, 'bl loc.imp.objc_msgSend'), (11777296, 'bl loc.imp.objc_msgSend'), (11777316, 'bl method.Vector2.operator_float__'), (11777340, 'bl method.Vector2.operator_float__'), (11777372, 'bl method.Vector2.operator_float__'), (11777392, 'bl method.Vector2.operator_float__'), (11777468, 'bl sym.imp.__wrap_glUniform4f'), (11777604, 'bl method.Vector2.operator_float__'), (11777624, 'bl method.Vector2.operator_float__'), (11777848, 'bl 0xb3dcf4'), (11778552, 'bl 0xb3dedc'), (11778584, 'bl loc.imp.objc_msgSend'), (11778604, 'bl loc.imp.objc_msgSend'), (11778620, 'bl loc.imp.objc_msgSend'), (11778640, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (11778672, 'bl loc.imp.objc_msgSend'), (11778700, 'bl loc.imp.objc_msgSend'), (11778716, 'bl loc.imp.objc_msgSend'), (11778732, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (11778776, 'bl loc.imp.objc_msgSend'), (11778888, 'bl 0xb3e49c'), (11779716, 'bl 0xb3dedc'), (11780428, 'bl 0xb3dedc'), (11780564, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (11780572, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (11780732, 'bl loc.imp.objc_msgSend'), (11780752, 'bl loc.imp.objc_msgSend'), (11780768, 'bl loc.imp.objc_msgSend'), (11780784, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (11780816, 'bl loc.imp.objc_msgSend'), (11780836, 'bl loc.imp.objc_msgSend'), (11780852, 'bl loc.imp.objc_msgSend'), (11780880, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (11780924, 'bl loc.imp.objc_msgSend'), (11780992, 'bl 0xb3e49c'), (11781820, 'bl 0xb3dedc'), (11782700, 'bl 0xb3dedc'), (11782860, 'bl loc.imp.objc_msgSend'), (11782880, 'bl loc.imp.objc_msgSend'), (11782896, 'bl loc.imp.objc_msgSend'), (11782912, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (11782944, 'bl loc.imp.objc_msgSend'), (11782964, 'bl loc.imp.objc_msgSend'), (11782980, 'bl loc.imp.objc_msgSend'), (11782996, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (11783028, 'bl loc.imp.objc_msgSend'), (11783036, 'bl sym.pushDepthMaskState'), (11783052, 'bl sym.imp.__wrap_glBindTexture'), (11783060, 'bl sym.imp.__wrap_glActiveTexture'), (11783068, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (11783112, 'bl loc.imp.objc_msgSend'), (11783116, 'bl sym.imp.__wrap_glUseProgram'), (11783148, 'bl loc.imp.objc_msgSend'), (11783168, 'bl loc.imp.objc_msgSend'), (11783184, 'bl loc.imp.objc_msgSend'), (11783192, 'bl sym.imp.__wrap_glUniform1i'), (11783224, 'bl loc.imp.objc_msgSend'), (11783244, 'bl loc.imp.objc_msgSend'), (11783260, 'bl loc.imp.objc_msgSend'), (11783276, 'bl method.Vector.operator_float__'), (11783292, 'bl method.Vector.operator_float__'), (11783308, 'bl method.Vector.operator_float__'), (11783340, 'bl sym.imp.__wrap_glUniform4f'), (11783480, 'bl method.Vector2.operator_float__'), (11783496, 'bl method.Vector2.operator_float__'), (11783740, 'bl 0xb3dcf4'), (11783880, 'bl sym.imp.__wrap_glEnable'), (11783916, 'bl loc.imp.objc_msgSend'), (11783936, 'bl sym.imp.__wrap_glBindTexture'), (11784888, 'bl 0xb3dedc'), (11785104, 'bl sym.imp.memcpy'), (11785140, 'blx r3'), (11785160, 'blx r3'), (11785176, 'blx r2'), (11785208, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (11785320, 'bl sym.drawShaderQuad'), (11785416, 'bl method.Vector.operator_float__'), (11785448, 'bl method.Vector.operator_float__'), (11785480, 'bl method.Vector.operator_float__'), (11785560, 'bl 0xb3a244'), (11785612, 'bl loc.imp.objc_msgSend'), (11785988, 'bl 0xb3dcf4'), (11786476, 'bl 0xb3e510'), (11787440, 'bl loc.imp.objc_msgSend'), (11787448, 'bl sym.imp.__wrap_glDisable'), (11787452, 'bl sym.popDepthMaskState')],
        branches=[(11773324, 'blt', 11773412), (11773408, 'b', 11773616), (11773528, 'bge', 11773612), (11773612, 'b', 11773616), (11773744, 'blt', 11773832), (11773828, 'b', 11774036), (11773948, 'bge', 11774032), (11774032, 'b', 11774036), (11774076, 'blt', 11774204), (11774120, 'bgt', 11774204), (11774160, 'blt', 11774204), (11774200, 'ble', 11774208), (11774204, 'b', 11787456), (11774392, 'ble', 11774520), (11774516, 'b', 11774784), (11774656, 'bpl', 11774780), (11774780, 'b', 11774784), (11774956, 'bne', 11774964), (11774960, 'b', 11787456), (11775020, 'beq', 11775048), (11775044, 'b', 11775084), (11775832, 'bpl', 11775856), (11775852, 'b', 11775872), (11775920, 'bpl', 11775944), (11775940, 'b', 11775960), (11776008, 'ble', 11776080), (11776240, 'beq', 11776404), (11776260, 'b', 11776436), (11779824, 'b', 11779836), (11781964, 'b', 11781980), (11784988, 'b', 11785048), (11785360, 'beq', 11787444)],
        semantics=('TrainStation -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:] @0xb3a2b0 (3729 words = the batch heavyweight, [census] grade, 159 call rows / 32 branches / 0 loops): 4KB+ frame (sub sp,#0xfb0, bic sp,#0xf), two GLKMatrix4 args by value (64B each) plus 4 camera ints read from the stack. Head: prologue wrap math (6x __aeabi_idiv for worldWidthMacro-based x normalisation, as in worldChanged:), then tileAtWorldPosition(pos.x,pos.y,&macroTile,self->world) with an early exit to the epilogue when nil (0xb3abec -> 0xb3dcc0). Bind pass: [self->world dayColor] as a 16-byte stret struct (zero-filled via memset,#0x10 when nil, 0xb3ac48), glBindTexture(GL_TEXTURE_2D 0xde1) for InteractionObject.texture@64 and, after glActiveTexture(GL_TEXTURE1 0x84c1), for TrainStation.tileDestructTexture@108. Body: two glUseProgram (0xb3ad84, 0xb3cbcc) with 3 glEnableVertexAttribArray / 1 glDisableVertexAttribArray / 5 glEnable / 2 glDisable (GL_BLEND 0xbe2 at the tail), 7 glUniformMatrix4fv (mvp + normal matrices), 4 glUniform4f (day colour / sign colour), 3 glUniform1i (texture units), 4 glBindTexture, glDisable + pushDepthMaskState (0xb3cb7c) / popDepthMaskState (0xb3dcbc) around the sign pass, 1 drawShaderQuad (0xb3d468) and 1 memcpy. Station geometry is unrolled Vector/Vector2 math (21 Vector.operator_float__ + 12 Vector2.operator_float__ + 3 Vector ctors + 52 objc_msgSend) over the float constants -1.5/-1.4/-1.03/-0.99/0.3/0.013089 (movw+movt pairs) and vmov.f32 #1.0 x5; ivar cells used: pos@16, world@4, floatPos@24, texture@64, tileDestructTexture@108, cubeShader@100, platformBlock@112, poleDrawCube@116, signShader@104, bitmapString@120. Sign tail (0xb3d2d8..0xb3da88): uniform lookup by name through [signShader program] -> uniformLocations -> objectAtIndex:[name intValue], then setColor: and renderWithProjectionMatrix:modelViewMatrix: on bitmapString@120; local stub calls 0xb3dcf4 x3, 0xb3dedc x6, 0xb3e49c x2, 0xb3e510 x1, 0xb3a244 x1.'),
    ),
    dict(
        name='ts_05',
        method='TrainStation -[freeBlockCreationDataA]',
        types='S8@0:4',
        start=11790128,
        end=11790156,
        disasm='disasm_worldtileloader_ts_05.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00b3e768; body trimmed at the next IMP 0x00b3e74c TrainStation -[freeBlockCreationDataB]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11790128, 'sub sp, sp, 8'), (11790152, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('TrainStation -[freeBlockCreationDataA] @0xb3e730 (7 words, 0 calls/branches): constant getter - movw r2,#0 then uxth r0,r2 returns u16 dataA = 0; the station\'s free-block creation record carries no dataA byte.'),
    ),
    dict(
        name='ts_06',
        method='TrainStation -[freeBlockCreationDataB]',
        types='S8@0:4',
        start=11790156,
        end=11790184,
        disasm='disasm_worldtileloader_ts_06.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00b3e768 (listing bound); next ObjC IMP 0x00b3e768 TrainStation -[remove:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11790156, 'sub sp, sp, 8'), (11790180, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('TrainStation -[freeBlockCreationDataB] @0xb3e74c (7 words, 0 calls/branches): constant getter - movw r2,#0 then uxth r0,r2 returns u16 dataB = 0 (same shape as freeBlockCreationDataA; the pair is the default \'no extra data\' answer for the free-block creation path).'),
    ),
    dict(
        name='ts_07',
        method='TrainStation -[freeBlockCreationSaveDict]',
        types='@8@0:4',
        start=11790052,
        end=11790128,
        disasm='disasm_worldtileloader_ts_07.txt',
        base_add=11790068,
        base_literal=11790124,
        boundary='ARM.exidx end 0x00b3e730 (listing bound); next ObjC IMP 0x00b3e730 TrainStation -[freeBlockCreationDataA]',
        selectors={
                 0xb3e728: (15230168, 'getSaveDict'),
        },
        imports={
                 0xb3e724: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(11790052, 'push {fp, lr}'), (11790124, 'ldrsheq r1, [r2], -0x38')],
        calls=[(11790104, 'blx r3')],
        branches=[],
        semantics=('TrainStation -[freeBlockCreationSaveDict] @0xb3e6e4 (19 words, 1 indirect send): pure forwarder - loads the getSaveDict selref cell (0xb3e728), keeps self in r0 and tails through objc_msgSend (blx r3), i.e. return [self getSaveDict]; the station reuses the InteractionObject save dict for the free-block creation record.'),
    ),
    dict(
        name='ts_08',
        method='TrainStation -[freeblockCreationItemType]',
        types='i8@0:4',
        start=11790024,
        end=11790052,
        disasm='disasm_worldtileloader_ts_08.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00b3e6e4 (listing bound); next ObjC IMP 0x00b3e6e4 TrainStation -[freeBlockCreationSaveDict]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11790024, 'sub sp, sp, 8'), (11790048, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('TrainStation -[freeblockCreationItemType] @0xb3e6c8 (7 words, 0 calls/branches): constant getter - movw r2,#0xc8 / mov r0,r2 returns ItemType 200 = TrainStation, identical to destroyItemType (the free block created when the station is removed is a station item).'),
    ),
    dict(
        name='ts_09',
        method='TrainStation -[initSubDerivedItems]',
        types='v8@0:4',
        start=11763932,
        end=11766136,
        disasm='disasm_worldtileloader_ts_09.txt',
        base_add=11763952,
        base_literal=11766132,
        boundary='ARM.exidx end 0x00b38978 (listing bound); next ObjC IMP 0x00b38978 TrainStation -[initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:]',
        selectors={
                 0xb388d8: (15230120, 'updateBitmapString'),
                 0xb388e4: (15230116, 'initWithWidth:height:depth:topMinS:topMaxS:topMinT:topMaxT:sideMinS:sideMaxS:sideMinT:sideMaxT:calculateNormals:'),
                 0xb388e8: (15230108, 'alloc'),
                 0xb38900: (15230112, 'initPyramidWithWidth:height:depth:centerX:centerY:centerZ:topMinS:topMaxS:topMinT:topMaxT:sideMinS:sideMaxS:sideMinT:sideMaxT:calculateNormals:topScale:rightScale:'),
                 0xb3890c: (15230096, 'shaderNamed:attributes:uniforms:'),
                 0xb3891c: (15230092, 'arrayWithObjects:'),
                 0xb3895c: (15230104, 'textureNamed:withAlpha:'),
                 0xb38968: (15230100, 'textureNamed:'),
        },
        imports={
                 0xb388d4: (17151904, 'objc_msgSend'),
                 0xb38908: (16373224, '__CFConstantStringClassReference'),
                 0xb38910: (16373032, '__CFConstantStringClassReference'),
                 0xb38914: (16373048, '__CFConstantStringClassReference'),
                 0xb38918: (16373240, '__CFConstantStringClassReference'),
                 0xb38924: (16373000, '__CFConstantStringClassReference'),
                 0xb38928: (16373016, '__CFConstantStringClassReference'),
                 0xb38934: (16373112, '__CFConstantStringClassReference'),
                 0xb38938: (16373144, '__CFConstantStringClassReference'),
                 0xb3893c: (16373160, '__CFConstantStringClassReference'),
                 0xb38940: (16373176, '__CFConstantStringClassReference'),
                 0xb38944: (16373192, '__CFConstantStringClassReference'),
                 0xb38948: (16373208, '__CFConstantStringClassReference'),
                 0xb3894c: (16373128, '__CFConstantStringClassReference'),
                 0xb38954: (16373080, '__CFConstantStringClassReference'),
                 0xb38958: (16373096, '__CFConstantStringClassReference'),
                 0xb38964: (16373064, '__CFConstantStringClassReference'),
                 0xb38970: (16372984, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xb388dc: (17165780, 'OBJC_IVAR_$_TrainStation.poleDrawCube', 116),
                 0xb388f0: (17165784, 'OBJC_IVAR_$_TrainStation.platformBlock', 112),
                 0xb38904: (17165788, 'OBJC_IVAR_$_TrainStation.signShader', 104),
                 0xb3892c: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0xb38930: (17165792, 'OBJC_IVAR_$_TrainStation.cubeShader', 100),
                 0xb38950: (17165796, 'OBJC_IVAR_$_TrainStation.tileDestructTexture', 108),
                 0xb38960: (17156844, 'OBJC_IVAR_$_InteractionObject.texture', 64),
                 0xb3896c: (17156776, 'OBJC_IVAR_$_InteractionObject.shader', 60),
        },
        classes={
                 0xb388ec: (15249820, 'OBJC_CLASS_$_DrawCube'),
                 0xb38920: (15249816, 'OBJC_CLASS_$_NSArray'),
        },
        instructions=[(11763932, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11766132, 'ldrsheq r7, [r2], -0x9c')],
        calls=[(11764424, 'blx ip'), (11764472, 'blx lr'), (11764516, 'blx lr'), (11764576, 'blx ip'), (11764640, 'blx ip'), (11764736, 'blx r5'), (11764824, 'blx r8'), (11764868, 'blx lr'), (11764956, 'blx r4'), (11765012, 'blx r4'), (11765056, 'blx lr'), (11765088, 'bl sym.texCoordsForImageIndex_int_'), (11765268, 'blx r5'), (11765536, 'blx lr'), (11765572, 'bl sym.tileTexCoordsForItemType_ItemType__signed_char_'), (11765588, 'bl sym.tileTexCoordsForItemType_ItemType__signed_char_'), (11765736, 'blx r7'), (11765916, 'blx lr'), (11765956, 'blx r3')],
        branches=[],
        semantics=('TrainStation -[initSubDerivedItems] @0xb380dc (551 words, 0 branches, 19 calls: 16 blx + 3 bl; [census-lite]: slot-table reconstruction of the ~90-instruction cell preload plus key windows). Builds the whole render set into fp-relative slots and writes InteractionObject.shader@60 / texture@64 and TrainStation.cubeShader@100 / signShader@104 / tileDestructTexture@108 / platformBlock@112 / poleDrawCube@116: [self->cache shaderNamed:attributes:uniforms:] twice with NSArray attribute sets {position, texCoord, normal} and uniform sets {mvp_matrix, texture, daylight, lightPosition, artificalLight, normal_matrix, destruct_texture} (the CFString cells 0xf9d4f8..0xf9d5e8; shader names StandardObject/FreeBlock/WorldObject); [cache textureNamed:@"TileMap.png"] (0xf9d548), [cache textureNamed:withAlpha:@"TileReflect.png"] (0xf9d568) and "TileDestruct.png" (0xf9d558); [DrawCube alloc] initWithWidth:height:depth:topMinS:...:calculateNormals: -> platformBlock; texCoordsForImageIndex(0xcb = 203) then [DrawCube alloc] initPyramidWithWidth:...:calculateNormals:topScale:rightScale: with float constants 4.0/2.0/1.0/0.2/0.0/0.7 and 5.0 (d7) -> poleDrawCube; tail does tileTexCoordsForItemType(0x419 = 1049) twice and ends with [self updateBitmapString].'),
    ),
    dict(
        name='ts_10',
        method='TrainStation -[initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:]',
        types='@48@0:4@8@12{?=ii}16@24@28c32@36@40@44',
        start=11766136,
        end=11767688,
        disasm='disasm_worldtileloader_ts_10.txt',
        base_add=11766152,
        base_literal=11767684,
        boundary='ARM.exidx end 0x00b38f88 (listing bound); next ObjC IMP 0x00b38f88 TrainStation -[initWithWorld:dynamicWorld:saveDict:cache:]',
        selectors={
                 0xb38f40: (15230124, 'initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:'),
                 0xb38f4c: (15230132, 'retain'),
                 0xb38f54: (15230128, 'objectForKey:'),
                 0xb38f5c: (15230136, 'initWithString:'),
                 0xb38f60: (15230108, 'alloc'),
                 0xb38f74: (15230140, 'fillTile:atPos:withType:dataA:dataB:placedByClient:saveDict:placedByClientName:'),
                 0xb38f80: (15230144, 'initSubDerivedItems'),
        },
        imports={
                 0xb38f48: (17151904, 'objc_msgSend'),
                 0xb38f50: (16373256, '__CFConstantStringClassReference'),
                 0xb38f58: (16373272, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xb38f44: (17165800, 'OBJC_IVAR_$_TrainStation.text', 128),
                 0xb38f68: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xb38f6c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={
                 0xb38f38: (15253132, 'OBJC_CLASS_$_TrainStation'),
                 0xb38f64: (15249824, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(11766136, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11767684, 'subseq r7, r2, r4, ror 2')],
        calls=[(11766428, 'bl loc.imp.objc_msgSendSuper2'), (11766560, 'blx r3'), (11766576, 'blx r2'), (11766712, 'blx r3'), (11766732, 'blx r3'), (11766828, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11766996, 'bl loc.imp.objc_msgSend'), (11767076, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11767192, 'bl sym.makeIntpair_int__int_'), (11767268, 'bl loc.imp.objc_msgSend'), (11767348, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11767464, 'bl sym.makeIntpair_int__int_'), (11767540, 'bl loc.imp.objc_msgSend'), (11767584, 'blx r2')],
        branches=[(11766456, 'bne', 11766472), (11766468, 'b', 11767596), (11766624, 'bne', 11766756), (11766848, 'beq', 11767000), (11767096, 'beq', 11767272), (11767368, 'beq', 11767544)],
        semantics=('TrainStation -[initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:] @0xb38978 (388 words, 6 branches, 14 calls): the placed-by-client ctor. Forwards all 9 arguments to objc_msgSendSuper2({self, TrainStation}, same selector) with pos.x/pos.y as the first two stack words (fp = entry_sp-8, so the 8 argument words live at [fp,#8..#0x24]); returns nil if super failed. Then text: [[saveDict objectForKey:@"text"] retain] stored to text@128 (cell key 0xf9d608), and when the result is nil it falls back to [[NSString alloc] initWithString:@"TRAIN"] (CFString 0xf9d618) - the station\'s default name. Finally three tile probes with fillTile:atPos:withType:dataA:dataB:placedByClient:saveDict:placedByClientName: at withType 0xc7 (199), dataA 1, dataB 0, placedByClient 0, saveDict 0, name 0: probe (x,y) -> fill (x,y), probe (x+1,y) -> fill (x-1,y), probe (x-1,y) -> fill (x+1,y) (the cross pairing is as compiled; makeIntpair@0x4b49fc writes arg1 to [r0] and arg2 to [r0+4]); then [self initSubDerivedItems].'),
    ),
    dict(
        name='ts_11',
        method='TrainStation -[initWithWorld:dynamicWorld:cache:netData:]',
        types='@24@0:4@8@12@16@20',
        start=11768108,
        end=11768924,
        disasm='disasm_worldtileloader_ts_11.txt',
        base_add=11768124,
        base_literal=11768920,
        boundary='ARM.exidx end 0x00b3945c (listing bound); next ObjC IMP 0x00b39480 TrainStation -[getSaveDict]',
        selectors={
                 0xb39418: (15230152, 'initWithWorld:dynamicWorld:cache:netData:'),
                 0xb39424: (15230144, 'initSubDerivedItems'),
                 0xb3942c: (15230132, 'retain'),
                 0xb39434: (15230128, 'objectForKey:'),
                 0xb39448: (15230164, 'gzipInflate'),
                 0xb3944c: (15230156, 'length'),
                 0xb39454: (15230160, 'subdataWithRange:'),
        },
        imports={
                 0xb39414: (17151900, 'objc_msgSendSuper2'),
                 0xb39420: (17151904, 'objc_msgSend'),
                 0xb39430: (16373304, '__CFConstantStringClassReference'),
                 0xb3943c: (16373288, '__CFConstantStringClassReference'),
                 0xb39444: (16373256, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xb39428: (17156788, 'OBJC_IVAR_$_InteractionObject.ownerName', 84),
                 0xb39438: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
                 0xb39440: (17165800, 'OBJC_IVAR_$_TrainStation.text', 128),
        },
        classes={
                 0xb3941c: (15253132, 'OBJC_CLASS_$_TrainStation'),
        },
        instructions=[(11768108, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11768920, 'ldrheq r6, [r2], -0x90')],
        calls=[(11768260, 'blx r6'), (11768364, 'bl loc.imp.objc_msgSend'), (11768432, 'bl loc.imp.objc_msgSend'), (11768456, 'blx r2'), (11768460, 'bl 0xb3945c'), (11768652, 'blx r3'), (11768668, 'blx r2'), (11768712, 'blx r3'), (11768728, 'blx r2'), (11768772, 'blx r3'), (11768788, 'blx r2'), (11768828, 'blx r3')],
        branches=[(11768288, 'bne', 11768304), (11768300, 'b', 11768840)],
        semantics=('TrainStation -[initWithWorld:dynamicWorld:cache:netData:] @0xb3912c (204 words, 2 branches, 12 calls): net twin of the placement ctor. super initWithWorld:dynamicWorld:cache:netData: with cache/netData taken from the 5th and 6th argument words (the 4-argument selector still receives two stack words); nil result returns nil. Then netData is split: tail = [netData subdataWithRange:NSMakeRange(0x28, [netData length] - 0x28)] (0x28 = 40 = the InteractionObjectNetData prefix), dict = helper 0xb3945c([tail gzipInflate]) (plist reader through propertyListWithData:options:format:error: with options 0 at 0xb3fa08), and the decoded fields are applied: self->text@128 = [[dict objectForKey:@"text"] retain], self->ownerID@36 = [[dict objectForKey:@"ownerID"] retain], self->ownerName@84 = [[dict objectForKey:@"ownerName"] retain], then [self initSubDerivedItems] and return self.'),
    ),
    dict(
        name='ts_12',
        method='TrainStation -[interactionObjectType]',
        types='S8@0:4',
        start=11772560,
        end=11772592,
        disasm='disasm_worldtileloader_ts_12.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00b3a2b0 (listing bound); next ObjC IMP 0x00b3a2b0 TrainStation -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11772560, 'sub sp, sp, 8'), (11772588, 'andeq r0, r0, r0')],
        calls=[],
        branches=[],
        semantics=('TrainStation -[interactionObjectType] @0xb3a290 (8 words, 0 calls/branches): constant getter - movw r2,#6 then uxth r0,r2 returns u16 6, the TrainStation InteractionObjectType written into the +0x20 u16 slot of the 0x28-byte InteractionObjectCreationNetData (ladder: base 0, Chest 2, TradingPost 5, TrainStation 6); the 8th word is an alignment filler (0x00b3a2ac andeq r0,r0,r0) after bx lr.'),
    ),
    dict(
        name='ts_13',
        method='TrainStation -[interactionRenderItemType]',
        types='i8@0:4',
        start=11794896,
        end=11794924,
        disasm='disasm_worldtileloader_ts_13.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00b3fa08; body trimmed at the next IMP 0x00b3f9ec TrainStation -[occupiesNormalContents]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11794896, 'sub sp, sp, 8'), (11794920, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('TrainStation -[interactionRenderItemType] @0x00b3f9d0 (7 words, 0 calls/branches): constant getter - movw r2,#0xc8 / mov r0,r2 returns ItemType 200 = TrainStation, the item rendered for the station\'s interaction surface.'),
    ),
    dict(
        name='ts_14',
        method='TrainStation -[occupiesNormalContents]',
        types='c8@0:4',
        start=11794924,
        end=11794952,
        disasm='disasm_worldtileloader_ts_14.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00b3fa08 (listing bound); next ObjC IMP 0x00b401d0 TableSelectionAlertView -[initWithTitle:message:options:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11794924, 'sub sp, sp, 8'), (11794948, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('TrainStation -[occupiesNormalContents] @0x00b3f9ec (7 words, 0 calls/branches): constant getter - movw r2,#1 then sxtb r0,r2 returns YES: the station occupies the tile\'s normal contents (no special content byte is reserved for it).'),
    ),
    dict(
        name='ts_15',
        method='TrainStation -[remoteUpdate:]',
        types='v12@0:4@8',
        start=11770572,
        end=11771376,
        disasm='disasm_worldtileloader_ts_15.txt',
        base_add=11770588,
        base_literal=11771372,
        boundary='ARM.exidx end 0x00b39df0 (listing bound); next ObjC IMP 0x00b39df0 TrainStation -[dealloc]',
        selectors={
                 0xb39da8: (15230200, 'remoteUpdate:'),
                 0xb39dbc: (15230132, 'retain'),
                 0xb39dc4: (15230128, 'objectForKey:'),
                 0xb39dc8: (15230208, 'release'),
                 0xb39dd4: (15230204, 'setText:'),
                 0xb39ddc: (15230164, 'gzipInflate'),
                 0xb39de0: (15230156, 'length'),
                 0xb39de8: (15230160, 'subdataWithRange:'),
        },
        imports={
                 0xb39da4: (17151900, 'objc_msgSendSuper2'),
                 0xb39db8: (17151904, 'objc_msgSend'),
                 0xb39dc0: (16373304, '__CFConstantStringClassReference'),
                 0xb39dd0: (16373288, '__CFConstantStringClassReference'),
                 0xb39dd8: (16373256, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xb39db0: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0xb39db4: (17156788, 'OBJC_IVAR_$_InteractionObject.ownerName', 84),
                 0xb39dcc: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
        },
        classes={
                 0xb39dac: (15253132, 'OBJC_CLASS_$_TrainStation'),
        },
        instructions=[(11770572, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11771372, 'subseq r6, r2, r0, lsl r0')],
        calls=[(11770664, 'blx lr'), (11770768, 'bl loc.imp.objc_msgSend'), (11770836, 'bl loc.imp.objc_msgSend'), (11770860, 'blx r2'), (11770864, 'bl 0xb3945c'), (11771068, 'blx r5'), (11771096, 'blx r3'), (11771132, 'blx r3'), (11771156, 'blx r3'), (11771172, 'blx r2'), (11771228, 'blx ip'), (11771252, 'blx r3'), (11771268, 'blx r2')],
        branches=[(11770704, 'bne', 11771292)],
        semantics=('TrainStation -[remoteUpdate:] @0xb39acc (201 words, 1 branch, 13 calls): net update path. objc_msgSendSuper2({self,TrainStation}, @selector(remoteUpdate:), data) first, then the gate if (self->currentBlockhead != nil) return; (currentBlockhead@56, 0xb39b50 -> epilogue, i.e. ignored while a local blockhead is attached). Otherwise tail = [data subdataWithRange:NSMakeRange(0x28, [data length]-0x28)], dict = helper 0xb3945c([tail gzipInflate]), and the fields are refreshed with an asymmetric discipline: [self setText:[dict objectForKey:@"text"]] (which itself releases the old string, retains the new one, calls updateBitmapString and notifies dynamicWorldChangedAtPos:objectType: + railOrStationNameChanged), while ownerID@36 and ownerName@84 are released and replaced manually by [[dict objectForKey:...] retain].'),
    ),
    dict(
        name='ts_16',
        method='TrainStation -[remove:]',
        types='v12@0:4@8',
        start=11790184,
        end=11791580,
        disasm='disasm_worldtileloader_ts_16.txt',
        base_add=11790200,
        base_literal=11791576,
        boundary='ARM.exidx end 0x00b3ecdc (listing bound); next ObjC IMP 0x00b3ecdc TrainStation -[setNeedsRemoved:]',
        selectors={
                 0xb3ec9c: (15230276, 'isNet'),
                 0xb3ecac: (15230280, 'stopInteracting'),
                 0xb3ecb0: (15230284, 'removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:'),
                 0xb3ecbc: (15230296, 'railOrStationNameChanged'),
                 0xb3ecc8: (15230288, 'setNeedsRemoved:'),
                 0xb3eccc: (15230168, 'getSaveDict'),
                 0xb3ecd0: (15230292, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
        },
        imports={
                 0xb3ec98: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xb3ec8c: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0xb3ec90: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xb3ec94: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0xb3eca0: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0xb3eca4: (17156816, 'OBJC_IVAR_$_InteractionObject.remoteBlockheadInUseUniqueID', 72),
                 0xb3ecb4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xb3ecb8: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xb3ecc0: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xb3ecd4: (17156820, 'OBJC_IVAR_$_InteractionObject.needsToBeRemovedWhenInteractionEnds', 96),
        },
        classes={},
        instructions=[(11790184, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11791576, 'subseq r1, r2, r4, ror r3')],
        calls=[(11790388, 'blx r2'), (11790548, 'blx r2'), (11790780, 'bl loc.imp.objc_msgSend'), (11790804, 'bl loc.imp.objc_msgSend'), (11790876, 'bl loc.imp.objc_msgSend'), (11790964, 'bl loc.imp.objc_msgSend'), (11791000, 'blx r3'), (11791096, 'blx ip'), (11791196, 'blx ip'), (11791292, 'blx ip'), (11791388, 'blx ip'), (11791488, 'blx ip')],
        branches=[(11790248, 'bne', 11790288), (11790284, 'beq', 11790292), (11790288, 'b', 11791492), (11790324, 'beq', 11790556), (11790400, 'bne', 11790452), (11790444, 'beq', 11790488), (11790448, 'b', 11790452), (11790484, 'b', 11791492), (11790552, 'b', 11790556)],
        semantics=('TrainStation -[remove:] @0xb3e768 (349 words, 9 branches, 12 calls): the destruction path. Guards: return when self->needsRemoved@48 (0xb3e7a4) or when NOT self->isNet@52 (0xb3e7d0). If self->isInUse@68 then: if [self->currentBlockhead isNet] or the 64-bit remoteBlockheadInUseUniqueID@72 is nonzero -> self->needsToBeRemovedWhenInteractionEnds@96 = 1 and return; else [self->currentBlockhead stopInteracting] and continue. Then [self->world removeTileAtWorldX:pos.x worldY:pos.y createContentsFreeblockCount:0 createForegroundContentsFreeblockCount:0 removeBlockhead:arg]; [self setNeedsRemoved:1]; [self->dynamicWorld createFreeBlockAtPosition:pos ofType:200 dataA:0 dataB:0 subItems:nil dynamicObjectSaveDict:[self getSaveDict] hovers:0 playSound:1 priorityBlockhead:arg]; [self->dynamicWorld railOrStationNameChanged]; then five more removeTileAtWorldX calls for the rest of the station footprint: (x-1,y), (x-1,y+1), (x,y+1), (x+1,y), (x+1,y+1) - six tiles in total, a 3x2 block.'),
    ),
    dict(
        name='ts_17',
        method='TrainStation -[requiresHumanInteraction]',
        types='c8@0:4',
        start=11792648,
        end=11792676,
        disasm='disasm_worldtileloader_ts_17.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00b3f198; body trimmed at the next IMP 0x00b3f124 TrainStation -[text]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11792648, 'sub sp, sp, 8'), (11792672, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('TrainStation -[requiresHumanInteraction] @0x00b3f108 (7 words, 0 calls/branches): constant getter - movw r2,#1 then sxtb r0,r2 returns YES, i.e. a blockhead must interact to use the station.'),
    ),
    dict(
        name='ts_18',
        method='TrainStation -[requiresSingleLineTextEditing]',
        types='c8@0:4',
        start=11792736,
        end=11792764,
        disasm='disasm_worldtileloader_ts_18.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00b3f198; body trimmed at the next IMP 0x00b3f17c TrainStation -[destroyItemType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11792736, 'sub sp, sp, 8'), (11792760, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('TrainStation -[requiresSingleLineTextEditing] @0x00b3f160 (7 words, 0 calls/branches): constant getter - movw r2,#1 then sxtb r0,r2 returns YES: the station\'s text@128 is edited through the one-line text UI (setText:/text are the accessors of that path).'),
    ),
    dict(
        name='ts_19',
        method='TrainStation -[setNeedsRemoved:]',
        types='v12@0:4c8',
        start=11791580,
        end=11792036,
        disasm='disasm_worldtileloader_ts_19.txt',
        base_add=11791596,
        base_literal=11792032,
        boundary='ARM.exidx end 0x00b3eea4 (listing bound); next ObjC IMP 0x00b3eea4 TrainStation -[title]',
        selectors={
                 0xb3ee88: (15230288, 'setNeedsRemoved:'),
                 0xb3ee9c: (15230300, 'removeRailAtPos:'),
        },
        imports={
                 0xb3ee84: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0xb3ee90: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xb3ee98: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={
                 0xb3ee8c: (15253132, 'OBJC_CLASS_$_TrainStation'),
        },
        instructions=[(11791580, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11792032, 'subseq r0, r2, r0, lsl 28')],
        calls=[(11791760, 'bl loc.imp.objc_msgSend'), (11791820, 'bl sym.makeIntpair_int__int_'), (11791848, 'bl loc.imp.objc_msgSend'), (11791908, 'bl sym.makeIntpair_int__int_'), (11791936, 'bl loc.imp.objc_msgSend'), (11791992, 'blx lr')],
        branches=[],
        semantics=('TrainStation -[setNeedsRemoved:] @0xb3ecdc (114 words, 0 branches, 6 calls): rail cleanup before the flag is set. Reads pos (pre-indexed ldr r7,[r0,r7]! -> pos.x@16, then [r0,4] -> pos.y) and calls [self->dynamicWorld removeRailAtPos:(x,y)], [.. removeRailAtPos:makeIntpair(x-1,y)] and [.. removeRailAtPos:makeIntpair(x+1,y)] - the station tile and both horizontal neighbours, straight-line (0 branches) - then objc_msgSendSuper2({self,TrainStation}, @selector(setNeedsRemoved:flag)) with the char flag sxtb\'d from fp-0x21.'),
    ),
    dict(
        name='ts_20',
        method='TrainStation -[setText:]',
        types='v12@0:4@8',
        start=11792180,
        end=11792648,
        disasm='disasm_worldtileloader_ts_20.txt',
        base_add=11792196,
        base_literal=11792644,
        boundary='ARM.exidx end 0x00b3f108 (listing bound); next ObjC IMP 0x00b3f108 TrainStation -[requiresHumanInteraction]',
        selectors={
                 0xb3f0d8: (15230304, 'isEqualToString:'),
                 0xb3f0e0: (15230296, 'railOrStationNameChanged'),
                 0xb3f0ec: (15230308, 'autorelease'),
                 0xb3f0f0: (15230132, 'retain'),
                 0xb3f0f4: (15230120, 'updateBitmapString'),
                 0xb3f0fc: (15230312, 'objectType'),
                 0xb3f100: (15230316, 'dynamicWorldChangedAtPos:objectType:'),
        },
        imports={
                 0xb3f0d4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xb3f0dc: (17165800, 'OBJC_IVAR_$_TrainStation.text', 128),
                 0xb3f0e4: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xb3f0f8: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={},
        instructions=[(11792180, 'push {r4, r5, fp, lr}'), (11792644, 'subseq r0, r2, r8, lsr 23')],
        calls=[(11792264, 'blx ip'), (11792368, 'bl loc.imp.objc_msgSend'), (11792400, 'bl loc.imp.objc_msgSend'), (11792436, 'bl loc.imp.objc_msgSend'), (11792512, 'bl loc.imp.objc_msgSend'), (11792548, 'bl loc.imp.objc_msgSend'), (11792584, 'blx r3')],
        branches=[(11792276, 'bne', 11792588)],
        semantics=('TrainStation -[setText:] @0xb3ef34 (117 words, 1 branch, 7 calls): text setter with change propagation. Early return when [newText isEqualToString:self->text] (0xb3ef88, sxtb + bne to the epilogue, i.e. the argument is the receiver of the comparison). Otherwise [self->text autorelease], self->text@128 = [newText retain], [self updateBitmapString], then [self->dynamicWorld dynamicWorldChangedAtPos:pos objectType:[self objectType]] (objectType pushed as the 5th word on the stack) and [self->dynamicWorld railOrStationNameChanged].'),
    ),
    dict(
        name='ts_21',
        method='TrainStation -[text]',
        types='@8@0:4',
        start=11792676,
        end=11792736,
        disasm='disasm_worldtileloader_ts_21.txt',
        base_add=11792684,
        base_literal=11792732,
        boundary='ARM.exidx end 0x00b3f198; body trimmed at the next IMP 0x00b3f160 TrainStation -[requiresSingleLineTextEditing]',
        selectors={},
        imports={},
        ivars={
                 0xb3f158: (17165800, 'OBJC_IVAR_$_TrainStation.text', 128),
        },
        classes={},
        instructions=[(11792676, 'sub sp, sp, 8'), (11792732, 'subseq r0, r2, r0, asr 19')],
        calls=[],
        branches=[],
        semantics=('TrainStation -[text] @0x00b3f124 (15 words, 0 calls/branches): plain ivar getter - the two-stage Apportable cell (pool 0xb3f158 = delta -0xd0c -> GOT cell -> OBJC_IVAR_$_TrainStation.text word, first dword 128) then ldr r0,[self+128]; returns the NSString without retain/autorelease. The second pool word (0xb3f15c) is the PIC base anchor, not data.'),
    ),
    dict(
        name='ts_22',
        method='TrainStation -[title]',
        types='@8@0:4',
        start=11792036,
        end=11792180,
        disasm='disasm_worldtileloader_ts_22.txt',
        base_add=11792052,
        base_literal=11792176,
        boundary='ARM.exidx end 0x00b3ef34 (listing bound); next ObjC IMP 0x00b3ef34 TrainStation -[setText:]',
        selectors={
                 0xb3ef24: (15230216, 'stringWithFormat:'),
        },
        imports={
                 0xb3ef1c: (16373320, '__CFConstantStringClassReference'),
                 0xb3ef20: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xb3ef28: (17165800, 'OBJC_IVAR_$_TrainStation.text', 128),
        },
        classes={
                 0xb3ef2c: (15249824, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(11792036, 'push {r4, r5, fp, lr}'), (11792176, 'subseq r0, r2, r8, lsr ip')],
        calls=[(11792144, 'blx ip')],
        branches=[],
        semantics=('TrainStation -[title] @0xb3eea4 (36 words, 1 indirect send): returns [NSString stringWithFormat:"%@ STATION", self->text] - the receiver class cell is OBJC_CLASS_$_NSString, the format CFString is "%@ STATION" (16-byte constant record at 0xf9d648, flags 0x7c8, len 10) and the single argument is text@128 read through its ivar cell; no caching, a fresh immutable string per call.'),
    ),
    dict(
        name='ts_23',
        method='TrainStation -[updateBitmapString]',
        types='v8@0:4',
        start=11771744,
        end=11772440,
        disasm='disasm_worldtileloader_ts_23.txt',
        base_add=11771760,
        base_literal=11772436,
        boundary='ARM.exidx end 0x00b3a218 (listing bound); next ObjC IMP 0x00b3a290 TrainStation -[interactionObjectType]',
        selectors={
                 0xb3a1e4: (15230216, 'stringWithFormat:'),
                 0xb3a1f0: (15230208, 'release'),
                 0xb3a200: (15230108, 'alloc'),
                 0xb3a208: (15230220, 'embossedFont'),
                 0xb3a210: (15230224, 'initWithString:dimensions:horizontalAlignment:font:cache:color:'),
        },
        imports={
                 0xb3a1dc: (16373320, '__CFConstantStringClassReference'),
                 0xb3a1e0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xb3a1d8: (17165800, 'OBJC_IVAR_$_TrainStation.text', 128),
                 0xb3a1ec: (17165804, 'OBJC_IVAR_$_TrainStation.bitmapString', 120),
                 0xb3a1f4: (17165808, 'OBJC_IVAR_$_TrainStation.needsToUpdateBitmapString', 124),
                 0xb3a20c: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
        },
        classes={
                 0xb3a1e8: (15249824, 'OBJC_CLASS_$_NSString'),
                 0xb3a1f8: (15249836, 'OBJC_CLASS_$_BitmapString'),
                 0xb3a204: (15249840, 'OBJC_CLASS_$_BitmapFont'),
        },
        instructions=[(11771744, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11772436, 'subseq r5, r2, ip, ror fp')],
        calls=[(11771940, 'blx r4'), (11772020, 'blx ip'), (11772108, 'bl loc.imp.objc_msgSend'), (11772156, 'bl 0xb3a218'), (11772180, 'bl loc.imp.objc_msgSend'), (11772248, 'bl 0xb3a244'), (11772344, 'bl loc.imp.objc_msgSend')],
        branches=[(11772056, 'beq', 11772368)],
        semantics=('TrainStation -[updateBitmapString] @0xb39f60 (174 words, 1 branch, 7 calls): rebuilds the station sign. First self->needsToUpdateBitmapString@124 = 0 (strb of movw #0), [self->bitmapString release] and bitmapString@120 = nil; then an early return when self->text == nil (0xb3a098 beq epilogue). Otherwise fmt = [NSString stringWithFormat:@"%@ STATION", self->text], and bitmapString@120 = [[BitmapString alloc] initWithString:fmt dimensions:Vector2(256.0f,48.0f) horizontalAlignment:1 font:[BitmapFont embossedFont] cache:self->cache color:Vector(1.0f,1.0f,1.0f,1.0f)] - the sizes come from movw/movt 0x43800000/0x42400000 and the colour/vector construction is done by the out-of-line stubs 0xb3a218 (Vector2) and 0xb3a244 (Vector 4-float).'),
    ),
    dict(
        name='ts_24',
        method='TrainStation -[updateNetDataForClient:]',
        types='@12@0:4@8',
        start=11769232,
        end=11769316,
        disasm='disasm_worldtileloader_ts_24.txt',
        base_add=11769248,
        base_literal=11769312,
        boundary='ARM.exidx end 0x00b395e4 (listing bound); next ObjC IMP 0x00b395e4 TrainStation -[creationNetDataForClient:]',
        selectors={
                 0xb395dc: (15230176, 'creationNetDataForClient:'),
        },
        imports={
                 0xb395d8: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(11769232, 'push {fp, lr}'), (11769312, 'subseq r6, r2, ip, asr 10')],
        calls=[(11769292, 'blx ip')],
        branches=[],
        semantics=('TrainStation -[updateNetDataForClient:] @0xb39590 (21 words, 1 indirect send): pure forwarder - objc_msgSend(self, @selector(creationNetDataForClient:), client) in a single tail call (blx ip), i.e. the per-update net record is byte-identical to the creation record for this class.'),
    ),
    dict(
        name='ts_25',
        method='TrainStation -[worldChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=11792792,
        end=11794356,
        disasm='disasm_worldtileloader_ts_25.txt',
        base_add=11792808,
        base_literal=11794352,
        boundary='ARM.exidx end 0x00b3f7b4 (listing bound); next ObjC IMP 0x00b3f7f0 TrainStation -[canBeUsedByBlockhead:]',
        selectors={
                 0xb3f798: (15230228, 'worldWidthMacro'),
                 0xb3f7ac: (15230320, 'remove:'),
        },
        imports={
                 0xb3f7a8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xb3f788: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xb3f78c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xb3f794: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(11792792, 'push {fp, lr}'), (11794352, 'subseq r0, r2, r4, asr 18')],
        calls=[(11793220, 'bl loc.imp.objc_msgSend'), (11793244, 'bl sym.imp.__aeabi_idiv'), (11793340, 'bl loc.imp.objc_msgSend'), (11793460, 'bl loc.imp.objc_msgSend'), (11793476, 'bl sym.imp.__aeabi_idiv'), (11793572, 'bl loc.imp.objc_msgSend'), (11793656, 'bl 0xb3f7b4'), (11793788, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11793816, 'bl sym.tileIsSolid_Tile_'), (11793876, 'blx r3'), (11793964, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11793992, 'bl sym.tileIsSolid_Tile_'), (11794052, 'blx r3'), (11794140, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11794168, 'bl sym.tileIsSolid_Tile_'), (11794228, 'blx r3')],
        branches=[(11792856, 'beq', 11792864), (11792860, 'b', 11794304), (11793100, 'beq', 11794304), (11793256, 'blt', 11793372), (11793368, 'b', 11793652), (11793488, 'bge', 11793604), (11793600, 'b', 11793644), (11793664, 'bge', 11794240), (11793708, 'bne', 11794240), (11793808, 'beq', 11793884), (11793828, 'bne', 11793884), (11793880, 'b', 11794304), (11793984, 'beq', 11794060), (11794004, 'bne', 11794060), (11794056, 'b', 11794304), (11794160, 'beq', 11794236), (11794180, 'bne', 11794236), (11794232, 'b', 11794304), (11794236, 'b', 11794240), (11794240, 'b', 11794244), (11794300, 'b', 11792948)],
        semantics=('TrainStation -[worldChanged:] @0xb3f198 (391 words, 21 branches, 16 calls): the argument is const std::vector<intpair>& (methtype ^{vector<intpair,...>}) and the body walks the changed-tile list (cursor stride 8 bytes, loop at 0xb3f234..0xb3f77c). Return immediately when self->isNet@52 (0xb3f1d8). For each entry it applies the world-wrap normalisation (worldWidthMacro << 5 divided by 2 through __aeabi_idiv, absolute value via 0xb3f7b4) and skips unless |normalised(pos.x - entry.x)| < 2 and entry.y == pos.y - 1 - i.e. only the three tiles directly above the station row matter. When that tile exists and !tileIsSolid(tile) it calls [self remove:nil] and returns; the same test runs for (pos.x, pos.y-1), (pos.x-1, pos.y-1) and (pos.x+1, pos.y-1). No other mutation path in the body.'),
    ),
    dict(
        name='ts_26',
        method='TrainStation -[objectType]',
        types='i8@0:4',
        start=11763904,
        end=11763932,
        disasm='disasm_worldtileloader_ts_26.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00b380dc (listing bound); next ObjC IMP 0x00b380dc TrainStation -[initSubDerivedItems]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11763904, 'sub sp, sp, 8'), (11763928, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('TrainStation -[objectType] @0xb380c0 (7 words, 0 branches, no calls): the class-constant stub - sub sp,#8; movw r2,0x31 (49); spill self/r1; mov r0,r2; add sp,#8; bx lr. Returns dynamic object type 49 for TrainStation, byte-identical in instruction words to the checked-in dynamicobject_type_objecttype_matrix.json row for TrainStation (imp 0x00b380c0, words 0xe24dd008/0xe3002031, type_id 49).'),
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
        'batch': 'TrainStation (E155): the rail station object; 27 bodies',
        'claim': ('\'the rail station surface (placement and net twin pair, sub-derived geometry, text editing, station removal); the train-side consumers are outside these bodies\''),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'trainstation.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale trainstation.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
