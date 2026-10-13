#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The electricity line: the SteamTrain remainder (the giant draw + update + smalls): the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 18484 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/STEAMTRAIN_CLOSE.md for the prose and boundaries.
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
    'bl 0xd20620': 0x00d20620,
    'bl 0xd20694': 0x00d20694,
    'bl 0xd20a2c': 0x00d20a2c,
    'bl 0xd20ce0': 0x00d20ce0,
    'bl 0xd2da64': 0x00d2da64,
    'bl 0xd2ddfc': 0x00d2ddfc,
    'bl 0xd2e3bc': 0x00d2e3bc,
    'bl 0xd2e5a4': 0x00d2e5a4,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector.Vector_float__float__float__float_': 0x004d0d08,
    'bl method.Vector.operator_float__': 0x004b5c08,
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl method.Vector2.normal__': 0x00575108,
    'bl method.Vector2.operator_Vector2_': 0x004d0418,
    'bl method.Vector2.operator__Vector2_': 0x004d04b4,
    'bl method.Vector2.operator_float_': 0x004d0368,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl sym.Vector2::operator_Vector2_': 0x00820690,
    'bl sym.Vector::operator_Vector_': 0x0058198c,
    'bl sym.drawShaderQuad': 0x007c43dc,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__wrap_fmodf': 0x001c3d4c,
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
    'bl sym.imp.atan2f': 0x001c410c,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.popDepthMaskState': 0x007c57ec,
    'bl sym.pushDepthMaskState': 0x007c55e4,
    'bl sym.texCoordsForItemType_ItemType_': 0x004d6040,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileAtWorldPosition_int__int__MacroTile__World_': 0x00a16e68,
    'bl sym.tileIsSolid_Tile_': 0x00a1179c,
    'bl sym.tileIsWater_Tile_': 0x00a11690,
}

SPECS = [
    dict(
        name='st4_draw',
        method='SteamTrain -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        types='v156@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76i140i144i148i152',
        start=13765920,
        end=13818468,
        disasm='disasm_worldtileloader_st4_draw.txt',
        base_add=13765960,
        base_literal=13769108,
        boundary='ARM.exidx end 0x00d2da64 (listing bound); next ObjC IMP 0x00d2e5b4 SteamTrain -[renderPos]',
        selectors={
                 0xd219a4: (15238616, 'worldWidthMacro'),
                 0xd227c8: (15238704, 'macroTiles'),
                 0xd227e8: (15238708, 'program'),
                 0xd227f0: (15238720, 'intValue'),
                 0xd227f4: (15238716, 'objectAtIndex:'),
                 0xd227f8: (15238712, 'uniformLocations'),
                 0xd227fc: (15238724, 'dayColor'),
                 0xd22800: (15238728, 'translation'),
                 0xd2280c: (15238732, 'name'),
                 0xd22818: (15238736, 'draw'),
                 0xd27b90: (15238720, 'intValue'),
                 0xd27b94: (15238716, 'objectAtIndex:'),
                 0xd27b98: (15238712, 'uniformLocations'),
                 0xd27ba0: (15238736, 'draw'),
                 0xd27ba4: (15238708, 'program'),
                 0xd27bb8: (15238732, 'name'),
                 0xd2d9f0: (15238724, 'dayColor'),
                 0xd2d9f4: (15238720, 'intValue'),
                 0xd2d9f8: (15238716, 'objectAtIndex:'),
                 0xd2d9fc: (15238712, 'uniformLocations'),
                 0xd2da14: (15238596, 'instance'),
                 0xd2da18: (15238740, 'addParticleAtPos:velocity:color:gravityType:life:scale:'),
                 0xd2da24: (15238744, 'multiSoundNamed:'),
                 0xd2da2c: (15238748, 'sound'),
                 0xd2da30: (15238752, 'setLooping:'),
                 0xd2da34: (15238612, 'playAtPosition:'),
                 0xd2da40: (15238756, 'setPosition:'),
                 0xd2da54: (15238760, 'setPitch:'),
                 0xd2da60: (15238576, 'stop'),
        },
        imports={
                 0xd227c4: (17151904, 'objc_msgSend'),
                 0xd27b8c: (17151904, 'objc_msgSend'),
                 0xd2d9e8: (17151904, 'objc_msgSend'),
                 0xd2da28: (16441176, '__CFConstantStringClassReference'),
                 0xd2da50: (16441192, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xd21998: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xd219a0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xd22458: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xd227cc: (17161264, 'OBJC_IVAR_$_TrainCar.visualVelocity', 128),
                 0xd227d0: (17168316, 'OBJC_IVAR_$_SteamTrain.goingRight', 252),
                 0xd227d4: (17161268, 'OBJC_IVAR_$_TrainCar.rotationAnimationTimer', 92),
                 0xd227dc: (17168368, 'OBJC_IVAR_$_SteamTrain.bigWheelRotationTimer', 256),
                 0xd227e0: (17161204, 'OBJC_IVAR_$_TrainCar.rightWheelPos', 104),
                 0xd227e4: (17161200, 'OBJC_IVAR_$_TrainCar.leftWheelPos', 96),
                 0xd227ec: (17161272, 'OBJC_IVAR_$_TrainCar.shader', 56),
                 0xd22808: (17161276, 'OBJC_IVAR_$_TrainCar.tileTexture', 64),
                 0xd22810: (17161280, 'OBJC_IVAR_$_TrainCar.tileDestructTexture', 68),
                 0xd22814: (17168284, 'OBJC_IVAR_$_SteamTrain.boilerCube', 208),
                 0xd2281c: (17168272, 'OBJC_IVAR_$_SteamTrain.driverCabCube', 220),
                 0xd22820: (17168268, 'OBJC_IVAR_$_SteamTrain.backWallCube', 228),
                 0xd22824: (17168264, 'OBJC_IVAR_$_SteamTrain.roofCube', 232),
                 0xd24d18: (17168280, 'OBJC_IVAR_$_SteamTrain.frontGrillCube', 216),
                 0xd24d1c: (17168276, 'OBJC_IVAR_$_SteamTrain.chimneyCube', 224),
                 0xd24d20: (17168260, 'OBJC_IVAR_$_SteamTrain.roofPoleCube', 236),
                 0xd27914: (17168256, 'OBJC_IVAR_$_SteamTrain.doorCube', 240),
                 0xd27b9c: (17161272, 'OBJC_IVAR_$_TrainCar.shader', 56),
                 0xd27ba8: (17161284, 'OBJC_IVAR_$_TrainCar.worldObjectShader', 60),
                 0xd27bb4: (17161288, 'OBJC_IVAR_$_TrainCar.itemTexture', 72),
                 0xd27bbc: (17161268, 'OBJC_IVAR_$_TrainCar.rotationAnimationTimer', 92),
                 0xd2aa3c: (17168368, 'OBJC_IVAR_$_SteamTrain.bigWheelRotationTimer', 256),
                 0xd2d9dc: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xd2d9e0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xd2d9e4: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xd2d9ec: (17161264, 'OBJC_IVAR_$_TrainCar.visualVelocity', 128),
                 0xd2da00: (17161284, 'OBJC_IVAR_$_TrainCar.worldObjectShader', 60),
                 0xd2da08: (17168356, 'OBJC_IVAR_$_SteamTrain.steamSound', 244),
                 0xd2da38: (17161220, 'OBJC_IVAR_$_TrainCar.riders', 76),
                 0xd2da44: (17168320, 'OBJC_IVAR_$_SteamTrain.stopped', 325),
                 0xd2da48: (17168352, 'OBJC_IVAR_$_SteamTrain.railSound', 248),
        },
        classes={
                 0xd2da10: (15251204, 'OBJC_CLASS_$_ParticleEmitter'),
                 0xd2da1c: (15251200, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(13765920, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13774080, 'bl 0xd2ddfc'), (13775928, 'bl 0xd2e3bc'), (13797952, 'bl sym.drawShaderQuad'), (13818320, 'b 0xd2d9d4'), (13818464, 'invalid')],
        calls=[(13766964, 'bl loc.imp.objc_msgSend'), (13766996, 'bl sym.imp.__aeabi_idiv'), (13767076, 'bl loc.imp.objc_msgSend'), (13767228, 'bl loc.imp.objc_msgSend'), (13767248, 'bl sym.imp.__aeabi_idiv'), (13767328, 'bl loc.imp.objc_msgSend'), (13767484, 'bl loc.imp.objc_msgSend'), (13767516, 'bl sym.imp.__aeabi_idiv'), (13767596, 'bl loc.imp.objc_msgSend'), (13767748, 'bl loc.imp.objc_msgSend'), (13767768, 'bl sym.imp.__aeabi_idiv'), (13767848, 'bl loc.imp.objc_msgSend'), (13768204, 'bl method.Vector2.Vector2_float__float_'), (13768256, 'bl method.Vector2.operator_Vector2_'), (13768268, 'bl method.Vector2.operator_float__'), (13768340, 'bl loc.imp.objc_msgSend'), (13768372, 'bl sym.imp.__aeabi_idiv'), (13768484, 'bl loc.imp.objc_msgSend'), (13768528, 'bl method.Vector2.operator_float__'), (13768592, 'bl method.Vector2.operator_float__'), (13768664, 'bl loc.imp.objc_msgSend'), (13768684, 'bl sym.imp.__aeabi_idiv'), (13768796, 'bl loc.imp.objc_msgSend'), (13768840, 'bl method.Vector2.operator_float__'), (13769000, 'blx r2'), (13769072, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (13769144, 'bl method.Vector2.operator_float__'), (13769172, 'bl method.Vector2.operator_float__'), (13769204, 'bl 0xd20620'), (13769244, 'bl method.Vector2.operator_float__'), (13769316, 'bl method.Vector2.operator_float__'), (13769624, 'bl method.Vector2.operator__Vector2_'), (13769632, 'bl method.Vector2.operator_float__'), (13769652, 'bl method.Vector2.operator_float__'), (13769664, 'bl sym.imp.atan2f'), (13770044, 'bl 0xd20694'), (13770092, 'bl sym.imp.memcpy'), (13770508, 'bl 0xd2da64'), (13770540, 'bl sym.imp.memcpy'), (13770616, 'blx r2'), (13770620, 'bl sym.imp.__wrap_glUseProgram'), (13770764, 'blx r6'), (13770784, 'blx r3'), (13770800, 'blx r2'), (13770808, 'bl sym.imp.__wrap_glUniform1i'), (13770952, 'blx r6'), (13770972, 'blx r3'), (13770988, 'blx r2'), (13770996, 'bl sym.imp.__wrap_glUniform1i'), (13771004, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (13771096, 'bl loc.imp.objc_msgSend_stret'), (13771144, 'bl sym.imp.memset'), (13771664, 'bl method.Vector.Vector_float__float__float_'), (13771684, 'bl method.Vector.operator_float__'), (13771712, 'bl method.Vector.operator_float__'), (13771740, 'bl method.Vector.operator_float__'), (13771984, 'bl method.Vector.Vector_float__float__float__float_'), (13772120, 'blx r2'), (13772140, 'blx r3'), (13772156, 'blx r2'), (13772172, 'bl method.Vector.operator_float__'), (13772200, 'bl method.Vector.operator_float__'), (13772228, 'bl method.Vector.operator_float__'), (13772256, 'bl method.Vector.operator_float__'), (13772312, 'bl sym.imp.__wrap_glUniform4f'), (13772456, 'blx r6'), (13772476, 'blx r3'), (13772492, 'blx r2'), (13772508, 'bl method.Vector.operator_float__'), (13772532, 'bl method.Vector.operator_float__'), (13772556, 'bl method.Vector.operator_float__'), (13772580, 'bl method.Vector.operator_float__'), (13772636, 'bl sym.imp.__wrap_glUniform4f'), (13772728, 'bl loc.imp.objc_msgSend_stret'), (13772872, 'bl sym.imp.memset'), (13772936, 'bl loc.imp.objc_msgSend'), (13772964, 'bl loc.imp.objc_msgSend'), (13772988, 'bl loc.imp.objc_msgSend'), (13773012, 'bl method.Vector2.operator_float__'), (13773040, 'bl method.Vector2.operator_float__'), (13773072, 'bl method.Vector2.operator_float__'), (13773092, 'bl method.Vector2.operator_float__'), (13773172, 'bl sym.imp.__wrap_glUniform4f'), (13774080, 'bl 0xd2ddfc'), (13774988, 'bl 0xd2ddfc'), (13775028, 'bl loc.imp.objc_msgSend'), (13775048, 'bl loc.imp.objc_msgSend'), (13775064, 'bl loc.imp.objc_msgSend'), (13775084, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (13775124, 'bl loc.imp.objc_msgSend'), (13775152, 'bl loc.imp.objc_msgSend'), (13775168, 'bl loc.imp.objc_msgSend'), (13775184, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (13775236, 'bl loc.imp.objc_msgSend'), (13775264, 'bl sym.imp.__wrap_glBindTexture'), (13775272, 'bl sym.imp.__wrap_glActiveTexture'), (13775316, 'bl loc.imp.objc_msgSend'), (13775336, 'bl sym.imp.__wrap_glBindTexture'), (13775388, 'bl loc.imp.objc_msgSend'), (13775432, 'bl loc.imp.objc_msgSend'), (13775476, 'bl loc.imp.objc_msgSend'), (13775520, 'bl loc.imp.objc_msgSend'), (13775928, 'bl 0xd2e3bc'), (13776832, 'bl 0xd2ddfc'), (13777872, 'bl 0xd2ddfc'), (13778048, 'bl loc.imp.objc_msgSend'), (13778068, 'bl loc.imp.objc_msgSend'), (13778084, 'bl loc.imp.objc_msgSend'), (13778100, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (13778140, 'bl loc.imp.objc_msgSend'), (13778160, 'bl loc.imp.objc_msgSend'), (13778176, 'bl loc.imp.objc_msgSend'), (13778192, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (13778236, 'bl loc.imp.objc_msgSend'), (13778640, 'bl 0xd2e3bc'), (13779544, 'bl 0xd2ddfc'), (13780584, 'bl 0xd2ddfc'), (13780760, 'bl loc.imp.objc_msgSend'), (13780780, 'bl loc.imp.objc_msgSend'), (13780796, 'bl loc.imp.objc_msgSend'), (13780812, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (13780852, 'bl loc.imp.objc_msgSend'), (13780872, 'bl loc.imp.objc_msgSend'), (13780888, 'bl loc.imp.objc_msgSend'), (13780904, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (13780948, 'bl loc.imp.objc_msgSend'), (13781372, 'bl 0xd2e3bc'), (13782428, 'bl 0xd2ddfc'), (13783468, 'bl 0xd2ddfc'), (13783644, 'bl loc.imp.objc_msgSend'), (13783664, 'bl loc.imp.objc_msgSend'), (13783680, 'bl loc.imp.objc_msgSend'), (13783696, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (13783736, 'bl loc.imp.objc_msgSend'), (13783756, 'bl loc.imp.objc_msgSend'), (13783772, 'bl loc.imp.objc_msgSend'), (13783788, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (13783836, 'bl loc.imp.objc_msgSend'), (13784252, 'bl 0xd2e3bc'), (13785292, 'bl 0xd2ddfc'), (13786332, 'bl 0xd2ddfc'), (13786508, 'bl loc.imp.objc_msgSend'), (13786528, 'bl loc.imp.objc_msgSend'), (13786544, 'bl loc.imp.objc_msgSend'), (13786560, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (13786600, 'bl loc.imp.objc_msgSend'), (13786620, 'bl loc.imp.objc_msgSend'), (13786636, 'bl loc.imp.objc_msgSend'), (13786652, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (13786692, 'bl loc.imp.objc_msgSend'), (13787092, 'bl 0xd2e3bc'), (13788132, 'bl 0xd2ddfc'), (13789172, 'bl 0xd2ddfc'), (13789348, 'bl loc.imp.objc_msgSend'), (13789368, 'bl loc.imp.objc_msgSend'), (13789384, 'bl loc.imp.objc_msgSend'), (13789400, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (13789440, 'bl loc.imp.objc_msgSend'), (13789460, 'bl loc.imp.objc_msgSend'), (13789476, 'bl loc.imp.objc_msgSend'), (13789492, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (13789536, 'bl loc.imp.objc_msgSend'), (13789936, 'bl 0xd2e3bc'), (13790976, 'bl 0xd2ddfc'), (13792016, 'bl 0xd2ddfc'), (13792192, 'bl sym.imp.memcpy'), (13792244, 'blx ip'), (13792264, 'blx r3'), (13792280, 'blx r2'), (13792312, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (13792468, 'blx r3'), (13792488, 'blx r3'), (13792504, 'blx r2'), (13792536, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (13792624, 'blx r3'), (13792632, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (13792644, 'bl sym.imp.__wrap_glBindTexture'), (13792652, 'bl sym.imp.__wrap_glActiveTexture'), (13792728, 'blx r2'), (13792732, 'bl sym.imp.__wrap_glUseProgram'), (13792876, 'blx r6'), (13792896, 'blx r3'), (13792912, 'blx r2'), (13792920, 'bl sym.imp.__wrap_glUniform1i'), (13793144, 'bl method.Vector.operator_float__'), (13793404, 'bl method.Vector.operator_float__'), (13793668, 'bl method.Vector.operator_float__'), (13793740, 'bl method.Vector.Vector_float__float__float_'), (13793804, 'bl method.Vector.operator_float__'), (13793936, 'bl method.Vector.operator_float__'), (13793960, 'bl method.Vector.operator_float__'), (13794092, 'bl method.Vector.operator_float__'), (13794116, 'bl method.Vector.operator_float__'), (13794300, 'bl method.Vector.operator_float__'), (13794376, 'bl loc.imp.objc_msgSend'), (13794404, 'bl loc.imp.objc_msgSend'), (13794428, 'bl loc.imp.objc_msgSend'), (13794444, 'bl method.Vector.operator_float__'), (13794460, 'bl method.Vector.operator_float__'), (13794476, 'bl method.Vector.operator_float__'), (13794516, 'bl sym.imp.__wrap_glUniform4f'), (13794524, 'bl sym.imp.__wrap_glEnable'), (13794536, 'bl sym.pushDepthMaskState'), (13794580, 'bl loc.imp.objc_msgSend'), (13794600, 'bl sym.imp.__wrap_glBindTexture'), (13794616, 'bl sym.texCoordsForItemType_ItemType_'), (13795044, 'bl 0xd2e3bc'), (13795484, 'bl 0xd20694'), (13796540, 'bl 0xd2ddfc'), (13797596, 'bl 0xd2ddfc'), (13797780, 'bl loc.imp.objc_msgSend'), (13797800, 'bl loc.imp.objc_msgSend'), (13797816, 'bl loc.imp.objc_msgSend'), (13797852, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (13797952, 'bl sym.drawShaderQuad'), (13798368, 'bl 0xd2e3bc'), (13798920, 'bl 0xd20694'), (13799976, 'bl 0xd2ddfc'), (13801032, 'bl 0xd2ddfc'), (13801216, 'bl loc.imp.objc_msgSend'), (13801236, 'bl loc.imp.objc_msgSend'), (13801252, 'bl loc.imp.objc_msgSend'), (13801268, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (13801340, 'bl sym.drawShaderQuad'), (13801764, 'bl 0xd2e3bc'), (13802356, 'bl 0xd20694'), (13803412, 'bl 0xd2ddfc'), (13804468, 'bl 0xd2ddfc'), (13804652, 'bl loc.imp.objc_msgSend'), (13804672, 'bl loc.imp.objc_msgSend'), (13804688, 'bl loc.imp.objc_msgSend'), (13804704, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (13804796, 'bl sym.drawShaderQuad'), (13805196, 'bl 0xd2e3bc'), (13805748, 'bl 0xd20694'), (13806812, 'bl 0xd2ddfc'), (13807868, 'bl 0xd2ddfc'), (13808052, 'bl loc.imp.objc_msgSend'), (13808072, 'bl loc.imp.objc_msgSend'), (13808088, 'bl loc.imp.objc_msgSend'), (13808104, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (13808176, 'bl sym.drawShaderQuad'), (13808576, 'bl 0xd2e3bc'), (13809128, 'bl 0xd20694'), (13810184, 'bl 0xd2ddfc'), (13811240, 'bl 0xd2ddfc'), (13811424, 'bl loc.imp.objc_msgSend'), (13811444, 'bl loc.imp.objc_msgSend'), (13811460, 'bl loc.imp.objc_msgSend'), (13811476, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (13811548, 'bl sym.drawShaderQuad'), (13811948, 'bl 0xd2e3bc'), (13812500, 'bl 0xd20694'), (13813556, 'bl 0xd2ddfc'), (13814612, 'bl 0xd2ddfc'), (13814788, 'bl sym.imp.memcpy'), (13814840, 'blx ip'), (13814860, 'blx r3'), (13814876, 'blx r2'), (13814908, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (13815008, 'bl sym.drawShaderQuad'), (13815016, 'bl sym.imp.__wrap_glDisable'), (13815020, 'bl sym.popDepthMaskState'), (13815136, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13815336, 'bl 0xd20ce0'), (13815648, 'bl 0xd20a2c'), (13815688, 'bl method.Vector.Vector_float__float__float_'), (13815784, 'bl loc.imp.objc_msgSend_stret'), (13815824, 'bl sym.imp.memset'), (13816016, 'bl method.Vector.operator_float__'), (13816228, 'bl method.Vector.operator_float__'), (13816484, 'bl method.Vector.operator_float__'), (13816540, 'bl method.Vector.Vector_float__float__float_'), (13816584, 'bl method.Vector.Vector_float__float__float__float_'), (13816636, 'bl sym.Vector::operator_Vector_'), (13816680, 'bl method.Vector2.operator_float__'), (13816728, 'bl loc.imp.objc_msgSend'), (13816776, 'bl 0xd2e5a4'), (13816828, 'bl 0xd2e5a4'), (13816904, 'bl method.Vector.Vector_float__float__float_'), (13817160, 'bl loc.imp.objc_msgSend'), (13817236, 'bl loc.imp.objc_msgSend'), (13817260, 'bl loc.imp.objc_msgSend'), (13817276, 'bl loc.imp.objc_msgSend'), (13817340, 'bl loc.imp.objc_msgSend'), (13817424, 'bl loc.imp.objc_msgSend'), (13817552, 'bl loc.imp.objc_msgSend'), (13817728, 'bl loc.imp.objc_msgSend'), (13817752, 'bl loc.imp.objc_msgSend'), (13817768, 'bl loc.imp.objc_msgSend'), (13817832, 'bl loc.imp.objc_msgSend'), (13817916, 'bl loc.imp.objc_msgSend'), (13818048, 'bl loc.imp.objc_msgSend'), (13818104, 'bl method.Vector2.operator_float__'), (13818192, 'blx ip'), (13818280, 'blx r3')],
        branches=[(13767012, 'blt', 13767120), (13767116, 'b', 13767372), (13767264, 'bge', 13767368), (13767368, 'b', 13767372), (13767532, 'blt', 13767640), (13767636, 'b', 13767892), (13767784, 'bge', 13767888), (13767888, 'b', 13767892), (13767940, 'blt', 13768100), (13767992, 'bgt', 13768100), (13768044, 'blt', 13768100), (13768096, 'ble', 13768104), (13768100, 'b', 13818324), (13768400, 'ble', 13768556), (13768552, 'b', 13768868), (13768712, 'bpl', 13768864), (13768864, 'b', 13768868), (13769100, 'bne', 13769136), (13769104, 'b', 13818324), (13769392, 'beq', 13769428), (13770128, 'beq', 13770544), (13771076, 'beq', 13771112), (13771100, 'b', 13771148), (13771272, 'bpl', 13771304), (13771296, 'b', 13771324), (13771376, 'bpl', 13771416), (13771400, 'b', 13771436), (13771488, 'ble', 13771564), (13771832, 'bpl', 13771892), (13771856, 'b', 13771912), (13772708, 'beq', 13772840), (13772732, 'b', 13772876), (13782292, 'b', 13782308), (13793008, 'bpl', 13793036), (13793032, 'b', 13793056), (13793268, 'bpl', 13793296), (13793292, 'b', 13793316), (13793528, 'bpl', 13793560), (13793552, 'b', 13793580), (13793848, 'bpl', 13793880), (13793872, 'b', 13793900), (13794004, 'bpl', 13794036), (13794028, 'b', 13794056), (13794160, 'bpl', 13794240), (13794184, 'b', 13794260), (13806136, 'b', 13806144), (13815048, 'ble', 13818324), (13815164, 'beq', 13818320), (13815764, 'beq', 13815792), (13815788, 'b', 13815828), (13815904, 'bpl', 13815932), (13815924, 'b', 13815948), (13816120, 'bpl', 13816144), (13816140, 'b', 13816160), (13816332, 'bpl', 13816380), (13816352, 'b', 13816396), (13817200, 'bne', 13817428), (13817592, 'beq', 13818200), (13817640, 'bne', 13818200), (13817692, 'bne', 13817920), (13818196, 'b', 13818316), (13818316, 'b', 13818320), (13818320, 'b', 13818324)],
        semantics=("[SteamTrain draw:...] (imp 0x00d20d20, 13137w): the train's render pass - the largest body in the project. Census of the 266 calls: **95 objc_msgSend** (the per-part draws/sprites), **20x glUniformMatrix4fv** (the per-part matrix uploads), 26 Vector::operator float* + 16 Vector2::operator float*, **6x drawShaderQuad** (the quad emit family of the E41/E44 passes), glUniform4f x4, glBindTexture x4, glUseProgram x2, glActiveTexture x2, glEnableVertexAttribArray, memcpy x4 + memset x3 (the buffer packs), **atan2f** (the part angles) + tileAtWorldPosition; the local helper family 0xd2ddfc (26x), 0xd2e3bc (12x), 0xd20694 (7x, the matrix helper of E70), 0xd20620, 0xd2e5a4, 0xd2da64; sprite-frame constants **0.2/1.2/0.35/1.1/-0.35/0.45/+/-0.3/-0.45/0.1/0.6** (the train's part offsets).\n"),
    ),
    dict(
        name='st4_update',
        method='SteamTrain -[update:accurateDT:isSimulation:]',
        types='v20@0:4f8f12c16',
        start=13744824,
        end=13764128,
        disasm='disasm_worldtileloader_st4_update.txt',
        base_add=13744848,
        base_literal=13748444,
        boundary='ARM.exidx end 0x00d20620 (listing bound); next ObjC IMP 0x00d20d20 SteamTrain -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        selectors={
                 0xd1c8e4: (15238632, 'update:accurateDT:isSimulation:'),
                 0xd1c8f0: (15238636, 'updateSearchForStations'),
                 0xd1c908: (15238640, 'needsRemoved'),
                 0xd1cbf4: (15238640, 'needsRemoved'),
                 0xd1cbfc: (15238588, 'isNet'),
                 0xd1cc18: (15238644, 'uniqueID'),
                 0xd1cc1c: (15238496, 'retain'),
                 0xd1cc20: (15238648, 'trainCarWithID:'),
                 0xd1cc28: (15238572, 'release'),
                 0xd1d1c4: (15238652, 'paused'),
                 0xd1d6b4: (15238656, 'setNeedsRemoved:'),
                 0xd1d6c0: (15238660, 'itemType'),
                 0xd1d6c4: (15238664, 'freeBlockCreationSaveDict'),
                 0xd1d6c8: (15238668, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
                 0xd1d6e4: (15238672, 'objectType'),
                 0xd1d6e8: (15238676, 'dynamicWorldChangedAtPos:objectType:'),
                 0xd1d6ec: (15238592, 'updateHasFuel'),
                 0xd1e85c: (15238680, 'autorelease'),
                 0xd1ea18: (15238684, 'getRailAtPos:'),
                 0xd1f014: (15238688, 'currentConfiguration'),
                 0xd1fea4: (15238692, 'leftWheelPos'),
                 0xd1feb4: (15238696, 'rightWheelPos'),
                 0xd20594: (15238588, 'isNet'),
                 0xd205b8: (15238656, 'setNeedsRemoved:'),
                 0xd205c0: (15238660, 'itemType'),
                 0xd205c4: (15238664, 'freeBlockCreationSaveDict'),
                 0xd205c8: (15238668, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
                 0xd205e4: (15238616, 'worldWidthMacro'),
                 0xd20614: (15238700, 'updatePosition:'),
        },
        imports={
                 0xd1c8e0: (17151900, 'objc_msgSendSuper2'),
                 0xd1c8ec: (17151904, 'objc_msgSend'),
                 0xd1e8ec: (17151904, 'objc_msgSend'),
                 0xd2058c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd1c90c: (17161220, 'OBJC_IVAR_$_TrainCar.riders', 76),
                 0xd1cbf8: (17161220, 'OBJC_IVAR_$_TrainCar.riders', 76),
                 0xd1cc00: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xd1cc04: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xd1cc08: (17161224, 'OBJC_IVAR_$_TrainCar.remoteRightCarID', 152),
                 0xd1cc10: (17161212, 'OBJC_IVAR_$_TrainCar.rightCar', 168),
                 0xd1cc2c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xd1ce74: (17161228, 'OBJC_IVAR_$_TrainCar.remoteLeftCarID', 144),
                 0xd1ce7c: (17161216, 'OBJC_IVAR_$_TrainCar.leftCar', 172),
                 0xd1d1c8: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xd1d1d0: (17161204, 'OBJC_IVAR_$_TrainCar.rightWheelPos', 104),
                 0xd1d1d4: (17161200, 'OBJC_IVAR_$_TrainCar.leftWheelPos', 96),
                 0xd1d4b4: (17168316, 'OBJC_IVAR_$_SteamTrain.goingRight', 252),
                 0xd1d6ac: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xd1d6b0: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0xd1d6bc: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xd1d6cc: (17168320, 'OBJC_IVAR_$_SteamTrain.stopped', 325),
                 0xd1d6d0: (17164504, 'OBJC_IVAR_$_TrainCar.remoteUpdateTimer', 136),
                 0xd1d6d4: (17168308, 'OBJC_IVAR_$_SteamTrain.hasFuel', 268),
                 0xd1d6d8: (17168304, 'OBJC_IVAR_$_SteamTrain.fuelCounter', 264),
                 0xd1d6e0: (17168312, 'OBJC_IVAR_$_SteamTrain.fuelFraction', 260),
                 0xd1d6f0: (17161236, 'OBJC_IVAR_$_TrainCar.leftWheelVel', 112),
                 0xd1d6f4: (17161240, 'OBJC_IVAR_$_TrainCar.rightWheelVel', 120),
                 0xd1e698: (17161244, 'OBJC_IVAR_$_TrainCar.leftWheelTilePos', 184),
                 0xd1e69c: (17161248, 'OBJC_IVAR_$_TrainCar.rightWheelTilePos', 192),
                 0xd1e7c0: (17161252, 'OBJC_IVAR_$_TrainCar.leftWheelRail', 200),
                 0xd1e8f0: (17161256, 'OBJC_IVAR_$_TrainCar.rightWheelRail', 204),
                 0xd1eb2c: (17161220, 'OBJC_IVAR_$_TrainCar.riders', 76),
                 0xd1ed8c: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xd1f398: (17161200, 'OBJC_IVAR_$_TrainCar.leftWheelPos', 96),
                 0xd1f5e8: (17161240, 'OBJC_IVAR_$_TrainCar.rightWheelVel', 120),
                 0xd1f964: (17161204, 'OBJC_IVAR_$_TrainCar.rightWheelPos', 104),
                 0xd1fd44: (17168308, 'OBJC_IVAR_$_SteamTrain.hasFuel', 268),
                 0xd1fd48: (17168316, 'OBJC_IVAR_$_SteamTrain.goingRight', 252),
                 0xd1fd50: (17161236, 'OBJC_IVAR_$_TrainCar.leftWheelVel', 112),
                 0xd1fe98: (17168320, 'OBJC_IVAR_$_SteamTrain.stopped', 325),
                 0xd1fe9c: (17161212, 'OBJC_IVAR_$_TrainCar.rightCar', 168),
                 0xd1feb0: (17161216, 'OBJC_IVAR_$_TrainCar.leftCar', 172),
                 0xd20590: (17161220, 'OBJC_IVAR_$_TrainCar.riders', 76),
                 0xd20598: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xd2059c: (17161216, 'OBJC_IVAR_$_TrainCar.leftCar', 172),
                 0xd205a0: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xd205a4: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xd205a8: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xd205ac: (17161204, 'OBJC_IVAR_$_TrainCar.rightWheelPos', 104),
                 0xd205b0: (17161200, 'OBJC_IVAR_$_TrainCar.leftWheelPos', 96),
                 0xd205b4: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0xd205bc: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xd205cc: (17168320, 'OBJC_IVAR_$_SteamTrain.stopped', 325),
                 0xd205d0: (17161240, 'OBJC_IVAR_$_TrainCar.rightWheelVel', 120),
                 0xd205d4: (17161236, 'OBJC_IVAR_$_TrainCar.leftWheelVel', 112),
                 0xd20604: (17161264, 'OBJC_IVAR_$_TrainCar.visualVelocity', 128),
                 0xd2060c: (17168324, 'OBJC_IVAR_$_SteamTrain.stopAtGoalPos', 324),
                 0xd20610: (17168336, 'OBJC_IVAR_$_SteamTrain.stationGoalPos', 316),
        },
        classes={
                 0xd1c8e8: (15253264, 'OBJC_CLASS_$_SteamTrain'),
        },
        instructions=[(13744824, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13747816, 'movw r2, 0x6666'), (13759572, 'movw ip, 0xcccd'), (13760164, 'movw ip, 0xcccd'), (13754476, 'ldr r0, [r0, r1]'), (13764124, 'eorseq pc, r3, ip, asr r6')],
        calls=[(13744992, 'blx r4'), (13745048, 'blx r2'), (13745172, 'blx r2'), (13745248, 'blx r2'), (13745524, 'bl loc.imp.objc_msgSend'), (13745668, 'bl loc.imp.objc_msgSend'), (13745732, 'bl loc.imp.objc_msgSend'), (13745748, 'blx r2'), (13746004, 'bl loc.imp.objc_msgSend'), (13746148, 'bl loc.imp.objc_msgSend'), (13746212, 'bl loc.imp.objc_msgSend'), (13746228, 'blx r2'), (13746388, 'blx r2'), (13746472, 'blx r3'), (13746560, 'blx r2'), (13746644, 'blx r3'), (13746736, 'blx r2'), (13746872, 'blx r2'), (13746948, 'bl method.Vector2.Vector2_float__float_'), (13746976, 'bl method.Vector2.operator_Vector2_'), (13746984, 'bl method.Vector2.operator_float__'), (13747000, 'bl method.Vector2.operator_float__'), (13747032, 'bl 0xd20620'), (13747128, 'bl method.Vector2.operator__Vector2_'), (13747136, 'bl method.Vector2.operator_float__'), (13747156, 'bl method.Vector2.operator_float__'), (13747168, 'bl sym.imp.atan2f'), (13747500, 'bl 0xd20694'), (13747828, 'bl 0xd20ce0'), (13748064, 'bl 0xd20a2c'), (13748128, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13748140, 'bl sym.tileIsSolid_Tile_'), (13748228, 'bl loc.imp.objc_msgSend'), (13748328, 'bl loc.imp.objc_msgSend'), (13748360, 'bl loc.imp.objc_msgSend'), (13748436, 'bl loc.imp.objc_msgSend'), (13748636, 'blx r2'), (13749120, 'bl loc.imp.objc_msgSend'), (13749156, 'bl loc.imp.objc_msgSend'), (13749224, 'blx r2'), (13749320, 'bl method.Vector2.operator_float__'), (13749400, 'bl method.Vector2.operator_float__'), (13749436, 'bl method.Vector2.operator_float__'), (13749516, 'bl method.Vector2.operator_float__'), (13749552, 'bl method.Vector2.operator_float__'), (13749592, 'bl sym.imp.__wrap_fmodf'), (13749652, 'bl method.Vector2.operator_float__'), (13749736, 'bl method.Vector2.operator_float__'), (13749772, 'bl method.Vector2.operator_float__'), (13749856, 'bl method.Vector2.operator_float__'), (13749932, 'bl method.Vector2.operator_float__'), (13750000, 'bl method.Vector2.operator_float__'), (13750036, 'bl method.Vector2.operator_float__'), (13750104, 'bl method.Vector2.operator_float__'), (13750160, 'bl method.Vector2.Vector2_float__float_'), (13750180, 'bl method.Vector2.Vector2_float__float_'), (13750220, 'bl method.Vector2.operator_float__'), (13750256, 'bl method.Vector2.operator_float__'), (13750280, 'bl sym.makeIntpair_int__int_'), (13750320, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13750356, 'bl method.Vector2.operator_float__'), (13750392, 'bl method.Vector2.operator_float__'), (13750416, 'bl sym.makeIntpair_int__int_'), (13750444, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13750516, 'bl method.Vector2.operator_Vector2_'), (13750532, 'bl method.Vector2.operator_float_'), (13750636, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13750700, 'bl sym.makeIntpair_int__int_'), (13750748, 'bl sym.tileIsSolid_Tile_'), (13750900, 'blx r2'), (13751028, 'bl loc.imp.objc_msgSend'), (13751128, 'bl loc.imp.objc_msgSend'), (13751160, 'bl loc.imp.objc_msgSend'), (13751236, 'bl loc.imp.objc_msgSend'), (13751248, 'bl method.Vector2.operator_float__'), (13751280, 'bl sym.tileIsWater_Tile_'), (13751384, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13751452, 'bl sym.makeIntpair_int__int_'), (13751484, 'bl sym.tileIsSolid_Tile_'), (13751636, 'blx r2'), (13751764, 'bl loc.imp.objc_msgSend'), (13751864, 'bl loc.imp.objc_msgSend'), (13751896, 'bl loc.imp.objc_msgSend'), (13751972, 'bl loc.imp.objc_msgSend'), (13752064, 'bl method.Vector2.operator_float__'), (13752096, 'bl sym.tileIsWater_Tile_'), (13752480, 'blx r3'), (13752564, 'blx r3'), (13752656, 'blx r2'), (13752740, 'blx r3'), (13752912, 'bl loc.imp.objc_msgSend'), (13752996, 'bl loc.imp.objc_msgSend'), (13753012, 'blx r2'), (13753176, 'bl loc.imp.objc_msgSend'), (13753260, 'bl loc.imp.objc_msgSend'), (13753276, 'blx r2'), (13753784, 'bl sym.makeIntpair_int__int_'), (13753836, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13753904, 'bl sym.makeIntpair_int__int_'), (13753972, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13754036, 'bl sym.makeIntpair_int__int_'), (13754104, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13754280, 'bl method.Vector2.operator_float__'), (13754360, 'bl method.Vector2.operator_float__'), (13754488, 'bl loc.imp.objc_msgSend'), (13754704, 'bl method.Vector2.operator_float__'), (13754748, 'bl method.Vector2.operator_float__'), (13754848, 'bl method.Vector2.operator_float__'), (13754884, 'bl method.Vector2.operator_float__'), (13754996, 'bl method.Vector2.operator_float__'), (13755032, 'bl method.Vector2.operator_float__'), (13755124, 'bl method.Vector2.operator_float__'), (13755168, 'bl method.Vector2.operator_float__'), (13755260, 'bl method.Vector2.operator_float__'), (13755296, 'bl method.Vector2.operator_float__'), (13755392, 'bl method.Vector2.operator_float__'), (13755428, 'bl method.Vector2.operator_float__'), (13755524, 'bl method.Vector2.operator_float__'), (13755588, 'bl method.Vector2.operator_float__'), (13755656, 'bl method.Vector2.operator_float__'), (13755676, 'bl method.Vector2.operator_float__'), (13755712, 'bl method.Vector2.operator_float__'), (13755740, 'bl method.Vector2.operator_float__'), (13755768, 'bl method.Vector2.operator_float__'), (13755876, 'bl method.Vector2.operator_float__'), (13755940, 'bl method.Vector2.operator_float__'), (13755976, 'bl method.Vector2.operator_float__'), (13756004, 'bl method.Vector2.operator_float__'), (13756040, 'bl method.Vector2.operator_float__'), (13756076, 'bl method.Vector2.operator_float__'), (13756104, 'bl method.Vector2.operator_float__'), (13756208, 'bl loc.imp.objc_msgSend'), (13756432, 'bl method.Vector2.operator_float__'), (13756476, 'bl method.Vector2.operator_float__'), (13756584, 'bl method.Vector2.operator_float__'), (13756620, 'bl method.Vector2.operator_float__'), (13756748, 'bl method.Vector2.operator_float__'), (13756784, 'bl method.Vector2.operator_float__'), (13756876, 'bl method.Vector2.operator_float__'), (13756920, 'bl method.Vector2.operator_float__'), (13757024, 'bl method.Vector2.operator_float__'), (13757060, 'bl method.Vector2.operator_float__'), (13757160, 'bl method.Vector2.operator_float__'), (13757196, 'bl method.Vector2.operator_float__'), (13757300, 'bl method.Vector2.operator_float__'), (13757364, 'bl method.Vector2.operator_float__'), (13757432, 'bl method.Vector2.operator_float__'), (13757452, 'bl method.Vector2.operator_float__'), (13757488, 'bl method.Vector2.operator_float__'), (13757520, 'bl method.Vector2.operator_float__'), (13757552, 'bl method.Vector2.operator_float__'), (13757656, 'bl method.Vector2.operator_float__'), (13757720, 'bl method.Vector2.operator_float__'), (13757756, 'bl method.Vector2.operator_float__'), (13757784, 'bl method.Vector2.operator_float__'), (13757820, 'bl method.Vector2.operator_float__'), (13757856, 'bl method.Vector2.operator_float__'), (13757888, 'bl method.Vector2.operator_float__'), (13758076, 'bl method.Vector2.operator_float__'), (13758112, 'bl method.Vector2.operator_float__'), (13758376, 'bl method.Vector2.Vector2_float__float_'), (13758396, 'bl method.Vector2.Vector2_float__float_'), (13758416, 'bl sym.Vector2::operator_Vector2_'), (13758440, 'bl method.Vector2.operator_Vector2_'), (13758568, 'bl method.Vector2.Vector2_float__float_'), (13758588, 'bl method.Vector2.Vector2_float__float_'), (13758612, 'bl sym.Vector2::operator_Vector2_'), (13758636, 'bl method.Vector2.operator_Vector2_'), (13758748, 'bl method.Vector2.operator_float_'), (13758772, 'bl method.Vector2.operator_float_'), (13758800, 'bl method.Vector2.operator_float_'), (13758820, 'bl method.Vector2.operator_Vector2_'), (13758944, 'bl method.Vector2.operator_float_'), (13758968, 'bl method.Vector2.operator_float_'), (13758984, 'bl method.Vector2.operator_float_'), (13759004, 'bl method.Vector2.operator_Vector2_'), (13759188, 'bl loc.imp.objc_msgSend_stret'), (13759224, 'bl sym.imp.memset'), (13759284, 'bl method.Vector2.operator__Vector2_'), (13759300, 'bl method.Vector2.normal__'), (13759376, 'bl loc.imp.objc_msgSend_stret'), (13759416, 'bl sym.imp.memset'), (13759440, 'bl method.Vector2.operator_float_'), (13759464, 'bl method.Vector2.operator__Vector2_'), (13759540, 'bl method.Vector2.operator__Vector2_'), (13759600, 'bl method.Vector2.operator_float_'), (13759620, 'bl method.Vector2.operator_Vector2_'), (13759760, 'bl loc.imp.objc_msgSend_stret'), (13759800, 'bl sym.imp.memset'), (13759868, 'bl method.Vector2.operator__Vector2_'), (13759884, 'bl method.Vector2.normal__'), (13759964, 'bl loc.imp.objc_msgSend_stret'), (13760016, 'bl sym.imp.memset'), (13760032, 'bl method.Vector2.operator_float_'), (13760064, 'bl method.Vector2.operator__Vector2_'), (13760136, 'bl method.Vector2.operator__Vector2_'), (13760192, 'bl method.Vector2.operator_float_'), (13760216, 'bl method.Vector2.operator_Vector2_'), (13760328, 'bl method.Vector2.operator_float_'), (13760360, 'bl method.Vector2.operator_float_'), (13760376, 'bl method.Vector2.operator_float_'), (13760400, 'bl method.Vector2.operator_Vector2_'), (13760504, 'bl method.Vector2.operator_float_'), (13760524, 'bl method.Vector2.operator_float_'), (13760540, 'bl method.Vector2.operator_float_'), (13760564, 'bl method.Vector2.operator_Vector2_'), (13760612, 'bl method.Vector2.operator_float__'), (13760708, 'bl loc.imp.objc_msgSend'), (13760752, 'bl method.Vector2.operator_float__'), (13760800, 'bl loc.imp.objc_msgSend'), (13760844, 'bl method.Vector2.operator_float__'), (13760916, 'bl method.Vector2.operator_float__'), (13760960, 'bl loc.imp.objc_msgSend'), (13761076, 'bl loc.imp.objc_msgSend'), (13761120, 'bl method.Vector2.operator_float__'), (13761168, 'bl loc.imp.objc_msgSend'), (13761212, 'bl method.Vector2.operator_float__'), (13761348, 'bl method.Vector2.operator_float_'), (13761384, 'bl method.Vector2.operator_float_'), (13761408, 'bl method.Vector2.operator_Vector2_'), (13761512, 'blx r2'), (13761580, 'bl method.Vector2.operator_float__'), (13761600, 'bl method.Vector2.operator_float__'), (13761652, 'bl loc.imp.objc_msgSend'), (13761676, 'bl sym.imp.__aeabi_idiv'), (13761748, 'bl method.Vector2.operator_float__'), (13761768, 'bl method.Vector2.operator_float__'), (13761820, 'bl loc.imp.objc_msgSend'), (13761928, 'bl method.Vector2.operator_float__'), (13761948, 'bl method.Vector2.operator_float__'), (13762000, 'bl loc.imp.objc_msgSend'), (13762016, 'bl sym.imp.__aeabi_idiv'), (13762088, 'bl method.Vector2.operator_float__'), (13762108, 'bl method.Vector2.operator_float__'), (13762160, 'bl loc.imp.objc_msgSend'), (13762260, 'bl method.Vector2.operator_float__'), (13762284, 'bl method.Vector2.operator_float__'), (13762356, 'bl method.Vector2.operator_float__'), (13762392, 'bl method.Vector2.operator_float__'), (13762416, 'bl method.Vector2.operator_float__'), (13762476, 'bl method.Vector2.operator_float__'), (13762600, 'bl method.Vector2.operator__Vector2_'), (13762620, 'bl method.Vector2.normal__'), (13762712, 'bl method.Vector2.operator_float_'), (13762732, 'bl method.Vector2.operator_Vector2_'), (13762820, 'bl method.Vector2.operator_float_'), (13762840, 'bl method.Vector2.operator_Vector2_'), (13762888, 'bl method.Vector2.operator_float__'), (13762936, 'bl method.Vector2.operator_float__'), (13762960, 'bl sym.makeIntpair_int__int_'), (13763444, 'bl loc.imp.objc_msgSend'), (13763548, 'blx r2'), (13763620, 'bl method.Vector2.operator_float__'), (13763656, 'bl method.Vector2.operator_float__'), (13763752, 'bl loc.imp.objc_msgSend'), (13763852, 'bl loc.imp.objc_msgSend'), (13763884, 'bl loc.imp.objc_msgSend'), (13763960, 'bl loc.imp.objc_msgSend')],
        branches=[(13745080, 'ble', 13745112), (13745084, 'b', 13745100), (13745184, 'beq', 13745328), (13745260, 'bne', 13745296), (13745360, 'beq', 13746328), (13745404, 'beq', 13745844), (13745408, 'b', 13745412), (13745448, 'beq', 13745560), (13745552, 'beq', 13745840), (13745556, 'b', 13745560), (13745796, 'beq', 13745836), (13745836, 'b', 13745840), (13745840, 'b', 13745844), (13745884, 'beq', 13746324), (13745888, 'b', 13745892), (13745928, 'beq', 13746040), (13746032, 'beq', 13746320), (13746036, 'b', 13746040), (13746276, 'beq', 13746316), (13746316, 'b', 13746320), (13746320, 'b', 13746324), (13746324, 'b', 13746676), (13746400, 'beq', 13746500), (13746572, 'beq', 13746672), (13746672, 'b', 13746676), (13746748, 'bne', 13746768), (13746764, 'beq', 13746772), (13746768, 'b', 13763972), (13746808, 'beq', 13748500), (13746884, 'bne', 13748500), (13748152, 'beq', 13748496), (13748188, 'bne', 13748440), (13748440, 'b', 13763972), (13748496, 'b', 13748500), (13748536, 'beq', 13749296), (13748572, 'bne', 13749296), (13748648, 'bne', 13749232), (13748724, 'ble', 13748796), (13748828, 'beq', 13749228), (13748936, 'blt', 13749184), (13749228, 'b', 13749232), (13749232, 'b', 13750120), (13749624, 'ble', 13749908), (13749868, 'b', 13750116), (13750116, 'b', 13750120), (13750548, 'beq', 13763972), (13750564, 'beq', 13763972), (13750580, 'beq', 13751316), (13750656, 'beq', 13750744), (13750672, 'bne', 13750744), (13750720, 'b', 13751312), (13750760, 'beq', 13751244), (13750796, 'bne', 13751240), (13750836, 'beq', 13750916), (13750912, 'beq', 13750992), (13750952, 'bne', 13751240), (13750988, 'bne', 13751240), (13751240, 'b', 13763972), (13751292, 'beq', 13751304), (13751304, 'b', 13751308), (13751308, 'b', 13751312), (13751312, 'b', 13751316), (13751328, 'beq', 13752132), (13751404, 'beq', 13751480), (13751420, 'bne', 13751480), (13751472, 'b', 13752128), (13751496, 'beq', 13752056), (13751532, 'bne', 13751976), (13751572, 'beq', 13751652), (13751648, 'beq', 13751728), (13751688, 'bne', 13751976), (13751724, 'bne', 13751976), (13751976, 'b', 13763972), (13752108, 'beq', 13752120), (13752120, 'b', 13752124), (13752124, 'b', 13752128), (13752128, 'b', 13752132), (13752176, 'bne', 13752228), (13752284, 'bne', 13752336), (13752492, 'beq', 13752596), (13752668, 'beq', 13752772), (13752784, 'bne', 13752828), (13752824, 'bne', 13753036), (13753048, 'bne', 13753092), (13753088, 'bne', 13753300), (13753332, 'bne', 13754256), (13753372, 'beq', 13754256), (13753408, 'beq', 13753468), (13753424, 'beq', 13753468), (13753464, 'bne', 13753560), (13753500, 'bne', 13754256), (13753516, 'beq', 13754256), (13753556, 'beq', 13754256), (13753600, 'beq', 13753636), (13753632, 'b', 13753664), (13753700, 'bge', 13754252), (13753856, 'beq', 13754228), (13753872, 'beq', 13754116), (13753992, 'beq', 13754112), (13754008, 'beq', 13754112), (13754112, 'b', 13754116), (13754128, 'beq', 13754208), (13754144, 'beq', 13754208), (13754204, 'b', 13754252), (13754224, 'b', 13754228), (13754228, 'b', 13754232), (13754244, 'b', 13753692), (13754252, 'b', 13754256), (13754448, 'beq', 13755796), (13754524, 'bhi', 13755456), (13754628, 'b', 13755500), (13754776, 'b', 13755500), (13754912, 'b', 13755500), (13755060, 'b', 13755500), (13755192, 'b', 13755500), (13755320, 'b', 13755500), (13755452, 'b', 13755500), (13755548, 'bhi', 13755728), (13755724, 'b', 13755788), (13755788, 'b', 13756132), (13755808, 'bne', 13756128), (13755900, 'bhi', 13756064), (13756052, 'b', 13756124), (13756124, 'b', 13756128), (13756128, 'b', 13756132), (13756168, 'beq', 13757576), (13756244, 'bhi', 13757232), (13756348, 'b', 13757276), (13756504, 'b', 13757276), (13756648, 'b', 13757276), (13756812, 'b', 13757276), (13756944, 'b', 13757276), (13757084, 'b', 13757276), (13757220, 'b', 13757276), (13757324, 'bhi', 13757504), (13757500, 'b', 13757572), (13757572, 'b', 13757916), (13757588, 'bne', 13757912), (13757680, 'bhi', 13757840), (13757832, 'b', 13757908), (13757908, 'b', 13757912), (13757912, 'b', 13757916), (13758000, 'bne', 13758024), (13758228, 'beq', 13758268), (13758264, 'beq', 13758308), (13758320, 'beq', 13758344), (13758340, 'b', 13758356), (13758456, 'beq', 13758500), (13758476, 'b', 13758512), (13759112, 'beq', 13759644), (13759172, 'beq', 13759196), (13759192, 'b', 13759228), (13759360, 'beq', 13759388), (13759380, 'b', 13759420), (13759680, 'beq', 13760240), (13759740, 'beq', 13759768), (13759764, 'b', 13759804), (13759944, 'beq', 13759984), (13759968, 'b', 13760020), (13760628, 'bpl', 13760872), (13760864, 'b', 13761236), (13760996, 'blt', 13761232), (13761232, 'b', 13761236), (13761448, 'ble', 13762488), (13761524, 'bne', 13762488), (13761700, 'blt', 13761876), (13761856, 'b', 13762312), (13762040, 'bpl', 13762236), (13762196, 'b', 13762304), (13763000, 'bne', 13763044), (13763040, 'beq', 13763448), (13763080, 'beq', 13763400), (13763116, 'beq', 13763396), (13763180, 'bge', 13763228), (13763224, 'bge', 13763336), (13763288, 'ble', 13763392), (13763332, 'bgt', 13763392), (13763392, 'b', 13763396), (13763396, 'b', 13763400), (13763484, 'beq', 13763968), (13763560, 'bne', 13763968), (13763576, 'beq', 13763596), (13763592, 'bne', 13763968), (13763676, 'ble', 13763968), (13763712, 'bne', 13763964), (13763964, 'b', 13763972), (13763968, 'b', 13763972)],
        semantics=("[SteamTrain update:accurateDT:isSimulation:] (imp 0x00d1bab8, 4826w): the train's per-tick simulation. Census of the 234 calls: the **Vector2 op family** (103x operator float*, 21x operator float(), 13x operator+(Vector2), 8x operator- = the motion integration), **tileAtWorldPositionLoaded x8 + makeIntpair x8** (the 8-point track probe), tileIsSolid x3, **tileIsWater x2** (the water interaction), **atan2f** (the heading), **__wrap_fmodf** (the coordinate wrap), objc_msgSend x40 (the rider/station notifies), the matrix helpers 0xd20620/0xd20694/0xd20ce0/0xd20a2c; constants **1.8 (0x3fe66666), 0.2, 0.2** (the acceleration/baseline factors).\n"),
    ),
    dict(
        name='st4_ctor_save',
        method='SteamTrain -[initWithWorld:dynamicWorld:saveDict:cache:]',
        types='@24@0:4@8@12@16@20',
        start=13731892,
        end=13732612,
        disasm='disasm_worldtileloader_st4_ctor_save.txt',
        base_add=13731908,
        base_literal=13732608,
        boundary='ARM.exidx end 0x00d18b04 (listing bound); next ObjC IMP 0x00d18b04 SteamTrain -[initWithWorld:dynamicWorld:cache:netData:]',
        selectors={
                 0xd18ac8: (15238512, 'initWithWorld:dynamicWorld:saveDict:cache:'),
                 0xd18ad8: (15238480, 'boolValue'),
                 0xd18ae0: (15238472, 'objectForKey:'),
                 0xd18af8: (15238476, 'floatValue'),
        },
        imports={
                 0xd18ac4: (17151900, 'objc_msgSendSuper2'),
                 0xd18ad4: (17151904, 'objc_msgSend'),
                 0xd18adc: (16441096, '__CFConstantStringClassReference'),
                 0xd18ae8: (16441080, '__CFConstantStringClassReference'),
                 0xd18af0: (16441064, '__CFConstantStringClassReference'),
                 0xd18afc: (16441048, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xd18ad0: (17168320, 'OBJC_IVAR_$_SteamTrain.stopped', 325),
                 0xd18ae4: (17168316, 'OBJC_IVAR_$_SteamTrain.goingRight', 252),
                 0xd18aec: (17168308, 'OBJC_IVAR_$_SteamTrain.hasFuel', 268),
                 0xd18af4: (17168312, 'OBJC_IVAR_$_SteamTrain.fuelFraction', 260),
        },
        classes={
                 0xd18acc: (15253264, 'OBJC_CLASS_$_SteamTrain'),
        },
        instructions=[(13731892, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13732056, 'blx r6'), (13732084, 'bne 0xd18904'), (13732132, 'ldr lr, [0x00d18adc]'), (13732608, 'eorseq r7, r4, r8, lsr 5')],
        calls=[(13732056, 'blx r6'), (13732304, 'blx r4'), (13732320, 'blx r2'), (13732368, 'blx r3'), (13732384, 'blx r2'), (13732428, 'blx r3'), (13732444, 'blx r2'), (13732488, 'blx r3'), (13732504, 'blx r2')],
        branches=[(13732084, 'bne', 13732100), (13732096, 'b', 13732536)],
        semantics=('[SteamTrain initWithWorld:dynamicWorld:saveDict:cache:] (imp 0x00d18834, 180w): the save-dict ctor - super2-shaped blx (@0xd188d8) + nil gate (@0xd188f4); binds the SaveTrain save-key pool **fff4e414/e3f4/e404** + the **fffffccc/c8/cc0** ivar cells + ffffbca8/bcac + ffe28a5c/a54/a7c/c41c.\n'),
    ),
    dict(
        name='st4_getsavedict',
        method='SteamTrain -[getSaveDict]',
        types='@8@0:4',
        start=13733508,
        end=13734280,
        disasm='disasm_worldtileloader_st4_getsavedict.txt',
        base_add=13733524,
        base_literal=13734276,
        boundary='ARM.exidx end 0x00d19188 (listing bound); next ObjC IMP 0x00d19188 SteamTrain -[creationNetDataForClient:]',
        selectors={
                 0xd19148: (15238536, 'getSaveDict'),
                 0xd19158: (15238544, 'setObject:forKey:'),
                 0xd1915c: (15238548, 'numberWithBool:'),
                 0xd1917c: (15238540, 'numberWithFloat:'),
        },
        imports={
                 0xd19144: (17151900, 'objc_msgSendSuper2'),
                 0xd19150: (16441096, '__CFConstantStringClassReference'),
                 0xd19154: (17151904, 'objc_msgSend'),
                 0xd19168: (16441080, '__CFConstantStringClassReference'),
                 0xd19170: (16441064, '__CFConstantStringClassReference'),
                 0xd19178: (16441048, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xd19160: (17168320, 'OBJC_IVAR_$_SteamTrain.stopped', 325),
                 0xd1916c: (17168316, 'OBJC_IVAR_$_SteamTrain.goingRight', 252),
                 0xd19174: (17168308, 'OBJC_IVAR_$_SteamTrain.hasFuel', 268),
                 0xd19180: (17168312, 'OBJC_IVAR_$_SteamTrain.fuelFraction', 260),
        },
        classes={
                 0xd1914c: (15253264, 'OBJC_CLASS_$_SteamTrain'),
                 0xd19164: (15251188, 'OBJC_CLASS_$_NSNumber'),
        },
        instructions=[(13733508, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13733592, 'blx ip'), (13733600, 'ldr r0, [0x00d19150]'), (13734276, 'eorseq r6, r4, r8, asr ip')],
        calls=[(13733592, 'blx ip'), (13733872, 'blx r3'), (13733908, 'blx ip'), (13733968, 'blx r3'), (13734004, 'blx ip'), (13734064, 'blx r3'), (13734100, 'blx ip'), (13734160, 'blx r3'), (13734196, 'blx ip')],
        branches=[],
        semantics=('[SteamTrain getSaveDict] (imp 0x00d18e84, 193w): the reverse save chain - super call (@0xd18ed8) then the key pool **fff4e414/e404/e3f4/e3e4** wraps the **fffffccc/c8/cc0** ivar reads into the dict via ffe28a94/a9c/aa0/bc00.\n'),
    ),
    dict(
        name='st4_title',
        method='SteamTrain -[title]',
        types='@8@0:4',
        start=13827240,
        end=13827288,
        disasm='disasm_worldtileloader_st4_title.txt',
        base_add=13827248,
        base_literal=13827284,
        boundary='ARM.exidx end 0x00d2fcd8 (listing bound); next ObjC IMP 0x00d2fcd8 SteamTrain -[fuelCount]',
        selectors={},
        imports={
                 0xd2fcd0: (16441272, '__CFConstantStringClassReference'),
        },
        ivars={},
        classes={},
        instructions=[(13827240, 'sub sp, sp, 8'), (13827284, 'eorseq pc, r2, ip, lsr lr')],
        calls=[],
        branches=[],
        semantics=('[SteamTrain title] (imp 0x00d2fca8, 12w): returns the static title string via the fff4e4c4 cell (the "Steam Train" string-table entry).\n'),
    ),
    dict(
        name='st4_actiontitle',
        method='SteamTrain -[actionTitle]',
        types='@8@0:4',
        start=13826776,
        end=13827008,
        disasm='disasm_worldtileloader_st4_actiontitle.txt',
        base_add=13826792,
        base_literal=13827004,
        boundary='ARM.exidx end 0x00d2fbc0 (listing bound); next ObjC IMP 0x00d2fbc0 SteamTrain -[secondOptionTitle]',
        selectors={
                 0xd2fbb4: (15238768, 'stringWithFormat:'),
        },
        imports={
                 0xd2fba8: (16441224, '__CFConstantStringClassReference'),
                 0xd2fbac: (16441208, '__CFConstantStringClassReference'),
                 0xd2fbb0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd2fba4: (17168348, 'OBJC_IVAR_$_SteamTrain.rightStationName', 276),
        },
        classes={
                 0xd2fbb8: (15251208, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(13826776, 'push {r4, sl, fp, lr}'), (13826840, 'beq 0xd2fb88'), (13826952, 'ldr r0, [0x00d2fba8]'), (13827004, 'eorseq r0, r3, r4')],
        calls=[(13826940, 'blx ip')],
        branches=[(13826840, 'beq', 13826952), (13826948, 'b', 13826968)],
        semantics=('[SteamTrain actionTitle] (imp 0x00d2fad8, 58w): the station-name action title - the **fffffce8** gate (`cmp r0, 0; beq` @0xd2fb18: nil falls to the default string fff4e494); the live path reads the rail state via fff4e484 + ffe28b7c/bc14 and formats the title with the station name.\n'),
    ),
    dict(
        name='st4_secondtitle',
        method='SteamTrain -[secondOptionTitle]',
        types='@8@0:4',
        start=13827008,
        end=13827240,
        disasm='disasm_worldtileloader_st4_secondtitle.txt',
        base_add=13827024,
        base_literal=13827236,
        boundary='ARM.exidx end 0x00d2fca8 (listing bound); next ObjC IMP 0x00d2fca8 SteamTrain -[title]',
        selectors={
                 0xd2fc9c: (15238768, 'stringWithFormat:'),
        },
        imports={
                 0xd2fc90: (16441256, '__CFConstantStringClassReference'),
                 0xd2fc94: (16441240, '__CFConstantStringClassReference'),
                 0xd2fc98: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd2fc8c: (17168344, 'OBJC_IVAR_$_SteamTrain.leftStationName', 272),
        },
        classes={
                 0xd2fca0: (15251208, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(13827008, 'push {r4, sl, fp, lr}'), (13827236, 'eorseq pc, r2, ip, lsl pc')],
        calls=[(13827172, 'blx ip')],
        branches=[(13827072, 'beq', 13827184), (13827180, 'b', 13827200)],
        semantics=("[SteamTrain secondOptionTitle] (imp 0x00d2fbc0, 58w): the mirror of actionTitle on the same **fffffce8** gate + fff4e484/ffe28b7c family (the second UI option's title).\n"),
    ),
    dict(
        name='st4_itemtype',
        method='SteamTrain -[itemType]',
        types='i8@0:4',
        start=13826248,
        end=13826276,
        disasm='disasm_worldtileloader_st4_itemtype.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00d2f8e4 (listing bound); next ObjC IMP 0x00d2f8e4 SteamTrain -[setWorkbenchChoiceUIOption:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13826248, 'sub sp, sp, 8'), (13826272, 'bx lr')],
        calls=[],
        branches=[],
        semantics=("[SteamTrain itemType] (imp 0x00d2f8c8, 7w): returns **0xcd (205)** - the train's item type; the SAME constant as the fuel-item gate of addToFuelForItem: (E70): the train item IS the fuel item of the furnace family.\n"),
    ),
    dict(
        name='st4_objecttype',
        method='SteamTrain -[objectType]',
        types='i8@0:4',
        start=13729404,
        end=13729432,
        disasm='disasm_worldtileloader_st4_objecttype.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00d17e98 (listing bound); next ObjC IMP 0x00d17e98 SteamTrain -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:placedByClient:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13729404, 'sub sp, sp, 8'), (13729428, 'bx lr')],
        calls=[],
        branches=[],
        semantics=("[SteamTrain objectType] (imp 0x00d17e7c, 7w): returns **0x2a (42)** - the SteamTrain's dynamic-object type code (new pin for the type table family of E36/E37).\n"),
    ),
    dict(
        name='st4_cxx_construct',
        method='SteamTrain -[.cxx_construct]',
        types='@8@0:4',
        start=13833080,
        end=13833104,
        disasm='disasm_worldtileloader_st4_cxx_construct.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00d31390 (listing bound); next ObjC IMP 0x00d31a48 AddCreditUI -[initWithWorldName:worldID:creditTimeString:windowInfo:cache:delegate:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13833080, 'sub sp, sp, 8'), (13833100, 'bx lr')],
        calls=[],
        branches=[],
        semantics=("[SteamTrain .cxx_construct] (imp 0x00d31378, 6w): empty body - no C++ members need construction (contrast WirePathCreator's map member in E68).\n"),
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
        'batch': 'SteamTrain remainder (E74): the giant draw + update censuses and the small accessor tail; 10 bodies',
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
                        default=NATIVE / 'steamtrain_close.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale steamtrain_close.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
