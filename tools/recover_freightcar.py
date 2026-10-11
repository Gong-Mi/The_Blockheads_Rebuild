#!/usr/bin/env python3
"""Hash-gated recovery of the FreightCar (E149).

FreightCar lands: the batch sweeps freightcar surface:
27 bodies, 10456 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/FREIGHTCAR.md for the prose and boundaries.
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
    'bl 0xa4091c': 0x00a4091c,
    'bl 0xa40e2c': 0x00a40e2c,
    'bl 0xa4c414': 0x00a4c414,
    'bl 0xa4c488': 0x00a4c488,
    'bl 0xa4c820': 0x00a4c820,
    'bl 0xa4cde0': 0x00a4cde0,
    'bl 0xa4d44c': 0x00a4d44c,
    'bl 0xa4d700': 0x00a4d700,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector.Vector_float__float__float__float_': 0x004d0d08,
    'bl method.Vector.operator_float__': 0x004b5c08,
    'bl method.Vector2.Vector2__': 0x004d5170,
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl method.Vector2.length___const': 0x0057509c,
    'bl method.Vector2.operator_Vector2_': 0x004d0418,
    'bl method.Vector2.operator__Vector2_': 0x004d04b4,
    'bl method.Vector2.operator__float_': 0x004d03c0,
    'bl method.Vector2.operator_float_': 0x004d0368,
    'bl method.Vector2.operator_float__': 0x004bdaac,
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
    'bl sym.imp.atan2f': 0x001c410c,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.popDepthMaskState': 0x007c57ec,
    'bl sym.pushDepthMaskState': 0x007c55e4,
    'bl sym.texCoordsForImageIndex_int_': 0x004d6820,
    'bl sym.texCoordsForItemType_ItemType_': 0x004d6040,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileAtWorldPosition_int__int__MacroTile__World_': 0x00a16e68,
    'bl sym.tileIsSolid_Tile_': 0x00a1179c,
}

SPECS = [
    dict(
        name='fc_00',
        method='FreightCar -[actionTitle]',
        types='@8@0:4',
        start=10803196,
        end=10803244,
        disasm='disasm_worldtileloader_fc_00.txt',
        base_add=10803204,
        base_literal=10803240,
        boundary='ARM.exidx end 0x00a4d82c (listing bound); next ObjC IMP 0x00a4d82c FreightCar -[blockheadCanRide:usingItem:]',
        selectors={},
        imports={
                 0xa4d824: (16347960, '__CFConstantStringClassReference'),
        },
        ivars={},
        classes={},
        instructions=[(10803196, 'sub sp, sp, 8'), (10803240, 'rsbeq r2, r1, r8, ror 5')],
        calls=[],
        branches=[],
        semantics=('[FreightCar -[actionTitle]] (imp 0x00a4d7fc, 12w): -[actionTitle] (0xa4d7fc, 12w): returns the static CFString "FREIGHT CAR" @0xF97338 (Apportable literal pattern: cell 0xa4d828 pc+0x6122e8 -> PIC base 0x105FAF4, value cell 0xa4d824 delta 0xfff37844; cstr @0xF4BFFF, flags 0x7c8, len 11). Hardcoded, not [self title]; same cstr as item 206\'s name..\n'),
    ),
    dict(
        name='fc_01',
        method='FreightCar -[actsAsInteractionObject]',
        types='@8@0:4',
        start=10805496,
        end=10805556,
        disasm='disasm_worldtileloader_fc_01.txt',
        base_add=10805504,
        base_literal=10805552,
        boundary='ARM.exidx end 0x00a4e134 (listing bound); next ObjC IMP 0x00a4e134 FreightCar -[childNeedsSaving:]',
        selectors={},
        imports={},
        ivars={
                 0xa4e12c: (17164472, 'OBJC_IVAR_$_FreightCar.chest', 220),
        },
        classes={},
        instructions=[(10805496, 'sub sp, sp, 8'), (10805552, 'rsbeq r1, r1, ip, ror 19')],
        calls=[],
        branches=[],
        semantics=('[FreightCar -[actsAsInteractionObject]] (imp 0x00a4e0f8, 15w): -[actsAsInteractionObject] (0xa4e0f8, 15w): `return self->chest;` (ivar 220; two-level cell 0x105E8B8 -> 0xF34B98 -> 0xdc). The child Chest IS the interaction proxy (Boat/NPC returned nil)..\n'),
    ),
    dict(
        name='fc_02',
        method='FreightCar -[blockheadCanRide:usingItem:]',
        types='c16@0:4@8i12',
        start=10803244,
        end=10803280,
        disasm='disasm_worldtileloader_fc_02.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a4d850 (listing bound); next ObjC IMP 0x00a4d850 FreightCar -[tapIsWithinBodyRadius:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10803244, 'sub sp, sp, 0x10'), (10803276, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[FreightCar -[blockheadCanRide:usingItem:]] (imp 0x00a4d82c, 9w): -[blockheadCanRide:usingItem:] (0xa4d82c, 9w): returns (signed char)0 = NO; both arguments ignored (the car never carries blockheads)..\n'),
    ),
    dict(
        name='fc_03',
        method='FreightCar -[blockheadsLoaded]',
        types='v8@0:4',
        start=10805816,
        end=10806000,
        disasm='disasm_worldtileloader_fc_03.txt',
        base_add=10805832,
        base_literal=10805996,
        boundary='ARM.exidx end 0x00a4e2f0 (listing bound); next ObjC IMP 0x00a4e2f0 FreightCar -[setUpdateNeedsToBeSent:]',
        selectors={
                 0xa4e2dc: (15224744, 'blockheadsLoaded'),
        },
        imports={
                 0xa4e2d8: (17151900, 'objc_msgSendSuper2'),
                 0xa4e2e4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa4e2e8: (17164472, 'OBJC_IVAR_$_FreightCar.chest', 220),
        },
        classes={
                 0xa4e2e0: (15253032, 'OBJC_CLASS_$_FreightCar'),
        },
        instructions=[(10805816, 'push {r4, sl, fp, lr}'), (10805996, 'rsbeq r1, r1, r4, lsr 17')],
        calls=[(10805900, 'blx ip'), (10805964, 'blx r2')],
        branches=[],
        semantics=('[FreightCar -[blockheadsLoaded]] (imp 0x00a4e238, 46w): -[blockheadsLoaded] (0xa4e238, 46w): [super blockheadsLoaded] (objc_msgSendSuper2, struct {self, FreightCar 0x00E919D0}) then forwards the same selector to self->chest (msgSend on ivar 220) so the chest reattaches its own riders..\n'),
    ),
    dict(
        name='fc_04',
        method='FreightCar -[cameraPos]',
        types='{Vector2=[2f]}8@0:4',
        start=10803004,
        end=10803140,
        disasm='disasm_worldtileloader_fc_04.txt',
        base_add=10803020,
        base_literal=10803136,
        boundary='ARM.exidx end 0x00a4d7c4 (listing bound); next ObjC IMP 0x00a4d7c4 FreightCar -[setTargetVelocity:]',
        selectors={
                 0xa4d7bc: (15224740, 'renderPos'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(10803004, 'push {fp, lr}'), (10803136, 'rsbeq r2, r1, r0, lsr 7')],
        calls=[(10803084, 'bl loc.imp.objc_msgSend_stret'), (10803120, 'bl sym.imp.memset')],
        branches=[(10803068, 'beq', 10803092), (10803088, 'b', 10803124)],
        semantics=('[FreightCar -[cameraPos]] (imp 0x00a4d73c, 34w): -[cameraPos] (0xa4d73c, 34w): stret one-liner `return [self renderPos];` (objc_msgSend_stret; nil-self -> memset(ret,0,8)). No bespoke camera (Boat had a look-ahead one)..\n'),
    ),
    dict(
        name='fc_05',
        method='FreightCar -[childNeedsSaving:]',
        types='v12@0:4@8',
        start=10805556,
        end=10805816,
        disasm='disasm_worldtileloader_fc_05.txt',
        base_add=10805572,
        base_literal=10805812,
        boundary='ARM.exidx end 0x00a4e238 (listing bound); next ObjC IMP 0x00a4e238 FreightCar -[blockheadsLoaded]',
        selectors={
                 0xa4e22c: (15224636, 'objectType'),
                 0xa4e230: (15224640, 'dynamicWorldChangedAtPos:objectType:'),
        },
        imports={},
        ivars={
                 0xa4e218: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xa4e21c: (17164468, 'OBJC_IVAR_$_FreightCar.needsChestSave', 224),
                 0xa4e224: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xa4e228: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={},
        instructions=[(10805556, 'push {fp, lr}'), (10805812, 'rsbeq r1, r1, r8, lsr 19')],
        calls=[(10805712, 'bl loc.imp.objc_msgSend'), (10805748, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[FreightCar -[childNeedsSaving:]] (imp 0x00a4e134, 65w): -[childNeedsSaving:] (0xa4e134, 65w): child arg IGNORED; self->needsChestSave@224=1; [[self dynamicWorld] dynamicWorldChangedAtPos:self->pos@16 objectType:[self objectType]]; self->updateNeedsToBeSent@49=1. This is the hook Chest ce_07 contentsDidChange fires via [proxyObjectOwner childNeedsSaving:self]..\n'),
    ),
    dict(
        name='fc_06',
        method='FreightCar -[creationNetDataForClient:]',
        types='@12@0:4@8',
        start=10750732,
        end=10751532,
        disasm='disasm_worldtileloader_fc_06.txt',
        base_add=10750748,
        base_literal=10751528,
        boundary='ARM.exidx end 0x00a40e2c (listing bound); next ObjC IMP 0x00a40f98 FreightCar -[updateNetDataForClient:]',
        selectors={
                 0xa40df0: (15224592, 'trainCarCreationNetData'),
                 0xa40dfc: (15224600, 'dictionary'),
                 0xa40e04: (15224596, 'dataWithBytes:length:'),
                 0xa40e10: (15224588, 'setObject:forKey:'),
                 0xa40e14: (15224604, 'creationNetDataForClient:'),
                 0xa40e20: (15224612, 'appendData:'),
                 0xa40e24: (15224608, 'gzipDeflate'),
        },
        imports={
                 0xa40df8: (17151904, 'objc_msgSend'),
                 0xa40e0c: (16347928, '__CFConstantStringClassReference'),
                 0xa40e1c: (16347944, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xa40df4: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
                 0xa40e18: (17164472, 'OBJC_IVAR_$_FreightCar.chest', 220),
        },
        classes={
                 0xa40e00: (15249076, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0xa40e08: (15249072, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(10750732, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10751528, 'invalid')],
        calls=[(10750824, 'bl loc.imp.objc_msgSend_stret'), (10750860, 'bl sym.imp.memset'), (10750992, 'bl sym.imp.memcpy'), (10751032, 'blx ip'), (10751068, 'blx r3'), (10751192, 'blx ip'), (10751272, 'blx r3'), (10751360, 'blx ip'), (10751368, 'bl 0xa40e2c'), (10751428, 'blx lr'), (10751456, 'blx r3')],
        branches=[(10750808, 'beq', 10750832), (10750828, 'b', 10750864), (10751104, 'beq', 10751196), (10751292, 'beq', 10751364)],
        semantics=('[FreightCar -[creationNetDataForClient:]] (imp 0x00a40b0c, 200w): -[creationNetDataForClient:] (0xa40b0c, 200w): rec=[self trainCarCreationNetData] (0x68=104B stret, zeroed when self nil); d=[NSMutableData dataWithBytes:&rec length:0x68]; dict=[NSMutableDictionary dictionary]; if(self->ownerID@36) dict["ownerID"@0xF97318]=ownerID; chestData=[self->chest creationNetDataForClient:client]; if(chestData) dict["chestData"@0xF97328]=chestData; [d appendData:[plistFromDict(dict) gzipDeflate]]; return d. plistFromDict = local helper 0xa40e2c (NSPropertyListSerialization dataWithPropertyList:format:100 options:0, @try/@catch + NSLog "Failed to load plist..." @0xF97348)..\n'),
    ),
    dict(
        name='fc_07',
        method='FreightCar -[dealloc]',
        types='v8@0:4',
        start=10752660,
        end=10753100,
        disasm='disasm_worldtileloader_fc_07.txt',
        base_add=10752676,
        base_literal=10753096,
        boundary='ARM.exidx end 0x00a4144c (listing bound); next ObjC IMP 0x00a4144c FreightCar -[updatePosition:]',
        selectors={
                 0xa41424: (15224624, 'dealloc'),
                 0xa41430: (15224620, 'release'),
                 0xa41438: (15224556, 'setProxyObjectOwner:'),
        },
        imports={
                 0xa41420: (17151900, 'objc_msgSendSuper2'),
                 0xa4142c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa41434: (17164472, 'OBJC_IVAR_$_FreightCar.chest', 220),
                 0xa4143c: (17164460, 'OBJC_IVAR_$_FreightCar.poleCube', 216),
                 0xa41440: (17164456, 'OBJC_IVAR_$_FreightCar.chestCube', 212),
                 0xa41444: (17164464, 'OBJC_IVAR_$_FreightCar.platformCube', 208),
        },
        classes={
                 0xa41428: (15253032, 'OBJC_CLASS_$_FreightCar'),
        },
        instructions=[(10752660, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10753096, 'rsbeq lr, r1, r8, asr 16')],
        calls=[(10752856, 'blx r6'), (10752892, 'blx r3'), (10752928, 'blx r3'), (10752968, 'blx r3'), (10753004, 'blx r3'), (10753044, 'blx r2')],
        branches=[],
        semantics=('[FreightCar -[dealloc]] (imp 0x00a41294, 110w): -[dealloc] (0xa41294, 110w): [platformCube@208 release]; [chestCube@212 release]; [poleCube@216 release]; [chest@220 setProxyObjectOwner:nil]; [chest release]; [super dealloc]..\n'),
    ),
    dict(
        name='fc_08',
        method='FreightCar -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        types='v156@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76i140i144i148i152',
        start=10770128,
        end=10798100,
        disasm='disasm_worldtileloader_fc_08.txt',
        base_add=10770172,
        base_literal=10774148,
        boundary='ARM.exidx end 0x00a4c414 (listing bound); next ObjC IMP 0x00a4cfc8 FreightCar -[renderPos]',
        selectors={
                 0xa46838: (15224700, 'worldWidthMacro'),
                 0xa46ba4: (15224704, 'macroTiles'),
                 0xa46bbc: (15224708, 'program'),
                 0xa46bc4: (15224720, 'intValue'),
                 0xa46bc8: (15224716, 'objectAtIndex:'),
                 0xa46bcc: (15224712, 'uniformLocations'),
                 0xa46bd0: (15224724, 'dayColor'),
                 0xa46bd4: (15224728, 'translation'),
                 0xa48130: (15224732, 'name'),
                 0xa4813c: (15224736, 'draw'),
                 0xa48144: (15224720, 'intValue'),
                 0xa48148: (15224716, 'objectAtIndex:'),
                 0xa4814c: (15224712, 'uniformLocations'),
                 0xa48164: (15224692, 'leftWheelPos'),
                 0xa4816c: (15224696, 'rightWheelPos'),
                 0xa492f0: (15224492, 'alloc'),
                 0xa492f4: (15224496, 'initWithWidth:height:depth:centerX:centerY:centerZ:topMinS:topMaxS:topMinT:topMaxT:sideMinS:sideMaxS:sideMinT:sideMaxT:calculateNormals:'),
                 0xa492f8: (15224620, 'release'),
                 0xa492fc: (15224708, 'program'),
                 0xa49310: (15224712, 'uniformLocations'),
                 0xa49314: (15224716, 'objectAtIndex:'),
                 0xa49318: (15224720, 'intValue'),
                 0xa49320: (15224732, 'name'),
                 0xa4c3fc: (15224720, 'intValue'),
                 0xa4c400: (15224716, 'objectAtIndex:'),
                 0xa4c404: (15224712, 'uniformLocations'),
        },
        imports={
                 0xa46ba0: (17151904, 'objc_msgSend'),
                 0xa48140: (17151904, 'objc_msgSend'),
                 0xa4c3f8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa4682c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa46834: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xa46b8c: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xa46ba8: (17161264, 'OBJC_IVAR_$_TrainCar.visualVelocity', 128),
                 0xa46bb0: (17161268, 'OBJC_IVAR_$_TrainCar.rotationAnimationTimer', 92),
                 0xa46bb4: (17161204, 'OBJC_IVAR_$_TrainCar.rightWheelPos', 104),
                 0xa46bb8: (17161200, 'OBJC_IVAR_$_TrainCar.leftWheelPos', 96),
                 0xa46bc0: (17161272, 'OBJC_IVAR_$_TrainCar.shader', 56),
                 0xa4812c: (17161276, 'OBJC_IVAR_$_TrainCar.tileTexture', 64),
                 0xa48134: (17161280, 'OBJC_IVAR_$_TrainCar.tileDestructTexture', 68),
                 0xa48138: (17164464, 'OBJC_IVAR_$_FreightCar.platformCube', 208),
                 0xa48150: (17161272, 'OBJC_IVAR_$_TrainCar.shader', 56),
                 0xa48154: (17161212, 'OBJC_IVAR_$_TrainCar.rightCar', 168),
                 0xa48158: (17164456, 'OBJC_IVAR_$_FreightCar.chestCube', 212),
                 0xa4815c: (17161260, 'OBJC_IVAR_$_TrainCar.engineIsRight', 180),
                 0xa48160: (17161216, 'OBJC_IVAR_$_TrainCar.leftCar', 172),
                 0xa48168: (17161204, 'OBJC_IVAR_$_TrainCar.rightWheelPos', 104),
                 0xa48170: (17161200, 'OBJC_IVAR_$_TrainCar.leftWheelPos', 96),
                 0xa49300: (17161284, 'OBJC_IVAR_$_TrainCar.worldObjectShader', 60),
                 0xa4931c: (17161288, 'OBJC_IVAR_$_TrainCar.itemTexture', 72),
                 0xa49324: (17161268, 'OBJC_IVAR_$_TrainCar.rotationAnimationTimer', 92),
                 0xa4c40c: (17161284, 'OBJC_IVAR_$_TrainCar.worldObjectShader', 60),
        },
        classes={
                 0xa492e8: (15249060, 'OBJC_CLASS_$_DrawCube'),
        },
        instructions=[(10770128, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10798096, 'mrclt p9, 4, sb, c9, c10, 4')],
        calls=[(10770844, 'bl loc.imp.objc_msgSend'), (10770868, 'bl sym.imp.__aeabi_idiv'), (10770936, 'bl loc.imp.objc_msgSend'), (10771064, 'bl loc.imp.objc_msgSend'), (10771080, 'bl sym.imp.__aeabi_idiv'), (10771148, 'bl loc.imp.objc_msgSend'), (10771280, 'bl loc.imp.objc_msgSend'), (10771304, 'bl sym.imp.__aeabi_idiv'), (10771372, 'bl loc.imp.objc_msgSend'), (10771500, 'bl loc.imp.objc_msgSend'), (10771516, 'bl sym.imp.__aeabi_idiv'), (10771584, 'bl loc.imp.objc_msgSend'), (10771880, 'bl method.Vector2.Vector2_float__float_'), (10771920, 'bl method.Vector2.operator_Vector2_'), (10771928, 'bl method.Vector2.operator_float__'), (10771992, 'bl loc.imp.objc_msgSend'), (10772016, 'bl sym.imp.__aeabi_idiv'), (10772116, 'bl loc.imp.objc_msgSend'), (10772152, 'bl method.Vector2.operator_float__'), (10772208, 'bl method.Vector2.operator_float__'), (10772276, 'bl loc.imp.objc_msgSend'), (10772292, 'bl sym.imp.__aeabi_idiv'), (10772392, 'bl loc.imp.objc_msgSend'), (10772428, 'bl method.Vector2.operator_float__'), (10772568, 'blx r2'), (10772616, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (10772668, 'bl method.Vector2.operator_float__'), (10772684, 'bl method.Vector2.operator_float__'), (10772704, 'bl 0xa4c414'), (10772744, 'bl method.Vector2.operator_float__'), (10772912, 'bl method.Vector2.operator__Vector2_'), (10772920, 'bl method.Vector2.operator_float__'), (10772940, 'bl method.Vector2.operator_float__'), (10772952, 'bl sym.imp.atan2f'), (10773304, 'bl 0xa4c488'), (10773376, 'bl sym.imp.memcpy'), (10773424, 'blx ip'), (10773428, 'bl sym.imp.__wrap_glUseProgram'), (10773560, 'blx r6'), (10773580, 'blx r3'), (10773596, 'blx r2'), (10773604, 'bl sym.imp.__wrap_glUniform1i'), (10773736, 'blx r6'), (10773756, 'blx r3'), (10773772, 'blx r2'), (10773780, 'bl sym.imp.__wrap_glUniform1i'), (10773788, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (10773872, 'bl loc.imp.objc_msgSend_stret'), (10773912, 'bl sym.imp.memset'), (10774384, 'bl method.Vector.Vector_float__float__float_'), (10774404, 'bl method.Vector.operator_float__'), (10774432, 'bl method.Vector.operator_float__'), (10774460, 'bl method.Vector.operator_float__'), (10774700, 'bl method.Vector.Vector_float__float__float__float_'), (10774828, 'blx r2'), (10774848, 'blx r3'), (10774864, 'blx r2'), (10774880, 'bl method.Vector.operator_float__'), (10774908, 'bl method.Vector.operator_float__'), (10774936, 'bl method.Vector.operator_float__'), (10774964, 'bl method.Vector.operator_float__'), (10775020, 'bl sym.imp.__wrap_glUniform4f'), (10775152, 'blx r6'), (10775172, 'blx r3'), (10775188, 'blx r2'), (10775204, 'bl method.Vector.operator_float__'), (10775228, 'bl method.Vector.operator_float__'), (10775252, 'bl method.Vector.operator_float__'), (10775276, 'bl method.Vector.operator_float__'), (10775332, 'bl sym.imp.__wrap_glUniform4f'), (10775416, 'bl loc.imp.objc_msgSend_stret'), (10775548, 'bl sym.imp.memset'), (10775608, 'bl loc.imp.objc_msgSend'), (10775636, 'bl loc.imp.objc_msgSend'), (10775660, 'bl loc.imp.objc_msgSend'), (10775684, 'bl method.Vector2.operator_float__'), (10775712, 'bl method.Vector2.operator_float__'), (10775744, 'bl method.Vector2.operator_float__'), (10775764, 'bl method.Vector2.operator_float__'), (10775832, 'bl sym.imp.__wrap_glUniform4f'), (10776628, 'bl 0xa4c820'), (10777424, 'bl 0xa4c820'), (10777460, 'bl loc.imp.objc_msgSend'), (10777480, 'bl loc.imp.objc_msgSend'), (10777496, 'bl loc.imp.objc_msgSend'), (10777516, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (10777552, 'bl loc.imp.objc_msgSend'), (10777572, 'bl loc.imp.objc_msgSend'), (10777588, 'bl loc.imp.objc_msgSend'), (10777604, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (10777652, 'bl loc.imp.objc_msgSend'), (10777680, 'bl sym.imp.__wrap_glBindTexture'), (10777688, 'bl sym.imp.__wrap_glActiveTexture'), (10777728, 'bl loc.imp.objc_msgSend'), (10777748, 'bl sym.imp.__wrap_glBindTexture'), (10777788, 'bl loc.imp.objc_msgSend'), (10778160, 'bl 0xa4cde0'), (10778952, 'bl 0xa4c820'), (10779876, 'bl 0xa4c820'), (10780048, 'bl sym.imp.memcpy'), (10780096, 'blx ip'), (10780116, 'blx r3'), (10780132, 'blx r2'), (10780164, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (10780304, 'blx r3'), (10780324, 'blx r3'), (10780340, 'blx r2'), (10780372, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (10780456, 'blx r3'), (10780628, 'bl method.Vector2.Vector2__'), (10780648, 'bl method.Vector2.Vector2__'), (10780820, 'bl loc.imp.objc_msgSend_stret'), (10780860, 'bl sym.imp.memset'), (10780964, 'bl loc.imp.objc_msgSend_stret'), (10781072, 'bl sym.imp.memset'), (10781168, 'bl method.Vector2.operator_float_'), (10781212, 'bl method.Vector2.operator_Vector2_'), (10781268, 'bl method.Vector2.operator__Vector2_'), (10781276, 'bl method.Vector2.length___const'), (10781324, 'bl method.Vector2.operator__Vector2_'), (10781360, 'bl method.Vector2.operator__float_'), (10781368, 'bl method.Vector2.operator_float__'), (10781388, 'bl method.Vector2.operator_float__'), (10781400, 'bl sym.imp.atan2f'), (10781424, 'bl sym.texCoordsForImageIndex_int_'), (10781460, 'bl loc.imp.objc_msgSend'), (10781600, 'bl loc.imp.objc_msgSend'), (10781616, 'bl method.Vector2.operator_float__'), (10781632, 'bl method.Vector2.operator_float__'), (10781656, 'bl 0xa4c414'), (10782004, 'bl 0xa4c488'), (10782928, 'bl 0xa4c820'), (10783852, 'bl 0xa4c820'), (10784024, 'bl sym.imp.memcpy'), (10784072, 'blx ip'), (10784092, 'blx r3'), (10784108, 'blx r2'), (10784140, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (10784280, 'blx r3'), (10784300, 'blx r3'), (10784316, 'blx r2'), (10784348, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (10784408, 'blx r3'), (10784440, 'blx r3'), (10784448, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (10784460, 'bl sym.imp.__wrap_glBindTexture'), (10784468, 'bl sym.imp.__wrap_glActiveTexture'), (10784536, 'blx r2'), (10784540, 'bl sym.imp.__wrap_glUseProgram'), (10784672, 'blx r6'), (10784692, 'blx r3'), (10784708, 'blx r2'), (10784716, 'bl sym.imp.__wrap_glUniform1i'), (10784728, 'bl method.Vector.operator_float__'), (10784800, 'bl method.Vector.operator_float__'), (10784852, 'bl method.Vector.operator_float__'), (10784924, 'bl method.Vector.operator_float__'), (10784976, 'bl method.Vector.operator_float__'), (10785048, 'bl method.Vector.operator_float__'), (10785120, 'bl method.Vector.Vector_float__float__float_'), (10785176, 'bl method.Vector.operator_float__'), (10785288, 'bl method.Vector.operator_float__'), (10785312, 'bl method.Vector.operator_float__'), (10785424, 'bl method.Vector.operator_float__'), (10785448, 'bl method.Vector.operator_float__'), (10785628, 'bl method.Vector.operator_float__'), (10785700, 'bl loc.imp.objc_msgSend'), (10785728, 'bl loc.imp.objc_msgSend'), (10785752, 'bl loc.imp.objc_msgSend'), (10785768, 'bl method.Vector.operator_float__'), (10785784, 'bl method.Vector.operator_float__'), (10785800, 'bl method.Vector.operator_float__'), (10785840, 'bl sym.imp.__wrap_glUniform4f'), (10785848, 'bl sym.imp.__wrap_glEnable'), (10785860, 'bl sym.pushDepthMaskState'), (10785900, 'bl loc.imp.objc_msgSend'), (10785920, 'bl sym.imp.__wrap_glBindTexture'), (10785936, 'bl sym.texCoordsForItemType_ItemType_'), (10786332, 'bl 0xa4cde0'), (10786736, 'bl 0xa4c488'), (10787660, 'bl 0xa4c820'), (10788592, 'bl 0xa4c820'), (10788764, 'bl loc.imp.objc_msgSend'), (10788784, 'bl loc.imp.objc_msgSend'), (10788800, 'bl loc.imp.objc_msgSend'), (10788836, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (10788932, 'bl sym.drawShaderQuad'), (10789316, 'bl 0xa4cde0'), (10789816, 'bl 0xa4c488'), (10790740, 'bl 0xa4c820'), (10791672, 'bl 0xa4c820'), (10791844, 'bl loc.imp.objc_msgSend'), (10791864, 'bl loc.imp.objc_msgSend'), (10791880, 'bl loc.imp.objc_msgSend'), (10791896, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (10791964, 'bl sym.drawShaderQuad'), (10792332, 'bl 0xa4cde0'), (10792828, 'bl 0xa4c488'), (10793748, 'bl 0xa4c820'), (10794676, 'bl 0xa4c820'), (10794848, 'bl loc.imp.objc_msgSend'), (10794868, 'bl loc.imp.objc_msgSend'), (10794884, 'bl loc.imp.objc_msgSend'), (10794900, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (10794968, 'bl sym.drawShaderQuad'), (10795332, 'bl 0xa4cde0'), (10795828, 'bl 0xa4c488'), (10796748, 'bl 0xa4c820'), (10797676, 'bl 0xa4c820'), (10797836, 'bl sym.imp.memcpy'), (10797884, 'blx ip'), (10797904, 'blx r3'), (10797920, 'blx r2'), (10797952, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (10798048, 'bl sym.drawShaderQuad'), (10798056, 'bl sym.imp.__wrap_glDisable'), (10798060, 'bl sym.popDepthMaskState')],
        branches=[(10770880, 'blt', 10770972), (10770968, 'b', 10771184), (10771092, 'bge', 10771180), (10771180, 'b', 10771184), (10771316, 'blt', 10771408), (10771404, 'b', 10771620), (10771528, 'bge', 10771616), (10771616, 'b', 10771620), (10771660, 'blt', 10771796), (10771704, 'bgt', 10771796), (10771748, 'blt', 10771796), (10771792, 'ble', 10771800), (10771796, 'b', 10798064), (10772044, 'ble', 10772180), (10772176, 'b', 10772456), (10772320, 'bpl', 10772452), (10772452, 'b', 10772456), (10772640, 'bne', 10772656), (10772644, 'b', 10798064), (10773852, 'beq', 10773880), (10773876, 'b', 10773916), (10774036, 'bpl', 10774060), (10774056, 'b', 10774076), (10774124, 'bpl', 10774152), (10774144, 'b', 10774168), (10774216, 'ble', 10774288), (10774548, 'bpl', 10774616), (10774568, 'b', 10774632), (10775396, 'beq', 10775516), (10775420, 'b', 10775552), (10780492, 'beq', 10780536), (10780532, 'bne', 10780620), (10780576, 'beq', 10784444), (10780616, 'bne', 10784444), (10780696, 'beq', 10780888), (10780800, 'beq', 10780828), (10780824, 'b', 10780864), (10780884, 'b', 10781140), (10780948, 'beq', 10781044), (10780968, 'b', 10781076), (10785216, 'bpl', 10785240), (10785236, 'b', 10785256), (10785352, 'bpl', 10785376), (10785372, 'b', 10785392), (10785488, 'bpl', 10785576), (10785508, 'b', 10785592)],
        semantics=('[FreightCar -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]] (imp 0x00a456d0, 6993w): -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:] (0xa456d0, 6993w, 46br, 217 calls) [census]: composite renderer. (A) six world-wrap blocks around halfW=((int)[world worldWidthMacro]*32)/2 with __aeabi_idiv (4 camera bounds vs pos, 2 vs a Vector2 position); (B) early-out when tileAtWorldPosition(pos) is nil; (C) rotationAnimationTimer@92 += visualVelocity@128.x / -0.3 * arg (pool double -0.3 @0xa460a8); angle=atan2f((rightWheelPos@104-leftWheelPos@96).y,.x); matrix chain helper 0xa4c414(translate pos,-0.5) + helper 0xa4c488({M,angle}); (D) program 1 = [self.shader@56 program] via glUseProgram + 2x (uniformLocations->objectAtIndex: 0 and 4 -> intValue) with glUniform1i(loc0, 0) + glUniform1i(loc4, 1) + glEnableVertexAttribArray(2) + [world dayColor] (stret+memset 0x10) + light Vector math (pool 1024.0f/0.3f/255.0f) + 3x glUniform4f; then per-cube blocks (platformCube@208 w/ tileTexture@64 + tileDestructTexture@68 binds+glActiveTexture(0x84c1); chestCube@212 branched on engineIsRight@180; a temp coupling DrawCube L x0.1 x0.1 built in-body from wheel gap L=rec[0x2cc] center (L/2,0.05,0.05)) each: 2x helper 0xa4c820 + uniformLocations/objectAtIndex:/intValue chain + 2x glUniformMatrix4fv (mvp + objectAtIndex:3 normal) + [cube draw]; (E) program 2 = [self.worldObjectShader@60 program] + uniform1i + Vector color math + glUniform4f + glEnable(GL_BLEND 0xbe2) + pushDepthMaskState + [itemTexture@72 name] glBindTexture + texCoordsForItemType(0xcb=203 TRAIN WHEEL) then FOUR wheel quads (each: helpers 0xa4cde0+0xa4c488+2x0xa4c820 + uniformLocations chain + glUniformMatrix4fv + drawShaderQuad with +/-0.3f consts) then glDisable(GL_BLEND) + popDepthMaskState..\n'),
    ),
    dict(
        name='fc_09',
        method='FreightCar -[freeBlockCreationSaveDict]',
        types='@8@0:4',
        start=10750496,
        end=10750732,
        disasm='disasm_worldtileloader_fc_09.txt',
        base_add=10750512,
        base_literal=10750728,
        boundary='ARM.exidx end 0x00a40b0c (listing bound); next ObjC IMP 0x00a40b0c FreightCar -[creationNetDataForClient:]',
        selectors={
                 0xa40afc: (15224588, 'setObject:forKey:'),
                 0xa40b00: (15224584, 'getSaveDict'),
        },
        imports={
                 0xa40af4: (16347912, '__CFConstantStringClassReference'),
                 0xa40af8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa40b04: (17164472, 'OBJC_IVAR_$_FreightCar.chest', 220),
        },
        classes={},
        instructions=[(10750496, 'push {r4, r5, r6, sl, fp, lr}'), (10750728, 'strhteq pc, [r1], -0xc')],
        calls=[(10750600, 'blx ip'), (10750656, 'blx ip'), (10750692, 'blx ip')],
        branches=[],
        semantics=('[FreightCar -[freeBlockCreationSaveDict]] (imp 0x00a40a20, 59w): -[freeBlockCreationSaveDict] (0xa40a20, 59w): d=[self getSaveDict]; [d setObject:[self->chest getSaveDict] forKey:@"chest"@0xF97308]; return d. (The child chest\'s full save dict rides the block-creation save under key "chest".).\n'),
    ),
    dict(
        name='fc_10',
        method='FreightCar -[getChestSaveDict]',
        types='@8@0:4',
        start=10750396,
        end=10750496,
        disasm='disasm_worldtileloader_fc_10.txt',
        base_add=10750412,
        base_literal=10750492,
        boundary='ARM.exidx end 0x00a40a20 (listing bound); next ObjC IMP 0x00a40a20 FreightCar -[freeBlockCreationSaveDict]',
        selectors={
                 0xa40a14: (15224584, 'getSaveDict'),
        },
        imports={
                 0xa40a10: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa40a18: (17164472, 'OBJC_IVAR_$_FreightCar.chest', 220),
        },
        classes={},
        instructions=[(10750396, 'push {fp, lr}'), (10750492, 'rsbeq pc, r1, r0, lsr 2')],
        calls=[(10750468, 'blx r3')],
        branches=[],
        semantics=('[FreightCar -[getChestSaveDict]] (imp 0x00a409bc, 25w): -[getChestSaveDict] (0xa409bc, 25w): tail `return [self->chest getSaveDict];` (single objc_msgSend on ivar 220)..\n'),
    ),
    dict(
        name='fc_11',
        method='FreightCar -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:placedByClient:]',
        types='@36@0:4@8@12{?=ii}16@24@28@32',
        start=10745976,
        end=10748904,
        disasm='disasm_worldtileloader_fc_11.txt',
        base_add=10745992,
        base_literal=10748900,
        boundary='ARM.exidx end 0x00a403e8 (listing bound); next ObjC IMP 0x00a403e8 FreightCar -[initWithWorld:dynamicWorld:saveDict:chestSaveDict:cache:]',
        selectors={
                 0xa40368: (15224504, 'initWithWorld:dynamicWorld:atPosition:cache:saveDict:placedByClient:'),
                 0xa40370: (15224540, 'objectForKey:'),
                 0xa40380: (15224492, 'alloc'),
                 0xa40384: (15224544, 'initWithType:dataA:dataB:subItems:dynamicObjectSaveDict:'),
                 0xa40388: (15224548, 'autorelease'),
                 0xa40398: (15224552, 'initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:'),
                 0xa403a0: (15224556, 'setProxyObjectOwner:'),
                 0xa403a8: (15224560, 'setFloatPosAndUpdatePosition:'),
                 0xa403b4: (15224508, 'checkForTrainCarUnderTap:'),
                 0xa403bc: (15224512, 'connectsToOtherCars'),
                 0xa403c4: (15224532, 'setLeftCar:'),
                 0xa403cc: (15224516, 'retain'),
                 0xa403d0: (15224528, 'setEngineCar:'),
                 0xa403d4: (15224524, 'engineCar'),
                 0xa403d8: (15224520, 'setRightCar:'),
                 0xa403e0: (15224536, 'isEngine'),
        },
        imports={
                 0xa40378: (16347912, '__CFConstantStringClassReference'),
                 0xa403b8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa4036c: (17164468, 'OBJC_IVAR_$_FreightCar.needsChestSave', 224),
                 0xa40390: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xa40394: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa4039c: (17164472, 'OBJC_IVAR_$_FreightCar.chest', 220),
                 0xa403a4: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xa403ac: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xa403c0: (17161208, 'OBJC_IVAR_$_TrainCar.engineCar', 176),
                 0xa403c8: (17161212, 'OBJC_IVAR_$_TrainCar.rightCar', 168),
                 0xa403dc: (17161216, 'OBJC_IVAR_$_TrainCar.leftCar', 172),
        },
        classes={
                 0xa40360: (15253032, 'OBJC_CLASS_$_FreightCar'),
                 0xa4037c: (15249064, 'OBJC_CLASS_$_InventoryItem'),
                 0xa4038c: (15249068, 'OBJC_CLASS_$_Chest'),
        },
        instructions=[(10745976, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10748900, 'rsbeq r0, r2, r4, ror 4')],
        calls=[(10746184, 'bl loc.imp.objc_msgSendSuper2'), (10746304, 'bl sym.makeIntpair_int__int_'), (10746356, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10746408, 'bl sym.tileIsSolid_Tile_'), (10746484, 'bl sym.makeIntpair_int__int_'), (10746552, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10746648, 'bl sym.makeIntpair_int__int_'), (10746716, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10746788, 'bl sym.makeIntpair_int__int_'), (10746840, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10746892, 'bl sym.tileIsSolid_Tile_'), (10746932, 'bl sym.makeIntpair_int__int_'), (10747000, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10747060, 'bl sym.makeIntpair_int__int_'), (10747128, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10747280, 'bl method.Vector2.Vector2_float__float_'), (10747308, 'bl loc.imp.objc_msgSend'), (10747372, 'blx r2'), (10747488, 'blx r3'), (10747556, 'blx ip'), (10747680, 'blx ip'), (10747712, 'blx r3'), (10747808, 'blx r3'), (10747876, 'blx ip'), (10748000, 'blx ip'), (10748032, 'blx r3'), (10748120, 'blx r2'), (10748184, 'blx r3'), (10748296, 'bl loc.imp.objc_msgSend'), (10748328, 'bl loc.imp.objc_msgSend'), (10748388, 'bl loc.imp.objc_msgSend'), (10748404, 'bl loc.imp.objc_msgSend'), (10748432, 'bl loc.imp.objc_msgSend'), (10748568, 'bl loc.imp.objc_msgSend'), (10748640, 'bl loc.imp.objc_msgSend'), (10748720, 'bl loc.imp.objc_msgSend')],
        branches=[(10746212, 'bne', 10746228), (10746224, 'b', 10748756), (10746244, 'bge', 10748232), (10746376, 'beq', 10748212), (10746400, 'beq', 10746756), (10746420, 'beq', 10746588), (10746572, 'beq', 10746584), (10746584, 'b', 10746752), (10746736, 'beq', 10746748), (10746748, 'b', 10746752), (10746752, 'b', 10746756), (10746764, 'beq', 10748208), (10746860, 'beq', 10748204), (10746884, 'beq', 10747168), (10746904, 'beq', 10747036), (10747020, 'beq', 10747032), (10747032, 'b', 10747164), (10747148, 'beq', 10747160), (10747160, 'b', 10747164), (10747164, 'b', 10747168), (10747176, 'beq', 10748200), (10747328, 'beq', 10748196), (10747384, 'beq', 10748196), (10747396, 'bne', 10747720), (10747588, 'bne', 10747716), (10747716, 'b', 10748040), (10747908, 'bne', 10748036), (10748036, 'b', 10748040), (10748076, 'bne', 10748192), (10748132, 'beq', 10748188), (10748188, 'b', 10748192), (10748192, 'b', 10748196), (10748196, 'b', 10748200), (10748200, 'b', 10748204), (10748204, 'b', 10748208), (10748208, 'b', 10748212), (10748212, 'b', 10748216), (10748228, 'b', 10746236)],
        semantics=('[FreightCar -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:placedByClient:]] (imp 0x00a3f878, 732w): -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:placedByClient:] (0xa3f878, 732w) [census-lite]: placed ctor. super2 (6 by-value args); nil -> nil. Consist scan `for dx in {-1,+1}`: require the rail marker (tile byte +0xb == 0x62) at (pos.x+dx,pos.y) or its (solid ? +1 : -1) y-neighbour, then a second rail marker one step further out (X+dx, Y) with the same zigzag; then car=[dynamicWorld checkForTrainCarUnderTap:Vector2(X2+0.5f, Y2+1.5f)] (gl #96=0.5f, #120=1.5f); if(car && [car connectsToOtherCars]): dx=-1 -> self->leftCar=[car retain]+[leftCar setRightCar:self]; dx=+1 -> rightCar mirror; then if(!self->engineCar && [car isEngine]) [self setEngineCar:car]. NO break: both sides may link. Tail: chestSaveDict=saveDict[@"chest"@0xF97308]; item=[[InventoryItem alloc] initWithType:0x413(1043 CHEST) dataA:0 dataB:0 subItems:nil dynamicObjectSaveDict:chestSaveDict]; [item autorelease]; self->chest=[[Chest alloc] initWithWorld:self->world dynamicWorld:arg atPosition:self->pos cache:self->cache item:item flipped:NO saveDict:chestSaveDict placedByClient:NO clientName:nil]; [chest setProxyObjectOwner:self]; [chest setFloatPosAndUpdatePosition:self->floatPos]; self->needsChestSave@224=1; return self..\n'),
    ),
    dict(
        name='fc_12',
        method='FreightCar -[initWithWorld:dynamicWorld:cache:netData:]',
        types='@24@0:4@8@12@16@20',
        start=10749440,
        end=10750236,
        disasm='disasm_worldtileloader_fc_12.txt',
        base_add=10749456,
        base_literal=10750232,
        boundary='ARM.exidx end 0x00a4091c (listing bound); next ObjC IMP 0x00a40940 FreightCar -[getSaveDict]',
        selectors={
                 0xa408c8: (15224568, 'initWithWorld:dynamicWorld:cache:netData:'),
                 0xa408d0: (15224572, 'length'),
                 0xa408d8: (15224576, 'subdataWithRange:'),
                 0xa408dc: (15224580, 'gzipInflate'),
                 0xa408e0: (15224540, 'objectForKey:'),
                 0xa408e8: (15224516, 'retain'),
                 0xa408f8: (15224492, 'alloc'),
                 0xa4090c: (15224556, 'setProxyObjectOwner:'),
                 0xa40914: (15224560, 'setFloatPosAndUpdatePosition:'),
        },
        imports={
                 0xa408c4: (17151900, 'objc_msgSendSuper2'),
                 0xa408e4: (16347928, '__CFConstantStringClassReference'),
                 0xa408f0: (16347944, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xa408ec: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
                 0xa408fc: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xa40900: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xa40904: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0xa40908: (17164472, 'OBJC_IVAR_$_FreightCar.chest', 220),
                 0xa40910: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={
                 0xa408cc: (15253032, 'OBJC_CLASS_$_FreightCar'),
                 0xa408f4: (15249068, 'OBJC_CLASS_$_Chest'),
        },
        instructions=[(10749440, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10750232, 'invalid')],
        calls=[(10749588, 'blx r6'), (10749660, 'bl loc.imp.objc_msgSend'), (10749728, 'bl loc.imp.objc_msgSend'), (10749748, 'bl loc.imp.objc_msgSend'), (10749752, 'bl 0xa4091c'), (10749788, 'bl loc.imp.objc_msgSend'), (10749804, 'bl loc.imp.objc_msgSend'), (10749852, 'bl loc.imp.objc_msgSend'), (10749880, 'bl loc.imp.objc_msgSend'), (10749972, 'bl loc.imp.objc_msgSend'), (10750044, 'bl loc.imp.objc_msgSend'), (10750124, 'bl loc.imp.objc_msgSend')],
        branches=[(10749616, 'bne', 10749632), (10749628, 'b', 10750136)],
        semantics=('[FreightCar -[initWithWorld:dynamicWorld:cache:netData:]] (imp 0x00a40600, 199w): -[initWithWorld:dynamicWorld:cache:netData:] (0xa40600, 199w): super2; nil -> nil. tail=[netData length]-0x68 (NO length guard, unlike Boat); sub=[netData subdataWithRange:{0x68, tail}]; plist=plistFromData([sub gzipInflate]) via thunk 0xa4091c -> 0xa4e9a0; self->ownerID@36=[[plist objectForKey:@"ownerID"@0xF97318] retain]; chestData=[plist objectForKey:@"chestData"@0xF97328]; if(chestData){ self->chest=[[Chest alloc] initWithWorld:self->world dynamicWorld:self->dynamicWorld cache:self->cache netData:chestData]; [chest setProxyObjectOwner:self]; [chest setFloatPosAndUpdatePosition:self->floatPos]; } return self. Reader mirror of fc_06..\n'),
    ),
    dict(
        name='fc_13',
        method='FreightCar -[itemType]',
        types='i8@0:4',
        start=10803168,
        end=10803196,
        disasm='disasm_worldtileloader_fc_13.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a4d82c; body trimmed at the next IMP 0x00a4d7fc FreightCar -[actionTitle]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10803168, 'sub sp, sp, 8'), (10803192, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[FreightCar -[itemType]] (imp 0x00a4d7e0, 7w): -[itemType] (0xa4d7e0, 7w, trimmed at next IMP 0xa4d7fc): `return 0xce;` = 206 = "FREIGHT CAR" (item_names_v1/item_type_names.tsv item_type 206 -> FREIGHT CAR @0xf75d28)..\n'),
    ),
    dict(
        name='fc_14',
        method='FreightCar -[loadDerivedStuff]',
        types='v8@0:4',
        start=10744272,
        end=10745948,
        disasm='disasm_worldtileloader_fc_14.txt',
        base_add=10744288,
        base_literal=10745944,
        boundary='ARM.exidx end 0x00a3f85c (listing bound); next ObjC IMP 0x00a3f85c FreightCar -[objectType]',
        selectors={
                 0xa3f81c: (15224500, 'loadDerivedStuff'),
                 0xa3f834: (15224496, 'initWithWidth:height:depth:centerX:centerY:centerZ:topMinS:topMaxS:topMinT:topMaxT:sideMinS:sideMaxS:sideMinT:sideMaxT:calculateNormals:'),
                 0xa3f838: (15224492, 'alloc'),
        },
        imports={
                 0xa3f818: (17151900, 'objc_msgSendSuper2'),
                 0xa3f830: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa3f824: (17164456, 'OBJC_IVAR_$_FreightCar.chestCube', 212),
                 0xa3f840: (17164460, 'OBJC_IVAR_$_FreightCar.poleCube', 216),
                 0xa3f844: (17164464, 'OBJC_IVAR_$_FreightCar.platformCube', 208),
                 0xa3f848: (17161200, 'OBJC_IVAR_$_TrainCar.leftWheelPos', 96),
                 0xa3f850: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xa3f854: (17161204, 'OBJC_IVAR_$_TrainCar.rightWheelPos', 104),
        },
        classes={
                 0xa3f820: (15253032, 'OBJC_CLASS_$_FreightCar'),
                 0xa3f83c: (15249060, 'OBJC_CLASS_$_DrawCube'),
        },
        instructions=[(10744272, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10745944, 'rsbeq r0, r2, ip, lsl 18')],
        calls=[(10744312, 'bl sym.texCoordsForImageIndex_int_'), (10744444, 'blx r3'), (10744664, 'blx lr'), (10744696, 'bl sym.texCoordsForImageIndex_int_'), (10744852, 'blx ip'), (10745064, 'blx lr'), (10745096, 'bl sym.texCoordsForImageIndex_int_'), (10745140, 'bl sym.texCoordsForImageIndex_int_'), (10745316, 'blx r6'), (10745548, 'blx lr'), (10745608, 'blx r3'), (10745712, 'bl method.Vector2.Vector2_float__float_'), (10745732, 'bl method.Vector2.operator_Vector2_'), (10745828, 'bl method.Vector2.Vector2_float__float_'), (10745848, 'bl method.Vector2.operator_Vector2_')],
        branches=[(10745340, 'b', 10745360)],
        semantics=('[FreightCar -[loadDerivedStuff]] (imp 0x00a3f1d0, 419w): -[loadDerivedStuff] (0xa3f1d0, 419w) [census-lite]: builds 3 DrawCubes (calculateNormals YES): platformCube@208 = texCoordsForImageIndex(0xc4=196), dims 2.5 x 0.1 x 0.8 center (1.25, 0.05, 0.4); poleCube@216 = idx 0x73=115, 1.0 x 0.1 x 0.1 center (0.5, 0.1, 0.05); chestCube@212 = top idx 0x157=343 / side idx 0x156=342, 1.0 x 1.0 x 0.8 center (0.5, 0.5, 0.4). Then [super loadDerivedStuff] (super2). Then leftWheelPos@96 = floatPos + Vector2(-1,0); rightWheelPos@104 = floatPos + Vector2(1,0). VFP truth per _gl (vmov #4=2.5, #116=1.25, #96=0.5; pools 0.1/0.8/0.05/0.4)..\n'),
    ),
    dict(
        name='fc_15',
        method='FreightCar -[needsChestSave]',
        types='c8@0:4',
        start=10806788,
        end=10806848,
        disasm='disasm_worldtileloader_fc_15.txt',
        base_add=10806796,
        base_literal=10806844,
        boundary='ARM.exidx end 0x00a4e640 (listing bound); next ObjC IMP 0x00a4e640 FreightCar -[setNeedsChestSave:]',
        selectors={},
        imports={},
        ivars={
                 0xa4e638: (17164468, 'OBJC_IVAR_$_FreightCar.needsChestSave', 224),
        },
        classes={},
        instructions=[(10806788, 'sub sp, sp, 8'), (10806844, 'rsbeq r1, r1, r0, ror 9')],
        calls=[],
        branches=[],
        semantics=('[FreightCar -[needsChestSave]] (imp 0x00a4e604, 15w): -[needsChestSave] (0xa4e604, 15w): `return (signed char)self->needsChestSave@224;` (plain getter)..\n'),
    ),
    dict(
        name='fc_16',
        method='FreightCar -[remoteUpdate:]',
        types='v12@0:4@8',
        start=10753328,
        end=10754144,
        disasm='disasm_worldtileloader_fc_16.txt',
        base_add=10753344,
        base_literal=10754136,
        boundary='ARM.exidx end 0x00a41860 (listing bound); next ObjC IMP 0x00a41860 FreightCar -[update:accurateDT:isSimulation:]',
        selectors={
                 0xa41810: (15224632, 'remoteUpdate:'),
                 0xa4181c: (15224572, 'length'),
                 0xa41820: (15224580, 'gzipInflate'),
                 0xa41828: (15224576, 'subdataWithRange:'),
                 0xa41830: (15224540, 'objectForKey:'),
                 0xa41850: (15224636, 'objectType'),
                 0xa41854: (15224640, 'dynamicWorldChangedAtPos:objectType:'),
        },
        imports={
                 0xa4180c: (17151900, 'objc_msgSendSuper2'),
                 0xa41818: (17151904, 'objc_msgSend'),
                 0xa4182c: (16347944, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xa41834: (17164472, 'OBJC_IVAR_$_FreightCar.chest', 220),
                 0xa41838: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xa4183c: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xa41840: (17164468, 'OBJC_IVAR_$_FreightCar.needsChestSave', 224),
                 0xa41848: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xa4184c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={
                 0xa41814: (15253032, 'OBJC_CLASS_$_FreightCar'),
        },
        instructions=[(10753328, 'push {r4, r5, fp, lr}'), (10754140, 'andeq r0, r0, r0')],
        calls=[(10753420, 'blx lr'), (10753464, 'blx r2'), (10753536, 'bl loc.imp.objc_msgSend'), (10753604, 'bl loc.imp.objc_msgSend'), (10753628, 'blx r2'), (10753632, 'bl 0xa4091c'), (10753716, 'blx r3'), (10753808, 'blx r3'), (10753988, 'bl loc.imp.objc_msgSend'), (10754024, 'bl loc.imp.objc_msgSend')],
        branches=[(10753472, 'bls', 10753820), (10753652, 'beq', 10753816), (10753736, 'beq', 10753812), (10753812, 'b', 10753816), (10753816, 'b', 10753820), (10753852, 'bne', 10754052)],
        semantics=('[FreightCar -[remoteUpdate:]] (imp 0x00a41530, 204w): -[remoteUpdate:] (0xa41530, 204w): [super remoteUpdate:]; if([netData length] > 0x68){ plist=plistFromData([subdata{0x68,len-0x68} gzipInflate]); if(plist){ chestData=plist[@"chestData"@0xF97328]; if(chestData) [self->chest remoteUpdate:chestData]; } } then if(!self->isNet@52){ self->needsChestSave@224=1; [[self dynamicWorld] dynamicWorldChangedAtPos:self->pos objectType:[self objectType]]; self->updateNeedsToBeSent@49=1; } (server-side dirty marking of a non-net car)..\n'),
    ),
    dict(
        name='fc_17',
        method='FreightCar -[renderPos]',
        types='{Vector2=[2f]}8@0:4',
        start=10801096,
        end=10802252,
        disasm='disasm_worldtileloader_fc_17.txt',
        base_add=10801132,
        base_literal=10802240,
        boundary='ARM.exidx end 0x00a4d44c (listing bound); next ObjC IMP 0x00a4d73c FreightCar -[cameraPos]',
        selectors={},
        imports={},
        ivars={
                 0xa4d43c: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xa4d444: (17161204, 'OBJC_IVAR_$_TrainCar.rightWheelPos', 104),
                 0xa4d448: (17161200, 'OBJC_IVAR_$_TrainCar.leftWheelPos', 96),
        },
        classes={},
        instructions=[(10801096, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10802248, 'invalid')],
        calls=[(10801180, 'bl method.Vector2.operator_float__'), (10801196, 'bl method.Vector2.operator_float__'), (10801216, 'bl 0xa4c414'), (10801316, 'bl method.Vector2.operator__Vector2_'), (10801324, 'bl method.Vector2.operator_float__'), (10801344, 'bl method.Vector2.operator_float__'), (10801356, 'bl sym.imp.atan2f'), (10801684, 'bl 0xa4c488'), (10801960, 'bl 0xa4d700'), (10802196, 'bl 0xa4d44c'), (10802220, 'bl method.Vector2.Vector2_float__float_')],
        branches=[],
        semantics=('[FreightCar -[renderPos]] (imp 0x00a4cfc8, 289w): -[renderPos] (0xa4cfc8, 289w [listing bound 0xa4d44c]; scan\'s 477w was tsv-gap): stret; M=helper_0xa4c414(floatPos.x, floatPos.y, -0.5f) [matrix-from-translation: memcpy 0x40B template + x/y/z at +0x30/0x34/0x38]; angle=atan2f((rightWheelPos-leftWheelPos).y, .x); {M words, angle} -> helper_0xa4c488 (4x4 compose); result fed with v=(0, 0.75f, 0) (helper_0xa4d700 = V3 store) through helper_0xa4d44c (0x150-frame transform; internally builds {m..., w=1.0f} and calls 0xa4e884) -> return Vector2(out.x, out.y) = the car body point 0.75 up along its own axis (wheel-tilt aware)..\n'),
    ),
    dict(
        name='fc_18',
        method='FreightCar -[requiresHumanInteraction]',
        types='c8@0:4',
        start=10806480,
        end=10806508,
        disasm='disasm_worldtileloader_fc_18.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a4e4ec (listing bound); next ObjC IMP 0x00a4e4ec FreightCar -[setNeedsRemoved:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10806480, 'sub sp, sp, 8'), (10806504, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[FreightCar -[requiresHumanInteraction]] (imp 0x00a4e4d0, 7w): -[requiresHumanInteraction] (0xa4e4d0, 7w): `return (signed char)1;` = YES (opening the car / its chest needs a human; Chest proxy flow)..\n'),
    ),
    dict(
        name='fc_19',
        method='FreightCar -[setNeedsChestSave:]',
        types='v12@0:4c8',
        start=10806848,
        end=10806916,
        disasm='disasm_worldtileloader_fc_19.txt',
        base_add=10806876,
        base_literal=10806912,
        boundary='ARM.exidx end 0x00a4e684 (listing bound); next ObjC IMP 0x00a4ec70 HandCar -[loadDerivedStuff]',
        selectors={},
        imports={},
        ivars={
                 0xa4e67c: (17164468, 'OBJC_IVAR_$_FreightCar.needsChestSave', 224),
        },
        classes={},
        instructions=[(10806848, 'sub sp, sp, 0xc'), (10806912, 'mlseq r1, r0, r4, r1')],
        calls=[],
        branches=[],
        semantics=('[FreightCar -[setNeedsChestSave:]] (imp 0x00a4e640, 17w): -[setNeedsChestSave:] (0xa4e640, 17w): self->needsChestSave@224 = arg; with dmb ish fences around the byte store (atomic-ish store, two-level ivar cell 0x105E8B4 -> 0xE0)..\n'),
    ),
    dict(
        name='fc_20',
        method='FreightCar -[setNeedsRemoved:]',
        types='v12@0:4c8',
        start=10806508,
        end=10806788,
        disasm='disasm_worldtileloader_fc_20.txt',
        base_add=10806524,
        base_literal=10806784,
        boundary='ARM.exidx end 0x00a4e604 (listing bound); next ObjC IMP 0x00a4e604 FreightCar -[needsChestSave]',
        selectors={
                 0xa4e5f0: (15224668, 'setNeedsRemoved:'),
        },
        imports={
                 0xa4e5ec: (17151904, 'objc_msgSend'),
                 0xa4e5f8: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0xa4e5e8: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0xa4e5f4: (17164472, 'OBJC_IVAR_$_FreightCar.chest', 220),
        },
        classes={
                 0xa4e5fc: (15253032, 'OBJC_CLASS_$_FreightCar'),
        },
        instructions=[(10806508, 'push {r4, sl, fp, lr}'), (10806784, 'invalid')],
        calls=[(10806672, 'blx ip'), (10806748, 'blx r3')],
        branches=[(10806552, 'beq', 10806676), (10806588, 'bne', 10806676)],
        semantics=('[FreightCar -[setNeedsRemoved:]] (imp 0x00a4e4ec, 70w): -[setNeedsRemoved:] (0xa4e4ec, 70w): on the 0->1 edge (arg != 0 && !self->needsRemoved@48): [self->chest setNeedsRemoved:1]; then [super setNeedsRemoved:arg] (objc_msgSendSuper2)..\n'),
    ),
    dict(
        name='fc_21',
        method='FreightCar -[setTargetVelocity:]',
        types='v16@0:4{Vector2=[2f]}8',
        start=10803140,
        end=10803168,
        disasm='disasm_worldtileloader_fc_21.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a4d7e0 (listing bound); next ObjC IMP 0x00a4d7e0 FreightCar -[itemType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10803140, 'sub sp, sp, 0x10'), (10803164, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[FreightCar -[setTargetVelocity:]] (imp 0x00a4d7c4, 7w): -[setTargetVelocity:] (0xa4d7c4, 7w): empty stub (args spilled to stack and dropped) - the freight car is not drivable (no target velocity state)..\n'),
    ),
    dict(
        name='fc_22',
        method='FreightCar -[setUpdateNeedsToBeSent:]',
        types='v12@0:4c8',
        start=10806000,
        end=10806236,
        disasm='disasm_worldtileloader_fc_22.txt',
        base_add=10806016,
        base_literal=10806232,
        boundary='ARM.exidx end 0x00a4e3dc (listing bound); next ObjC IMP 0x00a4e3dc FreightCar -[updateNeedsToBeSent]',
        selectors={
                 0xa4e3c8: (15224748, 'setUpdateNeedsToBeSent:'),
        },
        imports={
                 0xa4e3c4: (17151900, 'objc_msgSendSuper2'),
                 0xa4e3d0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa4e3d4: (17164472, 'OBJC_IVAR_$_FreightCar.chest', 220),
        },
        classes={
                 0xa4e3cc: (15253032, 'OBJC_CLASS_$_FreightCar'),
        },
        instructions=[(10806000, 'push {r4, r5, fp, lr}'), (10806232, 'rsbeq r1, r1, ip, ror 15')],
        calls=[(10806116, 'blx lr'), (10806200, 'blx r3')],
        branches=[(10806128, 'bne', 10806204)],
        semantics=('[FreightCar -[setUpdateNeedsToBeSent:]] (imp 0x00a4e2f0, 59w): -[setUpdateNeedsToBeSent:] (0xa4e2f0, 59w): [super setUpdateNeedsToBeSent:arg]; if(!arg) [self->chest setUpdateNeedsToBeSent:0]; the clear is propagated to the chest..\n'),
    ),
    dict(
        name='fc_23',
        method='FreightCar -[tapIsWithinBodyRadius:]',
        types='c16@0:4{Vector2=[2f]}8',
        start=10803280,
        end=10805496,
        disasm='disasm_worldtileloader_fc_23.txt',
        base_add=10803300,
        base_literal=10805492,
        boundary='ARM.exidx end 0x00a4e0f8 (listing bound); next ObjC IMP 0x00a4e0f8 FreightCar -[actsAsInteractionObject]',
        selectors={
                 0xa4e0e4: (15224700, 'worldWidthMacro'),
        },
        imports={},
        ivars={
                 0xa4e0d0: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xa4e0d8: (17161204, 'OBJC_IVAR_$_TrainCar.rightWheelPos', 104),
                 0xa4e0dc: (17161200, 'OBJC_IVAR_$_TrainCar.leftWheelPos', 96),
                 0xa4e0e0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(10803280, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10805492, 'rsbeq r2, r1, r8, lsl 5')],
        calls=[(10803408, 'bl method.Vector2.Vector2_float__float_'), (10803432, 'bl method.Vector2.operator_Vector2_'), (10803440, 'bl method.Vector2.operator_float__'), (10803456, 'bl method.Vector2.operator_float__'), (10803476, 'bl 0xa4c414'), (10803572, 'bl method.Vector2.operator__Vector2_'), (10803580, 'bl method.Vector2.operator_float__'), (10803600, 'bl method.Vector2.operator_float__'), (10803612, 'bl sym.imp.atan2f'), (10803944, 'bl 0xa4c488'), (10804112, 'bl method.Vector2.operator__Vector2_'), (10804248, 'bl method.Vector2.operator_float__'), (10804264, 'bl method.Vector2.operator_float__'), (10804284, 'bl 0xa4d700'), (10804520, 'bl 0xa4d44c'), (10804540, 'bl method.Vector2.Vector2_float__float_'), (10804560, 'bl method.Vector2.operator_float__'), (10804576, 'bl method.Vector2.operator_float__'), (10804628, 'bl loc.imp.objc_msgSend'), (10804652, 'bl sym.imp.__aeabi_idiv'), (10804724, 'bl method.Vector2.operator_float__'), (10804740, 'bl method.Vector2.operator_float__'), (10804792, 'bl loc.imp.objc_msgSend'), (10804884, 'bl method.Vector2.operator_float__'), (10804900, 'bl method.Vector2.operator_float__'), (10804952, 'bl loc.imp.objc_msgSend'), (10804968, 'bl sym.imp.__aeabi_idiv'), (10805040, 'bl method.Vector2.operator_float__'), (10805056, 'bl method.Vector2.operator_float__'), (10805108, 'bl loc.imp.objc_msgSend'), (10805172, 'bl method.Vector2.operator_float__'), (10805192, 'bl method.Vector2.operator_float__'), (10805280, 'bl method.Vector2.operator_float__'), (10805316, 'bl method.Vector2.operator_float__'), (10805344, 'bl method.Vector2.operator_float__'), (10805380, 'bl method.Vector2.operator_float__')],
        branches=[(10804676, 'blt', 10804832), (10804828, 'b', 10805220), (10804992, 'bpl', 10805148), (10805144, 'b', 10805212), (10805248, 'bpl', 10805432), (10805272, 'ble', 10805432), (10805336, 'ble', 10805432), (10805416, 'bpl', 10805432), (10805428, 'b', 10805440)],
        semantics=('[FreightCar -[tapIsWithinBodyRadius:]] (imp 0x00a4d850, 554w): -[tapIsWithinBodyRadius:] (0xa4d850, 554w) [census-lite]: bodyPos=floatPos+(0,0.5f); M=helper_0xa4c414(floatPos.x, floatPos.y+0.5, -0.5f); angle=atan2f((rightWheelPos-leftWheelPos).y,.x); {M, -angle} + delta=(tap-bodyPos) through helpers 0xa4c488/0xa4d44c -> res; dxCheck=floatPos.x - res.x wrapped by worldWidthMacro*32 into [-halfW, halfW) (halfW=(w*32)/2, idiv); return (-1.5 < dxCheck < 1.5) && (floatPos.y < res.y < floatPos.y + 2.0f). Bands gl-verified: vmov.f64 #120=1.5 / #248=-1.5; vmov.f32 #0=2.0. (Boat\'s pick was floatPos +/-0.5; the freight car uses the wheel-angle transform + a 3-wide x 2-tall box.).\n'),
    ),
    dict(
        name='fc_24',
        method='FreightCar -[updateNeedsToBeSent]',
        types='c8@0:4',
        start=10806236,
        end=10806480,
        disasm='disasm_worldtileloader_fc_24.txt',
        base_add=10806252,
        base_literal=10806476,
        boundary='ARM.exidx end 0x00a4e4d0 (listing bound); next ObjC IMP 0x00a4e4d0 FreightCar -[requiresHumanInteraction]',
        selectors={
                 0xa4e4bc: (15224616, 'updateNeedsToBeSent'),
        },
        imports={
                 0xa4e4b8: (17151900, 'objc_msgSendSuper2'),
                 0xa4e4c4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa4e4c8: (17164472, 'OBJC_IVAR_$_FreightCar.chest', 220),
        },
        classes={
                 0xa4e4c0: (15253032, 'OBJC_CLASS_$_FreightCar'),
        },
        instructions=[(10806236, 'push {r4, sl, fp, lr}'), (10806476, 'rsbeq r1, r1, r0, lsl 14')],
        calls=[(10806320, 'blx ip'), (10806412, 'blx r2')],
        branches=[(10806348, 'bne', 10806436)],
        semantics=('[FreightCar -[updateNeedsToBeSent]] (imp 0x00a4e3dc, 61w): -[updateNeedsToBeSent] (0xa4e3dc, 61w): r=[super updateNeedsToBeSent]; if(!r) r=[self->chest updateNeedsToBeSent]; return r; the car needs a net update if either the car or its chest does..\n'),
    ),
    dict(
        name='fc_25',
        method='FreightCar -[updateNetDataForClient:]',
        types='@12@0:4@8',
        start=10751896,
        end=10752660,
        disasm='disasm_worldtileloader_fc_25.txt',
        base_add=10751912,
        base_literal=10752656,
        boundary='ARM.exidx end 0x00a41294 (listing bound); next ObjC IMP 0x00a41294 FreightCar -[dealloc]',
        selectors={
                 0xa4125c: (15224616, 'updateNeedsToBeSent'),
                 0xa41264: (15224592, 'trainCarCreationNetData'),
                 0xa4126c: (15224600, 'dictionary'),
                 0xa41274: (15224596, 'dataWithBytes:length:'),
                 0xa41280: (15224588, 'setObject:forKey:'),
                 0xa41284: (15224612, 'appendData:'),
                 0xa41288: (15224608, 'gzipDeflate'),
                 0xa4128c: (15224604, 'creationNetDataForClient:'),
        },
        imports={
                 0xa41258: (17151904, 'objc_msgSend'),
                 0xa4127c: (16347928, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xa41260: (17164472, 'OBJC_IVAR_$_FreightCar.chest', 220),
                 0xa41268: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
        },
        classes={
                 0xa41270: (15249076, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0xa41278: (15249072, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(10751896, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10752656, 'rsbeq lr, r1, r4, asr 22')],
        calls=[(10751976, 'blx ip'), (10752040, 'blx r3'), (10752112, 'bl loc.imp.objc_msgSend_stret'), (10752148, 'bl sym.imp.memset'), (10752280, 'bl sym.imp.memcpy'), (10752320, 'blx ip'), (10752356, 'blx r3'), (10752480, 'blx ip'), (10752488, 'bl 0xa40e2c'), (10752548, 'blx lr'), (10752576, 'blx r3')],
        branches=[(10751988, 'beq', 10752052), (10752048, 'b', 10752588), (10752096, 'beq', 10752120), (10752116, 'b', 10752152), (10752392, 'beq', 10752484)],
        semantics=('[FreightCar -[updateNetDataForClient:]] (imp 0x00a40f98, 191w): -[updateNetDataForClient:] (0xa40f98, 191w): if([self->chest updateNeedsToBeSent]) return [self creationNetDataForClient:client] (full record incl. chestData); else sparse: rec=[self trainCarCreationNetData] 0x68; d=[NSMutableData dataWithBytes:&rec length:0x68]; dict=[NSMutableDictionary dictionary]; if(self->ownerID) dict["ownerID"@0xF97318]=ownerID; [d appendData:[plistFromDict(dict) gzipDeflate]]; return d..\n'),
    ),
    dict(
        name='fc_26',
        method='FreightCar -[updatePosition:]',
        types='v16@0:4{?=ii}8',
        start=10753100,
        end=10753328,
        disasm='disasm_worldtileloader_fc_26.txt',
        base_add=10753164,
        base_literal=10753304,
        boundary='ARM.exidx end 0x00a41530 (listing bound); next ObjC IMP 0x00a41530 FreightCar -[remoteUpdate:]',
        selectors={
                 0xa4151c: (15224628, 'updatePosition:'),
                 0xa4152c: (15224560, 'setFloatPosAndUpdatePosition:'),
        },
        imports={},
        ivars={
                 0xa41520: (17164472, 'OBJC_IVAR_$_FreightCar.chest', 220),
                 0xa41528: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={
                 0xa41514: (15253032, 'OBJC_CLASS_$_FreightCar'),
        },
        instructions=[(10753100, 'push {fp, lr}'), (10753324, 'invalid')],
        calls=[(10753200, 'bl loc.imp.objc_msgSendSuper2'), (10753288, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[FreightCar -[updatePosition:]] (imp 0x00a4144c, 57w): -[updatePosition:] (0xa4144c, 57w): [super updatePosition:arg] (objc_msgSendSuper2) then [self->chest setFloatPosAndUpdatePosition:self->floatPos] (the chest rides the car\'s floatPos)..\n'),
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
        'batch': 'FreightCar (E149): the freight train car; 27 bodies',
        'claim': ('the freight train car (rail scan, car linking, wheel geometry)'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'freightcar.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale freightcar.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
