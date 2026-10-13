#!/usr/bin/env python3
"""Hash-gated recovery of the NPC core (E117).

The NPC class opens: the name-tag renderer, the net-state receive and
tick giants (census-grade), the tame/economy loop, the riding and
ownership checks and the creation wire format:
30 bodies, 11055 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/NPC_CORE.md for the prose and boundaries.
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
    'bl 0x6445d8': 0x006445d8,
    'bl 0x64dbd0': 0x0064dbd0,
    'bl 0x64dc1c': 0x0064dc1c,
    'bl 0x64dc68': 0x0064dc68,
    'bl 0x64de50': 0x0064de50,
    'bl 0x64e008': 0x0064e008,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector__': 0x004bed60,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector.Vector_float__float__float__float_': 0x004d0d08,
    'bl method.Vector.operator_Vector_': 0x004d6538,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl sym.clamp_float__float__float_': 0x004be068,
    'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_': 0x00a15404,
    'bl sym.drawShaderQuadNoTexture': 0x007c4790,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__modsi3': 0x001c3020,
    'bl sym.imp.__wrap_glDisableVertexAttribArray': 0x001c3d58,
    'bl sym.imp.__wrap_glEnableVertexAttribArray': 0x001c2d5c,
    'bl sym.imp.__wrap_glUniform4f': 0x001c3d64,
    'bl sym.imp.__wrap_glUniformMatrix4fv': 0x001c2dd4,
    'bl sym.imp.__wrap_glUseProgram': 0x001c2d38,
    'bl sym.imp.lrand48': 0x001c2804,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.seasonForWorldX_int__double__World_': 0x00a14a48,
    'bl sym.tameCountRequirementForNPCType_NPCType_': 0x0064be74,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileContainsDoor_Tile_': 0x00a12818,
    'bl sym.tileContainsGate_Tile_': 0x00a127cc,
    'bl sym.tileContainsTrapDoor_Tile_': 0x00a12864,
}

SPECS = [
    dict(
        name='np_00',
        method='NPC -[setBreed:]',
        types='v12@0:4S8',
        start=6624228,
        end=6624300,
        disasm='disasm_worldtileloader_np_00.txt',
        base_add=6624256,
        base_literal=6624296,
        boundary='ARM.exidx end 0x0065142c (listing bound); next ObjC IMP 0x0065158c ScrollingNetPlayerButtons -[initWithFrame:cache:windowInfo:worldUI:world:]',
        selectors={},
        imports={},
        ivars={
                 0x651424: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
        },
        classes={},
        instructions=[(6624228, 'sub sp, sp, 0xc'), (6624296, 'adceq lr, r0, ip, ror 13')],
        calls=[],
        branches=[],
        semantics=('[NPC -[setBreed:]] (imp 0x006513e4, 18w): bare ivar setter (breed).\n'),
    ),
    dict(
        name='np_01',
        method='NPC -[drawName:modelViewMatrix:pinchScale:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        types='v156@0:4(_GLKMatrix4={?=ffffffffffffffff}[16f])8(_GLKMatrix4={?=ffffffffffffffff}[16f])72f136i140i144i148i152',
        start=6602544,
        end=6609872,
        disasm='disasm_worldtileloader_np_01.txt',
        base_add=6602568,
        base_literal=6605800,
        boundary='ARM.exidx end 0x0064dbd0 (listing bound); next ObjC IMP 0x0064e5c8 NPC -[name]',
        selectors={
                 0x64cbf4: (15200680, 'tamed'),
                 0x64cc08: (15200864, 'worldWidthMacro'),
                 0x64cc38: (15200528, 'isEqualToString:'),
                 0x64d710: (15200692, 'isClient'),
                 0x64d718: (15200524, 'localNetID'),
                 0x64d728: (15200788, 'alloc'),
                 0x64d730: (15200868, 'windowInfo'),
                 0x64d738: (15200872, 'standardFont'),
                 0x64d73c: (15200876, 'initWithFrame:cache:windowInfo:string:horizontalAlignment:font:color:'),
                 0x64d740: (15200880, 'namePos'),
                 0x64db6c: (15200864, 'worldWidthMacro'),
                 0x64db8c: (15200884, 'renderFrame:projectionMatrix:'),
                 0x64db98: (15200892, 'shaderNamed:attributes:uniforms:'),
                 0x64dba4: (15200888, 'arrayWithObjects:'),
                 0x64dbb0: (15200900, 'healthFraction'),
                 0x64dbb4: (15200896, 'fullnessFraction'),
                 0x64dbbc: (15200476, 'intValue'),
                 0x64dbc0: (15200912, 'objectAtIndex:'),
                 0x64dbc4: (15200908, 'uniformLocations'),
                 0x64dbcc: (15200904, 'program'),
        },
        imports={
                 0x64cbf0: (17151904, 'objc_msgSend'),
                 0x64cc34: (16254552, '__CFConstantStringClassReference'),
                 0x64db64: (17151904, 'objc_msgSend'),
                 0x64db94: (16254712, '__CFConstantStringClassReference'),
                 0x64db9c: (16254744, '__CFConstantStringClassReference'),
                 0x64dba0: (16254760, '__CFConstantStringClassReference'),
                 0x64dbac: (16254728, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x64cbec: (17157304, 'OBJC_IVAR_$_NPC.name', 92),
                 0x64cbf8: (17157404, 'OBJC_IVAR_$_NPC.inspectingBlockhead', 116),
                 0x64cbfc: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x64cc04: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x64cc28: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x64cc2c: (17157320, 'OBJC_IVAR_$_NPC.netTameType', 192),
                 0x64cc30: (17157308, 'OBJC_IVAR_$_NPC.tamedClientID', 108),
                 0x64d714: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x64d71c: (17157412, 'OBJC_IVAR_$_NPC.nameTextView', 120),
                 0x64d72c: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0x64db68: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x64db70: (17157412, 'OBJC_IVAR_$_NPC.nameTextView', 120),
                 0x64db74: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0x64db84: (17157392, 'OBJC_IVAR_$_NPC.beingControlled', 128),
                 0x64db90: (17157416, 'OBJC_IVAR_$_NPC.progressShader', 124),
        },
        classes={
                 0x64d720: (15245912, 'OBJC_CLASS_$_MJTextView'),
                 0x64d734: (15245916, 'OBJC_CLASS_$_BitmapFont'),
                 0x64dba8: (15245920, 'OBJC_CLASS_$_NSArray'),
        },
        instructions=[(6602544, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6609868, 'invalid')],
        calls=[(6603200, 'blx r2'), (6603352, 'bl loc.imp.objc_msgSend'), (6603376, 'bl sym.imp.__aeabi_idiv'), (6603444, 'bl loc.imp.objc_msgSend'), (6603564, 'bl loc.imp.objc_msgSend'), (6603580, 'bl sym.imp.__aeabi_idiv'), (6603648, 'bl loc.imp.objc_msgSend'), (6603772, 'bl loc.imp.objc_msgSend'), (6603796, 'bl sym.imp.__aeabi_idiv'), (6603864, 'bl loc.imp.objc_msgSend'), (6603984, 'bl loc.imp.objc_msgSend'), (6604000, 'bl sym.imp.__aeabi_idiv'), (6604068, 'bl loc.imp.objc_msgSend'), (6604336, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6604596, 'blx ip'), (6604672, 'blx r2'), (6604792, 'blx ip'), (6604824, 'blx r3'), (6604940, 'bl 0x64dbd0'), (6604996, 'bl 0x64dbd0'), (6605092, 'bl loc.imp.objc_msgSend'), (6605152, 'bl 0x64dc1c'), (6605212, 'bl loc.imp.objc_msgSend'), (6605272, 'bl loc.imp.objc_msgSend'), (6605428, 'bl loc.imp.objc_msgSend'), (6605504, 'bl loc.imp.objc_msgSend_stret'), (6605540, 'bl sym.imp.memset'), (6605568, 'bl method.Vector2.operator_float__'), (6605632, 'bl loc.imp.objc_msgSend'), (6605656, 'bl sym.imp.__aeabi_idiv'), (6605744, 'bl loc.imp.objc_msgSend'), (6605776, 'bl method.Vector2.operator_float__'), (6605920, 'bl method.Vector2.operator_float__'), (6605984, 'bl loc.imp.objc_msgSend'), (6606000, 'bl sym.imp.__aeabi_idiv'), (6606088, 'bl loc.imp.objc_msgSend'), (6606120, 'bl method.Vector2.operator_float__'), (6606280, 'bl method.Vector2.operator_float__'), (6606296, 'bl method.Vector2.operator_float__'), (6606512, 'bl 0x64dc68'), (6606868, 'bl 0x64de50'), (6607696, 'bl 0x64e008'), (6607760, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (6608140, 'bl loc.imp.objc_msgSend'), (6608148, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (6608396, 'blx sl'), (6608444, 'blx lr'), (6608488, 'blx lr'), (6608564, 'blx r3'), (6608604, 'blx r3'), (6608820, 'bl sym.clamp_float__float__float_'), (6608896, 'blx r2'), (6608900, 'bl sym.imp.__wrap_glUseProgram'), (6609032, 'blx r3'), (6609052, 'blx r3'), (6609068, 'blx r2'), (6609100, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (6609320, 'blx r6'), (6609340, 'blx r3'), (6609356, 'blx r2'), (6609392, 'bl sym.imp.__wrap_glUniform4f'), (6609452, 'bl sym.drawShaderQuadNoTexture'), (6609600, 'blx r6'), (6609620, 'blx r3'), (6609636, 'blx r2'), (6609672, 'bl sym.imp.__wrap_glUniform4f'), (6609740, 'bl sym.drawShaderQuadNoTexture')],
        branches=[(6603156, 'beq', 6603256), (6603212, 'beq', 6603256), (6603252, 'beq', 6603260), (6603256, 'b', 6609748), (6603388, 'blt', 6603476), (6603472, 'b', 6603680), (6603592, 'bge', 6603676), (6603676, 'b', 6603680), (6603808, 'blt', 6603896), (6603892, 'b', 6604100), (6604012, 'bge', 6604096), (6604096, 'b', 6604100), (6604136, 'blt', 6604260), (6604176, 'bgt', 6604260), (6604216, 'blt', 6604260), (6604256, 'ble', 6604264), (6604260, 'b', 6609748), (6604356, 'beq', 6604376), (6604372, 'bne', 6604380), (6604376, 'b', 6609748), (6604420, 'beq', 6604476), (6604472, 'b', 6604864), (6604512, 'beq', 6604860), (6604608, 'beq', 6604684), (6604680, 'b', 6604856), (6604856, 'b', 6604860), (6604860, 'b', 6604864), (6604900, 'bne', 6605452), (6604956, 'beq', 6605032), (6605488, 'beq', 6605512), (6605508, 'b', 6605544), (6605680, 'ble', 6605896), (6605796, 'b', 6606144), (6606024, 'bpl', 6606140), (6606140, 'b', 6606144), (6607732, 'bne', 6608152), (6608164, 'bne', 6609748), (6608204, 'bne', 6608512), (6608636, 'bpl', 6608716), (6608652, 'b', 6608728), (6608764, 'bpl', 6609744), (6609744, 'b', 6609748)],
        semantics=('[NPC -[drawName:modelViewMatrix:pinchScale:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]] (imp 0x0064bf30, 1832w): the NPC name-tag renderer (census-grade: 17 objc_msgSend + MJTextView/BitmapFont/NSArray + drawShaderQuadNoTexture x2 + glUniform4f x2 + __aeabi_idiv x6 + healthFraction/fullness/tamed display, name color by isClient/localNetID, inspectingBlockhead variant; scaling pool 0x3f800000/0x3f000000/0xcccd/0x6666) - census-grade, not a per-instruction walkthrough.\n'),
    ),
    dict(
        name='np_02',
        method='NPC -[remoteCreationDataUpdate:]',
        types='v12@0:4@8',
        start=6585592,
        end=6591320,
        disasm='disasm_worldtileloader_np_02.txt',
        base_add=6585608,
        base_literal=6589128,
        boundary='ARM.exidx end 0x00649358 (listing bound); next ObjC IMP 0x00649358 NPC -[creationDataStructSize]',
        selectors={
                 0x648ad0: (15200688, 'remoteCreationDataUpdate:'),
                 0x648d38: (15200692, 'isClient'),
                 0x648d40: (15200540, 'getBytes:length:'),
                 0x648d44: (15200648, 'hitWithForce:blockhead:'),
                 0x648d48: (15200696, 'blockheadWithIDIncludingNet:'),
                 0x648d50: (15200700, 'reactToBeingHit'),
                 0x648d58: (15200704, 'feedByBlockhead:'),
                 0x648d5c: (15200708, 'setFreeByBlockhead:'),
                 0x648d60: (15200712, 'captureByBlockhead:withItemType:'),
                 0x648d64: (15200716, 'milkByBlockhead:'),
                 0x6490ac: (15200720, 'shaveByBlockhead:'),
                 0x6490b4: (15200676, 'isNet'),
                 0x64913c: (15200548, 'uniqueID'),
                 0x6491f8: (15200728, 'removeRider:'),
                 0x6491fc: (15200724, 'stopRiding'),
                 0x6492c0: (15200692, 'isClient'),
                 0x6492cc: (15200676, 'isNet'),
                 0x6492d0: (15200548, 'uniqueID'),
                 0x6492d4: (15200728, 'removeRider:'),
                 0x6492d8: (15200724, 'stopRiding'),
                 0x6492e0: (15200492, 'autorelease'),
                 0x6492e8: (15200612, 'countByEnumeratingWithState:objects:count:'),
                 0x6492ec: (15200732, 'allBlockheadsIncludingNet'),
                 0x6492f4: (15200736, 'addRider:'),
                 0x649314: (15200668, 'die:'),
                 0x64931c: (15200744, 'reactToBeingFed'),
                 0x649320: (15200740, 'successfulTame'),
                 0x649324: (15200752, 'length'),
                 0x649328: (15200748, 'creationDataStructSize'),
                 0x649334: (15200468, 'objectForKey:'),
                 0x649338: (15200760, 'propertyListWithData:options:format:error:'),
                 0x649340: (15200756, 'subdataWithRange:'),
                 0x649348: (15200764, 'server'),
                 0x649350: (15200488, 'retain'),
                 0x649354: (15200768, 'removeCurseWordsFromBlockheadName:'),
        },
        imports={
                 0x648acc: (17151900, 'objc_msgSendSuper2'),
                 0x648d34: (17151904, 'objc_msgSend'),
                 0x6492bc: (17151904, 'objc_msgSend'),
                 0x649330: (16254504, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x648d3c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x6490b0: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0x6492c4: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x6492c8: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0x6492dc: (17157392, 'OBJC_IVAR_$_NPC.beingControlled', 128),
                 0x649300: (17157288, 'OBJC_IVAR_$_NPC.tameCooldownTimer', 72),
                 0x649304: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0x649308: (17157268, 'OBJC_IVAR_$_NPC.fullness', 68),
                 0x64930c: (17157260, 'OBJC_IVAR_$_NPC.damage', 54),
                 0x649310: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0x649318: (17157320, 'OBJC_IVAR_$_NPC.netTameType', 192),
                 0x64932c: (17157304, 'OBJC_IVAR_$_NPC.name', 92),
                 0x64934c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={
                 0x648ad4: (15252612, 'OBJC_CLASS_$_NPC'),
                 0x64933c: (15245888, 'OBJC_CLASS_$_NSPropertyListSerialization'),
        },
        instructions=[(6585592, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6591316, 'invalid')],
        calls=[(6585684, 'blx lr'), (6585776, 'blx lr'), (6585812, 'blx r3'), (6585928, 'bl loc.imp.objc_msgSend'), (6585960, 'blx ip'), (6586020, 'blx r2'), (6586088, 'blx r2'), (6586208, 'bl loc.imp.objc_msgSend'), (6586292, 'blx r3'), (6586364, 'blx r3'), (6586440, 'blx ip'), (6586512, 'blx r3'), (6586584, 'blx r3'), (6586716, 'blx r2'), (6586816, 'bl loc.imp.objc_msgSend'), (6586936, 'blx lr'), (6586976, 'blx r3'), (6587148, 'bl loc.imp.objc_msgSend'), (6587304, 'blx r2'), (6587328, 'bl sym.imp.memset'), (6587376, 'blx lr'), (6587476, 'bl sym.imp.objc_enumerationMutation'), (6587548, 'blx r2'), (6587584, 'bl loc.imp.objc_msgSend'), (6587668, 'blx r3'), (6587800, 'blx ip'), (6587984, 'blx lr'), (6588020, 'blx r3'), (6588192, 'blx r2'), (6588292, 'bl loc.imp.objc_msgSend'), (6588412, 'blx lr'), (6588452, 'blx r3'), (6588600, 'blx r2'), (6588624, 'bl sym.imp.memset'), (6588672, 'blx lr'), (6588772, 'bl sym.imp.objc_enumerationMutation'), (6588844, 'blx r2'), (6588880, 'bl loc.imp.objc_msgSend'), (6588964, 'blx r3'), (6589096, 'blx ip'), (6589272, 'blx r3'), (6589308, 'blx r3'), (6589620, 'blx r3'), (6589720, 'blx r3'), (6589740, 'blx r2'), (6589852, 'blx r2'), (6589916, 'blx r3'), (6589940, 'blx r2'), (6590116, 'bl loc.imp.objc_msgSend'), (6590172, 'blx lr'), (6590200, 'blx r3'), (6590320, 'blx r4'), (6590368, 'blx ip'), (6590524, 'blx r2'), (6590560, 'blx r3'), (6590592, 'blx r3'), (6590608, 'blx r2'), (6590732, 'blx lr'), (6590748, 'blx r2'), (6590844, 'blx r2'), (6590928, 'blx r3'), (6591036, 'blx r2'), (6591120, 'blx r3')],
        branches=[(6585824, 'bne', 6585968), (6585836, 'ble', 6585964), (6585964, 'b', 6586028), (6585976, 'ble', 6586024), (6586024, 'b', 6586028), (6586100, 'bne', 6588092), (6586120, 'beq', 6586616), (6586124, 'b', 6586128), (6586136, 'beq', 6586616), (6586228, 'beq', 6586612), (6586240, 'bne', 6586304), (6586300, 'b', 6586608), (6586312, 'bne', 6586372), (6586368, 'b', 6586604), (6586380, 'bne', 6586452), (6586448, 'b', 6586600), (6586460, 'bne', 6586524), (6586520, 'b', 6586596), (6586532, 'bne', 6586592), (6586592, 'b', 6586596), (6586596, 'b', 6586600), (6586600, 'b', 6586604), (6586604, 'b', 6586608), (6586608, 'b', 6586612), (6586612, 'b', 6586616), (6586652, 'beq', 6586984), (6586728, 'bne', 6586984), (6586748, 'beq', 6586980), (6586752, 'b', 6586756), (6586844, 'beq', 6586980), (6586848, 'b', 6586852), (6586980, 'b', 6588088), (6587020, 'beq', 6588084), (6587040, 'beq', 6587836), (6587044, 'b', 6587048), (6587084, 'beq', 6587188), (6587176, 'bne', 6587188), (6587180, 'b', 6587184), (6587184, 'b', 6587832), (6587388, 'beq', 6587824), (6587468, 'beq', 6587480), (6587560, 'beq', 6587672), (6587612, 'bne', 6587672), (6587616, 'b', 6587620), (6587728, 'blo', 6587432), (6587820, 'bne', 6587432), (6587824, 'b', 6587828), (6587828, 'b', 6587832), (6587832, 'b', 6588080), (6587872, 'beq', 6588076), (6588076, 'b', 6588080), (6588080, 'b', 6588084), (6588084, 'b', 6588088), (6588088, 'b', 6589864), (6588128, 'beq', 6588460), (6588204, 'bne', 6588460), (6588224, 'beq', 6588456), (6588228, 'b', 6588232), (6588320, 'beq', 6588456), (6588324, 'b', 6588328), (6588456, 'b', 6589376), (6588476, 'beq', 6589144), (6588480, 'b', 6588484), (6588684, 'beq', 6589120), (6588764, 'beq', 6588776), (6588856, 'beq', 6588968), (6588908, 'bne', 6588968), (6588912, 'b', 6588916), (6589024, 'blo', 6588728), (6589116, 'bne', 6588728), (6589120, 'b', 6589124), (6589124, 'b', 6589372), (6589180, 'beq', 6589340), (6589372, 'b', 6589376), (6589536, 'beq', 6589624), (6589572, 'bne', 6589624), (6589664, 'bne', 6589800), (6589744, 'b', 6589860), (6589808, 'bne', 6589856), (6589856, 'b', 6589860), (6589860, 'b', 6589864), (6589964, 'ble', 6590976), (6590212, 'beq', 6590784), (6590380, 'beq', 6590648), (6590632, 'b', 6590772), (6590772, 'b', 6590964), (6590856, 'beq', 6590960), (6590960, 'b', 6590964), (6590964, 'b', 6591156), (6591048, 'beq', 6591152), (6591152, 'b', 6591156)],
        semantics=('[NPC -[remoteCreationDataUpdate:]] (imp 0x00647cf8, 1432w): the NPC net-state receive - dispatches the full interaction family from the decoded record (hitWithForce:blockhead:, feedByBlockhead:, setFreeByBlockhead:, captureByBlockhead:withItemType:, milkByBlockhead:, shaveByBlockhead:, removeRider:/stopRiding) + NSPropertyListSerialization + 0x48-byte record + enumeration x2 - census-grade, not a per-instruction walkthrough.\n'),
    ),
    dict(
        name='np_03',
        method='NPC -[update:accurateDT:isSimulation:]',
        types='v20@0:4f8f12c16',
        start=6580432,
        end=6585476,
        disasm='disasm_worldtileloader_np_03.txt',
        base_add=6580448,
        base_literal=6583976,
        boundary='ARM.exidx end 0x00647c84 (listing bound); next ObjC IMP 0x00647c84 NPC -[remoteUpdate:]',
        selectors={
                 0x647bb0: (15200520, 'isServer'),
                 0x647bec: (15200632, 'count'),
                 0x647c10: (15200628, 'serverClients'),
                 0x647c1c: (15200500, 'maxAge'),
                 0x647c30: (15200604, 'worldTime'),
                 0x647c34: (15200636, 'getDayNightFractionForX:atWorldTime:'),
                 0x647c38: (15200640, 'getWeatherFractionForPos:atWorldTime:'),
                 0x647c3c: (15200644, 'suffersDamageAtHighTemperatures'),
                 0x647c44: (15200648, 'hitWithForce:blockhead:'),
                 0x647c48: (15200652, 'minFullness'),
                 0x647c4c: (15200656, 'diesOfLowFullness'),
                 0x647c54: (15200660, 'maxHealth'),
                 0x647c58: (15200664, 'diesOfOldAge'),
                 0x647c5c: (15200668, 'die:'),
                 0x647c60: (15200672, 'paused'),
                 0x647c68: (15200616, 'needsRemoved'),
                 0x647c6c: (15200676, 'isNet'),
                 0x647c78: (15200492, 'autorelease'),
                 0x647c80: (15200680, 'tamed'),
        },
        imports={
                 0x647bac: (17151904, 'objc_msgSend'),
                 0x647c0c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x6476b0: (17157368, 'OBJC_IVAR_$_NPC.sendSuccessfulTameState', 196),
                 0x647908: (17157368, 'OBJC_IVAR_$_NPC.sendSuccessfulTameState', 196),
                 0x64790c: (17157372, 'OBJC_IVAR_$_NPC.sendSuccessfulFeedState', 200),
                 0x647910: (17157328, 'OBJC_IVAR_$_NPC.sendWasHitState', 204),
                 0x647914: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x647918: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0x64791c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x647920: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x647924: (17157288, 'OBJC_IVAR_$_NPC.tameCooldownTimer', 72),
                 0x647928: (17157284, 'OBJC_IVAR_$_NPC.mateCooldownTimer', 76),
                 0x64792c: (17157292, 'OBJC_IVAR_$_NPC.layCooldownTimer', 84),
                 0x647bb4: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x647bf0: (17157368, 'OBJC_IVAR_$_NPC.sendSuccessfulTameState', 196),
                 0x647bf4: (17157372, 'OBJC_IVAR_$_NPC.sendSuccessfulFeedState', 200),
                 0x647bf8: (17157328, 'OBJC_IVAR_$_NPC.sendWasHitState', 204),
                 0x647bfc: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x647c00: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x647c04: (17157288, 'OBJC_IVAR_$_NPC.tameCooldownTimer', 72),
                 0x647c14: (17157308, 'OBJC_IVAR_$_NPC.tamedClientID', 108),
                 0x647c18: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0x647c20: (17157376, 'OBJC_IVAR_$_NPC.temperatureCheckTimer', 156),
                 0x647c24: (17157268, 'OBJC_IVAR_$_NPC.fullness', 68),
                 0x647c28: (17157380, 'OBJC_IVAR_$_NPC.currentTemperature', 148),
                 0x647c40: (17157384, 'OBJC_IVAR_$_NPC.damageDelayTimer', 152),
                 0x647c50: (17157316, 'OBJC_IVAR_$_NPC.randomHarmFromHungerTimer', 144),
                 0x647c64: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0x647c70: (17157388, 'OBJC_IVAR_$_DynamicObject.creationDataNeedsToBeSent', 50),
                 0x647c74: (17157392, 'OBJC_IVAR_$_NPC.beingControlled', 128),
                 0x647c7c: (17157396, 'OBJC_IVAR_$_NPC.remoteSendControlEventTimer', 140),
        },
        classes={},
        instructions=[(6580432, 'push {r4, r5, r6, sl, fp, lr}'), (6585472, 'invalid')],
        calls=[(6580832, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6581224, 'blx r2'), (6581320, 'blx ip'), (6581336, 'blx r2'), (6581564, 'blx r3'), (6581704, 'blx r3'), (6581992, 'bl loc.imp.objc_msgSend'), (6582032, 'bl loc.imp.objc_msgSend'), (6582084, 'bl loc.imp.objc_msgSend'), (6582132, 'bl sym.seasonForWorldX_int__double__World_'), (6582264, 'bl loc.imp.objc_msgSend'), (6582304, 'bl loc.imp.objc_msgSend'), (6582368, 'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_'), (6582476, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6582728, 'blx r2'), (6583108, 'blx ip'), (6583112, 'bl 0x6445d8'), (6583244, 'blx r2'), (6583340, 'blx lr'), (6583384, 'blx r3'), (6583560, 'blx lr'), (6583572, 'bl sym.imp.__aeabi_idiv'), (6583608, 'blx ip'), (6583612, 'bl 0x6445d8'), (6583768, 'blx r2'), (6583832, 'blx r2'), (6583892, 'blx r3'), (6583956, 'blx r2'), (6584048, 'blx r2'), (6584124, 'blx r2'), (6584260, 'blx lr'), (6584412, 'blx r2'), (6584828, 'blx r2'), (6584896, 'blx r2'), (6584964, 'blx r2'), (6585072, 'blx r3'), (6585212, 'blx r3')],
        branches=[(6580516, 'bne', 6580552), (6580584, 'bne', 6580620), (6580652, 'bne', 6580688), (6580720, 'bne', 6584624), (6580756, 'bne', 6584580), (6580852, 'beq', 6580876), (6580868, 'bne', 6580876), (6580872, 'b', 6585316), (6580940, 'bpl', 6580984), (6581088, 'bne', 6581164), (6581124, 'bne', 6581164), (6581160, 'beq', 6581432), (6581236, 'beq', 6581428), (6581344, 'bne', 6581428), (6581428, 'b', 6581432), (6581468, 'beq', 6581756), (6581596, 'bpl', 6581644), (6581640, 'b', 6581748), (6581748, 'b', 6581796), (6581896, 'bhi', 6582636), (6582496, 'bne', 6582548), (6582512, 'beq', 6582596), (6582528, 'bne', 6582548), (6582544, 'bne', 6582596), (6582684, 'ble', 6583176), (6582740, 'beq', 6583176), (6582872, 'bhi', 6583172), (6582988, 'bpl', 6583024), (6583000, 'b', 6583040), (6583172, 'b', 6583176), (6583264, 'bpl', 6583700), (6583396, 'beq', 6583696), (6583464, 'bhi', 6583692), (6583692, 'b', 6583696), (6583696, 'b', 6583700), (6583788, 'ble', 6583896), (6583844, 'beq', 6583896), (6583968, 'beq', 6583988), (6583972, 'b', 6585316), (6584060, 'beq', 6584316), (6584136, 'bne', 6584172), (6584348, 'beq', 6584576), (6584424, 'bne', 6584572), (6584496, 'ble', 6584568), (6584568, 'b', 6584572), (6584572, 'b', 6584576), (6584576, 'b', 6584580), (6584580, 'b', 6585316), (6584688, 'bpl', 6584732), (6584848, 'bpl', 6584924), (6584976, 'beq', 6585272), (6585104, 'bpl', 6585152), (6585148, 'b', 6585256), (6585256, 'b', 6585312), (6585312, 'b', 6585316)],
        semantics=('[NPC -[update:accurateDT:isSimulation:]] (imp 0x006468d0, 1261w): the NPC tick - serverClients loop + age/fullness/damage/health checks + the environment reads (getDayNightFractionForX:atWorldTime:, getWeatherFractionForPos:atWorldTime:, seasonForWorldX, currentTemperatureForTileAtWorldPos) driving diesOfOldAge/diesOfLowFullness/suffersDamageAtHighTemperatures -> die: + tame/mate/lay cooldowns; constants 0x64/0x14/0xa; helper 0x6445d8 - census-grade, not a per-instruction walkthrough.\n'),
    ),
    dict(
        name='np_04',
        method='NPC -[getSaveDict]',
        types='@8@0:4',
        start=6576812,
        end=6580024,
        disasm='disasm_worldtileloader_np_04.txt',
        base_add=6576828,
        base_literal=6580020,
        boundary='ARM.exidx end 0x00646738 (listing bound); next ObjC IMP 0x00646738 NPC -[dealloc]',
        selectors={
                 0x646680: (15200588, 'getSaveDict'),
                 0x646694: (15200560, 'setObject:forKey:'),
                 0x646698: (15200600, 'numberWithBool:'),
                 0x6466b0: (15200596, 'numberWithFloat:'),
                 0x6466d4: (15200592, 'numberWithInt:'),
                 0x646708: (15200604, 'worldTime'),
                 0x646720: (15200612, 'countByEnumeratingWithState:objects:count:'),
                 0x646724: (15200608, 'blockheads'),
                 0x64672c: (15200616, 'needsRemoved'),
        },
        imports={
                 0x64667c: (17151900, 'objc_msgSendSuper2'),
                 0x64668c: (16254440, '__CFConstantStringClassReference'),
                 0x646690: (17151904, 'objc_msgSend'),
                 0x6466a4: (16254424, '__CFConstantStringClassReference'),
                 0x6466ac: (16254360, '__CFConstantStringClassReference'),
                 0x6466b8: (16254408, '__CFConstantStringClassReference'),
                 0x6466c0: (16254376, '__CFConstantStringClassReference'),
                 0x6466c8: (16254392, '__CFConstantStringClassReference'),
                 0x6466d0: (16254456, '__CFConstantStringClassReference'),
                 0x6466dc: (16254328, '__CFConstantStringClassReference'),
                 0x6466e4: (16254312, '__CFConstantStringClassReference'),
                 0x6466ec: (16254472, '__CFConstantStringClassReference'),
                 0x6466f4: (16254344, '__CFConstantStringClassReference'),
                 0x6466fc: (16254504, '__CFConstantStringClassReference'),
                 0x646704: (16254568, '__CFConstantStringClassReference'),
                 0x646710: (16254520, '__CFConstantStringClassReference'),
                 0x646718: (16254488, '__CFConstantStringClassReference'),
                 0x646730: (16254536, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x646688: (17157304, 'OBJC_IVAR_$_NPC.name', 92),
                 0x64669c: (17157276, 'OBJC_IVAR_$_NPC.hasBeenFedByBlockheadOrChest', 101),
                 0x6466a8: (17157280, 'OBJC_IVAR_$_NPC.hasBred', 100),
                 0x6466b4: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0x6466bc: (17157284, 'OBJC_IVAR_$_NPC.mateCooldownTimer', 76),
                 0x6466c4: (17157292, 'OBJC_IVAR_$_NPC.layCooldownTimer', 84),
                 0x6466cc: (17157288, 'OBJC_IVAR_$_NPC.tameCooldownTimer', 72),
                 0x6466d8: (17157272, 'OBJC_IVAR_$_NPC.mateBreed', 98),
                 0x6466e0: (17157264, 'OBJC_IVAR_$_NPC.layTimer', 80),
                 0x6466e8: (17157268, 'OBJC_IVAR_$_NPC.fullness', 68),
                 0x6466f0: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
                 0x6466f8: (17157260, 'OBJC_IVAR_$_NPC.damage', 54),
                 0x646700: (17157300, 'OBJC_IVAR_$_NPC.tameCountsByClientID', 104),
                 0x64670c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x646714: (17157308, 'OBJC_IVAR_$_NPC.tamedClientID', 108),
                 0x64671c: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0x646728: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={
                 0x646684: (15252612, 'OBJC_CLASS_$_NPC'),
                 0x6466a0: (15245896, 'OBJC_CLASS_$_NSNumber'),
        },
        instructions=[(6576812, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6580020, 'adceq sl, r1, r0, lsr r0')],
        calls=[(6576896, 'blx ip'), (6577452, 'blx ip'), (6577488, 'blx ip'), (6577548, 'blx r3'), (6577584, 'blx ip'), (6577644, 'blx lr'), (6577680, 'blx ip'), (6577740, 'blx lr'), (6577776, 'blx ip'), (6577836, 'blx r3'), (6577872, 'blx ip'), (6577932, 'blx lr'), (6577968, 'blx ip'), (6578028, 'blx lr'), (6578064, 'blx ip'), (6578124, 'blx lr'), (6578160, 'blx ip'), (6578220, 'blx lr'), (6578256, 'blx ip'), (6578316, 'blx r3'), (6578352, 'blx ip'), (6578412, 'blx r3'), (6578448, 'blx ip'), (6578568, 'blx ip'), (6578720, 'blx ip'), (6578756, 'blx r3'), (6578792, 'blx ip'), (6578912, 'blx ip'), (6579040, 'blx ip'), (6579208, 'blx r2'), (6579248, 'bl sym.imp.memset'), (6579296, 'blx lr'), (6579396, 'bl sym.imp.objc_enumerationMutation'), (6579508, 'blx r2'), (6579644, 'blx ip'), (6579780, 'blx lr'), (6579816, 'blx ip')],
        branches=[(6578480, 'beq', 6578572), (6578824, 'beq', 6578916), (6578952, 'beq', 6579044), (6579080, 'beq', 6579824), (6579308, 'beq', 6579668), (6579388, 'beq', 6579400), (6579464, 'bne', 6579536), (6579520, 'bne', 6579536), (6579532, 'b', 6579672), (6579572, 'blo', 6579352), (6579664, 'bne', 6579352), (6579668, 'b', 6579672), (6579680, 'beq', 6579820), (6579820, 'b', 6579824)],
        semantics=('[NPC -[getSaveDict]] (imp 0x00645aac, 803w): the save serializer - all NPC state keys (name/age/fullness/breed/damage/tameCountsByClientID/tamedClientID/rider/cooldowns/hasBeenFedByBlockheadOrChest/hasBred) + worldTime + blockheads enumeration + needsRemoved; 20 objc_msgSend.\n'),
    ),
    dict(
        name='np_05',
        method='NPC -[feedByBlockhead:]',
        types='c12@0:4@8',
        start=6599576,
        end=6602356,
        disasm='disasm_worldtileloader_np_05.txt',
        base_add=6599592,
        base_literal=6602352,
        boundary='ARM.exidx end 0x0064be74 (listing bound); next ObjC IMP 0x0064bf30 NPC -[drawName:modelViewMatrix:pinchScale:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        selectors={
                 0x64bddc: (15200860, 'canBeFedByBlockhead:'),
                 0x64bde8: (15200660, 'maxHealth'),
                 0x64bdf8: (15200784, 'clientID'),
                 0x64be04: (15200792, 'init'),
                 0x64be08: (15200788, 'alloc'),
                 0x64be10: (15200772, 'npcType'),
                 0x64be14: (15200560, 'setObject:forKey:'),
                 0x64be18: (15200800, 'numberWithInteger:'),
                 0x64be20: (15200796, 'integerValue'),
                 0x64be24: (15200468, 'objectForKey:'),
                 0x64be28: (15200528, 'isEqualToString:'),
                 0x64be30: (15200612, 'countByEnumeratingWithState:objects:count:'),
                 0x64be38: (15200740, 'successfulTame'),
                 0x64be3c: (15200488, 'retain'),
                 0x64be40: (15200492, 'autorelease'),
                 0x64be50: (15200744, 'reactToBeingFed'),
                 0x64be5c: (15200776, 'objectType'),
                 0x64be60: (15200780, 'dynamicWorldChangedAtPos:objectType:'),
                 0x64be64: (15200548, 'uniqueID'),
        },
        imports={
                 0x64bdd8: (17151904, 'objc_msgSend'),
                 0x64bdfc: (16254552, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x64bde0: (17157268, 'OBJC_IVAR_$_NPC.fullness', 68),
                 0x64bde4: (17157260, 'OBJC_IVAR_$_NPC.damage', 54),
                 0x64bdec: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x64bdf0: (17157288, 'OBJC_IVAR_$_NPC.tameCooldownTimer', 72),
                 0x64bdf4: (17157276, 'OBJC_IVAR_$_NPC.hasBeenFedByBlockheadOrChest', 101),
                 0x64be00: (17157300, 'OBJC_IVAR_$_NPC.tameCountsByClientID', 104),
                 0x64be2c: (17157308, 'OBJC_IVAR_$_NPC.tamedClientID', 108),
                 0x64be34: (17157368, 'OBJC_IVAR_$_NPC.sendSuccessfulTameState', 196),
                 0x64be44: (17157388, 'OBJC_IVAR_$_DynamicObject.creationDataNeedsToBeSent', 50),
                 0x64be48: (17157372, 'OBJC_IVAR_$_NPC.sendSuccessfulFeedState', 200),
                 0x64be54: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x64be58: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x64be6c: (17157340, 'OBJC_IVAR_$_NPC.feedBlockheadUniqueIDToSend', 160),
        },
        classes={
                 0x64be0c: (15245880, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x64be1c: (15245896, 'OBJC_CLASS_$_NSNumber'),
        },
        instructions=[(6599576, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6602352, 'adceq r4, r1, r4, asr 14')],
        calls=[(6599640, 'blx ip'), (6599924, 'blx r3'), (6599936, 'bl sym.imp.__aeabi_idiv'), (6600156, 'bl loc.imp.objc_msgSend'), (6600428, 'blx r3'), (6600576, 'blx r2'), (6600592, 'blx r2'), (6600780, 'blx sl'), (6600796, 'blx r2'), (6600868, 'blx r3'), (6600916, 'blx ip'), (6600952, 'blx r3'), (6600956, 'bl sym.tameCountRequirementForNPCType_NPCType_'), (6601040, 'blx r3'), (6601156, 'bl sym.imp.memset'), (6601220, 'blx lr'), (6601320, 'bl sym.imp.objc_enumerationMutation'), (6601400, 'blx ip'), (6601504, 'blx ip'), (6601520, 'blx r2'), (6601696, 'blx ip'), (6601856, 'blx r3'), (6601888, 'blx r3'), (6601928, 'blx r3'), (6602044, 'bl loc.imp.objc_msgSend'), (6602120, 'bl loc.imp.objc_msgSend'), (6602156, 'bl loc.imp.objc_msgSend')],
        branches=[(6599652, 'bne', 6599668), (6599664, 'b', 6602188), (6599764, 'ble', 6599808), (6599840, 'ble', 6600036), (6599956, 'bge', 6599972), (6599968, 'b', 6599980), (6600068, 'beq', 6600272), (6600240, 'b', 6602188), (6600336, 'bhi', 6601964), (6600448, 'bne', 6600468), (6600504, 'bne', 6600616), (6600968, 'blt', 6601960), (6601052, 'bne', 6601960), (6601232, 'beq', 6601720), (6601312, 'beq', 6601324), (6601412, 'bne', 6601596), (6601556, 'bge', 6601572), (6601568, 'b', 6601580), (6601596, 'b', 6601600), (6601624, 'blo', 6601276), (6601716, 'bne', 6601276), (6601720, 'b', 6601724), (6601736, 'ble', 6601956), (6601956, 'b', 6601960), (6601960, 'b', 6601964)],
        semantics=('[NPC -[feedByBlockhead:]] (imp 0x0064b398, 695w): the feeding logic - canBeFedByBlockhead: gate, tameCountsByClientID counting (numberWithInteger:), the tameCountRequirementForNPCType(NPCType) threshold, fullness/damage updates, successfulTame trigger and reactToBeingFed; constants 0x1fa4/0xa8c (2700)/0x2a3 (675).\n'),
    ),
    dict(
        name='np_06',
        method='NPC -[updatePosition:]',
        types='v16@0:4{?=ii}8',
        start=6621968,
        end=6624020,
        disasm='disasm_worldtileloader_np_06.txt',
        base_add=6621984,
        base_literal=6624016,
        boundary='ARM.exidx end 0x00651314 (listing bound); next ObjC IMP 0x00651314 NPC -[age]',
        selectors={
                 0x6512d0: (15200676, 'isNet'),
                 0x6512d8: (15200976, 'markCircumNavigateX:'),
                 0x6512f4: (15200980, 'setDoorAtPos:toOpen:direction:'),
                 0x65130c: (15200984, 'updatePosition:'),
        },
        imports={
                 0x6512cc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x6512c8: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0x6512d4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x6512dc: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x6512e0: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x6512e4: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0x6512e8: (17157420, 'OBJC_IVAR_$_DynamicObject.unreliableUpdateNeedsToBeSent', 51),
                 0x6512ec: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={
                 0x651304: (15252612, 'OBJC_CLASS_$_NPC'),
        },
        instructions=[(6621968, 'push {r4, sl, fp, lr}'), (6624016, 'adceq lr, r0, ip, asr 31')],
        calls=[(6622104, 'blx r2'), (6622228, 'blx r3'), (6622368, 'blx r2'), (6622796, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6622808, 'bl sym.tileContainsDoor_Tile_'), (6622836, 'bl sym.tileContainsTrapDoor_Tile_'), (6622864, 'bl sym.tileContainsGate_Tile_'), (6622988, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6623016, 'bl sym.tileContainsDoor_Tile_'), (6623120, 'bl sym.makeIntpair_int__int_'), (6623164, 'bl loc.imp.objc_msgSend'), (6623256, 'bl sym.makeIntpair_int__int_'), (6623300, 'bl loc.imp.objc_msgSend'), (6623408, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6623420, 'bl sym.tileContainsDoor_Tile_'), (6623448, 'bl sym.tileContainsTrapDoor_Tile_'), (6623476, 'bl sym.tileContainsGate_Tile_'), (6623576, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6623604, 'bl sym.tileContainsDoor_Tile_'), (6623684, 'bl sym.makeIntpair_int__int_'), (6623732, 'bl loc.imp.objc_msgSend'), (6623800, 'bl sym.makeIntpair_int__int_'), (6623848, 'bl loc.imp.objc_msgSend'), (6623932, 'bl loc.imp.objc_msgSendSuper2')],
        branches=[(6622040, 'beq', 6622232), (6622116, 'bne', 6622232), (6622156, 'beq', 6622232), (6622264, 'beq', 6622384), (6622304, 'beq', 6622604), (6622380, 'bne', 6622604), (6622420, 'bne', 6622464), (6622460, 'beq', 6622604), (6622528, 'beq', 6622568), (6622564, 'b', 6622600), (6622600, 'b', 6622604), (6622640, 'beq', 6623856), (6622680, 'bne', 6622724), (6622720, 'beq', 6623856), (6622828, 'bne', 6622888), (6622856, 'bne', 6622888), (6622908, 'bne', 6623176), (6623008, 'beq', 6623172), (6623032, 'beq', 6623168), (6623168, 'b', 6623172), (6623172, 'b', 6623304), (6623440, 'bne', 6623500), (6623468, 'bne', 6623500), (6623520, 'bne', 6623744), (6623596, 'beq', 6623740), (6623620, 'beq', 6623736), (6623736, 'b', 6623740), (6623740, 'b', 6623852), (6623852, 'b', 6623856)],
        semantics=('[NPC -[updatePosition:]] (imp 0x00650b10, 513w): the movement update - door/trapdoor/gate interactions on the way (tileContainsDoor x4, tileContainsTrapDoor x2, tileContainsGate x2, setDoorAtPos:toOpen:direction:) + markCircumNavigateX: path fixation + rider offset + the DynamicObject super call.\n'),
    ),
    dict(
        name='np_07',
        method='NPC -[checkCurrentPositionForFood]',
        types='v8@0:4',
        start=6619672,
        end=6621548,
        disasm='disasm_worldtileloader_np_07.txt',
        base_add=6619688,
        base_literal=6621544,
        boundary='ARM.exidx end 0x0065096c (listing bound); next ObjC IMP 0x0065096c NPC -[reactToBeingFed]',
        selectors={
                 0x650914: (15200612, 'countByEnumeratingWithState:objects:count:'),
                 0x650924: (15200944, 'freeBlocksAtPos:'),
                 0x650928: (15200952, 'foodItemType'),
                 0x65092c: (15200948, 'itemType'),
                 0x650930: (15200744, 'reactToBeingFed'),
                 0x650934: (15200932, 'setNeedsRemoved:'),
                 0x650940: (15200776, 'objectType'),
                 0x650944: (15200780, 'dynamicWorldChangedAtPos:objectType:'),
                 0x65094c: (15200956, 'interactionObjectAtPos:'),
                 0x650950: (15200960, 'interactionObjectType'),
                 0x650954: (15200964, 'chestType'),
                 0x650958: (15200968, 'isInUse'),
                 0x65095c: (15200972, 'removeItemIfAvailable:'),
        },
        imports={
                 0x650910: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x650908: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x65090c: (17157268, 'OBJC_IVAR_$_NPC.fullness', 68),
                 0x650918: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x650920: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x65093c: (17157388, 'OBJC_IVAR_$_DynamicObject.creationDataNeedsToBeSent', 50),
                 0x650960: (17157276, 'OBJC_IVAR_$_NPC.hasBeenFedByBlockheadOrChest', 101),
        },
        classes={},
        instructions=[(6619672, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6621544, 'adceq pc, r0, r4, asr 17')],
        calls=[(6619952, 'bl loc.imp.objc_msgSend'), (6619976, 'bl sym.imp.memset'), (6620024, 'blx lr'), (6620124, 'bl sym.imp.objc_enumerationMutation'), (6620208, 'blx r3'), (6620248, 'blx r3'), (6620332, 'bl loc.imp.objc_msgSend'), (6620476, 'bl loc.imp.objc_msgSend'), (6620512, 'bl loc.imp.objc_msgSend'), (6620532, 'blx r2'), (6620660, 'blx ip'), (6620836, 'bl loc.imp.objc_msgSend'), (6620900, 'blx r2'), (6620964, 'blx r2'), (6621016, 'blx r2'), (6621100, 'blx ip'), (6621132, 'blx r3'), (6621344, 'bl loc.imp.objc_msgSend'), (6621380, 'bl loc.imp.objc_msgSend'), (6621400, 'blx r2')],
        branches=[(6619732, 'beq', 6619740), (6619736, 'b', 6621420), (6619792, 'bpl', 6621420), (6620036, 'beq', 6620684), (6620116, 'beq', 6620128), (6620260, 'bne', 6620560), (6620536, 'b', 6620688), (6620560, 'b', 6620564), (6620588, 'blo', 6620080), (6620680, 'bne', 6620080), (6620684, 'b', 6620688), (6620740, 'bpl', 6621416), (6620856, 'beq', 6621412), (6620912, 'bne', 6621412), (6620972, 'bne', 6621408), (6621028, 'bne', 6621408), (6621144, 'beq', 6621404), (6621404, 'b', 6621408), (6621408, 'b', 6621412), (6621412, 'b', 6621416), (6621416, 'b', 6621420)],
        semantics=('[NPC -[checkCurrentPositionForFood]] (imp 0x00650218, 469w): the position food check - freeBlocksAtPos: walk with interactionObjectAtPos: chest handling (interactionObjectType/chestType/isInUse/removeItemIfAvailable:) then reactToBeingFed; 0x1518 (5400).\n'),
    ),
    dict(
        name='np_08',
        method='NPC -[npcCreationNetDataForClient:]',
        types='{NPCCreationNetData={DynamicObjectNetData=QIIC[7C]}QQQSSCCCCssSsC[7C]}12@0:4@8',
        start=6573716,
        end=6575572,
        disasm='disasm_worldtileloader_np_08.txt',
        base_add=6573732,
        base_literal=6575568,
        boundary='ARM.exidx end 0x006455d4 (listing bound); next ObjC IMP 0x006455d4 NPC -[npcUpdateNetDataForClient:]',
        selectors={
                 0x645548: (15200544, 'dynamicObjectNetData'),
                 0x64556c: (15200528, 'isEqualToString:'),
                 0x645580: (15200548, 'uniqueID'),
        },
        imports={
                 0x645568: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x64554c: (17157308, 'OBJC_IVAR_$_NPC.tamedClientID', 108),
                 0x645550: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0x645558: (17157260, 'OBJC_IVAR_$_NPC.damage', 54),
                 0x64555c: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
                 0x645560: (17157268, 'OBJC_IVAR_$_NPC.fullness', 68),
                 0x645564: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0x645570: (17157328, 'OBJC_IVAR_$_NPC.sendWasHitState', 204),
                 0x645574: (17157332, 'OBJC_IVAR_$_NPC.hitForce', 64),
                 0x64557c: (17157336, 'OBJC_IVAR_$_NPC.killBlockhead', 60),
                 0x645584: (17157288, 'OBJC_IVAR_$_NPC.tameCooldownTimer', 72),
                 0x64558c: (17157340, 'OBJC_IVAR_$_NPC.feedBlockheadUniqueIDToSend', 160),
                 0x645590: (17157344, 'OBJC_IVAR_$_NPC.setFreeBlockheadUniqueIDToSend', 168),
                 0x645598: (17157348, 'OBJC_IVAR_$_NPC.captureBlockheadUniqueIDToSend', 176),
                 0x6455a0: (17157352, 'OBJC_IVAR_$_NPC.harvestBlockheadUniqueIDToSend', 184),
                 0x6455a8: (17157356, 'OBJC_IVAR_$_NPC.harvestTypeToSend', 193),
                 0x6455b0: (17157360, 'OBJC_IVAR_$_NPC.interactionItemTypeToSend', 194),
                 0x6455c0: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0x6455c8: (17157368, 'OBJC_IVAR_$_NPC.sendSuccessfulTameState', 196),
                 0x6455cc: (17157372, 'OBJC_IVAR_$_NPC.sendSuccessfulFeedState', 200),
        },
        classes={},
        instructions=[(6573716, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6575568, 'adceq sl, r1, r8, asr 24')],
        calls=[(6573804, 'bl loc.imp.objc_msgSend_stret'), (6573840, 'bl sym.imp.memset'), (6574168, 'blx r3'), (6574364, 'bl loc.imp.objc_msgSend'), (6575204, 'bl loc.imp.objc_msgSend')],
        branches=[(6573788, 'beq', 6573812), (6573808, 'b', 6573844), (6574096, 'beq', 6574216), (6574180, 'beq', 6574200), (6574196, 'b', 6574212), (6574212, 'b', 6574216), (6574260, 'beq', 6574404), (6574504, 'beq', 6574588), (6574508, 'b', 6574512), (6574584, 'b', 6575112), (6574628, 'beq', 6574712), (6574632, 'b', 6574636), (6574708, 'b', 6575108), (6574752, 'beq', 6574896), (6574756, 'b', 6574760), (6574892, 'b', 6575104), (6574936, 'beq', 6575100), (6574940, 'b', 6574944), (6574976, 'beq', 6575100), (6575100, 'b', 6575104), (6575104, 'b', 6575108), (6575108, 'b', 6575112), (6575164, 'beq', 6575220), (6575264, 'beq', 6575340), (6575336, 'b', 6575424), (6575372, 'beq', 6575420), (6575420, 'b', 6575424)],
        semantics=('[NPC -[npcCreationNetDataForClient:]] (imp 0x00644e94, 464w): the creation net record - tamedClientID/dead/damage/breed/fullness/age/hitForce/killBlockhead + the pending-action uniqueID slots (feed/setFree/capture/harvest/milk/shave ... UniqueIDToSend) into the 0x18 record + dynamicObjectNetData.\n'),
    ),
    dict(
        name='np_09',
        method='NPC -[successfulTame]',
        types='v8@0:4',
        start=6598016,
        end=6599576,
        disasm='disasm_worldtileloader_np_09.txt',
        base_add=6598032,
        base_literal=6599568,
        boundary='ARM.exidx end 0x0064b398 (listing bound); next ObjC IMP 0x0064b398 NPC -[feedByBlockhead:]',
        selectors={
                 0x64b35c: (15200840, 'instance'),
                 0x64b360: (15200844, 'multiSoundNamed:'),
                 0x64b36c: (15200848, 'playAtPosition:afterDelay:'),
                 0x64b378: (15200852, 'generateNewName'),
                 0x64b38c: (15200856, 'addParticleAtPos:velocity:color:gravityType:life:scale:center:'),
        },
        imports={
                 0x64b364: (16254696, '__CFConstantStringClassReference'),
                 0x64b374: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x64b350: (17157304, 'OBJC_IVAR_$_NPC.name', 92),
                 0x64b368: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x64b370: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
        },
        classes={
                 0x64b354: (15245904, 'OBJC_CLASS_$_MJSoundManager'),
                 0x64b380: (15245908, 'OBJC_CLASS_$_ParticleEmitter'),
        },
        instructions=[(6598016, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6599572, 'andeq r0, r0, r0')],
        calls=[(6598100, 'bl loc.imp.objc_msgSend'), (6598124, 'bl loc.imp.objc_msgSend'), (6598204, 'bl loc.imp.objc_msgSend'), (6598316, 'blx r2'), (6598344, 'bl method.Vector2.operator_float__'), (6598380, 'bl method.Vector2.operator_float__'), (6598432, 'bl method.Vector.Vector_float__float__float_'), (6598464, 'bl 0x6445d8'), (6598512, 'bl method.Vector.Vector__'), (6598620, 'bl method.Vector.Vector_float__float__float__float_'), (6598752, 'bl method.Vector.Vector_float__float__float__float_'), (6598824, 'bl loc.imp.objc_msgSend'), (6598832, 'bl 0x6445d8'), (6598872, 'bl 0x6445d8'), (6598920, 'bl method.Vector.Vector_float__float__float_'), (6598960, 'bl method.Vector.operator_Vector_'), (6598964, 'bl 0x6445d8'), (6599000, 'bl 0x6445d8'), (6599052, 'bl method.Vector.Vector_float__float__float_'), (6599088, 'bl 0x6445d8'), (6599132, 'bl 0x6445d8'), (6599428, 'bl loc.imp.objc_msgSend')],
        branches=[(6598236, 'bne', 6598320), (6598272, 'bne', 6598320), (6598460, 'bge', 6599448), (6598528, 'bge', 6598664), (6598660, 'b', 6598792), (6599444, 'b', 6598452)],
        semantics=('[NPC -[successfulTame]] (imp 0x0064ad80, 390w): the tame-success celebration - generateNewName + MJSoundManager playAtPosition + ParticleEmitter addParticleAtPos:velocity:color:gravityType:life:scale:center: (the hearts) + float expressions; helper 0x6445d8 x7.\n'),
    ),
    dict(
        name='np_10',
        method='NPC -[hitWithForce:blockhead:]',
        types='v16@0:4i8@12',
        start=6592660,
        end=6594080,
        disasm='disasm_worldtileloader_np_10.txt',
        base_add=6592676,
        base_literal=6594076,
        boundary='ARM.exidx end 0x00649e20 (listing bound); next ObjC IMP 0x00649e20 NPC -[willDieIfHitByForce:]',
        selectors={
                 0x649dac: (15200692, 'isClient'),
                 0x649db8: (15200660, 'maxHealth'),
                 0x649dbc: (15200784, 'clientID'),
                 0x649dc8: (15200792, 'init'),
                 0x649dcc: (15200788, 'alloc'),
                 0x649dd4: (15200560, 'setObject:forKey:'),
                 0x649dd8: (15200800, 'numberWithInteger:'),
                 0x649de0: (15200796, 'integerValue'),
                 0x649de4: (15200468, 'objectForKey:'),
                 0x649de8: (15200668, 'die:'),
                 0x649df4: (15200776, 'objectType'),
                 0x649df8: (15200780, 'dynamicWorldChangedAtPos:objectType:'),
                 0x649e00: (15200488, 'retain'),
                 0x649e04: (15200620, 'release'),
                 0x649e18: (15200700, 'reactToBeingHit'),
        },
        imports={
                 0x649da8: (17151904, 'objc_msgSend'),
                 0x649dc0: (16254552, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x649db0: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x649db4: (17157260, 'OBJC_IVAR_$_NPC.damage', 54),
                 0x649dc4: (17157300, 'OBJC_IVAR_$_NPC.tameCountsByClientID', 104),
                 0x649df0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x649dfc: (17157336, 'OBJC_IVAR_$_NPC.killBlockhead', 60),
                 0x649e08: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x649e0c: (17157388, 'OBJC_IVAR_$_DynamicObject.creationDataNeedsToBeSent', 50),
                 0x649e10: (17157332, 'OBJC_IVAR_$_NPC.hitForce', 64),
                 0x649e14: (17157328, 'OBJC_IVAR_$_NPC.sendWasHitState', 204),
        },
        classes={
                 0x649dd0: (15245880, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x649ddc: (15245896, 'OBJC_CLASS_$_NSNumber'),
        },
        instructions=[(6592660, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6594076, 'adceq r6, r1, r8, asr 4')],
        calls=[(6592780, 'blx lr'), (6592912, 'blx r2'), (6592932, 'blx r2'), (6593028, 'blx r2'), (6593096, 'blx r3'), (6593172, 'blx r3'), (6593320, 'blx r2'), (6593336, 'blx r2'), (6593520, 'blx sl'), (6593536, 'blx r2'), (6593612, 'blx r3'), (6593660, 'blx ip'), (6593748, 'bl loc.imp.objc_msgSend'), (6593784, 'bl loc.imp.objc_msgSend'), (6593948, 'blx r2')],
        branches=[(6592792, 'beq', 6592960), (6592832, 'beq', 6592956), (6592956, 'b', 6593788), (6593044, 'blt', 6593104), (6593100, 'b', 6593668), (6593116, 'beq', 6593664), (6593192, 'bne', 6593212), (6593248, 'bne', 6593360), (6593664, 'b', 6593668), (6593904, 'bne', 6593952)],
        semantics=('[NPC -[hitWithForce:blockhead:]] (imp 0x00649894, 355w): the damage application - maxHealth gate, tameCountsByClientID update (NSMutableDictionary/numberWithInteger:), killBlockhead, die: trigger, reactToBeingHit and the net dirty flags.\n'),
    ),
    dict(
        name='np_11',
        method='NPC -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:]',
        types='@44@0:4@8@12{?=ii}16@24@28c32c36@40',
        start=6571800,
        end=6572836,
        disasm='disasm_worldtileloader_np_11.txt',
        base_add=6571816,
        base_literal=6572832,
        boundary='ARM.exidx end 0x00644b24 (listing bound); next ObjC IMP 0x00644b24 NPC -[initWithWorld:dynamicWorld:saveDict:cache:]',
        selectors={
                 0x644ae0: (15200504, 'initWithWorld:dynamicWorld:atPosition:cache:'),
                 0x644aec: (15200512, 'setBabyCreationStartValues'),
                 0x644af0: (15200508, 'setAdultCreationStartValues'),
                 0x644af4: (15200516, 'loadValuesFromSaveDict:'),
                 0x644afc: (15200520, 'isServer'),
                 0x644b04: (15200528, 'isEqualToString:'),
                 0x644b08: (15200524, 'localNetID'),
                 0x644b10: (15200488, 'retain'),
                 0x644b14: (15200492, 'autorelease'),
        },
        imports={
                 0x644ae8: (17151904, 'objc_msgSend'),
                 0x644b0c: (16254552, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x644ae4: (17157312, 'OBJC_IVAR_$_NPC.savedBlockheadIndex', 136),
                 0x644af8: (17157308, 'OBJC_IVAR_$_NPC.tamedClientID', 108),
                 0x644b00: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x644b18: (17157316, 'OBJC_IVAR_$_NPC.randomHarmFromHungerTimer', 144),
        },
        classes={
                 0x644ad8: (15252612, 'OBJC_CLASS_$_NPC'),
        },
        instructions=[(6571800, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6572832, 'adceq fp, r1, r4, asr 7')],
        calls=[(6572008, 'bl loc.imp.objc_msgSendSuper2'), (6572136, 'blx r2'), (6572184, 'blx r2'), (6572252, 'blx r3'), (6572384, 'blx r2'), (6572480, 'blx ip'), (6572500, 'blx r3'), (6572604, 'blx r2'), (6572636, 'blx r3'), (6572660, 'bl 0x6445d8')],
        branches=[(6572036, 'bne', 6572052), (6572048, 'b', 6572748), (6572092, 'beq', 6572144), (6572140, 'b', 6572188), (6572200, 'beq', 6572256), (6572264, 'beq', 6572660), (6572304, 'beq', 6572660), (6572320, 'beq', 6572660), (6572396, 'beq', 6572532), (6572512, 'beq', 6572532)],
        semantics=('[NPC -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:]] (imp 0x00644718, 259w): the placement ctor - setBaby/setAdultCreationStartValues + loadValuesFromSaveDict: + savedBlockheadIndex/tamedClientID restore (super to DynamicObject); 0x14 (20).\n'),
    ),
    dict(
        name='np_12',
        method='NPC -[blockheadsLoaded]',
        types='v8@0:4',
        start=6618464,
        end=6619328,
        disasm='disasm_worldtileloader_np_12.txt',
        base_add=6618480,
        base_literal=6619324,
        boundary='ARM.exidx end 0x006500c0 (listing bound); next ObjC IMP 0x006500c0 NPC -[riderPosForBlockhead:]',
        selectors={
                 0x65008c: (15200608, 'blockheads'),
                 0x650094: (15200632, 'count'),
                 0x65009c: (15200488, 'retain'),
                 0x6500a0: (15200912, 'objectAtIndex:'),
                 0x6500a4: (15200492, 'autorelease'),
                 0x6500a8: (15200936, 'isClientBlockheadBeingControlledByServer'),
                 0x6500b0: (15200940, 'setRidingObject:'),
                 0x6500b4: (15200728, 'removeRider:'),
                 0x6500b8: (15200724, 'stopRiding'),
        },
        imports={
                 0x650088: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x650084: (17157312, 'OBJC_IVAR_$_NPC.savedBlockheadIndex', 136),
                 0x650090: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x650098: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0x6500ac: (17157392, 'OBJC_IVAR_$_NPC.beingControlled', 128),
        },
        classes={},
        instructions=[(6618464, 'push {r4, r5, r6, r7, fp, lr}'), (6619324, 'adceq pc, r0, ip, ror sp')],
        calls=[(6618592, 'blx r2'), (6618696, 'blx r2'), (6618816, 'blx r3'), (6618868, 'blx lr'), (6618884, 'blx r2'), (6618996, 'blx r2'), (6619096, 'blx lr'), (6619136, 'blx r3'), (6619228, 'blx r3')],
        branches=[(6618524, 'beq', 6619260), (6618624, 'blt', 6618908), (6618708, 'bhs', 6618908), (6619008, 'beq', 6619144), (6619140, 'b', 6619256), (6619256, 'b', 6619260)],
        semantics=('[NPC -[blockheadsLoaded]] (imp 0x0064fd60, 216w): reattaches the saved rider by blockhead index (blockheads objectAtIndex: + setRidingObject:) and clears riding state for controlled-server blockheads.\n'),
    ),
    dict(
        name='np_13',
        method='NPC -[setFreeByBlockhead:]',
        types='v12@0:4@8',
        start=6615332,
        end=6616132,
        disasm='disasm_worldtileloader_np_13.txt',
        base_add=6615348,
        base_literal=6616128,
        boundary='ARM.exidx end 0x0064f444 (listing bound); next ObjC IMP 0x0064f444 NPC -[captureByBlockhead:withItemType:]',
        selectors={
                 0x64f404: (15200816, 'belongsToPlayerWithBlockhead:'),
                 0x64f40c: (15200492, 'autorelease'),
                 0x64f418: (15200648, 'hitWithForce:blockhead:'),
                 0x64f42c: (15200776, 'objectType'),
                 0x64f430: (15200780, 'dynamicWorldChangedAtPos:objectType:'),
                 0x64f434: (15200548, 'uniqueID'),
        },
        imports={
                 0x64f400: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x64f3fc: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x64f408: (17157412, 'OBJC_IVAR_$_NPC.nameTextView', 120),
                 0x64f410: (17157304, 'OBJC_IVAR_$_NPC.name', 92),
                 0x64f414: (17157388, 'OBJC_IVAR_$_DynamicObject.creationDataNeedsToBeSent', 50),
                 0x64f420: (17157308, 'OBJC_IVAR_$_NPC.tamedClientID', 108),
                 0x64f424: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x64f428: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x64f43c: (17157344, 'OBJC_IVAR_$_NPC.setFreeBlockheadUniqueIDToSend', 168),
        },
        classes={},
        instructions=[(6615332, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6616128, 'invalid')],
        calls=[(6615456, 'bl loc.imp.objc_msgSend'), (6615564, 'blx r3'), (6615704, 'bl loc.imp.objc_msgSend'), (6615748, 'bl loc.imp.objc_msgSend'), (6615852, 'bl loc.imp.objc_msgSend'), (6615888, 'bl loc.imp.objc_msgSend'), (6615948, 'blx lr'), (6616020, 'blx r4')],
        branches=[(6615396, 'beq', 6615516), (6615512, 'b', 6616052), (6615576, 'beq', 6616052)],
        semantics=('[NPC -[setFreeByBlockhead:]] (imp 0x0064f124, 200w): the free-the-NPC action - belongsToPlayerWithBlockhead: gate + hitWithForce knockback + the setFreeBlockheadUniqueIDToSend net slot.\n'),
    ),
    dict(
        name='np_14',
        method='NPC -[generateNewName]',
        types='v8@0:4',
        start=6597112,
        end=6597880,
        disasm='disasm_worldtileloader_np_14.txt',
        base_add=6597128,
        base_literal=6597876,
        boundary='ARM.exidx end 0x0064acf8 (listing bound); next ObjC IMP 0x0064acf8 NPC -[getNamesArray]',
        selectors={
                 0x64acb8: (15200832, 'getNamesArrayCount'),
                 0x64acbc: (15200828, 'getNamesArray'),
                 0x64acd4: (15200836, 'uppercaseString'),
                 0x64acdc: (15200488, 'retain'),
                 0x64acec: (15200776, 'objectType'),
                 0x64acf0: (15200780, 'dynamicWorldChangedAtPos:objectType:'),
        },
        imports={
                 0x64acb4: (17151904, 'objc_msgSend'),
                 0x64acc0: (16254680, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x64acd0: (17157388, 'OBJC_IVAR_$_DynamicObject.creationDataNeedsToBeSent', 50),
                 0x64ace0: (17157304, 'OBJC_IVAR_$_NPC.name', 92),
                 0x64ace4: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x64ace8: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={},
        instructions=[(6597112, 'push {r4, sl, fp, lr}'), (6597876, 'adceq r5, r1, r4, ror 1')],
        calls=[(6597152, 'bl 0x6445d8'), (6597176, 'bl 0x6445d8'), (6597400, 'blx lr'), (6597424, 'blx r2'), (6597500, 'bl sym.imp.__modsi3'), (6597612, 'bl loc.imp.objc_msgSend'), (6597628, 'bl loc.imp.objc_msgSend'), (6597724, 'bl loc.imp.objc_msgSend'), (6597760, 'bl loc.imp.objc_msgSend')],
        branches=[(6597212, 'ble', 6597328), (6597324, 'b', 6597556), (6597444, 'beq', 6597536), (6597456, 'ble', 6597536), (6597532, 'b', 6597552), (6597552, 'b', 6597556)],
        semantics=('[NPC -[generateNewName]] (imp 0x0064a9f8, 192w): the name picker - getNamesArrayCount/getNamesArray + __modsi3 + uppercaseString.\n'),
    ),
    dict(
        name='np_15',
        method='NPC -[addRider:]',
        types='v12@0:4@8',
        start=6616776,
        end=6617504,
        disasm='disasm_worldtileloader_np_15.txt',
        base_add=6616792,
        base_literal=6617500,
        boundary='ARM.exidx end 0x0064f9a0 (listing bound); next ObjC IMP 0x0064f9a0 NPC -[removeRider:]',
        selectors={
                 0x64f964: (15200936, 'isClientBlockheadBeingControlledByServer'),
                 0x64f96c: (15200492, 'autorelease'),
                 0x64f970: (15200724, 'stopRiding'),
                 0x64f974: (15200692, 'isClient'),
                 0x64f97c: (15200488, 'retain'),
                 0x64f988: (15200776, 'objectType'),
                 0x64f98c: (15200780, 'dynamicWorldChangedAtPos:objectType:'),
                 0x64f990: (15200676, 'isNet'),
        },
        imports={
                 0x64f960: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x64f968: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0x64f978: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x64f984: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x64f994: (17157388, 'OBJC_IVAR_$_DynamicObject.creationDataNeedsToBeSent', 50),
                 0x64f998: (17157392, 'OBJC_IVAR_$_NPC.beingControlled', 128),
        },
        classes={},
        instructions=[(6616776, 'push {r4, r5, fp, lr}'), (6617500, 'adceq r0, r1, r4, lsl r4')],
        calls=[(6616836, 'blx ip'), (6616928, 'blx r3'), (6616964, 'blx r3'), (6617068, 'bl loc.imp.objc_msgSend'), (6617164, 'bl loc.imp.objc_msgSend'), (6617200, 'bl loc.imp.objc_msgSend'), (6617236, 'blx r3'), (6617312, 'blx r2')],
        branches=[(6616848, 'beq', 6617000), (6617248, 'beq', 6617328), (6617324, 'bne', 6617360)],
        semantics=('[NPC -[addRider:]] (imp 0x0064f6c8, 182w): rider attach - beingControlled flag + stopRiding on the previous rider + net dirty.\n'),
    ),
    dict(
        name='np_16',
        method='NPC -[belongsToPlayerWithBlockhead:]',
        types='c12@0:4@8',
        start=6613208,
        end=6613860,
        disasm='disasm_worldtileloader_np_16.txt',
        base_add=6613224,
        base_literal=6613856,
        boundary='ARM.exidx end 0x0064eb64 (listing bound); next ObjC IMP 0x0064eb64 NPC -[belongsToLocalPlayer]',
        selectors={
                 0x64eb4c: (15200528, 'isEqualToString:'),
                 0x64eb50: (15200784, 'clientID'),
                 0x64eb5c: (15200676, 'isNet'),
        },
        imports={
                 0x64eb48: (17151904, 'objc_msgSend'),
                 0x64eb54: (16254552, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x64eb40: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x64eb44: (17157308, 'OBJC_IVAR_$_NPC.tamedClientID', 108),
                 0x64eb58: (17157320, 'OBJC_IVAR_$_NPC.netTameType', 192),
        },
        classes={},
        instructions=[(6613208, 'push {r4, r5, fp, lr}'), (6613856, 'adceq r1, r1, r4, lsl 4')],
        calls=[(6613352, 'blx r2'), (6613548, 'blx lr'), (6613580, 'blx r3'), (6613656, 'blx r2'), (6613760, 'blx ip')],
        branches=[(6613272, 'beq', 6613400), (6613308, 'bne', 6613388), (6613384, 'b', 6613812), (6613396, 'b', 6613812), (6613444, 'beq', 6613800), (6613600, 'bne', 6613792), (6613676, 'bne', 6613784)],
        semantics=('[NPC -[belongsToPlayerWithBlockhead:]] (imp 0x0064e8d8, 163w): the ownership check - tamedClientID vs clientID (netTameType aware).\n'),
    ),
    dict(
        name='np_17',
        method='NPC -[captureByBlockhead:withItemType:]',
        types='c16@0:4@8i12',
        start=6616132,
        end=6616776,
        disasm='disasm_worldtileloader_np_17.txt',
        base_add=6616148,
        base_literal=6616772,
        boundary='ARM.exidx end 0x0064f6c8 (listing bound); next ObjC IMP 0x0064f6c8 NPC -[addRider:]',
        selectors={
                 0x64f68c: (15200920, 'canBeCapturedByBlockhead:withItemType:'),
                 0x64f694: (15200932, 'setNeedsRemoved:'),
                 0x64f6a4: (15200924, 'capturedItemType'),
                 0x64f6a8: (15200588, 'getSaveDict'),
                 0x64f6ac: (15200928, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
                 0x64f6b8: (15200548, 'uniqueID'),
        },
        imports={
                 0x64f688: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x64f690: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x64f698: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x64f6a0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x64f6b0: (17157388, 'OBJC_IVAR_$_DynamicObject.creationDataNeedsToBeSent', 50),
                 0x64f6b4: (17157360, 'OBJC_IVAR_$_NPC.interactionItemTypeToSend', 194),
                 0x64f6c0: (17157348, 'OBJC_IVAR_$_NPC.captureBlockheadUniqueIDToSend', 176),
        },
        classes={},
        instructions=[(6616132, 'push {r4, r5, fp, lr}'), (6616772, 'umlaleq r0, r1, r8, r6')],
        calls=[(6616204, 'blx lr'), (6616336, 'bl loc.imp.objc_msgSend'), (6616544, 'bl loc.imp.objc_msgSend'), (6616576, 'bl loc.imp.objc_msgSend'), (6616660, 'bl loc.imp.objc_msgSend'), (6616688, 'blx r3')],
        branches=[(6616216, 'bne', 6616232), (6616228, 'b', 6616700), (6616264, 'beq', 6616424), (6616420, 'b', 6616700)],
        semantics=('[NPC -[captureByBlockhead:withItemType:]] (imp 0x0064f444, 161w): the capture action - canBeCapturedByBlockhead:withItemType: gate + createFreeBlockAtPosition:... (spawn the captured item) + capturedItemType + setNeedsRemoved: + captureBlockheadUniqueIDToSend.\n'),
    ),
    dict(
        name='np_18',
        method='NPC -[removeRider:]',
        types='v12@0:4@8',
        start=6617504,
        end=6618096,
        disasm='disasm_worldtileloader_np_18.txt',
        base_add=6617520,
        base_literal=6618092,
        boundary='ARM.exidx end 0x0064fbf0 (listing bound); next ObjC IMP 0x0064fbf0 NPC -[swipeUpGesture]',
        selectors={
                 0x64fbc4: (15200692, 'isClient'),
                 0x64fbd4: (15200776, 'objectType'),
                 0x64fbd8: (15200780, 'dynamicWorldChangedAtPos:objectType:'),
                 0x64fbdc: (15200676, 'isNet'),
                 0x64fbe8: (15200492, 'autorelease'),
        },
        imports={
                 0x64fbc0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x64fbbc: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0x64fbc8: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x64fbd0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x64fbe0: (17157388, 'OBJC_IVAR_$_DynamicObject.creationDataNeedsToBeSent', 50),
                 0x64fbe4: (17157392, 'OBJC_IVAR_$_NPC.beingControlled', 128),
        },
        classes={},
        instructions=[(6617504, 'push {r4, r5, r6, sl, fp, lr}'), (6618092, 'adceq r0, r1, ip, lsr r1')],
        calls=[(6617696, 'bl loc.imp.objc_msgSend'), (6617732, 'bl loc.imp.objc_msgSend'), (6617768, 'blx r3'), (6617844, 'blx r2'), (6617980, 'blx lr')],
        branches=[(6617572, 'bne', 6618036), (6617780, 'beq', 6617860), (6617856, 'bne', 6617892)],
        semantics=('[NPC -[removeRider:]] (imp 0x0064f9a0, 148w): rider detach - beingControlled clear + net dirty.\n'),
    ),
    dict(
        name='np_19',
        method='NPC -[belongsToLocalPlayer]',
        types='c8@0:4',
        start=6613860,
        end=6614428,
        disasm='disasm_worldtileloader_np_19.txt',
        base_add=6613876,
        base_literal=6614424,
        boundary='ARM.exidx end 0x0064ed9c (listing bound); next ObjC IMP 0x0064ed9c NPC -[beginBlockheadInspection:]',
        selectors={
                 0x64ed84: (15200528, 'isEqualToString:'),
                 0x64ed88: (15200524, 'localNetID'),
                 0x64ed90: (15200692, 'isClient'),
        },
        imports={
                 0x64ed7c: (16254552, '__CFConstantStringClassReference'),
                 0x64ed80: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x64ed74: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x64ed78: (17157308, 'OBJC_IVAR_$_NPC.tamedClientID', 108),
                 0x64ed8c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x64ed94: (17157320, 'OBJC_IVAR_$_NPC.netTameType', 192),
        },
        classes={},
        instructions=[(6613860, 'push {r4, r5, fp, lr}'), (6614424, 'adceq r0, r1, r8, ror pc')],
        calls=[(6614104, 'blx ip'), (6614180, 'blx r2'), (6614324, 'blx ip'), (6614356, 'blx r3')],
        branches=[(6613920, 'beq', 6613984), (6613956, 'bne', 6613972), (6613968, 'b', 6614376), (6613980, 'b', 6614376), (6614020, 'beq', 6614368), (6614116, 'beq', 6614216), (6614212, 'b', 6614376), (6614364, 'b', 6614376)],
        semantics=('[NPC -[belongsToLocalPlayer]] (imp 0x0064eb64, 142w): the local-ownership check - tamedClientID vs localNetID.\n'),
    ),
    dict(
        name='np_20',
        method='NPC -[appendNPCCreationDataToData:]',
        types='@12@0:4@8',
        start=6575740,
        end=6576284,
        disasm='disasm_worldtileloader_np_20.txt',
        base_add=6575756,
        base_literal=6576280,
        boundary='ARM.exidx end 0x0064589c (listing bound); next ObjC IMP 0x0064589c NPC -[creationNetDataForClient:]',
        selectors={
                 0x645874: (15200556, 'dictionary'),
                 0x64587c: (15200552, 'dataWithData:'),
                 0x645888: (15200560, 'setObject:forKey:'),
                 0x64588c: (15200568, 'appendData:'),
                 0x645890: (15200564, 'dataWithPropertyList:format:options:error:'),
        },
        imports={
                 0x645870: (17151904, 'objc_msgSend'),
                 0x645884: (16254504, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x64586c: (17157304, 'OBJC_IVAR_$_NPC.name', 92),
        },
        classes={
                 0x645878: (15245880, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x645880: (15245884, 'OBJC_CLASS_$_NSMutableData'),
                 0x645894: (15245888, 'OBJC_CLASS_$_NSPropertyListSerialization'),
        },
        instructions=[(6575740, 'push {r4, r5, r6, sl, fp, lr}'), (6576280, 'adceq sl, r1, r0, ror 8')],
        calls=[(6575912, 'blx r3'), (6575948, 'blx r3'), (6576072, 'blx ip'), (6576172, 'blx ip'), (6576200, 'blx r3')],
        branches=[(6575808, 'beq', 6576216), (6575984, 'beq', 6576076), (6576212, 'b', 6576224)],
        semantics=('[NPC -[appendNPCCreationDataToData:]] (imp 0x0064567c, 136w): the creation-data append - NSPropertyListSerialization dataWithPropertyList: (name dict) + appendData:.\n'),
    ),
    dict(
        name='np_21',
        method='NPC -[blockheadUnloaded:]',
        types='v12@0:4@8',
        start=6594540,
        end=6595080,
        disasm='disasm_worldtileloader_np_21.txt',
        base_add=6594556,
        base_literal=6595076,
        boundary='ARM.exidx end 0x0064a208 (listing bound); next ObjC IMP 0x0064a208 NPC -[inspectionStopped]',
        selectors={
                 0x64a1ec: (15200620, 'release'),
                 0x64a200: (15200492, 'autorelease'),
        },
        imports={
                 0x64a1e8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x64a1e4: (17157336, 'OBJC_IVAR_$_NPC.killBlockhead', 60),
                 0x64a1f0: (17157404, 'OBJC_IVAR_$_NPC.inspectingBlockhead', 116),
                 0x64a1f4: (17157408, 'OBJC_IVAR_$_NPC.comingToInspectBlockhead', 112),
                 0x64a1f8: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0x64a1fc: (17157392, 'OBJC_IVAR_$_NPC.beingControlled', 128),
        },
        classes={},
        instructions=[(6594540, 'push {r4, r5, r6, sl, fp, lr}'), (6595076, 'invalid')],
        calls=[(6594680, 'blx r3'), (6594980, 'blx lr')],
        branches=[(6594608, 'bne', 6594708), (6594744, 'bne', 6594780), (6594816, 'bne', 6594852), (6594888, 'bne', 6595036)],
        semantics=('[NPC -[blockheadUnloaded:]] (imp 0x00649fec, 135w): the blockhead-unload cleanup - releases killBlockhead/inspectingBlockhead/comingToInspectBlockhead/rider/beingControlled.\n'),
    ),
    dict(
        name='np_22',
        method='NPC -[changeName:]',
        types='v12@0:4@8',
        start=6612484,
        end=6613020,
        disasm='disasm_worldtileloader_np_22.txt',
        base_add=6612500,
        base_literal=6613016,
        boundary='ARM.exidx end 0x0064e81c (listing bound); next ObjC IMP 0x0064e81c NPC -[tamed]',
        selectors={
                 0x64e7ec: (15200752, 'length'),
                 0x64e7f4: (15200492, 'autorelease'),
                 0x64e800: (15200488, 'retain'),
                 0x64e810: (15200776, 'objectType'),
                 0x64e814: (15200780, 'dynamicWorldChangedAtPos:objectType:'),
        },
        imports={
                 0x64e7e8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x64e7f0: (17157412, 'OBJC_IVAR_$_NPC.nameTextView', 120),
                 0x64e7f8: (17157304, 'OBJC_IVAR_$_NPC.name', 92),
                 0x64e804: (17157388, 'OBJC_IVAR_$_DynamicObject.creationDataNeedsToBeSent', 50),
                 0x64e808: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x64e80c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={},
        instructions=[(6612484, 'push {r4, r5, r6, sl, fp, lr}'), (6613016, 'invalid')],
        calls=[(6612544, 'blx ip'), (6612596, 'blx r2'), (6612708, 'bl loc.imp.objc_msgSend'), (6612740, 'bl loc.imp.objc_msgSend'), (6612856, 'bl loc.imp.objc_msgSend'), (6612892, 'bl loc.imp.objc_msgSend'), (6612928, 'blx r3')],
        branches=[(6612552, 'bls', 6612960), (6612604, 'bhs', 6612960)],
        semantics=('[NPC -[changeName:]] (imp 0x0064e604, 134w): the rename - name set + net dirty (creationDataNeedsToBeSent).\n'),
    ),
    dict(
        name='np_23',
        method='NPC -[die:]',
        types='v12@0:4@8',
        start=6592112,
        end=6592640,
        disasm='disasm_worldtileloader_np_23.txt',
        base_add=6592128,
        base_literal=6592636,
        boundary='ARM.exidx end 0x00649880 (listing bound); next ObjC IMP 0x00649880 NPC -[reactToBeingHit]',
        selectors={
                 0x649854: (15200488, 'retain'),
                 0x649858: (15200620, 'release'),
                 0x649868: (15200724, 'stopRiding'),
                 0x649874: (15200776, 'objectType'),
                 0x649878: (15200780, 'dynamicWorldChangedAtPos:objectType:'),
        },
        imports={
                 0x649850: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x649848: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0x64984c: (17157336, 'OBJC_IVAR_$_NPC.killBlockhead', 60),
                 0x64985c: (17157388, 'OBJC_IVAR_$_DynamicObject.creationDataNeedsToBeSent', 50),
                 0x649864: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0x64986c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x649870: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={},
        instructions=[(6592112, 'push {r4, r5, fp, lr}'), (6592636, 'adceq r6, r1, ip, ror 8')],
        calls=[(6592296, 'blx r2'), (6592316, 'blx r2'), (6592436, 'bl loc.imp.objc_msgSend'), (6592512, 'bl loc.imp.objc_msgSend'), (6592548, 'bl loc.imp.objc_msgSend')],
        branches=[(6592176, 'bne', 6592576), (6592216, 'beq', 6592340)],
        semantics=('[NPC -[die:]] (imp 0x00649670, 132w): the death routine - dead flag + stopRiding + killBlockhead + net dirty.\n'),
    ),
    dict(
        name='np_24',
        method='NPC -[mateWithNPC:]',
        types='c12@0:4@8',
        start=6614816,
        end=6615332,
        disasm='disasm_worldtileloader_np_24.txt',
        base_add=6614832,
        base_literal=6615328,
        boundary='ARM.exidx end 0x0064f124 (listing bound); next ObjC IMP 0x0064f124 NPC -[setFreeByBlockhead:]',
        selectors={
                 0x64f100: (15200916, 'breed'),
                 0x64f118: (15200776, 'objectType'),
                 0x64f11c: (15200780, 'dynamicWorldChangedAtPos:objectType:'),
        },
        imports={
                 0x64f0fc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x64f0f0: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x64f0f4: (17157284, 'OBJC_IVAR_$_NPC.mateCooldownTimer', 76),
                 0x64f0f8: (17157272, 'OBJC_IVAR_$_NPC.mateBreed', 98),
                 0x64f104: (17157280, 'OBJC_IVAR_$_NPC.hasBred', 100),
                 0x64f110: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x64f114: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={},
        instructions=[(6614816, 'push {fp, lr}'), (6615328, 'invalid')],
        calls=[(6614984, 'bl 0x6445d8'), (6615128, 'bl loc.imp.objc_msgSend'), (6615164, 'bl loc.imp.objc_msgSend'), (6615208, 'blx ip')],
        branches=[(6614880, 'bne', 6615248), (6614920, 'bhi', 6615244), (6615240, 'b', 6615256), (6615244, 'b', 6615248)],
        semantics=('[NPC -[mateWithNPC:]] (imp 0x0064ef20, 129w): the breeding hook - mateBreed/hasBred/mateCooldownTimer sync + net dirty.\n'),
    ),
    dict(
        name='np_25',
        method='NPC -[initWithWorld:dynamicWorld:cache:netData:]',
        types='@24@0:4@8@12@16@20',
        start=6573216,
        end=6573716,
        disasm='disasm_worldtileloader_np_25.txt',
        base_add=6573232,
        base_literal=6573712,
        boundary='ARM.exidx end 0x00644e94 (listing bound); next ObjC IMP 0x00644e94 NPC -[npcCreationNetDataForClient:]',
        selectors={
                 0x644e6c: (15200536, 'initWithWorld:dynamicWorld:cache:netData:'),
                 0x644e8c: (15200540, 'getBytes:length:'),
        },
        imports={
                 0x644e68: (17151900, 'objc_msgSendSuper2'),
                 0x644e88: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x644e74: (17157288, 'OBJC_IVAR_$_NPC.tameCooldownTimer', 72),
                 0x644e78: (17157320, 'OBJC_IVAR_$_NPC.netTameType', 192),
                 0x644e7c: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
                 0x644e80: (17157260, 'OBJC_IVAR_$_NPC.damage', 54),
                 0x644e84: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
        },
        classes={
                 0x644e70: (15252612, 'OBJC_CLASS_$_NPC'),
        },
        instructions=[(6573216, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6573712, 'adceq sl, r1, ip, lsr lr')],
        calls=[(6573368, 'blx r6'), (6573520, 'blx r5')],
        branches=[(6573396, 'bne', 6573412), (6573408, 'b', 6573660)],
        semantics=('[NPC -[initWithWorld:dynamicWorld:cache:netData:]] (imp 0x00644ca0, 125w): the net ctor - getBytes:length: decode of the 0x48-byte record into tameCooldownTimer/netTameType/breed/damage/dead.\n'),
    ),
    dict(
        name='np_26',
        method='NPC -[canBeFedByBlockhead:]',
        types='c12@0:4@8',
        start=6595312,
        end=6595740,
        disasm='disasm_worldtileloader_np_26.txt',
        base_add=6595328,
        base_literal=6595736,
        boundary='ARM.exidx end 0x0064a49c (listing bound); next ObjC IMP 0x0064a49c NPC -[cantBeFedTipStringForBlockhead:]',
        selectors={
                 0x64a484: (15200656, 'diesOfLowFullness'),
                 0x64a490: (15200680, 'tamed'),
        },
        imports={
                 0x64a480: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x64a488: (17157260, 'OBJC_IVAR_$_NPC.damage', 54),
                 0x64a48c: (17157288, 'OBJC_IVAR_$_NPC.tameCooldownTimer', 72),
                 0x64a494: (17157268, 'OBJC_IVAR_$_NPC.fullness', 68),
        },
        classes={},
        instructions=[(6595312, 'push {fp, lr}'), (6595736, 'adceq r5, r1, ip, ror 15')],
        calls=[(6595372, 'blx ip'), (6595520, 'blx r2')],
        branches=[(6595384, 'bne', 6595572), (6595428, 'bgt', 6595556), (6595476, 'bhi', 6595548), (6595568, 'b', 6595692), (6595632, 'bmi', 6595680)],
        semantics=('[NPC -[canBeFedByBlockhead:]] (imp 0x0064a2f0, 107w): the feeding gate - diesOfLowFullness + tamed + fullness/damage/tameCooldownTimer checks; 0x1518.\n'),
    ),
    dict(
        name='np_27',
        method='NPC -[dealloc]',
        types='v8@0:4',
        start=6580024,
        end=6580432,
        disasm='disasm_worldtileloader_np_27.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x006468d0 (listing bound); next ObjC IMP 0x006468d0 NPC -[update:accurateDT:isSimulation:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6580024, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6580428, 'andeq r0, r0, r0')],
        calls=[(6580212, 'blx r5'), (6580260, 'blx ip'), (6580296, 'blx r3'), (6580332, 'blx r3'), (6580372, 'blx r2')],
        branches=[],
        semantics=('[NPC -[dealloc]] (imp 0x00646738, 102w): dealloc - releases.\n'),
    ),
    dict(
        name='np_28',
        method='NPC -[setAdultCreationStartValues]',
        types='v8@0:4',
        start=6571148,
        end=6571496,
        disasm='disasm_worldtileloader_np_28.txt',
        base_add=6571164,
        base_literal=6571476,
        boundary='ARM.exidx end 0x00644704; body trimmed at the next IMP 0x006445e8 NPC -[setBabyCreationStartValues]',
        selectors={
                 0x6445d0: (15200500, 'maxAge'),
        },
        imports={
                 0x6445cc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x6445b8: (17157292, 'OBJC_IVAR_$_NPC.layCooldownTimer', 84),
                 0x6445c4: (17157268, 'OBJC_IVAR_$_NPC.fullness', 68),
                 0x6445c8: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
        },
        classes={},
        instructions=[(6571148, 'push {fp, lr}'), (6571492, 'pop {fp, pc}')],
        calls=[(6571180, 'bl 0x6445d8'), (6571256, 'blx r3'), (6571308, 'bl 0x6445d8'), (6571376, 'bl 0x6445d8'), (6571488, 'bl sym.imp.lrand48')],
        branches=[],
        semantics=('[NPC -[setAdultCreationStartValues]] (imp 0x0064448c, 87w): the adult seed - age/fullness/layCooldownTimer + lrand48; 0x384 (900).\n'),
    ),
    dict(
        name='np_29',
        method='NPC -[creationNetDataForClient:]',
        types='@12@0:4@8',
        start=6576284,
        end=6576576,
        disasm='disasm_worldtileloader_np_29.txt',
        base_add=6576300,
        base_literal=6576572,
        boundary='ARM.exidx end 0x006459c0 (listing bound); next ObjC IMP 0x006459c0 NPC -[updateNetDataForClient:]',
        selectors={
                 0x6459a8: (15200572, 'npcCreationNetDataForClient:'),
                 0x6459b0: (15200580, 'appendNPCCreationDataToData:'),
                 0x6459b4: (15200576, 'dataWithBytes:length:'),
        },
        imports={
                 0x6459ac: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0x6459b8: (15245892, 'OBJC_CLASS_$_NSData'),
        },
        instructions=[(6576284, 'push {r4, r5, fp, lr}'), (6576572, 'adceq sl, r1, r0, asr 4')],
        calls=[(6576380, 'bl loc.imp.objc_msgSend_stret'), (6576416, 'bl sym.imp.memset'), (6576504, 'blx ip'), (6576532, 'blx r3')],
        branches=[(6576360, 'beq', 6576388), (6576384, 'b', 6576420)],
        semantics=('[NPC -[creationNetDataForClient:]] (imp 0x0064589c, 73w): creationNetDataForClient: - appends npcCreationNetDataForClient: + appendNPCCreationDataToData: into the 0x48-byte record.\n'),
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
        'batch': 'NPC core (E117): the name-tag/net/tick giants and the interaction family; 30 bodies',
        'claim': ('the NPC operational core; the three giants are census-grade and the NSPropertyListSerialization/MJTextView/ParticleEmitter contracts are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'npc_core.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale npc_core.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
