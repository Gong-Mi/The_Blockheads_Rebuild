#!/usr/bin/env python3
"""Hash-gated recovery of the Boat (E148).

Boat lands: the batch sweeps boat surface:
35 bodies, 9565 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/BOAT.md for the prose and boundaries.
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
    'bl 0x96be18': 0x0096be18,
    'bl 0x96c994': 0x0096c994,
    'bl 0x975cb4': 0x00975cb4,
    'bl 0x975d28': 0x00975d28,
    'bl 0x9760c0': 0x009760c0,
    'bl 0x976458': 0x00976458,
    'bl 0x976a18': 0x00976a18,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector.operator_float__': 0x004b5c08,
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl method.Vector2.operator_Vector2_': 0x004d0418,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__wrap_glBindTexture': 0x001c2ad4,
    'bl sym.imp.__wrap_glDisableVertexAttribArray': 0x001c3d58,
    'bl sym.imp.__wrap_glEnableVertexAttribArray': 0x001c2d5c,
    'bl sym.imp.__wrap_glUniform1i': 0x001c2de0,
    'bl sym.imp.__wrap_glUniform4f': 0x001c3d64,
    'bl sym.imp.__wrap_glUniformMatrix4fv': 0x001c2dd4,
    'bl sym.imp.__wrap_glUseProgram': 0x001c2d38,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.tileAtWorldPosition_int__int__MacroTile__World_': 0x00a16e68,
}

SPECS = [
    dict(
        name='bo_00',
        method='Boat -[.cxx_construct]',
        types='@8@0:4',
        start=9928492,
        end=9928516,
        disasm='disasm_worldtileloader_bo_00.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00977f44 (listing bound); next ObjC IMP 0x009783b0 BlockheadPreviewView -[updateClothingCubes]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9928492, 'sub sp, sp, 8'), (9928512, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Boat -[.cxx_construct]] (imp 0x00977f2c, 6w): -[.cxx_construct] (0x977f2c, 6w, trimmed at next IMP 0x9783b0 BlockheadPreviewView -[updateClothingCubes]): no-op -- stores self/_cmd and returns the self pointer unchanged; no C++ members are constructed (Boat carries only ObjC ivars)..\n'),
    ),
    dict(
        name='bo_01',
        method='Boat -[actionTitle]',
        types='@8@0:4',
        start=9926444,
        end=9926492,
        disasm='disasm_worldtileloader_bo_01.txt',
        base_add=9926452,
        base_literal=9926488,
        boundary='ARM.exidx end 0x00977778; body trimmed at the next IMP 0x0097775c Boat -[isDoubleHeight]',
        selectors={},
        imports={
                 0x977754: (16341064, '__CFConstantStringClassReference'),
        },
        ivars={},
        classes={},
        instructions=[(9926444, 'sub sp, sp, 8'), (9926488, 'strhteq r8, [lr], -0x38')],
        calls=[],
        branches=[],
        semantics=('[Boat -[actionTitle]] (imp 0x0097772c, 12w): -[actionTitle] (0x97772c, 12w, trimmed at next IMP): returns the static CFString \'EMBARK\' @0xF95848 (flags 0x7c8, len 6) via the Apportable literal pattern (cell 0x977758 -> PIC base 0x105FAF4, delta cell 0x977754). Hardcoded, not [self title]..\n'),
    ),
    dict(
        name='bo_02',
        method='Boat -[actsAsInteractionObject]',
        types='@8@0:4',
        start=9928104,
        end=9928132,
        disasm='disasm_worldtileloader_bo_02.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00977dc4 (listing bound); next ObjC IMP 0x00977dc4 Boat -[blockheadUnloaded:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9928104, 'sub sp, sp, 8'), (9928128, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Boat -[actsAsInteractionObject]] (imp 0x00977da8, 7w): -[actsAsInteractionObject] (0x977da8, 7w): movw r2,0 -> returns nil (the same 7w nil idiom as NPC -[actsAsInteractionObject] 0x64fd44 / TrainCar 0xa3eb0c / DonkeyLike 0xac4bc4) -- the boat does not surface an interaction-object proxy; boarding goes through the rider DPad / tap path..\n'),
    ),
    dict(
        name='bo_03',
        method='Boat -[addRider:]',
        types='v12@0:4@8',
        start=9924072,
        end=9925140,
        disasm='disasm_worldtileloader_bo_03.txt',
        base_add=9924088,
        base_literal=9925136,
        boundary='ARM.exidx end 0x00977214 (listing bound); next ObjC IMP 0x00977214 Boat -[removeRider:]',
        selectors={
                 0x9771cc: (15220076, 'isClientBlockheadBeingControlledByServer'),
                 0x9771d4: (15220068, 'autorelease'),
                 0x9771d8: (15220080, 'stopRiding'),
                 0x9771dc: (15220148, 'isClient'),
                 0x9771e4: (15220152, 'isNet'),
                 0x9771ec: (15220020, 'retain'),
                 0x9771f8: (15220180, 'objectType'),
                 0x9771fc: (15220184, 'dynamicWorldChangedAtPos:objectType:'),
        },
        imports={
                 0x9771c8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x9771d0: (17163216, 'OBJC_IVAR_$_Boat.rider', 116),
                 0x9771e0: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x9771e8: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0x9771f4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x977200: (17163220, 'OBJC_IVAR_$_Boat.beingControlled', 112),
                 0x977208: (17163224, 'OBJC_IVAR_$_Boat.targetXSpeed', 100),
                 0x97720c: (17163228, 'OBJC_IVAR_$_Boat.actualXSpeed', 104),
        },
        classes={},
        instructions=[(9924072, 'push {r4, r5, fp, lr}'), (9925136, 'invalid')],
        calls=[(9924132, 'blx ip'), (9924224, 'blx r3'), (9924260, 'blx r3'), (9924396, 'blx r2'), (9924512, 'blx r2'), (9924616, 'bl loc.imp.objc_msgSend'), (9924712, 'bl loc.imp.objc_msgSend'), (9924748, 'bl loc.imp.objc_msgSend'), (9924844, 'blx r2')],
        branches=[(9924144, 'beq', 9924296), (9924332, 'beq', 9924896), (9924408, 'beq', 9924528), (9924448, 'beq', 9924560), (9924524, 'bne', 9924560), (9924780, 'beq', 9924892), (9924856, 'bne', 9924892), (9924892, 'b', 9924896), (9924988, 'bne', 9925056)],
        semantics=('[Boat -[addRider:]] (imp 0x00976de8, 267w): -[addRider:] (0x976de8, 267w, 9br, 9c): boarding. `if ([rider isClientBlockheadBeingControlledByServer]) { [rider stopRiding]; [self.rider autorelease]; self.rider=nil; rider=nil; }` then `if (rider==self.rider) goto tail;` `if (![[self dynamicWorld] isClient] || (self.rider && ![self.rider isNet])) self.updateNeedsToBeSent@49=1;` `self.rider=[rider retain];` `[[self dynamicWorld] dynamicWorldChangedAtPos:self.pos@16 objectType:[self objectType]];` `if (self.rider && ![self.rider isNet]) updateNeedsToBeSent=1;` tail: `beingControlled@112 = (self.rider!=nil); if (!beingControlled) { actualXSpeed@104=0.0f; targetXSpeed@100=0.0f; }` (0.0f pool @0x977204). Two independent set-flag gates (one over the old rider, one over the new) share the same boolean..\n'),
    ),
    dict(
        name='bo_04',
        method='Boat -[blockheadCanRide:usingItem:]',
        types='c16@0:4@8i12',
        start=9886776,
        end=9886932,
        disasm='disasm_worldtileloader_bo_04.txt',
        base_add=9886788,
        base_literal=9886928,
        boundary='ARM.exidx end 0x0096dcd4 (listing bound); next ObjC IMP 0x0096dcd4 Boat -[updatePosition:]',
        selectors={},
        imports={},
        ivars={
                 0x96dcc8: (17163220, 'OBJC_IVAR_$_Boat.beingControlled', 112),
                 0x96dccc: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
        },
        classes={},
        instructions=[(9886776, 'push {r4, lr}'), (9886928, 'rsbeq r1, pc, r8, lsr 29')],
        calls=[],
        branches=[(9886848, 'bne', 9886900)],
        semantics=('[Boat -[blockheadCanRide:usingItem:]] (imp 0x0096dc38, 39w): -[blockheadCanRide:usingItem:] (0x96dc38, 39w, 1br, 0c): returns `beingControlled@112 ? 0 : !needsRemoved@48` (ldrsb byte reads; cmp/movne/eor r0,1). Both arguments (blockhead, item) are ignored and no super call is made -- riding eligibility depends only on the boat\'s own state..\n'),
    ),
    dict(
        name='bo_05',
        method='Boat -[blockheadUnloaded:]',
        types='v12@0:4@8',
        start=9928132,
        end=9928464,
        disasm='disasm_worldtileloader_bo_05.txt',
        base_add=9928148,
        base_literal=9928460,
        boundary='ARM.exidx end 0x00977f10 (listing bound); next ObjC IMP 0x00977f10 Boat -[riderDPadShouldAllowUpDown]',
        selectors={
                 0x977f08: (15220068, 'autorelease'),
        },
        imports={
                 0x977f04: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x977ef0: (17163216, 'OBJC_IVAR_$_Boat.rider', 116),
                 0x977ef8: (17163224, 'OBJC_IVAR_$_Boat.targetXSpeed', 100),
                 0x977efc: (17163228, 'OBJC_IVAR_$_Boat.actualXSpeed', 104),
                 0x977f00: (17163220, 'OBJC_IVAR_$_Boat.beingControlled', 112),
        },
        classes={},
        instructions=[(9928132, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9928460, 'rsbeq r7, lr, r8, lsl sp')],
        calls=[(9928324, 'blx r5')],
        branches=[(9928200, 'bne', 9928424)],
        semantics=('[Boat -[blockheadUnloaded:]] (imp 0x00977dc4, 83w): -[blockheadUnloaded:] (0x977dc4, 83w, 1c): `if (bh != self.rider) return; [self.rider autorelease]; self.rider=nil; self.beingControlled@112=0; self.actualXSpeed@104=0.0f; self.targetXSpeed@100=0.0f;` (0.0f pool @0x977ef4). No dynamicWorldChanged notification and no updateNeedsToBeSent on this path..\n'),
    ),
    dict(
        name='bo_06',
        method='Boat -[blockheadsLoaded]',
        types='v8@0:4',
        start=9879100,
        end=9880120,
        disasm='disasm_worldtileloader_bo_06.txt',
        base_add=9879116,
        base_literal=9880116,
        boundary='ARM.exidx end 0x0096c238 (listing bound); next ObjC IMP 0x0096c238 Boat -[getSaveDict]',
        selectors={
                 0x96c1fc: (15220060, 'blockheads'),
                 0x96c204: (15220064, 'count'),
                 0x96c20c: (15220020, 'retain'),
                 0x96c210: (15220072, 'objectAtIndex:'),
                 0x96c214: (15220068, 'autorelease'),
                 0x96c218: (15220076, 'isClientBlockheadBeingControlledByServer'),
                 0x96c220: (15220084, 'setRidingObject:'),
                 0x96c230: (15220080, 'stopRiding'),
        },
        imports={
                 0x96c1f8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x96c1f4: (17163208, 'OBJC_IVAR_$_Boat.savedBlockheadIndex', 120),
                 0x96c200: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x96c208: (17163216, 'OBJC_IVAR_$_Boat.rider', 116),
                 0x96c21c: (17163220, 'OBJC_IVAR_$_Boat.beingControlled', 112),
                 0x96c228: (17163224, 'OBJC_IVAR_$_Boat.targetXSpeed', 100),
                 0x96c22c: (17163228, 'OBJC_IVAR_$_Boat.actualXSpeed', 104),
        },
        classes={},
        instructions=[(9879100, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9880116, 'rsbeq r3, pc, r0, lsr 25')],
        calls=[(9879228, 'blx r2'), (9879332, 'blx r2'), (9879452, 'blx r3'), (9879504, 'blx lr'), (9879520, 'blx r2'), (9879632, 'blx r2'), (9879788, 'blx r5'), (9879824, 'blx r3'), (9880012, 'blx r3')],
        branches=[(9879160, 'beq', 9880044), (9879260, 'blt', 9879544), (9879344, 'bhs', 9879544), (9879644, 'beq', 9879928), (9879924, 'b', 9880040), (9880040, 'b', 9880044)],
        semantics=('[Boat -[blockheadsLoaded]] (imp 0x0096be3c, 255w): -[blockheadsLoaded] (0x96be3c, 255w, 6br, 9c): restore the persisted rider. `if (savedBlockheadIndex@120 == -1) return;` (cmn r0,1) `arr=[[self dynamicWorld] blockheads];` `if (idx>=0 && idx<[arr count]) { [self.rider autorelease]; self.rider=[[arr objectAtIndex:idx] retain]; }` `self.savedBlockheadIndex=-1;` then `if ([self.rider isClientBlockheadBeingControlledByServer]) { [rider stopRiding]; [rider autorelease]; rider=nil; beingControlled=0; actualXSpeed=0.0f; targetXSpeed=0.0f; } else { beingControlled=1; [self.rider setRidingObject:self]; }` (0.0f pool @0x96c224). Sibling of the addRider:/blockheadUnloaded: rider lifecycle..\n'),
    ),
    dict(
        name='bo_07',
        method='Boat -[cameraPosForBlockhead:]',
        types='{Vector2=[2f]}12@0:4@8',
        start=9925992,
        end=9926420,
        disasm='disasm_worldtileloader_bo_07.txt',
        base_add=9926008,
        base_literal=9926416,
        boundary='ARM.exidx end 0x00977714 (listing bound); next ObjC IMP 0x00977714 Boat -[worldChanged:]',
        selectors={
                 0x9776f8: (15220240, 'renderPos'),
                 0x977708: (15220244, 'windowInfo'),
        },
        imports={},
        ivars={
                 0x9776fc: (17163224, 'OBJC_IVAR_$_Boat.targetXSpeed', 100),
                 0x977704: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(9925992, 'push {r4, sl, fp, lr}'), (9926416, 'rsbeq r8, lr, r4, ror r5')],
        calls=[(9926076, 'bl loc.imp.objc_msgSend_stret'), (9926112, 'bl sym.imp.memset'), (9926204, 'bl loc.imp.objc_msgSend'), (9926284, 'bl loc.imp.objc_msgSend'), (9926340, 'bl method.Vector2.Vector2_float__float_'), (9926360, 'bl method.Vector2.operator_Vector2_')],
        branches=[(9926060, 'beq', 9926084), (9926080, 'b', 9926116)],
        semantics=('[Boat -[cameraPosForBlockhead:]] (imp 0x00977568, 107w): -[cameraPosForBlockhead:] (0x977568, 107w, 2br, 6c, Vector2-return): `renderPos + Vector2(targetXSpeed@100 * 0.2 * (W + 240.0) / 320.0, (W + 240.0) * 0.5 / 320.0)` where W = first float of `[[self.world@4 windowInfo] floatPtr]`; double consts 0.2 @0x9776e8 and 320.0 @0x9776f0, float 240.0 @0x97770c; nil self -> zero Vector2 via memset(8) and [self renderPos] stret. The camera looks ahead along the boat\'s target speed..\n'),
    ),
    dict(
        name='bo_08',
        method='Boat -[creationNetDataForClient:]',
        types='@12@0:4@8',
        start=9881204,
        end=9882004,
        disasm='disasm_worldtileloader_bo_08.txt',
        base_add=9881220,
        base_literal=9882000,
        boundary='ARM.exidx end 0x0096c994 (listing bound); next ObjC IMP 0x0096cb00 Boat -[updateNetDataForClient:]',
        selectors={
                 0x96c94c: (15220108, 'dynamicObjectNetData'),
                 0x96c964: (15220112, 'uniqueID'),
                 0x96c970: (15220120, 'dictionary'),
                 0x96c978: (15220116, 'dataWithBytes:length:'),
                 0x96c984: (15220104, 'setObject:forKey:'),
                 0x96c988: (15220128, 'appendData:'),
                 0x96c98c: (15220124, 'gzipDeflate'),
        },
        imports={
                 0x96c96c: (17151904, 'objc_msgSend'),
                 0x96c980: (16341032, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x96c950: (17163216, 'OBJC_IVAR_$_Boat.rider', 116),
                 0x96c954: (17163228, 'OBJC_IVAR_$_Boat.actualXSpeed', 104),
                 0x96c968: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
        },
        classes={
                 0x96c974: (15248428, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x96c97c: (15248424, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(9881204, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9882000, 'rsbeq r3, pc, r8, ror 8')],
        calls=[(9881296, 'bl loc.imp.objc_msgSend_stret'), (9881332, 'bl sym.imp.memset'), (9881528, 'bl loc.imp.objc_msgSend'), (9881660, 'blx r5'), (9881696, 'blx r3'), (9881820, 'blx ip'), (9881828, 'bl 0x96c994'), (9881888, 'blx lr'), (9881916, 'blx r3')],
        branches=[(9881280, 'beq', 9881304), (9881300, 'b', 9881336), (9881488, 'beq', 9881540), (9881732, 'beq', 9881824)],
        semantics=('[Boat -[creationNetDataForClient:]] (imp 0x0096c674, 200w): -[creationNetDataForClient:] (0x96c674, 200w, 4br, 9c): builds the creation blob. char buf[0x28]; buf[0x00..0x17] = [self dynamicObjectNetData] (objc_msgSend_stret, 24-byte DynamicObjectNetData {Q uniqueID; I; I; C; C[7]}); buf[0x18..0x1f] = [self.rider uniqueID] u64 (0 when rider==nil); buf[0x20] = (int16)(actualXSpeed@104 * 255.0f) (pool @0x96c95c); bytes 0x22..0x27 stay uninitialized. d=[NSMutableData dataWithBytes:buf length:0x28]; dict=[NSMutableDictionary dictionary]; if (self.ownerID@36) [dict setObject:self.ownerID forKey:\'ownerID\'] (CFSTR \'ownerID\' @0xf95828); [d appendData:[plist(dict) gzipDeflate]] where plist()=local helper 0x96c994 (dataWithPropertyList:format:100 options:0 @try/@catch NSLog); returns d..\n'),
    ),
    dict(
        name='bo_09',
        method='Boat -[dealloc]',
        types='v8@0:4',
        start=9882452,
        end=9882904,
        disasm='disasm_worldtileloader_bo_09.txt',
        base_add=9882468,
        base_literal=9882900,
        boundary='ARM.exidx end 0x0096cd18 (listing bound); next ObjC IMP 0x0096cd18 Boat -[remoteUpdate:]',
        selectors={
                 0x96ccec: (15220140, 'dealloc'),
                 0x96ccf8: (15220068, 'autorelease'),
                 0x96cd00: (15220136, 'release'),
        },
        imports={
                 0x96cce8: (17151900, 'objc_msgSendSuper2'),
                 0x96ccf4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x96ccfc: (17163216, 'OBJC_IVAR_$_Boat.rider', 116),
                 0x96cd04: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
                 0x96cd08: (17163184, 'OBJC_IVAR_$_Boat.bottomCube', 76),
                 0x96cd0c: (17163188, 'OBJC_IVAR_$_Boat.sideCube', 72),
                 0x96cd10: (17163192, 'OBJC_IVAR_$_Boat.frontBackCube', 68),
        },
        classes={
                 0x96ccf0: (15252948, 'OBJC_CLASS_$_Boat'),
        },
        instructions=[(9882452, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9882900, 'rsbeq r2, pc, r8, lsl 31')],
        calls=[(9882652, 'blx r5'), (9882688, 'blx r3'), (9882724, 'blx r3'), (9882760, 'blx r3'), (9882796, 'blx r3'), (9882844, 'blx ip')],
        branches=[],
        semantics=('[Boat -[dealloc]] (imp 0x0096cb54, 113w): -[dealloc] (0x96cb54, 113w, 6c): releases frontBackCube@68, sideCube@72, bottomCube@76, ownerID@36 and rider@116 (five release sends), then objc_msgSendSuper2(objc_super{self, Boat}, dealloc). shader@56, texture@60, sailTexture@64, mastCube@80 and sailCube@84 are NOT released here..\n'),
    ),
    dict(
        name='bo_10',
        method='Boat -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        types='v156@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76i140i144i148i152',
        start=9896320,
        end=9919668,
        disasm='disasm_worldtileloader_bo_10.txt',
        base_add=9896356,
        base_literal=9899764,
        boundary='ARM.exidx end 0x00975cb4 (listing bound); next ObjC IMP 0x00976c00 Boat -[maxHealth]',
        selectors={
                 0x970f04: (15220176, 'worldWidthMacro'),
                 0x97197c: (15220200, 'macroTiles'),
                 0x971990: (15220204, 'fishingRod'),
                 0x971994: (15220208, 'isInCastingAnimation'),
                 0x971998: (15220212, 'hookInAir'),
                 0x97199c: (15220216, 'castingRight'),
                 0x9719ac: (15220220, 'program'),
                 0x9719b4: (15220036, 'intValue'),
                 0x9719b8: (15220072, 'objectAtIndex:'),
                 0x9719bc: (15220224, 'uniformLocations'),
                 0x9719c0: (15220228, 'dayColor'),
                 0x9719d8: (15220232, 'name'),
                 0x9719e0: (15220236, 'draw'),
                 0x975c94: (15220036, 'intValue'),
                 0x975c98: (15220072, 'objectAtIndex:'),
                 0x975c9c: (15220224, 'uniformLocations'),
                 0x975ca4: (15220236, 'draw'),
        },
        imports={
                 0x971978: (17151904, 'objc_msgSend'),
                 0x975c90: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x970ef8: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x970f00: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x971568: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x971980: (17163216, 'OBJC_IVAR_$_Boat.rider', 116),
                 0x971988: (17163228, 'OBJC_IVAR_$_Boat.actualXSpeed', 104),
                 0x9719a4: (17163168, 'OBJC_IVAR_$_Boat.bodyRotation', 88),
                 0x9719b0: (17163204, 'OBJC_IVAR_$_Boat.shader', 56),
                 0x9719d4: (17163200, 'OBJC_IVAR_$_Boat.texture', 60),
                 0x9719dc: (17163184, 'OBJC_IVAR_$_Boat.bottomCube', 76),
                 0x973bc8: (17163188, 'OBJC_IVAR_$_Boat.sideCube', 72),
                 0x973bcc: (17163192, 'OBJC_IVAR_$_Boat.frontBackCube', 68),
                 0x975ca0: (17163204, 'OBJC_IVAR_$_Boat.shader', 56),
                 0x975ca8: (17163176, 'OBJC_IVAR_$_Boat.sailCube', 84),
                 0x975cac: (17163180, 'OBJC_IVAR_$_Boat.mastCube', 80),
                 0x975cb0: (17163196, 'OBJC_IVAR_$_Boat.sailTexture', 64),
        },
        classes={},
        instructions=[(9896320, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9919664, 'invalid')],
        calls=[(9897016, 'bl loc.imp.objc_msgSend'), (9897040, 'bl sym.imp.__aeabi_idiv'), (9897108, 'bl loc.imp.objc_msgSend'), (9897236, 'bl loc.imp.objc_msgSend'), (9897252, 'bl sym.imp.__aeabi_idiv'), (9897320, 'bl loc.imp.objc_msgSend'), (9897452, 'bl loc.imp.objc_msgSend'), (9897476, 'bl sym.imp.__aeabi_idiv'), (9897544, 'bl loc.imp.objc_msgSend'), (9897672, 'bl loc.imp.objc_msgSend'), (9897688, 'bl sym.imp.__aeabi_idiv'), (9897756, 'bl loc.imp.objc_msgSend'), (9898052, 'bl method.Vector2.Vector2_float__float_'), (9898092, 'bl method.Vector2.operator_Vector2_'), (9898100, 'bl method.Vector2.operator_float__'), (9898164, 'bl loc.imp.objc_msgSend'), (9898188, 'bl sym.imp.__aeabi_idiv'), (9898288, 'bl loc.imp.objc_msgSend'), (9898324, 'bl method.Vector2.operator_float__'), (9898380, 'bl method.Vector2.operator_float__'), (9898448, 'bl loc.imp.objc_msgSend'), (9898464, 'bl sym.imp.__aeabi_idiv'), (9898564, 'bl loc.imp.objc_msgSend'), (9898600, 'bl method.Vector2.operator_float__'), (9898740, 'blx r2'), (9898788, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (9898832, 'bl method.Vector2.operator_float__'), (9898852, 'bl method.Vector2.operator_float__'), (9898936, 'bl 0x975cb4'), (9899188, 'blx r3'), (9899288, 'blx ip'), (9899316, 'blx r3'), (9899376, 'blx r2'), (9899416, 'bl loc.imp.objc_msgSend'), (9900252, 'bl 0x975d28'), (9900724, 'bl 0x9760c0'), (9900792, 'bl sym.imp.memcpy'), (9900840, 'blx ip'), (9900844, 'bl sym.imp.__wrap_glUseProgram'), (9900976, 'blx r6'), (9900996, 'blx r3'), (9901012, 'blx r2'), (9901020, 'bl sym.imp.__wrap_glUniform1i'), (9901028, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (9901112, 'bl loc.imp.objc_msgSend_stret'), (9901160, 'bl sym.imp.memset'), (9901656, 'bl method.Vector.Vector_float__float__float_'), (9901676, 'bl method.Vector.operator_float__'), (9901748, 'bl method.Vector.operator_float__'), (9901800, 'bl method.Vector.operator_float__'), (9901872, 'bl method.Vector.operator_float__'), (9901924, 'bl method.Vector.operator_float__'), (9901996, 'bl method.Vector.operator_float__'), (9902068, 'bl method.Vector.Vector_float__float__float_'), (9902088, 'bl method.Vector.operator_float__'), (9902208, 'bl method.Vector.operator_float__'), (9902236, 'bl method.Vector.operator_float__'), (9902356, 'bl method.Vector.operator_float__'), (9902384, 'bl method.Vector.operator_float__'), (9902620, 'bl method.Vector.operator_float__'), (9902692, 'bl loc.imp.objc_msgSend'), (9902720, 'bl loc.imp.objc_msgSend'), (9902744, 'bl loc.imp.objc_msgSend'), (9902760, 'bl method.Vector.operator_float__'), (9902776, 'bl method.Vector.operator_float__'), (9902792, 'bl method.Vector.operator_float__'), (9902824, 'bl sym.imp.__wrap_glUniform4f'), (9903620, 'bl 0x976458'), (9904416, 'bl 0x976458'), (9904452, 'bl loc.imp.objc_msgSend'), (9904480, 'bl loc.imp.objc_msgSend'), (9904496, 'bl loc.imp.objc_msgSend'), (9904516, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9904552, 'bl loc.imp.objc_msgSend'), (9904580, 'bl loc.imp.objc_msgSend'), (9904596, 'bl loc.imp.objc_msgSend'), (9904612, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9904660, 'bl loc.imp.objc_msgSend'), (9904688, 'bl sym.imp.__wrap_glBindTexture'), (9904736, 'bl loc.imp.objc_msgSend'), (9905116, 'bl 0x976a18'), (9905908, 'bl 0x976458'), (9906832, 'bl 0x976458'), (9907000, 'bl loc.imp.objc_msgSend'), (9907020, 'bl loc.imp.objc_msgSend'), (9907036, 'bl loc.imp.objc_msgSend'), (9907052, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9907088, 'bl loc.imp.objc_msgSend'), (9907108, 'bl loc.imp.objc_msgSend'), (9907124, 'bl loc.imp.objc_msgSend'), (9907140, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9907184, 'bl loc.imp.objc_msgSend'), (9907556, 'bl 0x976a18'), (9908348, 'bl 0x976458'), (9909272, 'bl 0x976458'), (9909440, 'bl loc.imp.objc_msgSend'), (9909460, 'bl loc.imp.objc_msgSend'), (9909476, 'bl loc.imp.objc_msgSend'), (9909492, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9909528, 'bl loc.imp.objc_msgSend'), (9909548, 'bl loc.imp.objc_msgSend'), (9909564, 'bl loc.imp.objc_msgSend'), (9909580, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9909616, 'bl loc.imp.objc_msgSend'), (9909988, 'bl 0x976a18'), (9910780, 'bl 0x976458'), (9911712, 'bl 0x976458'), (9911880, 'bl loc.imp.objc_msgSend'), (9911900, 'bl loc.imp.objc_msgSend'), (9911916, 'bl loc.imp.objc_msgSend'), (9911932, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9911968, 'bl loc.imp.objc_msgSend'), (9911988, 'bl loc.imp.objc_msgSend'), (9912004, 'bl loc.imp.objc_msgSend'), (9912020, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9912064, 'bl loc.imp.objc_msgSend'), (9912432, 'bl 0x976a18'), (9913220, 'bl 0x976458'), (9914140, 'bl 0x976458'), (9914308, 'bl loc.imp.objc_msgSend'), (9914328, 'bl loc.imp.objc_msgSend'), (9914344, 'bl loc.imp.objc_msgSend'), (9914360, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9914396, 'bl loc.imp.objc_msgSend'), (9914416, 'bl loc.imp.objc_msgSend'), (9914432, 'bl loc.imp.objc_msgSend'), (9914448, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9914484, 'bl loc.imp.objc_msgSend'), (9914852, 'bl 0x976a18'), (9915640, 'bl 0x976458'), (9916560, 'bl 0x976458'), (9916728, 'bl loc.imp.objc_msgSend'), (9916748, 'bl loc.imp.objc_msgSend'), (9916764, 'bl loc.imp.objc_msgSend'), (9916780, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9916816, 'bl loc.imp.objc_msgSend'), (9916836, 'bl loc.imp.objc_msgSend'), (9916852, 'bl loc.imp.objc_msgSend'), (9916868, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9916908, 'bl loc.imp.objc_msgSend'), (9916948, 'bl loc.imp.objc_msgSend'), (9916968, 'bl sym.imp.__wrap_glBindTexture'), (9917340, 'bl 0x976a18'), (9918128, 'bl 0x976458'), (9919048, 'bl 0x976458'), (9919208, 'bl sym.imp.memcpy'), (9919256, 'blx ip'), (9919276, 'blx r3'), (9919292, 'blx r2'), (9919324, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9919464, 'blx r3'), (9919484, 'blx r3'), (9919500, 'blx r2'), (9919532, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9919612, 'blx r3'), (9919620, 'bl sym.imp.__wrap_glDisableVertexAttribArray')],
        branches=[(9897052, 'blt', 9897144), (9897140, 'b', 9897356), (9897264, 'bge', 9897352), (9897352, 'b', 9897356), (9897488, 'blt', 9897580), (9897576, 'b', 9897792), (9897700, 'bge', 9897788), (9897788, 'b', 9897792), (9897832, 'blt', 9897968), (9897876, 'bgt', 9897968), (9897920, 'blt', 9897968), (9897964, 'ble', 9897972), (9897968, 'b', 9919624), (9898216, 'ble', 9898352), (9898348, 'b', 9898628), (9898492, 'bpl', 9898624), (9898624, 'b', 9898628), (9898812, 'bne', 9898820), (9898816, 'b', 9919624), (9898996, 'ble', 9899072), (9899068, 'b', 9899096), (9899092, 'b', 9899096), (9899200, 'beq', 9899456), (9899328, 'bne', 9899392), (9899388, 'beq', 9899452), (9899452, 'b', 9899456), (9899568, 'bpl', 9899596), (9899592, 'b', 9899612), (9899736, 'bpl', 9899812), (9899760, 'b', 9899828), (9901092, 'beq', 9901128), (9901116, 'b', 9901164), (9901284, 'bpl', 9901312), (9901304, 'b', 9901328), (9901376, 'bpl', 9901424), (9901396, 'b', 9901440), (9901488, 'ble', 9901560), (9902128, 'bpl', 9902156), (9902148, 'b', 9902172), (9902276, 'bpl', 9902304), (9902296, 'b', 9902320), (9902424, 'bpl', 9902564), (9902444, 'b', 9902580), (9911236, 'b', 9911248)],
        semantics=('[Boat -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]] (imp 0x00970180, 5837w): -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:] (0x970180, 5837w, 44br, 156 calls) [census grade, NOT instruction-by-instruction]. Frame: sub sp,0x19c0 + bic sp,0xf; ~36 words of stack args (two _GLKMatrix4 by value + 4 camera bounds) spilled to locals then copied into wrapper structs. Phase map: (A) four world-wrap clamp blocks using [world@4 worldWidthMacro] -> __aeabi_idiv and `lsl r0,r0,5` (x32 px), adjusting pos/floatPos against the camera window; (B) render-position math: Vector2::Vector2 + operator+ + operator float*, [self.world macroTiles] neighbour scan (sel @0x970a98), one indirect blx and tileAtWorldPosition @0x970b24; (C) bl 0x975cb4 (helper, 29w, memcpy) @0x970bb8; (D) fishing-rod lean: if ([self.rider@116 fishingRod]) -- sels fishingRod/isInCastingAnimation/hookInAir/castingRight @0x971990-9c -- the stored lean double is set to +pi/2 @0x970f10 or -pi/2 @0x970f08 when the rod is casting or its hook is in air, else 0.0 @0x970f18; (E) matrix helpers bl 0x975d28 @0x9710dc and bl 0x9760c0 @0x9712b4 (230w twins) + memcpy @0x9712f8; (F) shader bind: [[self.shader@56 program] (sel @0x9712c4) -> glUseProgram @0x97132c, glUniform1i @0x9713dc, glEnableVertexAttribArray @0x9713e4, [self.world dayColor] stret @0x971438 + memset(0x10) @0x971468, Vector ctor + 6x operator float* and glUniform4f @0x971ae8 (light colour; pool 255.0 @0x9719c8, 0.1 @0x9719cc, 0.3 @0x9719c4, 1024.0 @0x971848, movw/movt 0.9/-0.9/1.2/0.4/-0.4/-0.2/1.8); (G) seven part blocks, each = 2x bl 0x976458 (368w helper, pure VFP matrix builder, zero calls) + uniform-location chain ([shader uniformLocations]/objectAtIndex:/intValue) + 2x glUniformMatrix4fv + [self.<cube> draw] (SEL draw staged at [sp,0x5f0]): P1 bottomCube@76 (+ glBindTexture 0xde1 [texture@60 name] @0x972230), P2 sideCube@72, P3 sideCube again (slot [sp,0x514]), P4 frontBackCube@68, P5 frontBackCube again (slot [sp,0x368]), P6 mastCube@80 (+ glBindTexture 0xde1 [sailTexture@64] @0x975228), P7 sailCube@84 @0x975c48 ending with glDisableVertexAttribArray @0x975c84; six blocks additionally call bl 0x976a18 (122w helper, pure vector transform: 37 vldr/19 vstr/9 vmul/9 vadd, zero calls; colour consts 0.9f/0.5f and 1.2f/0.5f in its param struct). Graded census: structure + constants + call groups verified, individual float expressions inside the arg bundles not all unfolded..\n'),
    ),
    dict(
        name='bo_11',
        method='Boat -[freeblockCreationItemType]',
        types='i8@0:4',
        start=9876752,
        end=9876780,
        disasm='disasm_worldtileloader_bo_11.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0096b548; body trimmed at the next IMP 0x0096b52c Boat -[objectType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9876752, 'sub sp, sp, 8'), (9876776, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Boat -[freeblockCreationItemType]] (imp 0x0096b510, 7w): -[freeblockCreationItemType] (0x96b510, 7w, trimmed at next IMP 0x96b52c objectType): returns 0x6f = 111 (uxth) -- the boat item type handed to free-block creation..\n'),
    ),
    dict(
        name='bo_12',
        method='Boat -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:placedByClient:]',
        types='@36@0:4@8@12{?=ii}16@24@28@32',
        start=9876808,
        end=9877528,
        disasm='disasm_worldtileloader_bo_12.txt',
        base_add=9876824,
        base_literal=9877524,
        boundary='ARM.exidx end 0x0096b818 (listing bound); next ObjC IMP 0x0096b818 Boat -[initWithWorld:dynamicWorld:saveDict:cache:]',
        selectors={
                 0x96b7f0: (15220016, 'initWithWorld:dynamicWorld:atPosition:cache:'),
                 0x96b804: (15220024, 'objectForKey:'),
                 0x96b80c: (15220020, 'retain'),
                 0x96b810: (15220028, 'loadDerivedStuff'),
        },
        imports={
                 0x96b7fc: (16341032, '__CFConstantStringClassReference'),
                 0x96b800: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x96b7f4: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x96b7f8: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x96b808: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
        },
        classes={
                 0x96b7e8: (15252948, 'OBJC_CLASS_$_Boat'),
        },
        instructions=[(9876808, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9877524, 'mlseq pc, r4, r5, r4')],
        calls=[(9877000, 'bl loc.imp.objc_msgSendSuper2'), (9877112, 'bl method.Vector2.operator_float__'), (9877184, 'blx r2'), (9877272, 'blx r3'), (9877372, 'blx lr'), (9877388, 'blx r2'), (9877456, 'blx r2')],
        branches=[(9877028, 'bne', 9877044), (9877040, 'b', 9877468), (9877136, 'beq', 9877212), (9877208, 'b', 9877416), (9877284, 'beq', 9877412), (9877412, 'b', 9877416)],
        semantics=('[Boat -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:placedByClient:]] (imp 0x0096b548, 180w): -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:placedByClient:] (0x96b548, 180w, 6br, 7c): placing ctor. super initWithWorld:dynamicWorld:atPosition:cache: (msgSendSuper2, 4 args forwarded); nil -> nil; `((float*)&floatPos@24)[1] = (float)pos.y + 0.5f`; ownerID@36 = [placedByClient retain] when placedByClient != nil, else [saveDict objectForKey:\'ownerID\'] (CFSTR @0xf95828) retained when present; `[self loadDerivedStuff]`; return self..\n'),
    ),
    dict(
        name='bo_13',
        method='Boat -[initWithWorld:dynamicWorld:cache:netData:]',
        types='@24@0:4@8@12@16@20',
        start=9878200,
        end=9879064,
        disasm='disasm_worldtileloader_bo_13.txt',
        base_add=9878216,
        base_literal=9879060,
        boundary='ARM.exidx end 0x0096be18 (listing bound); next ObjC IMP 0x0096be3c Boat -[blockheadsLoaded]',
        selectors={
                 0x96bdd4: (15220040, 'initWithWorld:dynamicWorld:cache:netData:'),
                 0x96bde0: (15220044, 'length'),
                 0x96bdf0: (15220028, 'loadDerivedStuff'),
                 0x96bdf8: (15220020, 'retain'),
                 0x96be00: (15220024, 'objectForKey:'),
                 0x96be04: (15220052, 'gzipInflate'),
                 0x96be0c: (15220048, 'subdataWithRange:'),
                 0x96be10: (15220056, 'remoteUpdate:'),
        },
        imports={
                 0x96bdd0: (17151900, 'objc_msgSendSuper2'),
                 0x96bddc: (17151904, 'objc_msgSend'),
                 0x96bdfc: (16341032, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x96bde4: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x96bde8: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x96bdec: (17163212, 'OBJC_IVAR_$_Boat.remoteGoalPos', 132),
                 0x96bdf4: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
        },
        classes={
                 0x96bdd8: (15252948, 'OBJC_CLASS_$_Boat'),
        },
        instructions=[(9878200, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9879060, 'rsbeq r4, pc, r4, lsr 32')],
        calls=[(9878352, 'blx r6'), (9878472, 'blx ip'), (9878576, 'bl method.Vector2.operator_float__'), (9878628, 'blx r3'), (9878700, 'bl loc.imp.objc_msgSend'), (9878768, 'bl loc.imp.objc_msgSend'), (9878792, 'blx r2'), (9878796, 'bl 0x96be18'), (9878880, 'blx r3'), (9878896, 'blx r2'), (9878968, 'blx r3')],
        branches=[(9878380, 'bne', 9878396), (9878392, 'b', 9878980), (9878636, 'bls', 9878920)],
        semantics=('[Boat -[initWithWorld:dynamicWorld:cache:netData:]] (imp 0x0096bab8, 216w): -[initWithWorld:dynamicWorld:cache:netData:] (0x96bab8, 216w, 3br, 11c): net ctor. super initWithWorld:dynamicWorld:cache:netData:; nil->nil; `[self loadDerivedStuff]`; `remoteGoalPos@132 = self.pos@16` (intpair pair-copy); `((float*)&floatPos@24)[1] = (float)pos.y + 0.5f`; `if ([netData length] > 0x28) { sub=[netData subdataWithRange:{0x28, len-0x28}]; dict=helper(0x96be18 -> 0x9780e4) ([sub gzipInflate]); if ([dict objectForKey:\'ownerID\']) ownerID=[[dict objectForKey:\'ownerID\'] retain]; }`; `[self remoteUpdate:netData]`; return self. Header 0x28 bytes are decoded by remoteUpdate: itself..\n'),
    ),
    dict(
        name='bo_14',
        method='Boat -[isDoubleHeight]',
        types='c8@0:4',
        start=9926492,
        end=9926520,
        disasm='disasm_worldtileloader_bo_14.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00977778 (listing bound); next ObjC IMP 0x00977778 Boat -[tapIsWithinBodyRadius:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9926492, 'sub sp, sp, 8'), (9926516, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Boat -[isDoubleHeight]] (imp 0x0097775c, 7w): -[isDoubleHeight] (0x97775c, 7w): sxtb of movw r2,0 -> NO. The boat occupies one tile layer..\n'),
    ),
    dict(
        name='bo_15',
        method='Boat -[jumpsOnSwipe]',
        types='c8@0:4',
        start=9927808,
        end=9927836,
        disasm='disasm_worldtileloader_bo_15.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00977c9c (listing bound); next ObjC IMP 0x00977c9c Boat -[rideDirection]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9927808, 'sub sp, sp, 8'), (9927832, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Boat -[jumpsOnSwipe]] (imp 0x00977c80, 7w): -[jumpsOnSwipe] (0x977c80, 7w): returns 0 (sxtb) -- boat does not jump on swipe-up..\n'),
    ),
    dict(
        name='bo_16',
        method='Boat -[loadDerivedStuff]',
        types='v8@0:4',
        start=9875164,
        end=9876752,
        disasm='disasm_worldtileloader_bo_16.txt',
        base_add=9875180,
        base_literal=9876748,
        boundary='ARM.exidx end 0x0096b510 (listing bound); next ObjC IMP 0x0096b510 Boat -[freeblockCreationItemType]',
        selectors={
                 0x96b4a8: (15220012, 'initWithWidth:height:depth:calculateNormals:'),
                 0x96b4ac: (15220008, 'alloc'),
                 0x96b4cc: (15220004, 'textureNamed:'),
                 0x96b4e4: (15220000, 'shaderNamed:attributes:uniforms:'),
                 0x96b4f8: (15219996, 'arrayWithObjects:'),
        },
        imports={
                 0x96b4a4: (17151904, 'objc_msgSend'),
                 0x96b4c8: (16341016, '__CFConstantStringClassReference'),
                 0x96b4d8: (16341000, '__CFConstantStringClassReference'),
                 0x96b4e0: (16340872, '__CFConstantStringClassReference'),
                 0x96b4e8: (16340936, '__CFConstantStringClassReference'),
                 0x96b4ec: (16340952, '__CFConstantStringClassReference'),
                 0x96b4f0: (16340968, '__CFConstantStringClassReference'),
                 0x96b4f4: (16340984, '__CFConstantStringClassReference'),
                 0x96b500: (16340888, '__CFConstantStringClassReference'),
                 0x96b504: (16340904, '__CFConstantStringClassReference'),
                 0x96b508: (16340920, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x96b498: (17163168, 'OBJC_IVAR_$_Boat.bodyRotation', 88),
                 0x96b49c: (17163172, 'OBJC_IVAR_$_Boat.goalRotationType', 96),
                 0x96b4a0: (17163176, 'OBJC_IVAR_$_Boat.sailCube', 84),
                 0x96b4b4: (17163180, 'OBJC_IVAR_$_Boat.mastCube', 80),
                 0x96b4b8: (17163184, 'OBJC_IVAR_$_Boat.bottomCube', 76),
                 0x96b4bc: (17163188, 'OBJC_IVAR_$_Boat.sideCube', 72),
                 0x96b4c0: (17163192, 'OBJC_IVAR_$_Boat.frontBackCube', 68),
                 0x96b4c4: (17163196, 'OBJC_IVAR_$_Boat.sailTexture', 64),
                 0x96b4d0: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0x96b4d4: (17163200, 'OBJC_IVAR_$_Boat.texture', 60),
                 0x96b4dc: (17163204, 'OBJC_IVAR_$_Boat.shader', 56),
        },
        classes={
                 0x96b4b0: (15248416, 'OBJC_CLASS_$_DrawCube'),
                 0x96b4fc: (15248412, 'OBJC_CLASS_$_NSArray'),
        },
        instructions=[(9875164, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9876748, 'rsbeq r4, pc, r0, lsl 24')],
        calls=[(9875756, 'blx r7'), (9875820, 'blx r5'), (9875864, 'blx lr'), (9875924, 'blx ip'), (9875984, 'blx ip'), (9876036, 'blx ip'), (9876092, 'blx lr'), (9876144, 'blx ip'), (9876232, 'blx lr'), (9876284, 'blx ip'), (9876340, 'blx lr'), (9876392, 'blx ip'), (9876444, 'blx lr'), (9876496, 'blx ip'), (9876552, 'blx lr')],
        branches=[(9876196, 'b', 9876228)],
        semantics=('[Boat -[loadDerivedStuff]] (imp 0x0096aedc, 397w): -[loadDerivedStuff] (0x96aedc, 397w, 1br, 15c) [census-lite, fully traced]: builds all render assets. `self.shader@56 = [self.cache@32 shaderNamed:\'ShadedWorldObject\' attributes:@[\'position\',\'texCoord\',\'normal\'] uniforms:@[\'mvp_matrix\',\'texture\',\'light\',\'normal_matrix\']]` (CFSTRs 0xf95788/98/a8/b8/c8/d8/e8/f8); texture@60=[cache@32 textureNamed:\'boat.png\'] (0xf95808), sailTexture@64=[cache textureNamed:\'sail.png\'] (0xf95818); five DrawCube allocs via initWithWidth:height:depth:calculateNormals: (all calculateNormals=YES): frontBackCube@68 = 0.8 x 0.5 x 0.1, sideCube@72 = 0.1 x 0.5 x 1.8, bottomCube@76 = 0.8 x 0.1 x 1.8, mastCube@80 = 0.1 x 2.4 x 0.1, sailCube@84 = 0.05 x 1.0 x 1.4 (float pool 0.8@0x96b2fc, 0.5 #96, 0.1@0x96b2f4, 1.8@0x96b300, 0.05@0x96b2ec, 1.0 #112, 1.4@0x96b2f0, 2.4@0x96b2f8). Tail: goalRotationType@96 = 0 and bodyRotation@88 = pi (3.14159274f @0x96b2e8); prevRotation untouched..\n'),
    ),
    dict(
        name='bo_17',
        method='Boat -[maxHealth]',
        types='S8@0:4',
        start=9923584,
        end=9923612,
        disasm='disasm_worldtileloader_bo_17.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00976c1c (listing bound); next ObjC IMP 0x00976c1c Boat -[renderPos]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9923584, 'sub sp, sp, 8'), (9923608, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Boat -[maxHealth]] (imp 0x00976c00, 7w): -[maxHealth] (0x976c00, 7w): movw r2,0x20; uxth -> 32..\n'),
    ),
    dict(
        name='bo_18',
        method='Boat -[remoteUpdate:]',
        types='v12@0:4@8',
        start=9882904,
        end=9886776,
        disasm='disasm_worldtileloader_bo_18.txt',
        base_add=9882920,
        base_literal=9886772,
        boundary='ARM.exidx end 0x0096dc38 (listing bound); next ObjC IMP 0x0096dc38 Boat -[blockheadCanRide:usingItem:]',
        selectors={
                 0x96dbc8: (15220056, 'remoteUpdate:'),
                 0x96dbd8: (15220148, 'isClient'),
                 0x96dbe0: (15220144, 'getBytes:length:'),
                 0x96dbe8: (15220152, 'isNet'),
                 0x96dbf0: (15220112, 'uniqueID'),
                 0x96dbfc: (15220068, 'autorelease'),
                 0x96dc00: (15220080, 'stopRiding'),
                 0x96dc18: (15220092, 'countByEnumeratingWithState:objects:count:'),
                 0x96dc1c: (15220156, 'allBlockheadsIncludingNet'),
                 0x96dc24: (15220160, 'addRider:'),
        },
        imports={
                 0x96dbc4: (17151900, 'objc_msgSendSuper2'),
                 0x96dbd4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x96dbd0: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0x96dbdc: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x96dbe4: (17163216, 'OBJC_IVAR_$_Boat.rider', 116),
                 0x96dbf4: (17163224, 'OBJC_IVAR_$_Boat.targetXSpeed', 100),
                 0x96dbf8: (17163228, 'OBJC_IVAR_$_Boat.actualXSpeed', 104),
                 0x96dc08: (17163212, 'OBJC_IVAR_$_Boat.remoteGoalPos', 132),
                 0x96dc0c: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0x96dc10: (17163220, 'OBJC_IVAR_$_Boat.beingControlled', 112),
        },
        classes={
                 0x96dbcc: (15252948, 'OBJC_CLASS_$_Boat'),
        },
        instructions=[(9882904, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9886772, 'rsbeq r2, pc, r4, asr 27')],
        calls=[(9882996, 'blx lr'), (9883124, 'blx lr'), (9883160, 'blx r3'), (9883276, 'blx r2'), (9883376, 'bl loc.imp.objc_msgSend'), (9883532, 'blx lr'), (9883568, 'blx r3'), (9883768, 'bl sym.makeIntpair_int__int_'), (9884012, 'bl loc.imp.objc_msgSend'), (9884176, 'blx r2'), (9884200, 'bl sym.imp.memset'), (9884248, 'blx lr'), (9884348, 'bl sym.imp.objc_enumerationMutation'), (9884420, 'blx r2'), (9884456, 'bl loc.imp.objc_msgSend'), (9884552, 'blx r3'), (9884680, 'blx ip'), (9884900, 'blx r5'), (9884936, 'blx r3'), (9885148, 'blx r2'), (9885248, 'bl loc.imp.objc_msgSend'), (9885404, 'blx lr'), (9885440, 'blx r3'), (9885640, 'bl sym.makeIntpair_int__int_'), (9885872, 'blx r2'), (9885896, 'bl sym.imp.memset'), (9885944, 'blx lr'), (9886044, 'bl sym.imp.objc_enumerationMutation'), (9886116, 'blx r2'), (9886152, 'bl loc.imp.objc_msgSend'), (9886248, 'blx r3'), (9886376, 'blx ip'), (9886540, 'blx r3'), (9886576, 'blx r3')],
        branches=[(9883032, 'bne', 9886652), (9883172, 'bne', 9885048), (9883212, 'beq', 9883648), (9883288, 'bne', 9883648), (9883308, 'beq', 9883644), (9883312, 'b', 9883316), (9883404, 'beq', 9883644), (9883408, 'b', 9883412), (9883644, 'b', 9885044), (9883904, 'beq', 9884720), (9883908, 'b', 9883912), (9883948, 'beq', 9884060), (9884040, 'bne', 9884060), (9884044, 'b', 9884048), (9884048, 'b', 9884712), (9884260, 'beq', 9884704), (9884340, 'beq', 9884352), (9884432, 'beq', 9884580), (9884484, 'bne', 9884580), (9884488, 'b', 9884492), (9884580, 'b', 9884584), (9884608, 'blo', 9884304), (9884700, 'bne', 9884304), (9884704, 'b', 9884708), (9884708, 'b', 9884712), (9884712, 'b', 9885040), (9884756, 'beq', 9885036), (9885036, 'b', 9885040), (9885040, 'b', 9885044), (9885044, 'b', 9886648), (9885084, 'beq', 9885524), (9885160, 'bne', 9885524), (9885180, 'beq', 9885516), (9885184, 'b', 9885188), (9885276, 'beq', 9885516), (9885280, 'b', 9885284), (9885516, 'b', 9886644), (9885748, 'beq', 9886412), (9885752, 'b', 9885756), (9885956, 'beq', 9886400), (9886036, 'beq', 9886048), (9886128, 'beq', 9886276), (9886180, 'bne', 9886276), (9886184, 'b', 9886188), (9886276, 'b', 9886280), (9886304, 'blo', 9886000), (9886396, 'bne', 9886000), (9886400, 'b', 9886404), (9886404, 'b', 9886640), (9886448, 'beq', 9886608), (9886640, 'b', 9886644), (9886644, 'b', 9886648), (9886648, 'b', 9886652)],
        semantics=('[Boat -[remoteUpdate:]] (imp 0x0096cd18, 968w): -[remoteUpdate:] (0x96cd18, 968w, 53br, 34c) [census-lite, fully traced]: wire-state intake. [super remoteUpdate:data] then `if (needsRemoved@48) return;` char buf[0x28]; [data getBytes:buf length:0x28]; branch on [[self dynamicWorld] isClient]. SERVER path: if (rider && !rider.isNet && (buf[0x18]|buf[0x1c])!=0 && packetUID != [rider uniqueID]) -> [rider stopRiding]; [rider autorelease]; rider=nil; actualXSpeed=0; targetXSpeed=0; return. Then always: `actualXSpeed@104 = (float)(s16)buf[0x20] / 255.0f` (pool @0x96d198); `remoteGoalPos@132 = makeIntpair(buf[8], buf[0xc])`; `remoteGoalPos.x = (int)((float)remoteGoalPos.x + actualXSpeed*0.2f)` (0.2f @0x96d42c); `updateNeedsToBeSent@49 = 1`. If packet carries no rider UID -> detach any rider and zero both speeds. If UID matches the current rider -> keep. Otherwise fast-enumerate [[self dynamicWorld] allBlockheadsIncludingNet] and for every net blockhead whose uniqueID equals the packet UID: [self addRider:b]; beingControlled=1 (no early break). CLIENT path (0x96d578): if (rider && !rider.isNet) { return when packetUID==0 or ==[rider uniqueID]; else stopRiding+autorelease+rider=nil; return; } then the same speed/goal decode but WITHOUT updateNeedsToBeSent; if packetUID != 0 -> same enumeration + addRider/beingControlled=1; else detach rider and beingControlled=0. Enumeration uses countByEnumeratingWithState:objects:count: + memset(0x20) + objc_enumerationMutation..\n'),
    ),
    dict(
        name='bo_19',
        method='Boat -[removeRider:]',
        types='v12@0:4@8',
        start=9925140,
        end=9925860,
        disasm='disasm_worldtileloader_bo_19.txt',
        base_add=9925156,
        base_literal=9925856,
        boundary='ARM.exidx end 0x009774e4 (listing bound); next ObjC IMP 0x009774e4 Boat -[swipeUpGesture]',
        selectors={
                 0x9774ac: (15220148, 'isClient'),
                 0x9774b4: (15220152, 'isNet'),
                 0x9774c0: (15220068, 'autorelease'),
                 0x9774c8: (15220180, 'objectType'),
                 0x9774cc: (15220184, 'dynamicWorldChangedAtPos:objectType:'),
        },
        imports={
                 0x9774a8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x9774a4: (17163216, 'OBJC_IVAR_$_Boat.rider', 116),
                 0x9774b0: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x9774b8: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0x9774c4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x9774d0: (17163220, 'OBJC_IVAR_$_Boat.beingControlled', 112),
                 0x9774d8: (17163224, 'OBJC_IVAR_$_Boat.targetXSpeed', 100),
                 0x9774dc: (17163228, 'OBJC_IVAR_$_Boat.actualXSpeed', 104),
        },
        classes={},
        instructions=[(9925140, 'push {fp, lr}'), (9925856, 'rsbeq r8, lr, r8, asr 17')],
        calls=[(9925272, 'blx r2'), (9925388, 'blx r2'), (9925484, 'bl loc.imp.objc_msgSend'), (9925588, 'bl loc.imp.objc_msgSend'), (9925624, 'bl loc.imp.objc_msgSend')],
        branches=[(9925208, 'bne', 9925628), (9925284, 'beq', 9925404), (9925324, 'beq', 9925436), (9925400, 'bne', 9925436), (9925720, 'bne', 9925788)],
        semantics=('[Boat -[removeRider:]] (imp 0x00977214, 180w): -[removeRider:] (0x977214, 180w, 5br, 5c): `if (bh != self.rider) goto tail;` `if (![[self dynamicWorld] isClient] || (self.rider && ![self.rider isNet])) self.updateNeedsToBeSent@49=1;` `[self.rider autorelease]; self.rider=nil; [[self dynamicWorld] dynamicWorldChangedAtPos:self.pos@16 objectType:[self objectType]];` tail: `beingControlled@112=(self.rider!=nil); if (!beingControlled) { actualXSpeed@104=0.0f; targetXSpeed@100=0.0f; }` (0.0f pool @0x9774d4). Same flag gate as addRider:\'s first gate..\n'),
    ),
    dict(
        name='bo_20',
        method='Boat -[renderPos]',
        types='{Vector2=[2f]}8@0:4',
        start=9923612,
        end=9923736,
        disasm='disasm_worldtileloader_bo_20.txt',
        base_add=9923644,
        base_literal=9923732,
        boundary='ARM.exidx end 0x00976dcc; body trimmed at the next IMP 0x00976c98 Boat -[riderPosForBlockhead:]',
        selectors={},
        imports={},
        ivars={
                 0x976c90: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={},
        instructions=[(9923612, 'push {fp, lr}'), (9923732, 'strhteq r8, [lr], -0xe0')],
        calls=[(9923696, 'bl method.Vector2.Vector2_float__float_'), (9923716, 'bl method.Vector2.operator_Vector2_')],
        branches=[],
        semantics=('[Boat -[renderPos]] (imp 0x00976c1c, 31w): -[renderPos] (0x976c1c, 31w, 2c, Vector2-return, trimmed at next IMP): `floatPos@24 + Vector2(0.0f, -0.3f)` (0xbe99999a built with movw/movt) -- the render origin sits 0.3 below the float position..\n'),
    ),
    dict(
        name='bo_21',
        method='Boat -[requiresFuel]',
        types='c8@0:4',
        start=9928076,
        end=9928104,
        disasm='disasm_worldtileloader_bo_21.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00977dc4; body trimmed at the next IMP 0x00977da8 Boat -[actsAsInteractionObject]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9928076, 'sub sp, sp, 8'), (9928100, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Boat -[requiresFuel]] (imp 0x00977d8c, 7w): -[requiresFuel] (0x977d8c, 7w): returns 0 (sxtb) -- sailboat, no fuel..\n'),
    ),
    dict(
        name='bo_22',
        method='Boat -[rideDirection]',
        types='i8@0:4',
        start=9927836,
        end=9928076,
        disasm='disasm_worldtileloader_bo_22.txt',
        base_add=9927844,
        base_literal=9928072,
        boundary='ARM.exidx end 0x00977d8c (listing bound); next ObjC IMP 0x00977d8c Boat -[requiresFuel]',
        selectors={},
        imports={},
        ivars={
                 0x977d80: (17163216, 'OBJC_IVAR_$_Boat.rider', 116),
                 0x977d84: (17163224, 'OBJC_IVAR_$_Boat.targetXSpeed', 100),
        },
        classes={},
        instructions=[(9927836, 'sub sp, sp, 0x1c'), (9928072, 'rsbeq r7, lr, r8, asr 28')],
        calls=[],
        branches=[(9927892, 'beq', 9928044), (9927944, 'ble', 9927960), (9927956, 'b', 9928032), (9928040, 'b', 9928052)],
        semantics=('[Boat -[rideDirection]] (imp 0x00977c9c, 60w): -[rideDirection] (0x977c9c, 60w, 4br, 0c): 0 when rider==nil; else +1 when targetXSpeed@100 > 2.0f, -1 when targetXSpeed < -2.0f, 0 otherwise (thresholds 2.0f = vmov.f32 #0x40000000 / -2.0f #0xc0000000; vcmpe.f32 + vmrs APSR)..\n'),
    ),
    dict(
        name='bo_23',
        method='Boat -[riderBodyYRotationForBlockhead:]',
        types='f12@0:4@8',
        start=9925880,
        end=9925948,
        disasm='disasm_worldtileloader_bo_23.txt',
        base_add=9925908,
        base_literal=9925944,
        boundary='ARM.exidx end 0x0097753c (listing bound); next ObjC IMP 0x0097753c Boat -[riderBodyZRotation]',
        selectors={},
        imports={},
        ivars={
                 0x977534: (17163168, 'OBJC_IVAR_$_Boat.bodyRotation', 88),
        },
        classes={},
        instructions=[(9925880, 'sub sp, sp, 0xc'), (9925944, 'invalid')],
        calls=[],
        branches=[],
        semantics=('[Boat -[riderBodyYRotationForBlockhead:]] (imp 0x009774f8, 17w): -[riderBodyYRotationForBlockhead:] (0x9774f8, 17w): returns self.bodyRotation@88 (float, vldr) -- the rider\'s body yaw follows the boat hull rotation; blockhead argument unused..\n'),
    ),
    dict(
        name='bo_24',
        method='Boat -[riderBodyZRotation]',
        types='f8@0:4',
        start=9925948,
        end=9925992,
        disasm='disasm_worldtileloader_bo_24.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00977568 (listing bound); next ObjC IMP 0x00977568 Boat -[cameraPosForBlockhead:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9925948, 'sub sp, sp, 0x10'), (9925988, 'andeq r0, r0, r0')],
        calls=[],
        branches=[],
        semantics=('[Boat -[riderBodyZRotation]] (imp 0x0097753c, 11w): -[riderBodyZRotation] (0x97753c, 11w): returns 0.0f (pool @0x977564) -- no roll..\n'),
    ),
    dict(
        name='bo_25',
        method='Boat -[riderDPadShouldAllowUpDown]',
        types='c8@0:4',
        start=9928464,
        end=9928492,
        disasm='disasm_worldtileloader_bo_25.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00977f44; body trimmed at the next IMP 0x00977f2c Boat -[.cxx_construct]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9928464, 'sub sp, sp, 8'), (9928488, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Boat -[riderDPadShouldAllowUpDown]] (imp 0x00977f10, 7w): -[riderDPadShouldAllowUpDown] (0x977f10, 7w): returns 0 (sxtb) -- steering is left/right only..\n'),
    ),
    dict(
        name='bo_26',
        method='Boat -[riderDPadShouldGiveDiscreteValues]',
        types='c8@0:4',
        start=9924044,
        end=9924072,
        disasm='disasm_worldtileloader_bo_26.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00976de8 (listing bound); next ObjC IMP 0x00976de8 Boat -[addRider:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9924044, 'sub sp, sp, 8'), (9924068, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Boat -[riderDPadShouldGiveDiscreteValues]] (imp 0x00976dcc, 7w): -[riderDPadShouldGiveDiscreteValues] (0x976dcc, 7w): returns 0 (sxtb) -- the steering input is analog, not discrete..\n'),
    ),
    dict(
        name='bo_27',
        method='Boat -[riderPosForBlockhead:]',
        types='{Vector=[4f]}12@0:4@8',
        start=9923736,
        end=9923928,
        disasm='disasm_worldtileloader_bo_27.txt',
        base_add=9923752,
        base_literal=9923924,
        boundary='ARM.exidx end 0x00976dcc; body trimmed at the next IMP 0x00976d58 Boat -[setTargetVelocity:]',
        selectors={},
        imports={},
        ivars={
                 0x976d50: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={},
        instructions=[(9923736, 'push {fp, lr}'), (9923924, 'rsbeq r8, lr, r4, asr 28')],
        calls=[(9923800, 'bl method.Vector2.operator_float__'), (9923836, 'bl method.Vector2.operator_float__'), (9923892, 'bl method.Vector.Vector_float__float__float_')],
        branches=[],
        semantics=('[Boat -[riderPosForBlockhead:]] (imp 0x00976c98, 48w): -[riderPosForBlockhead:] (0x976c98, 48w, 3c, Vector-return): `Vector(floatPos.x, floatPos.y - 0.4 - 0.5, -0.75f)` (f64 0.4 @0x976d48 and 0.5 = vmov.f64 #96 subtracted from the double-promoted floatPos.y; z = 0xbf400000); blockhead argument unused..\n'),
    ),
    dict(
        name='bo_28',
        method='Boat -[setNeedsRemoved:]',
        types='v12@0:4c8',
        start=9927544,
        end=9927808,
        disasm='disasm_worldtileloader_bo_28.txt',
        base_add=9927560,
        base_literal=9927804,
        boundary='ARM.exidx end 0x00977c80 (listing bound); next ObjC IMP 0x00977c80 Boat -[jumpsOnSwipe]',
        selectors={
                 0x977c68: (15220080, 'stopRiding'),
                 0x977c74: (15220188, 'setNeedsRemoved:'),
        },
        imports={
                 0x977c64: (17151904, 'objc_msgSend'),
                 0x977c70: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0x977c60: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0x977c6c: (17163216, 'OBJC_IVAR_$_Boat.rider', 116),
        },
        classes={
                 0x977c78: (15252948, 'OBJC_CLASS_$_Boat'),
        },
        instructions=[(9927544, 'push {r4, sl, fp, lr}'), (9927804, 'rsbeq r7, lr, r4, ror 30')],
        calls=[(9927688, 'blx r2'), (9927764, 'blx r3')],
        branches=[(9927588, 'beq', 9927692), (9927624, 'bne', 9927692)],
        semantics=('[Boat -[setNeedsRemoved:]] (imp 0x00977b78, 66w): -[setNeedsRemoved:] (0x977b78, 66w, 2br, 2c): `if (flag && !self.needsRemoved@48) [self.rider@116 stopRiding];` then [super setNeedsRemoved:flag] (msgSendSuper2, super2{Boat})..\n'),
    ),
    dict(
        name='bo_29',
        method='Boat -[setTargetVelocity:]',
        types='v16@0:4{Vector2=[2f]}8',
        start=9923928,
        end=9924044,
        disasm='disasm_worldtileloader_bo_29.txt',
        base_add=9923944,
        base_literal=9924040,
        boundary='ARM.exidx end 0x00976dcc (listing bound); next ObjC IMP 0x00976dcc Boat -[riderDPadShouldGiveDiscreteValues]',
        selectors={},
        imports={},
        ivars={
                 0x976dc4: (17163224, 'OBJC_IVAR_$_Boat.targetXSpeed', 100),
        },
        classes={},
        instructions=[(9923928, 'push {fp, lr}'), (9924040, 'rsbeq r8, lr, r4, lsl 27')],
        calls=[(9923976, 'bl method.Vector2.operator_float__')],
        branches=[],
        semantics=('[Boat -[setTargetVelocity:]] (imp 0x00976d58, 29w): -[setTargetVelocity:] (0x976d58, 29w, 1c): `targetXSpeed@100 = v.x * 6.0f` (0x40c00000) where v is the Vector2 passed by value (operator float* then vmul.f32). DPad input scale = 6..\n'),
    ),
    dict(
        name='bo_30',
        method='Boat -[swipeUpGesture]',
        types='v8@0:4',
        start=9925860,
        end=9925880,
        disasm='disasm_worldtileloader_bo_30.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x009774f8 (listing bound); next ObjC IMP 0x009774f8 Boat -[riderBodyYRotationForBlockhead:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9925860, 'sub sp, sp, 8'), (9925876, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Boat -[swipeUpGesture]] (imp 0x009774e4, 5w): -[swipeUpGesture] (0x9774e4, 5w): empty void body (stores args, returns) -- no swipe-up handler..\n'),
    ),
    dict(
        name='bo_31',
        method='Boat -[tapIsWithinBodyRadius:]',
        types='c16@0:4{Vector2=[2f]}8',
        start=9926520,
        end=9927544,
        disasm='disasm_worldtileloader_bo_31.txt',
        base_add=9926536,
        base_literal=9927540,
        boundary='ARM.exidx end 0x00977b78 (listing bound); next ObjC IMP 0x00977b78 Boat -[setNeedsRemoved:]',
        selectors={
                 0x977b64: (15220176, 'worldWidthMacro'),
        },
        imports={},
        ivars={
                 0x977b58: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x977b60: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(9926520, 'push {r4, sl, fp, lr}'), (9927540, 'rsbeq r8, lr, r4, ror 6')],
        calls=[(9926580, 'bl method.Vector2.operator_float__'), (9926624, 'bl method.Vector2.operator_float__'), (9926676, 'bl loc.imp.objc_msgSend'), (9926700, 'bl sym.imp.__aeabi_idiv'), (9926744, 'bl method.Vector2.operator_float__'), (9926788, 'bl method.Vector2.operator_float__'), (9926840, 'bl loc.imp.objc_msgSend'), (9926904, 'bl method.Vector2.operator_float__'), (9926948, 'bl method.Vector2.operator_float__'), (9927000, 'bl loc.imp.objc_msgSend'), (9927016, 'bl sym.imp.__aeabi_idiv'), (9927060, 'bl method.Vector2.operator_float__'), (9927104, 'bl method.Vector2.operator_float__'), (9927156, 'bl loc.imp.objc_msgSend'), (9927200, 'bl method.Vector2.operator_float__'), (9927236, 'bl method.Vector2.operator_float__'), (9927324, 'bl method.Vector2.operator_float__'), (9927364, 'bl method.Vector2.operator_float__'), (9927404, 'bl method.Vector2.operator_float__'), (9927444, 'bl method.Vector2.operator_float__')],
        branches=[(9926724, 'blt', 9926880), (9926876, 'b', 9927264), (9927040, 'bpl', 9927196), (9927192, 'b', 9927256), (9927292, 'bpl', 9927492), (9927316, 'ble', 9927492), (9927396, 'ble', 9927492), (9927476, 'bpl', 9927492), (9927488, 'b', 9927500)],
        semantics=('[Boat -[tapIsWithinBodyRadius:]] (imp 0x00977778, 256w): -[tapIsWithinBodyRadius:] (0x977778, 256w, 9br, 20c): wrapped containment test for taps. `dx = tap.x - floatPos@24.x`; `halfW = (float)(([world@4 worldWidthMacro] * 32) / 2)` (`lsl r0,r0,5` + __aeabi_idiv by 2); wrap once: `if (dx >= halfW) dx -= worldWidthMacro*32; else if (dx < -halfW) dx += worldWidthMacro*32;` (negated denominator via `rsb r0, r0, 0`). Returns YES only when -0.5 < dx < 0.5 (f64 0.5 = vmov.f64 #96; vcmpe.f64 + vmrs/bpl/ble) and `floatPos.y - 0.5 < tap.y < floatPos.y + 0.5`. Tap Vector2 arrives by value in r2/r3..\n'),
    ),
    dict(
        name='bo_32',
        method='Boat -[updateNetDataForClient:]',
        types='@12@0:4@8',
        start=9882368,
        end=9882452,
        disasm='disasm_worldtileloader_bo_32.txt',
        base_add=9882384,
        base_literal=9882448,
        boundary='ARM.exidx end 0x0096cb54 (listing bound); next ObjC IMP 0x0096cb54 Boat -[dealloc]',
        selectors={
                 0x96cb4c: (15220132, 'creationNetDataForClient:'),
        },
        imports={
                 0x96cb48: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9882368, 'push {fp, lr}'), (9882448, 'invalid')],
        calls=[(9882428, 'blx ip')],
        branches=[],
        semantics=('[Boat -[updateNetDataForClient:]] (imp 0x0096cb00, 21w): -[updateNetDataForClient:] (0x96cb00, 21w, 1c): pure forward -- returns [self creationNetDataForClient:client] (arg passed through; no wrapping)..\n'),
    ),
    dict(
        name='bo_33',
        method='Boat -[updatePosition:]',
        types='v16@0:4{?=ii}8',
        start=9886932,
        end=9887328,
        disasm='disasm_worldtileloader_bo_33.txt',
        base_add=9886948,
        base_literal=9887320,
        boundary='ARM.exidx end 0x0096de60 (listing bound); next ObjC IMP 0x0096de60 Boat -[update:accurateDT:isSimulation:]',
        selectors={
                 0x96de3c: (15220152, 'isNet'),
                 0x96de44: (15220164, 'markCircumNavigateX:'),
                 0x96de54: (15220168, 'updatePosition:'),
        },
        imports={
                 0x96de38: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x96de34: (17163216, 'OBJC_IVAR_$_Boat.rider', 116),
                 0x96de40: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x96de48: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={
                 0x96de4c: (15252948, 'OBJC_CLASS_$_Boat'),
        },
        instructions=[(9886932, 'push {r4, sl, fp, lr}'), (9887324, 'andeq r0, r0, r0')],
        calls=[(9887068, 'blx r2'), (9887192, 'blx r3'), (9887272, 'bl loc.imp.objc_msgSendSuper2')],
        branches=[(9887004, 'beq', 9887196), (9887080, 'bne', 9887196), (9887120, 'beq', 9887196)],
        semantics=('[Boat -[updatePosition:]] (imp 0x0096dcd4, 99w): -[updatePosition:] (0x96dcd4, 99w, 3br, 3c): `if (self.rider@116 && ![self.rider isNet] && newPos.x != self.pos@16.x) [self.world@4 markCircumNavigateX:newPos.x];` then [super updatePosition:newPos] (msgSendSuper2, super2{Boat}). Marks the world\'s circum-navigation map only when the boat is locally ridden..\n'),
    ),
    dict(
        name='bo_34',
        method='Boat -[worldChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=9926420,
        end=9926444,
        disasm='disasm_worldtileloader_bo_34.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0097772c (listing bound); next ObjC IMP 0x0097772c Boat -[actionTitle]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9926420, 'sub sp, sp, 0xc'), (9926440, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Boat -[worldChanged:]] (imp 0x00977714, 6w): -[worldChanged:] (0x977714, 6w): empty void stub (stores args, returns); the boat reacts to no world-changed notifications in this body..\n'),
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
        'batch': 'Boat (E148): the sailing boat; 35 bodies',
        'claim': ('the sailing boat (mast/sail geometry, sailing physics, remote round-trip)'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'boat.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale boat.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
