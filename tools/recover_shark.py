#!/usr/bin/env python3
"""Hash-gated recovery of the Shark (E140).

Shark lands: the batch sweeps shark surface:
47 bodies, 15370 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/SHARK.md for the prose and boundaries.
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
    'bl 0x7c83e4': 0x007c83e4,
    'bl 0x7d49c8': 0x007d49c8,
    'bl 0x7d4a3c': 0x007d4a3c,
    'bl 0x7d4bf4': 0x007d4bf4,
    'bl 0x7d4ddc': 0x007d4ddc,
    'bl 0x7d5174': 0x007d5174,
    'bl 0x7d550c': 0x007d550c,
    'bl 0x7d58a4': 0x007d58a4,
    'bl 0x7d5b58': 0x007d5b58,
    'bl 0x7d5b94': 0x007d5b94,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl loc.imp.objc_msgSendSuper2_stret': 0x001c335c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector.Vector_float__float__float__float_': 0x004d0d08,
    'bl method.Vector.operator_float__': 0x004b5c08,
    'bl method.Vector2.Vector2__': 0x004d5170,
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl method.Vector2.operator_Vector2_': 0x004d0418,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl sym.Vector::operator_Vector_': 0x0058198c,
    'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_': 0x00a15404,
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
    'bl sym.imp.sinf': 0x001c2b34,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.seasonForWorldX_int__double__World_': 0x00a14a48,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileAtWorldPosition_int__int__MacroTile__World_': 0x00a16e68,
    'bl sym.tileIsSolid_Tile_': 0x00a1179c,
    'bl sym.tileIsWater_Tile_': 0x00a11690,
}

SPECS = [
    dict(
        name='sh_00',
        method='Shark -[.cxx_construct]',
        types='@8@0:4',
        start=8248000,
        end=8248124,
        disasm='disasm_worldtileloader_sh_00.txt',
        base_add=8248016,
        base_literal=8248120,
        boundary='ARM.exidx end 0x007ddb3c (listing bound); next ObjC IMP 0x007de158 CoffeeTree -[objectType]',
        selectors={},
        imports={},
        ivars={
                 0x7ddb30: (17160704, 'OBJC_IVAR_$_Shark.riderTargetVelocity', 388),
                 0x7ddb34: (17160676, 'OBJC_IVAR_$_Shark.namePosition', 336),
        },
        classes={},
        instructions=[(8248000, 'push {fp, lr}'), (8248120, 'addeq r2, r8, ip, lsl r0')],
        calls=[(8248052, 'bl method.Vector2.Vector2__'), (8248088, 'bl method.Vector2.Vector2__')],
        branches=[],
        semantics=('[Shark -[.cxx_construct]] (imp 0x007ddac0, 31w): -[.cxx_construct] (0x7ddac0, 31w): ObjC++ ivar constructor; default-constructs the two Vector2 ivars in place via Vector2::Vector2() (method.Vector2.Vector2__ x2): namePosition @336 (cell 0x7ddb34) then riderTargetVelocity @388 (cell 0x7ddb30). No sends, no literals..\n'),
    ),
    dict(
        name='sh_01',
        method='Shark -[addRider:]',
        types='v12@0:4@8',
        start=8246992,
        end=8247248,
        disasm='disasm_worldtileloader_sh_01.txt',
        base_add=8247008,
        base_literal=8247244,
        boundary='ARM.exidx end 0x007dd7d0 (listing bound); next ObjC IMP 0x007dd7d0 Shark -[removeRider:]',
        selectors={
                 0x7dd7b8: (15210708, 'addRider:'),
        },
        imports={
                 0x7dd7b4: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0x7dd7c0: (17157392, 'OBJC_IVAR_$_NPC.beingControlled', 128),
                 0x7dd7c8: (17160704, 'OBJC_IVAR_$_Shark.riderTargetVelocity', 388),
        },
        classes={
                 0x7dd7bc: (15252820, 'OBJC_CLASS_$_Shark'),
        },
        instructions=[(8246992, 'push {r4, r5, fp, lr}'), (8247244, 'addeq r2, r8, ip, lsl 8')],
        calls=[(8247084, 'blx lr'), (8247184, 'bl method.Vector2.Vector2_float__float_')],
        branches=[(8247120, 'bne', 8247212)],
        semantics=('[Shark -[addRider:]] (imp 0x007dd6d0, 64w): -[addRider:] (0x7dd6d0, 64w): objc_msgSendSuper2 [super addRider:rider] (struct {self, OBJC_CLASS_$_Shark} via cell 0x7dd7bc, selector cell 0x7dd7b8 = \'addRider:\'); then if the byte ivar NPC.beingControlled @128 (cell 0x7dd7c0, ldrsb) == 0, sets self.riderTargetVelocity @388 (cell 0x7dd7c8) = Vector2(0.0f, 0.0f) via Vector2::Vector2(float,float) + 2-word store; pool 0x7dd7c4 = 0x0..\n'),
    ),
    dict(
        name='sh_02',
        method='Shark -[blockheadCanRide:usingItem:]',
        types='c16@0:4@8i12',
        start=8247564,
        end=8247916,
        disasm='disasm_worldtileloader_sh_02.txt',
        base_add=8247580,
        base_literal=8247912,
        boundary='ARM.exidx end 0x007dda6c (listing bound); next ObjC IMP 0x007dda6c Shark -[jumpsOnSwipe]',
        selectors={
                 0x7dda54: (15210716, 'minRidableAge'),
                 0x7dda5c: (15210380, 'belongsToPlayerWithBlockhead:'),
        },
        imports={
                 0x7dda50: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x7dda58: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0x7dda60: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0x7dda64: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
        },
        classes={},
        instructions=[(8247564, 'push {r4, r5, r6, sl, fp, lr}'), (8247912, 'ldrdeq r2, r3, [r8], r0')],
        calls=[(8247664, 'blx r4'), (8247752, 'blx r3')],
        branches=[(8247692, 'ble', 8247868), (8247772, 'beq', 8247868), (8247816, 'bne', 8247868)],
        semantics=('[Shark -[blockheadCanRide:usingItem:]] (imp 0x007dd90c, 88w): -[blockheadCanRide:usingItem:] (0x7dd90c, 88w): ride gate. age = self.age (NPC @88, vldr float); if (age <= [self minRidableAge] (float returned in r0)) return NO; if (![self belongsToPlayerWithBlockhead:blockhead]) return NO; if (self.dead @56) return NO; return !self.needsRemoved (@48). The usingItem int arg is not used. Selector cells 0x7dda54 minRidableAge / 0x7dda5c belongsToPlayerWithBlockhead:..\n'),
    ),
    dict(
        name='sh_03',
        method='Shark -[blockheadUnloaded:]',
        types='v12@0:4@8',
        start=8244968,
        end=8245384,
        disasm='disasm_worldtileloader_sh_03.txt',
        base_add=8244984,
        base_literal=8245380,
        boundary='ARM.exidx end 0x007dd088 (listing bound); next ObjC IMP 0x007dd088 Shark -[reactToBeingFed]',
        selectors={
                 0x7dd068: (15210424, 'release'),
                 0x7dd07c: (15210696, 'blockheadUnloaded:'),
        },
        imports={
                 0x7dd064: (17151904, 'objc_msgSend'),
                 0x7dd078: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0x7dd060: (17160624, 'OBJC_IVAR_$_Shark.attackBlockhead', 380),
                 0x7dd06c: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0x7dd074: (17160704, 'OBJC_IVAR_$_Shark.riderTargetVelocity', 388),
        },
        classes={
                 0x7dd080: (15252820, 'OBJC_CLASS_$_Shark'),
        },
        instructions=[(8244968, 'push {r4, sl, fp, lr}'), (8245380, 'strdeq r2, r3, [r8], r4')],
        calls=[(8245108, 'blx r3'), (8245236, 'bl method.Vector2.Vector2_float__float_'), (8245332, 'blx r3')],
        branches=[(8245036, 'bne', 8245136), (8245172, 'bne', 8245264)],
        semantics=('[Shark -[blockheadUnloaded:]] (imp 0x007dcee8, 104w): -[blockheadUnloaded:] (0x7dcee8, 104w): if (blockhead == self.attackBlockhead @380 (cell 0x7dd060)) { objc_msgSend(self.attackBlockhead,\'release\')(cell 0x7dd068); self.attackBlockhead = nil; } if (blockhead == self.rider @132 (cell 0x7dd06c)) { self.riderTargetVelocity @388 (cell 0x7dd074) = Vector2(0.0f,0.0f) (pool 0x7dd070 = 0.0); } then [super blockheadUnloaded:blockhead] via msgSendSuper2 (cells 0x7dd07c/0x7dd080)..\n'),
    ),
    dict(
        name='sh_04',
        method='Shark -[cameraPosForBlockhead:]',
        types='{Vector2=[2f]}12@0:4@8',
        start=8246492,
        end=8246592,
        disasm='disasm_worldtileloader_sh_04.txt',
        base_add=8246508,
        base_literal=8246588,
        boundary='ARM.exidx end 0x007dd540 (listing bound); next ObjC IMP 0x007dd540 Shark -[riderBodyYRotationForBlockhead:]',
        selectors={
                 0x7dd534: (15210704, 'cameraPosForBlockhead:'),
        },
        imports={},
        ivars={},
        classes={
                 0x7dd538: (15252820, 'OBJC_CLASS_$_Shark'),
        },
        instructions=[(8246492, 'push {r4, sl, fp, lr}'), (8246588, 'addeq r2, r8, r0, lsl 12')],
        calls=[(8246568, 'bl loc.imp.objc_msgSendSuper2_stret')],
        branches=[],
        semantics=('[Shark -[cameraPosForBlockhead:]] (imp 0x007dd4dc, 25w): -[cameraPosForBlockhead:] (0x7dd4dc, 25w): pure forward [super cameraPosForBlockhead:blockhead] via objc_msgSendSuper2_stret returning Vector2 (superstruct {self, OBJC_CLASS_$_Shark} cells 0x7dd538/0x7dd534-class; selector cell 0x7dd534)..\n'),
    ),
    dict(
        name='sh_05',
        method='Shark -[canBeCapturedByBlockhead:withItemType:]',
        types='c16@0:4@8i12',
        start=8155880,
        end=8156164,
        disasm='disasm_worldtileloader_sh_05.txt',
        base_add=8155896,
        base_literal=8156160,
        boundary='ARM.exidx end 0x007c7404 (listing bound); next ObjC IMP 0x007c7404 Shark -[cantBeCapturedTipStringForBlockhead:withItemType:]',
        selectors={
                 0x7c73f8: (15210376, 'tamed'),
                 0x7c73fc: (15210380, 'belongsToPlayerWithBlockhead:'),
        },
        imports={
                 0x7c73f4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x7c73f0: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
        },
        classes={},
        instructions=[(8155880, 'push {fp, lr}'), (8156160, 'strdeq r8, sb, [sb], r4')],
        calls=[(8156024, 'blx r2'), (8156088, 'blx r3')],
        branches=[(8155928, 'bne', 8156120), (8155980, 'bpl', 8156116), (8156036, 'beq', 8156104), (8156100, 'beq', 8156116), (8156112, 'b', 8156128), (8156116, 'b', 8156120)],
        semantics=('[Shark -[canBeCapturedByBlockhead:withItemType:]] (imp 0x007c72e8, 71w): -[canBeCapturedByBlockhead:withItemType:] (0x7c72e8, 71w): return itemType == 0x66 (102, the capture item) && age (NPC @88) < 4500.0f (pool 0x7c73ec == minRidableAge) && ( ![self tamed] || [self belongsToPlayerWithBlockhead:blockhead] ). Selector cells 0x7c73f8 \'tamed\', 0x7c73fc \'belongsToPlayerWithBlockhead:\'..\n'),
    ),
    dict(
        name='sh_06',
        method='Shark -[cantBeCapturedTipStringForBlockhead:withItemType:]',
        types='@16@0:4@8i12',
        start=8156164,
        end=8156848,
        disasm='disasm_worldtileloader_sh_06.txt',
        base_add=8156180,
        base_literal=8156840,
        boundary='ARM.exidx end 0x007c76b0 (listing bound); next ObjC IMP 0x007c76b0 Shark -[loadDerivedStuff]',
        selectors={
                 0x7c7684: (15210388, 'stringWithFormat:'),
                 0x7c7688: (15210384, 'speciesName'),
                 0x7c7698: (15210376, 'tamed'),
                 0x7c769c: (15210380, 'belongsToPlayerWithBlockhead:'),
        },
        imports={
                 0x7c767c: (16322232, '__CFConstantStringClassReference'),
                 0x7c7680: (17151904, 'objc_msgSend'),
                 0x7c76a0: (16322216, '__CFConstantStringClassReference'),
                 0x7c76a4: (16322200, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x7c7694: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
        },
        classes={
                 0x7c768c: (15247156, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(8156164, 'push {r4, r5, fp, lr}'), (8156844, 'andeq r0, r0, r0')],
        calls=[(8156348, 'blx r2'), (8156384, 'blx ip'), (8156436, 'blx r2'), (8156500, 'blx r3'), (8156596, 'blx r2'), (8156632, 'blx ip'), (8156728, 'blx r2'), (8156764, 'blx ip')],
        branches=[(8156212, 'bne', 8156648), (8156264, 'ble', 8156396), (8156392, 'b', 8156784), (8156448, 'beq', 8156644), (8156512, 'bne', 8156644), (8156640, 'b', 8156784), (8156644, 'b', 8156776), (8156772, 'b', 8156784)],
        semantics=('[Shark -[cantBeCapturedTipStringForBlockhead:withItemType:]] (imp 0x007c7404, 171w): -[cantBeCapturedTipStringForBlockhead:withItemType:] (0x7c7404, 171w): returns the refusal tip NSString or nil. itemType != 0x66 -> [NSString stringWithFormat:@"%@S CAN ONLY BE CAPTURED\\nIN A BUCKET", [self speciesName]] (CFString obj 0xF90EB8); itemType == 0x66: if age > 4500.0f (pool 0x7c7690) -> fmt 0xF90E98 "THAT %@ IS TOO BIG\\nTO BE CAPTURED" with speciesName; else if (![self tamed]) nil; else if ([self belongsToPlayerWithBlockhead:blockhead]) nil; else fmt 0xF90EA8 "THAT %@ BELONGS TO\\nSOMEONE ELSE". [NSString class] via cell 0x7c768c; stringWithFormat: cell 0x7c7684..\n'),
    ),
    dict(
        name='sh_07',
        method='Shark -[captureRequiredItemType]',
        types='i8@0:4',
        start=8155852,
        end=8155880,
        disasm='disasm_worldtileloader_sh_07.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x007c72e8 (listing bound); next ObjC IMP 0x007c72e8 Shark -[canBeCapturedByBlockhead:withItemType:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8155852, 'sub sp, sp, 8'), (8155876, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Shark -[captureRequiredItemType]] (imp 0x007c72cc, 7w): -[captureRequiredItemType] (0x7c72cc, 7w): returns 0x66 (102) via movw r2,0x66; mov r0,r2..\n'),
    ),
    dict(
        name='sh_08',
        method='Shark -[capturedItemType]',
        types='i8@0:4',
        start=8155824,
        end=8155852,
        disasm='disasm_worldtileloader_sh_08.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x007c72e8; body trimmed at the next IMP 0x007c72cc Shark -[captureRequiredItemType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8155824, 'sub sp, sp, 8'), (8155848, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Shark -[capturedItemType]] (imp 0x007c72b0, 7w): -[capturedItemType] (0x7c72b0, 7w): returns 0x9f (159)..\n'),
    ),
    dict(
        name='sh_09',
        method='Shark -[center]',
        types='{Vector2=[2f]}8@0:4',
        start=8244536,
        end=8244968,
        disasm='disasm_worldtileloader_sh_09.txt',
        base_add=8244552,
        base_literal=8244964,
        boundary='ARM.exidx end 0x007dcee8 (listing bound); next ObjC IMP 0x007dcee8 Shark -[blockheadUnloaded:]',
        selectors={
                 0x7dced0: (15210692, 'renderPos'),
                 0x7dcedc: (15210536, 'maxAge'),
        },
        imports={
                 0x7dced8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x7dced4: (17160620, 'OBJC_IVAR_$_Shark.bodyRotation', 304),
                 0x7dcee0: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
        },
        classes={},
        instructions=[(8244536, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8244964, 'addeq r2, r8, r4, lsr 27')],
        calls=[(8244700, 'blx r6'), (8244852, 'bl loc.imp.objc_msgSend_stret'), (8244888, 'bl sym.imp.memset'), (8244904, 'bl method.Vector2.Vector2_float__float_'), (8244924, 'bl method.Vector2.operator_Vector2_')],
        branches=[(8244836, 'beq', 8244860), (8244856, 'b', 8244892)],
        semantics=('[Shark -[center]] (imp 0x007dcd38, 108w): -[center] (0x7dcd38, 108w): center = [self renderPos] (Vector2 sret via objc_msgSend_stret) + Vector2(v, 0) where v = ((age/maxAge)*1.5 + 0.25) * (-bodyRotation @304 / (pi/2)); t=age/maxAge via objc_msgSend(self,\'maxAge\'); gl truth: d1=1.0 d2=0.25 d3=1.5 (r2 comments wrong, 0.25/1.5); pi/2 double @0x7dcec8 = 0x3FF921FB54442D18; result via Vector2::Vector2 + Vector2::operator+(Vector2)..\n'),
    ),
    dict(
        name='sh_10',
        method='Shark -[creationDataStructSize]',
        types='L8@0:4',
        start=8163568,
        end=8163596,
        disasm='disasm_worldtileloader_sh_10.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x007c910c (listing bound); next ObjC IMP 0x007c910c Shark -[updateNetDataForClient:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8163568, 'sub sp, sp, 8'), (8163592, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Shark -[creationDataStructSize]] (imp 0x007c90f0, 7w): -[creationDataStructSize] (0x7c90f0, 7w): returns 0x78 (120) - the creation net blob length used by creationNetDataForClient: (npc 0x48 + sharkUpdate 0x28 + attackBlockhead uid 8)..\n'),
    ),
    dict(
        name='sh_11',
        method='Shark -[creationNetDataForClient:]',
        types='@12@0:4@8',
        start=8162864,
        end=8163568,
        disasm='disasm_worldtileloader_sh_11.txt',
        base_add=8162880,
        base_literal=8163564,
        boundary='ARM.exidx end 0x007c90f0 (listing bound); next ObjC IMP 0x007c90f0 Shark -[creationDataStructSize]',
        selectors={
                 0x7c90c4: (15210464, 'npcCreationNetDataForClient:'),
                 0x7c90c8: (15210468, 'sharkUpdateNetDataForClient:'),
                 0x7c90d8: (15210472, 'uniqueID'),
                 0x7c90e0: (15210480, 'appendNPCCreationDataToData:'),
                 0x7c90e4: (15210476, 'dataWithBytes:length:'),
        },
        imports={
                 0x7c90dc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x7c90cc: (17160624, 'OBJC_IVAR_$_Shark.attackBlockhead', 380),
                 0x7c90d0: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
        },
        classes={
                 0x7c90e8: (15247168, 'OBJC_CLASS_$_NSData'),
        },
        instructions=[(8162864, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8163564, 'addeq r6, sb, ip, lsr 25')],
        calls=[(8162968, 'bl loc.imp.objc_msgSend_stret'), (8163004, 'bl sym.imp.memset'), (8163060, 'bl sym.imp.memcpy'), (8163132, 'bl loc.imp.objc_msgSend_stret'), (8163168, 'bl sym.imp.memset'), (8163380, 'bl loc.imp.objc_msgSend'), (8163476, 'blx ip'), (8163504, 'blx r3')],
        branches=[(8162948, 'beq', 8162976), (8162972, 'b', 8163008), (8163112, 'beq', 8163140), (8163136, 'b', 8163172), (8163304, 'beq', 8163392), (8163340, 'bne', 8163392)],
        semantics=('[Shark -[creationNetDataForClient:]] (imp 0x007c8e30, 176w): -[creationNetDataForClient:] (0x7c8e30, 176w): builds the 0x78-byte creation blob in a local buffer: [0..0x48) = objc_msgSend_stret buffer from [self npcCreationNetDataForClient:arg] (cell 0x7c90c4); [0x48..0x70) = 0x28-byte copy of [self sharkUpdateNetDataForClient:arg] (cell 0x7c90c8); [0x70..0x78) = 8 bytes from [self.attackBlockhead @380 uniqueID] when attackBlockhead != nil && !self.isNet @52, else zero; returns [self appendNPCCreationDataToData:[NSData dataWithBytes:buf length:0x78]] (cells 0x7c90e0/0x7c90e4/NSData 0x7c90e8)..\n'),
    ),
    dict(
        name='sh_12',
        method='Shark -[dealloc]',
        types='v8@0:4',
        start=8163832,
        end=8164460,
        disasm='disasm_worldtileloader_sh_12.txt',
        base_add=8163848,
        base_literal=8164456,
        boundary='ARM.exidx end 0x007c946c (listing bound); next ObjC IMP 0x007c946c Shark -[remoteCreationDataUpdate:]',
        selectors={
                 0x7c9434: (15210484, 'dealloc'),
                 0x7c9440: (15210424, 'release'),
        },
        imports={
                 0x7c9430: (17151900, 'objc_msgSendSuper2'),
                 0x7c943c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x7c9444: (17160624, 'OBJC_IVAR_$_Shark.attackBlockhead', 380),
                 0x7c9448: (17160528, 'OBJC_IVAR_$_Shark.tailFinBottomCube', 272),
                 0x7c944c: (17160532, 'OBJC_IVAR_$_Shark.tailFinTopCube', 268),
                 0x7c9450: (17160524, 'OBJC_IVAR_$_Shark.sideFinCube', 264),
                 0x7c9454: (17160536, 'OBJC_IVAR_$_Shark.topFinCube', 260),
                 0x7c9458: (17160540, 'OBJC_IVAR_$_Shark.headBottomCube', 256),
                 0x7c945c: (17160544, 'OBJC_IVAR_$_Shark.headTopCube', 252),
                 0x7c9460: (17160548, 'OBJC_IVAR_$_Shark.bodyBackCube', 248),
                 0x7c9464: (17160552, 'OBJC_IVAR_$_Shark.bodyFrontCube', 244),
        },
        classes={
                 0x7c9438: (15252820, 'OBJC_CLASS_$_Shark'),
        },
        instructions=[(8163832, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8164456, 'addeq r6, sb, r4, ror 17')],
        calls=[(8164060, 'blx r5'), (8164096, 'blx r3'), (8164132, 'blx r3'), (8164168, 'blx r3'), (8164204, 'blx r3'), (8164240, 'blx r3'), (8164276, 'blx r3'), (8164312, 'blx r3'), (8164348, 'blx r3'), (8164388, 'blx r2')],
        branches=[],
        semantics=('[Shark -[dealloc]] (imp 0x007c91f8, 157w): -[dealloc] (0x7c91f8, 157w): releases 9 owned objects in order bodyFrontCube @244, headBottomCube @256, headTopCube @252, bodyBackCube @248, topFinCube @260, sideFinCube @264, tailFinTopCube @268, tailFinBottomCube @272 (selector \'release\'), attackBlockhead @380; then objc_msgSendSuper2 [super dealloc]. Textures/shader not released here..\n'),
    ),
    dict(
        name='sh_13',
        method='Shark -[die:]',
        types='v12@0:4@8',
        start=8216916,
        end=8217316,
        disasm='disasm_worldtileloader_sh_13.txt',
        base_add=8216932,
        base_literal=8217312,
        boundary='ARM.exidx end 0x007d62e4 (listing bound); next ObjC IMP 0x007d62e4 Shark -[isUnderLocalControl]',
        selectors={
                 0x7d62b8: (15210508, 'instance'),
                 0x7d62bc: (15210512, 'multiSoundNamed:'),
                 0x7d62c8: (15210576, 'playAtPosition:afterDelay:'),
                 0x7d62d0: (15210580, 'die:'),
        },
        imports={
                 0x7d62c0: (16322520, '__CFConstantStringClassReference'),
                 0x7d62cc: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0x7d62ac: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0x7d62c4: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x7d62dc: (17160604, 'OBJC_IVAR_$_Shark.travelFraction', 296),
        },
        classes={
                 0x7d62b0: (15247172, 'OBJC_CLASS_$_MJSoundManager'),
                 0x7d62d4: (15252820, 'OBJC_CLASS_$_Shark'),
        },
        instructions=[(8216916, 'push {r4, r5, fp, lr}'), (8217312, 'addeq sb, r8, r8, lsl 19')],
        calls=[(8217032, 'bl loc.imp.objc_msgSend'), (8217056, 'bl loc.imp.objc_msgSend'), (8217136, 'bl loc.imp.objc_msgSend'), (8217244, 'blx r3')],
        branches=[(8216980, 'bne', 8217252), (8216996, 'beq', 8217140), (8217248, 'b', 8217252)],
        semantics=('[Shark -[die:]] (imp 0x007d6154, 100w): -[die:] (0x7d6154, 100w): if (!self.dead @56): if (arg != nil) { snd = [[MJSoundManager instance] multiSoundNamed:@"fishDie.wav" (CFString 0xF90FD8)]; [snd playAtPosition:self.floatPos @24 afterDelay:0.1] (double 0x3FB99999A0000000); } self.travelFraction @296 = 0.0f (pool 0x7d62d8); [super die:arg] via msgSendSuper2 (cells 0x7d62d0/0x7d62d4). Selector cells: instance 0x7d62b8, multiSoundNamed: 0x7d62bc, playAtPosition:afterDelay: 0x7d62c8..\n'),
    ),
    dict(
        name='sh_14',
        method='Shark -[doRemoteUpdate:]',
        types='v48@0:4{SharkUpdateNetData={NPCUpdateNetData={DynamicObjectNetData=QIIC[7C]}}IIsScc[2C]}8',
        start=8166736,
        end=8167824,
        disasm='disasm_worldtileloader_sh_14.txt',
        base_add=8166752,
        base_literal=8167820,
        boundary='ARM.exidx end 0x007ca190 (listing bound); next ObjC IMP 0x007ca190 Shark -[remoteUpdate:]',
        selectors={
                 0x7ca158: (15210524, 'isClient'),
                 0x7ca164: (15210492, 'isNet'),
        },
        imports={
                 0x7ca154: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x7ca15c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x7ca160: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0x7ca168: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0x7ca16c: (17160592, 'OBJC_IVAR_$_Shark.movementDirection', 276),
                 0x7ca170: (17160636, 'OBJC_IVAR_$_Shark.remoteMovementDirection', 408),
                 0x7ca174: (17160596, 'OBJC_IVAR_$_Shark.walkSpeed', 324),
                 0x7ca178: (17160640, 'OBJC_IVAR_$_Shark.remoteWalkSpeed', 404),
                 0x7ca180: (17160644, 'OBJC_IVAR_$_Shark.remoteGoalSquare', 396),
                 0x7ca184: (17160624, 'OBJC_IVAR_$_Shark.attackBlockhead', 380),
                 0x7ca188: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
        },
        classes={},
        instructions=[(8166736, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8167820, 'addeq r5, sb, ip, lsl 27')],
        calls=[(8166924, 'blx lr'), (8167040, 'blx r2'), (8167100, 'bl sym.makeIntpair_int__int_'), (8167396, 'blx r2'), (8167548, 'blx r2'), (8167608, 'bl sym.makeIntpair_int__int_')],
        branches=[(8166936, 'bne', 8167288), (8166976, 'beq', 8167284), (8167052, 'beq', 8167284), (8167284, 'b', 8167756), (8167332, 'beq', 8167424), (8167444, 'bne', 8167716), (8167484, 'beq', 8167564), (8167560, 'beq', 8167716)],
        semantics=('[Shark -[doRemoteUpdate:]] (imp 0x007c9d50, 272w): -[doRemoteUpdate:] (0x7c9d50, 272w): takes the 0x28-byte SharkUpdateNetData by value (r2:r3 + 8 stack words staged at fp-0x40; word6/7 = pos pair, (s16)w8 = walkSpeed*255, (u16)@0x22 = age, (s8)w9 = movementDirection). Non-client ([self.dynamicWorld @8 isClient]==0): if (self.rider @132 && [rider isNet]) { remoteGoalSquare @396 = {w6,w7} (makeIntpair); f = (s16)w8 / 255.0f (pool 0x7ca17c=255.0); remoteWalkSpeed @404 = f; walkSpeed @324 = f; d = (s8)w9; remoteMovementDirection @408 = d; movementDirection @276 = d; updateNeedsToBeSent @49 = 1; } else nothing. Client: if (!(rider && ![rider isNet])) and (attackBlockhead @380 == nil || [attackBlockhead isNet]) { remoteGoalSquare = {w6,w7}; remoteWalkSpeed = (s16)w8/255.0f; remoteMovementDirection = (s8)w9; } then self.age @88 = (float)(u16)struct[0x22]..\n'),
    ),
    dict(
        name='sh_15',
        method='Shark -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        types='v156@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76i140i144i148i152',
        start=8168416,
        end=8210888,
        disasm='disasm_worldtileloader_sh_15.txt',
        base_add=8168476,
        base_literal=8172396,
        boundary='ARM.exidx end 0x007d49c8 (listing bound); next ObjC IMP 0x007d6154 Shark -[die:]',
        selectors={
                 0x7cb64c: (15210532, 'worldWidthMacro'),
                 0x7cb688: (15210536, 'maxAge'),
                 0x7cb690: (15210540, 'macroTiles'),
                 0x7cf840: (15210544, 'program'),
                 0x7cf848: (15210556, 'intValue'),
                 0x7cf84c: (15210552, 'objectAtIndex:'),
                 0x7cf850: (15210548, 'uniformLocations'),
                 0x7cf854: (15210560, 'dayColor'),
                 0x7cf878: (15210508, 'instance'),
                 0x7cf884: (15210564, 'addParticleAtPos:velocity:color:gravityType:life:scale:'),
                 0x7cf890: (15210568, 'name'),
                 0x7cf898: (15210572, 'draw'),
                 0x7d49a8: (15210556, 'intValue'),
                 0x7d49ac: (15210552, 'objectAtIndex:'),
                 0x7d49b0: (15210548, 'uniformLocations'),
                 0x7d49b8: (15210572, 'draw'),
                 0x7d49c0: (15210568, 'name'),
        },
        imports={
                 0x7cb684: (17151904, 'objc_msgSend'),
                 0x7cf83c: (17151904, 'objc_msgSend'),
                 0x7d49a4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x7cb640: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x7cb648: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x7cb66c: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x7cb680: (17160648, 'OBJC_IVAR_$_Shark.isOnAirAboveSolidGround', 378),
                 0x7cb68c: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0x7cb694: (17160612, 'OBJC_IVAR_$_Shark.fromSquare', 280),
                 0x7cb698: (17157400, 'OBJC_IVAR_$_NPC.visible', 57),
                 0x7cb69c: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0x7cb6a0: (17160652, 'OBJC_IVAR_$_Shark.bubbleEmitTimer', 348),
                 0x7cb6a4: (17160596, 'OBJC_IVAR_$_Shark.walkSpeed', 324),
                 0x7cb6a8: (17160656, 'OBJC_IVAR_$_Shark.walkTimer', 320),
                 0x7cb6b0: (17160660, 'OBJC_IVAR_$_Shark.falling', 356),
                 0x7cb6b4: (17160664, 'OBJC_IVAR_$_Shark.bobTimer', 328),
                 0x7cbf50: (17160592, 'OBJC_IVAR_$_Shark.movementDirection', 276),
                 0x7cc2f0: (17160592, 'OBJC_IVAR_$_Shark.movementDirection', 276),
                 0x7cc2f4: (17160616, 'OBJC_IVAR_$_Shark.goalRotation', 308),
                 0x7cc2f8: (17160608, 'OBJC_IVAR_$_Shark.toSquare', 288),
                 0x7cc2fc: (17160668, 'OBJC_IVAR_$_Shark.goalZRotation', 312),
                 0x7cc300: (17160620, 'OBJC_IVAR_$_Shark.bodyRotation', 304),
                 0x7cc304: (17160672, 'OBJC_IVAR_$_Shark.bodyZRotation', 316),
                 0x7cc310: (17160604, 'OBJC_IVAR_$_Shark.travelFraction', 296),
                 0x7cc328: (17160676, 'OBJC_IVAR_$_Shark.namePosition', 336),
                 0x7cc330: (17160664, 'OBJC_IVAR_$_Shark.bobTimer', 328),
                 0x7ccf48: (17160656, 'OBJC_IVAR_$_Shark.walkTimer', 320),
                 0x7ccf58: (17160596, 'OBJC_IVAR_$_Shark.walkSpeed', 324),
                 0x7cf44c: (17160632, 'OBJC_IVAR_$_Shark.biting', 364),
                 0x7cf834: (17160672, 'OBJC_IVAR_$_Shark.bodyZRotation', 316),
                 0x7cf844: (17160588, 'OBJC_IVAR_$_Shark.shader', 208),
                 0x7cf858: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x7cf868: (17160652, 'OBJC_IVAR_$_Shark.bubbleEmitTimer', 348),
                 0x7cf86c: (17160660, 'OBJC_IVAR_$_Shark.falling', 356),
                 0x7cf88c: (17160584, 'OBJC_IVAR_$_Shark.bodyFrontTexture', 212),
                 0x7cf894: (17160552, 'OBJC_IVAR_$_Shark.bodyFrontCube', 244),
                 0x7d1dc8: (17160580, 'OBJC_IVAR_$_Shark.bodyBackTexture', 216),
                 0x7d1dcc: (17160548, 'OBJC_IVAR_$_Shark.bodyBackCube', 248),
                 0x7d1dd0: (17160576, 'OBJC_IVAR_$_Shark.headTopTexture', 220),
                 0x7d1dd4: (17160544, 'OBJC_IVAR_$_Shark.headTopCube', 252),
                 0x7d1dd8: (17160572, 'OBJC_IVAR_$_Shark.headBottomTexture', 224),
                 0x7d1ddc: (17160540, 'OBJC_IVAR_$_Shark.headBottomCube', 256),
                 0x7d1de0: (17160568, 'OBJC_IVAR_$_Shark.topFinTexture', 228),
                 0x7d1de4: (17160536, 'OBJC_IVAR_$_Shark.topFinCube', 260),
                 0x7d3f2c: (17160560, 'OBJC_IVAR_$_Shark.tailFinTopTexture', 236),
                 0x7d3f30: (17160532, 'OBJC_IVAR_$_Shark.tailFinTopCube', 268),
                 0x7d3f34: (17160556, 'OBJC_IVAR_$_Shark.tailFinBottomTexture', 240),
                 0x7d3f38: (17160528, 'OBJC_IVAR_$_Shark.tailFinBottomCube', 272),
                 0x7d49b4: (17160588, 'OBJC_IVAR_$_Shark.shader', 208),
                 0x7d49bc: (17160524, 'OBJC_IVAR_$_Shark.sideFinCube', 264),
                 0x7d49c4: (17160564, 'OBJC_IVAR_$_Shark.sideFinTexture', 232),
        },
        classes={
                 0x7cf874: (15247176, 'OBJC_CLASS_$_ParticleEmitter'),
        },
        instructions=[(8168416, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8210884, 'invalid')],
        calls=[(8169160, 'bl loc.imp.objc_msgSend'), (8169184, 'bl sym.imp.__aeabi_idiv'), (8169252, 'bl loc.imp.objc_msgSend'), (8169380, 'bl loc.imp.objc_msgSend'), (8169396, 'bl sym.imp.__aeabi_idiv'), (8169464, 'bl loc.imp.objc_msgSend'), (8169596, 'bl loc.imp.objc_msgSend'), (8169620, 'bl sym.imp.__aeabi_idiv'), (8169688, 'bl loc.imp.objc_msgSend'), (8169816, 'bl loc.imp.objc_msgSend'), (8169832, 'bl sym.imp.__aeabi_idiv'), (8169900, 'bl loc.imp.objc_msgSend'), (8170188, 'bl method.Vector2.operator_float__'), (8170252, 'bl loc.imp.objc_msgSend'), (8170276, 'bl sym.imp.__aeabi_idiv'), (8170372, 'bl loc.imp.objc_msgSend'), (8170408, 'bl method.Vector2.operator_float__'), (8170460, 'bl method.Vector2.operator_float__'), (8170528, 'bl loc.imp.objc_msgSend'), (8170544, 'bl sym.imp.__aeabi_idiv'), (8170640, 'bl loc.imp.objc_msgSend'), (8170676, 'bl method.Vector2.operator_float__'), (8170856, 'blx r2'), (8170916, 'bl method.Vector2.operator_float__'), (8171060, 'blx r2'), (8171108, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (8171220, 'bl sym.tileIsSolid_Tile_'), (8171684, 'bl loc.imp.objc_msgSend'), (8171748, 'bl method.Vector2.operator_float__'), (8171764, 'bl method.Vector2.operator_float__'), (8171832, 'bl 0x7d49c8'), (8172204, 'bl 0x7d4a3c'), (8172252, 'bl sym.imp.memcpy'), (8173712, 'bl sym.imp.sinf'), (8173836, 'bl sym.imp.sinf'), (8174376, 'bl 0x7d4bf4'), (8174408, 'bl sym.imp.memcpy'), (8174804, 'bl 0x7d4ddc'), (8175340, 'bl 0x7d5174'), (8175384, 'bl sym.imp.memcpy'), (8175844, 'bl 0x7d4bf4'), (8175888, 'bl sym.imp.memcpy'), (8176328, 'bl 0x7d550c'), (8176360, 'bl sym.imp.memcpy'), (8176840, 'bl 0x7d550c'), (8176872, 'bl sym.imp.memcpy'), (8177040, 'bl 0x7d5b58'), (8177312, 'bl 0x7d58a4'), (8177372, 'bl method.Vector2.operator_float__'), (8177424, 'bl method.Vector2.operator_float__'), (8177812, 'bl 0x7d4bf4'), (8178204, 'bl 0x7d4ddc'), (8178552, 'bl sym.imp.sinf'), (8178844, 'bl 0x7d5174'), (8179360, 'bl 0x7d4bf4'), (8179776, 'bl 0x7d4ddc'), (8180312, 'bl 0x7d4bf4'), (8180660, 'bl 0x7d5174'), (8181148, 'bl 0x7d550c'), (8181644, 'bl 0x7d4bf4'), (8181996, 'bl 0x7d5174'), (8182476, 'bl 0x7d5174'), (8182952, 'bl 0x7d550c'), (8183464, 'bl 0x7d4bf4'), (8183844, 'bl 0x7d5174'), (8184320, 'bl 0x7d4ddc'), (8184836, 'bl 0x7d4bf4'), (8185212, 'bl 0x7d5174'), (8185260, 'bl sym.imp.memcpy'), (8185640, 'bl 0x7d4ddc'), (8185676, 'bl sym.imp.memcpy'), (8186064, 'bl 0x7d4bf4'), (8186492, 'bl 0x7d5174'), (8186972, 'bl 0x7d4ddc'), (8187468, 'bl 0x7d4bf4'), (8187860, 'bl 0x7d5174'), (8188336, 'bl 0x7d4ddc'), (8188412, 'bl sym.imp.memcpy'), (8188460, 'blx ip'), (8188464, 'bl sym.imp.__wrap_glUseProgram'), (8188596, 'blx r6'), (8188616, 'blx r3'), (8188632, 'blx r2'), (8188640, 'bl sym.imp.__wrap_glUniform1i'), (8188724, 'bl loc.imp.objc_msgSend_stret'), (8188764, 'bl sym.imp.memset'), (8189240, 'bl method.Vector.Vector_float__float__float_'), (8189260, 'bl method.Vector.operator_float__'), (8189332, 'bl method.Vector.operator_float__'), (8189384, 'bl method.Vector.operator_float__'), (8189456, 'bl method.Vector.operator_float__'), (8189508, 'bl method.Vector.operator_float__'), (8189580, 'bl method.Vector.operator_float__'), (8189648, 'bl method.Vector.Vector_float__float__float_'), (8189664, 'bl method.Vector.operator_float__'), (8189780, 'bl method.Vector.operator_float__'), (8189804, 'bl method.Vector.operator_float__'), (8189916, 'bl method.Vector.operator_float__'), (8189940, 'bl method.Vector.operator_float__'), (8190156, 'bl method.Vector.operator_float__'), (8190468, 'bl 0x7d5b58'), (8190740, 'bl 0x7d58a4'), (8190788, 'bl method.Vector.Vector_float__float__float__float_'), (8190800, 'bl method.Vector.operator_float__'), (8190816, 'bl method.Vector.operator_float__'), (8190832, 'bl method.Vector.operator_float__'), (8190868, 'bl method.Vector.Vector_float__float__float__float_'), (8190916, 'bl sym.Vector::operator_Vector_'), (8190944, 'bl method.Vector.Vector_float__float__float_'), (8190968, 'bl loc.imp.objc_msgSend'), (8191012, 'bl 0x7c83e4'), (8191060, 'bl 0x7c83e4'), (8191128, 'bl method.Vector.Vector_float__float__float_'), (8191360, 'bl loc.imp.objc_msgSend'), (8191428, 'bl loc.imp.objc_msgSend'), (8191464, 'bl loc.imp.objc_msgSend'), (8191488, 'bl loc.imp.objc_msgSend'), (8191508, 'bl method.Vector.operator_float__'), (8191524, 'bl method.Vector.operator_float__'), (8191540, 'bl method.Vector.operator_float__'), (8191572, 'bl sym.imp.__wrap_glUniform4f'), (8191580, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (8192380, 'bl 0x7d5b94'), (8193176, 'bl 0x7d5b94'), (8193212, 'bl loc.imp.objc_msgSend'), (8193240, 'bl loc.imp.objc_msgSend'), (8193256, 'bl loc.imp.objc_msgSend'), (8193276, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8193312, 'bl loc.imp.objc_msgSend'), (8193340, 'bl loc.imp.objc_msgSend'), (8193356, 'bl loc.imp.objc_msgSend'), (8193372, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8193420, 'bl loc.imp.objc_msgSend'), (8193448, 'bl sym.imp.__wrap_glBindTexture'), (8193496, 'bl loc.imp.objc_msgSend'), (8194292, 'bl 0x7d5b94'), (8195216, 'bl 0x7d5b94'), (8195384, 'bl loc.imp.objc_msgSend'), (8195404, 'bl loc.imp.objc_msgSend'), (8195420, 'bl loc.imp.objc_msgSend'), (8195436, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8195472, 'bl loc.imp.objc_msgSend'), (8195492, 'bl loc.imp.objc_msgSend'), (8195508, 'bl loc.imp.objc_msgSend'), (8195524, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8195564, 'bl loc.imp.objc_msgSend'), (8195584, 'bl sym.imp.__wrap_glBindTexture'), (8195624, 'bl loc.imp.objc_msgSend'), (8196420, 'bl 0x7d5b94'), (8197344, 'bl 0x7d5b94'), (8197512, 'bl loc.imp.objc_msgSend'), (8197532, 'bl loc.imp.objc_msgSend'), (8197548, 'bl loc.imp.objc_msgSend'), (8197564, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8197600, 'bl loc.imp.objc_msgSend'), (8197620, 'bl loc.imp.objc_msgSend'), (8197636, 'bl loc.imp.objc_msgSend'), (8197652, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8197692, 'bl loc.imp.objc_msgSend'), (8197712, 'bl sym.imp.__wrap_glBindTexture'), (8197752, 'bl loc.imp.objc_msgSend'), (8198548, 'bl 0x7d5b94'), (8199472, 'bl 0x7d5b94'), (8199676, 'bl loc.imp.objc_msgSend'), (8199696, 'bl loc.imp.objc_msgSend'), (8199712, 'bl loc.imp.objc_msgSend'), (8199728, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8199764, 'bl loc.imp.objc_msgSend'), (8199784, 'bl loc.imp.objc_msgSend'), (8199800, 'bl loc.imp.objc_msgSend'), (8199816, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8199856, 'bl loc.imp.objc_msgSend'), (8199876, 'bl sym.imp.__wrap_glBindTexture'), (8199916, 'bl loc.imp.objc_msgSend'), (8200712, 'bl 0x7d5b94'), (8201636, 'bl 0x7d5b94'), (8201804, 'bl loc.imp.objc_msgSend'), (8201824, 'bl loc.imp.objc_msgSend'), (8201840, 'bl loc.imp.objc_msgSend'), (8201856, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8201892, 'bl loc.imp.objc_msgSend'), (8201912, 'bl loc.imp.objc_msgSend'), (8201928, 'bl loc.imp.objc_msgSend'), (8201944, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8201984, 'bl loc.imp.objc_msgSend'), (8202004, 'bl sym.imp.__wrap_glBindTexture'), (8202044, 'bl loc.imp.objc_msgSend'), (8202840, 'bl 0x7d5b94'), (8203764, 'bl 0x7d5b94'), (8203932, 'bl loc.imp.objc_msgSend'), (8203952, 'bl loc.imp.objc_msgSend'), (8203968, 'bl loc.imp.objc_msgSend'), (8203984, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8204020, 'bl loc.imp.objc_msgSend'), (8204040, 'bl loc.imp.objc_msgSend'), (8204056, 'bl loc.imp.objc_msgSend'), (8204072, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8204112, 'bl loc.imp.objc_msgSend'), (8204132, 'bl sym.imp.__wrap_glBindTexture'), (8204172, 'bl loc.imp.objc_msgSend'), (8204968, 'bl 0x7d5b94'), (8205892, 'bl 0x7d5b94'), (8206060, 'bl loc.imp.objc_msgSend'), (8206080, 'bl loc.imp.objc_msgSend'), (8206096, 'bl loc.imp.objc_msgSend'), (8206112, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8206148, 'bl loc.imp.objc_msgSend'), (8206168, 'bl loc.imp.objc_msgSend'), (8206184, 'bl loc.imp.objc_msgSend'), (8206200, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8206240, 'bl loc.imp.objc_msgSend'), (8206260, 'bl sym.imp.__wrap_glBindTexture'), (8206300, 'bl loc.imp.objc_msgSend'), (8207096, 'bl 0x7d5b94'), (8208020, 'bl 0x7d5b94'), (8208208, 'bl loc.imp.objc_msgSend'), (8208228, 'bl loc.imp.objc_msgSend'), (8208244, 'bl loc.imp.objc_msgSend'), (8208260, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8208296, 'bl loc.imp.objc_msgSend'), (8208316, 'bl loc.imp.objc_msgSend'), (8208332, 'bl loc.imp.objc_msgSend'), (8208348, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8208388, 'bl loc.imp.objc_msgSend'), (8208408, 'bl sym.imp.__wrap_glBindTexture'), (8208448, 'bl loc.imp.objc_msgSend'), (8209244, 'bl 0x7d5b94'), (8210164, 'bl 0x7d5b94'), (8210324, 'bl sym.imp.memcpy'), (8210372, 'blx ip'), (8210392, 'blx r3'), (8210408, 'blx r2'), (8210440, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8210580, 'blx r3'), (8210600, 'blx r3'), (8210616, 'blx r2'), (8210648, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8210728, 'blx r3'), (8210748, 'bl sym.imp.__wrap_glBindTexture'), (8210828, 'blx r3'), (8210836, 'bl sym.imp.__wrap_glDisableVertexAttribArray')],
        branches=[(8169196, 'blt', 8169288), (8169284, 'b', 8169500), (8169408, 'bge', 8169496), (8169496, 'b', 8169500), (8169632, 'blt', 8169724), (8169720, 'b', 8169936), (8169844, 'bge', 8169932), (8169932, 'b', 8169936), (8169976, 'blt', 8170112), (8170020, 'bgt', 8170112), (8170064, 'blt', 8170112), (8170108, 'ble', 8170116), (8170112, 'b', 8210840), (8170304, 'ble', 8170436), (8170432, 'b', 8170704), (8170572, 'bpl', 8170700), (8170700, 'b', 8170704), (8170740, 'beq', 8170948), (8171132, 'beq', 8171156), (8171152, 'bne', 8171212), (8171192, 'b', 8210840), (8171232, 'beq', 8171256), (8171320, 'bne', 8171492), (8172296, 'bne', 8172340), (8172336, 'b', 8172548), (8172352, 'bne', 8172480), (8172392, 'b', 8172544), (8172492, 'bne', 8172540), (8172540, 'b', 8172544), (8172544, 'b', 8172548), (8172608, 'ble', 8172736), (8172676, 'bne', 8172732), (8172732, 'b', 8172972), (8172796, 'bge', 8172924), (8172864, 'bne', 8172920), (8172920, 'b', 8172968), (8172968, 'b', 8172972), (8173096, 'bpl', 8173272), (8173116, 'b', 8173292), (8173952, 'bne', 8174412), (8175416, 'beq', 8176880), (8175420, 'b', 8175444), (8175920, 'ble', 8176436), (8176364, 'b', 8176876), (8176876, 'b', 8176880), (8179512, 'b', 8179568), (8184620, 'b', 8184632), (8185292, 'beq', 8185680), (8188704, 'beq', 8188732), (8188728, 'b', 8188768), (8188892, 'bpl', 8188916), (8188912, 'b', 8188932), (8188980, 'bpl', 8189008), (8189000, 'b', 8189024), (8189072, 'ble', 8189144), (8189704, 'bpl', 8189732), (8189724, 'b', 8189748), (8189844, 'bpl', 8189868), (8189864, 'b', 8189884), (8189980, 'bpl', 8190108), (8190000, 'b', 8190124), (8190224, 'ble', 8191372), (8190264, 'bne', 8191372), (8191364, 'b', 8191372), (8199620, 'b', 8199656), (8208168, 'b', 8208188)],
        semantics=('[Shark -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]] (imp 0x007ca3e0, 10618w): -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:] (0x7ca3e0, 10618w) [census]: the render giant (dt float + 2 GLKMatrix4 + 5 camera ints; ~11.7KB locals, 3 scratch arenas + state snapshot buffer). 241 calls: 82 objc_msgSend, 18 glUniformMatrix4fv, 9 glBindTexture, 3 sinf (swim/bob phases), 10 memcpy(64B), matrix helpers 0x7d5b94 x18 / 0x7d4bf4 x10 / 0x7d5174 x9 / 0x7d4ddc x7 / 0x7d550c x4 / 0x7d5b58 / 0x7d58a4, 2x lrand48(0x7c83e4), tileAtWorldPosition_MacroTile + tileIsSolid (ground/falling checks), 48 ivars incl. all 8 cube+texture ivars and bodyZRotation @316/walkTimer @320/bobTimer @328. Flow: transform math -> glUseProgram([self.shader @208 program]) -> glUniform1i([shader.uniformLocations objectAtIndex:1].intValue, 0) -> [world dayColor] -> bubble particles ([ParticleEmitter instance] addParticleAtPos:velocity:color:gravityType:life:scale: with 2 random vectors) -> glUniform4f([uniformLocations[2].intValue], dayColor.rgb, 1.0f) -> glEnableVertexAttribArray(2) -> NINE draw blocks: the 8 cubes in bodyFront/bodyBack/headTop/headBottom/topFin/tailFinTop/tailFinBottom order, then sideFinCube@264 drawn TWICE (blocks 8 and 9 both use sideFinCube/sideFinTexture - the two side fins): each block = matrix compose + glUniformMatrix4fv([uniformLocations[0].intValue],1,0,&mvp) + glUniformMatrix4fv([uniformLocations[3].intValue],1,0,&normal_matrix) + glBindTexture(GL_TEXTURE_2D=0xde1,[texture name]) + objc_msgSend(cube,\'draw\') (selector \'draw\' cached on the stack after block 1) -> glDisableVertexAttribArray(2)..\n'),
    ),
    dict(
        name='sh_16',
        method='Shark -[foodItemType]',
        types='i8@0:4',
        start=8155720,
        end=8155748,
        disasm='disasm_worldtileloader_sh_16.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x007c72e8; body trimmed at the next IMP 0x007c7264 Shark -[getNamesArray]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8155720, 'sub sp, sp, 8'), (8155744, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Shark -[foodItemType]] (imp 0x007c7248, 7w): -[foodItemType] (0x7c7248, 7w): returns 0x97 (151) - the food item type (fish feed)..\n'),
    ),
    dict(
        name='sh_17',
        method='Shark -[getNamesArray]',
        types='^@8@0:4',
        start=8155748,
        end=8155796,
        disasm='disasm_worldtileloader_sh_17.txt',
        base_add=8155756,
        base_literal=8155792,
        boundary='ARM.exidx end 0x007c72e8; body trimmed at the next IMP 0x007c7294 Shark -[getNamesArrayCount]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8155748, 'sub sp, sp, 8'), (8155792, 'addeq r8, sb, r0, lsl 17')],
        calls=[],
        branches=[],
        semantics=('[Shark -[getNamesArray]] (imp 0x007c7264, 12w): -[getNamesArray] (0x7c7264, 12w): PIC-base + 0xffff2394 materialization (base 0x0105FAF4 at add-pc 0x7c726c); returns pointer 0x1051E88 = a contiguous 64-entry table of CFString pointers; names are alphabetical: Alpha, Angel, Barney, Berty, Blade, Bob, Bowie, Brutus ... Trevor, Victoria, Weasel (verified full 64-entry walk; CFString layout {0,0x7c8,cstr,len})..\n'),
    ),
    dict(
        name='sh_18',
        method='Shark -[getNamesArrayCount]',
        types='i8@0:4',
        start=8155796,
        end=8155824,
        disasm='disasm_worldtileloader_sh_18.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x007c72e8; body trimmed at the next IMP 0x007c72b0 Shark -[capturedItemType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8155796, 'sub sp, sp, 8'), (8155820, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Shark -[getNamesArrayCount]] (imp 0x007c7294, 7w): -[getNamesArrayCount] (0x7c7294, 7w): returns 0x40 (64) - count of the getNamesArray table..\n'),
    ),
    dict(
        name='sh_19',
        method='Shark -[hitWithForce:blockhead:]',
        types='v16@0:4i8@12',
        start=8243760,
        end=8244404,
        disasm='disasm_worldtileloader_sh_19.txt',
        base_add=8243776,
        base_literal=8244400,
        boundary='ARM.exidx end 0x007dccb4 (listing bound); next ObjC IMP 0x007dccb4 Shark -[renderPos]',
        selectors={
                 0x7dcc84: (15210536, 'maxAge'),
                 0x7dcc90: (15210688, 'hitWithForce:blockhead:'),
        },
        imports={
                 0x7dcc80: (17151904, 'objc_msgSend'),
                 0x7dcc8c: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0x7dcc88: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0x7dcc98: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0x7dcc9c: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x7dcca0: (17160600, 'OBJC_IVAR_$_Shark.randomTimeBetweenDirectionChanges', 300),
                 0x7dcca4: (17160596, 'OBJC_IVAR_$_Shark.walkSpeed', 324),
                 0x7dcca8: (17160592, 'OBJC_IVAR_$_Shark.movementDirection', 276),
        },
        classes={
                 0x7dcc94: (15252820, 'OBJC_CLASS_$_Shark'),
        },
        instructions=[(8243760, 'push {r4, r5, r6, sl, fp, lr}'), (8244400, 'addeq r3, r8, ip, lsr 1')],
        calls=[(8243876, 'blx r4'), (8244088, 'blx ip'), (8244164, 'bl 0x7c83e4')],
        branches=[(8243964, 'bge', 8243980), (8243976, 'b', 8243988), (8244124, 'bne', 8244336), (8244160, 'bne', 8244336)],
        semantics=('[Shark -[hitWithForce:blockhead:]] (imp 0x007dca30, 161w): -[hitWithForce:blockhead:] (0x7dca30, 161w): t = (age/maxAge)*2.8 + 0.2 (pools 0x7dcc78=0.2f, 0x7dcc7c=2.8f; maxAge via objc_msgSend); force\' = (int)(force / t); r = max(force\', 1); [super hitWithForce:r blockhead:blockhead] (msgSendSuper2 cells 0x7dcc90/0x7dcc94); if (!dead @56 && !isNet @52): rng = lrand48 wrapper @0x7c83e4; movementDirection @276 = (rng/2^31f as double > 0.5) ? +1 : -1 (gl d2=0.5; divisor pool 0x7dccac = 2^31f); walkSpeed @324 = 3.0f; randomTimeBetweenDirectionChanges @300 = 5.0f..\n'),
    ),
    dict(
        name='sh_20',
        method='Shark -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:]',
        types='@44@0:4@8@12{?=ii}16@24@28c32c36@40',
        start=8160248,
        end=8161560,
        disasm='disasm_worldtileloader_sh_20.txt',
        base_add=8160264,
        base_literal=8161556,
        boundary='ARM.exidx end 0x007c8918 (listing bound); next ObjC IMP 0x007c8918 Shark -[initWithWorld:dynamicWorld:saveDict:cache:]',
        selectors={
                 0x7c88e0: (15210416, 'initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:'),
                 0x7c88f0: (15210424, 'release'),
                 0x7c88f4: (15210420, 'removeFromMacroBlock'),
                 0x7c8900: (15210428, 'getWeatherFractionForPos:'),
                 0x7c8904: (15210432, 'worldTime'),
                 0x7c8908: (15210436, 'getDayNightFractionForX:atWorldTime:'),
                 0x7c8910: (15210440, 'loadDerivedStuff'),
        },
        imports={
                 0x7c88ec: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x7c88e4: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x7c88e8: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x7c890c: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
        },
        classes={
                 0x7c88d8: (15252820, 'OBJC_CLASS_$_Shark'),
        },
        instructions=[(8160248, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8161556, 'addeq r7, sb, r4, ror 13')],
        calls=[(8160492, 'bl loc.imp.objc_msgSendSuper2'), (8160608, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8160648, 'bl sym.tileIsWater_Tile_'), (8160744, 'blx ip'), (8160764, 'blx r2'), (8160900, 'bl loc.imp.objc_msgSend'), (8160972, 'bl loc.imp.objc_msgSend'), (8161012, 'bl loc.imp.objc_msgSend'), (8161064, 'bl loc.imp.objc_msgSend'), (8161112, 'bl sym.seasonForWorldX_int__double__World_'), (8161212, 'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_'), (8161384, 'blx ip'), (8161404, 'blx r2'), (8161464, 'blx r2')],
        branches=[(8160520, 'bne', 8160536), (8160532, 'b', 8161476), (8160628, 'beq', 8160680), (8160640, 'bne', 8160780), (8160660, 'beq', 8160680), (8160676, 'bge', 8160780), (8160776, 'b', 8161476), (8160788, 'bne', 8161424), (8161240, 'bmi', 8161320), (8161288, 'ble', 8161420), (8161316, 'bpl', 8161420), (8161416, 'b', 8161476), (8161420, 'b', 8161424)],
        semantics=('[Shark -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:]] (imp 0x007c83f8, 328w): -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:] (0x7c83f8, 328w): [super <same 8-arg selector>] via msgSendSuper2 (Shark class cell 0x7c88d8; selector cell 0x7c88e0; atPosition pair + rest passed on stack); nil -> return nil. tile = tileAtWorldPositionLoaded(pos.x @16, pos.y @20, world @4); if !(tile != 0 && (wasPlaced || (tileIsWater(tile) && tile->byte4 >= 0x7f))) { [self removeFromMacroBlock]; [self release]; return nil; }. if (wasPlaced) { [self loadDerivedStuff]; return self; }. w = [world getWeatherFractionForPos:{pos.x,pos.y}]; dn = [world getDayNightFractionForX:(float)pos.x atWorldTime:<double>[world worldTime]]; season = seasonForWorldX(pos.x, [world worldTime], world); temp = currentTemperatureForTileAtWorldPos(tile,{pos.x,pos.y},season,dn,w,world). Fail iff temp < 0.1f (pool 0x7c88f8) OR (age @88 > 0.1 double (pool 0x7c88d0) AND temp < 2.0f); success path: [self loadDerivedStuff]; return self..\n'),
    ),
    dict(
        name='sh_21',
        method='Shark -[initWithWorld:dynamicWorld:cache:netData:]',
        types='@24@0:4@8@12@16@20',
        start=8161856,
        end=8162356,
        disasm='disasm_worldtileloader_sh_21.txt',
        base_add=8161872,
        base_literal=8162352,
        boundary='ARM.exidx end 0x007c8c34 (listing bound); next ObjC IMP 0x007c8c34 Shark -[getSaveDict]',
        selectors={
                 0x7c8c08: (15210448, 'initWithWorld:dynamicWorld:cache:netData:'),
                 0x7c8c18: (15210452, 'remoteCreationDataUpdate:'),
                 0x7c8c1c: (15210440, 'loadDerivedStuff'),
        },
        imports={
                 0x7c8c04: (17151900, 'objc_msgSendSuper2'),
                 0x7c8c14: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x7c8c10: (17160592, 'OBJC_IVAR_$_Shark.movementDirection', 276),
                 0x7c8c24: (17160616, 'OBJC_IVAR_$_Shark.goalRotation', 308),
                 0x7c8c28: (17160620, 'OBJC_IVAR_$_Shark.bodyRotation', 304),
        },
        classes={
                 0x7c8c0c: (15252820, 'OBJC_CLASS_$_Shark'),
        },
        instructions=[(8161856, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8162352, 'umulleq r7, sb, ip, r0')],
        calls=[(8162008, 'blx r6'), (8162116, 'blx r2'), (8162140, 'blx r3')],
        branches=[(8162036, 'bne', 8162052), (8162048, 'b', 8162296), (8162168, 'bne', 8162232), (8162228, 'b', 8162288)],
        semantics=('[Shark -[initWithWorld:dynamicWorld:cache:netData:]] (imp 0x007c8a40, 125w): -[initWithWorld:dynamicWorld:cache:netData:] (0x7c8a40, 125w): [super initWithWorld:dynamicWorld:cache:netData:] via msgSendSuper2 (cells 0x7c8c08/0x7c8c0c; cache/netData on stack); nil -> return nil; [self loadDerivedStuff] (cell 0x7c8c1c); [self remoteCreationDataUpdate:netData] (cell 0x7c8c18); then goalRotation @308 = bodyRotation @304 = (movementDirection @276 == 1 ? +pi/2f (0x3fc90fdb @0x7c8c2c) : -pi/2f (0xbfc90fdb @0x7c8c20)); return self..\n'),
    ),
    dict(
        name='sh_22',
        method='Shark -[isUnderLocalControl]',
        types='c8@0:4',
        start=8217316,
        end=8217712,
        disasm='disasm_worldtileloader_sh_22.txt',
        base_add=8217332,
        base_literal=8217704,
        boundary='ARM.exidx end 0x007d6470 (listing bound); next ObjC IMP 0x007d6470 Shark -[update:accurateDT:isSimulation:]',
        selectors={
                 0x7d6464: (15210492, 'isNet'),
        },
        imports={
                 0x7d6460: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x7d6458: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x7d645c: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
        },
        classes={},
        instructions=[(8217316, 'push {fp, lr}'), (8217708, 'andeq r0, r0, r0')],
        calls=[(8217500, 'blx r3'), (8217632, 'blx r2')],
        branches=[(8217376, 'beq', 8217524), (8217424, 'beq', 8217664), (8217520, 'bne', 8217664), (8217568, 'beq', 8217656)],
        semantics=('[Shark -[isUnderLocalControl]] (imp 0x007d62e4, 99w): -[isUnderLocalControl] (0x7d62e4, 99w): netObj = (DynamicObject.isNet @52 ldrsb); if (netObj): return (self.rider @132 != 0) && ![self.rider isNet] (objc_msgSend cell 0x7d6464=\'isNet\'); else: return !(self.rider && [self.rider isNet]) - i.e. networked shark is locally controlled iff it carries a non-net rider; non-networked shark unless it carries a net rider..\n'),
    ),
    dict(
        name='sh_23',
        method='Shark -[jumpsOnSwipe]',
        types='c8@0:4',
        start=8247916,
        end=8247944,
        disasm='disasm_worldtileloader_sh_23.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x007ddac0; body trimmed at the next IMP 0x007dda88 Shark -[riderRidesWithArmsDown]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8247916, 'sub sp, sp, 8'), (8247940, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Shark -[jumpsOnSwipe]] (imp 0x007dda6c, 7w): -[jumpsOnSwipe] (0x7dda6c, 7w): returns 0 (NO) via movw r2,0; sxtb r0,r2..\n'),
    ),
    dict(
        name='sh_24',
        method='Shark -[loadDerivedStuff]',
        types='v8@0:4',
        start=8156848,
        end=8160228,
        disasm='disasm_worldtileloader_sh_24.txt',
        base_add=8156868,
        base_literal=8160224,
        boundary='ARM.exidx end 0x007c83e4 (listing bound); next ObjC IMP 0x007c83f8 Shark -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:]',
        selectors={
                 0x7c8310: (15210408, 'initWithWidth:height:depth:centerX:centerY:centerZ:calculateNormals:'),
                 0x7c8314: (15210404, 'alloc'),
                 0x7c8330: (15210412, 'initWithWidth:height:depth:calculateNormals:'),
                 0x7c8344: (15210400, 'textureNamed:'),
                 0x7c838c: (15210396, 'shaderNamed:attributes:uniforms:'),
                 0x7c83a0: (15210392, 'arrayWithObjects:'),
        },
        imports={
                 0x7c830c: (17151904, 'objc_msgSend'),
                 0x7c8340: (16322488, '__CFConstantStringClassReference'),
                 0x7c8350: (16322472, '__CFConstantStringClassReference'),
                 0x7c8358: (16322456, '__CFConstantStringClassReference'),
                 0x7c8360: (16322440, '__CFConstantStringClassReference'),
                 0x7c8368: (16322424, '__CFConstantStringClassReference'),
                 0x7c8370: (16322408, '__CFConstantStringClassReference'),
                 0x7c8378: (16322392, '__CFConstantStringClassReference'),
                 0x7c8380: (16322376, '__CFConstantStringClassReference'),
                 0x7c8388: (16322248, '__CFConstantStringClassReference'),
                 0x7c8390: (16322312, '__CFConstantStringClassReference'),
                 0x7c8394: (16322328, '__CFConstantStringClassReference'),
                 0x7c8398: (16322344, '__CFConstantStringClassReference'),
                 0x7c839c: (16322360, '__CFConstantStringClassReference'),
                 0x7c83a8: (16322264, '__CFConstantStringClassReference'),
                 0x7c83ac: (16322280, '__CFConstantStringClassReference'),
                 0x7c83b0: (16322296, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x7c8304: (17160524, 'OBJC_IVAR_$_Shark.sideFinCube', 264),
                 0x7c831c: (17160528, 'OBJC_IVAR_$_Shark.tailFinBottomCube', 272),
                 0x7c8320: (17160532, 'OBJC_IVAR_$_Shark.tailFinTopCube', 268),
                 0x7c8324: (17160536, 'OBJC_IVAR_$_Shark.topFinCube', 260),
                 0x7c8328: (17160540, 'OBJC_IVAR_$_Shark.headBottomCube', 256),
                 0x7c832c: (17160544, 'OBJC_IVAR_$_Shark.headTopCube', 252),
                 0x7c8334: (17160548, 'OBJC_IVAR_$_Shark.bodyBackCube', 248),
                 0x7c8338: (17160552, 'OBJC_IVAR_$_Shark.bodyFrontCube', 244),
                 0x7c833c: (17160556, 'OBJC_IVAR_$_Shark.tailFinBottomTexture', 240),
                 0x7c8348: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0x7c834c: (17160560, 'OBJC_IVAR_$_Shark.tailFinTopTexture', 236),
                 0x7c8354: (17160564, 'OBJC_IVAR_$_Shark.sideFinTexture', 232),
                 0x7c835c: (17160568, 'OBJC_IVAR_$_Shark.topFinTexture', 228),
                 0x7c8364: (17160572, 'OBJC_IVAR_$_Shark.headBottomTexture', 224),
                 0x7c836c: (17160576, 'OBJC_IVAR_$_Shark.headTopTexture', 220),
                 0x7c8374: (17160580, 'OBJC_IVAR_$_Shark.bodyBackTexture', 216),
                 0x7c837c: (17160584, 'OBJC_IVAR_$_Shark.bodyFrontTexture', 212),
                 0x7c8384: (17160588, 'OBJC_IVAR_$_Shark.shader', 208),
                 0x7c83b4: (17160592, 'OBJC_IVAR_$_Shark.movementDirection', 276),
                 0x7c83b8: (17160596, 'OBJC_IVAR_$_Shark.walkSpeed', 324),
                 0x7c83bc: (17160600, 'OBJC_IVAR_$_Shark.randomTimeBetweenDirectionChanges', 300),
                 0x7c83c0: (17160604, 'OBJC_IVAR_$_Shark.travelFraction', 296),
                 0x7c83c4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x7c83c8: (17160608, 'OBJC_IVAR_$_Shark.toSquare', 288),
                 0x7c83cc: (17160612, 'OBJC_IVAR_$_Shark.fromSquare', 280),
                 0x7c83d4: (17160616, 'OBJC_IVAR_$_Shark.goalRotation', 308),
                 0x7c83d8: (17160620, 'OBJC_IVAR_$_Shark.bodyRotation', 304),
        },
        classes={
                 0x7c8318: (15247164, 'OBJC_CLASS_$_DrawCube'),
                 0x7c83a4: (15247160, 'OBJC_CLASS_$_NSArray'),
        },
        instructions=[(8156848, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8160224, 'addeq r8, sb, r8, lsr 8')],
        calls=[(8157692, 'blx r4'), (8157756, 'blx r5'), (8157800, 'blx lr'), (8157860, 'blx ip'), (8157980, 'blx ip'), (8158040, 'blx ip'), (8158100, 'blx ip'), (8158160, 'blx ip'), (8158220, 'blx ip'), (8158280, 'blx ip'), (8158340, 'blx ip'), (8158392, 'blx ip'), (8158476, 'blx lr'), (8158528, 'blx ip'), (8158612, 'blx lr'), (8158664, 'blx ip'), (8158720, 'blx lr'), (8158772, 'blx ip'), (8158860, 'blx lr'), (8158912, 'blx ip'), (8158996, 'blx lr'), (8159048, 'blx ip'), (8159140, 'blx lr'), (8159192, 'blx ip'), (8159280, 'blx lr'), (8159332, 'blx ip'), (8159424, 'blx lr'), (8159448, 'bl 0x7c83e4'), (8159748, 'bl 0x7c83e4')],
        branches=[(8157880, 'b', 8157940), (8159492, 'ble', 8159508), (8159504, 'b', 8159552), (8159848, 'bne', 8159912), (8159908, 'b', 8159968)],
        semantics=('[Shark -[loadDerivedStuff]] (imp 0x007c76b0, 845w): -[loadDerivedStuff] (0x7c76b0, 845w): post-init asset build. Uses cache @32: shader = [cache shaderNamed:@"ShadedWorldObject" (0xF90EC8) attributes:[position,texCoord,normal] uniforms:[mvp_matrix,texture,light,normal_matrix]] -> self.shader @208; 8 textures via [cache textureNamed:]: sharkBodyFront.png->bodyFrontTexture @212, sharkBodyBack.png->@216, sharkHeadTop.png->@220, sharkHeadBottom.png->@224, sharkTopFin.png->@228, sharkSideFin.png->@232, sharkTailFinTop.png->@236, sharkTailFinBottom.png->@240; 8 cubes via [DrawCube alloc] initWithWidth:height:depth:centerX:centerY:centerZ:calculateNormals: (headTopCube via the 4-arg variant): bodyFrontCube @244=(1.5,0.6,0.6, 0,0.3,0.3), bodyBackCube @248=(0.75,0.4,0.4, 0,0.2,0.2), headTopCube @252=(0.7,0.3,0.4), headBottomCube @256=(0.4,0.03,0.3, 0.6,0.075,0.03), topFinCube @260=(0.6,0.6,0.1, 0.3,0.3,0.05), sideFinCube @264=(0.3,0.06,0.6, 0.03,0.15,0.0), tailFinTopCube @268=(0.25,0.5,0.1, 0.125,0,0.05), tailFinBottomCube @272=(0.25,0.3,0.08, 0.125,0.3,0.04). State: d = lrand48()/2^31f; movementDirection @276 = d>0.75 ? 1 : (d<0.25 ? -1 : 0) (gl 0.75/0.25); pos @16 copied to toSquare @288 and fromSquare @280; travelFraction @296 = 1.0f; randomTimeBetweenDirectionChanges @300 = 0.0f; walkSpeed @324 = 0.1 + 0.2*lrand48()/2^31 (doubles 0.1/0.2 @0x7c82f0/0x7c82f8); goalRotation @308 = bodyRotation @304 = (movementDirection==1 ? +pi/2 (0x7c83dc) : -pi/2 (0x7c83d0))..\n'),
    ),
    dict(
        name='sh_25',
        method='Shark -[maxAge]',
        types='f8@0:4',
        start=8155572,
        end=8155620,
        disasm='disasm_worldtileloader_sh_25.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x007c7218; body trimmed at the next IMP 0x007c71e4 Shark -[minFullness]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8155572, 'sub sp, sp, 0x10'), (8155616, 'ldrbmi pc, [r2], r0')],
        calls=[],
        branches=[],
        semantics=('[Shark -[maxAge]] (imp 0x007c71b4, 12w): -[maxAge] (0x7c71b4, 12w): returns 27000.0f - triple-materialized constant 0x46D2F000 (movw/movt into r0, vldr s0 from pool 0x7c71e0, and int 0x6978 in r2)..\n'),
    ),
    dict(
        name='sh_26',
        method='Shark -[maxHealth]',
        types='S8@0:4',
        start=8242344,
        end=8242372,
        disasm='disasm_worldtileloader_sh_26.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x007dc4c4 (listing bound); next ObjC IMP 0x007dc4c4 Shark -[tapIsWithinBodyRadius:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8242344, 'sub sp, sp, 8'), (8242368, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Shark -[maxHealth]] (imp 0x007dc4a8, 7w): -[maxHealth] (0x7dc4a8, 7w): returns 0x19 (25) via uxth r0,r2..\n'),
    ),
    dict(
        name='sh_27',
        method='Shark -[minFullness]',
        types='f8@0:4',
        start=8155620,
        end=8155672,
        disasm='disasm_worldtileloader_sh_27.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x007c7218 (listing bound); next ObjC IMP 0x007c7218 Shark -[speciesName]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8155620, 'sub sp, sp, 0x10'), (8155668, 'strgt sl, [ip], -r0')],
        calls=[],
        branches=[],
        semantics=('[Shark -[minFullness]] (imp 0x007c71e4, 13w): -[minFullness] (0x7c71e4, 13w): returns -9000.0f (bits 0xC60CA000 = both r0 and pool 0x7c7214; int form -9000 in r2 via 0xffffdcd8 PIC offset)..\n'),
    ),
    dict(
        name='sh_28',
        method='Shark -[minRidableAge]',
        types='f8@0:4',
        start=8247516,
        end=8247564,
        disasm='disasm_worldtileloader_sh_28.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x007dd90c (listing bound); next ObjC IMP 0x007dd90c Shark -[blockheadCanRide:usingItem:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8247516, 'sub sp, sp, 0x10'), (8247560, 'strmi sl, [ip]')],
        calls=[],
        branches=[],
        semantics=('[Shark -[minRidableAge]] (imp 0x007dd8dc, 12w): -[minRidableAge] (0x7dd8dc, 12w): returns 4500.0f (bits 0x458CA000, pool 0x7dd908; int 0x1194=4500 in r2) - the same threshold used by blockheadCanRide:/canBeCapturedByBlockhead:..\n'),
    ),
    dict(
        name='sh_29',
        method='Shark -[namePos]',
        types='{Vector2=[2f]}8@0:4',
        start=8246048,
        end=8246168,
        disasm='disasm_worldtileloader_sh_29.txt',
        base_add=8246080,
        base_literal=8246164,
        boundary='ARM.exidx end 0x007dd4dc; body trimmed at the next IMP 0x007dd398 Shark -[riderPosForBlockhead:]',
        selectors={},
        imports={},
        ivars={
                 0x7dd390: (17160676, 'OBJC_IVAR_$_Shark.namePosition', 336),
        },
        classes={},
        instructions=[(8246048, 'push {fp, lr}'), (8246164, 'addeq r2, r8, ip, lsr 15')],
        calls=[(8246128, 'bl method.Vector2.Vector2_float__float_'), (8246148, 'bl method.Vector2.operator_Vector2_')],
        branches=[],
        semantics=('[Shark -[namePos]] (imp 0x007dd320, 30w): -[namePos] (0x7dd320, 30w): returns self.namePosition @336 (cell 0x7dd390) + Vector2(0.0f, 1.0f) via Vector2::Vector2(float,float) + Vector2::operator+(Vector2) with sret (r0=dest, r1=self). Name floats one unit above namePosition..\n'),
    ),
    dict(
        name='sh_30',
        method='Shark -[npcType]',
        types='i8@0:4',
        start=8155544,
        end=8155572,
        disasm='disasm_worldtileloader_sh_30.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x007c71b4 (listing bound); next ObjC IMP 0x007c71b4 Shark -[maxAge]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8155544, 'sub sp, sp, 8'), (8155568, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Shark -[npcType]] (imp 0x007c7198, 7w): -[npcType] (0x7c7198, 7w): returns 5 (NPCType 5 -> 36 = Shark per DYNAMIC_OBJECT_NPCTYPE_MATRIX.md; raw movw r2,5)..\n'),
    ),
    dict(
        name='sh_31',
        method='Shark -[reactToBeingFed]',
        types='v8@0:4',
        start=8245384,
        end=8246048,
        disasm='disasm_worldtileloader_sh_31.txt',
        base_add=8245400,
        base_literal=8246044,
        boundary='ARM.exidx end 0x007dd320 (listing bound); next ObjC IMP 0x007dd320 Shark -[namePos]',
        selectors={
                 0x7dd2e0: (15210700, 'reactToBeingFed'),
                 0x7dd304: (15210508, 'instance'),
                 0x7dd308: (15210512, 'multiSoundNamed:'),
                 0x7dd314: (15210576, 'playAtPosition:afterDelay:'),
        },
        imports={
                 0x7dd2dc: (17151900, 'objc_msgSendSuper2'),
                 0x7dd30c: (16322616, '__CFConstantStringClassReference'),
                 0x7dd318: (16322600, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x7dd2e8: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0x7dd2ec: (17160600, 'OBJC_IVAR_$_Shark.randomTimeBetweenDirectionChanges', 300),
                 0x7dd2f0: (17160596, 'OBJC_IVAR_$_Shark.walkSpeed', 324),
                 0x7dd2f4: (17160592, 'OBJC_IVAR_$_Shark.movementDirection', 276),
                 0x7dd310: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={
                 0x7dd2e4: (15252820, 'OBJC_CLASS_$_Shark'),
                 0x7dd2fc: (15247172, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(8245384, 'push {r4, r5, r6, r7, fp, lr}'), (8246044, 'addeq r2, r8, r4, asr sl')],
        calls=[(8245468, 'blx ip'), (8245516, 'bl loc.imp.objc_msgSend'), (8245548, 'bl loc.imp.objc_msgSend'), (8245644, 'bl loc.imp.objc_msgSend'), (8245668, 'bl loc.imp.objc_msgSend'), (8245692, 'bl loc.imp.objc_msgSend'), (8245768, 'bl loc.imp.objc_msgSend'), (8245772, 'bl 0x7c83e4')],
        branches=[],
        semantics=('[Shark -[reactToBeingFed]] (imp 0x007dd088, 166w): -[reactToBeingFed] (0x7dd088, 166w): [super reactToBeingFed] (msgSendSuper2 cells 0x7dd2e0/0x7dd2e4); sound 1 = [[MJSoundManager instance] multiSoundNamed:@"crunch.wav" (CFString 0xF91038)] playAtPosition:self.floatPos @24 afterDelay:0.1; sound 2 = [instance multiSoundNamed:@"fishRun.wav" (0xF91028)] playAtPosition:floatPos afterDelay:0.6 (double 0x3FE3333340000000); rng = lrand48(); movementDirection @276 = (rng/2^31f > 0.5) ? 1 : -1 (gl 0.5, divisor 2^31 @0x7dd2f8); walkSpeed @324 = 3.0f; randomTimeBetweenDirectionChanges @300 = 5.0f; updateNeedsToBeSent @49 = 1..\n'),
    ),
    dict(
        name='sh_32',
        method='Shark -[reactToBeingHit]',
        types='v8@0:4',
        start=8243516,
        end=8243760,
        disasm='disasm_worldtileloader_sh_32.txt',
        base_add=8243532,
        base_literal=8243756,
        boundary='ARM.exidx end 0x007dca30 (listing bound); next ObjC IMP 0x007dca30 Shark -[hitWithForce:blockhead:]',
        selectors={
                 0x7dca18: (15210508, 'instance'),
                 0x7dca1c: (15210512, 'multiSoundNamed:'),
                 0x7dca28: (15210576, 'playAtPosition:afterDelay:'),
        },
        imports={
                 0x7dca20: (16322600, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x7dca0c: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0x7dca24: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={
                 0x7dca10: (15247172, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(8243516, 'push {fp, lr}'), (8243756, 'addeq r3, r8, r0, lsr 3')],
        calls=[(8243608, 'bl loc.imp.objc_msgSend'), (8243632, 'bl loc.imp.objc_msgSend'), (8243712, 'bl loc.imp.objc_msgSend')],
        branches=[(8243572, 'bne', 8243716)],
        semantics=('[Shark -[reactToBeingHit]] (imp 0x007dc93c, 61w): -[reactToBeingHit] (0x7dc93c, 61w): if (!self.dead @56): snd = [[MJSoundManager instance] multiSoundNamed:@"fishRun.wav" (CFString 0xF91028)]; [snd playAtPosition:self.floatPos @24 afterDelay:0.1] (double 0x3FB99999A0000000). Selector cells instance 0x7dca18, multiSoundNamed: 0x7dca1c, playAtPosition:afterDelay: 0x7dca28..\n'),
    ),
    dict(
        name='sh_33',
        method='Shark -[remoteCreationDataUpdate:]',
        types='v12@0:4@8',
        start=8164460,
        end=8166736,
        disasm='disasm_worldtileloader_sh_33.txt',
        base_add=8164476,
        base_literal=8166732,
        boundary='ARM.exidx end 0x007c9d50 (listing bound); next ObjC IMP 0x007c9d50 Shark -[doRemoteUpdate:]',
        selectors={
                 0x7c9cc4: (15210452, 'remoteCreationDataUpdate:'),
                 0x7c9cd8: (15210488, 'getBytes:length:'),
                 0x7c9ce0: (15210492, 'isNet'),
                 0x7c9ce8: (15210424, 'release'),
                 0x7c9cec: (15210500, 'countByEnumeratingWithState:objects:count:'),
                 0x7c9cf0: (15210496, 'allBlockheadsIncludingNet'),
                 0x7c9cf8: (15210472, 'uniqueID'),
                 0x7c9d18: (15210504, 'retain'),
                 0x7c9d24: (15210508, 'instance'),
                 0x7c9d28: (15210512, 'multiSoundNamed:'),
                 0x7c9d34: (15210516, 'playAtPosition:'),
                 0x7c9d38: (15210520, 'doRemoteUpdate:'),
                 0x7c9d44: (15210524, 'isClient'),
        },
        imports={
                 0x7c9cc0: (17151900, 'objc_msgSendSuper2'),
                 0x7c9cd4: (17151904, 'objc_msgSend'),
                 0x7c9d2c: (16322504, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x7c9ccc: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0x7c9cd0: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x7c9cdc: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0x7c9ce4: (17160624, 'OBJC_IVAR_$_Shark.attackBlockhead', 380),
                 0x7c9cf4: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x7c9d04: (17160596, 'OBJC_IVAR_$_Shark.walkSpeed', 324),
                 0x7c9d08: (17160628, 'OBJC_IVAR_$_Shark.biteTimer', 360),
                 0x7c9d0c: (17157388, 'OBJC_IVAR_$_DynamicObject.creationDataNeedsToBeSent', 50),
                 0x7c9d10: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0x7c9d14: (17160632, 'OBJC_IVAR_$_Shark.biting', 364),
                 0x7c9d30: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x7c9d40: (17160604, 'OBJC_IVAR_$_Shark.travelFraction', 296),
                 0x7c9d48: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
        },
        classes={
                 0x7c9cc8: (15252820, 'OBJC_CLASS_$_Shark'),
                 0x7c9d20: (15247172, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(8164460, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8166732, 'addeq r6, sb, r0, ror r6')],
        calls=[(8164552, 'blx lr'), (8164656, 'blx ip'), (8164788, 'blx r2'), (8164904, 'blx r2'), (8165060, 'blx r2'), (8165084, 'bl sym.imp.memset'), (8165132, 'blx lr'), (8165232, 'bl sym.imp.objc_enumerationMutation'), (8165268, 'bl loc.imp.objc_msgSend'), (8165388, 'bl loc.imp.objc_msgSend'), (8165512, 'blx ip'), (8165700, 'bl loc.imp.objc_msgSend'), (8165744, 'bl loc.imp.objc_msgSend'), (8165768, 'bl loc.imp.objc_msgSend'), (8165824, 'bl loc.imp.objc_msgSend'), (8166044, 'blx ip'), (8166184, 'blx r3'), (8166412, 'bl loc.imp.objc_msgSend'), (8166532, 'blx r2')],
        branches=[(8164588, 'bne', 8166420), (8164684, 'beq', 8164804), (8164724, 'beq', 8164920), (8164800, 'bne', 8164920), (8164840, 'beq', 8166220), (8164916, 'beq', 8166220), (8164936, 'beq', 8166076), (8164940, 'b', 8164944), (8165144, 'beq', 8166068), (8165224, 'beq', 8165236), (8165296, 'bne', 8165944), (8165300, 'b', 8165304), (8165348, 'beq', 8165552), (8165416, 'bne', 8165436), (8165420, 'b', 8165424), (8165432, 'b', 8165548), (8165548, 'b', 8165552), (8165560, 'beq', 8165940), (8165940, 'b', 8165944), (8165944, 'b', 8165948), (8165972, 'blo', 8165188), (8166064, 'bne', 8165188), (8166068, 'b', 8166072), (8166072, 'b', 8166216), (8166112, 'beq', 8166212), (8166212, 'b', 8166216), (8166216, 'b', 8166220), (8166416, 'b', 8166584), (8166468, 'bpl', 8166580), (8166544, 'bne', 8166580), (8166580, 'b', 8166584)],
        semantics=('[Shark -[remoteCreationDataUpdate:]] (imp 0x007c946c, 569w): -[remoteCreationDataUpdate:] (0x7c946c, 569w): [super remoteCreationDataUpdate:data] (cells 0x7c9cc4/0x7c9cc8); if (dead @56) -> dead-branch: if (travelFraction @296 < 1.0f && ![self.dynamicWorld @8 isClient]) needsRemoved @48 = 0. Else [data getBytes:buf(0x78) length:0x78]; if (isNet @52 ? (rider @132 == nil || [rider isNet]) : (rider != nil && [rider isNet])) { if (buf.uid64 @0x70 != 0): fast-enumerate [self.dynamicWorld allBlockheadsIncludingNet] (countByEnumeratingWithState:objects:count:); for each blockhead with matching [blockhead uniqueID]: found=1; if (self.attackBlockhead @380): if ([attackBlockhead uniqueID] == uid) found=0; else { [attackBlockhead release]; self.attackBlockhead=nil; }; if (found) { [blockhead retain]; self.attackBlockhead = blockhead; [[MJSoundManager instance] multiSoundNamed:@"jaws.wav" (0xF90FC8)] playAtPosition:self.floatPos; biting @364=1; updateNeedsToBeSent @49=1; creationDataNeedsToBeSent @50=1; biteTimer @360=1.0f; walkSpeed @324=4.0f; } (no break) ; else if (buf.uid64 == 0): if (attackBlockhead) { [attackBlockhead release]; attackBlockhead=nil; }; then [self doRemoteUpdate:<buf+0x48, 0x28 bytes>]. } else (local/riderless): also [self doRemoteUpdate:<buf+0x48, 0x28>]..\n'),
    ),
    dict(
        name='sh_34',
        method='Shark -[remoteUpdate:]',
        types='v12@0:4@8',
        start=8167824,
        end=8168416,
        disasm='disasm_worldtileloader_sh_34.txt',
        base_add=8167840,
        base_literal=8168412,
        boundary='ARM.exidx end 0x007ca3e0 (listing bound); next ObjC IMP 0x007ca3e0 Shark -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        selectors={
                 0x7ca3b0: (15210528, 'remoteUpdate:'),
                 0x7ca3bc: (15210488, 'getBytes:length:'),
                 0x7ca3c4: (15210520, 'doRemoteUpdate:'),
                 0x7ca3d0: (15210524, 'isClient'),
        },
        imports={
                 0x7ca3ac: (17151900, 'objc_msgSendSuper2'),
                 0x7ca3cc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x7ca3b8: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0x7ca3c8: (17160604, 'OBJC_IVAR_$_Shark.travelFraction', 296),
                 0x7ca3d4: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x7ca3d8: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
        },
        classes={
                 0x7ca3b4: (15252820, 'OBJC_CLASS_$_Shark'),
        },
        instructions=[(8167824, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8168412, 'addeq r5, sb, ip, asr 18')],
        calls=[(8167916, 'blx lr'), (8167996, 'bl loc.imp.objc_msgSend'), (8168184, 'bl loc.imp.objc_msgSend'), (8168304, 'blx r2')],
        branches=[(8167952, 'bne', 8168192), (8168188, 'b', 8168356), (8168240, 'bpl', 8168352), (8168316, 'bne', 8168352), (8168352, 'b', 8168356)],
        semantics=('[Shark -[remoteUpdate:]] (imp 0x007ca190, 148w): -[remoteUpdate:] (0x7ca190, 148w): [super remoteUpdate:arg] (cells 0x7ca3b0/0x7ca3b4); if (!self.dead @56) { [arg getBytes:buf length:0x28]; [self doRemoteUpdate:<that struct>] (cell 0x7ca3c4); } else { if (self.travelFraction @296 < 1.0f && ![self.dynamicWorld @8 isClient]) self.needsRemoved @48 = 0; } (selector cells: getBytes:length: 0x7ca3bc, isClient 0x7ca3d0)..\n'),
    ),
    dict(
        name='sh_35',
        method='Shark -[removeRider:]',
        types='v12@0:4@8',
        start=8247248,
        end=8247516,
        disasm='disasm_worldtileloader_sh_35.txt',
        base_add=8247264,
        base_literal=8247512,
        boundary='ARM.exidx end 0x007dd8dc (listing bound); next ObjC IMP 0x007dd8dc Shark -[minRidableAge]',
        selectors={
                 0x7dd8c8: (15210712, 'removeRider:'),
        },
        imports={
                 0x7dd8c4: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0x7dd8c0: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0x7dd8d4: (17160704, 'OBJC_IVAR_$_Shark.riderTargetVelocity', 388),
        },
        classes={
                 0x7dd8cc: (15252820, 'OBJC_CLASS_$_Shark'),
        },
        instructions=[(8247248, 'push {fp, lr}'), (8247512, 'addeq r2, r8, ip, lsl 6')],
        calls=[(8247388, 'blx r3'), (8247452, 'bl method.Vector2.Vector2_float__float_')],
        branches=[(8247316, 'bne', 8247480)],
        semantics=('[Shark -[removeRider:]] (imp 0x007dd7d0, 67w): -[removeRider:] (0x7dd7d0, 67w): if (blockhead == self.rider @132): [super removeRider:blockhead] via msgSendSuper2 (cells 0x7dd8c8/0x7dd8cc); then self.riderTargetVelocity @388 = Vector2(0.0f, 0.0f) (pool 0x7dd8d0 = 0.0) via Vector2::Vector2 + 2-word store..\n'),
    ),
    dict(
        name='sh_36',
        method='Shark -[renderPos]',
        types='{Vector2=[2f]}8@0:4',
        start=8244404,
        end=8244536,
        disasm='disasm_worldtileloader_sh_36.txt',
        base_add=8244436,
        base_literal=8244528,
        boundary='ARM.exidx end 0x007dcd38 (listing bound); next ObjC IMP 0x007dcd38 Shark -[center]',
        selectors={},
        imports={},
        ivars={
                 0x7dcd2c: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x7dcd34: (17160712, 'OBJC_IVAR_$_Shark.xOffset', 332),
        },
        classes={},
        instructions=[(8244404, 'push {fp, lr}'), (8244532, 'invalid')],
        calls=[(8244492, 'bl method.Vector2.Vector2_float__float_'), (8244512, 'bl method.Vector2.operator_Vector2_')],
        branches=[],
        semantics=('[Shark -[renderPos]] (imp 0x007dccb4, 33w): -[renderPos] (0x7dccb4, 33w): returns DynamicObject.floatPos @24 + Vector2(xOffset @332, 0.0f) via Vector2::Vector2(float,float) + Vector2::operator+(Vector2) (sret; xOffset loaded as float, second component from 0 register)..\n'),
    ),
    dict(
        name='sh_37',
        method='Shark -[rideDirection]',
        types='i8@0:4',
        start=8246744,
        end=8246992,
        disasm='disasm_worldtileloader_sh_37.txt',
        base_add=8246760,
        base_literal=8246988,
        boundary='ARM.exidx end 0x007dd6d0 (listing bound); next ObjC IMP 0x007dd6d0 Shark -[addRider:]',
        selectors={},
        imports={},
        ivars={
                 0x7dd6bc: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0x7dd6c4: (17160704, 'OBJC_IVAR_$_Shark.riderTargetVelocity', 388),
        },
        classes={},
        instructions=[(8246744, 'push {fp, lr}'), (8246988, 'addeq r2, r8, r4, lsl 10')],
        calls=[(8246836, 'bl method.Vector2.operator_float__'), (8246896, 'bl method.Vector2.operator_float__')],
        branches=[(8246808, 'beq', 8246952), (8246856, 'ble', 8246872), (8246868, 'b', 8246940), (8246948, 'b', 8246960)],
        semantics=('[Shark -[rideDirection]] (imp 0x007dd5d8, 62w): -[rideDirection] (0x7dd5d8, 62w): if (self.rider @132 == nil) return 0; x = (float*)self.riderTargetVelocity @388 first component (Vector2::operator float*()); if (x > +0.1f (pool 0x7dd6c0)) return 1; if (x < -0.1f (pool 0x7dd6c8)) return -1; return 0 (sign with dead zone)..\n'),
    ),
    dict(
        name='sh_38',
        method='Shark -[riderBodyYRotationForBlockhead:]',
        types='f12@0:4@8',
        start=8246592,
        end=8246660,
        disasm='disasm_worldtileloader_sh_38.txt',
        base_add=8246620,
        base_literal=8246656,
        boundary='ARM.exidx end 0x007dd584 (listing bound); next ObjC IMP 0x007dd584 Shark -[setTargetVelocity:]',
        selectors={},
        imports={},
        ivars={
                 0x7dd57c: (17160620, 'OBJC_IVAR_$_Shark.bodyRotation', 304),
        },
        classes={},
        instructions=[(8246592, 'sub sp, sp, 0xc'), (8246656, 'umulleq r2, r8, r0, r5')],
        calls=[],
        branches=[],
        semantics=('[Shark -[riderBodyYRotationForBlockhead:]] (imp 0x007dd540, 17w): -[riderBodyYRotationForBlockhead:] (0x7dd540, 17w): returns self.bodyRotation @304 as float (vldr s0 from self+offset; vmov r0,s0)..\n'),
    ),
    dict(
        name='sh_39',
        method='Shark -[riderDPadShouldAllowUpDown]',
        types='c8@0:4',
        start=8247972,
        end=8248000,
        disasm='disasm_worldtileloader_sh_39.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x007ddac0 (listing bound); next ObjC IMP 0x007ddac0 Shark -[.cxx_construct]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8247972, 'sub sp, sp, 8'), (8247996, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Shark -[riderDPadShouldAllowUpDown]] (imp 0x007ddaa4, 7w): -[riderDPadShouldAllowUpDown] (0x7ddaa4, 7w): returns 1 (YES) via movw r2,1; sxtb r0,r2..\n'),
    ),
    dict(
        name='sh_40',
        method='Shark -[riderPosForBlockhead:]',
        types='{Vector=[4f]}12@0:4@8',
        start=8246168,
        end=8246492,
        disasm='disasm_worldtileloader_sh_40.txt',
        base_add=8246184,
        base_literal=8246488,
        boundary='ARM.exidx end 0x007dd4dc (listing bound); next ObjC IMP 0x007dd4dc Shark -[cameraPosForBlockhead:]',
        selectors={},
        imports={},
        ivars={
                 0x7dd4d0: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0x7dd4d4: (17160676, 'OBJC_IVAR_$_Shark.namePosition', 336),
        },
        classes={},
        instructions=[(8246168, 'push {fp, lr}'), (8246488, 'addeq r2, r8, r4, asr 14')],
        calls=[(8246232, 'bl method.Vector2.operator_float__'), (8246268, 'bl method.Vector2.operator_float__'), (8246460, 'bl method.Vector.Vector_float__float__float_')],
        branches=[(8246376, 'bpl', 8246396), (8246392, 'b', 8246404)],
        semantics=('[Shark -[riderPosForBlockhead:]] (imp 0x007dd398, 81w): -[riderPosForBlockhead:] (0x7dd398, 81w): returns Vector3 (Vector::Vector(float,float,float)): x = namePosition @336 .x; y = (namePosition.y - 1.0f) + 0.5f * min(age/NPC.maxAge? no: age/9000.0f, 1.0f) - f = min((float)age @88 / 9000.0f (pool 0x7dd4cc), 1.0); 0.5 factor from gl (vmov.f64 d2=0.5); z = -0.75f (gl: vmov.f32 s2 #232 @0xbf400000)..\n'),
    ),
    dict(
        name='sh_41',
        method='Shark -[riderRidesWithArmsDown]',
        types='c8@0:4',
        start=8247944,
        end=8247972,
        disasm='disasm_worldtileloader_sh_41.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x007ddac0; body trimmed at the next IMP 0x007ddaa4 Shark -[riderDPadShouldAllowUpDown]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8247944, 'sub sp, sp, 8'), (8247968, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Shark -[riderRidesWithArmsDown]] (imp 0x007dda88, 7w): -[riderRidesWithArmsDown] (0x7dda88, 7w): returns 0 (NO) via movw r2,0; sxtb r0,r2..\n'),
    ),
    dict(
        name='sh_42',
        method='Shark -[setTargetVelocity:]',
        types='v16@0:4{Vector2=[2f]}8',
        start=8246660,
        end=8246744,
        disasm='disasm_worldtileloader_sh_42.txt',
        base_add=8246672,
        base_literal=8246740,
        boundary='ARM.exidx end 0x007dd5d8 (listing bound); next ObjC IMP 0x007dd5d8 Shark -[rideDirection]',
        selectors={},
        imports={},
        ivars={
                 0x7dd5d0: (17160704, 'OBJC_IVAR_$_Shark.riderTargetVelocity', 388),
        },
        classes={},
        instructions=[(8246660, 'push {fp, lr}'), (8246740, 'addeq r2, r8, ip, asr r5')],
        calls=[],
        branches=[],
        semantics=('[Shark -[setTargetVelocity:]] (imp 0x007dd584, 21w): -[setTargetVelocity:] (0x7dd584, 21w): stores the Vector2 by-value arg (r2/r3) directly into self.riderTargetVelocity @388 (2-word store); no conversion..\n'),
    ),
    dict(
        name='sh_43',
        method='Shark -[sharkUpdateNetDataForClient:]',
        types='{SharkUpdateNetData={NPCUpdateNetData={DynamicObjectNetData=QIIC[7C]}}IIsScc[2C]}12@0:4@8',
        start=8162480,
        end=8162864,
        disasm='disasm_worldtileloader_sh_43.txt',
        base_add=8162496,
        base_literal=8162860,
        boundary='ARM.exidx end 0x007c8e30 (listing bound); next ObjC IMP 0x007c8e30 Shark -[creationNetDataForClient:]',
        selectors={
                 0x7c8e10: (15210460, 'npcUpdateNetDataForClient:'),
        },
        imports={},
        ivars={
                 0x7c8e14: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x7c8e1c: (17160596, 'OBJC_IVAR_$_Shark.walkSpeed', 324),
                 0x7c8e24: (17160592, 'OBJC_IVAR_$_Shark.movementDirection', 276),
                 0x7c8e28: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
        },
        classes={},
        instructions=[(8162480, 'push {r4, sl, fp, lr}'), (8162860, 'addeq r6, sb, ip, lsr 28')],
        calls=[(8162576, 'bl loc.imp.objc_msgSend_stret'), (8162612, 'bl sym.imp.memset')],
        branches=[(8162556, 'beq', 8162584), (8162580, 'b', 8162616)],
        semantics=('[Shark -[sharkUpdateNetDataForClient:]] (imp 0x007c8cb0, 96w): -[sharkUpdateNetDataForClient:] (0x7c8cb0, 96w) [sret, returns 0x28-byte SharkUpdateNetData]: dest[0..0x18) = objc_msgSend_stret [self npcUpdateNetDataForClient:arg] (cell 0x7c8e10, 24 bytes); dest+0x18 = DynamicObject.pos @16 word0; dest+0x1c = pos word1; dest+0x20 = (short)(walkSpeed @324 * 255.0f) (pool 0x7c8e20=255.0); dest+0x22 = (short)age @88; dest+0x24 = (byte)movementDirection @276. Fields written by O0 store sequence rows 34-85..\n'),
    ),
    dict(
        name='sh_44',
        method='Shark -[speciesName]',
        types='@8@0:4',
        start=8155672,
        end=8155720,
        disasm='disasm_worldtileloader_sh_44.txt',
        base_add=8155680,
        base_literal=8155716,
        boundary='ARM.exidx end 0x007c72e8; body trimmed at the next IMP 0x007c7248 Shark -[foodItemType]',
        selectors={},
        imports={
                 0x7c7240: (16322184, '__CFConstantStringClassReference'),
        },
        ivars={},
        classes={},
        instructions=[(8155672, 'sub sp, sp, 8'), (8155716, 'addeq r8, sb, ip, asr 17')],
        calls=[],
        branches=[],
        semantics=('[Shark -[speciesName]] (imp 0x007c7218, 12w): -[speciesName] (0x7c7218, 12w): returns the CFString object @0xF90E88 (cstring 0xF563B1, len 5, "SHARK") materialized as PIC base 0x0105FAF4 + 0xfff31394 (add-pc pair self-checked)..\n'),
    ),
    dict(
        name='sh_45',
        method='Shark -[tapIsWithinBodyRadius:]',
        types='c16@0:4{Vector2=[2f]}8',
        start=8242372,
        end=8243516,
        disasm='disasm_worldtileloader_sh_45.txt',
        base_add=8242388,
        base_literal=8243512,
        boundary='ARM.exidx end 0x007dca30; body trimmed at the next IMP 0x007dc93c Shark -[reactToBeingHit]',
        selectors={
                 0x7dc92c: (15210536, 'maxAge'),
        },
        imports={
                 0x7dc928: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x7dc920: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0x7dc924: (17160592, 'OBJC_IVAR_$_Shark.movementDirection', 276),
                 0x7dc930: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0x7dc934: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={},
        instructions=[(8242372, 'push {fp, lr}'), (8243512, 'addeq r3, r8, r8, lsl r6')],
        calls=[(8242496, 'bl method.Vector2.operator_float__'), (8242536, 'bl method.Vector2.operator_float__'), (8242576, 'bl method.Vector2.operator_float__'), (8242616, 'bl method.Vector2.operator_float__'), (8242724, 'blx r2'), (8242796, 'bl method.Vector2.operator_float__'), (8242836, 'bl method.Vector2.operator_float__'), (8242880, 'bl method.Vector2.operator_float__'), (8242920, 'bl method.Vector2.operator_float__'), (8242980, 'bl method.Vector2.operator_float__'), (8243020, 'bl method.Vector2.operator_float__'), (8243136, 'blx r2'), (8243208, 'bl method.Vector2.operator_float__'), (8243248, 'bl method.Vector2.operator_float__'), (8243288, 'bl method.Vector2.operator_float__'), (8243328, 'bl method.Vector2.operator_float__'), (8243372, 'bl method.Vector2.operator_float__'), (8243412, 'bl method.Vector2.operator_float__')],
        branches=[(8242440, 'beq', 8242456), (8242452, 'b', 8243476), (8242488, 'bge', 8242976), (8242568, 'ble', 8242972), (8242788, 'bpl', 8242972), (8242872, 'ble', 8242972), (8242956, 'bpl', 8242972), (8242968, 'b', 8243476), (8242972, 'b', 8243468), (8243200, 'ble', 8243464), (8243280, 'bpl', 8243464), (8243364, 'ble', 8243464), (8243448, 'bpl', 8243464), (8243460, 'b', 8243476), (8243464, 'b', 8243468)],
        semantics=('[Shark -[tapIsWithinBodyRadius:]] (imp 0x007dc4c4, 286w): -[tapIsWithinBodyRadius:] (0x7dc4c4, 286w): hit-test for taps (Vector2 arg). If dead @56 -> NO. t = age/maxAge (27000); R = 2.0 * (0.25 + 1.5*t) (gl d1=2.0 d2=0.25 d3=1.5); facing = movementDirection @276 < 0: YES iff (floatPos.x@24 - 0.5) < pos.x < floatPos.x + R AND floatPos.y < pos.y < floatPos.y + 1.0; else: YES iff (floatPos.x - 0.5) - R < pos.x < floatPos.x + 0.5 AND same y-range (half-extents are 0.5 in gl - r2 labels them 5). Boundary: body trimmed at next IMP (0x7dc93c reactToBeingHit), exidx end 0x7dca30..\n'),
    ),
    dict(
        name='sh_46',
        method='Shark -[updateNetDataForClient:]',
        types='@12@0:4@8',
        start=8163596,
        end=8163832,
        disasm='disasm_worldtileloader_sh_46.txt',
        base_add=8163612,
        base_literal=8163828,
        boundary='ARM.exidx end 0x007c91f8 (listing bound); next ObjC IMP 0x007c91f8 Shark -[dealloc]',
        selectors={
                 0x7c91e4: (15210468, 'sharkUpdateNetDataForClient:'),
                 0x7c91ec: (15210476, 'dataWithBytes:length:'),
        },
        imports={
                 0x7c91e8: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0x7c91f0: (15247168, 'OBJC_CLASS_$_NSData'),
        },
        instructions=[(8163596, 'push {fp, lr}'), (8163828, 'ldrdeq r6, r7, [sb], r0')],
        calls=[(8163692, 'bl loc.imp.objc_msgSend_stret'), (8163728, 'bl sym.imp.memset'), (8163792, 'blx ip')],
        branches=[(8163672, 'beq', 8163700), (8163696, 'b', 8163732)],
        semantics=('[Shark -[updateNetDataForClient:]] (imp 0x007c910c, 59w): -[updateNetDataForClient:] (0x7c910c, 59w): return [NSData dataWithBytes:<objc_msgSend_stret [self sharkUpdateNetDataForClient:arg] 0x28 bytes> length:0x28] (cells: sharkUpdateNetDataForClient: 0x7c91e4, dataWithBytes:length: 0x7c91ec, NSData 0x7c91f0)..\n'),
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
        'batch': 'Shark (E140): the shark animal; 47 bodies',
        'claim': ('the shark animal (AI tick, motion/render, capture data)'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'shark.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale shark.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
