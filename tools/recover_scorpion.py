#!/usr/bin/env python3
"""Hash-gated recovery of the Scorpion (E143).

Scorpion lands: the batch sweeps scorpion surface:
42 bodies, 17765 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/SCORPION.md for the prose and boundaries.
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
    'bl 0x893bd0': 0x00893bd0,
    'bl 0x8a3164': 0x008a3164,
    'bl 0x8a31d8': 0x008a31d8,
    'bl 0x8a3570': 0x008a3570,
    'bl 0x8a3908': 0x008a3908,
    'bl 0x8a3af0': 0x008a3af0,
    'bl 0x8a3e88': 0x008a3e88,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl loc.imp.objc_msgSendSuper2_stret': 0x001c335c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector.operator_float__': 0x004b5c08,
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl method.Vector2.operator_Vector2_': 0x004d0418,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__wrap_fmodf': 0x001c3d4c,
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
    'bl sym.tileAtWorldPosition_int__int__MacroTile__World_': 0x00a16e68,
}

SPECS = [
    dict(
        name='sc_00',
        method='Scorpion -[.cxx_construct]',
        types='@8@0:4',
        start=9094300,
        end=9094324,
        disasm='disasm_worldtileloader_sc_00.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x008ac4b4 (listing bound); next ObjC IMP 0x008ac884 DynamicWorld -[initWithWorld:worldTileLoader:clientTileLoader:server:client:serverClients:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:appDatabase:worldDatabase:dynamicObjectDatabase:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9094300, 'sub sp, sp, 8'), (9094320, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Scorpion -[.cxx_construct]] (imp 0x008ac49c, 6w): -[.cxx_construct] (0x8ac49c, 6w): empty `return self` stub (O0 sub sp/save r0/r1/reload r0); no C++ member constructor calls - no non-POD Scorpion ivars need init..\n'),
    ),
    dict(
        name='sc_01',
        method='Scorpion -[addRider:]',
        types='v12@0:4@8',
        start=9093300,
        end=9093508,
        disasm='disasm_worldtileloader_sc_01.txt',
        base_add=9093316,
        base_literal=9093504,
        boundary='ARM.exidx end 0x008ac184 (listing bound); next ObjC IMP 0x008ac184 Scorpion -[removeRider:]',
        selectors={
                 0x8ac16c: (15215788, 'addRider:'),
        },
        imports={
                 0x8ac168: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0x8ac174: (17157392, 'OBJC_IVAR_$_NPC.beingControlled', 128),
                 0x8ac17c: (17162184, 'OBJC_IVAR_$_Scorpion.riderTargetVelocity', 340),
        },
        classes={
                 0x8ac170: (15252908, 'OBJC_CLASS_$_Scorpion'),
        },
        instructions=[(9093300, 'push {r4, r5, fp, lr}'), (9093504, 'rsbseq r3, fp, r8, lsr 20')],
        calls=[(9093392, 'blx lr')],
        branches=[(9093428, 'bne', 9093472)],
        semantics=('[Scorpion -[addRider:]] (imp 0x008ac0b4, 52w): -[addRider:] (0x8ac0b4, 52w): [super addRider:rider] via objc_msgSendSuper2 (superstruct {self, OBJC_CLASS_$_Scorpion}, SEL addRider:); then if (NPC.beingControlled@128 == 0) riderTargetVelocity@340 = 0.0f (pool 0x8ac178=0x0, float scalar not Vector2 - differs from Shark). Mounting clears rider velocity only when not being controlled..\n'),
    ),
    dict(
        name='sc_02',
        method='Scorpion -[blockheadCanRide:usingItem:]',
        types='c16@0:4@8i12',
        start=9093728,
        end=9094024,
        disasm='disasm_worldtileloader_sc_02.txt',
        base_add=9093744,
        base_literal=9094020,
        boundary='ARM.exidx end 0x008ac388 (listing bound); next ObjC IMP 0x008ac388 Scorpion -[jumpsOnSwipe]',
        selectors={
                 0x8ac374: (15215764, 'tamed'),
                 0x8ac378: (15215760, 'belongsToPlayerWithBlockhead:'),
        },
        imports={
                 0x8ac370: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8ac37c: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0x8ac380: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
        },
        classes={},
        instructions=[(9093728, 'push {r4, sl, fp, lr}'), (9094020, 'rsbseq r3, fp, ip, ror r8')],
        calls=[(9093792, 'blx lr'), (9093864, 'blx r3')],
        branches=[(9093804, 'beq', 9093888), (9093884, 'beq', 9093980), (9093928, 'bne', 9093980)],
        semantics=('[Scorpion -[blockheadCanRide:usingItem:]] (imp 0x008ac260, 74w): -[blockheadCanRide:usingItem:] (0x8ac260, 74w): returns (![self tamed] || [self belongsToPlayerWithBlockhead:blockhead]) && !NPC.dead@56 && !DynamicObject.needsRemoved@48 (needsRemoved value eor-inverted). usingItem: arg (r3) never read; there is no age gate (unlike Shark\'s minRidableAge)..\n'),
    ),
    dict(
        name='sc_03',
        method='Scorpion -[blockheadUnloaded:]',
        types='v12@0:4@8',
        start=9094052,
        end=9094272,
        disasm='disasm_worldtileloader_sc_03.txt',
        base_add=9094068,
        base_literal=9094268,
        boundary='ARM.exidx end 0x008ac480 (listing bound); next ObjC IMP 0x008ac480 Scorpion -[riderRidesWithArmsDown]',
        selectors={
                 0x8ac474: (15215796, 'blockheadUnloaded:'),
        },
        imports={
                 0x8ac470: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0x8ac464: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0x8ac46c: (17162184, 'OBJC_IVAR_$_Scorpion.riderTargetVelocity', 340),
        },
        classes={
                 0x8ac478: (15252908, 'OBJC_CLASS_$_Scorpion'),
        },
        instructions=[(9094052, 'push {fp, lr}'), (9094268, 'rsbseq r3, fp, r8, lsr r7')],
        calls=[(9094232, 'blx r3')],
        branches=[(9094120, 'bne', 9094164)],
        semantics=('[Scorpion -[blockheadUnloaded:]] (imp 0x008ac3a4, 55w): -[blockheadUnloaded:] (0x8ac3a4, 55w): if (arg == NPC.rider@132) riderTargetVelocity@340 = 0.0f (pool 0x8ac468=0x0); then unconditionally [super blockheadUnloaded:arg] via objc_msgSendSuper2. No attackBlockhead release here (unlike Shark sh_03)..\n'),
    ),
    dict(
        name='sc_04',
        method='Scorpion -[cameraPosForBlockhead:]',
        types='{Vector2=[2f]}12@0:4@8',
        start=9092780,
        end=9092880,
        disasm='disasm_worldtileloader_sc_04.txt',
        base_add=9092796,
        base_literal=9092876,
        boundary='ARM.exidx end 0x008abf10 (listing bound); next ObjC IMP 0x008abf10 Scorpion -[riderBodyYRotationForBlockhead:]',
        selectors={
                 0x8abf04: (15215784, 'cameraPosForBlockhead:'),
        },
        imports={},
        ivars={},
        classes={
                 0x8abf08: (15252908, 'OBJC_CLASS_$_Scorpion'),
        },
        instructions=[(9092780, 'push {r4, sl, fp, lr}'), (9092876, 'rsbseq r3, fp, r0, lsr ip')],
        calls=[(9092856, 'bl loc.imp.objc_msgSendSuper2_stret')],
        branches=[],
        semantics=('[Scorpion -[cameraPosForBlockhead:]] (imp 0x008abeac, 25w): -[cameraPosForBlockhead:] (0x8abeac, 25w): pure forward [super cameraPosForBlockhead:] via objc_msgSendSuper2_stret (Vector2 sret); the blockhead arg is passed through r3 and never read locally..\n'),
    ),
    dict(
        name='sc_05',
        method='Scorpion -[canBeCapturedByBlockhead:withItemType:]',
        types='c16@0:4@8i12',
        start=9091872,
        end=9092040,
        disasm='disasm_worldtileloader_sc_05.txt',
        base_add=9091888,
        base_literal=9092036,
        boundary='ARM.exidx end 0x008abbc8 (listing bound); next ObjC IMP 0x008abbc8 Scorpion -[cantBeCapturedTipStringForBlockhead:withItemType:]',
        selectors={
                 0x8abbc0: (15215760, 'belongsToPlayerWithBlockhead:'),
        },
        imports={
                 0x8abbbc: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9091872, 'push {fp, lr}'), (9092036, 'ldrhteq r3, [fp], -0xfc')],
        calls=[(9091976, 'blx r3')],
        branches=[(9091924, 'bne', 9092008), (9091988, 'beq', 9092004), (9092000, 'b', 9092016), (9092004, 'b', 9092008)],
        semantics=('[Scorpion -[canBeCapturedByBlockhead:withItemType:]] (imp 0x008abb20, 42w): -[canBeCapturedByBlockhead:withItemType:] (0x8abb20, 42w): if (itemType r3 != 0x12e/302) return 0; else return [self belongsToPlayerWithBlockhead:blockhead] (sxtb). No age check (Shark required age<4500)..\n'),
    ),
    dict(
        name='sc_06',
        method='Scorpion -[cantBeCapturedTipStringForBlockhead:withItemType:]',
        types='@16@0:4@8i12',
        start=9092040,
        end=9092536,
        disasm='disasm_worldtileloader_sc_06.txt',
        base_add=9092056,
        base_literal=9092532,
        boundary='ARM.exidx end 0x008abdb8 (listing bound); next ObjC IMP 0x008abdb8 Scorpion -[riderPosForBlockhead:]',
        selectors={
                 0x8abd98: (15215764, 'tamed'),
                 0x8abda0: (15215732, 'stringWithFormat:'),
                 0x8abda4: (15215776, 'speciesName'),
                 0x8abdac: (15215760, 'belongsToPlayerWithBlockhead:'),
        },
        imports={
                 0x8abd94: (17151904, 'objc_msgSend'),
                 0x8abd9c: (16332440, '__CFConstantStringClassReference'),
                 0x8abdb0: (16332424, '__CFConstantStringClassReference'),
        },
        ivars={},
        classes={
                 0x8abda8: (15247776, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(9092040, 'push {r4, r5, fp, lr}'), (9092532, 'rsbseq r3, fp, r4, lsl pc')],
        calls=[(9092136, 'blx r2'), (9092200, 'blx r3'), (9092296, 'blx r2'), (9092332, 'blx ip'), (9092428, 'blx r2'), (9092464, 'blx ip')],
        branches=[(9092092, 'bne', 9092480), (9092148, 'beq', 9092348), (9092212, 'bne', 9092344), (9092340, 'b', 9092488), (9092344, 'b', 9092476), (9092472, 'b', 9092488), (9092476, 'b', 9092480)],
        semantics=('[Scorpion -[cantBeCapturedTipStringForBlockhead:withItemType:]] (imp 0x008abbc8, 124w): -[cantBeCapturedTipStringForBlockhead:withItemType:] (0x8abbc8, 124w): if (itemType != 0x12e) return nil; if (![self tamed]) return [NSString stringWithFormat:@"%@S MUST BE TAMED\\nBEFORE YOU CAN CAPTURE THEM", [self speciesName]] (fmt obj 0xF93698, cstr 0xF5607B); if ([self belongsToPlayerWithBlockhead:blockhead]) return nil; else return fmt @"THAT %@ BELONGS TO\\nSOMEONE ELSE" (obj 0xF93688, cstr 0xF55DCE)..\n'),
    ),
    dict(
        name='sc_07',
        method='Scorpion -[captureRequiredItemType]',
        types='i8@0:4',
        start=8991164,
        end=8991192,
        disasm='disasm_worldtileloader_sc_07.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00893224; body trimmed at the next IMP 0x008931d8 Scorpion -[getNamesArray]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8991164, 'sub sp, sp, 8'), (8991188, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Scorpion -[captureRequiredItemType]] (imp 0x008931bc, 7w): -[captureRequiredItemType] (0x8931bc, 7w): return 0x12e (302)..\n'),
    ),
    dict(
        name='sc_08',
        method='Scorpion -[capturedItemType]',
        types='i8@0:4',
        start=8991136,
        end=8991164,
        disasm='disasm_worldtileloader_sc_08.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00893224; body trimmed at the next IMP 0x008931bc Scorpion -[captureRequiredItemType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8991136, 'sub sp, sp, 8'), (8991160, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Scorpion -[capturedItemType]] (imp 0x008931a0, 7w): -[capturedItemType] (0x8931a0, 7w): return 0x147 (327)..\n'),
    ),
    dict(
        name='sc_09',
        method='Scorpion -[creationDataStructSize]',
        types='L8@0:4',
        start=8996896,
        end=8996924,
        disasm='disasm_worldtileloader_sc_09.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0089483c (listing bound); next ObjC IMP 0x0089483c Scorpion -[remoteCreationDataUpdate:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8996896, 'sub sp, sp, 8'), (8996920, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Scorpion -[creationDataStructSize]] (imp 0x00894820, 7w): -[creationDataStructSize] (0x894820, 7w): return 0x80 (128)..\n'),
    ),
    dict(
        name='sc_10',
        method='Scorpion -[creationNetDataForClient:]',
        types='@12@0:4@8',
        start=8995424,
        end=8996136,
        disasm='disasm_worldtileloader_sc_10.txt',
        base_add=8995440,
        base_literal=8996132,
        boundary='ARM.exidx end 0x00894528 (listing bound); next ObjC IMP 0x00894528 Scorpion -[updateNetDataForClient:]',
        selectors={
                 0x8944fc: (15215520, 'npcCreationNetDataForClient:'),
                 0x894500: (15215524, 'scorpionUpdateNetDataForClient:'),
                 0x894510: (15215528, 'uniqueID'),
                 0x894518: (15215536, 'appendNPCCreationDataToData:'),
                 0x89451c: (15215532, 'dataWithBytes:length:'),
        },
        imports={
                 0x894514: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x894504: (17162132, 'OBJC_IVAR_$_Scorpion.attackBlockhead', 312),
                 0x894508: (17162136, 'OBJC_IVAR_$_Scorpion.spitting', 328),
        },
        classes={
                 0x894520: (15247764, 'OBJC_CLASS_$_NSData'),
        },
        instructions=[(8995424, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8996132, 'rsbseq fp, ip, ip, ror r8')],
        calls=[(8995528, 'bl loc.imp.objc_msgSend_stret'), (8995564, 'bl sym.imp.memset'), (8995620, 'bl sym.imp.memcpy'), (8995692, 'bl loc.imp.objc_msgSend_stret'), (8995728, 'bl sym.imp.memset'), (8995924, 'bl loc.imp.objc_msgSend'), (8996044, 'blx ip'), (8996072, 'blx r3')],
        branches=[(8995508, 'beq', 8995536), (8995532, 'b', 8995568), (8995672, 'beq', 8995700), (8995696, 'b', 8995732), (8995864, 'beq', 8995960)],
        semantics=('[Scorpion -[creationNetDataForClient:]] (imp 0x00894260, 178w): -[creationNetDataForClient:] (0x894260, 178w): local 0x80-byte creation buffer at fp-0xa8. 1) objc_msgSend_stret(sp+0x78, self, \'npcCreationNetDataForClient:\', arg) -> 0x48 bytes (self==0 -> memset 0x48), then memcpy into buf[0..0x48). 2) objc_msgSend_stret(sp+0x50, self, \'scorpionUpdateNetDataForClient:\', arg) -> 0x28 bytes (self==0 -> memset), copied (word by word) into buf[0x48..0x70). 3) if (attackBlockhead@312 != nil): buf+0x70/0x74 = [attackBlockhead uniqueID] qword; buf+0x78 = spitting@328 byte (uid qword pre-zeroed at fp-0x34/-0x38). 4) return [self appendNPCCreationDataToData:[NSData dataWithBytes:buf length:0x80]]. No isNet guard on the attackBlockhead field (unlike Shark sh_11)..\n'),
    ),
    dict(
        name='sc_11',
        method='Scorpion -[dealloc]',
        types='v8@0:4',
        start=8996372,
        end=8996896,
        disasm='disasm_worldtileloader_sc_11.txt',
        base_add=8996388,
        base_literal=8996892,
        boundary='ARM.exidx end 0x00894820 (listing bound); next ObjC IMP 0x00894820 Scorpion -[creationDataStructSize]',
        selectors={
                 0x8947f0: (15215544, 'dealloc'),
                 0x8947fc: (15215540, 'release'),
        },
        imports={
                 0x8947ec: (17151900, 'objc_msgSendSuper2'),
                 0x8947f8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x894800: (17162056, 'OBJC_IVAR_$_Scorpion.armCube', 244),
                 0x894804: (17162060, 'OBJC_IVAR_$_Scorpion.legCube', 240),
                 0x894808: (17162064, 'OBJC_IVAR_$_Scorpion.tailCubeD', 236),
                 0x89480c: (17162068, 'OBJC_IVAR_$_Scorpion.tailCubeC', 232),
                 0x894810: (17162072, 'OBJC_IVAR_$_Scorpion.tailCubeB', 228),
                 0x894814: (17162076, 'OBJC_IVAR_$_Scorpion.tailCubeA', 224),
                 0x894818: (17162080, 'OBJC_IVAR_$_Scorpion.bodyCube', 220),
        },
        classes={
                 0x8947f4: (15252908, 'OBJC_CLASS_$_Scorpion'),
        },
        instructions=[(8996372, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8996892, 'rsbseq fp, ip, r8, asr 9')],
        calls=[(8996576, 'blx r5'), (8996612, 'blx r3'), (8996648, 'blx r3'), (8996684, 'blx r3'), (8996720, 'blx r3'), (8996756, 'blx r3'), (8996792, 'blx r3'), (8996832, 'blx r2')],
        branches=[],
        semantics=('[Scorpion -[dealloc]] (imp 0x00894614, 131w): -[dealloc] (0x894614, 131w): releases 7 cubes in order bodyCube@220, tailCubeA@224, tailCubeB@228, tailCubeC@232, tailCubeD@236, legCube@240, armCube@244 (each [obj release]), then [super dealloc] via objc_msgSendSuper2. Textures (bodyTexture@212/legTexture@216), shader@208 and attackBlockhead@312 are NOT released..\n'),
    ),
    dict(
        name='sc_12',
        method='Scorpion -[die:]',
        types='v12@0:4@8',
        start=9061448,
        end=9061872,
        disasm='disasm_worldtileloader_sc_12.txt',
        base_add=9061464,
        base_literal=9061868,
        boundary='ARM.exidx end 0x008a45f0 (listing bound); next ObjC IMP 0x008a45f0 Scorpion -[update:accurateDT:isSimulation:]',
        selectors={
                 0x8a45c0: (15215628, 'die:'),
                 0x8a45d8: (15215616, 'instance'),
                 0x8a45dc: (15215620, 'multiSoundNamed:'),
                 0x8a45e8: (15215624, 'playAtPosition:afterDelay:'),
        },
        imports={
                 0x8a45bc: (17151900, 'objc_msgSendSuper2'),
                 0x8a45e0: (16332312, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x8a45b8: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0x8a45cc: (17162104, 'OBJC_IVAR_$_Scorpion.travelFraction', 268),
                 0x8a45e4: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={
                 0x8a45c4: (15252908, 'OBJC_CLASS_$_Scorpion'),
                 0x8a45d0: (15247768, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(9061448, 'push {r4, r5, r6, r7, fp, lr}'), (9061868, 'invalid')],
        calls=[(9061628, 'bl loc.imp.objc_msgSend'), (9061652, 'bl loc.imp.objc_msgSend'), (9061732, 'bl loc.imp.objc_msgSend'), (9061800, 'blx ip')],
        branches=[(9061512, 'bne', 9061808), (9061804, 'b', 9061808)],
        semantics=('[Scorpion -[die:]] (imp 0x008a4448, 106w): -[die:] (0x8a4448, 106w): if (!NPC.dead@56): [MJSoundManager instance] -> multiSoundNamed:@"scorpionAttack.wav" (obj 0xF93618) -> playAtPosition:floatPos@24.x,.y afterDelay:0.1 (double 0x3FB99999A0000000); travelFraction@268 = 0.0f (pool 0x8a45c8=0x0); [super die:arg] via objc_msgSendSuper2 (arg passed through, not tested)..\n'),
    ),
    dict(
        name='sc_13',
        method='Scorpion -[doRemoteUpdate:]',
        types='v48@0:4{ScorpionUpdateNetData={NPCUpdateNetData={DynamicObjectNetData=QIIC[7C]}}IIscC[4c]}8',
        start=8999040,
        end=9000088,
        disasm='disasm_worldtileloader_sc_13.txt',
        base_add=8999056,
        base_literal=9000084,
        boundary='ARM.exidx end 0x00895498 (listing bound); next ObjC IMP 0x00895498 Scorpion -[remoteUpdate:]',
        selectors={
                 0x895464: (15215572, 'isClient'),
                 0x895470: (15215552, 'isNet'),
        },
        imports={
                 0x895460: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x895468: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x89546c: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0x895474: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0x895478: (17162116, 'OBJC_IVAR_$_Scorpion.movementDirection', 248),
                 0x89547c: (17162120, 'OBJC_IVAR_$_Scorpion.remoteMovementDirection', 356),
                 0x895480: (17162096, 'OBJC_IVAR_$_Scorpion.walkSpeed', 288),
                 0x895484: (17162124, 'OBJC_IVAR_$_Scorpion.remoteWalkSpeed', 352),
                 0x89548c: (17162128, 'OBJC_IVAR_$_Scorpion.remoteGoalSquare', 344),
                 0x895490: (17162132, 'OBJC_IVAR_$_Scorpion.attackBlockhead', 312),
        },
        classes={},
        instructions=[(8999040, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9000084, 'rsbseq sl, ip, ip, asr sl')],
        calls=[(8999228, 'blx lr'), (8999344, 'blx r2'), (8999404, 'bl sym.makeIntpair_int__int_'), (8999700, 'blx r2'), (8999852, 'blx r2'), (8999912, 'bl sym.makeIntpair_int__int_')],
        branches=[(8999240, 'bne', 8999592), (8999280, 'beq', 8999588), (8999356, 'beq', 8999588), (8999588, 'b', 9000024), (8999636, 'beq', 8999728), (8999748, 'bne', 9000020), (8999788, 'beq', 8999868), (8999864, 'beq', 9000020), (9000020, 'b', 9000024)],
        semantics=('[Scorpion -[doRemoteUpdate:]] (imp 0x00895080, 262w): -[doRemoteUpdate:] (0x895080, 262w): net struct 0x28 (w0/w1 in r2/r3, w2..w9 on stack; w6/w7=toSquare pair, w8=(s16)walkSpeed*255 | (s8)movementDirection<<16). Server branch (![self.dynamicWorld@8 isClient]): if (rider@132 != nil && [rider isNet]) { remoteGoalSquare@344 = (w6,w7) via makeIntpair; remoteWalkSpeed@352 = walkSpeed@288 = (s16)w8 / 255.0f (pool 0x895488=255.0); remoteMovementDirection@356 = movementDirection@248 = (s8)(w8>>16); updateNeedsToBeSent@49 = 1; }. Client branch (isClient): if ((rider==nil || [rider isNet]) && (attackBlockhead@312==nil || [attackBlockhead isNet])) { remoteGoalSquare=(w6,w7); remoteWalkSpeed=(s16)w8/255; remoteMovementDirection=(s8)(w8>>16); } - no walkSpeed mirror, no age update..\n'),
    ),
    dict(
        name='sc_14',
        method='Scorpion -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        types='v156@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76i140i144i148i152',
        start=9000496,
        end=9056612,
        disasm='disasm_worldtileloader_sc_14.txt',
        base_add=9000552,
        base_literal=9004524,
        boundary='ARM.exidx end 0x008a3164 (listing bound); next ObjC IMP 0x008a4448 Scorpion -[die:]',
        selectors={
                 0x8965fc: (15215580, 'worldWidthMacro'),
                 0x89716c: (15215584, 'macroTiles'),
                 0x89b88c: (15215588, 'program'),
                 0x89b894: (15215600, 'intValue'),
                 0x89b898: (15215596, 'objectAtIndex:'),
                 0x89b89c: (15215592, 'uniformLocations'),
                 0x89b8a0: (15215604, 'dayColor'),
                 0x89b8c4: (15215608, 'name'),
                 0x89b8cc: (15215612, 'draw'),
                 0x8a314c: (15215600, 'intValue'),
                 0x8a3150: (15215596, 'objectAtIndex:'),
                 0x8a3154: (15215592, 'uniformLocations'),
                 0x8a315c: (15215612, 'draw'),
        },
        imports={
                 0x897168: (17151904, 'objc_msgSend'),
                 0x89b888: (17151904, 'objc_msgSend'),
                 0x8a3148: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8965f0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x8965f8: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x896e98: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x897170: (17162112, 'OBJC_IVAR_$_Scorpion.fromSquare', 252),
                 0x897174: (17157400, 'OBJC_IVAR_$_NPC.visible', 57),
                 0x897178: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0x89717c: (17162116, 'OBJC_IVAR_$_Scorpion.movementDirection', 248),
                 0x897180: (17162152, 'OBJC_IVAR_$_Scorpion.bodyRotation', 276),
                 0x897184: (17162156, 'OBJC_IVAR_$_Scorpion.randomGoalRotation', 280),
                 0x89718c: (17162160, 'OBJC_IVAR_$_Scorpion.zRotation', 300),
                 0x897190: (17162104, 'OBJC_IVAR_$_Scorpion.travelFraction', 268),
                 0x8971a0: (17162144, 'OBJC_IVAR_$_Scorpion.biting', 320),
                 0x8971a4: (17162140, 'OBJC_IVAR_$_Scorpion.biteTimer', 324),
                 0x8971a8: (17162136, 'OBJC_IVAR_$_Scorpion.spitting', 328),
                 0x8971ac: (17162148, 'OBJC_IVAR_$_Scorpion.spitTimer', 332),
                 0x8971b8: (17162164, 'OBJC_IVAR_$_Scorpion.walkTimer', 284),
                 0x8992e0: (17162168, 'OBJC_IVAR_$_Scorpion.multiplierA', 304),
                 0x8992e4: (17162172, 'OBJC_IVAR_$_Scorpion.multiplierB', 308),
                 0x89b890: (17162092, 'OBJC_IVAR_$_Scorpion.shader', 208),
                 0x89b8a4: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x89b8c0: (17162088, 'OBJC_IVAR_$_Scorpion.bodyTexture', 212),
                 0x89b8c8: (17162080, 'OBJC_IVAR_$_Scorpion.bodyCube', 220),
                 0x89db40: (17162076, 'OBJC_IVAR_$_Scorpion.tailCubeA', 224),
                 0x89db44: (17162072, 'OBJC_IVAR_$_Scorpion.tailCubeB', 228),
                 0x89db48: (17162068, 'OBJC_IVAR_$_Scorpion.tailCubeC', 232),
                 0x89db4c: (17162064, 'OBJC_IVAR_$_Scorpion.tailCubeD', 236),
                 0x89db50: (17162084, 'OBJC_IVAR_$_Scorpion.legTexture', 216),
                 0x8a0028: (17162056, 'OBJC_IVAR_$_Scorpion.armCube', 244),
                 0x8a002c: (17162060, 'OBJC_IVAR_$_Scorpion.legCube', 240),
                 0x8a3158: (17162092, 'OBJC_IVAR_$_Scorpion.shader', 208),
                 0x8a3160: (17162060, 'OBJC_IVAR_$_Scorpion.legCube', 240),
        },
        classes={},
        instructions=[(9000496, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9056608, 'invalid')],
        calls=[(9001580, 'bl loc.imp.objc_msgSend'), (9001612, 'bl sym.imp.__aeabi_idiv'), (9001692, 'bl loc.imp.objc_msgSend'), (9001844, 'bl loc.imp.objc_msgSend'), (9001864, 'bl sym.imp.__aeabi_idiv'), (9001944, 'bl loc.imp.objc_msgSend'), (9002100, 'bl loc.imp.objc_msgSend'), (9002132, 'bl sym.imp.__aeabi_idiv'), (9002212, 'bl loc.imp.objc_msgSend'), (9002364, 'bl loc.imp.objc_msgSend'), (9002384, 'bl sym.imp.__aeabi_idiv'), (9002464, 'bl loc.imp.objc_msgSend'), (9002812, 'bl method.Vector2.operator_float__'), (9002884, 'bl loc.imp.objc_msgSend'), (9002916, 'bl sym.imp.__aeabi_idiv'), (9003028, 'bl loc.imp.objc_msgSend'), (9003072, 'bl method.Vector2.operator_float__'), (9003136, 'bl method.Vector2.operator_float__'), (9003208, 'bl loc.imp.objc_msgSend'), (9003228, 'bl sym.imp.__aeabi_idiv'), (9003332, 'bl loc.imp.objc_msgSend'), (9003368, 'bl method.Vector2.operator_float__'), (9003516, 'blx r2'), (9003568, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (9003760, 'bl method.Vector2.operator_float__'), (9003788, 'bl method.Vector2.operator_float__'), (9003844, 'bl 0x8a3164'), (9005120, 'bl 0x8a31d8'), (9005664, 'bl 0x8a3570'), (9005716, 'bl sym.imp.memcpy'), (9006180, 'bl 0x8a3908'), (9006232, 'bl sym.imp.memcpy'), (9006700, 'bl 0x8a3af0'), (9006736, 'bl sym.imp.memcpy'), (9007188, 'bl 0x8a3af0'), (9007224, 'bl sym.imp.memcpy'), (9007648, 'bl sym.imp.sinf'), (9008088, 'bl 0x8a3908'), (9008316, 'bl sym.imp.sinf'), (9008604, 'bl 0x8a31d8'), (9009120, 'bl 0x8a3908'), (9009324, 'bl sym.imp.sinf'), (9009608, 'bl 0x8a31d8'), (9010124, 'bl 0x8a3908'), (9010328, 'bl sym.imp.sinf'), (9010612, 'bl 0x8a31d8'), (9011128, 'bl 0x8a3908'), (9011332, 'bl sym.imp.sinf'), (9011616, 'bl 0x8a31d8'), (9011792, 'bl sym.imp.__wrap_fmodf'), (9011880, 'bl sym.imp.__wrap_fmodf'), (9012516, 'bl 0x8a3908'), (9012956, 'bl 0x8a3570'), (9013464, 'bl 0x8a3af0'), (9014048, 'bl 0x8a3908'), (9014484, 'bl 0x8a3570'), (9014992, 'bl 0x8a3af0'), (9015552, 'bl 0x8a3908'), (9015928, 'bl 0x8a3af0'), (9016508, 'bl 0x8a31d8'), (9017044, 'bl 0x8a3908'), (9017420, 'bl 0x8a3af0'), (9017976, 'bl 0x8a31d8'), (9018520, 'bl 0x8a3908'), (9018896, 'bl 0x8a3af0'), (9019452, 'bl 0x8a31d8'), (9019988, 'bl 0x8a3908'), (9020364, 'bl 0x8a3af0'), (9020920, 'bl 0x8a31d8'), (9021456, 'bl 0x8a3908'), (9021832, 'bl 0x8a3af0'), (9022388, 'bl 0x8a31d8'), (9022924, 'bl 0x8a3908'), (9023300, 'bl 0x8a3af0'), (9023864, 'bl 0x8a31d8'), (9023944, 'bl sym.imp.memcpy'), (9023996, 'blx ip'), (9024000, 'bl sym.imp.__wrap_glUseProgram'), (9024144, 'blx r6'), (9024164, 'blx r3'), (9024180, 'blx r2'), (9024188, 'bl sym.imp.__wrap_glUniform1i'), (9024280, 'bl loc.imp.objc_msgSend_stret'), (9024320, 'bl sym.imp.memset'), (9024832, 'bl method.Vector.Vector_float__float__float_'), (9024852, 'bl method.Vector.operator_float__'), (9024928, 'bl method.Vector.operator_float__'), (9024980, 'bl method.Vector.operator_float__'), (9025056, 'bl method.Vector.operator_float__'), (9025108, 'bl method.Vector.operator_float__'), (9025184, 'bl method.Vector.operator_float__'), (9025256, 'bl method.Vector.Vector_float__float__float_'), (9025276, 'bl method.Vector.operator_float__'), (9025412, 'bl method.Vector.operator_float__'), (9025440, 'bl method.Vector.operator_float__'), (9025572, 'bl method.Vector.operator_float__'), (9025600, 'bl method.Vector.operator_float__'), (9025808, 'bl method.Vector.operator_float__'), (9025884, 'bl loc.imp.objc_msgSend'), (9025920, 'bl loc.imp.objc_msgSend'), (9025944, 'bl loc.imp.objc_msgSend'), (9025960, 'bl method.Vector.operator_float__'), (9025976, 'bl method.Vector.operator_float__'), (9025992, 'bl method.Vector.operator_float__'), (9026024, 'bl sym.imp.__wrap_glUniform4f'), (9026032, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (9026084, 'bl loc.imp.objc_msgSend'), (9026112, 'bl sym.imp.__wrap_glBindTexture'), (9027020, 'bl 0x8a3e88'), (9027928, 'bl 0x8a3e88'), (9027968, 'bl loc.imp.objc_msgSend'), (9027996, 'bl loc.imp.objc_msgSend'), (9028012, 'bl loc.imp.objc_msgSend'), (9028032, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9028072, 'bl loc.imp.objc_msgSend'), (9028100, 'bl loc.imp.objc_msgSend'), (9028116, 'bl loc.imp.objc_msgSend'), (9028132, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9028184, 'bl loc.imp.objc_msgSend'), (9029096, 'bl 0x8a3e88'), (9030136, 'bl 0x8a3e88'), (9030312, 'bl loc.imp.objc_msgSend'), (9030332, 'bl loc.imp.objc_msgSend'), (9030348, 'bl loc.imp.objc_msgSend'), (9030364, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9030404, 'bl loc.imp.objc_msgSend'), (9030424, 'bl loc.imp.objc_msgSend'), (9030440, 'bl loc.imp.objc_msgSend'), (9030456, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9030500, 'bl loc.imp.objc_msgSend'), (9031428, 'bl 0x8a3e88'), (9032468, 'bl 0x8a3e88'), (9032652, 'bl loc.imp.objc_msgSend'), (9032672, 'bl loc.imp.objc_msgSend'), (9032688, 'bl loc.imp.objc_msgSend'), (9032704, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9032744, 'bl loc.imp.objc_msgSend'), (9032764, 'bl loc.imp.objc_msgSend'), (9032780, 'bl loc.imp.objc_msgSend'), (9032796, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9032840, 'bl loc.imp.objc_msgSend'), (9033752, 'bl 0x8a3e88'), (9034832, 'bl 0x8a3e88'), (9035016, 'bl loc.imp.objc_msgSend'), (9035036, 'bl loc.imp.objc_msgSend'), (9035052, 'bl loc.imp.objc_msgSend'), (9035068, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9035108, 'bl loc.imp.objc_msgSend'), (9035128, 'bl loc.imp.objc_msgSend'), (9035144, 'bl loc.imp.objc_msgSend'), (9035160, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9035204, 'bl loc.imp.objc_msgSend'), (9036116, 'bl 0x8a3e88'), (9037172, 'bl 0x8a3e88'), (9037356, 'bl loc.imp.objc_msgSend'), (9037376, 'bl loc.imp.objc_msgSend'), (9037392, 'bl loc.imp.objc_msgSend'), (9037408, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9037448, 'bl loc.imp.objc_msgSend'), (9037468, 'bl loc.imp.objc_msgSend'), (9037484, 'bl loc.imp.objc_msgSend'), (9037500, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9037544, 'bl loc.imp.objc_msgSend'), (9037588, 'bl loc.imp.objc_msgSend'), (9037608, 'bl sym.imp.__wrap_glBindTexture'), (9038520, 'bl 0x8a3e88'), (9039576, 'bl 0x8a3e88'), (9039760, 'bl loc.imp.objc_msgSend'), (9039780, 'bl loc.imp.objc_msgSend'), (9039796, 'bl loc.imp.objc_msgSend'), (9039812, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9039852, 'bl loc.imp.objc_msgSend'), (9039872, 'bl loc.imp.objc_msgSend'), (9039888, 'bl loc.imp.objc_msgSend'), (9039904, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9039952, 'bl loc.imp.objc_msgSend'), (9040864, 'bl 0x8a3e88'), (9041920, 'bl 0x8a3e88'), (9042104, 'bl loc.imp.objc_msgSend'), (9042124, 'bl loc.imp.objc_msgSend'), (9042140, 'bl loc.imp.objc_msgSend'), (9042156, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9042196, 'bl loc.imp.objc_msgSend'), (9042216, 'bl loc.imp.objc_msgSend'), (9042232, 'bl loc.imp.objc_msgSend'), (9042248, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9042288, 'bl loc.imp.objc_msgSend'), (9043200, 'bl 0x8a3e88'), (9044268, 'bl 0x8a3e88'), (9044452, 'bl loc.imp.objc_msgSend'), (9044472, 'bl loc.imp.objc_msgSend'), (9044488, 'bl loc.imp.objc_msgSend'), (9044504, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9044544, 'bl loc.imp.objc_msgSend'), (9044564, 'bl loc.imp.objc_msgSend'), (9044580, 'bl loc.imp.objc_msgSend'), (9044596, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9044644, 'bl loc.imp.objc_msgSend'), (9045556, 'bl 0x8a3e88'), (9046612, 'bl 0x8a3e88'), (9046796, 'bl loc.imp.objc_msgSend'), (9046816, 'bl loc.imp.objc_msgSend'), (9046832, 'bl loc.imp.objc_msgSend'), (9046848, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9046888, 'bl loc.imp.objc_msgSend'), (9046908, 'bl loc.imp.objc_msgSend'), (9046924, 'bl loc.imp.objc_msgSend'), (9046940, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9046980, 'bl loc.imp.objc_msgSend'), (9047892, 'bl 0x8a3e88'), (9048948, 'bl 0x8a3e88'), (9049132, 'bl loc.imp.objc_msgSend'), (9049152, 'bl loc.imp.objc_msgSend'), (9049168, 'bl loc.imp.objc_msgSend'), (9049184, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9049224, 'bl loc.imp.objc_msgSend'), (9049244, 'bl loc.imp.objc_msgSend'), (9049260, 'bl loc.imp.objc_msgSend'), (9049276, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9049316, 'bl loc.imp.objc_msgSend'), (9050228, 'bl 0x8a3e88'), (9051284, 'bl 0x8a3e88'), (9051468, 'bl loc.imp.objc_msgSend'), (9051488, 'bl loc.imp.objc_msgSend'), (9051504, 'bl loc.imp.objc_msgSend'), (9051520, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9051560, 'bl loc.imp.objc_msgSend'), (9051580, 'bl loc.imp.objc_msgSend'), (9051596, 'bl loc.imp.objc_msgSend'), (9051612, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9051652, 'bl loc.imp.objc_msgSend'), (9052564, 'bl 0x8a3e88'), (9053620, 'bl 0x8a3e88'), (9053804, 'bl loc.imp.objc_msgSend'), (9053824, 'bl loc.imp.objc_msgSend'), (9053840, 'bl loc.imp.objc_msgSend'), (9053856, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9053896, 'bl loc.imp.objc_msgSend'), (9053916, 'bl loc.imp.objc_msgSend'), (9053932, 'bl loc.imp.objc_msgSend'), (9053948, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9053988, 'bl loc.imp.objc_msgSend'), (9054900, 'bl 0x8a3e88'), (9055956, 'bl 0x8a3e88'), (9056132, 'bl sym.imp.memcpy'), (9056184, 'blx ip'), (9056204, 'blx r3'), (9056220, 'blx r2'), (9056252, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9056408, 'blx r3'), (9056428, 'blx r3'), (9056444, 'blx r2'), (9056476, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9056564, 'blx r3'), (9056572, 'bl sym.imp.__wrap_glDisableVertexAttribArray')],
        branches=[(9001628, 'blt', 9001736), (9001732, 'b', 9001988), (9001880, 'bge', 9001984), (9001984, 'b', 9001988), (9002148, 'blt', 9002256), (9002252, 'b', 9002508), (9002400, 'bge', 9002504), (9002504, 'b', 9002508), (9002556, 'blt', 9002716), (9002608, 'bgt', 9002716), (9002660, 'blt', 9002716), (9002712, 'ble', 9002720), (9002716, 'b', 9056576), (9002944, 'ble', 9003100), (9003096, 'b', 9003396), (9003256, 'bpl', 9003392), (9003392, 'b', 9003396), (9003596, 'beq', 9003624), (9003620, 'bne', 9003672), (9003668, 'b', 9056576), (9003744, 'bne', 9003752), (9003748, 'b', 9003752), (9003916, 'bne', 9004064), (9003992, 'bpl', 9004060), (9004056, 'b', 9003936), (9004060, 'b', 9004648), (9004080, 'bne', 9004228), (9004156, 'ble', 9004224), (9004220, 'b', 9004100), (9004224, 'b', 9004644), (9004328, 'ble', 9004396), (9004392, 'b', 9004272), (9004396, 'b', 9004400), (9004456, 'bpl', 9004640), (9004520, 'b', 9004400), (9004640, 'b', 9004644), (9004644, 'b', 9004648), (9005752, 'beq', 9007232), (9006268, 'ble', 9006760), (9006740, 'b', 9007228), (9007228, 'b', 9007232), (9007276, 'beq', 9007364), (9007328, 'b', 9007592), (9007408, 'beq', 9007552), (9007460, 'b', 9007576), (9007572, 'b', 9007576), (9013688, 'b', 9013720), (9016028, 'b', 9016048), (9024260, 'beq', 9024288), (9024284, 'b', 9024324), (9024456, 'bpl', 9024484), (9024480, 'b', 9024504), (9024556, 'bpl', 9024584), (9024580, 'b', 9024604), (9024656, 'ble', 9024732), (9025320, 'bpl', 9025352), (9025344, 'b', 9025372), (9025484, 'bpl', 9025512), (9025508, 'b', 9025532), (9025644, 'bpl', 9025744), (9025668, 'b', 9025764), (9034556, 'b', 9034580), (9044004, 'b', 9044016)],
        semantics=('[Scorpion -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]] (imp 0x00895630, 14029w): -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:...cameraMaxYWorld:] (0x895630, 14029w, CENSUS 63br/255 calls): renders the scorpion. Huge O0 frame: two-stage sub sp (0x8e0 + 0x3000, bic sp,#0xf) with 4 scratch arenas (sp+0x1000/0x2000/0x3000/0x3400) + ~30 spilled args. Head: toroidal wrap of dx/dy against worldWidthMacro*32 (pairs of blt/bge wraps at 0x895a9c/0x895b98/0x895ca4/0x895da0), then visibility early-outs b 0x8a3140 (skips everything incl. glDisable; gates include dead/visible ivars + a 4-compare range chain at 0x895e3c..0x895ed8), tileAtWorldPosition@0x896230 ground check (beq/bne at 0x89624c/264), two matrix-compose loops (0x8963a0..0x8965e8), 4x conditional 64B memcpy (0x896a94/96c98/96e90/97078) with guards at 0x896ab8/96cbc, 5x sinf (0x897220/974bc/978ac/97c98/98084 - walk/tail sway phases) + 2x fmodf (0x898250/982a8: fmodf(angle,1.0f) wrap *4.0). GL setup at 0x89b200: glUseProgram([shader program]); glUniform1i([uniformLocations[1].intValue], 0); objc_msgSend_stret dayColor (0x89b318) -> glUniform4f(uniformLocations[2].intValue, dayColor.rgb,1.0f) (0x89b9e8); glEnableVertexAttribArray(2) (0x89b9f0); glBindTexture(GL_TEXTURE_2D=0xde1, [bodyTexture name]) (0x89ba40). Then 12 cube draw blocks (starts 0x89c180, caa8, d3cc, dd08, e62c, ef90, f8b8, 8a01e4, 0b0c, 142c, 1d4c, 266c): each = matrix compose (helpers 0x8a3e88 x26, 0x8a3908 x13, 0x8a31d8 x11, 0x8a3af0 x10, 0x8a3570 x3, 0x8a3164 x1) + memcpy(64B) + 3 objc_msgSend ([shader uniformLocations]/[. objectAtIndex:0]/[. intValue]) + glUniformMatrix4fv(mvp) (x26 total) + again objectAtIndex:3 -> glUniformMatrix4fv(normal_matrix) + [cube draw]. Cube identity pinned by cell loads: B1 bodyCube@220 (cell 0x89b8c8), B2-B5 tailCubeA..D@224-236 (cells 0x89db40-4c), B6 armCube@244 (cell 0x8a0028; legTexture bound at 0x89e728 just before, cell 0x89db50), B8 legCube@240 (cell 0x8a002c); B7/B9-B12 reuse stack-spilled cube pointers. Tail (0x8a2f84-0x8a313c): memcpy + 2 more glUniformMatrix4fv + draws with legCube@240 (cell 0x8a3160, x2), then glDisableVertexAttribArray(2) (0x8a313c). Float constants: vmov 0.5 (d2/s2/s6), 1.0, -0.5, 5.0, 4.0; movw/movt bit patterns 0x3eb33333(0.35) 0x3ee66666(0.45) 0x3e99999a(0.3) 0x3e851eb8(0.26) 0xbe800000(-0.25) etc; selectors used: worldWidthMacro, macroTiles, dayColor, name, draw, intValue, objectAtIndex:, uniformLocations, program..\n'),
    ),
    dict(
        name='sc_15',
        method='Scorpion -[foodItemType]',
        types='i8@0:4',
        start=8991108,
        end=8991136,
        disasm='disasm_worldtileloader_sc_15.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00893224; body trimmed at the next IMP 0x008931a0 Scorpion -[capturedItemType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8991108, 'sub sp, sp, 8'), (8991132, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Scorpion -[foodItemType]] (imp 0x00893184, 7w): -[foodItemType] (0x893184, 7w): return 0x18 (24)..\n'),
    ),
    dict(
        name='sc_16',
        method='Scorpion -[getNamesArray]',
        types='^@8@0:4',
        start=8991192,
        end=8991240,
        disasm='disasm_worldtileloader_sc_16.txt',
        base_add=8991200,
        base_literal=8991236,
        boundary='ARM.exidx end 0x00893224; body trimmed at the next IMP 0x00893208 Scorpion -[getNamesArrayCount]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8991192, 'sub sp, sp, 8'), (8991236, 'rsbseq ip, ip, ip, lsl 18')],
        calls=[],
        branches=[],
        semantics=('[Scorpion -[getNamesArray]] (imp 0x008931d8, 12w): -[getNamesArray] (0x8931d8, 12w): returns PIC-materialized pointer 0x01052148 -> 22-entry CFString table (full walk verified): Muffet, Spindra, Aragog, Fluffy, Nightmare, Sparkles, Diablo, Legs, Pincers, Claws, Aladin, Bandit, Basil, Herculies, Nero, Ringo, Spike, Snuggles, Bubbles, Venom, Pinchy, Scorpio..\n'),
    ),
    dict(
        name='sc_17',
        method='Scorpion -[getNamesArrayCount]',
        types='i8@0:4',
        start=8991240,
        end=8991268,
        disasm='disasm_worldtileloader_sc_17.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00893224 (listing bound); next ObjC IMP 0x00893224 Scorpion -[loadDerivedStuff]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8991240, 'sub sp, sp, 8'), (8991264, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Scorpion -[getNamesArrayCount]] (imp 0x00893208, 7w): -[getNamesArrayCount] (0x893208, 7w): return 0x16 (22)..\n'),
    ),
    dict(
        name='sc_18',
        method='Scorpion -[hitWithForce:blockhead:]',
        types='v16@0:4i8@12',
        start=9090628,
        end=9091160,
        disasm='disasm_worldtileloader_sc_18.txt',
        base_add=9090644,
        base_literal=9091156,
        boundary='ARM.exidx end 0x008ab858 (listing bound); next ObjC IMP 0x008ab858 Scorpion -[renderPos]',
        selectors={
                 0x8ab820: (15215768, 'hitWithForce:blockhead:'),
                 0x8ab830: (15215720, 'isUnderLocalControl'),
        },
        imports={
                 0x8ab81c: (17151900, 'objc_msgSendSuper2'),
                 0x8ab82c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8ab828: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0x8ab834: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0x8ab838: (17162100, 'OBJC_IVAR_$_Scorpion.randomTimeBetweenDirectionChanges', 272),
                 0x8ab83c: (17162096, 'OBJC_IVAR_$_Scorpion.walkSpeed', 288),
                 0x8ab840: (17162116, 'OBJC_IVAR_$_Scorpion.movementDirection', 248),
                 0x8ab84c: (17162180, 'OBJC_IVAR_$_Scorpion.attackDelay', 316),
                 0x8ab850: (17162188, 'OBJC_IVAR_$_Scorpion.provoked', 336),
        },
        classes={
                 0x8ab824: (15252908, 'OBJC_CLASS_$_Scorpion'),
        },
        instructions=[(9090628, 'push {r4, r5, r6, r7, fp, lr}'), (9091156, 'invalid')],
        calls=[(9090728, 'blx r4'), (9090808, 'blx r2'), (9090892, 'bl 0x893bd0')],
        branches=[(9090764, 'bne', 9091092), (9090820, 'beq', 9091092)],
        semantics=('[Scorpion -[hitWithForce:blockhead:]] (imp 0x008ab644, 133w): -[hitWithForce:blockhead:] (0x8ab644, 133w): [super hitWithForce:force blockhead:blockhead]; if (!NPC.dead@56 && [self isUnderLocalControl]): provoked@336 = 1; attackDelay@316 = 0.0f (pool 0x8ab848=0x0); r = lrand48 wrapper 0x893bd0 (bare bl); movementDirection@248 = ((double)((float)r / 2^31f) > 0.5) ? 1 : -1 (pool 0x8ab844=2^31; gl: vmov.f64 d2,#96=0.5, mvneq r7,#0 -> -1); walkSpeed@288 = 3.0f; randomTimeBetweenDirectionChanges@272 = 5.0f; updateNeedsToBeSent@49 = 1..\n'),
    ),
    dict(
        name='sc_19',
        method='Scorpion -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:]',
        types='@44@0:4@8@12{?=ii}16@24@28c32c36@40',
        start=8993760,
        end=8994136,
        disasm='disasm_worldtileloader_sc_19.txt',
        base_add=8993776,
        base_literal=8994132,
        boundary='ARM.exidx end 0x00893d58 (listing bound); next ObjC IMP 0x00893d58 Scorpion -[initWithWorld:dynamicWorld:saveDict:cache:]',
        selectors={
                 0x893d48: (15215492, 'initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:'),
                 0x893d50: (15215496, 'loadDerivedStuff'),
        },
        imports={
                 0x893d4c: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0x893d40: (15252908, 'OBJC_CLASS_$_Scorpion'),
        },
        instructions=[(8993760, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8994132, 'ldrshteq fp, [ip], -0xec')],
        calls=[(8994004, 'bl loc.imp.objc_msgSendSuper2'), (8994088, 'blx r2')],
        branches=[(8994032, 'bne', 8994048), (8994044, 'b', 8994100)],
        semantics=('[Scorpion -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:]] (imp 0x00893be0, 94w): -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:] (0x893be0, 94w): re-packs the 2-word atPosition arg + 5 singles onto its stack and calls [super <same 8-arg selector>] via objc_msgSendSuper2; if (result == nil) return nil; else [self loadDerivedStuff]; return self. No terrain/water/temperature validation (unlike Shark sh_20)..\n'),
    ),
    dict(
        name='sc_20',
        method='Scorpion -[initWithWorld:dynamicWorld:cache:netData:]',
        types='@24@0:4@8@12@16@20',
        start=8994432,
        end=8994944,
        disasm='disasm_worldtileloader_sc_20.txt',
        base_add=8994448,
        base_literal=8994940,
        boundary='ARM.exidx end 0x00894080 (listing bound); next ObjC IMP 0x00894080 Scorpion -[getSaveDict]',
        selectors={
                 0x894054: (15215504, 'initWithWorld:dynamicWorld:cache:netData:'),
                 0x894060: (15215508, 'remoteCreationDataUpdate:'),
                 0x894078: (15215496, 'loadDerivedStuff'),
        },
        imports={
                 0x894050: (17151900, 'objc_msgSendSuper2'),
                 0x89405c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x894064: (17162120, 'OBJC_IVAR_$_Scorpion.remoteMovementDirection', 356),
                 0x89406c: (17162124, 'OBJC_IVAR_$_Scorpion.remoteWalkSpeed', 352),
                 0x894070: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x894074: (17162128, 'OBJC_IVAR_$_Scorpion.remoteGoalSquare', 344),
        },
        classes={
                 0x894058: (15252908, 'OBJC_CLASS_$_Scorpion'),
        },
        instructions=[(8994432, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8994940, 'rsbseq fp, ip, ip, asr ip')],
        calls=[(8994584, 'blx r6'), (8994752, 'blx r7'), (8994872, 'blx r5')],
        branches=[(8994612, 'bne', 8994628), (8994624, 'b', 8994884)],
        semantics=('[Scorpion -[initWithWorld:dynamicWorld:cache:netData:]] (imp 0x00893e80, 128w): -[initWithWorld:dynamicWorld:cache:netData:] (0x893e80, 128w): [super <same>]; nil -> nil; [self loadDerivedStuff]; remoteGoalSquare@344 = DynamicObject.pos@16 (2-word copy); remoteWalkSpeed@352 = 0.0f (pool 0x894068=0x0); remoteMovementDirection@356 = 0; [self remoteCreationDataUpdate:netData]; return self..\n'),
    ),
    dict(
        name='sc_21',
        method='Scorpion -[isUnderLocalControl]',
        types='c8@0:4',
        start=9090236,
        end=9090628,
        disasm='disasm_worldtileloader_sc_21.txt',
        base_add=9090252,
        base_literal=9090624,
        boundary='ARM.exidx end 0x008ab644 (listing bound); next ObjC IMP 0x008ab644 Scorpion -[hitWithForce:blockhead:]',
        selectors={
                 0x8ab63c: (15215552, 'isNet'),
        },
        imports={
                 0x8ab638: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8ab630: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x8ab634: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
        },
        classes={},
        instructions=[(9090236, 'push {fp, lr}'), (9090624, 'rsbseq r4, fp, r0, lsr 12')],
        calls=[(9090420, 'blx r3'), (9090552, 'blx r2')],
        branches=[(9090296, 'beq', 9090444), (9090344, 'beq', 9090584), (9090440, 'bne', 9090584), (9090488, 'beq', 9090576)],
        semantics=('[Scorpion -[isUnderLocalControl]] (imp 0x008ab4bc, 98w): -[isUnderLocalControl] (0x8ab4bc, 98w): if (DynamicObject.isNet@52) return (NPC.rider@132 != 0 && ![rider isNet]); else return !(rider != 0 && [rider isNet]) (eor-inverted). i.e. loc rider exists XOR rider is net-bound. Same shape as Shark sh_22..\n'),
    ),
    dict(
        name='sc_22',
        method='Scorpion -[jumpsOnSwipe]',
        types='c8@0:4',
        start=9094024,
        end=9094052,
        disasm='disasm_worldtileloader_sc_22.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x008ac3a4 (listing bound); next ObjC IMP 0x008ac3a4 Scorpion -[blockheadUnloaded:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9094024, 'sub sp, sp, 8'), (9094048, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Scorpion -[jumpsOnSwipe]] (imp 0x008ac388, 7w): -[jumpsOnSwipe] (0x8ac388, 7w): return 0 (sxtb) - does not use swipe-jump..\n'),
    ),
    dict(
        name='sc_23',
        method='Scorpion -[loadDerivedStuff]',
        types='v8@0:4',
        start=8991268,
        end=8993744,
        disasm='disasm_worldtileloader_sc_23.txt',
        base_add=8991288,
        base_literal=8993740,
        boundary='ARM.exidx end 0x00893bd0 (listing bound); next ObjC IMP 0x00893be0 Scorpion -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:]',
        selectors={
                 0x893b3c: (15215488, 'initWithWidth:height:depth:centerX:centerY:centerZ:calculateNormals:'),
                 0x893b40: (15215480, 'alloc'),
                 0x893b64: (15215484, 'initWithWidth:height:depth:calculateNormals:'),
                 0x893b70: (15215476, 'textureNamed:'),
                 0x893b88: (15215472, 'shaderNamed:attributes:uniforms:'),
                 0x893b9c: (15215468, 'arrayWithObjects:'),
        },
        imports={
                 0x893b38: (17151904, 'objc_msgSend'),
                 0x893b6c: (16332296, '__CFConstantStringClassReference'),
                 0x893b7c: (16332280, '__CFConstantStringClassReference'),
                 0x893b84: (16332152, '__CFConstantStringClassReference'),
                 0x893b8c: (16332216, '__CFConstantStringClassReference'),
                 0x893b90: (16332232, '__CFConstantStringClassReference'),
                 0x893b94: (16332248, '__CFConstantStringClassReference'),
                 0x893b98: (16332264, '__CFConstantStringClassReference'),
                 0x893ba4: (16332168, '__CFConstantStringClassReference'),
                 0x893ba8: (16332184, '__CFConstantStringClassReference'),
                 0x893bac: (16332200, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x893b34: (17162056, 'OBJC_IVAR_$_Scorpion.armCube', 244),
                 0x893b48: (17162060, 'OBJC_IVAR_$_Scorpion.legCube', 240),
                 0x893b4c: (17162064, 'OBJC_IVAR_$_Scorpion.tailCubeD', 236),
                 0x893b54: (17162068, 'OBJC_IVAR_$_Scorpion.tailCubeC', 232),
                 0x893b58: (17162072, 'OBJC_IVAR_$_Scorpion.tailCubeB', 228),
                 0x893b5c: (17162076, 'OBJC_IVAR_$_Scorpion.tailCubeA', 224),
                 0x893b60: (17162080, 'OBJC_IVAR_$_Scorpion.bodyCube', 220),
                 0x893b68: (17162084, 'OBJC_IVAR_$_Scorpion.legTexture', 216),
                 0x893b74: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0x893b78: (17162088, 'OBJC_IVAR_$_Scorpion.bodyTexture', 212),
                 0x893b80: (17162092, 'OBJC_IVAR_$_Scorpion.shader', 208),
                 0x893bb0: (17162096, 'OBJC_IVAR_$_Scorpion.walkSpeed', 288),
                 0x893bb4: (17162100, 'OBJC_IVAR_$_Scorpion.randomTimeBetweenDirectionChanges', 272),
                 0x893bb8: (17162104, 'OBJC_IVAR_$_Scorpion.travelFraction', 268),
                 0x893bbc: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x893bc0: (17162108, 'OBJC_IVAR_$_Scorpion.toSquare', 260),
                 0x893bc4: (17162112, 'OBJC_IVAR_$_Scorpion.fromSquare', 252),
                 0x893bc8: (17162116, 'OBJC_IVAR_$_Scorpion.movementDirection', 248),
        },
        classes={
                 0x893b44: (15247760, 'OBJC_CLASS_$_DrawCube'),
                 0x893ba0: (15247756, 'OBJC_CLASS_$_NSArray'),
        },
        instructions=[(8991268, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8993740, 'ldrhteq ip, [ip], -0x84')],
        calls=[(8991940, 'blx lr'), (8992004, 'blx r5'), (8992048, 'blx lr'), (8992108, 'blx ip'), (8992168, 'blx ip'), (8992220, 'blx ip'), (8992276, 'blx lr'), (8992392, 'blx ip'), (8992484, 'blx lr'), (8992536, 'blx ip'), (8992624, 'blx lr'), (8992676, 'blx ip'), (8992768, 'blx lr'), (8992820, 'blx ip'), (8992904, 'blx lr'), (8992956, 'blx ip'), (8993040, 'blx lr'), (8993092, 'blx ip'), (8993176, 'blx lr'), (8993200, 'bl 0x893bd0'), (8993500, 'bl 0x893bd0')],
        branches=[(8992308, 'b', 8992372), (8993244, 'ble', 8993260), (8993256, 'b', 8993304)],
        semantics=('[Scorpion -[loadDerivedStuff]] (imp 0x00893224, 619w): -[loadDerivedStuff] (0x893224, 619w, census-lite): builds all GPU resources + randomizes movement state. shader@208 = [cache@32 shaderNamed:@"ShadedWorldObject"(0xF93578) attributes:[NSArray arrayWithObjects:@"position",@"texCoord",@"normal",nil] uniforms:[NSArray arrayWithObjects:@"mvp_matrix",@"texture",@"light",@"normal_matrix",nil]]; bodyTexture@212 = [cache textureNamed:@"scorpion.png"(0xF935F8)]; legTexture@216 = [cache textureNamed:@"scorpionLeg.png"(0xF93608)]. Cubes (DrawCube alloc + init; floats passed in GPRs per tsv types): bodyCube@220 = initWithWidth:0.8 height:0.3 depth:0.4 calculateNormals:1 [4-arg]; tailCubeA@224 = (5.0, 0.2, 0.12, 0.0, 0.1, 0.175, 1); tailCubeB@228 = (0.4, 0.15, 0.3, 0.0, 0.075, 0.15, 1); tailCubeC@232 = (0.12, 0.27, 0.06, 0.0, 0.135, 0.35, 1); tailCubeD@236 = (5.0, 0.1, 0.1, 0.0, 0.05, 0.05, 1); legCube@240 = (0.1, 0.3, 0.1, 0.05, 2.0, 0.05, 1); armCube@244 = (0.4, 0.15, 0.3, 0.4, 0.075, 0.15, 1) [all 8-arg W,H,D,cx,cy,cz,calculateNormals=1]. Constants: 0.4/0.15/0.3/0.075/0.1/0.05/0.0/0.35/0.12/0.27/0.06/0.135/0.2/0.175/0.8 (pool 0x893638..0x893670), vmov 2.0/5.0. State: md = (lrand48()/2^31f > 0.75) ? 1 : ((...<0.25) ? -1 : 0) (gl: d9=0.75,d0=0.25; mvn -1) -> movementDirection@248; fromSquare@252 = toSquare@260 = pos@16 (both 2-word copies); travelFraction@268 = 1.0f; randomTimeBetweenDirectionChanges@272 = 0.0f; walkSpeed@288 = (lrand48()/2^31f + 2.0) * 2.0 = uniform in [4.0, 6.0)..\n'),
    ),
    dict(
        name='sc_24',
        method='Scorpion -[maxAge]',
        types='f8@0:4',
        start=8991012,
        end=8991060,
        disasm='disasm_worldtileloader_sc_24.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00893154 (listing bound); next ObjC IMP 0x00893154 Scorpion -[speciesName]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8991012, 'sub sp, sp, 0x10'), (8991056, 'strbmi r0, [r1, 0]!')],
        calls=[],
        branches=[],
        semantics=('[Scorpion -[maxAge]] (imp 0x00893124, 12w): -[maxAge] (0x893124, 12w): return float 7200.0f (r0 bits 0x45e10000; pool 0x893150 holds the same value, plus a dead s0/spill pair - O0 triple materialization)..\n'),
    ),
    dict(
        name='sc_25',
        method='Scorpion -[maxHealth]',
        types='S8@0:4',
        start=9088880,
        end=9088908,
        disasm='disasm_worldtileloader_sc_25.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x008aaf8c (listing bound); next ObjC IMP 0x008aaf8c Scorpion -[tapIsWithinBodyRadius:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9088880, 'sub sp, sp, 8'), (9088904, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Scorpion -[maxHealth]] (imp 0x008aaf70, 7w): -[maxHealth] (0x8aaf70, 7w): return 0x14 (20) (uxth)..\n'),
    ),
    dict(
        name='sc_26',
        method='Scorpion -[npcType]',
        types='i8@0:4',
        start=8990984,
        end=8991012,
        disasm='disasm_worldtileloader_sc_26.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00893124 (listing bound); next ObjC IMP 0x00893124 Scorpion -[maxAge]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8990984, 'sub sp, sp, 8'), (8991008, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Scorpion -[npcType]] (imp 0x00893108, 7w): -[npcType] (0x893108, 7w): return 7..\n'),
    ),
    dict(
        name='sc_27',
        method='Scorpion -[reactToBeingFed]',
        types='v8@0:4',
        start=9091232,
        end=9091872,
        disasm='disasm_worldtileloader_sc_27.txt',
        base_add=9091248,
        base_literal=9091868,
        boundary='ARM.exidx end 0x008abb20 (listing bound); next ObjC IMP 0x008abb20 Scorpion -[canBeCapturedByBlockhead:withItemType:]',
        selectors={
                 0x8abae0: (15215772, 'reactToBeingFed'),
                 0x8abb04: (15215616, 'instance'),
                 0x8abb08: (15215620, 'multiSoundNamed:'),
                 0x8abb14: (15215624, 'playAtPosition:afterDelay:'),
        },
        imports={
                 0x8abadc: (17151900, 'objc_msgSendSuper2'),
                 0x8abb0c: (16332392, '__CFConstantStringClassReference'),
                 0x8abb18: (16332408, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x8abaec: (17162164, 'OBJC_IVAR_$_Scorpion.walkTimer', 284),
                 0x8abaf0: (17162096, 'OBJC_IVAR_$_Scorpion.walkSpeed', 288),
                 0x8abaf4: (17162156, 'OBJC_IVAR_$_Scorpion.randomGoalRotation', 280),
                 0x8abaf8: (17162116, 'OBJC_IVAR_$_Scorpion.movementDirection', 248),
                 0x8abb10: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={
                 0x8abae4: (15252908, 'OBJC_CLASS_$_Scorpion'),
                 0x8abafc: (15247768, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(9091232, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9091868, 'rsbseq r4, fp, ip, lsr r2')],
        calls=[(9091316, 'blx ip'), (9091448, 'bl loc.imp.objc_msgSend'), (9091480, 'bl loc.imp.objc_msgSend'), (9091576, 'bl loc.imp.objc_msgSend'), (9091600, 'bl loc.imp.objc_msgSend'), (9091624, 'bl loc.imp.objc_msgSend'), (9091700, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[Scorpion -[reactToBeingFed]] (imp 0x008ab8a0, 160w): -[reactToBeingFed] (0x8ab8a0, 160w): [super reactToBeingFed]; [MJSoundManager instance] -> multiSoundNamed:@"scorpionFire.wav"(0xF93668) playAtPosition:floatPos@24 afterDelay:0.6 (0x3FE3333340000000); a second instance -> multiSoundNamed:@"crunch.wav"(0xF93678) playAtPosition:floatPos afterDelay:0.1; movementDirection@248 = 0; walkSpeed@288 = 0.0f (pool 0x8abae8=0x0); randomGoalRotation@280 = 1.0f; walkTimer@284 = 0.0f..\n'),
    ),
    dict(
        name='sc_28',
        method='Scorpion -[reactToBeingHit]',
        types='v8@0:4',
        start=9089992,
        end=9090236,
        disasm='disasm_worldtileloader_sc_28.txt',
        base_add=9090008,
        base_literal=9090232,
        boundary='ARM.exidx end 0x008ab644; body trimmed at the next IMP 0x008ab4bc Scorpion -[isUnderLocalControl]',
        selectors={
                 0x8ab4a4: (15215616, 'instance'),
                 0x8ab4a8: (15215620, 'multiSoundNamed:'),
                 0x8ab4b4: (15215624, 'playAtPosition:afterDelay:'),
        },
        imports={
                 0x8ab4ac: (16332392, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x8ab498: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0x8ab4b0: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={
                 0x8ab49c: (15247768, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(9089992, 'push {fp, lr}'), (9090232, 'rsbseq r4, fp, r4, lsl r7')],
        calls=[(9090084, 'bl loc.imp.objc_msgSend'), (9090108, 'bl loc.imp.objc_msgSend'), (9090188, 'bl loc.imp.objc_msgSend')],
        branches=[(9090048, 'bne', 9090192)],
        semantics=('[Scorpion -[reactToBeingHit]] (imp 0x008ab3c8, 61w): -[reactToBeingHit] (0x8ab3c8, 61w): if (!NPC.dead@56): [MJSoundManager instance] -> multiSoundNamed:@"scorpionFire.wav" (same CFString obj 0xF93668) playAtPosition:floatPos@24 afterDelay:0.1 (0x3FB99999A0000000)..\n'),
    ),
    dict(
        name='sc_29',
        method='Scorpion -[remoteCreationDataUpdate:]',
        types='v12@0:4@8',
        start=8996924,
        end=8999040,
        disasm='disasm_worldtileloader_sc_29.txt',
        base_add=8996940,
        base_literal=8999036,
        boundary='ARM.exidx end 0x00895080 (listing bound); next ObjC IMP 0x00895080 Scorpion -[doRemoteUpdate:]',
        selectors={
                 0x895014: (15215508, 'remoteCreationDataUpdate:'),
                 0x895028: (15215548, 'getBytes:length:'),
                 0x895030: (15215552, 'isNet'),
                 0x895038: (15215540, 'release'),
                 0x89503c: (15215560, 'countByEnumeratingWithState:objects:count:'),
                 0x895040: (15215556, 'allBlockheadsIncludingNet'),
                 0x895048: (15215528, 'uniqueID'),
                 0x895054: (15215564, 'retain'),
                 0x895074: (15215568, 'doRemoteUpdate:'),
        },
        imports={
                 0x895010: (17151900, 'objc_msgSendSuper2'),
                 0x895024: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x89501c: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0x895020: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x89502c: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0x895034: (17162132, 'OBJC_IVAR_$_Scorpion.attackBlockhead', 312),
                 0x895044: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x89505c: (17162140, 'OBJC_IVAR_$_Scorpion.biteTimer', 324),
                 0x895060: (17162144, 'OBJC_IVAR_$_Scorpion.biting', 320),
                 0x895064: (17162148, 'OBJC_IVAR_$_Scorpion.spitTimer', 332),
                 0x895068: (17162136, 'OBJC_IVAR_$_Scorpion.spitting', 328),
                 0x89506c: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0x895070: (17162096, 'OBJC_IVAR_$_Scorpion.walkSpeed', 288),
        },
        classes={
                 0x895018: (15252908, 'OBJC_CLASS_$_Scorpion'),
        },
        instructions=[(8996924, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8999036, 'rsbseq fp, ip, r0, lsr 5')],
        calls=[(8997016, 'blx lr'), (8997120, 'blx ip'), (8997252, 'blx r2'), (8997368, 'blx r2'), (8997524, 'blx r2'), (8997548, 'bl sym.imp.memset'), (8997596, 'blx lr'), (8997696, 'bl sym.imp.objc_enumerationMutation'), (8997732, 'bl loc.imp.objc_msgSend'), (8997852, 'bl loc.imp.objc_msgSend'), (8997976, 'blx ip'), (8998072, 'blx r2'), (8998548, 'blx ip'), (8998688, 'blx r3'), (8998912, 'bl loc.imp.objc_msgSend')],
        branches=[(8997052, 'bne', 8998920), (8997148, 'beq', 8997268), (8997188, 'beq', 8997384), (8997264, 'bne', 8997384), (8997304, 'beq', 8998916), (8997380, 'beq', 8998916), (8997400, 'beq', 8998580), (8997404, 'b', 8997408), (8997608, 'beq', 8998572), (8997688, 'beq', 8997700), (8997760, 'bne', 8998448), (8997764, 'b', 8997768), (8997812, 'beq', 8998016), (8997880, 'bne', 8997900), (8997884, 'b', 8997888), (8997896, 'b', 8998012), (8998012, 'b', 8998016), (8998024, 'beq', 8998444), (8998104, 'beq', 8998180), (8998176, 'b', 8998248), (8998280, 'bne', 8998316), (8998380, 'bpl', 8998396), (8998392, 'b', 8998404), (8998444, 'b', 8998448), (8998448, 'b', 8998452), (8998476, 'blo', 8997652), (8998568, 'bne', 8997652), (8998572, 'b', 8998576), (8998576, 'b', 8998720), (8998616, 'beq', 8998716), (8998716, 'b', 8998720), (8998916, 'b', 8998920)],
        semantics=('[Scorpion -[remoteCreationDataUpdate:]] (imp 0x0089483c, 529w): -[remoteCreationDataUpdate:] (0x89483c, 529w, census-lite): [super remoteCreationDataUpdate:arg]; if (dead@56) return; [arg getBytes:buf(fp-0xb0) length:0x80] (creation struct per sc_10). Guard: proceed iff (isNet@52 ? (rider@132==nil || [rider isNet]) : (rider!=nil && [rider isNet])) else return. If uid64 (buf+0x70) != 0: NSFastEnumeration over [self.dynamicWorld@8 allBlockheadsIncludingNet] (countByEnumeratingWithState 0x894a20/0x894e50); per blockhead with [blockhead uniqueID] == uid64: if attackBlockhead@312: same uid -> keep (flag 0); different -> [attackBlockhead release]; attackBlockhead=nil (flag 1); if flag: attackBlockhead@312 = [blockhead retain]; if (buf+0x78 spitting byte) { spitting@328 = 1; spitTimer@332 = 0.0f (pool 0x895058=0x0); } else { biting@320 = 1; biteTimer@324 = 0.0f; }; if (!isNet) updateNeedsToBeSent@49 = 1; walkSpeed@288 = max(walkSpeed, 3.0f); no break. If uid64 == 0: if attackBlockhead: [attackBlockhead release]; attackBlockhead = nil. Tail (all loop-exit paths): [self doRemoteUpdate:<buf+0x48, 0x28 bytes>] (same struct shape as sc_13)..\n'),
    ),
    dict(
        name='sc_30',
        method='Scorpion -[remoteUpdate:]',
        types='v12@0:4@8',
        start=9000088,
        end=9000496,
        disasm='disasm_worldtileloader_sc_30.txt',
        base_add=9000104,
        base_literal=9000488,
        boundary='ARM.exidx end 0x00895630 (listing bound); next ObjC IMP 0x00895630 Scorpion -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        selectors={
                 0x895610: (15215576, 'remoteUpdate:'),
                 0x89561c: (15215548, 'getBytes:length:'),
                 0x895624: (15215568, 'doRemoteUpdate:'),
        },
        imports={
                 0x89560c: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0x895618: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
        },
        classes={
                 0x895614: (15252908, 'OBJC_CLASS_$_Scorpion'),
        },
        instructions=[(9000088, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9000492, 'andeq r0, r0, r0')],
        calls=[(9000180, 'blx lr'), (9000260, 'bl loc.imp.objc_msgSend'), (9000448, 'bl loc.imp.objc_msgSend')],
        branches=[(9000216, 'bne', 9000452)],
        semantics=('[Scorpion -[remoteUpdate:]] (imp 0x00895498, 102w): -[remoteUpdate:] (0x895498, 102w): [super remoteUpdate:arg]; if (!NPC.dead@56): [arg getBytes:buf(sp+0x58) length:0x28]; objc_msgSend(self, \'doRemoteUpdate:\', <w0/w1 in r2/r3 + w2..w9 staged on stack>) - the 0x28-byte ScorpionUpdateNetData is forwarded field-for-field. No else branch (Shark sh_34 cleared needsRemoved instead)..\n'),
    ),
    dict(
        name='sc_31',
        method='Scorpion -[removeRider:]',
        types='v12@0:4@8',
        start=9093508,
        end=9093728,
        disasm='disasm_worldtileloader_sc_31.txt',
        base_add=9093524,
        base_literal=9093724,
        boundary='ARM.exidx end 0x008ac260 (listing bound); next ObjC IMP 0x008ac260 Scorpion -[blockheadCanRide:usingItem:]',
        selectors={
                 0x8ac24c: (15215792, 'removeRider:'),
        },
        imports={
                 0x8ac248: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0x8ac244: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0x8ac258: (17162184, 'OBJC_IVAR_$_Scorpion.riderTargetVelocity', 340),
        },
        classes={
                 0x8ac250: (15252908, 'OBJC_CLASS_$_Scorpion'),
        },
        instructions=[(9093508, 'push {fp, lr}'), (9093724, 'rsbseq r3, fp, r8, asr sb')],
        calls=[(9093648, 'blx r3')],
        branches=[(9093576, 'bne', 9093692)],
        semantics=('[Scorpion -[removeRider:]] (imp 0x008ac184, 55w): -[removeRider:] (0x8ac184, 55w): if (arg == NPC.rider@132) { [super removeRider:arg] via objc_msgSendSuper2; riderTargetVelocity@340 = 0.0f (pool 0x8ac254=0x0); }. Same as Shark sh_35..\n'),
    ),
    dict(
        name='sc_32',
        method='Scorpion -[renderPos]',
        types='{Vector2=[2f]}8@0:4',
        start=9091160,
        end=9091232,
        disasm='disasm_worldtileloader_sc_32.txt',
        base_add=9091168,
        base_literal=9091228,
        boundary='ARM.exidx end 0x008ab8a0 (listing bound); next ObjC IMP 0x008ab8a0 Scorpion -[reactToBeingFed]',
        selectors={},
        imports={},
        ivars={
                 0x8ab898: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={},
        instructions=[(9091160, 'sub sp, sp, 8'), (9091228, 'rsbseq r4, fp, ip, lsl 5')],
        calls=[],
        branches=[],
        semantics=('[Scorpion -[renderPos]] (imp 0x008ab858, 18w): -[renderPos] (0x8ab858, 18w): Vector2 sret = DynamicObject.floatPos@24 (plain 2-word copy; no offset added, unlike Shark\'s xOffset)..\n'),
    ),
    dict(
        name='sc_33',
        method='Scorpion -[rideDirection]',
        types='i8@0:4',
        start=9093048,
        end=9093300,
        disasm='disasm_worldtileloader_sc_33.txt',
        base_add=9093056,
        base_literal=9093296,
        boundary='ARM.exidx end 0x008ac0b4 (listing bound); next ObjC IMP 0x008ac0b4 Scorpion -[addRider:]',
        selectors={},
        imports={},
        ivars={
                 0x8ac0a8: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0x8ac0ac: (17162184, 'OBJC_IVAR_$_Scorpion.riderTargetVelocity', 340),
        },
        classes={},
        instructions=[(9093048, 'sub sp, sp, 0x14'), (9093296, 'rsbseq r3, fp, ip, lsr 22')],
        calls=[],
        branches=[(9093104, 'beq', 9093248), (9093152, 'ble', 9093168), (9093164, 'b', 9093236), (9093244, 'b', 9093256)],
        semantics=('[Scorpion -[rideDirection]] (imp 0x008abfb8, 63w): -[rideDirection] (0x8abfb8, 63w): if (NPC.rider@132 == nil) return 0; else v = riderTargetVelocity@340: v > 0.1 -> 1; v < -0.1 -> -1; else 0 (doubles 0.1 @0x8ac098 and -0.1 @0x8ac0a0)..\n'),
    ),
    dict(
        name='sc_34',
        method='Scorpion -[riderBodyYRotationForBlockhead:]',
        types='f12@0:4@8',
        start=9092880,
        end=9092948,
        disasm='disasm_worldtileloader_sc_34.txt',
        base_add=9092908,
        base_literal=9092944,
        boundary='ARM.exidx end 0x008abf54 (listing bound); next ObjC IMP 0x008abf54 Scorpion -[setTargetVelocity:]',
        selectors={},
        imports={},
        ivars={
                 0x8abf4c: (17162152, 'OBJC_IVAR_$_Scorpion.bodyRotation', 276),
        },
        classes={},
        instructions=[(9092880, 'sub sp, sp, 0xc'), (9092944, 'rsbseq r3, fp, r0, asr 23')],
        calls=[],
        branches=[],
        semantics=('[Scorpion -[riderBodyYRotationForBlockhead:]] (imp 0x008abf10, 17w): -[riderBodyYRotationForBlockhead:] (0x8abf10, 17w): return bodyRotation@276 (float moved to r0 via vmov)..\n'),
    ),
    dict(
        name='sc_35',
        method='Scorpion -[riderPosForBlockhead:]',
        types='{Vector=[4f]}12@0:4@8',
        start=9092536,
        end=9092780,
        disasm='disasm_worldtileloader_sc_35.txt',
        base_add=9092552,
        base_literal=9092776,
        boundary='ARM.exidx end 0x008abeac (listing bound); next ObjC IMP 0x008abeac Scorpion -[cameraPosForBlockhead:]',
        selectors={
                 0x8abea4: (15215780, 'renderPos'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(9092536, 'push {r4, sl, fp, lr}'), (9092776, 'rsbseq r3, fp, r4, lsr 26')],
        calls=[(9092620, 'bl loc.imp.objc_msgSend_stret'), (9092656, 'bl sym.imp.memset'), (9092676, 'bl method.Vector2.Vector2_float__float_'), (9092696, 'bl method.Vector2.operator_Vector2_'), (9092704, 'bl method.Vector2.operator_float__'), (9092724, 'bl method.Vector2.operator_float__'), (9092756, 'bl method.Vector.Vector_float__float__float_')],
        branches=[(9092604, 'beq', 9092628), (9092624, 'b', 9092660)],
        semantics=('[Scorpion -[riderPosForBlockhead:]] (imp 0x008abdb8, 61w): -[riderPosForBlockhead:] (0x8abdb8, 61w): Vector3 sret: v = [self renderPos] (stret Vector2) + Vector2(0.0f, -0.15f) (ctor r1=0, r2=0xbe19999a); returns Vector3(v.x, v.y, -0.25) (gl truth: vmov.f32 s0,#208=0xbe800000=-0.25; r2 renderer mislabels it -2)..\n'),
    ),
    dict(
        name='sc_36',
        method='Scorpion -[riderRidesWithArmsDown]',
        types='c8@0:4',
        start=9094272,
        end=9094300,
        disasm='disasm_worldtileloader_sc_36.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x008ac4b4; body trimmed at the next IMP 0x008ac49c Scorpion -[.cxx_construct]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9094272, 'sub sp, sp, 8'), (9094296, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Scorpion -[riderRidesWithArmsDown]] (imp 0x008ac480, 7w): -[riderRidesWithArmsDown] (0x8ac480, 7w): return 1 (true, sxtb)..\n'),
    ),
    dict(
        name='sc_37',
        method='Scorpion -[scorpionUpdateNetDataForClient:]',
        types='{ScorpionUpdateNetData={NPCUpdateNetData={DynamicObjectNetData=QIIC[7C]}}IIscC[4c]}12@0:4@8',
        start=8995068,
        end=8995424,
        disasm='disasm_worldtileloader_sc_37.txt',
        base_add=8995084,
        base_literal=8995420,
        boundary='ARM.exidx end 0x00894260 (listing bound); next ObjC IMP 0x00894260 Scorpion -[creationNetDataForClient:]',
        selectors={
                 0x894244: (15215516, 'npcUpdateNetDataForClient:'),
        },
        imports={},
        ivars={
                 0x894248: (17162116, 'OBJC_IVAR_$_Scorpion.movementDirection', 248),
                 0x89424c: (17162108, 'OBJC_IVAR_$_Scorpion.toSquare', 260),
                 0x894254: (17162096, 'OBJC_IVAR_$_Scorpion.walkSpeed', 288),
        },
        classes={},
        instructions=[(8995068, 'push {r4, r5, r6, sl, fp, lr}'), (8995420, 'rsbseq fp, ip, r0, ror 19')],
        calls=[(8995168, 'bl loc.imp.objc_msgSend_stret'), (8995204, 'bl sym.imp.memset')],
        branches=[(8995148, 'beq', 8995176), (8995172, 'b', 8995208)],
        semantics=('[Scorpion -[scorpionUpdateNetDataForClient:]] (imp 0x008940fc, 89w): -[scorpionUpdateNetDataForClient:] (0x8940fc, 89w, sret 0x28): [0..0x18) = objc_msgSend_stret [self npcUpdateNetDataForClient:arg] (24 bytes; self==0 -> memset); +0x18/+0x1c = toSquare@260 (x,y pair); +0x20 = (s16)(walkSpeed@288 * 255.0f) (pool 0x894258=255.0); +0x22 = (s8)movementDirection@248..\n'),
    ),
    dict(
        name='sc_38',
        method='Scorpion -[setTargetVelocity:]',
        types='v16@0:4{Vector2=[2f]}8',
        start=9092948,
        end=9093048,
        disasm='disasm_worldtileloader_sc_38.txt',
        base_add=9092964,
        base_literal=9093044,
        boundary='ARM.exidx end 0x008abfb8 (listing bound); next ObjC IMP 0x008abfb8 Scorpion -[rideDirection]',
        selectors={},
        imports={},
        ivars={
                 0x8abfb0: (17162184, 'OBJC_IVAR_$_Scorpion.riderTargetVelocity', 340),
        },
        classes={},
        instructions=[(9092948, 'push {fp, lr}'), (9093044, 'rsbseq r3, fp, r8, lsl 23')],
        calls=[(9092996, 'bl method.Vector2.operator_float__')],
        branches=[],
        semantics=('[Scorpion -[setTargetVelocity:]] (imp 0x008abf54, 25w): -[setTargetVelocity:] (0x8abf54, 25w): riderTargetVelocity@340 = arg.x (Vector2 arg; only the x component is stored - scalar float ivar)..\n'),
    ),
    dict(
        name='sc_39',
        method='Scorpion -[speciesName]',
        types='@8@0:4',
        start=8991060,
        end=8991108,
        disasm='disasm_worldtileloader_sc_39.txt',
        base_add=8991068,
        base_literal=8991104,
        boundary='ARM.exidx end 0x00893224; body trimmed at the next IMP 0x00893184 Scorpion -[foodItemType]',
        selectors={},
        imports={
                 0x89317c: (16332136, '__CFConstantStringClassReference'),
        },
        ivars={},
        classes={},
        instructions=[(8991060, 'sub sp, sp, 8'), (8991104, 'invalid')],
        calls=[],
        branches=[],
        semantics=('[Scorpion -[speciesName]] (imp 0x00893154, 12w): -[speciesName] (0x893154, 12w): CFString "SCORPION" (obj 0xF93568, cstr 0xF9357B, len 8), PIC-materialized..\n'),
    ),
    dict(
        name='sc_40',
        method='Scorpion -[tapIsWithinBodyRadius:]',
        types='c16@0:4{Vector2=[2f]}8',
        start=9088908,
        end=9089992,
        disasm='disasm_worldtileloader_sc_40.txt',
        base_add=9088924,
        base_literal=9089988,
        boundary='ARM.exidx end 0x008ab644; body trimmed at the next IMP 0x008ab3c8 Scorpion -[reactToBeingHit]',
        selectors={
                 0x8ab3b4: (15215580, 'worldWidthMacro'),
        },
        imports={},
        ivars={
                 0x8ab3a4: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0x8ab3a8: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x8ab3b0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(9088908, 'push {fp, lr}'), (9089988, 'rsbseq r4, fp, r0, asr fp')],
        calls=[(9089016, 'bl method.Vector2.operator_float__'), (9089060, 'bl method.Vector2.operator_float__'), (9089112, 'bl loc.imp.objc_msgSend'), (9089136, 'bl sym.imp.__aeabi_idiv'), (9089180, 'bl method.Vector2.operator_float__'), (9089224, 'bl method.Vector2.operator_float__'), (9089276, 'bl loc.imp.objc_msgSend'), (9089340, 'bl method.Vector2.operator_float__'), (9089384, 'bl method.Vector2.operator_float__'), (9089436, 'bl loc.imp.objc_msgSend'), (9089452, 'bl sym.imp.__aeabi_idiv'), (9089496, 'bl method.Vector2.operator_float__'), (9089540, 'bl method.Vector2.operator_float__'), (9089592, 'bl loc.imp.objc_msgSend'), (9089636, 'bl method.Vector2.operator_float__'), (9089672, 'bl method.Vector2.operator_float__'), (9089760, 'bl method.Vector2.operator_float__'), (9089800, 'bl method.Vector2.operator_float__'), (9089844, 'bl method.Vector2.operator_float__'), (9089884, 'bl method.Vector2.operator_float__')],
        branches=[(9088976, 'beq', 9088992), (9088988, 'b', 9089944), (9089160, 'blt', 9089316), (9089312, 'b', 9089700), (9089476, 'bpl', 9089632), (9089628, 'b', 9089692), (9089728, 'bpl', 9089936), (9089752, 'ble', 9089936), (9089836, 'ble', 9089936), (9089920, 'bpl', 9089936), (9089932, 'b', 9089944)],
        semantics=('[Scorpion -[tapIsWithinBodyRadius:]] (imp 0x008aaf8c, 271w): -[tapIsWithinBodyRadius:] (0x8aaf8c, 271w): if (NPC.dead@56) return NO. Computes toroidal dx = pos.x - floatPos.x@24.x wrapped into [-W/2, W/2) with W = [world worldWidthMacro] * 32 (block units; divisor 2; wrap constants pair the sc_40 head branches). Then YES iff -0.5 < dx < 0.5 (strict; gl: d1=#96=0.5, d0=#224=-0.5) AND floatPos.y < pos.y < floatPos.y + 1.0 (both strict; gl d1=0.5 and floatPos.y+1.0 window). Dead constant 5 spills are unused O0 artifacts..\n'),
    ),
    dict(
        name='sc_41',
        method='Scorpion -[updateNetDataForClient:]',
        types='@12@0:4@8',
        start=8996136,
        end=8996372,
        disasm='disasm_worldtileloader_sc_41.txt',
        base_add=8996152,
        base_literal=8996368,
        boundary='ARM.exidx end 0x00894614 (listing bound); next ObjC IMP 0x00894614 Scorpion -[dealloc]',
        selectors={
                 0x894600: (15215524, 'scorpionUpdateNetDataForClient:'),
                 0x894608: (15215532, 'dataWithBytes:length:'),
        },
        imports={
                 0x894604: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0x89460c: (15247764, 'OBJC_CLASS_$_NSData'),
        },
        instructions=[(8996136, 'push {fp, lr}'), (8996368, 'ldrhteq fp, [ip], -0x54')],
        calls=[(8996232, 'bl loc.imp.objc_msgSend_stret'), (8996268, 'bl sym.imp.memset'), (8996332, 'blx ip')],
        branches=[(8996212, 'beq', 8996240), (8996236, 'b', 8996272)],
        semantics=('[Scorpion -[updateNetDataForClient:]] (imp 0x00894528, 59w): -[updateNetDataForClient:] (0x894528, 59w): return [NSData dataWithBytes:<stret [self scorpionUpdateNetDataForClient:arg], 0x28 bytes> length:0x28]. Same shape as Shark sh_46..\n'),
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
        'batch': 'Scorpion (E143): the scorpion animal; 42 bodies',
        'claim': ('the scorpion animal (AI tick, tail-strike/spit combat, net round-trip)'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'scorpion.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale scorpion.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
