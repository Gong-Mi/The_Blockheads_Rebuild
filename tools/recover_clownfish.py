#!/usr/bin/env python3
"""Hash-gated recovery of the ClownFish (E144).

ClownFish lands: the batch sweeps clownfish surface:
34 bodies, 9587 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/CLOWNFISH.md for the prose and boundaries.
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
    'bl 0x78dc28': 0x0078dc28,
    'bl 0x795a24': 0x00795a24,
    'bl 0x795a98': 0x00795a98,
    'bl 0x795c80': 0x00795c80,
    'bl 0x796018': 0x00796018,
    'bl 0x7963b0': 0x007963b0,
    'bl 0x796748': 0x00796748,
    'bl 0x7969fc': 0x007969fc,
    'bl 0x796a38': 0x00796a38,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector.Vector_float__float__float__float_': 0x004d0d08,
    'bl method.Vector.operator_float__': 0x004b5c08,
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl method.Vector2.operator_Vector2_': 0x004d0418,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl sym.Vector::operator_Vector_': 0x0058198c,
    'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_': 0x00a15404,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__modsi3': 0x001c3020,
    'bl sym.imp.__wrap_glBindTexture': 0x001c2ad4,
    'bl sym.imp.__wrap_glDisableVertexAttribArray': 0x001c3d58,
    'bl sym.imp.__wrap_glEnableVertexAttribArray': 0x001c2d5c,
    'bl sym.imp.__wrap_glUniform1i': 0x001c2de0,
    'bl sym.imp.__wrap_glUniform4f': 0x001c3d64,
    'bl sym.imp.__wrap_glUniformMatrix4fv': 0x001c2dd4,
    'bl sym.imp.__wrap_glUseProgram': 0x001c2d38,
    'bl sym.imp.atan2': 0x001c296c,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.memset': 0x001c2924,
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
        name='clf_00',
        method='ClownFish -[.cxx_construct]',
        types='@8@0:4',
        start=7979340,
        end=7979364,
        disasm='disasm_worldtileloader_clf_00.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0079c164 (listing bound); next ObjC IMP 0x0079c780 DropBear -[npcType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7979340, 'sub sp, sp, 8'), (7979360, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[ClownFish -[.cxx_construct]] (imp 0x0079c14c, 6w): -[.cxx_construct] (0x79c14c, 6w): empty `return self` stub (O0 sub sp/save r0/r1/reload r0); no C++ member constructor calls - no non-POD ClownFish ivars need init..\n'),
    ),
    dict(
        name='clf_01',
        method='ClownFish -[blockheadUnloaded:]',
        types='v12@0:4@8',
        start=7978524,
        end=7978748,
        disasm='disasm_worldtileloader_clf_01.txt',
        base_add=7978540,
        base_literal=7978744,
        boundary='ARM.exidx end 0x0079befc (listing bound); next ObjC IMP 0x0079befc ClownFish -[ridableWhenTamed]',
        selectors={
                 0x79beec: (15209472, 'blockhead'),
                 0x79bef4: (15209276, 'autorelease'),
        },
        imports={
                 0x79bee8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x79bef0: (17160104, 'OBJC_IVAR_$_ClownFish.hookedFishingRod', 312),
        },
        classes={},
        instructions=[(7978524, 'push {r4, sl, fp, lr}'), (7978744, 'addeq r3, ip, r0, asr 25')],
        calls=[(7978604, 'blx ip'), (7978688, 'blx r3')],
        branches=[(7978616, 'bne', 7978720)],
        semantics=('[ClownFish -[blockheadUnloaded:]] (imp 0x0079be1c, 56w): -[blockheadUnloaded:] (0x79be1c, 56w): if ([self.hookedFishingRod blockhead] == bh) { [self.hookedFishingRod autorelease]; self.hookedFishingRod = nil; }. No [super blockheadUnloaded:] call at all (unlike Scorpion sc_03) - the fish only clears its own rod back-ref. Selector cells: blockhead/autorelease on the FishingRod..\n'),
    ),
    dict(
        name='clf_02',
        method='ClownFish -[canBeCapturedByBlockhead:withItemType:]',
        types='c16@0:4@8i12',
        start=7920696,
        end=7920920,
        disasm='disasm_worldtileloader_clf_02.txt',
        base_add=7920712,
        base_literal=7920916,
        boundary='ARM.exidx end 0x0078dd18 (listing bound); next ObjC IMP 0x0078dd18 ClownFish -[cantBeCapturedTipStringForBlockhead:withItemType:]',
        selectors={
                 0x78dd0c: (15209192, 'tamed'),
                 0x78dd10: (15209196, 'belongsToPlayerWithBlockhead:'),
        },
        imports={
                 0x78dd08: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(7920696, 'push {fp, lr}'), (7920916, 'addeq r1, sp, r4, lsr 29')],
        calls=[(7920788, 'blx r2'), (7920852, 'blx r3')],
        branches=[(7920744, 'bne', 7920884), (7920800, 'beq', 7920868), (7920864, 'beq', 7920880), (7920876, 'b', 7920892), (7920880, 'b', 7920884)],
        semantics=('[ClownFish -[canBeCapturedByBlockhead:withItemType:]] (imp 0x0078dc38, 56w): -[canBeCapturedByBlockhead:withItemType:] (0x78dc38, 56w): if (itemType != 0x66/102) return 0; if (![self tamed]) return 1; return [self belongsToPlayerWithBlockhead:blockhead]. Capture item 102 = bucket; wild (untamed) fish capturable by anyone, tamed only by owner..\n'),
    ),
    dict(
        name='clf_03',
        method='ClownFish -[cantBeCapturedTipStringForBlockhead:withItemType:]',
        types='@16@0:4@8i12',
        start=7920920,
        end=7921408,
        disasm='disasm_worldtileloader_clf_03.txt',
        base_add=7920936,
        base_literal=7921404,
        boundary='ARM.exidx end 0x0078df00 (listing bound); next ObjC IMP 0x0078df00 ClownFish -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:]',
        selectors={
                 0x78dee4: (15209204, 'stringWithFormat:'),
                 0x78dee8: (15209200, 'speciesName'),
                 0x78def0: (15209192, 'tamed'),
                 0x78def4: (15209196, 'belongsToPlayerWithBlockhead:'),
        },
        imports={
                 0x78dedc: (16319448, '__CFConstantStringClassReference'),
                 0x78dee0: (17151904, 'objc_msgSend'),
                 0x78def8: (16319432, '__CFConstantStringClassReference'),
        },
        ivars={},
        classes={
                 0x78deec: (15247008, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(7920920, 'push {r4, r5, fp, lr}'), (7921404, 'addeq r1, sp, r4, asr 27')],
        calls=[(7921012, 'blx r2'), (7921076, 'blx r3'), (7921172, 'blx r2'), (7921208, 'blx ip'), (7921304, 'blx r2'), (7921340, 'blx ip')],
        branches=[(7920968, 'bne', 7921224), (7921024, 'beq', 7921220), (7921088, 'bne', 7921220), (7921216, 'b', 7921360), (7921220, 'b', 7921352), (7921348, 'b', 7921360)],
        semantics=('[ClownFish -[cantBeCapturedTipStringForBlockhead:withItemType:]] (imp 0x0078dd18, 122w): -[cantBeCapturedTipStringForBlockhead:withItemType:] (0x78dd18, 122w): if (itemType != 0x66/102) return [NSString stringWithFormat:@"%@ CAN ONLY BE CAPTURED\\nIN A BUCKET" (fmt obj 0xF903D8), [self speciesName]]; if (!tamed) return nil; if (belongs) return nil; return [NSString stringWithFormat:@"THAT %@ BELONGS TO\\nSOMEONE ELSE" (obj 0xF903C8), speciesName]..\n'),
    ),
    dict(
        name='clf_04',
        method='ClownFish -[captureRequiredItemType]',
        types='i8@0:4',
        start=7918636,
        end=7918664,
        disasm='disasm_worldtileloader_clf_04.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0078d448 (listing bound); next ObjC IMP 0x0078d448 ClownFish -[loadDerivedStuff]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7918636, 'sub sp, sp, 8'), (7918660, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[ClownFish -[captureRequiredItemType]] (imp 0x0078d42c, 7w): -[captureRequiredItemType] (0x78d42c, 7w): return 0x66 (102, the bucket)..\n'),
    ),
    dict(
        name='clf_05',
        method='ClownFish -[capturedItemType]',
        types='i8@0:4',
        start=7918608,
        end=7918636,
        disasm='disasm_worldtileloader_clf_05.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0078d448; body trimmed at the next IMP 0x0078d42c ClownFish -[captureRequiredItemType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7918608, 'sub sp, sp, 8'), (7918632, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[ClownFish -[capturedItemType]] (imp 0x0078d410, 7w): -[capturedItemType] (0x78d410, 7w): return 0x9e (158)..\n'),
    ),
    dict(
        name='clf_06',
        method='ClownFish -[clownFishUpdateNetDataForClient:]',
        types='{ClownFishUpdateNetData={NPCUpdateNetData={DynamicObjectNetData=QIIC[7C]}}IIsc[5c]}12@0:4@8',
        start=7923688,
        end=7924044,
        disasm='disasm_worldtileloader_clf_06.txt',
        base_add=7923704,
        base_literal=7924040,
        boundary='ARM.exidx end 0x0078e94c (listing bound); next ObjC IMP 0x0078e94c ClownFish -[creationNetDataForClient:]',
        selectors={
                 0x78e930: (15209252, 'npcUpdateNetDataForClient:'),
        },
        imports={},
        ivars={
                 0x78e934: (17160060, 'OBJC_IVAR_$_ClownFish.movementDirection', 236),
                 0x78e938: (17160076, 'OBJC_IVAR_$_ClownFish.toSquare', 248),
                 0x78e940: (17160064, 'OBJC_IVAR_$_ClownFish.walkSpeed', 284),
        },
        classes={},
        instructions=[(7923688, 'push {r4, r5, r6, sl, fp, lr}'), (7924040, 'strdeq r1, r2, [sp], r4')],
        calls=[(7923788, 'bl loc.imp.objc_msgSend_stret'), (7923824, 'bl sym.imp.memset')],
        branches=[(7923768, 'beq', 7923796), (7923792, 'b', 7923828)],
        semantics=('[ClownFish -[clownFishUpdateNetDataForClient:]] (imp 0x0078e7e8, 89w): -[clownFishUpdateNetDataForClient:] (0x78e7e8, 89w): WIRE WRITER, struct-return by sret (r0=dest, r1=self, r2=_cmd, r3=arg; tsv: {ClownFishUpdateNetData=...}12@0:4@8). Writes the 0x28-byte ClownFishUpdateNetData: (1) [self npcUpdateNetDataForClient:arg] sret -> 0x18B NPCUpdateNetData at sp+0x18 (self==0 -> memset 0x18), copied to dest+0x00; (2) dest+0x18 = self.toSquare@248.x; (3) dest+0x1c = toSquare.y@252; (4) dest+0x20 = (s16)(self.walkSpeed@284 * 255.0f) (pool 0x78e944 = 0x437f0000); (5) dest+0x22 = (s8)self.movementDirection@236; +0x23..0x27 = the c[5] padding of the struct..\n'),
    ),
    dict(
        name='clf_07',
        method='ClownFish -[creationDataStructSize]',
        types='L8@0:4',
        start=7927224,
        end=7927256,
        disasm='disasm_worldtileloader_clf_07.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0078f5d8 (listing bound); next ObjC IMP 0x0078f5d8 ClownFish -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7927224, 'sub sp, sp, 8'), (7927252, 'andeq r0, r0, r0')],
        calls=[],
        branches=[],
        semantics=('[ClownFish -[creationDataStructSize]] (imp 0x0078f5b8, 8w): -[creationDataStructSize] (0x78f5b8, 8w): return 0x70 (112) = 0x48 NPCCreationNetData + 0x28 ClownFishUpdateNetData (tsv: L8@0:4)..\n'),
    ),
    dict(
        name='clf_08',
        method='ClownFish -[creationNetDataForClient:]',
        types='@12@0:4@8',
        start=7924044,
        end=7924568,
        disasm='disasm_worldtileloader_clf_08.txt',
        base_add=7924060,
        base_literal=7924564,
        boundary='ARM.exidx end 0x0078eb58 (listing bound); next ObjC IMP 0x0078eb58 ClownFish -[updateNetDataForClient:]',
        selectors={
                 0x78eb3c: (15209256, 'npcCreationNetDataForClient:'),
                 0x78eb40: (15209260, 'clownFishUpdateNetDataForClient:'),
                 0x78eb48: (15209268, 'appendNPCCreationDataToData:'),
                 0x78eb4c: (15209264, 'dataWithBytes:length:'),
        },
        imports={
                 0x78eb44: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0x78eb50: (15247012, 'OBJC_CLASS_$_NSData'),
        },
        instructions=[(7924044, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7924564, 'umulleq r1, sp, r0, r1')],
        calls=[(7924148, 'bl loc.imp.objc_msgSend_stret'), (7924184, 'bl sym.imp.memset'), (7924240, 'bl sym.imp.memcpy'), (7924312, 'bl loc.imp.objc_msgSend_stret'), (7924348, 'bl sym.imp.memset'), (7924452, 'bl sym.imp.memcpy'), (7924492, 'blx ip'), (7924520, 'blx r3')],
        branches=[(7924128, 'beq', 7924156), (7924152, 'b', 7924188), (7924292, 'beq', 7924320), (7924316, 'b', 7924352)],
        semantics=('[ClownFish -[creationNetDataForClient:]] (imp 0x0078e94c, 131w): -[creationNetDataForClient:] (0x78e94c, 131w): buf[0x70]; (1) [self npcCreationNetDataForClient:arg] sret -> 0x48B at sp+0x80 (self==0 -> memset 0x48), memcpy(buf, sp+0x80, 0x48); (2) [self clownFishUpdateNetDataForClient:arg] sret -> 0x28B at sp+0x58, memcpy(buf+0x48, sp+0x58, 0x28); (3) return [self appendNPCCreationDataToData:[NSData dataWithBytes:buf length:0x70]]..\n'),
    ),
    dict(
        name='clf_09',
        method='ClownFish -[dealloc]',
        types='v8@0:4',
        start=7924804,
        end=7925280,
        disasm='disasm_worldtileloader_clf_09.txt',
        base_add=7924820,
        base_literal=7925276,
        boundary='ARM.exidx end 0x0078ee20 (listing bound); next ObjC IMP 0x0078ee20 ClownFish -[doRemoteUpdate:]',
        selectors={
                 0x78edf4: (15209280, 'dealloc'),
                 0x78ee00: (15209276, 'autorelease'),
                 0x78ee08: (15209272, 'setHookedFish:'),
                 0x78ee0c: (15209216, 'release'),
        },
        imports={
                 0x78edf0: (17151900, 'objc_msgSendSuper2'),
                 0x78edfc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x78ee04: (17160104, 'OBJC_IVAR_$_ClownFish.hookedFishingRod', 312),
                 0x78ee10: (17160032, 'OBJC_IVAR_$_ClownFish.sideFinCube', 232),
                 0x78ee14: (17160036, 'OBJC_IVAR_$_ClownFish.tailCube', 228),
                 0x78ee18: (17160040, 'OBJC_IVAR_$_ClownFish.bodyCube', 224),
        },
        classes={
                 0x78edf8: (15252792, 'OBJC_CLASS_$_ClownFish'),
        },
        instructions=[(7924804, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7925276, 'umulleq r0, sp, r8, lr')],
        calls=[(7925024, 'blx r5'), (7925060, 'blx r3'), (7925096, 'blx r3'), (7925136, 'blx r3'), (7925172, 'blx r3'), (7925220, 'blx ip')],
        branches=[],
        semantics=('[ClownFish -[dealloc]] (imp 0x0078ec44, 119w): -[dealloc] (0x78ec44, 119w): [bodyCube@224 release]; [tailCube@228 release]; [sideFinCube@232 release]; [self.hookedFishingRod setHookedFish:nil] (clears rod back-ref); [self.hookedFishingRod autorelease]; then [super dealloc] via msgSendSuper2 (superstruct at fp-0x28 {self, *(class slot 0xE8BD38) = ClownFish 0xE90FF8}). Shader/textures NOT released (cf. Scorpion sc_11)..\n'),
    ),
    dict(
        name='clf_10',
        method='ClownFish -[die:]',
        types='v12@0:4@8',
        start=7958520,
        end=7959296,
        disasm='disasm_worldtileloader_clf_10.txt',
        base_add=7958536,
        base_literal=7959292,
        boundary='ARM.exidx end 0x00797300 (listing bound); next ObjC IMP 0x00797300 ClownFish -[update:accurateDT:isSimulation:]',
        selectors={
                 0x7972b8: (15209276, 'autorelease'),
                 0x7972cc: (15209332, 'instance'),
                 0x7972d0: (15209348, 'multiSoundNamed:'),
                 0x7972dc: (15209352, 'playAtPosition:afterDelay:'),
                 0x7972e4: (15209360, 'die:'),
                 0x7972f8: (15209356, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
        },
        imports={
                 0x7972b4: (17151904, 'objc_msgSend'),
                 0x7972d4: (16319464, '__CFConstantStringClassReference'),
                 0x7972e0: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0x7972ac: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0x7972b0: (17160104, 'OBJC_IVAR_$_ClownFish.hookedFishingRod', 312),
                 0x7972c0: (17160072, 'OBJC_IVAR_$_ClownFish.travelFraction', 256),
                 0x7972d8: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x7972ec: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x7972f4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={
                 0x7972c4: (15247020, 'OBJC_CLASS_$_MJSoundManager'),
                 0x7972e8: (15252792, 'OBJC_CLASS_$_ClownFish'),
        },
        instructions=[(7958520, 'push {r4, r5, r6, sl, fp, lr}'), (7959292, 'addeq r8, ip, r4, ror 21')],
        calls=[(7958692, 'bl loc.imp.objc_msgSend'), (7958716, 'bl loc.imp.objc_msgSend'), (7958796, 'bl loc.imp.objc_msgSend'), (7958856, 'blx ip'), (7958908, 'bl 0x78dc28'), (7958928, 'bl sym.imp.__modsi3'), (7959104, 'bl loc.imp.objc_msgSend'), (7959196, 'blx r3')],
        branches=[(7958584, 'bne', 7959204), (7958896, 'beq', 7959128), (7958960, 'bge', 7959124), (7959120, 'b', 7958948), (7959124, 'b', 7959128), (7959200, 'b', 7959204)],
        semantics=('[ClownFish -[die:]] (imp 0x00796ff8, 194w): -[die:] (0x796ff8, 194w): if (self.dead@56) return; s=[[MJSoundManager instance] multiSoundNamed:@"fishDie.wav"(obj 0xF903E8)]; [s playAtPosition:self.floatPos afterDelay:0.1 (double 0x3FB99999A0000000)]; self.travelFraction@256 = 0.0f (pool 0x7972bc); [self.hookedFishingRod autorelease]; self.hookedFishingRod = nil; if (arg != 0) { n = lrand48()%3 + 1 (call 0x78dc28 = rng wrapper, __modsi3); for i in 0..n-1: [self.dynamicWorld createFreeBlockAtPosition:self.pos ofType:0x97/151 dataA:0 dataB:0 subItems:0 dynamicObjectSaveDict:0 hovers:0 playSound:1 priorityBlockhead:arg]; } [super die:arg] (msgSendSuper2)..\n'),
    ),
    dict(
        name='clf_11',
        method='ClownFish -[doRemoteUpdate:]',
        types='v48@0:4{ClownFishUpdateNetData={NPCUpdateNetData={DynamicObjectNetData=QIIC[7C]}}IIsc[5c]}8',
        start=7925280,
        end=7926040,
        disasm='disasm_worldtileloader_clf_11.txt',
        base_add=7925296,
        base_literal=7926036,
        boundary='ARM.exidx end 0x0078f118 (listing bound); next ObjC IMP 0x0078f118 ClownFish -[remoteUpdate:]',
        selectors={
                 0x78f0e4: (15209284, 'isClient'),
        },
        imports={
                 0x78f0e0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x78f0e8: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x78f0ec: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0x78f0f0: (17160076, 'OBJC_IVAR_$_ClownFish.toSquare', 248),
                 0x78f0f4: (17160060, 'OBJC_IVAR_$_ClownFish.movementDirection', 236),
                 0x78f0f8: (17160064, 'OBJC_IVAR_$_ClownFish.walkSpeed', 284),
                 0x78f100: (17160108, 'OBJC_IVAR_$_ClownFish.currentNetQueueSize', 316),
                 0x78f104: (17160092, 'OBJC_IVAR_$_ClownFish.nextToSquare', 320),
                 0x78f10c: (17160096, 'OBJC_IVAR_$_ClownFish.nextWalkSpeed', 352),
                 0x78f110: (17160100, 'OBJC_IVAR_$_ClownFish.nextMovementDirection', 368),
        },
        classes={},
        instructions=[(7925280, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7926036, 'strheq r0, [sp], ip')],
        calls=[(7925468, 'blx lr'), (7925828, 'bl sym.makeIntpair_int__int_')],
        branches=[(7925480, 'bne', 7925648), (7925644, 'b', 7925976), (7925700, 'blt', 7925740)],
        semantics=('[ClownFish -[doRemoteUpdate:]] (imp 0x0078ee20, 190w): -[doRemoteUpdate:] (0x78ee20, 190w): applies a 0x28B ClownFishUpdateNetData (w0/w1 in r2/r3 + w2..w9 stack, AAPCS split; struct copy to fp-0x40..-0x1c). If (![self.dynamicWorld isClient]): SERVER path - self.walkSpeed@284 = (s16)w8/255.0f; self.movementDirection@236 = (s8)(w8 byte+0x22); self.toSquare@248 = {w6,w7}; self.updateNeedsToBeSent@49 = 1. Else CLIENT path - 4-slot queue: size=self.currentNetQueueSize@316; if (size>=4){size=3; currentNetQueueSize=3;} self.nextToSquare@320[size] = makeIntpair(w6,w7); self.nextWalkSpeed@352[size] = (s16)w8/255.0f; self.nextMovementDirection@368[size] = (s8)w8.byte2; self.currentNetQueueSize = size+1. K=255.0 at pool 0x78f0fc. w9 (+0x24..+0x27 pad) unused..\n'),
    ),
    dict(
        name='clf_12',
        method='ClownFish -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        types='v156@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76i140i144i148i152',
        start=7927256,
        end=7952932,
        disasm='disasm_worldtileloader_clf_12.txt',
        base_add=7927304,
        base_literal=7931288,
        boundary='ARM.exidx end 0x00795a24 (listing bound); next ObjC IMP 0x00796ff8 ClownFish -[die:]',
        selectors={
                 0x7907d8: (15209300, 'worldWidthMacro'),
                 0x790b80: (15209304, 'macroTiles'),
                 0x791724: (15209308, 'hookedFishDirection'),
                 0x793308: (15209312, 'program'),
                 0x793310: (15209324, 'intValue'),
                 0x793314: (15209320, 'objectAtIndex:'),
                 0x793318: (15209316, 'uniformLocations'),
                 0x79331c: (15209328, 'dayColor'),
                 0x793340: (15209332, 'instance'),
                 0x793350: (15209336, 'addParticleAtPos:velocity:color:gravityType:life:scale:'),
                 0x79335c: (15209340, 'name'),
                 0x793364: (15209344, 'draw'),
                 0x795a08: (15209324, 'intValue'),
                 0x795a0c: (15209320, 'objectAtIndex:'),
                 0x795a10: (15209316, 'uniformLocations'),
                 0x795a18: (15209344, 'draw'),
        },
        imports={
                 0x790b7c: (17151904, 'objc_msgSend'),
                 0x793304: (17151904, 'objc_msgSend'),
                 0x795a04: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x7907cc: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x7907d4: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x790b64: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x790b78: (17160112, 'OBJC_IVAR_$_ClownFish.isOnAirAboveSolidGround', 309),
                 0x790b84: (17160080, 'OBJC_IVAR_$_ClownFish.fromSquare', 240),
                 0x790b88: (17157400, 'OBJC_IVAR_$_NPC.visible', 57),
                 0x790b8c: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x790b90: (17160064, 'OBJC_IVAR_$_ClownFish.walkSpeed', 284),
                 0x790b94: (17160108, 'OBJC_IVAR_$_ClownFish.currentNetQueueSize', 316),
                 0x790b98: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0x790b9c: (17160116, 'OBJC_IVAR_$_ClownFish.bubbleEmitTimer', 300),
                 0x790ba0: (17160120, 'OBJC_IVAR_$_ClownFish.walkTimer', 280),
                 0x790ba4: (17160124, 'OBJC_IVAR_$_ClownFish.falling', 308),
                 0x790bac: (17160128, 'OBJC_IVAR_$_ClownFish.bobTimer', 288),
                 0x790bb0: (17160104, 'OBJC_IVAR_$_ClownFish.hookedFishingRod', 312),
                 0x790bb4: (17160060, 'OBJC_IVAR_$_ClownFish.movementDirection', 236),
                 0x790bb8: (17160084, 'OBJC_IVAR_$_ClownFish.goalRotation', 268),
                 0x790bbc: (17160076, 'OBJC_IVAR_$_ClownFish.toSquare', 248),
                 0x790bc0: (17160132, 'OBJC_IVAR_$_ClownFish.goalZRotation', 272),
                 0x790bc4: (17160136, 'OBJC_IVAR_$_ClownFish.bodyZRotation', 276),
                 0x791728: (17160088, 'OBJC_IVAR_$_ClownFish.bodyRotation', 264),
                 0x791730: (17160072, 'OBJC_IVAR_$_ClownFish.travelFraction', 256),
                 0x791f40: (17160064, 'OBJC_IVAR_$_ClownFish.walkSpeed', 284),
                 0x79330c: (17160056, 'OBJC_IVAR_$_ClownFish.shader', 208),
                 0x793320: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x793330: (17160116, 'OBJC_IVAR_$_ClownFish.bubbleEmitTimer', 300),
                 0x793334: (17160124, 'OBJC_IVAR_$_ClownFish.falling', 308),
                 0x793358: (17160052, 'OBJC_IVAR_$_ClownFish.bodyTexture', 212),
                 0x793360: (17160040, 'OBJC_IVAR_$_ClownFish.bodyCube', 224),
                 0x795860: (17160048, 'OBJC_IVAR_$_ClownFish.tailTexture', 216),
                 0x795864: (17160036, 'OBJC_IVAR_$_ClownFish.tailCube', 228),
                 0x795a14: (17160056, 'OBJC_IVAR_$_ClownFish.shader', 208),
                 0x795a1c: (17160032, 'OBJC_IVAR_$_ClownFish.sideFinCube', 232),
                 0x795a20: (17160044, 'OBJC_IVAR_$_ClownFish.sideFinTexture', 220),
        },
        classes={
                 0x79333c: (15247016, 'OBJC_CLASS_$_ParticleEmitter'),
        },
        instructions=[(7927256, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7952928, 'invalid')],
        calls=[(7927976, 'bl loc.imp.objc_msgSend'), (7928000, 'bl sym.imp.__aeabi_idiv'), (7928068, 'bl loc.imp.objc_msgSend'), (7928196, 'bl loc.imp.objc_msgSend'), (7928212, 'bl sym.imp.__aeabi_idiv'), (7928280, 'bl loc.imp.objc_msgSend'), (7928412, 'bl loc.imp.objc_msgSend'), (7928436, 'bl sym.imp.__aeabi_idiv'), (7928504, 'bl loc.imp.objc_msgSend'), (7928632, 'bl loc.imp.objc_msgSend'), (7928648, 'bl sym.imp.__aeabi_idiv'), (7928716, 'bl loc.imp.objc_msgSend'), (7929004, 'bl method.Vector2.operator_float__'), (7929068, 'bl loc.imp.objc_msgSend'), (7929092, 'bl sym.imp.__aeabi_idiv'), (7929188, 'bl loc.imp.objc_msgSend'), (7929224, 'bl method.Vector2.operator_float__'), (7929276, 'bl method.Vector2.operator_float__'), (7929344, 'bl loc.imp.objc_msgSend'), (7929360, 'bl sym.imp.__aeabi_idiv'), (7929456, 'bl loc.imp.objc_msgSend'), (7929492, 'bl method.Vector2.operator_float__'), (7929564, 'bl method.Vector2.operator_float__'), (7929696, 'blx r2'), (7929744, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (7929840, 'bl sym.tileIsSolid_Tile_'), (7930520, 'bl method.Vector2.operator_float__'), (7930540, 'bl method.Vector2.operator_float__'), (7930636, 'bl 0x795a24'), (7932136, 'bl loc.imp.objc_msgSend_stret'), (7932184, 'bl sym.imp.memset'), (7932196, 'bl method.Vector2.operator_float__'), (7932224, 'bl method.Vector2.operator_float__'), (7932256, 'bl method.Vector2.operator_float__'), (7932284, 'bl sym.imp.atan2'), (7932432, 'bl method.Vector2.operator_float__'), (7932468, 'bl method.Vector2.operator_float__'), (7932500, 'bl sym.imp.atan2'), (7933120, 'bl sym.imp.sinf'), (7933600, 'bl 0x795a98'), (7933636, 'bl sym.imp.memcpy'), (7934032, 'bl 0x795c80'), (7934252, 'bl sym.imp.sinf'), (7934724, 'bl 0x796018'), (7934772, 'bl sym.imp.memcpy'), (7935248, 'bl 0x795a98'), (7935296, 'bl sym.imp.memcpy'), (7935736, 'bl 0x7963b0'), (7935772, 'bl sym.imp.memcpy'), (7936224, 'bl 0x7963b0'), (7936260, 'bl sym.imp.memcpy'), (7936652, 'bl 0x795a98'), (7936908, 'bl sym.imp.sinf'), (7937244, 'bl 0x796018'), (7937724, 'bl 0x795c80'), (7938284, 'bl 0x795a98'), (7938504, 'bl sym.imp.sinf'), (7938800, 'bl 0x7963b0'), (7939280, 'bl 0x796018'), (7939776, 'bl 0x795a98'), (7940128, 'bl 0x796018'), (7940476, 'bl sym.imp.sinf'), (7940772, 'bl 0x7963b0'), (7941252, 'bl 0x796018'), (7941328, 'bl sym.imp.memcpy'), (7941376, 'blx ip'), (7941380, 'bl sym.imp.__wrap_glUseProgram'), (7941512, 'blx r6'), (7941532, 'blx r3'), (7941548, 'blx r2'), (7941556, 'bl sym.imp.__wrap_glUniform1i'), (7941640, 'bl loc.imp.objc_msgSend_stret'), (7941680, 'bl sym.imp.memset'), (7942152, 'bl method.Vector.Vector_float__float__float_'), (7942172, 'bl method.Vector.operator_float__'), (7942244, 'bl method.Vector.operator_float__'), (7942296, 'bl method.Vector.operator_float__'), (7942368, 'bl method.Vector.operator_float__'), (7942420, 'bl method.Vector.operator_float__'), (7942492, 'bl method.Vector.operator_float__'), (7942560, 'bl method.Vector.Vector_float__float__float_'), (7942576, 'bl method.Vector.operator_float__'), (7942692, 'bl method.Vector.operator_float__'), (7942716, 'bl method.Vector.operator_float__'), (7942828, 'bl method.Vector.operator_float__'), (7942852, 'bl method.Vector.operator_float__'), (7943064, 'bl method.Vector.operator_float__'), (7943372, 'bl 0x7969fc'), (7943640, 'bl 0x796748'), (7943684, 'bl method.Vector.Vector_float__float__float__float_'), (7943696, 'bl method.Vector.operator_float__'), (7943712, 'bl method.Vector.operator_float__'), (7943728, 'bl method.Vector.operator_float__'), (7943760, 'bl method.Vector.Vector_float__float__float__float_'), (7943804, 'bl sym.Vector::operator_Vector_'), (7943832, 'bl method.Vector.Vector_float__float__float_'), (7943856, 'bl loc.imp.objc_msgSend'), (7943900, 'bl 0x78dc28'), (7943948, 'bl 0x78dc28'), (7944012, 'bl method.Vector.Vector_float__float__float_'), (7944244, 'bl loc.imp.objc_msgSend'), (7944304, 'bl loc.imp.objc_msgSend'), (7944340, 'bl loc.imp.objc_msgSend'), (7944364, 'bl loc.imp.objc_msgSend'), (7944384, 'bl method.Vector.operator_float__'), (7944400, 'bl method.Vector.operator_float__'), (7944416, 'bl method.Vector.operator_float__'), (7944448, 'bl sym.imp.__wrap_glUniform4f'), (7944456, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (7945248, 'bl 0x796a38'), (7946040, 'bl 0x796a38'), (7946076, 'bl loc.imp.objc_msgSend'), (7946104, 'bl loc.imp.objc_msgSend'), (7946120, 'bl loc.imp.objc_msgSend'), (7946140, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (7946176, 'bl loc.imp.objc_msgSend'), (7946204, 'bl loc.imp.objc_msgSend'), (7946220, 'bl loc.imp.objc_msgSend'), (7946236, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (7946284, 'bl loc.imp.objc_msgSend'), (7946312, 'bl sym.imp.__wrap_glBindTexture'), (7946360, 'bl loc.imp.objc_msgSend'), (7947152, 'bl 0x796a38'), (7948072, 'bl 0x796a38'), (7948240, 'bl loc.imp.objc_msgSend'), (7948260, 'bl loc.imp.objc_msgSend'), (7948276, 'bl loc.imp.objc_msgSend'), (7948292, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (7948328, 'bl loc.imp.objc_msgSend'), (7948348, 'bl loc.imp.objc_msgSend'), (7948364, 'bl loc.imp.objc_msgSend'), (7948380, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (7948420, 'bl loc.imp.objc_msgSend'), (7948440, 'bl sym.imp.__wrap_glBindTexture'), (7948480, 'bl loc.imp.objc_msgSend'), (7949272, 'bl 0x796a38'), (7950192, 'bl 0x796a38'), (7950360, 'bl loc.imp.objc_msgSend'), (7950380, 'bl loc.imp.objc_msgSend'), (7950396, 'bl loc.imp.objc_msgSend'), (7950412, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (7950448, 'bl loc.imp.objc_msgSend'), (7950468, 'bl loc.imp.objc_msgSend'), (7950484, 'bl loc.imp.objc_msgSend'), (7950500, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (7950540, 'bl loc.imp.objc_msgSend'), (7950560, 'bl sym.imp.__wrap_glBindTexture'), (7950600, 'bl loc.imp.objc_msgSend'), (7951392, 'bl 0x796a38'), (7952312, 'bl 0x796a38'), (7952468, 'bl sym.imp.memcpy'), (7952528, 'blx ip'), (7952548, 'blx r3'), (7952564, 'blx r2'), (7952596, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (7952732, 'blx r3'), (7952752, 'blx r3'), (7952768, 'blx r2'), (7952800, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (7952880, 'blx r3'), (7952888, 'bl sym.imp.__wrap_glDisableVertexAttribArray')],
        branches=[(7928012, 'blt', 7928104), (7928100, 'b', 7928316), (7928224, 'bge', 7928312), (7928312, 'b', 7928316), (7928448, 'blt', 7928540), (7928536, 'b', 7928752), (7928660, 'bge', 7928748), (7928748, 'b', 7928752), (7928792, 'blt', 7928928), (7928836, 'bgt', 7928928), (7928880, 'blt', 7928928), (7928924, 'ble', 7928932), (7928928, 'b', 7952892), (7929120, 'ble', 7929252), (7929248, 'b', 7929520), (7929388, 'bpl', 7929516), (7929516, 'b', 7929520), (7929556, 'beq', 7929584), (7929768, 'beq', 7929792), (7929788, 'bne', 7929832), (7929828, 'b', 7952892), (7929852, 'beq', 7929876), (7929968, 'beq', 7930200), (7930068, 'ble', 7930196), (7930120, 'bpl', 7930148), (7930140, 'b', 7930168), (7930196, 'b', 7930200), (7930236, 'bne', 7930376), (7930684, 'bne', 7930732), (7930724, 'b', 7930788), (7930744, 'bne', 7930784), (7930784, 'b', 7930788), (7930848, 'ble', 7931344), (7930916, 'bne', 7930972), (7931092, 'bpl', 7931116), (7931112, 'b', 7931136), (7931284, 'b', 7932012), (7931404, 'bge', 7931876), (7931472, 'bne', 7931528), (7931648, 'bpl', 7931680), (7931668, 'b', 7931700), (7931848, 'b', 7932008), (7932008, 'b', 7932012), (7932052, 'beq', 7932624), (7932116, 'beq', 7932152), (7932140, 'b', 7932188), (7932212, 'ble', 7932424), (7932404, 'b', 7932620), (7932620, 'b', 7932624), (7932744, 'bpl', 7932896), (7932764, 'b', 7932916), (7933180, 'beq', 7933204), (7933240, 'bne', 7933640), (7934804, 'beq', 7936268), (7934808, 'b', 7934848), (7935328, 'ble', 7935820), (7935776, 'b', 7936264), (7936264, 'b', 7936268), (7937836, 'b', 7937880), (7941620, 'beq', 7941648), (7941644, 'b', 7941684), (7941808, 'bpl', 7941832), (7941828, 'b', 7941848), (7941896, 'bpl', 7941920), (7941916, 'b', 7941936), (7941984, 'ble', 7942056), (7942616, 'bpl', 7942644), (7942636, 'b', 7942660), (7942756, 'bpl', 7942780), (7942776, 'b', 7942796), (7942892, 'bpl', 7943016), (7942912, 'b', 7943032), (7943132, 'ble', 7944248), (7943172, 'bne', 7944248), (7952476, 'b', 7952488)],
        semantics=('[ClownFish -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]] (imp 0x0078f5d8, 6419w): -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:] (0x78f5d8, 6419w, CENSUS 75br/161 calls): renders the fish. Huge O0 frame (sub sp 0x9f0 + 0x1000, bic sp,#0xf) with a stack "draw-state" struct built at sp+0x176c: +0x1e0..+0x1f4 camera/aux ints+floats, +0x1f8 float dt (f8 of tsv arg, zeroed when ground solid), +0x1fc, +0x200 self pointer, +0x204/+0x244 the two 16f GLKMatrix4 args (tsv: f8 m12 m76 i140 i144 i148 i152). Head: toroidal dx wrap vs worldWidthMacro*32 /2 (blt/bge pairs at 0x78f8a8/0x78f9a0/0x78fa78/0x78fb50) into [state+0x1e4]; then camera-bounds early-outs (exit b 0x7959fc) from range chain 0x78fbd0..0x78fc5c against [state+0x1e0/0x1e4/0x1e8/0x1ec]. Then: accum Vector2 at sp+0x1940 += walk offset; if (isOnAirAboveSolidGround@309) y -= 0.3 (pool 0x790120); tile = tileAtWorldPosition(fromSquare.x, fromSquare.y, world) (0x78ff90); if (tile==0 || tile->byte6==0) { self.visible@57=0; return; } self.visible=1; [state+0x1cc]=self.walkSpeed; if (!<byte ivar>) skip; if (tileIsSolid(tile) 0x78fff0) [state+0x1f8]=0.0. Bubble timer block 0x790180: bubbleEmitTimer@300 += dt*[state+0x1cc] (f64 math, D0=0.5 gl #96) etc. 0x790880 hooked block: if (self.hookedFishingRod != nil): dir=[rod hookedFishDirection] sret (Vector2); if (dir.x>0) a=atan2(dir.y,dir.x) else a=atan2(-dir.y,-dir.x); goalZRotation@272=bodyZRotation@276=(float)a; goalRotation@268=bodyRotation@264 = (dir.x>0? +pi/2 0x790718=0x3fc90fdb : -pi/2 0x79071c=0xbfc90fdb). 0x790ad0..0x792c94 pose section: 5 sinf phases (0x790cc0/0x79112c/0x791b8c/0x7921c8/0x79297c; phase=sin(x)*amp via f64, amp-spills in arenas) + matrix helper family (bl 0x795a24/0x795a98 x5/0x795c80 x2/0x796018 x5/0x7963b0 x4/0x796748/0x7969fc/0x796a38 x8: local 64B matrix-compose helpers just past the body) + 7 memcpy(64B) + Vector/Vector2 operator float* helper calls. GL prologue 0x792c94: memcpy64; glUseProgram([shader@208 program]); idx=[[shader uniformLocations] objectAtIndex:0]; glUniform1i([idx intValue], 0). Particle block 0x7936xx: [ParticleEmitter instance] (class cell 0x793340, sel instance); 2x rng (0x78dc28) -> velocity Vector (x=(rnd-0.5)*0.5 [gl #96], y=rnd*0.2+0.4 (pools 0x793348/0x79334c), z); addParticleAtPos:velocity:color:gravityType:life:scale: (sel cell 0x793350) + glUniform4f (dayColor) 0x793900 + glEnableVertexAttribArray(2) 0x793908. 4 cube blocks (2x glUniformMatrix4fv each = mvp_matrix (uniformLocations[0]) + normal_matrix (uniformLocations[3])): B1 0x793f9c/0x793ffc mvp+normal -> glBindTexture(bodyTexture@212) 0x794048 -> [bodyCube@224 draw]; B2 0x794804/0x79485c -> bind tailTexture@216 0x794898 -> [tailCube@228 draw] 0x7948c0; B3 0x79504c/0x7950a4 -> bind sideFinTexture@220 0x7950e0 -> [sideFinCube@232 draw] 0x795108; B4 0x7958d4/0x7959a0 -> [sideFinCube draw again] 0x7959f0; then glDisableVertexAttribArray(2) 0x7959f8, exit. ~161 calls incl. 41 objc_msgSend, 8 __wrap_glUniformMatrix4fv, 3 glBindTexture, 5 sinf, 2 atan2, 7 memcpy, 18 Vector::operator float*, 12 Vector2::operator float*..\n'),
    ),
    dict(
        name='clf_13',
        method='ClownFish -[foodItemType]',
        types='i8@0:4',
        start=7918504,
        end=7918532,
        disasm='disasm_worldtileloader_clf_13.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0078d448; body trimmed at the next IMP 0x0078d3c4 ClownFish -[getNamesArray]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7918504, 'sub sp, sp, 8'), (7918528, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[ClownFish -[foodItemType]] (imp 0x0078d3a8, 7w): -[foodItemType] (0x78d3a8, 7w): return 0x90 (144)..\n'),
    ),
    dict(
        name='clf_14',
        method='ClownFish -[getNamesArray]',
        types='^@8@0:4',
        start=7918532,
        end=7918580,
        disasm='disasm_worldtileloader_clf_14.txt',
        base_add=7918540,
        base_literal=7918576,
        boundary='ARM.exidx end 0x0078d448; body trimmed at the next IMP 0x0078d3f4 ClownFish -[getNamesArrayCount]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7918532, 'sub sp, sp, 8'), (7918576, 'addeq r2, sp, r0, lsr 14')],
        calls=[],
        branches=[],
        semantics=('[ClownFish -[getNamesArray]] (imp 0x0078d3c4, 12w): -[getNamesArray] (0x78d3c4, 12w): PIC-materialized pointer 0x01051CF8 -> 62-entry CFString table (table itself continues into other NPC name arrays past index 62; count pinned by clf_15 = 62). Names: Amethyst, Sapphire, Ruby, Emerald, Diamond, Angel, Babel, Bait, Bubbles, Bubbly, Calypso, Chandler, Chanel, Chip, Curly, Deb, Diablo, Danny, Dory, Elvis, Eureka, Lulu, Marble, Macaroni, Marshmellow, Max, Miggy, Moe, Mouse, Mr. Bubbles, Mr. Wigglesworth, Napoleon, Nemo, PeeWee, Clown, Fez, Fish, Flounder, Franky, Fred, Fredrick, Frosty, George, Gilbert, Grant, Hippo, Jaws, Jerry, Joe, Samson, Shark, Fishy McFishface, Champ, Sonic, Sophie, Speedy, Spud, Squirt, Sushi, Coconut, Trevor, Xavier..\n'),
    ),
    dict(
        name='clf_15',
        method='ClownFish -[getNamesArrayCount]',
        types='i8@0:4',
        start=7918580,
        end=7918608,
        disasm='disasm_worldtileloader_clf_15.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0078d448; body trimmed at the next IMP 0x0078d410 ClownFish -[capturedItemType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7918580, 'sub sp, sp, 8'), (7918604, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[ClownFish -[getNamesArrayCount]] (imp 0x0078d3f4, 7w): -[getNamesArrayCount] (0x78d3f4, 7w): return 0x3e (62)..\n'),
    ),
    dict(
        name='clf_16',
        method='ClownFish -[hitWithForce:blockhead:]',
        types='v16@0:4i8@12',
        start=7977324,
        end=7977720,
        disasm='disasm_worldtileloader_clf_16.txt',
        base_add=7977340,
        base_literal=7977716,
        boundary='ARM.exidx end 0x0079baf8 (listing bound); next ObjC IMP 0x0079baf8 ClownFish -[renderPos]',
        selectors={
                 0x79bad4: (15209464, 'hitWithForce:blockhead:'),
        },
        imports={
                 0x79bad0: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0x79badc: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0x79bae0: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x79bae4: (17160068, 'OBJC_IVAR_$_ClownFish.randomTimeBetweenDirectionChanges', 260),
                 0x79bae8: (17160064, 'OBJC_IVAR_$_ClownFish.walkSpeed', 284),
                 0x79baec: (17160060, 'OBJC_IVAR_$_ClownFish.movementDirection', 236),
        },
        classes={
                 0x79bad8: (15252792, 'OBJC_CLASS_$_ClownFish'),
        },
        instructions=[(7977324, 'push {r4, r5, r6, sl, fp, lr}'), (7977716, 'addeq r4, ip, r0, ror r1')],
        calls=[(7977424, 'blx r4'), (7977500, 'bl 0x78dc28')],
        branches=[(7977460, 'bne', 7977672), (7977496, 'bne', 7977672)],
        semantics=('[ClownFish -[hitWithForce:blockhead:]] (imp 0x0079b96c, 99w): -[hitWithForce:blockhead:] (0x79b96c, 99w): FIRST [super hitWithForce:force blockhead:bh] via msgSendSuper2 (superstruct at sp+0x18; tsv v16@0:4 i8 @12 - force is an int). Then if (self.dead@56) return; if (self.isNet@52) return; x = lrand48()/2147483648.0f (pool 0x79baf0 = 0x4f000000); self.movementDirection@236 = (x > 0.5) ? 1 : -1 (gl d2 #96=0.5, mvneq gives -1); self.walkSpeed@284 = 3.0f (gl s2 #8); self.randomTimeBetweenDirectionChanges@260 = 5.0f (gl s0 #20). Local-control only..\n'),
    ),
    dict(
        name='clf_17',
        method='ClownFish -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:]',
        types='@44@0:4@8@12{?=ii}16@24@28c32c36@40',
        start=7921408,
        end=7922720,
        disasm='disasm_worldtileloader_clf_17.txt',
        base_add=7921424,
        base_literal=7922716,
        boundary='ARM.exidx end 0x0078e420 (listing bound); next ObjC IMP 0x0078e420 ClownFish -[initWithWorld:dynamicWorld:saveDict:cache:]',
        selectors={
                 0x78e3e8: (15209208, 'initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:'),
                 0x78e3f8: (15209216, 'release'),
                 0x78e3fc: (15209212, 'removeFromMacroBlock'),
                 0x78e408: (15209220, 'getWeatherFractionForPos:'),
                 0x78e40c: (15209224, 'worldTime'),
                 0x78e410: (15209228, 'getDayNightFractionForX:atWorldTime:'),
                 0x78e418: (15209232, 'loadDerivedStuff'),
        },
        imports={
                 0x78e3f4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x78e3ec: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x78e3f0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x78e414: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
        },
        classes={
                 0x78e3e0: (15252792, 'OBJC_CLASS_$_ClownFish'),
        },
        instructions=[(7921408, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7922716, 'ldrdeq r1, r2, [sp], ip')],
        calls=[(7921652, 'bl loc.imp.objc_msgSendSuper2'), (7921768, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (7921808, 'bl sym.tileIsWater_Tile_'), (7921904, 'blx ip'), (7921924, 'blx r2'), (7922060, 'bl loc.imp.objc_msgSend'), (7922132, 'bl loc.imp.objc_msgSend'), (7922172, 'bl loc.imp.objc_msgSend'), (7922224, 'bl loc.imp.objc_msgSend'), (7922272, 'bl sym.seasonForWorldX_int__double__World_'), (7922372, 'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_'), (7922544, 'blx ip'), (7922564, 'blx r2'), (7922624, 'blx r2')],
        branches=[(7921680, 'bne', 7921696), (7921692, 'b', 7922636), (7921788, 'beq', 7921840), (7921800, 'bne', 7921940), (7921820, 'beq', 7921840), (7921836, 'bge', 7921940), (7921936, 'b', 7922636), (7921948, 'bne', 7922584), (7922400, 'bmi', 7922480), (7922448, 'ble', 7922580), (7922476, 'bpl', 7922580), (7922576, 'b', 7922636), (7922580, 'b', 7922584)],
        semantics=('[ClownFish -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:]] (imp 0x0078df00, 328w): -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:] (0x78df00, 328w, census-lite): [super same 8-arg selector] via msgSendSuper2 (superstruct {self, ClownFish}; stack: pos pair, cache, saveDict, isAdult(sxtb), wasPlaced(sxtb), placedByClient); if (!self) return nil. tile = tileAtWorldPositionLoaded(pos.x, pos.y, world). If (!wasPlaced) require tile != 0 && tileIsWater(tile) && tile->byte4 >= 0x7f, else { [self removeFromMacroBlock]; [self release]; return nil; }. If (wasPlaced) skip checks. Else: w = [world getWeatherFractionForPos:{pos.x,pos.y}]; dn = [world getDayNightFractionForX:(float)pos.x atWorldTime:[world worldTime]]; season = seasonForWorldX(pos.x, [world worldTime], world); temp = currentTemperatureForTileAtWorldPos(tile, {pos.x,pos.y}, season, dn, w, world); if (temp < 0.1f) fail; if (age@88 <= 0.1 double) ok; else if (temp >= 2.0f) ok; else fail. OK: [self loadDerivedStuff]; return self. (worldTime called twice - no CSE at O0)..\n'),
    ),
    dict(
        name='clf_18',
        method='ClownFish -[initWithWorld:dynamicWorld:cache:netData:]',
        types='@24@0:4@8@12@16@20',
        start=7923016,
        end=7923564,
        disasm='disasm_worldtileloader_clf_18.txt',
        base_add=7923032,
        base_literal=7923560,
        boundary='ARM.exidx end 0x0078e76c (listing bound); next ObjC IMP 0x0078e76c ClownFish -[getSaveDict]',
        selectors={
                 0x78e740: (15209240, 'initWithWorld:dynamicWorld:cache:netData:'),
                 0x78e74c: (15209232, 'loadDerivedStuff'),
                 0x78e750: (15209244, 'remoteCreationDataUpdate:'),
        },
        imports={
                 0x78e73c: (17151900, 'objc_msgSendSuper2'),
                 0x78e748: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x78e754: (17160092, 'OBJC_IVAR_$_ClownFish.nextToSquare', 320),
                 0x78e75c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x78e760: (17160096, 'OBJC_IVAR_$_ClownFish.nextWalkSpeed', 352),
                 0x78e764: (17160100, 'OBJC_IVAR_$_ClownFish.nextMovementDirection', 368),
        },
        classes={
                 0x78e744: (15252792, 'OBJC_CLASS_$_ClownFish'),
        },
        instructions=[(7923016, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7923560, 'umulleq r1, sp, r4, r5')],
        calls=[(7923168, 'blx r6'), (7923264, 'blx r3'), (7923492, 'blx r3')],
        branches=[(7923196, 'bne', 7923212), (7923208, 'b', 7923504), (7923288, 'bge', 7923444), (7923440, 'b', 7923280)],
        semantics=('[ClownFish -[initWithWorld:dynamicWorld:cache:netData:]] (imp 0x0078e548, 137w): -[initWithWorld:dynamicWorld:cache:netData:] (0x78e548, 137w): self = [super initWithWorld:dynamicWorld:cache:netData:] (msgSendSuper2); if (!self) return nil; [self loadDerivedStuff]; for (i = 0; i < 4; i++) { self.nextToSquare@320[i] = self.pos@16; self.nextWalkSpeed@352[i] = 0; self.nextMovementDirection@368[i] = 0; } [self remoteCreationDataUpdate:netData]; return self..\n'),
    ),
    dict(
        name='clf_19',
        method='ClownFish -[loadDerivedStuff]',
        types='v8@0:4',
        start=7918664,
        end=7920680,
        disasm='disasm_worldtileloader_clf_19.txt',
        base_add=7918684,
        base_literal=7920676,
        boundary='ARM.exidx end 0x0078dc28 (listing bound); next ObjC IMP 0x0078dc38 ClownFish -[canBeCapturedByBlockhead:withItemType:]',
        selectors={
                 0x78db90: (15209188, 'initWithWidth:height:depth:centerX:centerY:centerZ:calculateNormals:'),
                 0x78db94: (15209180, 'alloc'),
                 0x78dba4: (15209184, 'initWithWidth:height:depth:calculateNormals:'),
                 0x78dbb0: (15209176, 'textureNamed:'),
                 0x78dbd0: (15209172, 'shaderNamed:attributes:uniforms:'),
                 0x78dbe4: (15209168, 'arrayWithObjects:'),
        },
        imports={
                 0x78db8c: (17151904, 'objc_msgSend'),
                 0x78dbac: (16319416, '__CFConstantStringClassReference'),
                 0x78dbbc: (16319400, '__CFConstantStringClassReference'),
                 0x78dbc4: (16319384, '__CFConstantStringClassReference'),
                 0x78dbcc: (16319256, '__CFConstantStringClassReference'),
                 0x78dbd4: (16319320, '__CFConstantStringClassReference'),
                 0x78dbd8: (16319336, '__CFConstantStringClassReference'),
                 0x78dbdc: (16319352, '__CFConstantStringClassReference'),
                 0x78dbe0: (16319368, '__CFConstantStringClassReference'),
                 0x78dbec: (16319272, '__CFConstantStringClassReference'),
                 0x78dbf0: (16319288, '__CFConstantStringClassReference'),
                 0x78dbf4: (16319304, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x78db84: (17160032, 'OBJC_IVAR_$_ClownFish.sideFinCube', 232),
                 0x78db9c: (17160036, 'OBJC_IVAR_$_ClownFish.tailCube', 228),
                 0x78dba0: (17160040, 'OBJC_IVAR_$_ClownFish.bodyCube', 224),
                 0x78dba8: (17160044, 'OBJC_IVAR_$_ClownFish.sideFinTexture', 220),
                 0x78dbb4: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0x78dbb8: (17160048, 'OBJC_IVAR_$_ClownFish.tailTexture', 216),
                 0x78dbc0: (17160052, 'OBJC_IVAR_$_ClownFish.bodyTexture', 212),
                 0x78dbc8: (17160056, 'OBJC_IVAR_$_ClownFish.shader', 208),
                 0x78dbf8: (17160060, 'OBJC_IVAR_$_ClownFish.movementDirection', 236),
                 0x78dbfc: (17160064, 'OBJC_IVAR_$_ClownFish.walkSpeed', 284),
                 0x78dc00: (17160068, 'OBJC_IVAR_$_ClownFish.randomTimeBetweenDirectionChanges', 260),
                 0x78dc04: (17160072, 'OBJC_IVAR_$_ClownFish.travelFraction', 256),
                 0x78dc08: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x78dc0c: (17160076, 'OBJC_IVAR_$_ClownFish.toSquare', 248),
                 0x78dc10: (17160080, 'OBJC_IVAR_$_ClownFish.fromSquare', 240),
                 0x78dc18: (17160084, 'OBJC_IVAR_$_ClownFish.goalRotation', 268),
                 0x78dc1c: (17160088, 'OBJC_IVAR_$_ClownFish.bodyRotation', 264),
        },
        classes={
                 0x78db98: (15247004, 'OBJC_CLASS_$_DrawCube'),
                 0x78dbe8: (15247000, 'OBJC_CLASS_$_NSArray'),
        },
        instructions=[(7918664, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7920676, 'umulleq r2, sp, r0, r6')],
        calls=[(7919240, 'blx r4'), (7919304, 'blx r5'), (7919348, 'blx lr'), (7919408, 'blx ip'), (7919468, 'blx ip'), (7919528, 'blx ip'), (7919580, 'blx ip'), (7919632, 'blx lr'), (7919684, 'blx ip'), (7919800, 'blx lr'), (7919852, 'blx ip'), (7919940, 'blx lr'), (7919964, 'bl 0x78dc28'), (7920264, 'bl 0x78dc28')],
        branches=[(7919696, 'b', 7919728), (7920008, 'ble', 7920024), (7920020, 'b', 7920068), (7920364, 'bne', 7920428), (7920424, 'b', 7920484)],
        semantics=('[ClownFish -[loadDerivedStuff]] (imp 0x0078d448, 504w): -[loadDerivedStuff] (0x78d448, 504w, census-lite): post-init asset build + state seeds. cache = [self.cache@32]; shader@208 = [cache shaderNamed:@"ShadedWorldObject"(0xF90318) attributes:[NSArray arrayWithObjects:@"position","texCoord","normal",nil (0xF90328/38/48)] uniforms:[NSArray arrayWithObjects:@"mvp_matrix","texture","light","normal_matrix",nil (0xF90358/68/78/88)]]; bodyTexture@212 = [shader textureNamed:@"clownFishBody.png"(0xF90398)]; tailTexture@216 = @"clownFishTail.png"(0xF903A8); sideFinTexture@220 = @"clownFishSideFin.png"(0xF903B8). Cubes ([DrawCube alloc]): bodyCube@224 = initWithWidth:0.5 height:0.5 depth:0.2 calculateNormals:1 (4-arg; gl s12 #96=0.5, pool 0x78d86c=0.2); tailCube@228 = 8-arg (0.4, 0.4, 0.1, cx 0.0, cy 0.4, cz 0.05, cn 1); sideFinCube@232 = 8-arg (0.3, 0.1, 0.15, cx 0.1, cy 0.05, cz 0.0, cn 1) (pools 0x78d854=0.3, 0x78d858=0.1, 0x78d85c=0.15, 0x78d860=0.05, 0x78d864=0.0, 0x78d868=0.4). State: x = lrand48()/2^31f; movementDirection = x>0.75?1:(x<0.25?-1:0) (gl d8 #104=0.75, d0 #80=0.25); toSquare@248 = pos; fromSquare@240 = toSquare; travelFraction@256 = 1.0; randomTimeBetweenDirectionChanges@260 = 0.0 (pool 0x78db88); walkSpeed@284 = (float)(0.1 + x2*0.2) (doubles 0x78db70=0.1, 0x78db78=0.2); bodyRotation@264 = goalRotation@268 = (movementDirection==1 ? +pi/2 (0x78dc20=0x3fc90fdb) : -pi/2 (0x78dc14=0xbfc90fdb))..\n'),
    ),
    dict(
        name='clf_20',
        method='ClownFish -[maxAge]',
        types='f8@0:4',
        start=7918408,
        end=7918456,
        disasm='disasm_worldtileloader_clf_20.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0078d378 (listing bound); next ObjC IMP 0x0078d378 ClownFish -[speciesName]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7918408, 'sub sp, sp, 0x10'), (7918452, 'strbmi r0, [r1, 0]!')],
        calls=[],
        branches=[],
        semantics=('[ClownFish -[maxAge]] (imp 0x0078d348, 12w): -[maxAge] (0x78d348, 12w): return 7200.0f (r0 bits 0x45e10000 via movw 0/movt 0x45e1; dead vldr from pool 0x78d374 = same)..\n'),
    ),
    dict(
        name='clf_21',
        method='ClownFish -[maxHealth]',
        types='S8@0:4',
        start=7975908,
        end=7975936,
        disasm='disasm_worldtileloader_clf_21.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0079b400 (listing bound); next ObjC IMP 0x0079b400 ClownFish -[tapIsWithinBodyRadius:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7975908, 'sub sp, sp, 8'), (7975932, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[ClownFish -[maxHealth]] (imp 0x0079b3e4, 7w): -[maxHealth] (0x79b3e4, 7w): return 0x19 (25) (uxth; tsv S8@0:4)..\n'),
    ),
    dict(
        name='clf_22',
        method='ClownFish -[npcType]',
        types='i8@0:4',
        start=7918380,
        end=7918408,
        disasm='disasm_worldtileloader_clf_22.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0078d348 (listing bound); next ObjC IMP 0x0078d348 ClownFish -[maxAge]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7918380, 'sub sp, sp, 8'), (7918404, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[ClownFish -[npcType]] (imp 0x0078d32c, 7w): -[npcType] (0x78d32c, 7w): return 4..\n'),
    ),
    dict(
        name='clf_23',
        method='ClownFish -[reactToBeingFed]',
        types='v8@0:4',
        start=7978776,
        end=7979340,
        disasm='disasm_worldtileloader_clf_23.txt',
        base_add=7978792,
        base_literal=7979336,
        boundary='ARM.exidx end 0x0079c14c (listing bound); next ObjC IMP 0x0079c14c ClownFish -[.cxx_construct]',
        selectors={
                 0x79c114: (15209476, 'reactToBeingFed'),
                 0x79c130: (15209332, 'instance'),
                 0x79c134: (15209348, 'multiSoundNamed:'),
                 0x79c140: (15209352, 'playAtPosition:afterDelay:'),
        },
        imports={
                 0x79c110: (17151900, 'objc_msgSendSuper2'),
                 0x79c138: (16319480, '__CFConstantStringClassReference'),
                 0x79c144: (16319496, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x79c120: (17160120, 'OBJC_IVAR_$_ClownFish.walkTimer', 280),
                 0x79c124: (17160064, 'OBJC_IVAR_$_ClownFish.walkSpeed', 284),
                 0x79c13c: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={
                 0x79c118: (15252792, 'OBJC_CLASS_$_ClownFish'),
                 0x79c128: (15247020, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(7978776, 'push {r4, r5, r6, r7, fp, lr}'), (7979336, 'addeq r3, ip, r4, asr 23')],
        calls=[(7978860, 'blx ip'), (7978968, 'bl loc.imp.objc_msgSend'), (7979000, 'bl loc.imp.objc_msgSend'), (7979096, 'bl loc.imp.objc_msgSend'), (7979120, 'bl loc.imp.objc_msgSend'), (7979144, 'bl loc.imp.objc_msgSend'), (7979220, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[ClownFish -[reactToBeingFed]] (imp 0x0079bf18, 141w): -[reactToBeingFed] (0x79bf18, 141w): [super reactToBeingFed] (msgSendSuper2); s = [MJSoundManager instance]; [s multiSoundNamed:@"fishRun.wav"(0xF903F8)] playAtPosition:self.floatPos afterDelay:0.6 (double 0x3FE3333340000000); [s multiSoundNamed:@"crunch.wav"(0xF90408)] playAtPosition:floatPos afterDelay:0.1 (0x3FB99999A0000000); self.walkSpeed@284 = 1.0f (gl s2 #112); self.walkTimer@280 = 0.0f (pool 0x79c11c). Not a full stop (unlike Scorpion) - speed clamps to 1.0..\n'),
    ),
    dict(
        name='clf_24',
        method='ClownFish -[reactToBeingHit]',
        types='v8@0:4',
        start=7977020,
        end=7977324,
        disasm='disasm_worldtileloader_clf_24.txt',
        base_add=7977036,
        base_literal=7977320,
        boundary='ARM.exidx end 0x0079b96c (listing bound); next ObjC IMP 0x0079b96c ClownFish -[hitWithForce:blockhead:]',
        selectors={
                 0x79b954: (15209332, 'instance'),
                 0x79b958: (15209348, 'multiSoundNamed:'),
                 0x79b964: (15209352, 'playAtPosition:afterDelay:'),
        },
        imports={
                 0x79b95c: (16319480, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x79b944: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0x79b948: (17160108, 'OBJC_IVAR_$_ClownFish.currentNetQueueSize', 316),
                 0x79b960: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={
                 0x79b94c: (15247020, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(7977020, 'push {fp, lr}'), (7977320, 'addeq r4, ip, r0, lsr 5')],
        calls=[(7977144, 'bl loc.imp.objc_msgSend'), (7977168, 'bl loc.imp.objc_msgSend'), (7977248, 'bl loc.imp.objc_msgSend')],
        branches=[(7977080, 'bne', 7977276)],
        semantics=('[ClownFish -[reactToBeingHit]] (imp 0x0079b83c, 76w): -[reactToBeingHit] (0x79b83c, 76w): if (self.dead@56) return; [s multiSoundNamed:@"fishRun.wav"(0xF903F8)] playAtPosition:self.floatPos afterDelay:0.1; self.currentNetQueueSize@316 = 0 (queue reset on hit)..\n'),
    ),
    dict(
        name='clf_25',
        method='ClownFish -[remoteBlockheadHookedYou:]',
        types='v12@0:4@8',
        start=7978108,
        end=7978524,
        disasm='disasm_worldtileloader_clf_25.txt',
        base_add=7978124,
        base_literal=7978520,
        boundary='ARM.exidx end 0x0079be1c (listing bound); next ObjC IMP 0x0079be1c ClownFish -[blockheadUnloaded:]',
        selectors={
                 0x79be00: (15209440, 'fishingRod'),
                 0x79be04: (15209448, 'hookedFish'),
                 0x79be0c: (15209272, 'setHookedFish:'),
                 0x79be10: (15209456, 'retain'),
                 0x79be14: (15209276, 'autorelease'),
        },
        imports={
                 0x79bdfc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x79be08: (17160104, 'OBJC_IVAR_$_ClownFish.hookedFishingRod', 312),
        },
        classes={},
        instructions=[(7978108, 'push {r4, r5, r6, sl, fp, lr}'), (7978520, 'addeq r3, ip, r0, ror 28')],
        calls=[(7978176, 'blx lr'), (7978252, 'blx r3'), (7978404, 'blx r4'), (7978436, 'blx r3'), (7978480, 'blx r3')],
        branches=[(7978196, 'beq', 7978484), (7978264, 'bne', 7978484), (7978304, 'beq', 7978484)],
        semantics=('[ClownFish -[remoteBlockheadHookedYou:]] (imp 0x0079bc7c, 104w): -[remoteBlockheadHookedYou:] (0x79bc7c, 104w): arg is a Blockhead (tsv v12@0:4@8; -[Blockhead fishingRod] @0xC80FB0). rod = [bh fishingRod]; if (rod == nil) return; if ([rod hookedFish] != nil) return; if (self.hookedFishingRod == rod) return; [self.hookedFishingRod autorelease]; self.hookedFishingRod = [rod retain]; [rod setHookedFish:self]. Rod-side accessors: -[FishingRod hookedFish]/setHookedFish:/blockhead used here and in clf_01..\n'),
    ),
    dict(
        name='clf_26',
        method='ClownFish -[remoteCreationDataUpdate:]',
        types='v12@0:4@8',
        start=7926632,
        end=7927224,
        disasm='disasm_worldtileloader_clf_26.txt',
        base_add=7926648,
        base_literal=7927220,
        boundary='ARM.exidx end 0x0078f5b8 (listing bound); next ObjC IMP 0x0078f5b8 ClownFish -[creationDataStructSize]',
        selectors={
                 0x78f588: (15209244, 'remoteCreationDataUpdate:'),
                 0x78f594: (15209292, 'getBytes:length:'),
                 0x78f59c: (15209296, 'doRemoteUpdate:'),
                 0x78f5a8: (15209284, 'isClient'),
        },
        imports={
                 0x78f584: (17151900, 'objc_msgSendSuper2'),
                 0x78f5a4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x78f590: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0x78f5a0: (17160072, 'OBJC_IVAR_$_ClownFish.travelFraction', 256),
                 0x78f5ac: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x78f5b0: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
        },
        classes={
                 0x78f58c: (15252792, 'OBJC_CLASS_$_ClownFish'),
        },
        instructions=[(7926632, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7927220, 'addeq r0, sp, r4, ror r7')],
        calls=[(7926724, 'blx lr'), (7926804, 'bl loc.imp.objc_msgSend'), (7926992, 'bl loc.imp.objc_msgSend'), (7927112, 'blx r2')],
        branches=[(7926760, 'bne', 7927000), (7926996, 'b', 7927164), (7927048, 'bpl', 7927160), (7927124, 'bne', 7927160), (7927160, 'b', 7927164)],
        semantics=('[ClownFish -[remoteCreationDataUpdate:]] (imp 0x0078f368, 148w): -[remoteCreationDataUpdate:] (0x78f368, 148w): [super remoteCreationDataUpdate:data] (msgSendSuper2); if (self.dead@56) { if (self.travelFraction@256 < 1.0f && ![self.dynamicWorld isClient]) self.needsRemoved@48 = 0; return; } buf[0x70]; [data getBytes:buf length:0x70]; [self doRemoteUpdate:(char*)buf+0x48] - the 0x28B fish struct, w0/w1 in r2/r3 + w2..w9 on stack (AAPCS split, same as clf_27)..\n'),
    ),
    dict(
        name='clf_27',
        method='ClownFish -[remoteUpdate:]',
        types='v12@0:4@8',
        start=7926040,
        end=7926632,
        disasm='disasm_worldtileloader_clf_27.txt',
        base_add=7926056,
        base_literal=7926628,
        boundary='ARM.exidx end 0x0078f368 (listing bound); next ObjC IMP 0x0078f368 ClownFish -[remoteCreationDataUpdate:]',
        selectors={
                 0x78f338: (15209288, 'remoteUpdate:'),
                 0x78f344: (15209292, 'getBytes:length:'),
                 0x78f34c: (15209296, 'doRemoteUpdate:'),
                 0x78f358: (15209284, 'isClient'),
        },
        imports={
                 0x78f334: (17151900, 'objc_msgSendSuper2'),
                 0x78f354: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x78f340: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0x78f350: (17160072, 'OBJC_IVAR_$_ClownFish.travelFraction', 256),
                 0x78f35c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x78f360: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
        },
        classes={
                 0x78f33c: (15252792, 'OBJC_CLASS_$_ClownFish'),
        },
        instructions=[(7926040, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7926628, 'addeq r0, sp, r4, asr 19')],
        calls=[(7926132, 'blx lr'), (7926212, 'bl loc.imp.objc_msgSend'), (7926400, 'bl loc.imp.objc_msgSend'), (7926520, 'blx r2')],
        branches=[(7926168, 'bne', 7926408), (7926404, 'b', 7926572), (7926456, 'bpl', 7926568), (7926532, 'bne', 7926568), (7926568, 'b', 7926572)],
        semantics=('[ClownFish -[remoteUpdate:]] (imp 0x0078f118, 148w): -[remoteUpdate:] (0x78f118, 148w): [super remoteUpdate:data] (msgSendSuper2); dead-path identical to clf_26 (travelFraction<1.0 && !isClient -> needsRemoved=0); else buf[0x28]; [data getBytes:buf length:0x28]; [self doRemoteUpdate:buf] (same w0..w9 split). The wire update blob is exactly the 0x28B ClownFishUpdateNetData..\n'),
    ),
    dict(
        name='clf_28',
        method='ClownFish -[renderPos]',
        types='{Vector2=[2f]}8@0:4',
        start=7977720,
        end=7977852,
        disasm='disasm_worldtileloader_clf_28.txt',
        base_add=7977752,
        base_literal=7977844,
        boundary='ARM.exidx end 0x0079bb7c (listing bound); next ObjC IMP 0x0079bb7c ClownFish -[setNeedsRemoved:]',
        selectors={},
        imports={},
        ivars={
                 0x79bb70: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x79bb78: (17160152, 'OBJC_IVAR_$_ClownFish.xOffset', 292),
        },
        classes={},
        instructions=[(7977720, 'push {fp, lr}'), (7977848, 'invalid')],
        calls=[(7977808, 'bl method.Vector2.Vector2_float__float_'), (7977828, 'bl method.Vector2.operator_Vector2_')],
        branches=[],
        semantics=('[ClownFish -[renderPos]] (imp 0x0079baf8, 33w): -[renderPos] (0x79baf8, 33w): return self.floatPos@24 + Vector2(self.xOffset@292, 0.0f) (Vector2 ctor + operator+ via sret; struct-return). Horizontal bob only..\n'),
    ),
    dict(
        name='clf_29',
        method='ClownFish -[ridableWhenTamed]',
        types='c8@0:4',
        start=7978748,
        end=7978776,
        disasm='disasm_worldtileloader_clf_29.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0079bf18 (listing bound); next ObjC IMP 0x0079bf18 ClownFish -[reactToBeingFed]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7978748, 'sub sp, sp, 8'), (7978772, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[ClownFish -[ridableWhenTamed]] (imp 0x0079befc, 7w): -[ridableWhenTamed] (0x79befc, 7w): return 0 (sxtb)..\n'),
    ),
    dict(
        name='clf_30',
        method='ClownFish -[setNeedsRemoved:]',
        types='v12@0:4c8',
        start=7977852,
        end=7978108,
        disasm='disasm_worldtileloader_clf_30.txt',
        base_add=7977868,
        base_literal=7978104,
        boundary='ARM.exidx end 0x0079bc7c (listing bound); next ObjC IMP 0x0079bc7c ClownFish -[remoteBlockheadHookedYou:]',
        selectors={
                 0x79bc64: (15209468, 'setNeedsRemoved:'),
                 0x79bc74: (15209276, 'autorelease'),
        },
        imports={
                 0x79bc60: (17151900, 'objc_msgSendSuper2'),
                 0x79bc70: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x79bc6c: (17160104, 'OBJC_IVAR_$_ClownFish.hookedFishingRod', 312),
        },
        classes={
                 0x79bc68: (15252792, 'OBJC_CLASS_$_ClownFish'),
        },
        instructions=[(7977852, 'push {r4, r5, fp, lr}'), (7978104, 'addeq r3, ip, r0, ror 30')],
        calls=[(7977968, 'blx lr'), (7978040, 'blx r3')],
        branches=[],
        semantics=('[ClownFish -[setNeedsRemoved:]] (imp 0x0079bb7c, 64w): -[setNeedsRemoved:] (0x79bb7c, 64w): [super setNeedsRemoved:flag] (msgSendSuper2, flag sxtb\'d); then [self.hookedFishingRod autorelease]; self.hookedFishingRod = nil..\n'),
    ),
    dict(
        name='clf_31',
        method='ClownFish -[speciesName]',
        types='@8@0:4',
        start=7918456,
        end=7918504,
        disasm='disasm_worldtileloader_clf_31.txt',
        base_add=7918464,
        base_literal=7918500,
        boundary='ARM.exidx end 0x0078d448; body trimmed at the next IMP 0x0078d3a8 ClownFish -[foodItemType]',
        selectors={},
        imports={
                 0x78d3a0: (16319240, '__CFConstantStringClassReference'),
        },
        ivars={},
        classes={},
        instructions=[(7918456, 'sub sp, sp, 8'), (7918500, 'addeq r2, sp, ip, ror 14')],
        calls=[],
        branches=[],
        semantics=('[ClownFish -[speciesName]] (imp 0x0078d378, 12w): -[speciesName] (0x78d378, 12w, TRIMMED at next IMP): CFString obj 0xF90308 = "FISH" (len 4, cstr 0xF55D7E, flags 0x7c8)..\n'),
    ),
    dict(
        name='clf_32',
        method='ClownFish -[tapIsWithinBodyRadius:]',
        types='c16@0:4{Vector2=[2f]}8',
        start=7975936,
        end=7977020,
        disasm='disasm_worldtileloader_clf_32.txt',
        base_add=7975952,
        base_literal=7977016,
        boundary='ARM.exidx end 0x0079b96c; body trimmed at the next IMP 0x0079b83c ClownFish -[reactToBeingHit]',
        selectors={
                 0x79b828: (15209300, 'worldWidthMacro'),
        },
        imports={},
        ivars={
                 0x79b818: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0x79b81c: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x79b824: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(7975936, 'push {fp, lr}'), (7977016, 'ldrdeq r4, r5, [ip], ip')],
        calls=[(7976044, 'bl method.Vector2.operator_float__'), (7976088, 'bl method.Vector2.operator_float__'), (7976140, 'bl loc.imp.objc_msgSend'), (7976164, 'bl sym.imp.__aeabi_idiv'), (7976208, 'bl method.Vector2.operator_float__'), (7976252, 'bl method.Vector2.operator_float__'), (7976304, 'bl loc.imp.objc_msgSend'), (7976368, 'bl method.Vector2.operator_float__'), (7976412, 'bl method.Vector2.operator_float__'), (7976464, 'bl loc.imp.objc_msgSend'), (7976480, 'bl sym.imp.__aeabi_idiv'), (7976524, 'bl method.Vector2.operator_float__'), (7976568, 'bl method.Vector2.operator_float__'), (7976620, 'bl loc.imp.objc_msgSend'), (7976664, 'bl method.Vector2.operator_float__'), (7976700, 'bl method.Vector2.operator_float__'), (7976788, 'bl method.Vector2.operator_float__'), (7976828, 'bl method.Vector2.operator_float__'), (7976872, 'bl method.Vector2.operator_float__'), (7976912, 'bl method.Vector2.operator_float__')],
        branches=[(7976004, 'beq', 7976020), (7976016, 'b', 7976972), (7976188, 'blt', 7976344), (7976340, 'b', 7976728), (7976504, 'bpl', 7976660), (7976656, 'b', 7976720), (7976756, 'bpl', 7976964), (7976780, 'ble', 7976964), (7976864, 'ble', 7976964), (7976948, 'bpl', 7976964), (7976960, 'b', 7976972)],
        semantics=('[ClownFish -[tapIsWithinBodyRadius:]] (imp 0x0079b400, 271w): -[tapIsWithinBodyRadius:] (0x79b400, 271w): if (self.dead@56) return NO. dx = pt.x - floatPos.x toroidally wrapped into [-W/2, W/2) with W = [world worldWidthMacro]*32 (divisor 2 [sp,0x88c], idiv). YES iff -0.5 < dx < 0.5 (strict; gl d1 #96=0.5, d0 #224=-0.5) AND floatPos.y < pt.y < floatPos.y + 1.0 (dy window (0, 1.0); the f64 fpy+0.5+0.5 chain cancels/accumulates to +1.0 relative to floatPos.y). Mirrors Scorpion sc_40 shape (its constants identical)..\n'),
    ),
    dict(
        name='clf_33',
        method='ClownFish -[updateNetDataForClient:]',
        types='@12@0:4@8',
        start=7924568,
        end=7924804,
        disasm='disasm_worldtileloader_clf_33.txt',
        base_add=7924584,
        base_literal=7924800,
        boundary='ARM.exidx end 0x0078ec44 (listing bound); next ObjC IMP 0x0078ec44 ClownFish -[dealloc]',
        selectors={
                 0x78ec30: (15209260, 'clownFishUpdateNetDataForClient:'),
                 0x78ec38: (15209264, 'dataWithBytes:length:'),
        },
        imports={
                 0x78ec34: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0x78ec3c: (15247012, 'OBJC_CLASS_$_NSData'),
        },
        instructions=[(7924568, 'push {fp, lr}'), (7924800, 'addeq r0, sp, r4, lsl 31')],
        calls=[(7924664, 'bl loc.imp.objc_msgSend_stret'), (7924700, 'bl sym.imp.memset'), (7924764, 'blx ip')],
        branches=[(7924644, 'beq', 7924672), (7924668, 'b', 7924704)],
        semantics=('[ClownFish -[updateNetDataForClient:]] (imp 0x0078eb58, 59w): -[updateNetDataForClient:] (0x78eb58, 59w): return [NSData dataWithBytes:stret([self clownFishUpdateNetDataForClient:arg]) length:0x28] (self==0 -> memset 0x28; wraps the 0x28B fish update struct)..\n'),
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
        'batch': 'ClownFish (E144): the clownfish animal; 34 bodies',
        'claim': ('the clownfish animal (water AI tick, fishing-rod hook, remote update queue)'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'clownfish.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale clownfish.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
