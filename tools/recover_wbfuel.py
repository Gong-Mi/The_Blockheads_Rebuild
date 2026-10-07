#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The electricity line: the Workbench fuel/craft-status cluster: the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 1684 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/WORKBENCH_FUEL.md for the prose and boundaries.
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
    'bl 0xae3c5c': 0x00ae3c5c,
    'bl 0xafe458': 0x00afe458,
    'bl 0xb01800': 0x00b01800,
    'bl 0xb018f8': 0x00b018f8,
    'bl 0xb01a84': 0x00b01a84,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector.Vector_float__float__float__float_': 0x004d0d08,
    'bl method.Vector.operator_Vector_': 0x004d6538,
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_': 0x00a197b4,
}

SPECS = [
    dict(
        name='wf_updatehasfuel',
        method='Workbench -[updateHasFuel]',
        types='v8@0:4',
        start=11459416,
        end=11461128,
        disasm='disasm_worldtileloader_wf_updatehasfuel.txt',
        base_add=11459432,
        base_literal=11461120,
        boundary='ARM.exidx end 0x00aee208 (listing bound); next ObjC IMP 0x00aee208 Workbench -[combinedLightForSolarPanelWithFullSunlight]',
        selectors={
                 0xaee1b4: (15228700, 'removeFromMacroBlock'),
                 0xaee1b8: (15228704, 'release'),
                 0xaee1c0: (15228712, 'alloc'),
                 0xaee1d4: (15228716, 'initWithWorld:dynamicWorld:atPosition:cache:parentObject:colorR:colorG:colorB:heat:radius:lightDirection:'),
                 0xaee1d8: (15228872, 'objectType'),
                 0xaee1dc: (15228876, 'dynamicWorldChangedAtPos:objectType:'),
                 0xaee1e0: (15228680, 'macroTiles'),
        },
        imports={
                 0xaee1f4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xaee1a4: (17165368, 'OBJC_IVAR_$_Workbench.hasFuel', 220),
                 0xaee1a8: (17165376, 'OBJC_IVAR_$_Workbench.fuelFraction', 212),
                 0xaee1ac: (17165372, 'OBJC_IVAR_$_Workbench.light', 100),
                 0xaee1c4: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xaee1c8: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xaee1cc: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xaee1d0: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0xaee1e4: (17165352, 'OBJC_IVAR_$_Workbench.requiresFuel', 221),
                 0xaee1e8: (17165364, 'OBJC_IVAR_$_Workbench.fuelCounter', 216),
                 0xaee1ec: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xaee1f0: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
        },
        classes={
                 0xaee1bc: (15249616, 'OBJC_CLASS_$_ArtificialLight'),
        },
        instructions=[(11459416, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11459476, 'beq 0xaedf04'), (11459520, 'bpl 0xaedf04'), (11459616, 'strb r2, [r3]'), (11459900, 'bl loc.imp.objc_msgSend'), (11461124, 'andeq r0, r0, r0')],
        calls=[(11459776, 'blx ip'), (11459812, 'blx r3'), (11459900, 'bl loc.imp.objc_msgSend'), (11460092, 'bl loc.imp.objc_msgSend'), (11460172, 'bl loc.imp.objc_msgSend'), (11460216, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_'), (11460304, 'bl loc.imp.objc_msgSend'), (11460340, 'bl loc.imp.objc_msgSend'), (11460480, 'bl loc.imp.objc_msgSend'), (11460512, 'bl loc.imp.objc_msgSend'), (11460560, 'bl loc.imp.objc_msgSend'), (11460768, 'bl loc.imp.objc_msgSend'), (11460872, 'bl loc.imp.objc_msgSend'), (11460908, 'bl loc.imp.objc_msgSend'), (11460968, 'bl loc.imp.objc_msgSend'), (11461012, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_')],
        branches=[(11459476, 'beq', 11460356), (11459520, 'bpl', 11460356), (11459644, 'beq', 11460224), (11459680, 'bne', 11460224), (11459864, 'bne', 11460220), (11460220, 'b', 11460224), (11460344, 'b', 11461020), (11460388, 'bne', 11461016), (11460428, 'ble', 11461016), (11461016, 'b', 11461020)],
        semantics=('[Workbench updateHasFuel] (imp 0x00aedb58, 428w): the fuel-state refresh - the fffff144 flag gate (`ldrsb; cmp 0; beq` exits @0xaedb94) + the **fffff14c float compare** (`vcmpe.f32 s2, s0; bpl` @0xaedbc0: the fuel fraction vs threshold); the empty path clears the byte (`strb r2=0` @0xaedc20) and the cancel chain runs: the ffffcacc gate (@0xaedc60), the fffff120 type read, fffff148 + the **ffe26428/2c/34 objc** trio (the cancel-crafting notify @0xaedcc0-0xaedd3c) with the `cmp r0, 3` gate (@0xaedd14).\n'),
    ),
    dict(
        name='wf_hurry',
        method='Workbench -[hurryCompletion:]',
        types='v12@0:4i8',
        start=11457880,
        end=11459416,
        disasm='disasm_worldtileloader_wf_hurry.txt',
        base_add=11457896,
        base_literal=11459412,
        boundary='ARM.exidx end 0x00aedb58 (listing bound); next ObjC IMP 0x00aedb58 Workbench -[updateHasFuel]',
        selectors={
                 0xaedb0c: (15229068, 'play'),
                 0xaedb14: (15229064, 'multiSoundNamed:'),
                 0xaedb18: (15228960, 'instance'),
                 0xaedb38: (15228872, 'objectType'),
                 0xaedb3c: (15228876, 'dynamicWorldChangedAtPos:objectType:'),
                 0xaedb50: (15229072, 'addParticleAtPos:velocity:color:gravityType:life:scale:center:'),
        },
        imports={
                 0xaedb08: (17151904, 'objc_msgSend'),
                 0xaedb10: (16366744, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xaedb00: (17165404, 'OBJC_IVAR_$_Workbench.hurrying', 200),
                 0xaedb04: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xaedb20: (17165416, 'OBJC_IVAR_$_Workbench.craftProgressCount', 188),
                 0xaedb28: (17165408, 'OBJC_IVAR_$_Workbench.hurrySeconds', 196),
                 0xaedb2c: (17165412, 'OBJC_IVAR_$_Workbench.hurryTimer', 192),
                 0xaedb30: (17165400, 'OBJC_IVAR_$_Workbench.hurryCost', 204),
                 0xaedb34: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={
                 0xaedb1c: (15249668, 'OBJC_CLASS_$_MJSoundManager'),
                 0xaedb44: (15249672, 'OBJC_CLASS_$_ParticleEmitter'),
        },
        instructions=[(11457880, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11457944, 'bne 0xaedae8'), (11458108, 'strb r0, [r2, sl]'), (11459200, 'mov r0, 2'), (11459412, 'subseq r2, r7, r4, lsl 11')],
        calls=[(11458316, 'bl loc.imp.objc_msgSend'), (11458352, 'bl loc.imp.objc_msgSend'), (11458384, 'blx r3'), (11458404, 'blx r3'), (11458420, 'blx r2'), (11458504, 'bl method.Vector.Vector_float__float__float_'), (11458536, 'bl 0xae3c5c'), (11458636, 'bl method.Vector.Vector_float__float__float__float_'), (11458672, 'bl loc.imp.objc_msgSend'), (11458680, 'bl 0xae3c5c'), (11458716, 'bl 0xae3c5c'), (11458764, 'bl method.Vector.Vector_float__float__float_'), (11458804, 'bl method.Vector.operator_Vector_'), (11458808, 'bl 0xae3c5c'), (11458852, 'bl 0xae3c5c'), (11458908, 'bl method.Vector.Vector_float__float__float_'), (11458944, 'bl 0xae3c5c'), (11458984, 'bl 0xae3c5c'), (11459280, 'bl loc.imp.objc_msgSend')],
        branches=[(11457944, 'bne', 11459304), (11458532, 'bge', 11459300), (11459296, 'b', 11458524), (11459300, 'b', 11459304)],
        semantics=('[Workbench hurryCompletion:] (imp 0x00aed558, 384w): the time-crystal speed-up - the **fffff168 gate** (`ldrsb; cmp 0; bne` @0xaed598: already hurrying exits); the busy/flag stores (`movw r0,1; strb r0` @0xaed63c + the fffff170/16c/164 stores + ffffc8b4/c89c walk) and the ffe264d4/d8 + ffe2652c/594/598/59c notifies; the time interpolation runs the `vcvt.f32.s32; vdiv.f32; vsub.f32/vadd.f32; vmul.f32` chains over the fff3c1a4 record (@0xaed900-0xaed9c4) with Vector(float,float,float) position math and the arg frame (`mov r0, 2` @0xaeda80) - the E58-style sound/crystal emitter costs.\n'),
    ),
    dict(
        name='wf_addfuel',
        method='Workbench -[addToFuel:]',
        types='v12@0:4i8',
        start=11526036,
        end=11526940,
        disasm='disasm_worldtileloader_wf_addfuel.txt',
        base_add=11526052,
        base_literal=11526936,
        boundary='ARM.exidx end 0x00afe31c (listing bound); next ObjC IMP 0x00afe31c Workbench -[hasRequiredFuel]',
        selectors={
                 0xafe2e4: (15229088, 'updateHasFuel'),
                 0xafe2f0: (15228960, 'instance'),
                 0xafe2f4: (15229064, 'multiSoundNamed:'),
                 0xafe300: (15229156, 'playAtPosition:'),
                 0xafe30c: (15228872, 'objectType'),
                 0xafe310: (15228876, 'dynamicWorldChangedAtPos:objectType:'),
        },
        imports={
                 0xafe2f8: (16366984, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xafe2d0: (17165352, 'OBJC_IVAR_$_Workbench.requiresFuel', 221),
                 0xafe2d4: (17165376, 'OBJC_IVAR_$_Workbench.fuelFraction', 212),
                 0xafe2dc: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xafe2e0: (17165380, 'OBJC_IVAR_$_Workbench.availableElectricity', 222),
                 0xafe2fc: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xafe304: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xafe308: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={
                 0xafe2ec: (15249668, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(11526036, 'push {fp, lr}'), (11526132, 'vmov s4, r3'), (11526160, 'vadd.f32 s2, s4, s2'), (11526344, 'cmp r0, 0x64'), (11526532, 'strh r0, [r1]'), (11526936, 'subseq r1, r6, r8, asr 22')],
        calls=[(11526572, 'bl loc.imp.objc_msgSend'), (11526596, 'bl loc.imp.objc_msgSend'), (11526620, 'bl loc.imp.objc_msgSend'), (11526692, 'bl method.Vector2.Vector2_float__float_'), (11526720, 'bl loc.imp.objc_msgSend'), (11526816, 'bl loc.imp.objc_msgSend'), (11526852, 'bl loc.imp.objc_msgSend')],
        branches=[(11526100, 'beq', 11526856), (11526196, 'ble', 11526240), (11526272, 'bne', 11526548), (11526312, 'ble', 11526544), (11526348, 'bge', 11526544), (11526352, 'b', 11526356), (11526400, 'ble', 11526448), (11526456, 'beq', 11526540), (11526536, 'b', 11526356), (11526540, 'b', 11526544), (11526544, 'b', 11526548)],
        semantics=('[Workbench addToFuel:] (imp 0x00afdf94, 226w): THE fuel addition - the fffff134 gate (@0xafdfd4); the fraction math (`vcvt.f32.s32; vmul.f32; vadd.f32` @0xafdff8-0xafe010 = fuel += amount x multiplier) with the `vcmpe; ble` bound; **type == 0xf (15)** enters the furnace arm: the **u16 fuel counter read (`ldrh` fffff150 @0xafe0c4) compared with `0x64` (100 = the fuel cap!)** (`cmp r0, 0x64; bge` @0xafe0c8), the guard booleanized (`movlt 1` @0xafe128), then **`add r0, r3, r0; strh r0, [r1]`** (@0xafe180-0xafe184) adds the units - the same u16 store cell as the electricity charge (E75), per-type semantics (furnace fuel cap 100 vs battery charge 8192).\n'),
    ),
    dict(
        name='wf_addfuelitem',
        method='Workbench -[addToFuelForItem:]',
        types='v12@0:4i8',
        start=11540928,
        end=11541124,
        disasm='disasm_worldtileloader_wf_addfuelitem.txt',
        base_add=11540944,
        base_literal=11541120,
        boundary='ARM.exidx end 0x00b01a84 (listing bound); next ObjC IMP 0x00b01bd4 Workbench -[isStorageDevice]',
        selectors={
                 0xb01a74: (15229296, 'addToFuel:'),
        },
        imports={
                 0xb01a70: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xb01a78: (17165348, 'OBJC_IVAR_$_Workbench.level', 176),
                 0xb01a7c: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
        },
        classes={},
        instructions=[(11540928, 'push {fp, lr}'), (11541120, 'subseq lr, r5, ip, lsl r1')],
        calls=[(11541036, 'bl 0xb01a84'), (11541092, 'blx r3')],
        branches=[],
        semantics=("[Workbench addToFuelForItem:] (imp 0x00b019c0, 49w): the per-item fuel add - the type cell fffff120 + the fffff130 chain gate the item's dataA/dataB fuel value (the item identifies itself; the amount maps to the same u16 store as addToFuel:).\n"),
    ),
    dict(
        name='wf_startfuel',
        method='Workbench -[startManagingFuelWithBlockhead:]',
        types='v12@0:4@8',
        start=11520124,
        end=11520764,
        disasm='disasm_worldtileloader_wf_startfuel.txt',
        base_add=11520140,
        base_literal=11520760,
        boundary='ARM.exidx end 0x00afcafc (listing bound); next ObjC IMP 0x00afcafc Workbench -[requiresHumanInteraction]',
        selectors={
                 0xafcad0: (15229240, 'stopInteracting'),
                 0xafcad4: (15228848, 'retain'),
                 0xafcad8: (15228704, 'release'),
                 0xafcae4: (15228812, 'setInteractionWorkbench:'),
                 0xafcaf0: (15228872, 'objectType'),
                 0xafcaf4: (15228876, 'dynamicWorldChangedAtPos:objectType:'),
        },
        imports={
                 0xafcacc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xafcac4: (17165396, 'OBJC_IVAR_$_Workbench.isInUseFuel', 112),
                 0xafcac8: (17165444, 'OBJC_IVAR_$_Workbench.currentFuelBlockhead', 108),
                 0xafcadc: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xafcae8: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xafcaec: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={},
        instructions=[(11520124, 'push {r4, r5, fp, lr}'), (11520188, 'beq 0xafc928'), (11520228, 'beq 0xafc928'), (11520308, 'movw r2, 1'), (11520760, 'subseq r3, r6, r0, ror 4')],
        calls=[(11520292, 'blx r2'), (11520440, 'blx r2'), (11520460, 'blx r2'), (11520560, 'bl loc.imp.objc_msgSend'), (11520636, 'bl loc.imp.objc_msgSend'), (11520672, 'bl loc.imp.objc_msgSend')],
        branches=[(11520188, 'beq', 11520296), (11520228, 'beq', 11520296), (11520360, 'beq', 11520484)],
        semantics=('[Workbench startManagingFuelWithBlockhead:] (imp 0x00afc87c, 160w): the fuel-manager handover - the **fffff160 flag** gate (@0xafc8bc) + the **fffff190 managing-blockhead compare** (`cmp r0, r2; beq` @0xafc8e4: the same blockhead exits) + the ffe26644 notify (@0xafc924); the managing flag + owner are set (`movw r2, 1` @0xafc934).\n'),
    ),
    dict(
        name='wf_totalleft',
        method='Workbench -[totalItemsLeftToCraft]',
        types='i8@0:4',
        start=11457304,
        end=11457880,
        disasm='disasm_worldtileloader_wf_totalleft.txt',
        base_add=11457320,
        base_literal=11457608,
        boundary='ARM.exidx end 0x00aed558 (listing bound); next ObjC IMP 0x00aed44c Workbench -[currentlyCraftingItemType]',
        selectors={
                 0xaed43c: (15228780, 'craftableItem'),
                 0xaed54c: (15228780, 'craftableItem'),
        },
        imports={},
        ivars={
                 0xaed434: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0xaed438: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0xaed440: (17165428, 'OBJC_IVAR_$_Workbench.craftingItemObject', 180),
                 0xaed444: (17165436, 'OBJC_IVAR_$_Workbench.countLeft', 232),
                 0xaed544: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0xaed548: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0xaed550: (17165428, 'OBJC_IVAR_$_Workbench.craftingItemObject', 180),
        },
        classes={},
        instructions=[(11457304, 'push {fp, lr}'), (11457364, 'beq 0xaed420'), (11457496, 'add r0, sp, 0x18'), (11457876, 'invalid')],
        calls=[(11457508, 'bl loc.imp.objc_msgSend_stret'), (11457544, 'bl sym.imp.memset'), (11457788, 'bl loc.imp.objc_msgSend_stret'), (11457824, 'bl sym.imp.memset')],
        branches=[(11457364, 'beq', 11457568), (11457404, 'beq', 11457568), (11457492, 'beq', 11457516), (11457512, 'b', 11457548), (11457564, 'b', 11457576), (11457672, 'beq', 11457840), (11457712, 'beq', 11457840), (11457772, 'beq', 11457796), (11457792, 'b', 11457828), (11457836, 'b', 11457848)],
        semantics=('[Workbench totalItemsLeftToCraft] (imp 0x00aed318, 144w): the craft-record stret - the ffffcffd8/cffd0 gates (@0xaed354/0xaed37c) guard the record read; the fffff180/188 cells thread the crafting state; the objc_msgSend_stret fetches the record (@0xaed3d8+) - the remaining-items count of the active craft.\n'),
    ),
    dict(
        name='wf_fuelitems',
        method='Workbench -[fuelItems]',
        types='^i8@0:4',
        start=11540628,
        end=11540728,
        disasm='disasm_worldtileloader_wf_fuelitems.txt',
        base_add=11540644,
        base_literal=11540724,
        boundary='ARM.exidx end 0x00b018f8 (listing bound); next ObjC IMP 0x00b019c0 Workbench -[addToFuelForItem:]',
        selectors={},
        imports={},
        ivars={
                 0xb018ec: (17165348, 'OBJC_IVAR_$_Workbench.level', 176),
                 0xb018f0: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
        },
        classes={},
        instructions=[(11540628, 'push {fp, lr}'), (11540724, 'subseq lr, r5, r8, asr 4')],
        calls=[(11540704, 'bl 0xb018f8')],
        branches=[],
        semantics=('[Workbench fuelItems] (imp 0x00b01894, 25w): the type-keyed fuel items table read (fffff130 cell + type cell fffff120).\n'),
    ),
    dict(
        name='wf_crafttype',
        method='Workbench -[currentlyCraftingItemType]',
        types='i8@0:4',
        start=11457612,
        end=11457880,
        disasm='disasm_worldtileloader_wf_crafttype.txt',
        base_add=11457628,
        base_literal=11457876,
        boundary='ARM.exidx end 0x00aed558 (listing bound); next ObjC IMP 0x00aed558 Workbench -[hurryCompletion:]',
        selectors={
                 0xaed54c: (15228780, 'craftableItem'),
        },
        imports={},
        ivars={
                 0xaed544: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0xaed548: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0xaed550: (17165428, 'OBJC_IVAR_$_Workbench.craftingItemObject', 180),
        },
        classes={},
        instructions=[(11457612, 'push {fp, lr}'), (11457800, 'movw r2, 0x7c'), (11457876, 'invalid')],
        calls=[(11457788, 'bl loc.imp.objc_msgSend_stret'), (11457824, 'bl sym.imp.memset')],
        branches=[(11457672, 'beq', 11457840), (11457712, 'beq', 11457840), (11457772, 'beq', 11457796), (11457792, 'b', 11457828), (11457836, 'b', 11457848)],
        semantics=('[Workbench currentlyCraftingItemType] (imp 0x00aed44c, 67w): the same stret shape with the **0x7c (124)-byte record nil-fill** (`movw r2, 0x7c; memset` @0xaed508-0xaed51c) - the crafting record is 124 bytes; the type comes from the fffff180 state.\n'),
    ),
    dict(
        name='wf_fuelitemcount',
        method='Workbench -[fuelItemCount]',
        types='i8@0:4',
        start=11540380,
        end=11540480,
        disasm='disasm_worldtileloader_wf_fuelitemcount.txt',
        base_add=11540396,
        base_literal=11540476,
        boundary='ARM.exidx end 0x00b01800 (listing bound); next ObjC IMP 0x00b01894 Workbench -[fuelItems]',
        selectors={},
        imports={},
        ivars={
                 0xb017f4: (17165348, 'OBJC_IVAR_$_Workbench.level', 176),
                 0xb017f8: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
        },
        classes={},
        instructions=[(11540380, 'push {fp, lr}'), (11540476, 'subseq lr, r5, r0, asr 6')],
        calls=[(11540456, 'bl 0xb01800')],
        branches=[],
        semantics=('[Workbench fuelItemCount] (imp 0x00b0179c, 25w): the type-keyed count (the fffff130 chain adds the type-specific offset then loads the count).\n'),
    ),
    dict(
        name='wf_hasreqfuel',
        method='Workbench -[hasRequiredFuel]',
        types='c8@0:4',
        start=11526940,
        end=11527180,
        disasm='disasm_worldtileloader_wf_hasreqfuel.txt',
        base_add=11526948,
        base_literal=11527176,
        boundary='ARM.exidx end 0x00afe40c (listing bound); next ObjC IMP 0x00afe40c Workbench -[isDoubleHeight]',
        selectors={},
        imports={},
        ivars={
                 0xafe3f8: (17165368, 'OBJC_IVAR_$_Workbench.hasFuel', 220),
                 0xafe3fc: (17165352, 'OBJC_IVAR_$_Workbench.requiresFuel', 221),
                 0xafe400: (17165380, 'OBJC_IVAR_$_Workbench.availableElectricity', 222),
                 0xafe404: (17165344, 'OBJC_IVAR_$_Workbench.requiresElectricity', 224),
        },
        classes={},
        instructions=[(11526940, 'sub sp, sp, 0x14'), (11526992, 'bne 0xafe380'), (11527080, 'bgt 0xafe3dc'), (11527124, 'eor r0, r0, 1'), (11527176, 'subseq r1, r6, r8, asr 15')],
        calls=[],
        branches=[(11526992, 'bne', 11527040), (11527036, 'bne', 11527140), (11527080, 'bgt', 11527132)],
        semantics=('[Workbench hasRequiredFuel] (imp 0x00afe31c, 60w): the compound predicate - if the fffff144 flag is set the answer is true (@0xafe350); else the fffff134 byte + the **`ldrh` fffff150 fuel-units read with `cmp r1, 0; bgt`** (units > 0 → true @0xafe3a8) falls through to the **fffff12c flag negated with `eor r0, r0, 1`** (@0xafe3d4) - "needs no fuel" satisfies the requirement.\n'),
    ),
    dict(
        name='wf_fuelcount',
        method='Workbench -[fuelCount]',
        types='i8@0:4',
        start=11525828,
        end=11526036,
        disasm='disasm_worldtileloader_wf_fuelcount.txt',
        base_add=11525836,
        base_literal=11526032,
        boundary='ARM.exidx end 0x00afdf94 (listing bound); next ObjC IMP 0x00afdf94 Workbench -[addToFuel:]',
        selectors={},
        imports={},
        ivars={
                 0xafdf8c: (17165376, 'OBJC_IVAR_$_Workbench.fuelFraction', 212),
        },
        classes={},
        instructions=[(11525828, 'sub sp, sp, 0x28'), (11525892, 'vcvt.s32.f32 s0, s0'), (11525980, 'bge 0xafdf6c'), (11526032, 'subseq r1, r6, r0, lsr 24')],
        calls=[],
        branches=[(11525920, 'bge', 11525936), (11525932, 'b', 11525944), (11525980, 'bge', 11525996), (11525992, 'b', 11526004)],
        semantics=("[Workbench fuelCount] (imp 0x00afdec4, 52w): the same float accumulator shape as the SteamTrain's fuelCount (E70): `movw r3, 0xa` (10) + `vmul.f32; vadd.f32; vcvt.s32.f32` (@0xafdefc-0xafdf04) + the two clamp compares (@0xafdf1c/0xafdf5c) - the integer count clamped to [0, 10].\n"),
    ),
    dict(
        name='wf_doubleheight',
        method='Workbench -[isDoubleHeight]',
        types='c8@0:4',
        start=11527180,
        end=11527256,
        disasm='disasm_worldtileloader_wf_doubleheight.txt',
        base_add=11527196,
        base_literal=11527252,
        boundary='ARM.exidx end 0x00afe458 (listing bound); next ObjC IMP 0x00afe4c4 Workbench -[setNeedsRemoved:]',
        selectors={},
        imports={},
        ivars={
                 0xafe450: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
        },
        classes={},
        instructions=[(11527180, 'push {fp, lr}'), (11527236, 'sxtb r0, r0'), (11527252, 'ldrsbeq r1, [r6], -0x60')],
        calls=[(11527232, 'bl 0xafe458')],
        branches=[],
        semantics=('[Workbench isDoubleHeight] (imp 0x00afe40c, 19w): reads the type cell (fffff120) and delegates to the type-class helper 0xafe458 (`bl; sxtb` @0xafe440-0xafe444) - which workbench variants are double-height.\n'),
    ),
    dict(
        name='wf_frac',
        method='Workbench -[fractionComplete]',
        types='f8@0:4',
        start=11527740,
        end=11527804,
        disasm='disasm_worldtileloader_wf_frac.txt',
        base_add=11527764,
        base_literal=11527800,
        boundary='ARM.exidx end 0x00afe67c (listing bound); next ObjC IMP 0x00afe67c Workbench -[requiresPhysicalBlock]',
        selectors={},
        imports={},
        ivars={
                 0xafe674: (17165460, 'OBJC_IVAR_$_Workbench.fractionComplete', 264),
        },
        classes={},
        instructions=[(11527740, 'sub sp, sp, 8'), (11527800, 'invalid')],
        calls=[],
        branches=[],
        semantics=('[Workbench fractionComplete] (imp 0x00afe63c, 16w): the **u16 craft-progress read** through the **fffff1a0** cell (`ldrh`-adjacent halfword access) - craft progress is a u16 like the fuel/charge store.\n'),
    ),
    dict(
        name='wf_reqhuman',
        method='Workbench -[requiresHumanInteraction]',
        types='c8@0:4',
        start=11520764,
        end=11520824,
        disasm='disasm_worldtileloader_wf_reqhuman.txt',
        base_add=11520772,
        base_literal=11520820,
        boundary='ARM.exidx end 0x00afcb38 (listing bound); next ObjC IMP 0x00afcb38 Workbench -[worldChanged:]',
        selectors={},
        imports={},
        ivars={
                 0xafcb30: (17165396, 'OBJC_IVAR_$_Workbench.isInUseFuel', 112),
        },
        classes={},
        instructions=[(11520764, 'sub sp, sp, 8'), (11520820, 'subseq r2, r6, r8, ror 31')],
        calls=[],
        branches=[],
        semantics=('[Workbench requiresHumanInteraction] (imp 0x00afcafc, 15w): `ldrsb` of the **fffff160** flag - whether this workbench variant needs a blockhead at the controls.\n'),
    ),
    dict(
        name='wf_candismiss',
        method='Workbench -[canDismissFuelUI]',
        types='c8@0:4',
        start=11542836,
        end=11542864,
        disasm='disasm_worldtileloader_wf_candismiss.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00b02150 (listing bound); next ObjC IMP 0x00b02150 Workbench -[destroyItemType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11542836, 'sub sp, sp, 8'), (11542860, 'bx lr')],
        calls=[],
        branches=[],
        semantics=("[Workbench canDismissFuelUI] (imp 0x00b02134, 7w): returns **1** (movw r2, 1; sxtb) - unlike the SteamTrain's fuel UI (0 in E70), the workbench fuel UI can be dismissed.\n"),
    ),
    dict(
        name='wf_iobjtype',
        method='Workbench -[interactionObjectType]',
        types='S8@0:4',
        start=11443036,
        end=11443064,
        disasm='disasm_worldtileloader_wf_iobjtype.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00ae9b78 (listing bound); next ObjC IMP 0x00ae9b78 Workbench -[abortCraft]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11443036, 'sub sp, sp, 8'), (11443060, 'bx lr')],
        calls=[],
        branches=[],
        semantics=("[Workbench interactionObjectType] (imp 0x00ae9b5c, 7w): returns **1** (uxth) - the workbench's interaction-object type.\n"),
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
        'batch': 'Workbench fuel/craft-status cluster (E76): the fuel cap 100, the fraction accumulator, the manager handover, the hurry chain and the craft-record stret; 16 bodies',
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
                        default=NATIVE / 'workbench_fuel.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale workbench_fuel.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
