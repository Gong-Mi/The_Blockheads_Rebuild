#!/usr/bin/env python3
"""Hash-gated recovery of the Fire + light + temperature (E120).

The fire/light/temperature substrate lands: FireObject, ArtificialLight,
GlowBlock and the temperature C functions with the custom-rules climate presets:
50 bodies, 12812 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/HEATLINE.md for the prose and boundaries.
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
    'bl 0x674678': 0x00674678,
    'bl 0x678b70': 0x00678b70,
    'bl 0x678d58': 0x00678d58,
    'bl 0x6790f0': 0x006790f0,
    'bl 0x6796b0': 0x006796b0,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl method.std::__1::list_unsigned_int__std::__1::allocator_unsigned_int___._list__': 0x00a93160,
    'bl method.std::__1::list_unsigned_int__std::__1::allocator_unsigned_int___.pop_front__': 0x00a91d30,
    'bl method.std::__1::list_unsigned_int__std::__1::allocator_unsigned_int___.push_back_unsigned_int_': 0x00a91e48,
    'bl sym.absoluteSeasonFraction_double_': 0x00a149f8,
    'bl sym.baseTemperatureForWorldPos_intpair__float__float__float__World_': 0x00a14f28,
    'bl sym.customRulesBaseTemp_World_': 0x00a14ba0,
    'bl sym.customRulesPoleOffset_World_': 0x00a14d98,
    'bl sym.drawShaderQuad': 0x007c43dc,
    'bl sym.getWorldPosForWorldIndex_int__int__int__World_': 0x00a15518,
    'bl sym.imp._Unwind_Resume': 0x001c29c0,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__modsi3': 0x001c3020,
    'bl sym.imp.__stack_chk_fail': 0x001c28b8,
    'bl sym.imp.__wrap_calloc': 0x001c2fe4,
    'bl sym.imp.__wrap_fmodf': 0x001c3d4c,
    'bl sym.imp.__wrap_free': 0x001c2e64,
    'bl sym.imp.__wrap_glBindTexture': 0x001c2ad4,
    'bl sym.imp.__wrap_glDisable': 0x001c2c48,
    'bl sym.imp.__wrap_glEnable': 0x001c2b04,
    'bl sym.imp.__wrap_glUniform1i': 0x001c2de0,
    'bl sym.imp.__wrap_glUniformMatrix4fv': 0x001c2dd4,
    'bl sym.imp.__wrap_glUseProgram': 0x001c2d38,
    'bl sym.imp.cosf': 0x001c2b58,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.popDepthMaskState': 0x007c57ec,
    'bl sym.pushDepthMaskState': 0x007c55e4,
    'bl sym.recalculateDrawBlockLightingForTile_int__int__MacroTile__World_': 0x00a18f68,
    'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_': 0x00a197b4,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileAtWorldPosition_int__int__MacroTile__World_': 0x00a16e68,
    'bl sym.tileIsAirWaterOrSnow_Tile_': 0x00a126dc,
    'bl sym.tileIsBurnableBlock_Tile_': 0x00a140ec,
    'bl sym.tileIsBurnable_Tile__DynamicWorld__intpair_': 0x00a14180,
    'bl sym.tileIsDeadTree_Tile_': 0x00a138fc,
    'bl sym.tileIsPlant_Tile_': 0x00a13ce0,
    'bl sym.tileIsSemiTransparentSolidBlock_Tile_': 0x00a128b0,
    'bl sym.tileIsSolid_Tile_': 0x00a1179c,
    'bl sym.tileIsTree_Tile_': 0x00a13214,
    'bl sym.tileIsWater_Tile_': 0x00a11690,
    'bl sym.tileRequiresGlowBlock_Tile_': 0x00a14824,
    'bl sym.worldIndexAtWorldPosition_int__int__World_': 0x00a156a8,
}

SPECS = [
    dict(
        name='hl_00',
        method='FireObject -[initSubDerivedItems]',
        types='v8@0:4',
        start=6767628,
        end=6768248,
        disasm='disasm_worldtileloader_hl_00.txt',
        base_add=6767644,
        base_literal=6768244,
        boundary='ARM.exidx end 0x00674678 (listing bound); next ObjC IMP 0x00674688 FireObject -[objectType]',
        selectors={
                 0x674644: (15201664, 'textureNamed:'),
                 0x674654: (15201660, 'shaderNamed:attributes:uniforms:'),
                 0x674660: (15201656, 'arrayWithObjects:'),
        },
        imports={
                 0x67463c: (16262472, '__CFConstantStringClassReference'),
                 0x674640: (17151904, 'objc_msgSend'),
                 0x674650: (16262392, '__CFConstantStringClassReference'),
                 0x674658: (16262440, '__CFConstantStringClassReference'),
                 0x67465c: (16262456, '__CFConstantStringClassReference'),
                 0x674668: (16262408, '__CFConstantStringClassReference'),
                 0x67466c: (16262424, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x674638: (17157684, 'OBJC_IVAR_$_FireObject.texture', 84),
                 0x674648: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0x67464c: (17157688, 'OBJC_IVAR_$_FireObject.shader', 80),
                 0x674670: (17157692, 'OBJC_IVAR_$_FireObject.animationLoopIndex', 88),
        },
        classes={
                 0x674664: (15246004, 'OBJC_CLASS_$_NSArray'),
        },
        instructions=[(6767628, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6768244, 'ldrsbeq fp, [lr], r0')],
        calls=[(6767660, 'bl 0x674678'), (6767912, 'bl sym.imp.__modsi3'), (6768000, 'blx r4'), (6768048, 'blx lr'), (6768092, 'blx lr'), (6768152, 'blx ip')],
        branches=[],
        semantics=('[FireObject -[initSubDerivedItems]] (imp 0x0067440c, 155w): the fire\'s render setup - textureNamed:/shaderNamed: + the animationLoopIndex seed.\n'),
    ),
    dict(
        name='hl_01',
        method='FireObject -[objectType]',
        types='i8@0:4',
        start=6768264,
        end=6768292,
        disasm='disasm_worldtileloader_hl_01.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x006746a4 (listing bound); next ObjC IMP 0x006746a4 FireObject -[getLightRGB]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6768264, 'sub sp, sp, 8'), (6768288, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[FireObject -[objectType]] (imp 0x00674688, 7w): returns the object type constant 16 (FireObject).\n'),
    ),
    dict(
        name='hl_02',
        method='FireObject -[getLightRGB]',
        types='{Vector=[4f]}8@0:4',
        start=6768292,
        end=6768388,
        disasm='disasm_worldtileloader_hl_02.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00674704 (listing bound); next ObjC IMP 0x00674704 FireObject -[initWithWorld:dynamicWorld:atPosition:cache:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6768292, 'push {r4, sl, fp, lr}'), (6768384, 'addmi r0, r0, 0')],
        calls=[(6768364, 'bl method.Vector.Vector_float__float__float_')],
        branches=[],
        semantics=('[FireObject -[getLightRGB]] (imp 0x006746a4, 24w): forwards the fire\'s colour to FireObject.light lightColor.\n'),
    ),
    dict(
        name='hl_03',
        method='FireObject -[initWithWorld:dynamicWorld:atPosition:cache:]',
        types='@28@0:4@8@12{?=ii}16@24',
        start=6768388,
        end=6769396,
        disasm='disasm_worldtileloader_hl_03.txt',
        base_add=6768404,
        base_literal=6769392,
        boundary='ARM.exidx end 0x00674af4 (listing bound); next ObjC IMP 0x00674af4 FireObject -[initWithWorld:dynamicWorld:saveDict:cache:]',
        selectors={
                 0x674ab0: (15201668, 'initWithWorld:dynamicWorld:atPosition:cache:'),
                 0x674ab8: (15201684, 'initSubDerivedItems'),
                 0x674ad0: (15201672, 'alloc'),
                 0x674ae4: (15201676, 'initWithWorld:dynamicWorld:atPosition:cache:parentObject:colorR:colorG:colorB:heat:radius:lightDirection:'),
                 0x674aec: (15201680, 'macroTiles'),
        },
        imports={
                 0x674ab4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x674ac0: (17157696, 'OBJC_IVAR_$_FireObject.burnTimer', 56),
                 0x674ac8: (17157700, 'OBJC_IVAR_$_FireObject.spreadTimers', 60),
                 0x674ad4: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x674ad8: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x674adc: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x674ae0: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0x674ae8: (17157704, 'OBJC_IVAR_$_FireObject.light', 76),
        },
        classes={
                 0x674aa8: (15252636, 'OBJC_CLASS_$_FireObject'),
                 0x674acc: (15246008, 'OBJC_CLASS_$_ArtificialLight'),
        },
        instructions=[(6768388, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6769392, 'ldrsbeq fp, [lr], r8')],
        calls=[(6768564, 'bl loc.imp.objc_msgSendSuper2'), (6768608, 'bl 0x674678'), (6768692, 'bl 0x674678'), (6768752, 'bl 0x674678'), (6768804, 'bl 0x674678'), (6768856, 'bl 0x674678'), (6768932, 'bl loc.imp.objc_msgSend'), (6769128, 'bl loc.imp.objc_msgSend'), (6769208, 'bl loc.imp.objc_msgSend'), (6769252, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_'), (6769296, 'blx r2')],
        branches=[(6768592, 'bne', 6768608), (6768604, 'b', 6769308)],
        semantics=('[FireObject -[initWithWorld:dynamicWorld:atPosition:cache:]] (imp 0x00674704, 252w): the placement ctor - super + initSubDerivedItems; seeds burnTimer/spreadTimers via the PRNG (0x674678) and creates FireObject.light (the ArtificialLight with heat/radius).\n'),
    ),
    dict(
        name='hl_04',
        method='FireObject -[initWithWorld:dynamicWorld:saveDict:cache:]',
        types='@24@0:4@8@12@16@20',
        start=6769396,
        end=6770432,
        disasm='disasm_worldtileloader_hl_04.txt',
        base_add=6769412,
        base_literal=6770428,
        boundary='ARM.exidx end 0x00674f00 (listing bound); next ObjC IMP 0x00674f00 FireObject -[initWithWorld:dynamicWorld:cache:netData:]',
        selectors={
                 0x674e9c: (15201688, 'initWithWorld:dynamicWorld:saveDict:cache:'),
                 0x674ea8: (15201684, 'initSubDerivedItems'),
                 0x674eac: (15201692, 'objectForKey:'),
                 0x674eb8: (15201696, 'floatValue'),
                 0x674ed8: (15201672, 'alloc'),
                 0x674eec: (15201700, 'initWithWorld:dynamicWorld:saveDict:cache:parentObject:'),
                 0x674ef8: (15201680, 'macroTiles'),
        },
        imports={
                 0x674e98: (17151900, 'objc_msgSendSuper2'),
                 0x674ea4: (17151904, 'objc_msgSend'),
                 0x674eb4: (16262488, '__CFConstantStringClassReference'),
                 0x674ec0: (16262504, '__CFConstantStringClassReference'),
                 0x674ec8: (16262520, '__CFConstantStringClassReference'),
                 0x674ecc: (16262536, '__CFConstantStringClassReference'),
                 0x674ed0: (16262552, '__CFConstantStringClassReference'),
                 0x674ee4: (16262568, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x674ebc: (17157696, 'OBJC_IVAR_$_FireObject.burnTimer', 56),
                 0x674ec4: (17157700, 'OBJC_IVAR_$_FireObject.spreadTimers', 60),
                 0x674edc: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x674ee0: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x674ee8: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0x674ef0: (17157704, 'OBJC_IVAR_$_FireObject.light', 76),
                 0x674ef4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={
                 0x674ea0: (15252636, 'OBJC_CLASS_$_FireObject'),
                 0x674ed4: (15246008, 'OBJC_CLASS_$_ArtificialLight'),
        },
        instructions=[(6769396, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6770428, 'addseq sl, lr, r8, ror 31')],
        calls=[(6769548, 'blx r6'), (6769636, 'bl loc.imp.objc_msgSend'), (6769660, 'bl loc.imp.objc_msgSend'), (6769708, 'bl loc.imp.objc_msgSend'), (6769724, 'bl loc.imp.objc_msgSend'), (6769780, 'bl loc.imp.objc_msgSend'), (6769796, 'bl loc.imp.objc_msgSend'), (6769844, 'bl loc.imp.objc_msgSend'), (6769860, 'bl loc.imp.objc_msgSend'), (6769908, 'bl loc.imp.objc_msgSend'), (6769924, 'bl loc.imp.objc_msgSend'), (6769968, 'bl loc.imp.objc_msgSend'), (6770064, 'bl loc.imp.objc_msgSend'), (6770132, 'bl loc.imp.objc_msgSend'), (6770216, 'bl loc.imp.objc_msgSend'), (6770260, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_'), (6770304, 'blx r2')],
        branches=[(6769576, 'bne', 6769592), (6769588, 'b', 6770316)],
        semantics=('[FireObject -[initWithWorld:dynamicWorld:saveDict:cache:]] (imp 0x00674af4, 259w): the load ctor - super saveDict chain + burnTimer/spreadTimers/light restore (floatValue objectForKey:); the light via the saveDict parentObject: ctor.\n'),
    ),
    dict(
        name='hl_05',
        method='FireObject -[initWithWorld:dynamicWorld:cache:netData:]',
        types='@24@0:4@8@12@16@20',
        start=6770432,
        end=6770716,
        disasm='disasm_worldtileloader_hl_05.txt',
        base_add=6770448,
        base_literal=6770712,
        boundary='ARM.exidx end 0x0067501c (listing bound); next ObjC IMP 0x0067501c FireObject -[getSaveDict]',
        selectors={
                 0x675008: (15201704, 'initWithWorld:dynamicWorld:cache:netData:'),
                 0x675014: (15201684, 'initSubDerivedItems'),
        },
        imports={
                 0x675004: (17151900, 'objc_msgSendSuper2'),
                 0x675010: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0x67500c: (15252636, 'OBJC_CLASS_$_FireObject'),
        },
        instructions=[(6770432, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6770712, 'ldrsbeq sl, [lr], ip')],
        calls=[(6770584, 'blx r6'), (6770668, 'blx r2')],
        branches=[(6770612, 'bne', 6770628), (6770624, 'b', 6770680)],
        semantics=('[FireObject -[initWithWorld:dynamicWorld:cache:netData:]] (imp 0x00674f00, 71w): the net ctor - super cache:netData: + initSubDerivedItems.\n'),
    ),
    dict(
        name='hl_06',
        method='FireObject -[getSaveDict]',
        types='@8@0:4',
        start=6770716,
        end=6771692,
        disasm='disasm_worldtileloader_hl_06.txt',
        base_add=6770732,
        base_literal=6771688,
        boundary='ARM.exidx end 0x006753ec (listing bound); next ObjC IMP 0x006753ec FireObject -[updateNetDataForClient:]',
        selectors={
                 0x6753ac: (15201708, 'getSaveDict'),
                 0x6753c0: (15201716, 'setObject:forKey:'),
                 0x6753c4: (15201712, 'numberWithFloat:'),
        },
        imports={
                 0x6753a8: (17151900, 'objc_msgSendSuper2'),
                 0x6753b4: (17151904, 'objc_msgSend'),
                 0x6753bc: (16262552, '__CFConstantStringClassReference'),
                 0x6753d0: (16262536, '__CFConstantStringClassReference'),
                 0x6753d4: (16262520, '__CFConstantStringClassReference'),
                 0x6753d8: (16262504, '__CFConstantStringClassReference'),
                 0x6753dc: (16262488, '__CFConstantStringClassReference'),
                 0x6753e4: (16262568, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x6753b8: (17157704, 'OBJC_IVAR_$_FireObject.light', 76),
                 0x6753c8: (17157700, 'OBJC_IVAR_$_FireObject.spreadTimers', 60),
                 0x6753e0: (17157696, 'OBJC_IVAR_$_FireObject.burnTimer', 56),
        },
        classes={
                 0x6753b0: (15252636, 'OBJC_CLASS_$_FireObject'),
                 0x6753cc: (15246012, 'OBJC_CLASS_$_NSNumber'),
        },
        instructions=[(6770716, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6771688, 'addseq sl, lr, r0, asr 21')],
        calls=[(6770800, 'blx ip'), (6771064, 'blx r3'), (6771100, 'blx ip'), (6771160, 'blx lr'), (6771196, 'blx ip'), (6771256, 'blx lr'), (6771292, 'blx ip'), (6771352, 'blx lr'), (6771388, 'blx ip'), (6771448, 'blx lr'), (6771484, 'blx ip'), (6771520, 'blx r3'), (6771608, 'blx ip')],
        branches=[(6771540, 'beq', 6771612)],
        semantics=('[FireObject -[getSaveDict]] (imp 0x0067501c, 244w): the save serializer - burnTimer/spreadTimers/light entries (numberWithFloat:/setObject:forKey:).\n'),
    ),
    dict(
        name='hl_07',
        method='FireObject -[updateNetDataForClient:]',
        types='@12@0:4@8',
        start=6771692,
        end=6771776,
        disasm='disasm_worldtileloader_hl_07.txt',
        base_add=6771708,
        base_literal=6771772,
        boundary='ARM.exidx end 0x00675440 (listing bound); next ObjC IMP 0x00675440 FireObject -[creationNetDataForClient:]',
        selectors={
                 0x675438: (15201720, 'creationNetDataForClient:'),
        },
        imports={
                 0x675434: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(6771692, 'push {fp, lr}'), (6771772, 'ldrsheq sl, [lr], r0')],
        calls=[(6771752, 'blx ip')],
        branches=[],
        semantics=('[FireObject -[updateNetDataForClient:]] (imp 0x006753ec, 21w): the net update - forwards to creationNetDataForClient:.\n'),
    ),
    dict(
        name='hl_08',
        method='FireObject -[creationNetDataForClient:]',
        types='@12@0:4@8',
        start=6771776,
        end=6772064,
        disasm='disasm_worldtileloader_hl_08.txt',
        base_add=6771792,
        base_literal=6772060,
        boundary='ARM.exidx end 0x00675560 (listing bound); next ObjC IMP 0x00675560 FireObject -[dealloc]',
        selectors={
                 0x67554c: (15201724, 'dynamicObjectNetData'),
                 0x675554: (15201728, 'dataWithBytes:length:'),
        },
        imports={
                 0x675550: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0x675558: (15246016, 'OBJC_CLASS_$_NSData'),
        },
        instructions=[(6771776, 'push {r4, r5, fp, lr}'), (6772060, 'umullseq sl, lr, ip, r6')],
        calls=[(6771868, 'bl loc.imp.objc_msgSend_stret'), (6771904, 'bl sym.imp.memset'), (6771984, 'bl sym.imp.memcpy'), (6772024, 'blx ip')],
        branches=[(6771852, 'beq', 6771876), (6771872, 'b', 6771908)],
        semantics=('[FireObject -[creationNetDataForClient:]] (imp 0x00675440, 72w): the creation net record - dynamicObjectNetData append (dataWithBytes:length:).\n'),
    ),
    dict(
        name='hl_09',
        method='FireObject -[dealloc]',
        types='v8@0:4',
        start=6772064,
        end=6772296,
        disasm='disasm_worldtileloader_hl_09.txt',
        base_add=6772080,
        base_literal=6772292,
        boundary='ARM.exidx end 0x00675648 (listing bound); next ObjC IMP 0x00675648 FireObject -[setNeedsRemoved:]',
        selectors={
                 0x675630: (15201736, 'dealloc'),
                 0x675640: (15201732, 'release'),
        },
        imports={
                 0x67562c: (17151900, 'objc_msgSendSuper2'),
                 0x67563c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x675638: (17157704, 'OBJC_IVAR_$_FireObject.light', 76),
        },
        classes={
                 0x675634: (15252636, 'OBJC_CLASS_$_FireObject'),
        },
        instructions=[(6772064, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6772292, 'addseq sl, lr, ip, ror r5')],
        calls=[(6772192, 'blx r7'), (6772256, 'blx ip')],
        branches=[],
        semantics=('[FireObject -[dealloc]] (imp 0x00675560, 58w): releases light + super dealloc.\n'),
    ),
    dict(
        name='hl_10',
        method='FireObject -[setNeedsRemoved:]',
        types='v12@0:4c8',
        start=6772296,
        end=6772528,
        disasm='disasm_worldtileloader_hl_10.txt',
        base_add=6772312,
        base_literal=6772524,
        boundary='ARM.exidx end 0x00675730 (listing bound); next ObjC IMP 0x00675730 FireObject -[removeFromMacroBlock]',
        selectors={
                 0x675718: (15201740, 'setNeedsRemoved:'),
                 0x675724: (15201744, 'removeFromTiles'),
        },
        imports={
                 0x675714: (17151900, 'objc_msgSendSuper2'),
                 0x675720: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x675728: (17157704, 'OBJC_IVAR_$_FireObject.light', 76),
        },
        classes={
                 0x67571c: (15252636, 'OBJC_CLASS_$_FireObject'),
        },
        instructions=[(6772296, 'push {r4, r5, fp, lr}'), (6772524, 'umullseq sl, lr, r4, r4')],
        calls=[(6772412, 'blx lr'), (6772488, 'blx r2')],
        branches=[(6772424, 'beq', 6772492)],
        semantics=('[FireObject -[setNeedsRemoved:]] (imp 0x00675648, 58w): the removal setter - light removeFromTiles + super.\n'),
    ),
    dict(
        name='hl_11',
        method='FireObject -[removeFromMacroBlock]',
        types='v8@0:4',
        start=6772528,
        end=6773972,
        disasm='disasm_worldtileloader_hl_11.txt',
        base_add=6772544,
        base_literal=6773968,
        boundary='ARM.exidx end 0x00675cd4 (listing bound); next ObjC IMP 0x00675cd4 FireObject -[requiresPhysicalBlock]',
        selectors={
                 0x675c78: (15201748, 'removeFromMacroBlock'),
                 0x675c7c: (15201732, 'release'),
                 0x675c88: (15201680, 'macroTiles'),
                 0x675c90: (15201752, 'worldChangedAtPos:sendReliably:'),
                 0x675c98: (15201764, 'removePlantWithoutCreatingFreeblocks'),
                 0x675ca0: (15201760, 'getPlantAtPos:'),
                 0x675ca8: (15201756, 'removeLadderAtPos:'),
                 0x675cb0: (15201768, 'interactionObjectAtPos:'),
                 0x675cb4: (15201772, 'interactionObjectType'),
                 0x675cb8: (15201776, 'destroyItemType'),
                 0x675cc0: (15201780, 'removeInteractionObjectAtPos:removeBlockhead:'),
                 0x675cc4: (15201784, 'removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:onlyRemoveCOntents:onlyRemoveForegroundContents:'),
        },
        imports={
                 0x675c94: (17151904, 'objc_msgSend'),
                 0x675cc8: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0x675c70: (17157704, 'OBJC_IVAR_$_FireObject.light', 76),
                 0x675c80: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x675c84: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x675c8c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={
                 0x675ccc: (15252636, 'OBJC_CLASS_$_FireObject'),
        },
        instructions=[(6772528, 'push {r4, r5, r6, sl, fp, lr}'), (6773968, 'addseq sl, lr, ip, lsr 7')],
        calls=[(6772608, 'bl loc.imp.objc_msgSend'), (6772640, 'bl loc.imp.objc_msgSend'), (6772740, 'bl loc.imp.objc_msgSend'), (6772784, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_'), (6772836, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6772940, 'bl loc.imp.objc_msgSend'), (6773060, 'bl loc.imp.objc_msgSend'), (6773076, 'bl sym.tileIsPlant_Tile_'), (6773204, 'bl loc.imp.objc_msgSend'), (6773228, 'blx r2'), (6773348, 'bl loc.imp.objc_msgSend'), (6773412, 'blx r2'), (6773468, 'blx r2'), (6773576, 'bl loc.imp.objc_msgSend'), (6773596, 'bl sym.tileIsTree_Tile_'), (6773616, 'bl sym.tileIsBurnableBlock_Tile_'), (6773792, 'blx r4'), (6773860, 'blx r3')],
        branches=[(6772956, 'beq', 6773240), (6772972, 'bne', 6773072), (6773068, 'b', 6773236), (6773088, 'beq', 6773232), (6773232, 'b', 6773236), (6773236, 'b', 6773240), (6773252, 'bne', 6773592), (6773368, 'beq', 6773588), (6773424, 'bne', 6773588), (6773476, 'beq', 6773584), (6773584, 'b', 6773588), (6773588, 'b', 6773592), (6773608, 'bne', 6773632), (6773628, 'beq', 6773796)],
        semantics=('[FireObject -[removeFromMacroBlock]] (imp 0x00675730, 361w): the removal cleanup - detaches the burned neighbours (interactionObjectAtPos:/interactionObjectType/removeInteractionObjectAtPos:removeBlockhead:/removeLad.../destroyItemType/getPlantAtPos:); 361w.\n'),
    ),
    dict(
        name='hl_12',
        method='FireObject -[requiresPhysicalBlock]',
        types='c8@0:4',
        start=6773972,
        end=6774064,
        disasm='disasm_worldtileloader_hl_12.txt',
        base_add=6773980,
        base_literal=6774060,
        boundary='ARM.exidx end 0x00675d30 (listing bound); next ObjC IMP 0x00675d30 FireObject -[update:accurateDT:isSimulation:]',
        selectors={},
        imports={},
        ivars={
                 0x675d28: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
        },
        classes={},
        instructions=[(6773972, 'sub sp, sp, 0xc'), (6774060, 'addseq sb, lr, r0, lsl lr')],
        calls=[],
        branches=[(6774020, 'beq', 6774036), (6774032, 'b', 6774044)],
        semantics=('[FireObject -[requiresPhysicalBlock]] (imp 0x00675cd4, 23w): requiresPhysicalBlock = !isNet (a server-authoritative object).\n'),
    ),
    dict(
        name='hl_13',
        method='FireObject -[update:accurateDT:isSimulation:]',
        types='v20@0:4f8f12c16',
        start=6774064,
        end=6776832,
        disasm='disasm_worldtileloader_hl_13.txt',
        base_add=6774080,
        base_literal=6776828,
        boundary='ARM.exidx end 0x00676800 (listing bound); next ObjC IMP 0x00676800 FireObject -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        selectors={
                 0x6767ac: (15201680, 'macroTiles'),
                 0x6767b8: (15201740, 'setNeedsRemoved:'),
                 0x6767c4: (15201788, 'objectType'),
                 0x6767c8: (15201792, 'dynamicWorldChangedAtPos:objectType:'),
                 0x6767dc: (15201796, 'placeFireAtPosition:'),
        },
        imports={},
        ivars={
                 0x676798: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x67679c: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0x6767a0: (17157696, 'OBJC_IVAR_$_FireObject.burnTimer', 56),
                 0x6767a4: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x6767b0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x6767b4: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x6767c0: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0x6767cc: (17157700, 'OBJC_IVAR_$_FireObject.spreadTimers', 60),
        },
        classes={},
        instructions=[(6774064, 'push {r4, r5, r6, r7, fp, lr}'), (6776828, 'addseq sb, lr, ip, lsr 27')],
        calls=[(6774296, 'bl loc.imp.objc_msgSend'), (6774396, 'bl loc.imp.objc_msgSend'), (6774432, 'bl loc.imp.objc_msgSend'), (6774488, 'bl loc.imp.objc_msgSend'), (6774564, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (6774640, 'bl sym.tileIsBurnable_Tile__DynamicWorld__intpair_'), (6774692, 'bl loc.imp.objc_msgSend'), (6774792, 'bl loc.imp.objc_msgSend'), (6774828, 'bl loc.imp.objc_msgSend'), (6774908, 'bl 0x674678'), (6775048, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (6775132, 'bl sym.makeIntpair_int__int_'), (6775152, 'bl sym.tileIsBurnable_Tile__DynamicWorld__intpair_'), (6775252, 'bl sym.makeIntpair_int__int_'), (6775280, 'bl loc.imp.objc_msgSend'), (6775360, 'bl 0x674678'), (6775504, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (6775588, 'bl sym.makeIntpair_int__int_'), (6775608, 'bl sym.tileIsBurnable_Tile__DynamicWorld__intpair_'), (6775724, 'bl sym.makeIntpair_int__int_'), (6775752, 'bl loc.imp.objc_msgSend'), (6775832, 'bl 0x674678'), (6775976, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (6776060, 'bl sym.makeIntpair_int__int_'), (6776080, 'bl sym.tileIsBurnable_Tile__DynamicWorld__intpair_'), (6776196, 'bl sym.makeIntpair_int__int_'), (6776224, 'bl loc.imp.objc_msgSend'), (6776304, 'bl 0x674678'), (6776452, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (6776536, 'bl sym.makeIntpair_int__int_'), (6776556, 'bl sym.tileIsBurnable_Tile__DynamicWorld__intpair_'), (6776672, 'bl sym.makeIntpair_int__int_'), (6776700, 'bl loc.imp.objc_msgSend')],
        branches=[(6774148, 'bne', 6774188), (6774184, 'beq', 6774192), (6774188, 'b', 6776720), (6774256, 'bhi', 6774440), (6774436, 'b', 6776720), (6774652, 'bne', 6774840), (6774832, 'b', 6776716), (6774904, 'bpl', 6775292), (6775164, 'beq', 6775288), (6775288, 'b', 6775292), (6775356, 'bpl', 6775764), (6775620, 'beq', 6775760), (6775636, 'bne', 6775760), (6775760, 'b', 6775764), (6775828, 'bpl', 6776236), (6776092, 'beq', 6776232), (6776108, 'bne', 6776232), (6776232, 'b', 6776236), (6776300, 'bpl', 6776712), (6776568, 'beq', 6776708), (6776584, 'bne', 6776708), (6776708, 'b', 6776712), (6776712, 'b', 6776716), (6776716, 'b', 6776720)],
        semantics=('[FireObject -[update:accurateDT:isSimulation:]] (imp 0x00675d30, 692w): the fire tick - burnTimer -= accurateDT (expiry -> setNeedsRemoved + net dirty); the spreadTimers quad polls neighbours (at least (x, y+1)) and calls DynamicWorld placeFireAtPosition: on the burnable ones; 33 calls - census-grade, not a per-instruction walkthrough.\n'),
    ),
    dict(
        name='hl_14',
        method='FireObject -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        types='v156@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76i140i144i148i152',
        start=6776832,
        end=6785904,
        disasm='disasm_worldtileloader_hl_14.txt',
        base_add=6776860,
        base_literal=6779572,
        boundary='ARM.exidx end 0x00678b70 (listing bound); next ObjC IMP 0x00679a48 FireObject -[worldChanged:]',
        selectors={
                 0x6772c8: (15201800, 'worldWidthMacro'),
                 0x677300: (15201804, 'program'),
                 0x677308: (15201816, 'intValue'),
                 0x67730c: (15201812, 'objectAtIndex:'),
                 0x677310: (15201808, 'uniformLocations'),
                 0x677320: (15201820, 'name'),
                 0x678b54: (15201816, 'intValue'),
                 0x678b58: (15201812, 'objectAtIndex:'),
                 0x678b5c: (15201808, 'uniformLocations'),
        },
        imports={
                 0x6772fc: (17151904, 'objc_msgSend'),
                 0x678b50: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x6772b8: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0x6772bc: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x6772c4: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x6772e8: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x677304: (17157688, 'OBJC_IVAR_$_FireObject.shader', 80),
                 0x677314: (17157708, 'OBJC_IVAR_$_FireObject.animationLoopTimer', 92),
                 0x67731c: (17157692, 'OBJC_IVAR_$_FireObject.animationLoopIndex', 88),
                 0x677324: (17157684, 'OBJC_IVAR_$_FireObject.texture', 84),
                 0x678b60: (17157688, 'OBJC_IVAR_$_FireObject.shader', 80),
        },
        classes={},
        instructions=[(6776832, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6785900, 'andeq r0, r0, r0')],
        calls=[(6777552, 'bl loc.imp.objc_msgSend'), (6777576, 'bl sym.imp.__aeabi_idiv'), (6777644, 'bl loc.imp.objc_msgSend'), (6777764, 'bl loc.imp.objc_msgSend'), (6777780, 'bl sym.imp.__aeabi_idiv'), (6777848, 'bl loc.imp.objc_msgSend'), (6777972, 'bl loc.imp.objc_msgSend'), (6777996, 'bl sym.imp.__aeabi_idiv'), (6778064, 'bl loc.imp.objc_msgSend'), (6778184, 'bl loc.imp.objc_msgSend'), (6778200, 'bl sym.imp.__aeabi_idiv'), (6778268, 'bl loc.imp.objc_msgSend'), (6778532, 'bl method.Vector2.operator_float__'), (6778592, 'bl loc.imp.objc_msgSend'), (6778616, 'bl sym.imp.__aeabi_idiv'), (6778704, 'bl loc.imp.objc_msgSend'), (6778736, 'bl method.Vector2.operator_float__'), (6778784, 'bl method.Vector2.operator_float__'), (6778848, 'bl loc.imp.objc_msgSend'), (6778864, 'bl sym.imp.__aeabi_idiv'), (6778952, 'bl loc.imp.objc_msgSend'), (6778984, 'bl method.Vector2.operator_float__'), (6779080, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6779168, 'blx r2'), (6779172, 'bl sym.imp.__wrap_glUseProgram'), (6779300, 'blx r6'), (6779320, 'blx r3'), (6779336, 'blx r2'), (6779344, 'bl sym.imp.__wrap_glUniform1i'), (6779728, 'bl sym.imp.__wrap_glEnable'), (6779740, 'bl sym.pushDepthMaskState'), (6779816, 'blx r3'), (6779836, 'bl sym.imp.__wrap_glBindTexture'), (6779928, 'bl sym.imp.__modsi3'), (6779944, 'bl sym.imp.__aeabi_idiv'), (6780100, 'bl sym.tileIsSolid_Tile_'), (6780264, 'bl method.Vector2.operator_float__'), (6780292, 'bl method.Vector2.operator_float__'), (6780508, 'bl 0x678b70'), (6780836, 'bl 0x678d58'), (6781668, 'bl 0x6790f0'), (6781724, 'bl loc.imp.objc_msgSend'), (6781760, 'bl loc.imp.objc_msgSend'), (6781784, 'bl loc.imp.objc_msgSend'), (6781804, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (6781884, 'bl sym.drawShaderQuad'), (6782020, 'bl method.Vector2.operator_float__'), (6782044, 'bl method.Vector2.operator_float__'), (6782260, 'bl 0x678b70'), (6782716, 'bl 0x678d58'), (6783544, 'bl 0x6790f0'), (6783704, 'bl loc.imp.objc_msgSend'), (6783724, 'bl loc.imp.objc_msgSend'), (6783740, 'bl loc.imp.objc_msgSend'), (6783756, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (6783824, 'bl sym.drawShaderQuad'), (6783960, 'bl method.Vector2.operator_float__'), (6783976, 'bl method.Vector2.operator_float__'), (6784192, 'bl 0x678b70'), (6784648, 'bl 0x6796b0'), (6785476, 'bl 0x6790f0'), (6785632, 'bl sym.imp.memcpy'), (6785668, 'blx r3'), (6785688, 'blx r3'), (6785704, 'blx r2'), (6785736, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (6785848, 'bl sym.drawShaderQuad'), (6785856, 'bl sym.imp.__wrap_glDisable'), (6785860, 'bl sym.popDepthMaskState')],
        branches=[(6777452, 'beq', 6777460), (6777456, 'b', 6785864), (6777588, 'blt', 6777676), (6777672, 'b', 6777880), (6777792, 'bge', 6777876), (6777876, 'b', 6777880), (6778008, 'blt', 6778096), (6778092, 'b', 6778300), (6778212, 'bge', 6778296), (6778296, 'b', 6778300), (6778336, 'blt', 6778460), (6778376, 'bgt', 6778460), (6778416, 'blt', 6778460), (6778456, 'ble', 6778464), (6778460, 'b', 6785864), (6778640, 'ble', 6778760), (6778756, 'b', 6779008), (6778888, 'bpl', 6779004), (6779004, 'b', 6779008), (6779100, 'bne', 6779108), (6779104, 'b', 6785864), (6779432, 'ble', 6779724), (6779528, 'blt', 6779568), (6779568, 'b', 6779392), (6780112, 'beq', 6780128)],
        semantics=('[FireObject -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]] (imp 0x00676800, 2268w): the fire renderer - the animated flame quads (animationLoopTimer/Index, shader uniformLocations, the cloud-style draws); 2268w - census-grade, not a per-instruction walkthrough.\n'),
    ),
    dict(
        name='hl_15',
        method='FireObject -[worldChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=6789704,
        end=6789812,
        disasm='disasm_worldtileloader_hl_15.txt',
        base_add=6789720,
        base_literal=6789808,
        boundary='ARM.exidx end 0x00679ab4 (listing bound); next ObjC IMP 0x00679ab4 FireObject -[addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:]',
        selectors={
                 0x679aa8: (15201824, 'worldChanged:'),
        },
        imports={
                 0x679aa4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x679aac: (17157704, 'OBJC_IVAR_$_FireObject.light', 76),
        },
        classes={},
        instructions=[(6789704, 'push {r4, sl, fp, lr}'), (6789808, 'umullseq r6, lr, r4, r0')],
        calls=[(6789784, 'blx ip')],
        branches=[],
        semantics=('[FireObject -[worldChanged:]] (imp 0x00679a48, 27w): the world-change reaction - forwards to light worldChanged:.\n'),
    ),
    dict(
        name='hl_16',
        method='FireObject -[addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:]',
        types='v16@0:4i8i12',
        start=6789812,
        end=6789928,
        disasm='disasm_worldtileloader_hl_16.txt',
        base_add=6789828,
        base_literal=6789924,
        boundary='ARM.exidx end 0x00679b28 (listing bound); next ObjC IMP 0x00679e28 ScrollingButtonsTradePortal -[initWithFrame:cache:windowInfo:tradePortalUI:world:]',
        selectors={
                 0x679b1c: (15201828, 'addContributionForPhysicalBlockLoadedAtXPos:yPos:'),
        },
        imports={
                 0x679b18: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x679b20: (17157704, 'OBJC_IVAR_$_FireObject.light', 76),
        },
        classes={},
        instructions=[(6789812, 'push {r4, r5, fp, lr}'), (6789924, 'addseq r6, lr, r8, lsr 32')],
        calls=[(6789900, 'blx lr')],
        branches=[],
        semantics=('[FireObject -[addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:]] (imp 0x00679ab4, 29w): forwards the contribution to FireObject.light (ArtificialLight addContributionForPhysicalBlockLoadedAtXPos:yPos:).\n'),
    ),
    dict(
        name='hl_17',
        method='ArtificialLight -[recursivelyUpdateLightWithList:]',
        types='v12@0:4^{list<unsigned int, std::__1::allocator<unsigned int> >={__list_node_base<unsigned int, void *>=^{__list_node<unsigned int, void *>}^{__list_node<unsigned int, void *>}}{__compressed_pair<unsigned long, std::__1::allocator<std::__1::__list_node<unsigned int, void *> > >=L}}8',
        start=11072044,
        end=11083056,
        disasm='disasm_worldtileloader_hl_17.txt',
        base_add=11072060,
        base_literal=11075952,
        boundary='ARM.exidx end 0x00a91d30 (listing bound); next ObjC IMP 0x00a92238 ArtificialLight -[addToTiles]',
        selectors={
                 0xa9017c: (15226060, 'macroTiles'),
                 0xa90188: (15226064, 'worldWidthMacro'),
                 0xa91cf8: (15226060, 'macroTiles'),
        },
        imports={
                 0xa90178: (17151904, 'objc_msgSend'),
                 0xa91cf4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa90174: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xa90180: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa904a4: (17164820, 'OBJC_IVAR_$_ArtificialLight.contributionGridOrigin', 84),
                 0xa90554: (17164824, 'OBJC_IVAR_$_ArtificialLight.diameter', 92),
                 0xa905e4: (17164828, 'OBJC_IVAR_$_ArtificialLight.contributionGrid', 56),
                 0xa905e8: (17164832, 'OBJC_IVAR_$_ArtificialLight.radius', 80),
                 0xa905f0: (17164836, 'OBJC_IVAR_$_ArtificialLight.lightDirection', 96),
                 0xa91cf0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xa91cfc: (17164820, 'OBJC_IVAR_$_ArtificialLight.contributionGridOrigin', 84),
                 0xa91d00: (17164824, 'OBJC_IVAR_$_ArtificialLight.diameter', 92),
                 0xa91d04: (17164828, 'OBJC_IVAR_$_ArtificialLight.contributionGrid', 56),
                 0xa91d08: (17164836, 'OBJC_IVAR_$_ArtificialLight.lightDirection', 96),
                 0xa91d0c: (17164832, 'OBJC_IVAR_$_ArtificialLight.radius', 80),
        },
        classes={},
        instructions=[(11072044, 'push {r4, sl, fp, lr}'), (11083052, 'subseq sp, ip, r0, asr 31')],
        calls=[(11072108, 'bl method.std::__1::list_unsigned_int__std::__1::allocator_unsigned_int___.pop_front__'), (11072168, 'bl sym.getWorldPosForWorldIndex_int__int__int__World_'), (11072248, 'blx r2'), (11072292, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (11072440, 'bl loc.imp.objc_msgSend'), (11072464, 'bl sym.imp.__aeabi_idiv'), (11072532, 'bl loc.imp.objc_msgSend'), (11072652, 'bl loc.imp.objc_msgSend'), (11072668, 'bl sym.imp.__aeabi_idiv'), (11072736, 'bl loc.imp.objc_msgSend'), (11073508, 'blx r2'), (11073552, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (11073616, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (11073636, 'bl sym.tileIsSemiTransparentSolidBlock_Tile_'), (11073656, 'bl sym.tileIsWater_Tile_'), (11073728, 'bl sym.imp.__aeabi_idiv'), (11073916, 'bl sym.imp.__aeabi_idiv'), (11074400, 'blx r2'), (11074444, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (11074508, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (11074528, 'bl sym.tileIsSemiTransparentSolidBlock_Tile_'), (11074548, 'bl sym.tileIsWater_Tile_'), (11074620, 'bl sym.imp.__aeabi_idiv'), (11074808, 'bl sym.imp.__aeabi_idiv'), (11075292, 'blx r2'), (11075336, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (11075436, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (11075456, 'bl sym.tileIsSemiTransparentSolidBlock_Tile_'), (11075476, 'bl sym.tileIsWater_Tile_'), (11075548, 'bl sym.imp.__aeabi_idiv'), (11075772, 'bl sym.imp.__aeabi_idiv'), (11075908, 'bl sym.imp.__aeabi_idiv'), (11076416, 'blx r2'), (11076460, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (11076560, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (11076580, 'bl sym.tileIsSemiTransparentSolidBlock_Tile_'), (11076600, 'bl sym.tileIsWater_Tile_'), (11076672, 'bl sym.imp.__aeabi_idiv'), (11076904, 'bl sym.imp.__aeabi_idiv'), (11077048, 'bl sym.imp.__aeabi_idiv'), (11077544, 'blx r2'), (11077588, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (11077688, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (11077708, 'bl sym.tileIsSemiTransparentSolidBlock_Tile_'), (11077728, 'bl sym.tileIsWater_Tile_'), (11077800, 'bl sym.imp.__aeabi_idiv'), (11077988, 'bl sym.imp.__aeabi_idiv'), (11078484, 'blx r2'), (11078528, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (11078628, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (11078648, 'bl sym.tileIsSemiTransparentSolidBlock_Tile_'), (11078668, 'bl sym.tileIsWater_Tile_'), (11078740, 'bl sym.imp.__aeabi_idiv'), (11078928, 'bl sym.imp.__aeabi_idiv'), (11079424, 'blx r2'), (11079468, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (11079568, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (11079588, 'bl sym.tileIsSemiTransparentSolidBlock_Tile_'), (11079608, 'bl sym.tileIsWater_Tile_'), (11079680, 'bl sym.imp.__aeabi_idiv'), (11079868, 'bl sym.imp.__aeabi_idiv'), (11080364, 'blx r2'), (11080408, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (11080508, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (11080528, 'bl sym.tileIsSemiTransparentSolidBlock_Tile_'), (11080548, 'bl sym.tileIsWater_Tile_'), (11080620, 'bl sym.imp.__aeabi_idiv'), (11080808, 'bl sym.imp.__aeabi_idiv'), (11081136, 'bl sym.worldIndexAtWorldPosition_int__int__World_'), (11081532, 'bl method.std::__1::list_unsigned_int__std::__1::allocator_unsigned_int___.push_back_unsigned_int_'), (11081616, 'bl sym.worldIndexAtWorldPosition_int__int__World_'), (11082008, 'bl method.std::__1::list_unsigned_int__std::__1::allocator_unsigned_int___.push_back_unsigned_int_'), (11082092, 'bl sym.worldIndexAtWorldPosition_int__int__World_'), (11082488, 'bl method.std::__1::list_unsigned_int__std::__1::allocator_unsigned_int___.push_back_unsigned_int_'), (11082572, 'bl sym.worldIndexAtWorldPosition_int__int__World_'), (11082964, 'bl method.std::__1::list_unsigned_int__std::__1::allocator_unsigned_int___.push_back_unsigned_int_')],
        branches=[(11072312, 'beq', 11082984), (11072476, 'ble', 11072564), (11072560, 'b', 11072768), (11072680, 'bge', 11072764), (11072764, 'b', 11072768), (11072844, 'blt', 11082980), (11072884, 'bge', 11082980), (11072896, 'blt', 11082980), (11072936, 'bge', 11082980), (11073064, 'bne', 11073152), (11073104, 'bne', 11073152), (11073148, 'b', 11080940), (11073232, 'blt', 11074044), (11073272, 'bge', 11074044), (11073284, 'blt', 11074044), (11073324, 'bge', 11074044), (11073424, 'ble', 11074040), (11073572, 'beq', 11074036), (11073608, 'beq', 11073824), (11073628, 'bne', 11073652), (11073648, 'beq', 11073824), (11073668, 'beq', 11073808), (11073756, 'bge', 11073772), (11073768, 'b', 11073780), (11073804, 'b', 11073820), (11073820, 'b', 11074008), (11073856, 'beq', 11073996), (11073944, 'bge', 11073960), (11073956, 'b', 11073968), (11073992, 'b', 11074004), (11074004, 'b', 11074008), (11074020, 'ble', 11074032), (11074032, 'b', 11074036), (11074036, 'b', 11074040), (11074040, 'b', 11074044), (11074124, 'blt', 11074936), (11074164, 'bge', 11074936), (11074176, 'blt', 11074936), (11074216, 'bge', 11074936), (11074316, 'ble', 11074932), (11074464, 'beq', 11074928), (11074500, 'beq', 11074716), (11074520, 'bne', 11074544), (11074540, 'beq', 11074716), (11074560, 'beq', 11074700), (11074648, 'bge', 11074664), (11074660, 'b', 11074672), (11074696, 'b', 11074712), (11074712, 'b', 11074900), (11074748, 'beq', 11074888), (11074836, 'bge', 11074852), (11074848, 'b', 11074860), (11074884, 'b', 11074896), (11074896, 'b', 11074900), (11074912, 'ble', 11074924), (11074924, 'b', 11074928), (11074928, 'b', 11074932), (11074932, 'b', 11074936), (11075016, 'blt', 11076060), (11075056, 'bge', 11076060), (11075068, 'blt', 11076060), (11075108, 'bge', 11076060), (11075208, 'ble', 11076056), (11075356, 'beq', 11076052), (11075392, 'beq', 11075644), (11075428, 'beq', 11075644), (11075448, 'bne', 11075472), (11075468, 'beq', 11075644), (11075488, 'beq', 11075628), (11075576, 'bge', 11075592), (11075588, 'b', 11075600), (11075624, 'b', 11075640), (11075640, 'b', 11076024), (11075676, 'beq', 11075852), (11075712, 'beq', 11075852), (11075800, 'bge', 11075816), (11075812, 'b', 11075824), (11075848, 'b', 11076020), (11075936, 'bge', 11075988), (11075948, 'b', 11075996), (11076020, 'b', 11076024), (11076036, 'ble', 11076048), (11076048, 'b', 11076052), (11076052, 'b', 11076056), (11076056, 'b', 11076060), (11076140, 'blt', 11077180), (11076180, 'bge', 11077180), (11076192, 'blt', 11077180), (11076232, 'bge', 11077180), (11076332, 'ble', 11077176), (11076480, 'beq', 11077172), (11076516, 'beq', 11076776), (11076552, 'beq', 11076776), (11076572, 'bne', 11076596), (11076592, 'beq', 11076776), (11076612, 'beq', 11076752), (11076700, 'bge', 11076716), (11076712, 'b', 11076724), (11076748, 'b', 11076764), (11076764, 'b', 11077144), (11076808, 'beq', 11076992), (11076844, 'beq', 11076992), (11076932, 'bge', 11076952), (11076944, 'b', 11076960), (11076984, 'b', 11077140), (11077076, 'bge', 11077108), (11077088, 'b', 11077116), (11077140, 'b', 11077144), (11077156, 'ble', 11077168), (11077168, 'b', 11077172), (11077172, 'b', 11077176), (11077176, 'b', 11077180), (11077264, 'blt', 11078120), (11077304, 'bge', 11078120), (11077316, 'blt', 11078120), (11077356, 'bge', 11078120), (11077456, 'ble', 11078116), (11077608, 'beq', 11078112), (11077644, 'beq', 11077896), (11077680, 'beq', 11077896), (11077700, 'bne', 11077724), (11077720, 'beq', 11077896), (11077740, 'beq', 11077880), (11077828, 'bge', 11077844), (11077840, 'b', 11077852), (11077876, 'b', 11077892), (11077892, 'b', 11078084), (11077928, 'beq', 11078072), (11078016, 'bge', 11078032), (11078028, 'b', 11078040), (11078064, 'b', 11078080), (11078080, 'b', 11078084), (11078096, 'ble', 11078108), (11078108, 'b', 11078112), (11078112, 'b', 11078116), (11078116, 'b', 11078120), (11078204, 'blt', 11079060), (11078244, 'bge', 11079060), (11078256, 'blt', 11079060), (11078296, 'bge', 11079060), (11078396, 'ble', 11079056), (11078548, 'beq', 11079052), (11078584, 'beq', 11078836), (11078620, 'beq', 11078836), (11078640, 'bne', 11078664), (11078660, 'beq', 11078836), (11078680, 'beq', 11078820), (11078768, 'bge', 11078784), (11078780, 'b', 11078792), (11078816, 'b', 11078832), (11078832, 'b', 11079024), (11078868, 'beq', 11079012), (11078956, 'bge', 11078972), (11078968, 'b', 11078980), (11079004, 'b', 11079020), (11079020, 'b', 11079024), (11079036, 'ble', 11079048), (11079048, 'b', 11079052), (11079052, 'b', 11079056), (11079056, 'b', 11079060), (11079144, 'blt', 11080000), (11079184, 'bge', 11080000), (11079196, 'blt', 11080000), (11079236, 'bge', 11080000), (11079336, 'ble', 11079996), (11079488, 'beq', 11079992), (11079524, 'beq', 11079776), (11079560, 'beq', 11079776), (11079580, 'bne', 11079604), (11079600, 'beq', 11079776), (11079620, 'beq', 11079760), (11079708, 'bge', 11079724), (11079720, 'b', 11079732), (11079756, 'b', 11079772), (11079772, 'b', 11079964), (11079808, 'beq', 11079952), (11079896, 'bge', 11079912), (11079908, 'b', 11079920), (11079944, 'b', 11079960), (11079960, 'b', 11079964), (11079976, 'ble', 11079988), (11079988, 'b', 11079992), (11079992, 'b', 11079996), (11079996, 'b', 11080000), (11080084, 'blt', 11080936), (11080124, 'bge', 11080936), (11080136, 'blt', 11080936), (11080176, 'bge', 11080936), (11080276, 'ble', 11080932), (11080428, 'beq', 11080928), (11080464, 'beq', 11080716), (11080500, 'beq', 11080716), (11080520, 'bne', 11080544), (11080540, 'beq', 11080716), (11080560, 'beq', 11080700), (11080648, 'bge', 11080664), (11080660, 'b', 11080672), (11080696, 'b', 11080712), (11080712, 'b', 11080900), (11080748, 'beq', 11080888), (11080836, 'bge', 11080852), (11080848, 'b', 11080860), (11080884, 'b', 11080896), (11080896, 'b', 11080900), (11080912, 'ble', 11080924), (11080924, 'b', 11080928), (11080928, 'b', 11080932), (11080932, 'b', 11080936), (11080936, 'b', 11080940), (11081000, 'ble', 11082976), (11081072, 'ble', 11081540), (11081324, 'beq', 11081400), (11081360, 'bne', 11081368), (11081364, 'b', 11081400), (11081392, 'b', 11081256), (11081512, 'bne', 11081536), (11081536, 'b', 11081540), (11081552, 'ble', 11082016), (11081804, 'beq', 11081876), (11081840, 'bne', 11081848), (11081844, 'b', 11081876), (11081872, 'b', 11081736), (11081988, 'bne', 11082012), (11082012, 'b', 11082016), (11082028, 'ble', 11082496), (11082280, 'beq', 11082356), (11082316, 'bne', 11082324), (11082320, 'b', 11082356), (11082348, 'b', 11082212), (11082468, 'bne', 11082492), (11082492, 'b', 11082496), (11082508, 'ble', 11082972), (11082760, 'beq', 11082832), (11082796, 'bne', 11082804), (11082800, 'b', 11082832), (11082828, 'b', 11082692), (11082944, 'bne', 11082968), (11082968, 'b', 11082972), (11082972, 'b', 11082976), (11082976, 'b', 11082980), (11082980, 'b', 11082984)],
        semantics=('[ArtificialLight -[recursivelyUpdateLightWithList:]] (imp 0x00a8f22c, 2753w): the light propagation - the contributionGrid recalc walking radius/diameter cells with the worldWidthMacro wrap; 76 calls, 241 branches - census-grade, not a per-instruction walkthrough.\n'),
    ),
    dict(
        name='hl_18',
        method='ArtificialLight -[addToTiles]',
        types='v8@0:4',
        start=11084344,
        end=11088224,
        disasm='disasm_worldtileloader_hl_18.txt',
        base_add=11084360,
        base_literal=11088220,
        boundary='ARM.exidx end 0x00a93160 (listing bound); next ObjC IMP 0x00a93198 ArtificialLight -[removeFromTiles]',
        selectors={
                 0xa930a8: (15226060, 'macroTiles'),
                 0xa930cc: (15226072, 'dynamicWorld'),
                 0xa930d4: (15226084, 'createTreasureChestOrTrollAtTile:atPos:loadTroll:loadTreasure:'),
                 0xa930e4: (15226080, 'addTorchAtPos:ofType:dataA:dataB:saveDict:placedByClient:'),
                 0xa93124: (15226076, 'loadGlowBlockIfNeededAtPos:tile:'),
                 0xa93138: (15226064, 'worldWidthMacro'),
                 0xa9314c: (15226088, 'lightChangedAtMacroPos:sendReliably:'),
                 0xa93154: (15226068, 'recursivelyUpdateLightWithList:'),
        },
        imports={},
        ivars={
                 0xa93084: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa9308c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xa93090: (17164824, 'OBJC_IVAR_$_ArtificialLight.diameter', 92),
                 0xa93094: (17164840, 'OBJC_IVAR_$_ArtificialLight.addedGrid', 60),
                 0xa93098: (17164828, 'OBJC_IVAR_$_ArtificialLight.contributionGrid', 56),
                 0xa930a0: (17164820, 'OBJC_IVAR_$_ArtificialLight.contributionGridOrigin', 84),
                 0xa930b4: (17164832, 'OBJC_IVAR_$_ArtificialLight.radius', 80),
                 0xa930b8: (17164844, 'OBJC_IVAR_$_ArtificialLight.maxRed', 64),
                 0xa930bc: (17164848, 'OBJC_IVAR_$_ArtificialLight.maxGreen', 68),
                 0xa930c0: (17164852, 'OBJC_IVAR_$_ArtificialLight.maxBlue', 72),
                 0xa930c4: (17164856, 'OBJC_IVAR_$_ArtificialLight.maxHeat', 76),
        },
        classes={},
        instructions=[(11084344, 'push {r4, r5, fp, lr}'), (11088220, 'subseq sp, ip, r4, lsr 17')],
        calls=[(11084536, 'bl sym.worldIndexAtWorldPosition_int__int__World_'), (11084568, 'bl method.std::__1::list_unsigned_int__std::__1::allocator_unsigned_int___.push_back_unsigned_int_'), (11084680, 'bl loc.imp.objc_msgSend'), (11084708, 'bl method.std::__1::list_unsigned_int__std::__1::allocator_unsigned_int___._list__'), (11085064, 'bl loc.imp.objc_msgSend'), (11085116, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (11085724, 'bl sym.tileRequiresGlowBlock_Tile_'), (11085788, 'bl loc.imp.objc_msgSend'), (11085852, 'bl sym.makeIntpair_int__int_'), (11085900, 'bl loc.imp.objc_msgSend'), (11085976, 'bl loc.imp.objc_msgSend'), (11086040, 'bl sym.makeIntpair_int__int_'), (11086108, 'bl loc.imp.objc_msgSend'), (11086184, 'bl loc.imp.objc_msgSend'), (11086248, 'bl sym.makeIntpair_int__int_'), (11086316, 'bl loc.imp.objc_msgSend'), (11086392, 'bl loc.imp.objc_msgSend'), (11086456, 'bl sym.makeIntpair_int__int_'), (11086524, 'bl loc.imp.objc_msgSend'), (11086600, 'bl loc.imp.objc_msgSend'), (11086664, 'bl sym.makeIntpair_int__int_'), (11086732, 'bl loc.imp.objc_msgSend'), (11086808, 'bl loc.imp.objc_msgSend'), (11086872, 'bl sym.makeIntpair_int__int_'), (11086940, 'bl loc.imp.objc_msgSend'), (11087120, 'bl loc.imp.objc_msgSend'), (11087208, 'bl sym.makeIntpair_int__int_'), (11087272, 'bl loc.imp.objc_msgSend'), (11087400, 'bl loc.imp.objc_msgSend'), (11087452, 'bl sym.recalculateDrawBlockLightingForTile_int__int__MacroTile__World_'), (11087540, 'bl loc.imp.objc_msgSend'), (11087616, 'bl loc.imp.objc_msgSend'), (11087708, 'bl loc.imp.objc_msgSend'), (11087788, 'bl loc.imp.objc_msgSend'), (11087872, 'bl sym.makeIntpair_int__int_'), (11087920, 'bl loc.imp.objc_msgSend'), (11087980, 'bl method.std::__1::list_unsigned_int__std::__1::allocator_unsigned_int___._list__'), (11088000, 'bl sym.imp._Unwind_Resume')],
        branches=[(11084544, 'b', 11084548), (11084572, 'b', 11084576), (11084576, 'b', 11084580), (11084652, 'beq', 11084720), (11084684, 'b', 11084688), (11084688, 'b', 11084580), (11084716, 'b', 11087996), (11084768, 'bge', 11087976), (11084820, 'bge', 11087956), (11084912, 'bne', 11087936), (11084972, 'ble', 11087936), (11085072, 'b', 11085076), (11085124, 'b', 11085128), (11085148, 'beq', 11087932), (11085732, 'b', 11085736), (11085748, 'beq', 11085912), (11085796, 'b', 11085800), (11085856, 'b', 11085860), (11085904, 'b', 11085908), (11085908, 'b', 11087312), (11085924, 'bne', 11086120), (11085984, 'b', 11085988), (11086044, 'b', 11086048), (11086112, 'b', 11086116), (11086116, 'b', 11087308), (11086132, 'bne', 11086328), (11086192, 'b', 11086196), (11086252, 'b', 11086256), (11086320, 'b', 11086324), (11086324, 'b', 11087304), (11086340, 'bne', 11086536), (11086400, 'b', 11086404), (11086460, 'b', 11086464), (11086528, 'b', 11086532), (11086532, 'b', 11087300), (11086548, 'bne', 11086744), (11086608, 'b', 11086612), (11086668, 'b', 11086672), (11086736, 'b', 11086740), (11086740, 'b', 11087296), (11086756, 'bne', 11086952), (11086816, 'b', 11086820), (11086876, 'b', 11086880), (11086944, 'b', 11086948), (11086948, 'b', 11087292), (11086964, 'beq', 11087000), (11086980, 'beq', 11087000), (11086996, 'bne', 11087288), (11087080, 'bne', 11087284), (11087128, 'b', 11087132), (11087212, 'b', 11087216), (11087276, 'b', 11087280), (11087280, 'b', 11087284), (11087284, 'b', 11087288), (11087288, 'b', 11087292), (11087292, 'b', 11087296), (11087296, 'b', 11087300), (11087300, 'b', 11087304), (11087304, 'b', 11087308), (11087308, 'b', 11087312), (11087408, 'b', 11087412), (11087456, 'b', 11087460), (11087548, 'b', 11087552), (11087576, 'blt', 11087660), (11087624, 'b', 11087628), (11087656, 'b', 11087752), (11087668, 'bge', 11087748), (11087716, 'b', 11087720), (11087748, 'b', 11087752), (11087796, 'b', 11087800), (11087876, 'b', 11087880), (11087924, 'b', 11087928), (11087928, 'b', 11087932), (11087932, 'b', 11087936), (11087936, 'b', 11087940), (11087952, 'b', 11084784), (11087956, 'b', 11087960), (11087972, 'b', 11084732)],
        semantics=('[ArtificialLight -[addToTiles]] (imp 0x00a92238, 970w): the grid apply - writes the contribution across the tiles with the addedGrid bookkeeping + lightChangedAtMacroPos:sendReliably: notifications; 38 calls, 78 branches - census-grade, not a per-instruction walkthrough.\n'),
    ),
    dict(
        name='hl_19',
        method='ArtificialLight -[removeFromTiles]',
        types='v8@0:4',
        start=11088280,
        end=11089704,
        disasm='disasm_worldtileloader_hl_19.txt',
        base_add=11088296,
        base_literal=11089700,
        boundary='ARM.exidx end 0x00a93728 (listing bound); next ObjC IMP 0x00a93728 ArtificialLight -[objectType]',
        selectors={
                 0xa93700: (15226060, 'macroTiles'),
                 0xa93710: (15226064, 'worldWidthMacro'),
                 0xa93720: (15226088, 'lightChangedAtMacroPos:sendReliably:'),
        },
        imports={
                 0xa936fc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa936e8: (17164824, 'OBJC_IVAR_$_ArtificialLight.diameter', 92),
                 0xa936ec: (17164840, 'OBJC_IVAR_$_ArtificialLight.addedGrid', 60),
                 0xa936f0: (17164828, 'OBJC_IVAR_$_ArtificialLight.contributionGrid', 56),
                 0xa936f8: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xa93704: (17164820, 'OBJC_IVAR_$_ArtificialLight.contributionGridOrigin', 84),
                 0xa93718: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={},
        instructions=[(11088280, 'push {r4, r5, r6, sl, fp, lr}'), (11089700, 'subseq ip, ip, r4, asr 18')],
        calls=[(11088732, 'blx r2'), (11088776, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (11089212, 'bl loc.imp.objc_msgSend'), (11089252, 'bl sym.recalculateDrawBlockLightingForTile_int__int__MacroTile__World_'), (11089320, 'bl loc.imp.objc_msgSend'), (11089400, 'bl loc.imp.objc_msgSend'), (11089544, 'bl sym.makeIntpair_int__int_'), (11089584, 'bl loc.imp.objc_msgSend')],
        branches=[(11088360, 'bge', 11089632), (11088412, 'bge', 11089612), (11088504, 'bne', 11089592), (11088564, 'ble', 11089592), (11088796, 'beq', 11089588), (11089020, 'bgt', 11089064), (11089040, 'bgt', 11089064), (11089060, 'ble', 11089100), (11089344, 'blt', 11089428), (11089588, 'b', 11089592), (11089592, 'b', 11089596), (11089608, 'b', 11088376), (11089612, 'b', 11089616), (11089628, 'b', 11088324)],
        semantics=('[ArtificialLight -[removeFromTiles]] (imp 0x00a93198, 356w): the contribution removal - walks the addedGrid and clears it (lightChangedAtMacroPos:sendReliably:).\n'),
    ),
    dict(
        name='hl_20',
        method='ArtificialLight -[objectType]',
        types='i8@0:4',
        start=11089704,
        end=11089732,
        disasm='disasm_worldtileloader_hl_20.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a93744 (listing bound); next ObjC IMP 0x00a93744 ArtificialLight -[initWithWorld:dynamicWorld:atPosition:cache:parentObject:colorR:colorG:colorB:heat:radius:lightDirection:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11089704, 'sub sp, sp, 8'), (11089728, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[ArtificialLight -[objectType]] (imp 0x00a93728, 7w): returns the object type constant 21 (ArtificialLight).\n'),
    ),
    dict(
        name='hl_21',
        method='ArtificialLight -[initWithWorld:dynamicWorld:atPosition:cache:parentObject:colorR:colorG:colorB:heat:radius:lightDirection:]',
        types='@56@0:4@8@12{?=ii}16@24@28i32i36i40i44i48i52',
        start=11089732,
        end=11090876,
        disasm='disasm_worldtileloader_hl_21.txt',
        base_add=11089748,
        base_literal=11090872,
        boundary='ARM.exidx end 0x00a93bbc (listing bound); next ObjC IMP 0x00a93bbc ArtificialLight -[lightColor]',
        selectors={
                 0xa93b68: (15226092, 'isClient'),
                 0xa93b78: (15226100, 'initWithWorld:dynamicWorld:atPosition:cache:'),
                 0xa93b7c: (15226104, 'addToTiles'),
                 0xa93bb4: (15226096, 'release'),
        },
        imports={
                 0xa93b64: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa93b6c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xa93b80: (17164832, 'OBJC_IVAR_$_ArtificialLight.radius', 80),
                 0xa93b84: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa93b88: (17164820, 'OBJC_IVAR_$_ArtificialLight.contributionGridOrigin', 84),
                 0xa93b8c: (17164840, 'OBJC_IVAR_$_ArtificialLight.addedGrid', 60),
                 0xa93b90: (17164824, 'OBJC_IVAR_$_ArtificialLight.diameter', 92),
                 0xa93b94: (17164828, 'OBJC_IVAR_$_ArtificialLight.contributionGrid', 56),
                 0xa93b98: (17164860, 'OBJC_IVAR_$_ArtificialLight.parentObject', 100),
                 0xa93b9c: (17164836, 'OBJC_IVAR_$_ArtificialLight.lightDirection', 96),
                 0xa93ba4: (17164844, 'OBJC_IVAR_$_ArtificialLight.maxRed', 64),
                 0xa93ba8: (17164848, 'OBJC_IVAR_$_ArtificialLight.maxGreen', 68),
                 0xa93bac: (17164852, 'OBJC_IVAR_$_ArtificialLight.maxBlue', 72),
                 0xa93bb0: (17164856, 'OBJC_IVAR_$_ArtificialLight.maxHeat', 76),
        },
        classes={
                 0xa93b70: (15253064, 'OBJC_CLASS_$_ArtificialLight'),
        },
        instructions=[(11089732, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11090872, 'invalid')],
        calls=[(11089952, 'blx r5'), (11090020, 'blx r3'), (11090140, 'bl loc.imp.objc_msgSendSuper2'), (11090464, 'bl sym.imp.__wrap_calloc'), (11090544, 'bl sym.imp.__wrap_calloc'), (11090700, 'bl sym.makeIntpair_int__int_'), (11090764, 'blx r2')],
        branches=[(11089964, 'beq', 11090036), (11090032, 'b', 11090776), (11090168, 'bne', 11090184), (11090180, 'b', 11090776)],
        semantics=('[ArtificialLight -[initWithWorld:dynamicWorld:atPosition:cache:parentObject:colorR:colorG:colorB:heat:radius:lightDirection:]] (imp 0x00a93744, 286w): the light ctor - stores color/heat/radius/direction (maxRed/Green/Blue/Heat), builds the contributionGrid from radius/diameter and applies (addToTiles) when not client.\n'),
    ),
    dict(
        name='hl_22',
        method='ArtificialLight -[lightColor]',
        types='{Vector=[4f]}8@0:4',
        start=11090876,
        end=11091044,
        disasm='disasm_worldtileloader_hl_22.txt',
        base_add=11090892,
        base_literal=11091040,
        boundary='ARM.exidx end 0x00a93c64 (listing bound); next ObjC IMP 0x00a93c64 ArtificialLight -[initWithWorld:dynamicWorld:saveDict:cache:parentObject:]',
        selectors={},
        imports={},
        ivars={
                 0xa93c54: (17164852, 'OBJC_IVAR_$_ArtificialLight.maxBlue', 72),
                 0xa93c58: (17164848, 'OBJC_IVAR_$_ArtificialLight.maxGreen', 68),
                 0xa93c5c: (17164844, 'OBJC_IVAR_$_ArtificialLight.maxRed', 64),
        },
        classes={},
        instructions=[(11090876, 'push {r4, sl, fp, lr}'), (11091040, 'subseq fp, ip, r0, lsr 30')],
        calls=[(11091012, 'bl method.Vector.Vector_float__float__float_')],
        branches=[],
        semantics=('[ArtificialLight -[lightColor]] (imp 0x00a93bbc, 42w): the colour vector - (maxRed, maxGreen, maxBlue).\n'),
    ),
    dict(
        name='hl_23',
        method='ArtificialLight -[initWithWorld:dynamicWorld:saveDict:cache:parentObject:]',
        types='@28@0:4@8@12@16@20@24',
        start=11091044,
        end=11092692,
        disasm='disasm_worldtileloader_hl_23.txt',
        base_add=11091060,
        base_literal=11092688,
        boundary='ARM.exidx end 0x00a942d4 (listing bound); next ObjC IMP 0x00a942d4 ArtificialLight -[getSaveDict]',
        selectors={
                 0xa94258: (15226092, 'isClient'),
                 0xa94260: (15226108, 'initWithWorld:dynamicWorld:saveDict:cache:'),
                 0xa94268: (15226120, 'boolValue'),
                 0xa94270: (15226112, 'objectForKey:'),
                 0xa94278: (15226116, 'intValue'),
                 0xa942b8: (15226104, 'addToTiles'),
                 0xa942cc: (15226096, 'release'),
        },
        imports={
                 0xa94254: (17151904, 'objc_msgSend'),
                 0xa9425c: (17151900, 'objc_msgSendSuper2'),
                 0xa9426c: (16364216, '__CFConstantStringClassReference'),
                 0xa9427c: (16364200, '__CFConstantStringClassReference'),
                 0xa94284: (16364184, '__CFConstantStringClassReference'),
                 0xa94288: (16364168, '__CFConstantStringClassReference'),
                 0xa94290: (16364152, '__CFConstantStringClassReference'),
                 0xa94298: (16364136, '__CFConstantStringClassReference'),
                 0xa942a0: (16364120, '__CFConstantStringClassReference'),
                 0xa942a8: (16364104, '__CFConstantStringClassReference'),
                 0xa942b0: (16364088, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xa94274: (17164836, 'OBJC_IVAR_$_ArtificialLight.lightDirection', 96),
                 0xa94280: (17164820, 'OBJC_IVAR_$_ArtificialLight.contributionGridOrigin', 84),
                 0xa9428c: (17164832, 'OBJC_IVAR_$_ArtificialLight.radius', 80),
                 0xa94294: (17164856, 'OBJC_IVAR_$_ArtificialLight.maxHeat', 76),
                 0xa9429c: (17164852, 'OBJC_IVAR_$_ArtificialLight.maxBlue', 72),
                 0xa942a4: (17164848, 'OBJC_IVAR_$_ArtificialLight.maxGreen', 68),
                 0xa942ac: (17164844, 'OBJC_IVAR_$_ArtificialLight.maxRed', 64),
                 0xa942b4: (17164860, 'OBJC_IVAR_$_ArtificialLight.parentObject', 100),
                 0xa942bc: (17164840, 'OBJC_IVAR_$_ArtificialLight.addedGrid', 60),
                 0xa942c0: (17164824, 'OBJC_IVAR_$_ArtificialLight.diameter', 92),
                 0xa942c4: (17164828, 'OBJC_IVAR_$_ArtificialLight.contributionGrid', 56),
        },
        classes={
                 0xa94264: (15253064, 'OBJC_CLASS_$_ArtificialLight'),
        },
        instructions=[(11091044, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11092688, 'subseq fp, ip, r8, ror lr')],
        calls=[(11091132, 'blx r6'), (11091200, 'blx r3'), (11091308, 'blx ip'), (11091732, 'blx lr'), (11091748, 'blx r2'), (11091792, 'blx r3'), (11091808, 'blx r2'), (11091852, 'blx r3'), (11091868, 'blx r2'), (11091912, 'blx r3'), (11091928, 'blx r2'), (11091972, 'blx r3'), (11091988, 'blx r2'), (11092032, 'blx r3'), (11092048, 'blx r2'), (11092092, 'blx r3'), (11092108, 'blx r2'), (11092152, 'blx r3'), (11092168, 'blx r2'), (11092212, 'blx r3'), (11092228, 'blx r2'), (11092392, 'bl sym.imp.__wrap_calloc'), (11092472, 'bl sym.imp.__wrap_calloc'), (11092540, 'blx r3')],
        branches=[(11091144, 'beq', 11091216), (11091212, 'b', 11092552), (11091336, 'bne', 11091352), (11091348, 'b', 11092552), (11092240, 'beq', 11092276)],
        semantics=('[ArtificialLight -[initWithWorld:dynamicWorld:saveDict:cache:parentObject:]] (imp 0x00a93c64, 412w): the load ctor - restores color/heat/radius/direction from the save dict + grid rebuild + addToTiles when not client.\n'),
    ),
    dict(
        name='hl_24',
        method='ArtificialLight -[getSaveDict]',
        types='@8@0:4',
        start=11092692,
        end=11093932,
        disasm='disasm_worldtileloader_hl_24.txt',
        base_add=11092708,
        base_literal=11093928,
        boundary='ARM.exidx end 0x00a947ac (listing bound); next ObjC IMP 0x00a947ac ArtificialLight -[dealloc]',
        selectors={
                 0xa94754: (15226124, 'getSaveDict'),
                 0xa94764: (15226132, 'setObject:forKey:'),
                 0xa94768: (15226128, 'numberWithInt:'),
        },
        imports={
                 0xa94750: (17151900, 'objc_msgSendSuper2'),
                 0xa9475c: (16364200, '__CFConstantStringClassReference'),
                 0xa94760: (17151904, 'objc_msgSend'),
                 0xa94774: (16364184, '__CFConstantStringClassReference'),
                 0xa9477c: (16364168, '__CFConstantStringClassReference'),
                 0xa94780: (16364152, '__CFConstantStringClassReference'),
                 0xa94788: (16364136, '__CFConstantStringClassReference'),
                 0xa94790: (16364120, '__CFConstantStringClassReference'),
                 0xa94798: (16364104, '__CFConstantStringClassReference'),
                 0xa947a0: (16364088, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xa9476c: (17164836, 'OBJC_IVAR_$_ArtificialLight.lightDirection', 96),
                 0xa94778: (17164820, 'OBJC_IVAR_$_ArtificialLight.contributionGridOrigin', 84),
                 0xa94784: (17164832, 'OBJC_IVAR_$_ArtificialLight.radius', 80),
                 0xa9478c: (17164856, 'OBJC_IVAR_$_ArtificialLight.maxHeat', 76),
                 0xa94794: (17164852, 'OBJC_IVAR_$_ArtificialLight.maxBlue', 72),
                 0xa9479c: (17164848, 'OBJC_IVAR_$_ArtificialLight.maxGreen', 68),
                 0xa947a4: (17164844, 'OBJC_IVAR_$_ArtificialLight.maxRed', 64),
        },
        classes={
                 0xa94758: (15253064, 'OBJC_CLASS_$_ArtificialLight'),
                 0xa94770: (15249228, 'OBJC_CLASS_$_NSNumber'),
        },
        instructions=[(11092692, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11093928, 'subseq fp, ip, r8, lsl 16')],
        calls=[(11092776, 'blx ip'), (11093116, 'blx r3'), (11093152, 'blx ip'), (11093212, 'blx r3'), (11093248, 'blx ip'), (11093308, 'blx r3'), (11093344, 'blx ip'), (11093404, 'blx r3'), (11093440, 'blx ip'), (11093500, 'blx r3'), (11093536, 'blx ip'), (11093596, 'blx r3'), (11093632, 'blx ip'), (11093692, 'blx r3'), (11093728, 'blx ip'), (11093788, 'blx r3'), (11093824, 'blx ip')],
        branches=[],
        semantics=('[ArtificialLight -[getSaveDict]] (imp 0x00a942d4, 310w): the save serializer - colorR/G/B, maxHeat, radius, lightDirection, contributionGridOrigin.\n'),
    ),
    dict(
        name='hl_25',
        method='ArtificialLight -[dealloc]',
        types='v8@0:4',
        start=11093932,
        end=11094168,
        disasm='disasm_worldtileloader_hl_25.txt',
        base_add=11093948,
        base_literal=11094164,
        boundary='ARM.exidx end 0x00a94898 (listing bound); next ObjC IMP 0x00a94898 ArtificialLight -[worldChanged:]',
        selectors={
                 0xa9487c: (15226140, 'dealloc'),
                 0xa94890: (15226136, 'removeFromTiles'),
        },
        imports={
                 0xa94878: (17151900, 'objc_msgSendSuper2'),
                 0xa9488c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa94884: (17164840, 'OBJC_IVAR_$_ArtificialLight.addedGrid', 60),
                 0xa94888: (17164828, 'OBJC_IVAR_$_ArtificialLight.contributionGrid', 56),
        },
        classes={
                 0xa94880: (15253064, 'OBJC_CLASS_$_ArtificialLight'),
        },
        instructions=[(11093932, 'push {fp, lr}'), (11094164, 'subseq fp, ip, r0, lsr r3')],
        calls=[(11094000, 'blx ip'), (11094024, 'bl sym.imp.__wrap_free'), (11094056, 'bl sym.imp.__wrap_free'), (11094124, 'blx r3')],
        branches=[],
        semantics=('[ArtificialLight -[dealloc]] (imp 0x00a947ac, 59w): removeFromTiles + releases the grids.\n'),
    ),
    dict(
        name='hl_26',
        method='ArtificialLight -[worldChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=11094168,
        end=11096476,
        disasm='disasm_worldtileloader_hl_26.txt',
        base_add=11094184,
        base_literal=11096472,
        boundary='ARM.exidx end 0x00a9519c (listing bound); next ObjC IMP 0x00a9519c ArtificialLight -[removeFromMacroBlock]',
        selectors={
                 0xa95150: (15226064, 'worldWidthMacro'),
                 0xa9518c: (15226104, 'addToTiles'),
                 0xa95190: (15226136, 'removeFromTiles'),
        },
        imports={
                 0xa95188: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa95144: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa9514c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xa95160: (17164832, 'OBJC_IVAR_$_ArtificialLight.radius', 80),
                 0xa95174: (17164820, 'OBJC_IVAR_$_ArtificialLight.contributionGridOrigin', 84),
                 0xa95178: (17164824, 'OBJC_IVAR_$_ArtificialLight.diameter', 92),
                 0xa9517c: (17164840, 'OBJC_IVAR_$_ArtificialLight.addedGrid', 60),
                 0xa95180: (17164828, 'OBJC_IVAR_$_ArtificialLight.contributionGrid', 56),
        },
        classes={},
        instructions=[(11094168, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11096472, 'subseq fp, ip, r4, asr 4')],
        calls=[(11094568, 'bl loc.imp.objc_msgSend'), (11094592, 'bl sym.imp.__aeabi_idiv'), (11094688, 'bl loc.imp.objc_msgSend'), (11094808, 'bl loc.imp.objc_msgSend'), (11094824, 'bl sym.imp.__aeabi_idiv'), (11094920, 'bl loc.imp.objc_msgSend'), (11095136, 'bl loc.imp.objc_msgSend'), (11095160, 'bl sym.imp.__aeabi_idiv'), (11095256, 'bl loc.imp.objc_msgSend'), (11095376, 'bl loc.imp.objc_msgSend'), (11095392, 'bl sym.imp.__aeabi_idiv'), (11095488, 'bl loc.imp.objc_msgSend'), (11095816, 'bl sym.makeIntpair_int__int_'), (11096264, 'bl loc.imp.objc_msgSend'), (11096356, 'bl sym.imp.memset'), (11096376, 'blx r2')],
        branches=[(11094448, 'beq', 11096160), (11094604, 'blt', 11094720), (11094716, 'b', 11095000), (11094836, 'bge', 11094952), (11094948, 'b', 11094992), (11095044, 'blt', 11096096), (11095172, 'blt', 11095288), (11095284, 'b', 11095568), (11095404, 'bge', 11095520), (11095516, 'b', 11095560), (11095604, 'bge', 11096096), (11095680, 'blt', 11096096), (11095748, 'bge', 11096096), (11095828, 'ble', 11096092), (11095868, 'bge', 11096092), (11095880, 'ble', 11096092), (11095920, 'bge', 11096092), (11096012, 'bne', 11096088), (11096072, 'ble', 11096088), (11096084, 'b', 11096160), (11096088, 'b', 11096092), (11096092, 'b', 11096096), (11096096, 'b', 11096100), (11096156, 'b', 11094296), (11096168, 'beq', 11096380)],
        semantics=('[ArtificialLight -[worldChanged:]] (imp 0x00a94898, 577w): the area recompute - worldChanged: re-derives the grid (addToTiles/removeFromTiles pairs); 16 calls, 25 branches.\n'),
    ),
    dict(
        name='hl_27',
        method='ArtificialLight -[removeFromMacroBlock]',
        types='v8@0:4',
        start=11096476,
        end=11096648,
        disasm='disasm_worldtileloader_hl_27.txt',
        base_add=11096492,
        base_literal=11096644,
        boundary='ARM.exidx end 0x00a95248 (listing bound); next ObjC IMP 0x00a95248 ArtificialLight -[addContributionForPhysicalBlockLoadedAtXPos:yPos:]',
        selectors={
                 0xa95234: (15226144, 'removeFromMacroBlock'),
                 0xa95240: (15226136, 'removeFromTiles'),
        },
        imports={
                 0xa95230: (17151900, 'objc_msgSendSuper2'),
                 0xa9523c: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0xa95238: (15253064, 'OBJC_CLASS_$_ArtificialLight'),
        },
        instructions=[(11096476, 'push {r4, r5, r6, sl, fp, lr}'), (11096644, 'subseq sl, ip, r0, asr 18')],
        calls=[(11096572, 'blx r5'), (11096612, 'blx r2')],
        branches=[],
        semantics=('[ArtificialLight -[removeFromMacroBlock]] (imp 0x00a9519c, 43w): removeFromTiles then the super removeFromMacroBlock.\n'),
    ),
    dict(
        name='hl_28',
        method='ArtificialLight -[addContributionForPhysicalBlockLoadedAtXPos:yPos:]',
        types='v16@0:4i8i12',
        start=11096648,
        end=11098300,
        disasm='disasm_worldtileloader_hl_28.txt',
        base_add=11096664,
        base_literal=11098296,
        boundary='ARM.exidx end 0x00a958bc (listing bound); next ObjC IMP 0x00a958bc ArtificialLight -[.cxx_construct]',
        selectors={
                 0xa9587c: (15226064, 'worldWidthMacro'),
                 0xa958a4: (15226104, 'addToTiles'),
                 0xa958ac: (15226136, 'removeFromTiles'),
        },
        imports={
                 0xa958a0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa95870: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa95878: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xa9588c: (17164832, 'OBJC_IVAR_$_ArtificialLight.radius', 80),
                 0xa958a8: (17164824, 'OBJC_IVAR_$_ArtificialLight.diameter', 92),
                 0xa958b4: (17164828, 'OBJC_IVAR_$_ArtificialLight.contributionGrid', 56),
        },
        classes={},
        instructions=[(11096648, 'push {r4, r5, r6, r7, fp, lr}'), (11098296, 'invalid')],
        calls=[(11096720, 'bl sym.makeIntpair_int__int_'), (11096752, 'bl sym.makeIntpair_int__int_'), (11096824, 'bl loc.imp.objc_msgSend'), (11096848, 'bl sym.imp.__aeabi_idiv'), (11096944, 'bl loc.imp.objc_msgSend'), (11097064, 'bl loc.imp.objc_msgSend'), (11097080, 'bl sym.imp.__aeabi_idiv'), (11097176, 'bl loc.imp.objc_msgSend'), (11097392, 'bl loc.imp.objc_msgSend'), (11097416, 'bl sym.imp.__aeabi_idiv'), (11097512, 'bl loc.imp.objc_msgSend'), (11097632, 'bl loc.imp.objc_msgSend'), (11097648, 'bl sym.imp.__aeabi_idiv'), (11097744, 'bl loc.imp.objc_msgSend'), (11098100, 'bl loc.imp.objc_msgSend'), (11098192, 'bl sym.imp.memset'), (11098212, 'blx r2')],
        branches=[(11096860, 'blt', 11096976), (11096972, 'b', 11097256), (11097092, 'bge', 11097208), (11097204, 'b', 11097248), (11097300, 'blt', 11098216), (11097428, 'blt', 11097544), (11097540, 'b', 11097824), (11097660, 'bge', 11097776), (11097772, 'b', 11097816), (11097860, 'bge', 11098216), (11097936, 'blt', 11098216), (11098004, 'bge', 11098216)],
        semantics=('[ArtificialLight -[addContributionForPhysicalBlockLoadedAtXPos:yPos:]] (imp 0x00a95248, 413w): the per-cell contribution writer - clamps by radius/diameter against the macro neighbourhood and writes the (light, heat) contribution for the loaded physical block.\n'),
    ),
    dict(
        name='hl_29',
        method='ArtificialLight -[.cxx_construct]',
        types='@8@0:4',
        start=11098300,
        end=11098324,
        disasm='disasm_worldtileloader_hl_29.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a958d4 (listing bound); next ObjC IMP 0x00a95bd8 OrangeTree -[objectType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11098300, 'sub sp, sp, 8'), (11098320, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[ArtificialLight -[.cxx_construct]] (imp 0x00a958bc, 6w): the C++ ctor anchor.\n'),
    ),
    dict(
        name='hl_30',
        method='GlowBlock -[initSubDerivedItems]',
        types='v8@0:4',
        start=13271812,
        end=13271832,
        disasm='disasm_worldtileloader_hl_30.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00ca8334; body trimmed at the next IMP 0x00ca8318 GlowBlock -[objectType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13271812, 'sub sp, sp, 8'), (13271828, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[GlowBlock -[initSubDerivedItems]] (imp 0x00ca8304, 5w): the seed (5 words, no ObjC work).\n'),
    ),
    dict(
        name='hl_31',
        method='GlowBlock -[objectType]',
        types='i8@0:4',
        start=13271832,
        end=13271860,
        disasm='disasm_worldtileloader_hl_31.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00ca8334 (listing bound); next ObjC IMP 0x00ca8334 GlowBlock -[getLightRGB]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13271832, 'sub sp, sp, 8'), (13271856, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[GlowBlock -[objectType]] (imp 0x00ca8318, 7w): returns the object type constant 18 (GlowBlock).\n'),
    ),
    dict(
        name='hl_32',
        method='GlowBlock -[getLightRGB]',
        types='{Vector=[4f]}8@0:4',
        start=13271860,
        end=13272020,
        disasm='disasm_worldtileloader_hl_32.txt',
        base_add=13271876,
        base_literal=13272016,
        boundary='ARM.exidx end 0x00ca83d4 (listing bound); next ObjC IMP 0x00ca83d4 GlowBlock -[initWithWorld:dynamicWorld:atPosition:cache:tile:]',
        selectors={
                 0xca83c8: (15235860, 'lightColor'),
        },
        imports={},
        ivars={
                 0xca83cc: (17167452, 'OBJC_IVAR_$_GlowBlock.light', 56),
        },
        classes={},
        instructions=[(13271860, 'push {r4, sl, fp, lr}'), (13272016, 'eorseq r7, fp, r8, lsr 15')],
        calls=[(13271960, 'bl loc.imp.objc_msgSend_stret'), (13271996, 'bl sym.imp.memset')],
        branches=[(13271944, 'beq', 13271968), (13271964, 'b', 13272000)],
        semantics=('[GlowBlock -[getLightRGB]] (imp 0x00ca8334, 40w): the glow colour from GlowBlock.light (lightColor).\n'),
    ),
    dict(
        name='hl_33',
        method='GlowBlock -[initWithWorld:dynamicWorld:atPosition:cache:tile:]',
        types='@32@0:4@8@12{?=ii}16@24^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}28',
        start=13272020,
        end=13273376,
        disasm='disasm_worldtileloader_hl_33.txt',
        base_add=13272036,
        base_literal=13273372,
        boundary='ARM.exidx end 0x00ca8920 (listing bound); next ObjC IMP 0x00ca8920 GlowBlock -[initWithWorld:dynamicWorld:saveDict:cache:]',
        selectors={
                 0xca88e4: (15235864, 'initWithWorld:dynamicWorld:atPosition:cache:'),
                 0xca88f0: (15235880, 'initSubDerivedItems'),
                 0xca88fc: (15235868, 'alloc'),
                 0xca8910: (15235872, 'initWithWorld:dynamicWorld:atPosition:cache:parentObject:colorR:colorG:colorB:heat:radius:lightDirection:'),
                 0xca8918: (15235876, 'macroTiles'),
        },
        imports={
                 0xca88ec: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xca88e8: (17167456, 'OBJC_IVAR_$_GlowBlock.tileType', 60),
                 0xca8900: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xca8904: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xca8908: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xca890c: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0xca8914: (17167452, 'OBJC_IVAR_$_GlowBlock.light', 56),
        },
        classes={
                 0xca88dc: (15253216, 'OBJC_CLASS_$_GlowBlock'),
                 0xca88f4: (15250844, 'OBJC_CLASS_$_ArtificialLight'),
        },
        instructions=[(13272020, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13273372, 'eorseq r7, fp, r8, lsl 14')],
        calls=[(13272204, 'bl loc.imp.objc_msgSendSuper2'), (13272880, 'bl loc.imp.objc_msgSend'), (13273116, 'bl loc.imp.objc_msgSend'), (13273196, 'bl loc.imp.objc_msgSend'), (13273240, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_'), (13273284, 'blx r2')],
        branches=[(13272232, 'bne', 13272248), (13272244, 'b', 13273296), (13272336, 'beq', 13272848), (13272372, 'beq', 13272848), (13272408, 'beq', 13272428), (13272424, 'bne', 13272456), (13272452, 'b', 13272844), (13272488, 'bne', 13272520), (13272516, 'b', 13272840), (13272552, 'bne', 13272580), (13272576, 'b', 13272836), (13272612, 'bne', 13272640), (13272636, 'b', 13272832), (13272672, 'bne', 13272700), (13272696, 'b', 13272828), (13272732, 'bne', 13272760), (13272756, 'b', 13272824), (13272792, 'bne', 13272820), (13272820, 'b', 13272824), (13272824, 'b', 13272828), (13272828, 'b', 13272832), (13272832, 'b', 13272836), (13272836, 'b', 13272840), (13272840, 'b', 13272844), (13272844, 'b', 13272848)],
        semantics=('[GlowBlock -[initWithWorld:dynamicWorld:atPosition:cache:tile:]] (imp 0x00ca83d4, 339w): the placement ctor - derives the glow config from the tile (tileType; 25 branches) + the parent light.\n'),
    ),
    dict(
        name='hl_34',
        method='GlowBlock -[initWithWorld:dynamicWorld:saveDict:cache:]',
        types='@24@0:4@8@12@16@20',
        start=13273376,
        end=13274232,
        disasm='disasm_worldtileloader_hl_34.txt',
        base_add=13273392,
        base_literal=13274228,
        boundary='ARM.exidx end 0x00ca8c78 (listing bound); next ObjC IMP 0x00ca8c78 GlowBlock -[getSaveDict]',
        selectors={
                 0xca8c28: (15235884, 'initWithWorld:dynamicWorld:saveDict:cache:'),
                 0xca8c38: (15235888, 'objectForKey:'),
                 0xca8c40: (15235892, 'intValue'),
                 0xca8c50: (15235868, 'alloc'),
                 0xca8c60: (15235896, 'initWithWorld:dynamicWorld:saveDict:cache:parentObject:'),
                 0xca8c6c: (15235876, 'macroTiles'),
                 0xca8c70: (15235880, 'initSubDerivedItems'),
        },
        imports={
                 0xca8c24: (17151900, 'objc_msgSendSuper2'),
                 0xca8c30: (16396520, '__CFConstantStringClassReference'),
                 0xca8c34: (17151904, 'objc_msgSend'),
                 0xca8c44: (16396504, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xca8c3c: (17167456, 'OBJC_IVAR_$_GlowBlock.tileType', 60),
                 0xca8c54: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xca8c58: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xca8c5c: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0xca8c64: (17167452, 'OBJC_IVAR_$_GlowBlock.light', 56),
                 0xca8c68: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={
                 0xca8c2c: (15253216, 'OBJC_CLASS_$_GlowBlock'),
                 0xca8c48: (15250844, 'OBJC_CLASS_$_ArtificialLight'),
        },
        instructions=[(13273376, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13274228, 'ldrhteq r7, [fp], -ip')],
        calls=[(13273528, 'blx r6'), (13273680, 'blx ip'), (13273696, 'blx r2'), (13273740, 'blx r3'), (13273788, 'bl loc.imp.objc_msgSend'), (13273884, 'bl loc.imp.objc_msgSend'), (13273952, 'bl loc.imp.objc_msgSend'), (13274036, 'bl loc.imp.objc_msgSend'), (13274080, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_'), (13274124, 'blx r2')],
        branches=[(13273556, 'bne', 13273572), (13273568, 'b', 13274136), (13273752, 'beq', 13274084)],
        semantics=('[GlowBlock -[initWithWorld:dynamicWorld:saveDict:cache:]] (imp 0x00ca8920, 214w): the load ctor - tileType restore + the light.\n'),
    ),
    dict(
        name='hl_35',
        method='GlowBlock -[getSaveDict]',
        types='@8@0:4',
        start=13274232,
        end=13274724,
        disasm='disasm_worldtileloader_hl_35.txt',
        base_add=13274248,
        base_literal=13274720,
        boundary='ARM.exidx end 0x00ca8e64 (listing bound); next ObjC IMP 0x00ca8e64 GlowBlock -[dealloc]',
        selectors={
                 0xca8e38: (15235900, 'getSaveDict'),
                 0xca8e4c: (15235908, 'setObject:forKey:'),
                 0xca8e50: (15235904, 'numberWithInt:'),
        },
        imports={
                 0xca8e34: (17151900, 'objc_msgSendSuper2'),
                 0xca8e40: (17151904, 'objc_msgSend'),
                 0xca8e48: (16396504, '__CFConstantStringClassReference'),
                 0xca8e5c: (16396520, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xca8e44: (17167452, 'OBJC_IVAR_$_GlowBlock.light', 56),
                 0xca8e54: (17167456, 'OBJC_IVAR_$_GlowBlock.tileType', 60),
        },
        classes={
                 0xca8e3c: (15253216, 'OBJC_CLASS_$_GlowBlock'),
                 0xca8e58: (15250848, 'OBJC_CLASS_$_NSNumber'),
        },
        instructions=[(13274232, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13274720, 'eorseq r6, fp, r4, ror 28')],
        calls=[(13274316, 'blx ip'), (13274500, 'blx r8'), (13274536, 'blx ip'), (13274572, 'blx r3'), (13274660, 'blx ip')],
        branches=[(13274592, 'beq', 13274664)],
        semantics=('[GlowBlock -[getSaveDict]] (imp 0x00ca8c78, 123w): the serializer - the tileType entry (+ light).\n'),
    ),
    dict(
        name='hl_36',
        method='GlowBlock -[dealloc]',
        types='v8@0:4',
        start=13274724,
        end=13274956,
        disasm='disasm_worldtileloader_hl_36.txt',
        base_add=13274740,
        base_literal=13274952,
        boundary='ARM.exidx end 0x00ca8f4c (listing bound); next ObjC IMP 0x00ca8f4c GlowBlock -[removeFromMacroBlock]',
        selectors={
                 0xca8f34: (15235916, 'dealloc'),
                 0xca8f44: (15235912, 'release'),
        },
        imports={
                 0xca8f30: (17151900, 'objc_msgSendSuper2'),
                 0xca8f40: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xca8f3c: (17167452, 'OBJC_IVAR_$_GlowBlock.light', 56),
        },
        classes={
                 0xca8f38: (15253216, 'OBJC_CLASS_$_GlowBlock'),
        },
        instructions=[(13274724, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13274952, 'eorseq r6, fp, r8, ror ip')],
        calls=[(13274852, 'blx r7'), (13274916, 'blx ip')],
        branches=[],
        semantics=('[GlowBlock -[dealloc]] (imp 0x00ca8e64, 58w): releases light + super dealloc.\n'),
    ),
    dict(
        name='hl_37',
        method='GlowBlock -[removeFromMacroBlock]',
        types='v8@0:4',
        start=13274956,
        end=13275324,
        disasm='disasm_worldtileloader_hl_37.txt',
        base_add=13274972,
        base_literal=13275320,
        boundary='ARM.exidx end 0x00ca90bc (listing bound); next ObjC IMP 0x00ca90bc GlowBlock -[worldChanged:]',
        selectors={
                 0xca9098: (15235920, 'removeFromMacroBlock'),
                 0xca90a8: (15235912, 'release'),
                 0xca90b4: (15235876, 'macroTiles'),
        },
        imports={
                 0xca9094: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0xca90a0: (17167452, 'OBJC_IVAR_$_GlowBlock.light', 56),
                 0xca90ac: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xca90b0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={
                 0xca909c: (15253216, 'OBJC_CLASS_$_GlowBlock'),
        },
        instructions=[(13274956, 'push {fp, lr}'), (13275320, 'mlaseq fp, r0, fp, r6')],
        calls=[(13275036, 'bl loc.imp.objc_msgSend'), (13275068, 'bl loc.imp.objc_msgSend'), (13275160, 'bl loc.imp.objc_msgSend'), (13275204, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_'), (13275272, 'blx r3')],
        branches=[],
        semantics=('[GlowBlock -[removeFromMacroBlock]] (imp 0x00ca8f4c, 92w): removes the glow from the macro block + releases light.\n'),
    ),
    dict(
        name='hl_38',
        method='GlowBlock -[worldChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=13275324,
        end=13276076,
        disasm='disasm_worldtileloader_hl_38.txt',
        base_add=13275340,
        base_literal=13276072,
        boundary='ARM.exidx end 0x00ca93ac (listing bound); next ObjC IMP 0x00ca93ac GlowBlock -[setNeedsRemoved:]',
        selectors={
                 0xca9390: (15235924, 'worldChanged:'),
                 0xca93a4: (15235928, 'setNeedsRemoved:'),
        },
        imports={
                 0xca938c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xca9394: (17167452, 'OBJC_IVAR_$_GlowBlock.light', 56),
                 0xca9398: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xca939c: (17167456, 'OBJC_IVAR_$_GlowBlock.tileType', 60),
                 0xca93a0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(13275324, 'push {r4, r5, r6, sl, fp, lr}'), (13276072, 'eorseq r6, fp, r0, lsr 20')],
        calls=[(13275424, 'blx r4'), (13275852, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13275964, 'blx ip')],
        branches=[(13275664, 'beq', 13276036), (13275736, 'bne', 13275972), (13275776, 'bne', 13275972), (13275900, 'beq', 13275968), (13275968, 'b', 13276036), (13275972, 'b', 13275976), (13276032, 'b', 13275512)],
        semantics=('[GlowBlock -[worldChanged:]] (imp 0x00ca90bc, 188w): the invalidation - a tileType change -> setNeedsRemoved; 7 branches.\n'),
    ),
    dict(
        name='hl_39',
        method='GlowBlock -[setNeedsRemoved:]',
        types='v12@0:4c8',
        start=13276076,
        end=13276416,
        disasm='disasm_worldtileloader_hl_39.txt',
        base_add=13276092,
        base_literal=13276412,
        boundary='ARM.exidx end 0x00ca9500 (listing bound); next ObjC IMP 0x00ca9500 GlowBlock -[lightGlowQuadCount]',
        selectors={
                 0xca94dc: (15235928, 'setNeedsRemoved:'),
                 0xca94ec: (15235932, 'removeFromTiles'),
                 0xca94f8: (15235876, 'macroTiles'),
        },
        imports={
                 0xca94d8: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0xca94e4: (17167452, 'OBJC_IVAR_$_GlowBlock.light', 56),
                 0xca94f0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xca94f4: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={
                 0xca94e0: (15253216, 'OBJC_CLASS_$_GlowBlock'),
        },
        instructions=[(13276076, 'push {r4, r5, fp, lr}'), (13276412, 'eorseq r6, fp, r0, lsr r7')],
        calls=[(13276188, 'blx lr'), (13276244, 'bl loc.imp.objc_msgSend'), (13276320, 'bl loc.imp.objc_msgSend'), (13276364, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_')],
        branches=[(13276200, 'beq', 13276368)],
        semantics=('[GlowBlock -[setNeedsRemoved:]] (imp 0x00ca93ac, 85w): the removal setter - light removeFromTiles + super.\n'),
    ),
    dict(
        name='hl_40',
        method='GlowBlock -[lightGlowQuadCount]',
        types='i8@0:4',
        start=13276416,
        end=13276508,
        disasm='disasm_worldtileloader_hl_40.txt',
        base_add=13276424,
        base_literal=13276504,
        boundary='ARM.exidx end 0x00ca955c (listing bound); next ObjC IMP 0x00ca955c GlowBlock -[lightPos]',
        selectors={},
        imports={},
        ivars={
                 0xca9554: (17167456, 'OBJC_IVAR_$_GlowBlock.tileType', 60),
        },
        classes={},
        instructions=[(13276416, 'sub sp, sp, 0xc'), (13276504, 'eorseq r6, fp, r4, ror 11')],
        calls=[],
        branches=[(13276464, 'bne', 13276480), (13276476, 'b', 13276488)],
        semantics=('[GlowBlock -[lightGlowQuadCount]] (imp 0x00ca9500, 23w): the glow quad count switch by tileType.\n'),
    ),
    dict(
        name='hl_41',
        method='GlowBlock -[lightPos]',
        types='{Vector=[4f]}8@0:4',
        start=13276508,
        end=13276684,
        disasm='disasm_worldtileloader_hl_41.txt',
        base_add=13276524,
        base_literal=13276680,
        boundary='ARM.exidx end 0x00ca960c (listing bound); next ObjC IMP 0x00ca960c GlowBlock -[addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:]',
        selectors={},
        imports={},
        ivars={
                 0xca9604: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={},
        instructions=[(13276508, 'push {fp, lr}'), (13276680, 'eorseq r6, fp, r0, lsl 11')],
        calls=[(13276568, 'bl method.Vector2.operator_float__'), (13276604, 'bl method.Vector2.operator_float__'), (13276656, 'bl method.Vector.Vector_float__float__float_')],
        branches=[],
        semantics=('[GlowBlock -[lightPos]] (imp 0x00ca955c, 44w): the glow position (floatPos-derived).\n'),
    ),
    dict(
        name='hl_42',
        method='GlowBlock -[addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:]',
        types='v16@0:4i8i12',
        start=13276684,
        end=13276800,
        disasm='disasm_worldtileloader_hl_42.txt',
        base_add=13276700,
        base_literal=13276796,
        boundary='ARM.exidx end 0x00ca9680 (listing bound); next ObjC IMP 0x00ca97ac BHMatch -[localPlayerID]',
        selectors={
                 0xca9674: (15235936, 'addContributionForPhysicalBlockLoadedAtXPos:yPos:'),
        },
        imports={
                 0xca9670: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xca9678: (17167452, 'OBJC_IVAR_$_GlowBlock.light', 56),
        },
        classes={},
        instructions=[(13276684, 'push {r4, r5, fp, lr}'), (13276796, 'ldrsbteq r6, [fp], -r0')],
        calls=[(13276772, 'blx lr')],
        branches=[],
        semantics=('[GlowBlock -[addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:]] (imp 0x00ca960c, 29w): forwards the contribution to GlowBlock.light.\n'),
    ),
    dict(
        name='hl_43',
        method='tileIsBurnableBlock',
        types='',
        start=10567916,
        end=10568064,
        disasm='disasm_worldtileloader_hl_43.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a14180 (listing bound); next ObjC IMP 0x00a346c0 OwnershipSign -[updateText]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10567916, 'sub sp, sp, 8'), (10568060, 'bx lr')],
        calls=[],
        branches=[(10567944, 'beq', 10568044), (10567968, 'beq', 10568044), (10567992, 'beq', 10568044), (10568016, 'beq', 10568044)],
        semantics=('[tileIsBurnableBlock] (imp 0x00a140ec, 37w): tileIsBurnableBlock - typeIndex in {9, 0x15, 0x16, 0x17, 0x20} (the five burnable material codes).\n'),
    ),
    dict(
        name='hl_44',
        method='tileIsBurnable',
        types='',
        start=10568064,
        end=10568556,
        disasm='disasm_worldtileloader_hl_44.txt',
        base_add=10568080,
        base_literal=10568552,
        boundary='ARM.exidx end 0x00a1436c (listing bound); next ObjC IMP 0x00a346c0 OwnershipSign -[updateText]',
        selectors={
                 0xa14354: (15223868, 'interactionObjectAtPos:'),
                 0xa14360: (15223900, 'interactionObjectType'),
                 0xa14364: (15223904, 'itemType'),
        },
        imports={
                 0xa1435c: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(10568064, 'push {fp, lr}'), (10568552, 'rsbeq fp, r4, ip, asr sb')],
        calls=[(10568164, 'bl loc.imp.objc_msgSend'), (10568228, 'blx r2'), (10568284, 'blx r2'), (10568340, 'bl sym.tileIsWater_Tile_'), (10568368, 'bl sym.tileIsTree_Tile_'), (10568396, 'bl sym.tileIsDeadTree_Tile_'), (10568424, 'bl sym.tileIsBurnableBlock_Tile_'), (10568476, 'bl sym.tileIsPlant_Tile_')],
        branches=[(10568184, 'beq', 10568312), (10568240, 'bne', 10568312), (10568292, 'beq', 10568308), (10568304, 'b', 10568520), (10568308, 'b', 10568312), (10568332, 'beq', 10568508), (10568360, 'bne', 10568508), (10568388, 'bne', 10568500), (10568416, 'bne', 10568500), (10568444, 'bne', 10568500), (10568468, 'beq', 10568500)],
        semantics=('[tileIsBurnable] (imp 0x00a14180, 123w): tileIsBurnable - the interaction object at pos (interactionObjectType == 3 with itemType != 0xAA) OR the tile itself: not water && (tree / dead tree / burnable block / the \'B\' 0x42 foregroundContents marker / plant).\n'),
    ),
    dict(
        name='hl_45',
        method='baseTemperatureForWorldPos',
        types='',
        start=10571560,
        end=10572240,
        disasm='disasm_worldtileloader_hl_45.txt',
        base_add=10571576,
        base_literal=10572236,
        boundary='ARM.exidx end 0x00a155dc; body trimmed at the dynsym size (170 words)',
        selectors={
                 0xa151bc: (15223912, 'worldWidthMacro'),
        },
        imports={
                 0xa151b8: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(10571560, 'push {fp, lr}'), (10572236, 'strhteq sl, [r4], -0xb4')],
        calls=[(10571628, 'bl sym.customRulesBaseTemp_World_'), (10571720, 'blx r2'), (10571752, 'bl sym.imp.__wrap_fmodf'), (10571800, 'bl sym.customRulesPoleOffset_World_'), (10572116, 'bl sym.imp.cosf')],
        branches=[(10571884, 'bpl', 10571900), (10571896, 'b', 10571908), (10571940, 'ble', 10572012)],
        semantics=('[baseTemperatureForWorldPos] (imp 0x00a14f28, 170w): [read] the base climate - customRulesBaseTemp - hemi * customRulesPoleOffset - min(arg, 5.0) + argB * (1 - hemi*0.8) + cos(2pi*argA - pi) * 5.0 * (1 - hemi*0.8) - depth cooling (y > 512: (y-512)/512*50); hemi = |fmod(x/32/mw, 5) - 2|/2.\n'),
    ),
    dict(
        name='hl_46',
        method='currentTemperatureForTileAtWorldPos',
        types='',
        start=10572804,
        end=10573080,
        disasm='disasm_worldtileloader_hl_46.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a155dc; body trimmed at the dynsym size (69 words)',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10572804, 'push {fp, lr}'), (10573076, 'cdplo p12, 4, c12, c12, c13, 6')],
        calls=[(10572924, 'bl sym.baseTemperatureForWorldPos_intpair__float__float__float__World_')],
        branches=[],
        semantics=('[currentTemperatureForTileAtWorldPos] (imp 0x00a15404, 69w): [read] the tile temperature - baseTemperatureForWorldPos * cov + 20.0 * (1 - cov) + tile.artificialHeat; cov = sunLight/255 * 0.8 + 0.2 (the E119/E120 corrected field names).\n'),
    ),
    dict(
        name='hl_47',
        method='customRulesBaseTemp',
        types='',
        start=10570656,
        end=10571160,
        disasm='disasm_worldtileloader_hl_47.txt',
        base_add=10570672,
        base_literal=10571156,
        boundary='ARM.exidx end 0x00a155dc; body trimmed at the dynsym size (126 words)',
        selectors={
                 0xa14d80: (15223916, 'customRules'),
        },
        imports={
                 0xa14d84: (17151968, '__stack_chk_guard'),
        },
        ivars={},
        classes={},
        instructions=[(10570656, 'push {fp, lr}'), (10571156, 'rsbeq sl, r4, ip, lsr pc')],
        calls=[(10570748, 'bl loc.imp.objc_msgSend_stret'), (10570784, 'bl sym.imp.memset'), (10570852, 'bl loc.imp.objc_msgSend_stret'), (10570888, 'bl sym.imp.memset'), (10571132, 'bl sym.imp.__stack_chk_fail')],
        branches=[(10570732, 'beq', 10570756), (10570752, 'b', 10570788), (10570796, 'beq', 10571064), (10570836, 'beq', 10570860), (10570856, 'b', 10570892), (10570908, 'bhi', 10571056), (10570972, 'b', 10571080), (10570992, 'b', 10571080), (10571012, 'b', 10571080), (10571032, 'b', 10571080), (10571052, 'b', 10571080), (10571056, 'b', 10571060), (10571060, 'b', 10571064), (10571112, 'bne', 10571132)],
        semantics=('[customRulesBaseTemp] (imp 0x00a14ba0, 126w): [read] the custom-rules base temp - the climate byte switch {0:0.0, 1:1.0, 2:3.0, 3:37.0, 4:45.0}; default (no rules) 3.0.\n'),
    ),
    dict(
        name='hl_48',
        method='customRulesPoleOffset',
        types='',
        start=10571160,
        end=10571556,
        disasm='disasm_worldtileloader_hl_48.txt',
        base_add=10571176,
        base_literal=10571552,
        boundary='ARM.exidx end 0x00a155dc; body trimmed at the dynsym size (99 words)',
        selectors={
                 0xa14f14: (15223916, 'customRules'),
        },
        imports={
                 0xa14f18: (17151968, '__stack_chk_guard'),
        },
        ivars={},
        classes={},
        instructions=[(10571160, 'push {fp, lr}'), (10571552, 'rsbeq sl, r4, r4, asr 26')],
        calls=[(10571252, 'bl loc.imp.objc_msgSend_stret'), (10571288, 'bl sym.imp.memset'), (10571356, 'bl loc.imp.objc_msgSend_stret'), (10571392, 'bl sym.imp.memset'), (10571536, 'bl sym.imp.__stack_chk_fail')],
        branches=[(10571236, 'beq', 10571260), (10571256, 'b', 10571292), (10571300, 'beq', 10571468), (10571340, 'beq', 10571364), (10571360, 'b', 10571396), (10571420, 'bhi', 10571460), (10571432, 'bne', 10571440), (10571436, 'b', 10571460), (10571456, 'b', 10571484), (10571460, 'b', 10571464), (10571464, 'b', 10571468), (10571516, 'bne', 10571536)],
        semantics=('[customRulesPoleOffset] (imp 0x00a14d98, 99w): [read] the custom-rules pole offset - the climate byte {0,1,3,4}: 2.0; {2}: 45.0; default 45.0.\n'),
    ),
    dict(
        name='hl_49',
        method='seasonForWorldX',
        types='',
        start=10570312,
        end=10570656,
        disasm='disasm_worldtileloader_hl_49.txt',
        base_add=10570368,
        base_literal=10570648,
        boundary='ARM.exidx end 0x00a155dc; body trimmed at the dynsym size (86 words)',
        selectors={
                 0xa14b94: (15223912, 'worldWidthMacro'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(10570312, 'push {fp, lr}'), (10570652, 'rsbeq fp, r4, r8')],
        calls=[(10570392, 'bl loc.imp.objc_msgSend'), (10570496, 'bl loc.imp.objc_msgSend'), (10570552, 'bl sym.absoluteSeasonFraction_double_'), (10570592, 'bl sym.imp.__wrap_fmodf'), (10570616, 'bl sym.absoluteSeasonFraction_double_')],
        branches=[(10570436, 'ble', 10570608), (10570540, 'bpl', 10570608), (10570604, 'b', 10570628)],
        semantics=('[seasonForWorldX] (imp 0x00a14a48, 86w): [read] the season fraction - absoluteSeasonFraction(d), with the far-longitude band (x in (mw*64, mw*224)) passing through (abs + 5.0) mod 1.0; the worldWidthMacro-driven wrap.\n'),
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
        'batch': 'Fire + light + temperature (E120): FireObject/ArtificialLight/GlowBlock + the temperature C functions and the custom-rules climate; 50 bodies',
        'claim': ('the fire/light/temperature substrate; four giants are census-grade and the particle/draw internals stay outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'heatline.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale heatline.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
