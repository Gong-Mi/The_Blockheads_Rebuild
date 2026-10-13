#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The plants line closes: GemTree, the branching gem tree: the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 4471 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/GEM_TREE.md for the prose and boundaries.
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
    'bl 0x5290e8': 0x005290e8,
    'bl 0x5290f8': 0x005290f8,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl method.std::__1::__hash_const_iterator_std::__1::__hash_node_int__void__const__std::__1::__hash_table_int__std::__1::hash_int___std::__1::equal_to_int___std::__1::allocator_int___.find_int__int_const__const': 0x0052d5ac,
    'bl method.std::__1::__hash_table_int__std::__1::hash_int___std::__1::equal_to_int___std::__1::allocator_int___.__insert_unique_int_const_': 0x0052be60,
    'bl method.std::__1::unordered_set_int__std::__1::hash_int___std::__1::equal_to_int___std::__1::allocator_int___._unordered_set__': 0x0052b6e8,
    'bl method.std::__1::vector_intpair__std::__1::allocator_intpair___._vector__': 0x0052b718,
    'bl method.void_std::__1::vector_intpair__std::__1::allocator_intpair___.__push_back_slow_path_intpair_const__intpair_const_': 0x0052d84c,
    'bl sym.clampi_int__int__int_': 0x004c0b70,
    'bl sym.imp._Unwind_Resume': 0x001c29c0,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__modsi3': 0x001c3020,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_': 0x00a1915c,
    'bl sym.seasonForWorldX_int__double__World_': 0x00a14a48,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileAtWorldPosition_int__int__MacroTile__World_': 0x00a16e68,
    'bl sym.tileIsSolid_Tile_': 0x00a1179c,
    'bl sym.tileIsTree_Tile_': 0x00a13214,
    'bl sym.worldIndexAtWorldPosition_int__int__World_': 0x00a156a8,
}

SPECS = [
    dict(
        name='g_objecttype',
        method='GemTree -[objectType]',
        types='i8@0:4',
        start=5404084,
        end=5404112,
        disasm='disasm_worldtileloader_g_objecttype.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x005275d0 (listing bound); next ObjC IMP 0x005275d0 GemTree -[fruitItemType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(5404084, 'sub sp, sp, 8'), (5404108, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[GemTree objectType] (imp 0x005275b4, 7w): the object-type constant.\n'),
    ),
    dict(
        name='g_fruititem',
        method='GemTree -[fruitItemType]',
        types='i8@0:4',
        start=5404112,
        end=5404192,
        disasm='disasm_worldtileloader_g_fruititem.txt',
        base_add=5404128,
        base_literal=5404184,
        boundary='ARM.exidx end 0x00527620 (listing bound); next ObjC IMP 0x00527620 GemTree -[fruitShouldFallInSeason:]',
        selectors={
                 0x527614: (15194432, 'gemItemType'),
        },
        imports={
                 0x527610: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(5404112, 'push {fp, lr}'), (5404188, 'andeq r0, r0, r0')],
        calls=[(5404164, 'blx r3')],
        branches=[],
        semantics=('[GemTree fruitItemType] (imp 0x005275d0, 20w): the fruit item.\n'),
    ),
    dict(
        name='g_fruitseason',
        method='GemTree -[fruitShouldFallInSeason:]',
        types='c12@0:4i8',
        start=5404192,
        end=5404460,
        disasm='disasm_worldtileloader_g_fruitseason.txt',
        base_add=5404208,
        base_literal=5404456,
        boundary='ARM.exidx end 0x0052772c (listing bound); next ObjC IMP 0x0052772c GemTree -[shouldAddFallenFruits]',
        selectors={
                 0x527720: (15194436, 'worldTime'),
        },
        imports={
                 0x52771c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x527718: (17155712, 'OBJC_IVAR_$_GemTree.fruitYear', 140),
                 0x527724: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(5404192, 'push {r4, r5, r6, r7, fp, lr}'), (5404456, 'ldrhteq r8, [r3], ip')],
        calls=[(5404304, 'blx r5'), (5404348, 'bl sym.imp.__modsi3')],
        branches=[(5404376, 'bne', 5404408), (5404404, 'b', 5404416)],
        semantics=('[GemTree fruitShouldFallInSeason:] (imp 0x00527620, 67w): the fruit season gate - const **0xe10 (3600)** + `__modsi3`: the season clock on the 3600-domain.\n'),
    ),
    dict(
        name='g_shouldfall',
        method='GemTree -[shouldAddFallenFruits]',
        types='c8@0:4',
        start=5404460,
        end=5404488,
        disasm='disasm_worldtileloader_g_shouldfall.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00527748 (listing bound); next ObjC IMP 0x00527748 GemTree -[initWithWorld:dynamicWorld:atPosition:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:gemTreeType:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(5404460, 'sub sp, sp, 8'), (5404484, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[GemTree shouldAddFallenFruits] (imp 0x0052772c, 7w): the fallen-fruit flag.\n'),
    ),
    dict(
        name='g_ctor',
        method='GemTree -[initWithWorld:dynamicWorld:atPosition:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:gemTreeType:]',
        types='@40@0:4@8@12{?=ii}16@24@28@32i36',
        start=5404488,
        end=5411048,
        disasm='disasm_worldtileloader_g_ctor.txt',
        base_add=5404504,
        base_literal=5408208,
        boundary='ARM.exidx end 0x005290e8 (listing bound); next ObjC IMP 0x00529134 GemTree -[initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:]',
        selectors={
                 0x5287ac: (15194440, 'initStaticTreeWithWorld:dynamicWorld:atPosition:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:'),
                 0x5287f8: (15194448, 'getX:Y:octaves:'),
                 0x528900: (15194444, 'worldWidthMacro'),
                 0x528d7c: (15194452, 'worldContentsChangedAtPos:'),
                 0x528d80: (15194456, 'trunkContentsType'),
                 0x5290ac: (15194476, 'macroTiles'),
                 0x5290c4: (15194460, 'objectType'),
                 0x5290c8: (15194464, 'dynamicWorldChangedAtPos:objectType:'),
                 0x5290cc: (15194456, 'trunkContentsType'),
                 0x5290d0: (15194468, 'trunkBushContentsType'),
                 0x5290d4: (15194472, 'bushContentsType'),
                 0x5290dc: (15194452, 'worldContentsChangedAtPos:'),
        },
        imports={
                 0x5287f4: (17151904, 'objc_msgSend'),
                 0x52909c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5287fc: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x528800: (17155716, 'OBJC_IVAR_$_GemTree.gemTreeType', 136),
                 0x528808: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0x5288f8: (17155712, 'OBJC_IVAR_$_GemTree.fruitYear', 140),
                 0x5288fc: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x528904: (17155028, 'OBJC_IVAR_$_Tree.seasonOffsetNoiseFunction', 80),
                 0x528a08: (17155096, 'OBJC_IVAR_$_Tree.treeSeasonOffset', 84),
                 0x528a0c: (17155032, 'OBJC_IVAR_$_Tree.treeDensityNoiseFunction', 76),
                 0x528d74: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x528d84: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0x5290a0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x5290a4: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0x5290a8: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x5290b4: (17155056, 'OBJC_IVAR_$_Tree.fruitCount', 128),
                 0x5290bc: (17155036, 'OBJC_IVAR_$_Tree.treeFruits', 124),
                 0x5290c0: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x5290e0: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
        },
        classes={
                 0x5287a4: (15252564, 'OBJC_CLASS_$_GemTree'),
        },
        instructions=[(5404488, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5411044, 'adcseq r7, r3, r4, ror 19')],
        calls=[(5404704, 'bl loc.imp.objc_msgSendSuper2'), (5404904, 'bl 0x5290e8'), (5405032, 'bl loc.imp.objc_msgSend'), (5405124, 'bl loc.imp.objc_msgSend'), (5405216, 'bl loc.imp.objc_msgSend'), (5405344, 'bl loc.imp.objc_msgSend'), (5405460, 'blx lr'), (5405516, 'bl sym.clampi_int__int__int_'), (5405700, 'bl sym.makeIntpair_int__int_'), (5406032, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5406076, 'bl sym.tileIsSolid_Tile_'), (5406112, 'bl sym.tileIsTree_Tile_'), (5406200, 'bl sym.imp.__aeabi_idiv'), (5406236, 'bl 0x5290e8'), (5406444, 'bl sym.imp.__aeabi_idiv'), (5406588, 'bl loc.imp.objc_msgSend'), (5406608, 'bl loc.imp.objc_msgSend'), (5406808, 'bl sym.makeIntpair_int__int_'), (5406860, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5406904, 'bl sym.tileIsSolid_Tile_'), (5406940, 'bl sym.tileIsTree_Tile_'), (5407044, 'bl loc.imp.objc_msgSend'), (5407064, 'bl loc.imp.objc_msgSend'), (5407148, 'bl 0x5290e8'), (5407196, 'bl 0x5290e8'), (5407408, 'bl sym.imp.__aeabi_idiv'), (5407428, 'bl sym.imp.__aeabi_idiv'), (5407452, 'bl sym.clampi_int__int__int_'), (5407476, 'bl 0x5290f8'), (5407756, 'bl sym.imp.__aeabi_idiv'), (5407776, 'bl sym.imp.__aeabi_idiv'), (5407800, 'bl sym.clampi_int__int__int_'), (5407872, 'bl 0x5290f8'), (5408132, 'bl sym.clampi_int__int__int_'), (5408336, 'bl sym.makeIntpair_int__int_'), (5408388, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5408496, 'bl 0x5290e8'), (5408568, 'bl 0x5290e8'), (5408848, 'bl 0x5290e8'), (5408916, 'bl 0x5290f8'), (5409136, 'bl sym.makeIntpair_int__int_'), (5409188, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5409232, 'bl sym.tileIsSolid_Tile_'), (5409268, 'bl sym.tileIsTree_Tile_'), (5409356, 'bl 0x5290e8'), (5409600, 'bl loc.imp.objc_msgSend'), (5409636, 'bl loc.imp.objc_msgSend'), (5409696, 'blx r2'), (5409764, 'blx r2'), (5409820, 'blx r2'), (5409876, 'blx r2'), (5409960, 'bl loc.imp.objc_msgSend'), (5410284, 'bl sym.makeIntpair_int__int_'), (5410372, 'bl sym.makeIntpair_int__int_'), (5410460, 'blx r3'), (5410516, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (5410604, 'blx r3'), (5410660, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (5410748, 'blx r3'), (5410804, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (5410892, 'blx r3'), (5410948, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_')],
        branches=[(5404732, 'bne', 5404748), (5404744, 'b', 5410960), (5405576, 'bge', 5408212), (5405604, 'bge', 5408188), (5405744, 'bge', 5405764), (5405756, 'b', 5405772), (5405840, 'bge', 5405856), (5405852, 'b', 5405864), (5405932, 'bge', 5405968), (5405944, 'b', 5405976), (5406052, 'beq', 5406140), (5406068, 'bne', 5406128), (5406088, 'bne', 5406128), (5406104, 'beq', 5406136), (5406124, 'bne', 5406136), (5406128, 'b', 5408188), (5406136, 'b', 5406140), (5406340, 'bge', 5406356), (5406352, 'b', 5406396), (5406364, 'ble', 5406380), (5406376, 'b', 5406388), (5406480, 'bge', 5406496), (5406492, 'b', 5406504), (5406668, 'ble', 5407148), (5406692, 'bge', 5407144), (5406880, 'beq', 5407120), (5406896, 'bne', 5406956), (5406916, 'bne', 5406956), (5406932, 'beq', 5406960), (5406952, 'bne', 5406960), (5406956, 'b', 5407116), (5407116, 'b', 5407120), (5407120, 'b', 5407124), (5407136, 'b', 5406680), (5407144, 'b', 5407148), (5407256, 'bgt', 5407300), (5407296, 'bge', 5407628), (5407468, 'ble', 5407580), (5407484, 'ble', 5407580), (5407496, 'bge', 5407580), (5407624, 'b', 5408168), (5407644, 'bgt', 5407688), (5407684, 'bge', 5408024), (5407816, 'bne', 5407856), (5407864, 'ble', 5407976), (5407880, 'ble', 5407976), (5407892, 'bge', 5407976), (5408020, 'b', 5408164), (5408164, 'b', 5408168), (5408168, 'b', 5408172), (5408184, 'b', 5405592), (5408188, 'b', 5408192), (5408204, 'b', 5405564), (5408236, 'bge', 5410200), (5408408, 'beq', 5410144), (5408432, 'bge', 5410140), (5408660, 'bge', 5408688), (5408672, 'b', 5408696), (5408740, 'bge', 5408780), (5408752, 'b', 5408788), (5408844, 'bge', 5410120), (5409000, 'bge', 5409032), (5409012, 'b', 5409040), (5409080, 'bge', 5410100), (5409208, 'beq', 5410080), (5409224, 'bne', 5409284), (5409244, 'bne', 5409284), (5409260, 'beq', 5409304), (5409280, 'bne', 5409304), (5409284, 'b', 5410100), (5409336, 'bge', 5409644), (5409352, 'bne', 5409644), (5409400, 'ble', 5409640), (5409640, 'b', 5409644), (5409708, 'beq', 5409780), (5409776, 'bne', 5409836), (5409832, 'b', 5409888), (5410040, 'bge', 5410056), (5410052, 'b', 5410064), (5410080, 'b', 5410084), (5410096, 'b', 5409068), (5410100, 'b', 5410104), (5410116, 'b', 5408820), (5410120, 'b', 5410124), (5410136, 'b', 5408424), (5410140, 'b', 5410144), (5410144, 'b', 5410148), (5410160, 'b', 5408224)],
        semantics=('[GemTree initWithWorld:dynamicWorld:atPosition:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:gemTreeType:] (imp 0x00527748, 1640w): the mega-ctor - objc x11 + the helper **0x5290e8 x8** (the gem-tree local) + makeIntpair x6 + `__aeabi_idiv` x6 + **`clampi` x4** (the gene clamps) + `tileAtWorldPositionLoaded` x4 + **`reloadDrawBlock...`** + consts 0x18/0x400/0xff + cmps 0xff/0x40: the gem tree type drives the gene clamps and the placement walk.\n'),
    ),
    dict(
        name='g_growth',
        method='GemTree -[updateGrowth:]',
        types='v12@0:4c8',
        start=5412216,
        end=5412240,
        disasm='disasm_worldtileloader_g_growth.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00529590 (listing bound); next ObjC IMP 0x00529590 GemTree -[bushContentsType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(5412216, 'sub sp, sp, 0xc'), (5412236, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[GemTree updateGrowth:] (imp 0x00529578, 6w): the growth hook (empty - the gem tree grows via update).\n'),
    ),
    dict(
        name='g_bushcontents',
        method='GemTree -[bushContentsType]',
        types='i8@0:4',
        start=5412240,
        end=5412792,
        disasm='disasm_worldtileloader_g_bushcontents.txt',
        base_add=5412264,
        base_literal=5412420,
        boundary='ARM.exidx end 0x005297b8 (listing bound); next ObjC IMP 0x00529648 GemTree -[trunkContentsType]',
        selectors={},
        imports={},
        ivars={
                 0x529640: (17155716, 'OBJC_IVAR_$_GemTree.gemTreeType', 136),
                 0x5296f8: (17155716, 'OBJC_IVAR_$_GemTree.gemTreeType', 136),
                 0x5297b0: (17155716, 'OBJC_IVAR_$_GemTree.gemTreeType', 136),
        },
        classes={},
        instructions=[(5412240, 'sub sp, sp, 0x10'), (5412788, 'ldrsbteq r6, [r3], r4')],
        calls=[],
        branches=[(5412292, 'bhi', 5412396), (5412344, 'b', 5412404), (5412356, 'b', 5412404), (5412368, 'b', 5412404), (5412380, 'b', 5412404), (5412392, 'b', 5412404), (5412476, 'bhi', 5412580), (5412528, 'b', 5412588), (5412540, 'b', 5412588), (5412552, 'b', 5412588), (5412564, 'b', 5412588), (5412576, 'b', 5412588), (5412660, 'bhi', 5412764), (5412712, 'b', 5412772), (5412724, 'b', 5412772), (5412736, 'b', 5412772), (5412748, 'b', 5412772), (5412760, 'b', 5412772)],
        semantics=('[GemTree bushContentsType] (imp 0x00529590, 138w): the bush contents ladder - a 12-const table **{0x6e,0x71,0x74,0x77,0x7a,0x6d,0x70,0x73,0x76,0x79,0x6f,0x72}** (the 0x6d..0x7b family, 3-apart ladders = the gem-content codes).\n'),
    ),
    dict(
        name='g_trunkcontents',
        method='GemTree -[trunkContentsType]',
        types='i8@0:4',
        start=5412424,
        end=5412792,
        disasm='disasm_worldtileloader_g_trunkcontents.txt',
        base_add=5412448,
        base_literal=5412604,
        boundary='ARM.exidx end 0x005297b8 (listing bound); next ObjC IMP 0x00529700 GemTree -[trunkBushContentsType]',
        selectors={},
        imports={},
        ivars={
                 0x5296f8: (17155716, 'OBJC_IVAR_$_GemTree.gemTreeType', 136),
                 0x5297b0: (17155716, 'OBJC_IVAR_$_GemTree.gemTreeType', 136),
        },
        classes={},
        instructions=[(5412424, 'sub sp, sp, 0x10'), (5412788, 'ldrsbteq r6, [r3], r4')],
        calls=[],
        branches=[(5412476, 'bhi', 5412580), (5412528, 'b', 5412588), (5412540, 'b', 5412588), (5412552, 'b', 5412588), (5412564, 'b', 5412588), (5412576, 'b', 5412588), (5412660, 'bhi', 5412764), (5412712, 'b', 5412772), (5412724, 'b', 5412772), (5412736, 'b', 5412772), (5412748, 'b', 5412772), (5412760, 'b', 5412772)],
        semantics=('[GemTree trunkContentsType] (imp 0x00529648, 92w): the trunk contents ladder - **{0x6d,0x70,0x73,0x76,0x79,0x6f,0x72,0x75,0x78,0x7b}**.\n'),
    ),
    dict(
        name='g_trunkbushcontents',
        method='GemTree -[trunkBushContentsType]',
        types='i8@0:4',
        start=5412608,
        end=5412792,
        disasm='disasm_worldtileloader_g_trunkbushcontents.txt',
        base_add=5412632,
        base_literal=5412788,
        boundary='ARM.exidx end 0x005297b8 (listing bound); next ObjC IMP 0x005297b8 GemTree -[makeTileDead:]',
        selectors={},
        imports={},
        ivars={
                 0x5297b0: (17155716, 'OBJC_IVAR_$_GemTree.gemTreeType', 136),
        },
        classes={},
        instructions=[(5412608, 'sub sp, sp, 0x10'), (5412788, 'ldrsbteq r6, [r3], r4')],
        calls=[],
        branches=[(5412660, 'bhi', 5412764), (5412712, 'b', 5412772), (5412724, 'b', 5412772), (5412736, 'b', 5412772), (5412748, 'b', 5412772), (5412760, 'b', 5412772)],
        semantics=('[GemTree trunkBushContentsType] (imp 0x00529700, 46w): the trunk-bush ladder - **{0x6f,0x72,0x75,0x78,0x7b}**.\n'),
    ),
    dict(
        name='g_makedead',
        method='GemTree -[makeTileDead:]',
        types='v12@0:4^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}8',
        start=5412792,
        end=5413088,
        disasm='disasm_worldtileloader_g_makedead.txt',
        base_add=5412808,
        base_literal=5413080,
        boundary='ARM.exidx end 0x005298e0 (listing bound); next ObjC IMP 0x005298e0 GemTree -[update:accurateDT:isSimulation:]',
        selectors={
                 0x5298cc: (15194456, 'trunkContentsType'),
                 0x5298d0: (15194468, 'trunkBushContentsType'),
                 0x5298d4: (15194472, 'bushContentsType'),
        },
        imports={
                 0x5298c8: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(5412792, 'push {fp, lr}'), (5413084, 'andeq r0, r0, r0')],
        calls=[(5412872, 'blx ip'), (5412940, 'blx r2'), (5413024, 'blx r2')],
        branches=[(5412884, 'beq', 5412956), (5412952, 'bne', 5412972), (5412968, 'b', 5413056), (5413036, 'bne', 5413052), (5413052, 'b', 5413056)],
        semantics=("[GemTree makeTileDead:] (imp 0x005297b8, 74w): the dead markers **0x1d/0x22** (the gem tree's stage->dead pair, matching the kindself set).\n"),
    ),
    dict(
        name='g_update',
        method='GemTree -[update:accurateDT:isSimulation:]',
        types='v20@0:4f8f12c16',
        start=5413088,
        end=5415032,
        disasm='disasm_worldtileloader_g_update.txt',
        base_add=5413104,
        base_literal=5415028,
        boundary='ARM.exidx end 0x0052a078 (listing bound); next ObjC IMP 0x0052a078 GemTree -[worldChanged:]',
        selectors={
                 0x52a018: (15194508, 'update:accurateDT:isSimulation:'),
                 0x52a02c: (15194436, 'worldTime'),
                 0x52a03c: (15194476, 'macroTiles'),
                 0x52a044: (15194512, 'tileIsKindOfSelf:'),
                 0x52a058: (15194460, 'objectType'),
                 0x52a05c: (15194464, 'dynamicWorldChangedAtPos:objectType:'),
                 0x52a06c: (15194432, 'gemItemType'),
                 0x52a070: (15194516, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
        },
        imports={
                 0x52a014: (17151900, 'objc_msgSendSuper2'),
                 0x52a028: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x52a020: (17155068, 'OBJC_IVAR_$_Tree.dead', 104),
                 0x52a024: (17155712, 'OBJC_IVAR_$_GemTree.fruitYear', 140),
                 0x52a030: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x52a034: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x52a038: (17155056, 'OBJC_IVAR_$_Tree.fruitCount', 128),
                 0x52a040: (17155036, 'OBJC_IVAR_$_Tree.treeFruits', 124),
                 0x52a048: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0x52a054: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={
                 0x52a01c: (15252564, 'OBJC_CLASS_$_GemTree'),
        },
        instructions=[(5413088, 'push {r4, r5, r6, r7, fp, lr}'), (5415028, 'ldrshteq r6, [r3], ip')],
        calls=[(5413244, 'blx lr'), (5413380, 'blx r3'), (5413424, 'bl sym.imp.__modsi3'), (5413556, 'blx r2'), (5413608, 'bl sym.seasonForWorldX_int__double__World_'), (5413800, 'blx r2'), (5413844, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (5413916, 'blx r3'), (5414092, 'bl sym.imp.__modsi3'), (5414236, 'bl loc.imp.objc_msgSend'), (5414308, 'bl loc.imp.objc_msgSend'), (5414376, 'bl loc.imp.objc_msgSend'), (5414412, 'bl loc.imp.objc_msgSend'), (5414528, 'bl loc.imp.objc_msgSend'), (5414564, 'bl loc.imp.objc_msgSend'), (5414852, 'bl loc.imp.objc_msgSend'), (5414888, 'bl loc.imp.objc_msgSend')],
        branches=[(5413280, 'bne', 5414924), (5413452, 'bne', 5414920), (5413456, 'b', 5413472), (5413668, 'bge', 5414916), (5413864, 'beq', 5414896), (5413928, 'beq', 5414576), (5413992, 'bne', 5414576), (5413996, 'b', 5414000), (5414108, 'beq', 5414124), (5414120, 'bne', 5414420), (5414136, 'bne', 5414416), (5414416, 'b', 5414572), (5414432, 'beq', 5414568), (5414568, 'b', 5414572), (5414572, 'b', 5414892), (5414624, 'bge', 5414744), (5414740, 'b', 5414584), (5414892, 'b', 5414896), (5414896, 'b', 5414900), (5414912, 'b', 5413632), (5414916, 'b', 5414920), (5414920, 'b', 5414924)],
        semantics=('[GemTree update:accurateDT:isSimulation:] (imp 0x005298e0, 486w): the tick - objc x8 + **`seasonForWorldX`** + `__modsi3` x2 + `tileAtWorldPosition` + consts **0xe10 (3600 - the season/growth clock!)/0xc**.\n'),
    ),
    dict(
        name='g_worldchanged',
        method='GemTree -[worldChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=5415032,
        end=5420776,
        disasm='disasm_worldtileloader_g_worldchanged.txt',
        base_add=5415052,
        base_literal=5416776,
        boundary='ARM.exidx end 0x0052b6e8 (listing bound); next ObjC IMP 0x0052b750 GemTree -[recursivelyAddOwnedTile:toPositions:]',
        selectors={
                 0x52a764: (15194512, 'tileIsKindOfSelf:'),
                 0x52b634: (15194520, 'isRequiredSoilType:'),
                 0x52b640: (15194524, 'recursivelyAddOwnedTile:toPositions:'),
                 0x52b654: (15194512, 'tileIsKindOfSelf:'),
                 0x52b668: (15194528, 'removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:'),
                 0x52b67c: (15194432, 'gemItemType'),
                 0x52b680: (15194516, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
        },
        imports={},
        ivars={
                 0x52a74c: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0x52a750: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x52a75c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x52b628: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x52b630: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x52b64c: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0x52b674: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={},
        instructions=[(5415032, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5420772, 'adcseq r4, r3, ip, lsl 11')],
        calls=[(5415604, 'bl 0x5290f8'), (5415704, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5415764, 'bl loc.imp.objc_msgSend'), (5416080, 'bl method.void_std::__1::vector_intpair__std::__1::allocator_intpair___.__push_back_slow_path_intpair_const__intpair_const_'), (5416224, 'bl sym.imp.__aeabi_idiv'), (5416572, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5416636, 'bl loc.imp.objc_msgSend'), (5416736, 'bl loc.imp.objc_msgSend'), (5416764, 'bl method.std::__1::unordered_set_int__std::__1::hash_int___std::__1::equal_to_int___std::__1::allocator_int___._unordered_set__'), (5417108, 'bl sym.makeIntpair_int__int_'), (5417152, 'bl sym.worldIndexAtWorldPosition_int__int__World_'), (5417216, 'bl method.std::__1::__hash_const_iterator_std::__1::__hash_node_int__void__const__std::__1::__hash_table_int__std::__1::hash_int___std::__1::equal_to_int___std::__1::allocator_int___.find_int__int_const__const'), (5417368, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5417512, 'bl loc.imp.objc_msgSend'), (5417588, 'bl 0x5290e8'), (5417692, 'bl loc.imp.objc_msgSend'), (5417700, 'bl 0x5290e8'), (5417816, 'bl loc.imp.objc_msgSend'), (5417900, 'bl loc.imp.objc_msgSend'), (5417936, 'bl sym.makeIntpair_int__int_'), (5417996, 'bl sym.worldIndexAtWorldPosition_int__int__World_'), (5418060, 'bl method.std::__1::__hash_const_iterator_std::__1::__hash_node_int__void__const__std::__1::__hash_table_int__std::__1::hash_int___std::__1::equal_to_int___std::__1::allocator_int___.find_int__int_const__const'), (5418212, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5418356, 'bl loc.imp.objc_msgSend'), (5418432, 'bl 0x5290e8'), (5418536, 'bl loc.imp.objc_msgSend'), (5418560, 'bl 0x5290e8'), (5418676, 'bl loc.imp.objc_msgSend'), (5418760, 'bl loc.imp.objc_msgSend'), (5418796, 'bl sym.makeIntpair_int__int_'), (5418856, 'bl sym.worldIndexAtWorldPosition_int__int__World_'), (5418920, 'bl method.std::__1::__hash_const_iterator_std::__1::__hash_node_int__void__const__std::__1::__hash_table_int__std::__1::hash_int___std::__1::equal_to_int___std::__1::allocator_int___.find_int__int_const__const'), (5419072, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5419216, 'bl loc.imp.objc_msgSend'), (5419292, 'bl 0x5290e8'), (5419396, 'bl loc.imp.objc_msgSend'), (5419404, 'bl 0x5290e8'), (5419520, 'bl loc.imp.objc_msgSend'), (5419604, 'bl loc.imp.objc_msgSend'), (5419640, 'bl sym.makeIntpair_int__int_'), (5419700, 'bl sym.worldIndexAtWorldPosition_int__int__World_'), (5419764, 'bl method.std::__1::__hash_const_iterator_std::__1::__hash_node_int__void__const__std::__1::__hash_table_int__std::__1::hash_int___std::__1::equal_to_int___std::__1::allocator_int___.find_int__int_const__const'), (5419916, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5420060, 'bl loc.imp.objc_msgSend'), (5420136, 'bl 0x5290e8'), (5420240, 'bl loc.imp.objc_msgSend'), (5420248, 'bl 0x5290e8'), (5420364, 'bl loc.imp.objc_msgSend'), (5420448, 'bl loc.imp.objc_msgSend'), (5420536, 'bl method.std::__1::unordered_set_int__std::__1::hash_int___std::__1::equal_to_int___std::__1::allocator_int___._unordered_set__'), (5420548, 'bl method.std::__1::vector_intpair__std::__1::allocator_intpair___._vector__'), (5420568, 'bl method.std::__1::vector_intpair__std::__1::allocator_intpair___._vector__'), (5420580, 'bl sym.imp._Unwind_Resume')],
        branches=[(5415420, 'beq', 5416184), (5415520, 'bgt', 5416120), (5415564, 'blt', 5416120), (5415612, 'b', 5415616), (5415664, 'bge', 5416116), (5415712, 'b', 5415716), (5415736, 'beq', 5416112), (5415772, 'b', 5415776), (5415788, 'bne', 5416112), (5415860, 'beq', 5416072), (5416008, 'beq', 5416052), (5416068, 'b', 5416092), (5416084, 'b', 5416088), (5416088, 'b', 5416092), (5416092, 'b', 5416096), (5416096, 'b', 5416112), (5416108, 'b', 5420564), (5416112, 'b', 5416116), (5416116, 'b', 5416120), (5416120, 'b', 5416124), (5416180, 'b', 5415268), (5416232, 'bls', 5420544), (5416580, 'b', 5416584), (5416604, 'beq', 5416824), (5416644, 'b', 5416648), (5416660, 'beq', 5416824), (5416740, 'b', 5416744), (5416744, 'b', 5416824), (5416772, 'b', 5420564), (5417060, 'beq', 5420532), (5417112, 'b', 5417116), (5417160, 'b', 5417164), (5417328, 'bne', 5417920), (5417376, 'b', 5417380), (5417400, 'beq', 5417916), (5417464, 'bne', 5417916), (5417468, 'b', 5417472), (5417484, 'bne', 5417916), (5417520, 'b', 5417524), (5417536, 'beq', 5417916), (5417596, 'b', 5417600), (5417696, 'b', 5417700), (5417708, 'b', 5417712), (5417744, 'ble', 5417912), (5417824, 'b', 5417828), (5417904, 'b', 5417908), (5417908, 'b', 5417912), (5417912, 'b', 5417916), (5417916, 'b', 5417920), (5417940, 'b', 5417944), (5418004, 'b', 5418008), (5418172, 'bne', 5418780), (5418220, 'b', 5418224), (5418244, 'beq', 5418776), (5418308, 'bne', 5418776), (5418312, 'b', 5418316), (5418328, 'bne', 5418776), (5418364, 'b', 5418368), (5418380, 'beq', 5418776), (5418440, 'b', 5418444), (5418540, 'b', 5418560), (5418544, 'b', 5418560), (5418568, 'b', 5418572), (5418604, 'ble', 5418772), (5418684, 'b', 5418688), (5418764, 'b', 5418768), (5418768, 'b', 5418772), (5418772, 'b', 5418776), (5418776, 'b', 5418780), (5418800, 'b', 5418804), (5418864, 'b', 5418868), (5419032, 'bne', 5419624), (5419080, 'b', 5419084), (5419104, 'beq', 5419620), (5419168, 'bne', 5419620), (5419172, 'b', 5419176), (5419188, 'bne', 5419620), (5419224, 'b', 5419228), (5419240, 'beq', 5419620), (5419300, 'b', 5419304), (5419400, 'b', 5419404), (5419412, 'b', 5419416), (5419448, 'ble', 5419616), (5419528, 'b', 5419532), (5419608, 'b', 5419612), (5419612, 'b', 5419616), (5419616, 'b', 5419620), (5419620, 'b', 5419624), (5419644, 'b', 5419648), (5419708, 'b', 5419712), (5419876, 'bne', 5420468), (5419924, 'b', 5419928), (5419948, 'beq', 5420464), (5420012, 'bne', 5420464), (5420016, 'b', 5420020), (5420032, 'bne', 5420464), (5420068, 'b', 5420072), (5420084, 'beq', 5420464), (5420144, 'b', 5420148), (5420244, 'b', 5420248), (5420256, 'b', 5420260), (5420292, 'ble', 5420460), (5420372, 'b', 5420376), (5420452, 'b', 5420456), (5420456, 'b', 5420460), (5420460, 'b', 5420464), (5420464, 'b', 5420468), (5420468, 'b', 5420472), (5420528, 'b', 5416908)],
        semantics=('[GemTree worldChanged:] (imp 0x0052a078, 1436w): the giant re-check - objc x19 + the helper 0x5290e8 x8 + `tileAtWorldPositionLoaded` x6 + makeIntpair x4 + **`worldIndexAtWorldPosition` x4** + the **tile-search (`find(...)`)** + const 0x3f80 (1.0f): the gem tree re-resolves its trunk/stalk tiles through the world-index lookup.\n'),
    ),
    dict(
        name='g_recursivetiles',
        method='GemTree -[recursivelyAddOwnedTile:toPositions:]',
        types='v20@0:4{?=ii}8^{unordered_set<int, std::__1::hash<int>, std::__1::equal_to<int>, std::__1::allocator<int> >={__hash_table<int, std::__1::hash<int>, std::__1::equal_to<int>, std::__1::allocator<int> >={unique_ptr<std::__1::__hash_node<int, void *> *[], std::__1::__bucket_list_deallocator<std::__1::allocator<std::__1::__hash_node<int, void *> *> > >={__compressed_pair<std::__1::__hash_node<int, void *> **, std::__1::__bucket_list_deallocator<std::__1::allocator<std::__1::__hash_node<int, void *> *> > >=^^{__hash_node<int, void *>}{__bucket_list_deallocator<std::__1::allocator<std::__1::__hash_node<int, void *> *> >={__compressed_pair<unsigned long, std::__1::allocator<std::__1::__hash_node<int, void *> *> >=L}}}}{__compressed_pair<std::__1::__hash_node_base<std::__1::__hash_node<int, void *> *>, std::__1::allocator<std::__1::__hash_node<int, void *> > >={__hash_node_base<std::__1::__hash_node<int, void *> *>=^{__hash_node<int, void *>}}}{__compressed_pair<unsigned long, std::__1::hash<int> >=L}{__compressed_pair<float, std::__1::equal_to<int> >=f}}}16',
        start=5420880,
        end=5421796,
        disasm='disasm_worldtileloader_g_recursivetiles.txt',
        base_add=5420896,
        base_literal=5421792,
        boundary='ARM.exidx end 0x0052bae4 (listing bound); next ObjC IMP 0x0052bae4 GemTree -[treeType]',
        selectors={
                 0x52bacc: (15194512, 'tileIsKindOfSelf:'),
                 0x52bad8: (15194524, 'recursivelyAddOwnedTile:toPositions:'),
        },
        imports={
                 0x52bac8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x52bac4: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x52bad0: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
        },
        classes={},
        instructions=[(5420880, 'push {r4, sl, fp, lr}'), (5421792, 'adcseq r4, r3, ip, lsl 7')],
        calls=[(5420960, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5421008, 'bl sym.worldIndexAtWorldPosition_int__int__World_'), (5421080, 'blx r3'), (5421208, 'bl method.std::__1::__hash_const_iterator_std::__1::__hash_node_int__void__const__std::__1::__hash_table_int__std::__1::hash_int___std::__1::equal_to_int___std::__1::allocator_int___.find_int__int_const__const'), (5421360, 'bl method.std::__1::__hash_table_int__std::__1::hash_int___std::__1::equal_to_int___std::__1::allocator_int___.__insert_unique_int_const_'), (5421472, 'bl sym.makeIntpair_int__int_'), (5421536, 'bl loc.imp.objc_msgSend'), (5421568, 'bl sym.makeIntpair_int__int_'), (5421608, 'bl loc.imp.objc_msgSend'), (5421640, 'bl sym.makeIntpair_int__int_'), (5421680, 'bl loc.imp.objc_msgSend'), (5421712, 'bl sym.makeIntpair_int__int_'), (5421752, 'bl loc.imp.objc_msgSend')],
        branches=[(5421028, 'beq', 5421756), (5421092, 'beq', 5421756), (5421156, 'bne', 5421756), (5421160, 'b', 5421164), (5421312, 'bne', 5421756)],
        semantics=('[GemTree recursivelyAddOwnedTile:toPositions:] (imp 0x0052b750, 229w): the recursive tile adder - makeIntpair x4 + objc x4 + `worldIndexAtWorldPosition` + the tile-search `find(...)`: the gem tree owns a tile set built recursively (the branching structure!).\n'),
    ),
    dict(
        name='g_treetype',
        method='GemTree -[treeType]',
        types='i8@0:4',
        start=5421796,
        end=5421856,
        disasm='disasm_worldtileloader_g_treetype.txt',
        base_add=5421804,
        base_literal=5421852,
        boundary='ARM.exidx end 0x0052bb20 (listing bound); next ObjC IMP 0x0052bb20 GemTree -[gemItemType]',
        selectors={},
        imports={},
        ivars={
                 0x52bb18: (17155716, 'OBJC_IVAR_$_GemTree.gemTreeType', 136),
        },
        classes={},
        instructions=[(5421796, 'sub sp, sp, 8'), (5421852, 'adcseq r4, r3, r0')],
        calls=[],
        branches=[],
        semantics=('[GemTree treeType] (imp 0x0052bae4, 15w): the tree-type (the gem-tree type value).\n'),
    ),
    dict(
        name='g_gemitem',
        method='GemTree -[gemItemType]',
        types='i8@0:4',
        start=5421856,
        end=5422044,
        disasm='disasm_worldtileloader_g_gemitem.txt',
        base_add=5421880,
        base_literal=5422040,
        boundary='ARM.exidx end 0x0052bbdc (listing bound); next ObjC IMP 0x0052bbdc GemTree -[tileIsKindOfSelf:]',
        selectors={},
        imports={},
        ivars={
                 0x52bbd4: (17155716, 'OBJC_IVAR_$_GemTree.gemTreeType', 136),
        },
        classes={},
        instructions=[(5421856, 'sub sp, sp, 0x10'), (5422040, 'ldrhteq r3, [r3], r4')],
        calls=[],
        branches=[(5421908, 'bhi', 5422012), (5421960, 'b', 5422024), (5421972, 'b', 5422024), (5421984, 'b', 5422024), (5421996, 'b', 5422024), (5422008, 'b', 5422024), (5422012, 'b', 5422016)],
        semantics=('[GemTree gemItemType] (imp 0x0052bb20, 47w): the GEM item codes - consts **{0x57,0x56,0x4c,0x4b,0x58}** (the 5 gem families the tree yields).\n'),
    ),
    dict(
        name='g_kindself',
        method='GemTree -[tileIsKindOfSelf:]',
        types='c12@0:4^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}8',
        start=5422044,
        end=5422660,
        disasm='disasm_worldtileloader_g_kindself.txt',
        base_add=5422116,
        base_literal=5422656,
        boundary='ARM.exidx end 0x0052be44 (listing bound); next ObjC IMP 0x0052be44 GemTree -[isStaticTree]',
        selectors={},
        imports={},
        ivars={
                 0x52be3c: (17155716, 'OBJC_IVAR_$_GemTree.gemTreeType', 136),
        },
        classes={},
        instructions=[(5422044, 'sub sp, sp, 0x28'), (5422656, 'adcseq r3, r3, r8, asr 29')],
        calls=[],
        branches=[(5422072, 'beq', 5422092), (5422088, 'bne', 5422104), (5422100, 'b', 5422640), (5422144, 'bhi', 5422628), (5422208, 'beq', 5422260), (5422232, 'beq', 5422260), (5422272, 'b', 5422640), (5422296, 'beq', 5422348), (5422320, 'beq', 5422348), (5422360, 'b', 5422640), (5422384, 'beq', 5422436), (5422408, 'beq', 5422436), (5422448, 'b', 5422640), (5422472, 'beq', 5422524), (5422496, 'beq', 5422524), (5422536, 'b', 5422640), (5422560, 'beq', 5422612), (5422584, 'beq', 5422612), (5422624, 'b', 5422640), (5422628, 'b', 5422632)],
        semantics=('[GemTree tileIsKindOfSelf:] (imp 0x0052bbdc, 154w): the membership - cmps 0x22/0x1d + the long 0x6d..0x7b contents ladder: the gem tree recognizes its own stage/contents codes.\n'),
    ),
    dict(
        name='g_isstatic',
        method='GemTree -[isStaticTree]',
        types='c8@0:4',
        start=5422660,
        end=5422688,
        disasm='disasm_worldtileloader_g_isstatic.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0052be60 (listing bound); next ObjC IMP 0x0052eb80 BHServer -[initWithDelegate:match:netNodeType:saveID:maxPlayers:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(5422660, 'sub sp, sp, 8'), (5422684, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[GemTree isStaticTree] (imp 0x0052be44, 7w): the static flag (the gem tree is static?).\n'),
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
        'batch': 'GemTree (E95): the plant-line closer - contents ladders, gem codes, the recursive tile set; 17 bodies',
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
                        default=NATIVE / 'gem_tree.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale gem_tree.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
