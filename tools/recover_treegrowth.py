#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The plants line: the tree growth and update giants: the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 22630 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/TREE_GROWTH.md for the prose and boundaries.
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
    'bl 0x7deb18': 0x007deb18,
    'bl 0x809c2c': 0x00809c2c,
    'bl 0x9bd3a0': 0x009bd3a0,
    'bl 0xa965f4': 0x00a965f4,
    'bl 0xb533ac': 0x00b533ac,
    'bl 0xb64f38': 0x00b64f38,
    'bl 0xd0df1c': 0x00d0df1c,
    'bl 0xd4b4e4': 0x00d4b4e4,
    'bl 0xdb5fa4': 0x00db5fa4,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_': 0x00a15404,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__modsi3': 0x001c3020,
    'bl sym.imp.__wrap_fmodf': 0x001c3d4c,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_': 0x00a1915c,
    'bl sym.seasonForWorldX_int__double__World_': 0x00a14a48,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileAtWorldPosition_int__int__MacroTile__World_': 0x00a16e68,
    'bl sym.tileIsBush_Tile_': 0x00a13a4c,
    'bl sym.tileIsDeadTree_Tile_': 0x00a138fc,
    'bl sym.tileIsSolid_Tile_': 0x00a1179c,
    'bl sym.tileIsTreeTrunk_Tile_': 0x00a11390,
    'bl sym.tileIsTree_Tile_': 0x00a13214,
}

SPECS = [
    dict(
        name='cf_growth',
        method='CoffeeTree -[updateGrowth:]',
        types='v12@0:4c8',
        start=8252576,
        end=8260644,
        disasm='disasm_worldtileloader_cf_growth.txt',
        base_add=8252596,
        base_literal=8255428,
        boundary='ARM.exidx end 0x007e0c24 (listing bound); next ObjC IMP 0x007e0c24 CoffeeTree -[makeTileDead:]',
        selectors={
                 0x7dfed0: (15210748, 'worldContentsChangedAtPos:'),
                 0x7dfed8: (15210728, 'getX:Y:octaves:'),
                 0x7dfee4: (15210724, 'worldWidthMacro'),
                 0x7e08e4: (15210752, 'expertMode'),
                 0x7e0bd0: (15210756, 'objectType'),
                 0x7e0bd4: (15210760, 'dynamicWorldChangedAtPos:objectType:'),
                 0x7e0bf0: (15210748, 'worldContentsChangedAtPos:'),
                 0x7e0bf8: (15210728, 'getX:Y:octaves:'),
                 0x7e0c04: (15210724, 'worldWidthMacro'),
                 0x7e0c0c: (15210764, 'tileIsKindOfSelf:'),
                 0x7e0c10: (15210768, 'removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:'),
                 0x7e0c20: (15210772, 'macroTiles'),
        },
        imports={
                 0x7dfed4: (17151904, 'objc_msgSend'),
                 0x7e0bf4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x7df7c8: (17155068, 'OBJC_IVAR_$_Tree.dead', 104),
                 0x7df7cc: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0x7dfd64: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x7dfd68: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x7dfd6c: (17155096, 'OBJC_IVAR_$_Tree.treeSeasonOffset', 84),
                 0x7dfec0: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0x7dfec8: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x7dfedc: (17155032, 'OBJC_IVAR_$_Tree.treeDensityNoiseFunction', 76),
                 0x7e06e8: (17155056, 'OBJC_IVAR_$_Tree.fruitCount', 128),
                 0x7e08e0: (17155028, 'OBJC_IVAR_$_Tree.seasonOffsetNoiseFunction', 80),
                 0x7e08ec: (17155036, 'OBJC_IVAR_$_Tree.treeFruits', 124),
                 0x7e0bd8: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0x7e0bdc: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x7e0be0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x7e0be4: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0x7e0bec: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x7e0bfc: (17155032, 'OBJC_IVAR_$_Tree.treeDensityNoiseFunction', 76),
        },
        classes={},
        instructions=[(8252576, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8260640, 'invalid')],
        calls=[(8252716, 'bl sym.imp.__aeabi_idiv'), (8252912, 'bl sym.imp.__aeabi_idiv'), (8253012, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8253056, 'bl sym.tileIsSolid_Tile_'), (8253092, 'bl sym.tileIsTree_Tile_'), (8253320, 'bl 0x7deb18'), (8253520, 'bl sym.makeIntpair_int__int_'), (8253548, 'bl loc.imp.objc_msgSend'), (8253832, 'bl loc.imp.objc_msgSend'), (8253956, 'bl loc.imp.objc_msgSend'), (8254064, 'bl loc.imp.objc_msgSend'), (8254216, 'blx lr'), (8254428, 'bl sym.imp.__aeabi_idiv'), (8255128, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8255276, 'bl sym.tileIsSolid_Tile_'), (8255320, 'bl sym.tileIsDeadTree_Tile_'), (8255372, 'bl sym.tileIsBush_Tile_'), (8255672, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8255884, 'bl loc.imp.objc_msgSend'), (8256000, 'bl loc.imp.objc_msgSend'), (8256096, 'bl loc.imp.objc_msgSend'), (8256176, 'bl loc.imp.objc_msgSend'), (8256368, 'bl sym.makeIntpair_int__int_'), (8256528, 'bl loc.imp.objc_msgSend'), (8256564, 'bl loc.imp.objc_msgSend'), (8256580, 'bl 0x7deb18'), (8256792, 'bl sym.makeIntpair_int__int_'), (8256820, 'bl loc.imp.objc_msgSend'), (8256936, 'blx r3'), (8256956, 'bl sym.tileIsTreeTrunk_Tile_'), (8257336, 'bl 0x7deb18'), (8257512, 'bl sym.makeIntpair_int__int_'), (8257540, 'bl loc.imp.objc_msgSend'), (8257824, 'bl loc.imp.objc_msgSend'), (8257948, 'bl loc.imp.objc_msgSend'), (8258056, 'bl loc.imp.objc_msgSend'), (8258208, 'blx lr'), (8258420, 'bl sym.imp.__aeabi_idiv'), (8258948, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8259116, 'blx r3'), (8259280, 'blx lr'), (8259424, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8259592, 'blx r3'), (8259756, 'blx lr'), (8259880, 'bl sym.makeIntpair_int__int_'), (8259968, 'bl sym.makeIntpair_int__int_'), (8260056, 'blx r3'), (8260112, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (8260200, 'blx r3'), (8260256, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (8260344, 'blx r3'), (8260400, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (8260488, 'blx r3'), (8260544, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_')],
        branches=[(8252644, 'beq', 8252652), (8252648, 'b', 8260548), (8252788, 'bge', 8259824), (8253032, 'beq', 8253116), (8253048, 'bne', 8253108), (8253068, 'bne', 8253108), (8253084, 'beq', 8253112), (8253104, 'bne', 8253112), (8253108, 'b', 8259824), (8253112, 'b', 8253116), (8253128, 'bgt', 8253168), (8253164, 'bge', 8257260), (8253180, 'beq', 8253552), (8253268, 'bne', 8253308), (8253284, 'beq', 8253308), (8253300, 'b', 8253320), (8254456, 'bge', 8254480), (8254468, 'b', 8254488), (8254580, 'bpl', 8254612), (8254600, 'b', 8254620), (8254720, 'bpl', 8254748), (8254740, 'b', 8254756), (8254792, 'ble', 8254804), (8254824, 'bge', 8254844), (8254888, 'blt', 8254916), (8254924, 'beq', 8257212), (8254948, 'bge', 8257192), (8254960, 'bne', 8254992), (8254972, 'beq', 8254992), (8254988, 'blt', 8255032), (8255000, 'bne', 8257172), (8255012, 'beq', 8257172), (8255028, 'bge', 8257172), (8255148, 'beq', 8257168), (8255176, 'beq', 8255248), (8255268, 'beq', 8255484), (8255288, 'bne', 8255316), (8255312, 'beq', 8255344), (8255364, 'bne', 8255480), (8255384, 'beq', 8255476), (8255408, 'bne', 8255448), (8255412, 'b', 8255416), (8255424, 'b', 8255472), (8255456, 'bge', 8255468), (8255468, 'b', 8255472), (8255472, 'b', 8255476), (8255476, 'b', 8255480), (8255480, 'b', 8255484), (8255492, 'beq', 8256888), (8255584, 'bge', 8256572), (8255692, 'beq', 8255752), (8255708, 'beq', 8255744), (8255724, 'beq', 8255744), (8255740, 'bne', 8255752), (8256220, 'ble', 8256568), (8256568, 'b', 8256572), (8256840, 'bne', 8256856), (8256852, 'b', 8256864), (8256864, 'b', 8256984), (8256948, 'beq', 8256972), (8256968, 'beq', 8256980), (8256980, 'b', 8256984), (8256996, 'beq', 8257008), (8257016, 'beq', 8257164), (8257080, 'beq', 8257164), (8257084, 'b', 8257088), (8257096, 'bne', 8257152), (8257108, 'b', 8257160), (8257160, 'b', 8257164), (8257164, 'b', 8257168), (8257168, 'b', 8257172), (8257172, 'b', 8257176), (8257188, 'b', 8254940), (8257192, 'b', 8257196), (8257208, 'b', 8254868), (8257212, 'b', 8259784), (8257272, 'beq', 8257544), (8258448, 'bge', 8258464), (8258460, 'b', 8258472), (8258564, 'bpl', 8258596), (8258584, 'b', 8258604), (8258704, 'bpl', 8258736), (8258724, 'b', 8258744), (8258780, 'ble', 8258792), (8258812, 'bge', 8258832), (8258856, 'bge', 8259312), (8258968, 'beq', 8259284), (8259032, 'beq', 8259068), (8259036, 'b', 8259040), (8259060, 'bne', 8259284), (8259064, 'b', 8259068), (8259128, 'beq', 8259284), (8259284, 'b', 8259288), (8259300, 'b', 8258844), (8259332, 'bge', 8259780), (8259444, 'beq', 8259760), (8259508, 'beq', 8259544), (8259512, 'b', 8259516), (8259536, 'bne', 8259760), (8259540, 'b', 8259544), (8259604, 'beq', 8259760), (8259760, 'b', 8259764), (8259776, 'b', 8259320), (8259780, 'b', 8259784), (8259784, 'b', 8259788), (8259800, 'b', 8252752)],
        semantics=('[CoffeeTree updateGrowth:] (imp 0x007deca0, 2017w): the growth tick. Census: **objc_msgSend x15** + makeIntpair x6 + tileAtWorldPositionLoaded x5 + **`reloadDrawBlockGeometryForTile` x4** (the geometry-reload render tie - the growth invalidates the tile geometry; the sibling of the E84/E73 quad reloads) + __aeabi_idiv x4 + tileIsSolid + the per-tree helper 0x7deb18 x3. Window read (at_growth): the **ffffc908 gate** (ldrsb exit), the clamp constants **mvn 0x62 (-99) / movw 0x63 (99) / movw 8** (the growth clamp + divisor), the **rounding divide-by-2** (`add r5, r5, r5, lsr 31; sub r4, r4, r5, asr 1`) + `lsl r4, r4, 2` + __aeabi_idiv + **`add r0, r0, 0x7f` (+127 bias)**, and the ffffc8a0/c89c/c904/c924 position/state cells; 1 unclassified pool word (0x3fffffff the half-max sentinel).\n'),
    ),
    dict(
        name='cf_update',
        method='CoffeeTree -[update:accurateDT:isSimulation:]',
        types='v20@0:4f8f12c16',
        start=8260748,
        end=8262504,
        disasm='disasm_worldtileloader_cf_update.txt',
        base_add=8260764,
        base_literal=8262500,
        boundary='ARM.exidx end 0x007e1368 (listing bound); next ObjC IMP 0x007e1368 CoffeeTree -[treeType]',
        selectors={
                 0x7e130c: (15210776, 'update:accurateDT:isSimulation:'),
                 0x7e1320: (15210780, 'worldTime'),
                 0x7e1330: (15210764, 'tileIsKindOfSelf:'),
                 0x7e1344: (15210756, 'objectType'),
                 0x7e1348: (15210760, 'dynamicWorldChangedAtPos:objectType:'),
                 0x7e1358: (15210784, 'maxHeightGeneVariation'),
                 0x7e135c: (15210788, 'growthRateGeneVariation'),
                 0x7e1360: (15210792, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
        },
        imports={
                 0x7e1308: (17151900, 'objc_msgSendSuper2'),
                 0x7e131c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x7e1314: (17155068, 'OBJC_IVAR_$_Tree.dead', 104),
                 0x7e1318: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x7e1324: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x7e1328: (17155056, 'OBJC_IVAR_$_Tree.fruitCount', 128),
                 0x7e132c: (17155036, 'OBJC_IVAR_$_Tree.treeFruits', 124),
                 0x7e1334: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0x7e1340: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x7e134c: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
        },
        classes={
                 0x7e1310: (15252824, 'OBJC_CLASS_$_CoffeeTree'),
        },
        instructions=[(8260748, 'push {r4, r5, fp, lr}'), (8262500, 'addeq lr, r7, r0, asr lr')],
        calls=[(8260904, 'blx lr'), (8261028, 'blx r2'), (8261080, 'bl sym.seasonForWorldX_int__double__World_'), (8261244, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8261316, 'blx r3'), (8261492, 'bl sym.imp.__modsi3'), (8261672, 'bl loc.imp.objc_msgSend'), (8261704, 'bl loc.imp.objc_msgSend'), (8261784, 'bl loc.imp.objc_msgSend'), (8261852, 'bl loc.imp.objc_msgSend'), (8261888, 'bl loc.imp.objc_msgSend'), (8262004, 'bl loc.imp.objc_msgSend'), (8262040, 'bl loc.imp.objc_msgSend'), (8262328, 'bl loc.imp.objc_msgSend'), (8262364, 'bl loc.imp.objc_msgSend')],
        branches=[(8260940, 'bne', 8262396), (8261140, 'bge', 8262392), (8261264, 'beq', 8262372), (8261328, 'beq', 8262052), (8261392, 'bne', 8262052), (8261396, 'b', 8261400), (8261508, 'beq', 8261524), (8261520, 'bne', 8261896), (8261556, 'blt', 8261896), (8261572, 'bne', 8261892), (8261892, 'b', 8262048), (8261908, 'beq', 8262044), (8262044, 'b', 8262048), (8262048, 'b', 8262368), (8262100, 'bge', 8262220), (8262216, 'b', 8262060), (8262368, 'b', 8262372), (8262372, 'b', 8262376), (8262388, 'b', 8261104), (8262392, 'b', 8262396)],
        semantics=('[CoffeeTree update:accurateDT:isSimulation:] (imp 0x007e0c8c, 439w): the per-tick frame - **`seasonForWorldX(int, double, World*)`** (the shared season query) + objc_msgSend x15 + tile probes + the ffffc908-style gate; tile probes + the per-tree helper 0x7deb18 family. The blockhead-facing tick (spawn/fruit/season notifies) riding the ffffc8xx cells.\n'),
    ),
    dict(
        name='lt_growth',
        method='LimeTree -[updateGrowth:]',
        types='v12@0:4c8',
        start=8428976,
        end=8436864,
        disasm='disasm_worldtileloader_lt_growth.txt',
        base_add=8428996,
        base_literal=8433084,
        boundary='ARM.exidx end 0x0080bc80 (listing bound); next ObjC IMP 0x0080bc80 LimeTree -[update:accurateDT:isSimulation:]',
        selectors={
                 0x80ae28: (15211616, 'worldContentsChangedAtPos:'),
                 0x80ae30: (15211596, 'getX:Y:octaves:'),
                 0x80ae3c: (15211592, 'worldWidthMacro'),
                 0x80b6c8: (15211620, 'expertMode'),
                 0x80bc2c: (15211616, 'worldContentsChangedAtPos:'),
                 0x80bc34: (15211596, 'getX:Y:octaves:'),
                 0x80bc40: (15211592, 'worldWidthMacro'),
                 0x80bc48: (15211624, 'tileIsKindOfSelf:'),
                 0x80bc4c: (15211628, 'removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:'),
                 0x80bc5c: (15211632, 'macroTiles'),
                 0x80bc60: (15211636, 'worldTime'),
                 0x80bc64: (15211640, 'getWeatherFractionForPos:atWorldTime:'),
                 0x80bc68: (15211644, 'getDayNightFractionForX:atWorldTime:'),
                 0x80bc74: (15211648, 'killAllOwnedTiles'),
                 0x80bc78: (15211652, 'objectType'),
                 0x80bc7c: (15211656, 'dynamicWorldChangedAtPos:objectType:'),
        },
        imports={
                 0x80ae2c: (17151904, 'objc_msgSend'),
                 0x80bc30: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x80adc0: (17155068, 'OBJC_IVAR_$_Tree.dead', 104),
                 0x80ae04: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0x80ae08: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x80ae0c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x80ae10: (17155096, 'OBJC_IVAR_$_Tree.treeSeasonOffset', 84),
                 0x80ae18: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0x80ae20: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x80ae34: (17155032, 'OBJC_IVAR_$_Tree.treeDensityNoiseFunction', 76),
                 0x80b6b8: (17155056, 'OBJC_IVAR_$_Tree.fruitCount', 128),
                 0x80b6c4: (17155028, 'OBJC_IVAR_$_Tree.seasonOffsetNoiseFunction', 80),
                 0x80b6cc: (17155036, 'OBJC_IVAR_$_Tree.treeFruits', 124),
                 0x80bc10: (17155068, 'OBJC_IVAR_$_Tree.dead', 104),
                 0x80bc14: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0x80bc18: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x80bc1c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x80bc20: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0x80bc28: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x80bc38: (17155032, 'OBJC_IVAR_$_Tree.treeDensityNoiseFunction', 76),
                 0x80bc70: (17155080, 'OBJC_IVAR_$_Tree.timeDied', 112),
        },
        classes={},
        instructions=[(8428976, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8436860, 'invalid')],
        calls=[(8429116, 'bl sym.imp.__aeabi_idiv'), (8429312, 'bl sym.imp.__aeabi_idiv'), (8429412, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8429456, 'bl sym.tileIsSolid_Tile_'), (8429492, 'bl sym.tileIsTree_Tile_'), (8429744, 'bl 0x809c2c'), (8429944, 'bl sym.makeIntpair_int__int_'), (8429972, 'bl loc.imp.objc_msgSend'), (8430236, 'bl loc.imp.objc_msgSend'), (8430360, 'bl loc.imp.objc_msgSend'), (8430468, 'bl loc.imp.objc_msgSend'), (8430620, 'blx lr'), (8431160, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8431308, 'bl sym.tileIsSolid_Tile_'), (8431352, 'bl sym.tileIsDeadTree_Tile_'), (8431404, 'bl sym.tileIsBush_Tile_'), (8431684, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8431896, 'bl loc.imp.objc_msgSend'), (8432012, 'bl loc.imp.objc_msgSend'), (8432108, 'bl loc.imp.objc_msgSend'), (8432188, 'bl loc.imp.objc_msgSend'), (8432388, 'bl sym.makeIntpair_int__int_'), (8432520, 'bl 0x809c2c'), (8432732, 'bl sym.makeIntpair_int__int_'), (8432760, 'bl loc.imp.objc_msgSend'), (8432868, 'blx r3'), (8432888, 'bl sym.tileIsTreeTrunk_Tile_'), (8433304, 'bl 0x809c2c'), (8433480, 'bl sym.makeIntpair_int__int_'), (8433508, 'bl loc.imp.objc_msgSend'), (8433772, 'bl loc.imp.objc_msgSend'), (8433896, 'bl loc.imp.objc_msgSend'), (8434004, 'bl loc.imp.objc_msgSend'), (8434156, 'blx lr'), (8434528, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8434696, 'blx r3'), (8434860, 'blx lr'), (8435004, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8435172, 'blx r3'), (8435336, 'blx lr'), (8435484, 'bl sym.makeIntpair_int__int_'), (8435548, 'bl sym.makeIntpair_int__int_'), (8435616, 'bl loc.imp.objc_msgSend'), (8435672, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (8435728, 'bl loc.imp.objc_msgSend'), (8435780, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (8435836, 'bl loc.imp.objc_msgSend'), (8435888, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (8435944, 'bl loc.imp.objc_msgSend'), (8435996, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (8436048, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8436128, 'bl loc.imp.objc_msgSend'), (8436168, 'bl loc.imp.objc_msgSend'), (8436236, 'bl loc.imp.objc_msgSend'), (8436276, 'bl loc.imp.objc_msgSend'), (8436368, 'bl loc.imp.objc_msgSend'), (8436416, 'bl sym.seasonForWorldX_int__double__World_'), (8436480, 'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_'), (8436576, 'bl loc.imp.objc_msgSend'), (8436624, 'bl loc.imp.objc_msgSend'), (8436700, 'bl loc.imp.objc_msgSend'), (8436736, 'bl loc.imp.objc_msgSend')],
        branches=[(8429044, 'beq', 8429052), (8429048, 'b', 8436740), (8429188, 'bge', 8435412), (8429432, 'beq', 8429516), (8429448, 'bne', 8429508), (8429468, 'bne', 8429508), (8429484, 'beq', 8429512), (8429504, 'bne', 8429512), (8429508, 'b', 8435412), (8429512, 'b', 8429516), (8429528, 'bgt', 8429568), (8429564, 'bge', 8433228), (8429580, 'beq', 8429976), (8429668, 'bne', 8429732), (8429684, 'beq', 8429732), (8429700, 'b', 8429744), (8430824, 'ble', 8430836), (8430856, 'bge', 8430876), (8430920, 'blt', 8430948), (8430956, 'beq', 8433152), (8430980, 'bge', 8433092), (8430992, 'bne', 8431024), (8431004, 'beq', 8431024), (8431020, 'blt', 8431064), (8431032, 'bne', 8433064), (8431044, 'beq', 8433064), (8431060, 'bge', 8433064), (8431180, 'beq', 8433060), (8431208, 'beq', 8431280), (8431300, 'beq', 8431496), (8431320, 'bne', 8431348), (8431344, 'beq', 8431376), (8431396, 'bne', 8431492), (8431416, 'beq', 8431488), (8431440, 'bne', 8431460), (8431444, 'b', 8431448), (8431456, 'b', 8431484), (8431468, 'bge', 8431480), (8431480, 'b', 8431484), (8431484, 'b', 8431488), (8431488, 'b', 8431492), (8431492, 'b', 8431496), (8431504, 'beq', 8432820), (8431596, 'bge', 8432512), (8431704, 'beq', 8431764), (8431720, 'beq', 8431756), (8431736, 'beq', 8431756), (8431752, 'bne', 8431764), (8432232, 'ble', 8432508), (8432508, 'b', 8432512), (8432780, 'bne', 8432796), (8432792, 'b', 8432804), (8432804, 'b', 8432916), (8432880, 'beq', 8432904), (8432900, 'beq', 8432912), (8432912, 'b', 8432916), (8432928, 'beq', 8432940), (8432948, 'beq', 8433056), (8433012, 'beq', 8433056), (8433016, 'b', 8433020), (8433028, 'bne', 8433044), (8433040, 'b', 8433052), (8433052, 'b', 8433056), (8433056, 'b', 8433060), (8433060, 'b', 8433064), (8433064, 'b', 8433068), (8433080, 'b', 8430972), (8433092, 'b', 8433096), (8433108, 'b', 8430900), (8433152, 'b', 8435364), (8433240, 'beq', 8433512), (8434360, 'ble', 8434372), (8434392, 'bge', 8434412), (8434436, 'bge', 8434892), (8434548, 'beq', 8434864), (8434612, 'beq', 8434648), (8434616, 'b', 8434620), (8434640, 'bne', 8434864), (8434644, 'b', 8434648), (8434708, 'beq', 8434864), (8434864, 'b', 8434868), (8434880, 'b', 8434424), (8434912, 'bge', 8435360), (8435024, 'beq', 8435340), (8435088, 'beq', 8435124), (8435092, 'b', 8435096), (8435116, 'bne', 8435340), (8435120, 'b', 8435124), (8435184, 'beq', 8435340), (8435340, 'b', 8435344), (8435356, 'b', 8434900), (8435360, 'b', 8435364), (8435364, 'b', 8435368), (8435380, 'b', 8429152), (8436508, 'bpl', 8436740)],
        semantics=('[LimeTree updateGrowth:] (imp 0x00809db0, 1972w): the growth tick. Census: **objc_msgSend x26** + makeIntpair x6 + tileAtWorldPositionLoaded x6 + **`reloadDrawBlockGeometryForTile` x4** (the geometry-reload render tie - the growth invalidates the tile geometry; the sibling of the E84/E73 quad reloads) + __aeabi_idiv x2 + tileIsSolid + the per-tree helper 0x809c2c x3. Window read (at_growth): the **ffffc908 gate** (ldrsb exit), the clamp constants **mvn 0x62 (-99) / movw 0x63 (99) / movw 8** (the growth clamp + divisor), the **rounding divide-by-2** (`add r5, r5, r5, lsr 31; sub r4, r4, r5, asr 1`) + `lsl r4, r4, 2` + __aeabi_idiv + **`add r0, r0, 0x7f` (+127 bias)**, and the ffffc8a0/c89c/c904/c924 position/state cells; 1 unclassified pool word (0x3fffffff the half-max sentinel).\n'),
    ),
    dict(
        name='lt_update',
        method='LimeTree -[update:accurateDT:isSimulation:]',
        types='v20@0:4f8f12c16',
        start=8436864,
        end=8438696,
        disasm='disasm_worldtileloader_lt_update.txt',
        base_add=8436880,
        base_literal=8438692,
        boundary='ARM.exidx end 0x0080c3a8 (listing bound); next ObjC IMP 0x0080c3a8 LimeTree -[makeTileDead:]',
        selectors={
                 0x80c348: (15211660, 'update:accurateDT:isSimulation:'),
                 0x80c35c: (15211636, 'worldTime'),
                 0x80c368: (15211632, 'macroTiles'),
                 0x80c370: (15211624, 'tileIsKindOfSelf:'),
                 0x80c384: (15211652, 'objectType'),
                 0x80c388: (15211656, 'dynamicWorldChangedAtPos:objectType:'),
                 0x80c398: (15211664, 'maxHeightGeneVariation'),
                 0x80c39c: (15211668, 'growthRateGeneVariation'),
                 0x80c3a0: (15211672, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
        },
        imports={
                 0x80c344: (17151900, 'objc_msgSendSuper2'),
                 0x80c358: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x80c350: (17155068, 'OBJC_IVAR_$_Tree.dead', 104),
                 0x80c354: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x80c360: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x80c364: (17155056, 'OBJC_IVAR_$_Tree.fruitCount', 128),
                 0x80c36c: (17155036, 'OBJC_IVAR_$_Tree.treeFruits', 124),
                 0x80c374: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0x80c380: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x80c38c: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
        },
        classes={
                 0x80c34c: (15252836, 'OBJC_CLASS_$_LimeTree'),
        },
        instructions=[(8436864, 'push {r4, r5, fp, lr}'), (8438692, 'addeq r3, r5, ip, asr lr')],
        calls=[(8437020, 'blx lr'), (8437144, 'blx r2'), (8437196, 'bl sym.seasonForWorldX_int__double__World_'), (8437388, 'blx r2'), (8437432, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (8437504, 'blx r3'), (8437680, 'bl sym.imp.__modsi3'), (8437860, 'bl loc.imp.objc_msgSend'), (8437892, 'bl loc.imp.objc_msgSend'), (8437972, 'bl loc.imp.objc_msgSend'), (8438040, 'bl loc.imp.objc_msgSend'), (8438076, 'bl loc.imp.objc_msgSend'), (8438192, 'bl loc.imp.objc_msgSend'), (8438228, 'bl loc.imp.objc_msgSend'), (8438516, 'bl loc.imp.objc_msgSend'), (8438552, 'bl loc.imp.objc_msgSend')],
        branches=[(8437056, 'bne', 8438584), (8437256, 'bge', 8438580), (8437452, 'beq', 8438560), (8437516, 'beq', 8438240), (8437580, 'bne', 8438240), (8437584, 'b', 8437588), (8437696, 'beq', 8437712), (8437708, 'bne', 8438084), (8437744, 'blt', 8438084), (8437760, 'bne', 8438080), (8438080, 'b', 8438236), (8438096, 'beq', 8438232), (8438232, 'b', 8438236), (8438236, 'b', 8438556), (8438288, 'bge', 8438408), (8438404, 'b', 8438248), (8438556, 'b', 8438560), (8438560, 'b', 8438564), (8438576, 'b', 8437220), (8438580, 'b', 8438584)],
        semantics=('[LimeTree update:accurateDT:isSimulation:] (imp 0x0080bc80, 458w): the per-tick frame - **`seasonForWorldX(int, double, World*)`** (the shared season query) + objc_msgSend x16 + tile probes + the ffffc908-style gate; tile probes + helper 0x809c2c. The blockhead-facing tick (spawn/fruit/season notifies) riding the ffffc8xx cells.\n'),
    ),
    dict(
        name='at_growth',
        method='AppleTree -[updateGrowth:]',
        types='v12@0:4c8',
        start=10212992,
        end=10220936,
        disasm='disasm_worldtileloader_at_growth.txt',
        base_add=10213012,
        base_literal=10217084,
        boundary='ARM.exidx end 0x009bf588 (listing bound); next ObjC IMP 0x009bf588 AppleTree -[makeTileDead:]',
        selectors={
                 0x9be98c: (15221140, 'worldContentsChangedAtPos:'),
                 0x9be994: (15221104, 'getX:Y:octaves:'),
                 0x9be9a0: (15221100, 'worldWidthMacro'),
                 0x9bf230: (15221144, 'expertMode'),
                 0x9bf23c: (15221088, 'objectType'),
                 0x9bf240: (15221092, 'dynamicWorldChangedAtPos:objectType:'),
                 0x9bf540: (15221140, 'worldContentsChangedAtPos:'),
                 0x9bf548: (15221104, 'getX:Y:octaves:'),
                 0x9bf554: (15221100, 'worldWidthMacro'),
                 0x9bf55c: (15221148, 'tileIsKindOfSelf:'),
                 0x9bf560: (15221152, 'removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:'),
                 0x9bf574: (15221088, 'objectType'),
                 0x9bf578: (15221092, 'dynamicWorldChangedAtPos:objectType:'),
                 0x9bf584: (15221156, 'macroTiles'),
        },
        imports={
                 0x9be990: (17151904, 'objc_msgSend'),
                 0x9bf544: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x9be680: (17155068, 'OBJC_IVAR_$_Tree.dead', 104),
                 0x9be684: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0x9be6a8: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x9be6ac: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x9be6b0: (17155096, 'OBJC_IVAR_$_Tree.treeSeasonOffset', 84),
                 0x9be798: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x9be79c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x9be7dc: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0x9be984: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x9be998: (17155032, 'OBJC_IVAR_$_Tree.treeDensityNoiseFunction', 76),
                 0x9bf030: (17155056, 'OBJC_IVAR_$_Tree.fruitCount', 128),
                 0x9bf22c: (17155028, 'OBJC_IVAR_$_Tree.seasonOffsetNoiseFunction', 80),
                 0x9bf238: (17155036, 'OBJC_IVAR_$_Tree.treeFruits', 124),
                 0x9bf528: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0x9bf52c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x9bf530: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x9bf534: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0x9bf53c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x9bf54c: (17155032, 'OBJC_IVAR_$_Tree.treeDensityNoiseFunction', 76),
                 0x9bf568: (17155056, 'OBJC_IVAR_$_Tree.fruitCount', 128),
                 0x9bf570: (17155036, 'OBJC_IVAR_$_Tree.treeFruits', 124),
        },
        classes={},
        instructions=[(10212992, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10213060, 'beq 0x9bd6cc'), (10213132, 'bl sym.imp.__aeabi_idiv'), (10217084, 'rsbeq r2, sl, r8, asr r4'), (10220932, 'invalid')],
        calls=[(10213132, 'bl sym.imp.__aeabi_idiv'), (10213328, 'bl sym.imp.__aeabi_idiv'), (10213428, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10213472, 'bl sym.tileIsSolid_Tile_'), (10213508, 'bl sym.tileIsTree_Tile_'), (10213792, 'bl 0x9bd3a0'), (10213992, 'bl sym.makeIntpair_int__int_'), (10214020, 'bl loc.imp.objc_msgSend'), (10214284, 'bl loc.imp.objc_msgSend'), (10214408, 'bl loc.imp.objc_msgSend'), (10214516, 'bl loc.imp.objc_msgSend'), (10214668, 'blx lr'), (10215208, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10215356, 'bl sym.tileIsSolid_Tile_'), (10215400, 'bl sym.tileIsDeadTree_Tile_'), (10215452, 'bl sym.tileIsBush_Tile_'), (10215732, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10215944, 'bl loc.imp.objc_msgSend'), (10216060, 'bl loc.imp.objc_msgSend'), (10216156, 'bl loc.imp.objc_msgSend'), (10216236, 'bl loc.imp.objc_msgSend'), (10216428, 'bl sym.makeIntpair_int__int_'), (10216588, 'bl loc.imp.objc_msgSend'), (10216624, 'bl loc.imp.objc_msgSend'), (10216716, 'bl 0x9bd3a0'), (10216796, 'bl 0x9bd3a0'), (10217008, 'bl sym.makeIntpair_int__int_'), (10217036, 'bl loc.imp.objc_msgSend'), (10217192, 'blx r3'), (10217212, 'bl sym.tileIsTreeTrunk_Tile_'), (10217656, 'bl sym.makeIntpair_int__int_'), (10217816, 'bl loc.imp.objc_msgSend'), (10217852, 'bl loc.imp.objc_msgSend'), (10217988, 'bl 0x9bd3a0'), (10218164, 'bl sym.makeIntpair_int__int_'), (10218192, 'bl loc.imp.objc_msgSend'), (10218456, 'bl loc.imp.objc_msgSend'), (10218580, 'bl loc.imp.objc_msgSend'), (10218688, 'bl loc.imp.objc_msgSend'), (10218840, 'blx lr'), (10219212, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10219380, 'blx r3'), (10219544, 'blx lr'), (10219696, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10219864, 'blx r3'), (10220028, 'blx lr'), (10220160, 'bl sym.makeIntpair_int__int_'), (10220248, 'bl sym.makeIntpair_int__int_'), (10220336, 'blx r3'), (10220392, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (10220480, 'blx r3'), (10220536, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (10220624, 'blx r3'), (10220680, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (10220768, 'blx r3'), (10220824, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_')],
        branches=[(10213060, 'beq', 10213068), (10213064, 'b', 10220828), (10213204, 'bge', 10220104), (10213448, 'beq', 10213532), (10213464, 'bne', 10213524), (10213484, 'bne', 10213524), (10213500, 'beq', 10213528), (10213520, 'bne', 10213528), (10213524, 'b', 10220104), (10213528, 'b', 10213532), (10213544, 'bgt', 10213584), (10213580, 'bge', 10217912), (10213628, 'beq', 10214024), (10213716, 'bne', 10213780), (10213732, 'beq', 10213780), (10213748, 'b', 10213792), (10214872, 'ble', 10214884), (10214904, 'bge', 10214924), (10214968, 'blt', 10214996), (10215004, 'beq', 10217448), (10215028, 'bge', 10217416), (10215040, 'bne', 10215072), (10215052, 'beq', 10215072), (10215068, 'blt', 10215112), (10215080, 'bne', 10217396), (10215092, 'beq', 10217396), (10215108, 'bge', 10217396), (10215228, 'beq', 10217392), (10215256, 'beq', 10215328), (10215348, 'beq', 10215544), (10215368, 'bne', 10215396), (10215392, 'beq', 10215424), (10215444, 'bne', 10215540), (10215464, 'beq', 10215536), (10215488, 'bne', 10215508), (10215492, 'b', 10215496), (10215504, 'b', 10215532), (10215516, 'bge', 10215528), (10215528, 'b', 10215532), (10215532, 'b', 10215536), (10215536, 'b', 10215540), (10215540, 'b', 10215544), (10215552, 'beq', 10217144), (10215644, 'bge', 10216788), (10215752, 'beq', 10215812), (10215768, 'beq', 10215804), (10215784, 'beq', 10215804), (10215800, 'bne', 10215812), (10216280, 'ble', 10216644), (10216628, 'b', 10216784), (10216676, 'bne', 10216780), (10216712, 'bne', 10216780), (10216728, 'ble', 10216780), (10216780, 'b', 10216784), (10216784, 'b', 10216788), (10217056, 'bne', 10217072), (10217068, 'b', 10217080), (10217080, 'b', 10217240), (10217204, 'beq', 10217228), (10217224, 'beq', 10217236), (10217236, 'b', 10217240), (10217252, 'beq', 10217264), (10217272, 'beq', 10217388), (10217336, 'beq', 10217388), (10217340, 'b', 10217344), (10217352, 'bne', 10217376), (10217364, 'b', 10217384), (10217384, 'b', 10217388), (10217388, 'b', 10217392), (10217392, 'b', 10217396), (10217396, 'b', 10217400), (10217412, 'b', 10215020), (10217416, 'b', 10217420), (10217432, 'b', 10214948), (10217480, 'bne', 10217856), (10217516, 'bne', 10217856), (10217856, 'b', 10220056), (10217924, 'beq', 10218196), (10219044, 'ble', 10219056), (10219076, 'bge', 10219096), (10219120, 'bge', 10219584), (10219232, 'beq', 10219548), (10219296, 'beq', 10219332), (10219300, 'b', 10219304), (10219324, 'bne', 10219548), (10219328, 'b', 10219332), (10219392, 'beq', 10219548), (10219548, 'b', 10219552), (10219564, 'b', 10219108), (10219604, 'bge', 10220052), (10219716, 'beq', 10220032), (10219780, 'beq', 10219816), (10219784, 'b', 10219788), (10219808, 'bne', 10220032), (10219812, 'b', 10219816), (10219876, 'beq', 10220032), (10220032, 'b', 10220036), (10220048, 'b', 10219592), (10220052, 'b', 10220056), (10220056, 'b', 10220060), (10220072, 'b', 10213168)],
        semantics=('[AppleTree updateGrowth:] (imp 0x009bd680, 1986w): the growth tick. Census: **objc_msgSend x17** + makeIntpair x7 + tileAtWorldPositionLoaded x5 + **`reloadDrawBlockGeometryForTile` x4** (the geometry-reload render tie - the growth invalidates the tile geometry; the sibling of the E84/E73 quad reloads) + __aeabi_idiv x2 + tileIsSolid + the per-tree helper 0x9bd3a0 x4. Window read (at_growth): the **ffffc908 gate** (ldrsb exit), the clamp constants **mvn 0x62 (-99) / movw 0x63 (99) / movw 8** (the growth clamp + divisor), the **rounding divide-by-2** (`add r5, r5, r5, lsr 31; sub r4, r4, r5, asr 1`) + `lsl r4, r4, 2` + __aeabi_idiv + **`add r0, r0, 0x7f` (+127 bias)**, and the ffffc8a0/c89c/c904/c924 position/state cells; 1 unclassified pool word (0x3fffffff the half-max sentinel).\n'),
    ),
    dict(
        name='at_update',
        method='AppleTree -[update:accurateDT:isSimulation:]',
        types='v20@0:4f8f12c16',
        start=10221040,
        end=10223380,
        disasm='disasm_worldtileloader_at_update.txt',
        base_add=10221056,
        base_literal=10223376,
        boundary='ARM.exidx end 0x009bff14 (listing bound); next ObjC IMP 0x009bff14 AppleTree -[treeType]',
        selectors={
                 0x9bfea4: (15221160, 'update:accurateDT:isSimulation:'),
                 0x9bfebc: (15221164, 'worldTime'),
                 0x9bfecc: (15221168, 'npcExistsAtPos:ignoreNPC:'),
                 0x9bfed4: (15221172, 'loadNPCAtPosition:type:saveDict:isAdult:wasPlaced:placedByClient:'),
                 0x9bfee0: (15221148, 'tileIsKindOfSelf:'),
                 0x9bfef0: (15221088, 'objectType'),
                 0x9bfef4: (15221092, 'dynamicWorldChangedAtPos:objectType:'),
                 0x9bff04: (15221176, 'maxHeightGeneVariation'),
                 0x9bff08: (15221180, 'growthRateGeneVariation'),
                 0x9bff0c: (15221184, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
        },
        imports={
                 0x9bfea0: (17151900, 'objc_msgSendSuper2'),
                 0x9bfeb8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x9bfeac: (17155068, 'OBJC_IVAR_$_Tree.dead', 104),
                 0x9bfeb0: (17163660, 'OBJC_IVAR_$_AppleTree.availableFood', 136),
                 0x9bfeb4: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x9bfec0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x9bfec4: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x9bfed8: (17155056, 'OBJC_IVAR_$_Tree.fruitCount', 128),
                 0x9bfedc: (17155036, 'OBJC_IVAR_$_Tree.treeFruits', 124),
                 0x9bfee4: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0x9bfef8: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
        },
        classes={
                 0x9bfea8: (15252972, 'OBJC_CLASS_$_AppleTree'),
        },
        instructions=[(10221040, 'push {r4, r5, fp, lr}'), (10223376, 'rsbeq r0, sl, ip, ror 9')],
        calls=[(10221196, 'blx lr'), (10221320, 'blx r2'), (10221372, 'bl sym.seasonForWorldX_int__double__World_'), (10221628, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10221668, 'bl 0x9bd3a0'), (10221804, 'bl loc.imp.objc_msgSend'), (10221936, 'bl loc.imp.objc_msgSend'), (10222104, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10222176, 'blx r3'), (10222348, 'bl sym.imp.__modsi3'), (10222528, 'bl loc.imp.objc_msgSend'), (10222560, 'bl loc.imp.objc_msgSend'), (10222640, 'bl loc.imp.objc_msgSend'), (10222708, 'bl loc.imp.objc_msgSend'), (10222744, 'bl loc.imp.objc_msgSend'), (10222860, 'bl loc.imp.objc_msgSend'), (10222896, 'bl loc.imp.objc_msgSend'), (10223184, 'bl loc.imp.objc_msgSend'), (10223220, 'bl loc.imp.objc_msgSend')],
        branches=[(10221232, 'bne', 10223252), (10221432, 'bpl', 10221508), (10221484, 'b', 10221952), (10221648, 'beq', 10221948), (10221664, 'bne', 10221948), (10221704, 'ble', 10221948), (10221816, 'bne', 10221944), (10221944, 'b', 10221948), (10221948, 'b', 10221952), (10222000, 'bge', 10223248), (10222124, 'beq', 10223228), (10222188, 'beq', 10222908), (10222252, 'bne', 10222908), (10222256, 'b', 10222260), (10222364, 'beq', 10222380), (10222376, 'bne', 10222752), (10222412, 'blt', 10222752), (10222428, 'bne', 10222748), (10222748, 'b', 10222904), (10222764, 'beq', 10222900), (10222900, 'b', 10222904), (10222904, 'b', 10223224), (10222956, 'bge', 10223076), (10223072, 'b', 10222916), (10223224, 'b', 10223228), (10223228, 'b', 10223232), (10223244, 'b', 10221964), (10223248, 'b', 10223252)],
        semantics=('[AppleTree update:accurateDT:isSimulation:] (imp 0x009bf5f0, 585w): the per-tick frame - **`seasonForWorldX(int, double, World*)`** (the shared season query) + objc_msgSend x11 + census probes: 2x tile probes + the ffffc908-style gate; tileAtWorldPositionLoaded x2 + the per-tree helper 0x9bd3a0 x1 + __modsi3 x1. The blockhead-facing tick (spawn/fruit/season notifies) riding the ffffc8xx cells.\n'),
    ),
    dict(
        name='ot_growth',
        method='OrangeTree -[updateGrowth:]',
        types='v12@0:4c8',
        start=11102072,
        end=11109960,
        disasm='disasm_worldtileloader_ot_growth.txt',
        base_add=11102092,
        base_literal=11106180,
        boundary='ARM.exidx end 0x00a98648 (listing bound); next ObjC IMP 0x00a98648 OrangeTree -[update:accurateDT:isSimulation:]',
        selectors={
                 0xa977f0: (15226176, 'worldContentsChangedAtPos:'),
                 0xa977f8: (15226156, 'getX:Y:octaves:'),
                 0xa97804: (15226152, 'worldWidthMacro'),
                 0xa98090: (15226180, 'expertMode'),
                 0xa985f4: (15226176, 'worldContentsChangedAtPos:'),
                 0xa985fc: (15226156, 'getX:Y:octaves:'),
                 0xa98608: (15226152, 'worldWidthMacro'),
                 0xa98610: (15226184, 'tileIsKindOfSelf:'),
                 0xa98614: (15226188, 'removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:'),
                 0xa98624: (15226192, 'macroTiles'),
                 0xa98628: (15226196, 'worldTime'),
                 0xa9862c: (15226200, 'getWeatherFractionForPos:atWorldTime:'),
                 0xa98630: (15226204, 'getDayNightFractionForX:atWorldTime:'),
                 0xa9863c: (15226208, 'killAllOwnedTiles'),
                 0xa98640: (15226212, 'objectType'),
                 0xa98644: (15226216, 'dynamicWorldChangedAtPos:objectType:'),
        },
        imports={
                 0xa977f4: (17151904, 'objc_msgSend'),
                 0xa985f8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa97788: (17155068, 'OBJC_IVAR_$_Tree.dead', 104),
                 0xa977cc: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0xa977d0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xa977d4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa977d8: (17155096, 'OBJC_IVAR_$_Tree.treeSeasonOffset', 84),
                 0xa977e0: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0xa977e8: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xa977fc: (17155032, 'OBJC_IVAR_$_Tree.treeDensityNoiseFunction', 76),
                 0xa98080: (17155056, 'OBJC_IVAR_$_Tree.fruitCount', 128),
                 0xa9808c: (17155028, 'OBJC_IVAR_$_Tree.seasonOffsetNoiseFunction', 80),
                 0xa98094: (17155036, 'OBJC_IVAR_$_Tree.treeFruits', 124),
                 0xa985d8: (17155068, 'OBJC_IVAR_$_Tree.dead', 104),
                 0xa985dc: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0xa985e0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xa985e4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa985e8: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0xa985f0: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xa98600: (17155032, 'OBJC_IVAR_$_Tree.treeDensityNoiseFunction', 76),
                 0xa98638: (17155080, 'OBJC_IVAR_$_Tree.timeDied', 112),
        },
        classes={},
        instructions=[(11102072, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11109956, 'invalid')],
        calls=[(11102212, 'bl sym.imp.__aeabi_idiv'), (11102408, 'bl sym.imp.__aeabi_idiv'), (11102508, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11102552, 'bl sym.tileIsSolid_Tile_'), (11102588, 'bl sym.tileIsTree_Tile_'), (11102840, 'bl 0xa965f4'), (11103040, 'bl sym.makeIntpair_int__int_'), (11103068, 'bl loc.imp.objc_msgSend'), (11103332, 'bl loc.imp.objc_msgSend'), (11103456, 'bl loc.imp.objc_msgSend'), (11103564, 'bl loc.imp.objc_msgSend'), (11103716, 'blx lr'), (11104256, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11104404, 'bl sym.tileIsSolid_Tile_'), (11104448, 'bl sym.tileIsDeadTree_Tile_'), (11104500, 'bl sym.tileIsBush_Tile_'), (11104780, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11104992, 'bl loc.imp.objc_msgSend'), (11105108, 'bl loc.imp.objc_msgSend'), (11105204, 'bl loc.imp.objc_msgSend'), (11105284, 'bl loc.imp.objc_msgSend'), (11105484, 'bl sym.makeIntpair_int__int_'), (11105616, 'bl 0xa965f4'), (11105828, 'bl sym.makeIntpair_int__int_'), (11105856, 'bl loc.imp.objc_msgSend'), (11105964, 'blx r3'), (11105984, 'bl sym.tileIsTreeTrunk_Tile_'), (11106400, 'bl 0xa965f4'), (11106576, 'bl sym.makeIntpair_int__int_'), (11106604, 'bl loc.imp.objc_msgSend'), (11106868, 'bl loc.imp.objc_msgSend'), (11106992, 'bl loc.imp.objc_msgSend'), (11107100, 'bl loc.imp.objc_msgSend'), (11107252, 'blx lr'), (11107624, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11107792, 'blx r3'), (11107956, 'blx lr'), (11108100, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11108268, 'blx r3'), (11108432, 'blx lr'), (11108580, 'bl sym.makeIntpair_int__int_'), (11108644, 'bl sym.makeIntpair_int__int_'), (11108712, 'bl loc.imp.objc_msgSend'), (11108768, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (11108824, 'bl loc.imp.objc_msgSend'), (11108876, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (11108932, 'bl loc.imp.objc_msgSend'), (11108984, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (11109040, 'bl loc.imp.objc_msgSend'), (11109092, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (11109144, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11109224, 'bl loc.imp.objc_msgSend'), (11109264, 'bl loc.imp.objc_msgSend'), (11109332, 'bl loc.imp.objc_msgSend'), (11109372, 'bl loc.imp.objc_msgSend'), (11109464, 'bl loc.imp.objc_msgSend'), (11109512, 'bl sym.seasonForWorldX_int__double__World_'), (11109576, 'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_'), (11109672, 'bl loc.imp.objc_msgSend'), (11109720, 'bl loc.imp.objc_msgSend'), (11109796, 'bl loc.imp.objc_msgSend'), (11109832, 'bl loc.imp.objc_msgSend')],
        branches=[(11102140, 'beq', 11102148), (11102144, 'b', 11109836), (11102284, 'bge', 11108508), (11102528, 'beq', 11102612), (11102544, 'bne', 11102604), (11102564, 'bne', 11102604), (11102580, 'beq', 11102608), (11102600, 'bne', 11102608), (11102604, 'b', 11108508), (11102608, 'b', 11102612), (11102624, 'bgt', 11102664), (11102660, 'bge', 11106324), (11102676, 'beq', 11103072), (11102764, 'bne', 11102828), (11102780, 'beq', 11102828), (11102796, 'b', 11102840), (11103920, 'ble', 11103932), (11103952, 'bge', 11103972), (11104016, 'blt', 11104044), (11104052, 'beq', 11106248), (11104076, 'bge', 11106188), (11104088, 'bne', 11104120), (11104100, 'beq', 11104120), (11104116, 'blt', 11104160), (11104128, 'bne', 11106160), (11104140, 'beq', 11106160), (11104156, 'bge', 11106160), (11104276, 'beq', 11106156), (11104304, 'beq', 11104376), (11104396, 'beq', 11104592), (11104416, 'bne', 11104444), (11104440, 'beq', 11104472), (11104492, 'bne', 11104588), (11104512, 'beq', 11104584), (11104536, 'bne', 11104556), (11104540, 'b', 11104544), (11104552, 'b', 11104580), (11104564, 'bge', 11104576), (11104576, 'b', 11104580), (11104580, 'b', 11104584), (11104584, 'b', 11104588), (11104588, 'b', 11104592), (11104600, 'beq', 11105916), (11104692, 'bge', 11105608), (11104800, 'beq', 11104860), (11104816, 'beq', 11104852), (11104832, 'beq', 11104852), (11104848, 'bne', 11104860), (11105328, 'ble', 11105604), (11105604, 'b', 11105608), (11105876, 'bne', 11105892), (11105888, 'b', 11105900), (11105900, 'b', 11106012), (11105976, 'beq', 11106000), (11105996, 'beq', 11106008), (11106008, 'b', 11106012), (11106024, 'beq', 11106036), (11106044, 'beq', 11106152), (11106108, 'beq', 11106152), (11106112, 'b', 11106116), (11106124, 'bne', 11106140), (11106136, 'b', 11106148), (11106148, 'b', 11106152), (11106152, 'b', 11106156), (11106156, 'b', 11106160), (11106160, 'b', 11106164), (11106176, 'b', 11104068), (11106188, 'b', 11106192), (11106204, 'b', 11103996), (11106248, 'b', 11108460), (11106336, 'beq', 11106608), (11107456, 'ble', 11107468), (11107488, 'bge', 11107508), (11107532, 'bge', 11107988), (11107644, 'beq', 11107960), (11107708, 'beq', 11107744), (11107712, 'b', 11107716), (11107736, 'bne', 11107960), (11107740, 'b', 11107744), (11107804, 'beq', 11107960), (11107960, 'b', 11107964), (11107976, 'b', 11107520), (11108008, 'bge', 11108456), (11108120, 'beq', 11108436), (11108184, 'beq', 11108220), (11108188, 'b', 11108192), (11108212, 'bne', 11108436), (11108216, 'b', 11108220), (11108280, 'beq', 11108436), (11108436, 'b', 11108440), (11108452, 'b', 11107996), (11108456, 'b', 11108460), (11108460, 'b', 11108464), (11108476, 'b', 11102248), (11109604, 'bpl', 11109836)],
        semantics=('[OrangeTree updateGrowth:] (imp 0x00a96778, 1972w): the growth tick. Census: **objc_msgSend x26** + makeIntpair x6 + tileAtWorldPositionLoaded x6 + **`reloadDrawBlockGeometryForTile` x4** (the geometry-reload render tie - the growth invalidates the tile geometry; the sibling of the E84/E73 quad reloads) + __aeabi_idiv x2 + tileIsSolid + the per-tree helper 0xa965f4 x3. Window read (at_growth): the **ffffc908 gate** (ldrsb exit), the clamp constants **mvn 0x62 (-99) / movw 0x63 (99) / movw 8** (the growth clamp + divisor), the **rounding divide-by-2** (`add r5, r5, r5, lsr 31; sub r4, r4, r5, asr 1`) + `lsl r4, r4, 2` + __aeabi_idiv + **`add r0, r0, 0x7f` (+127 bias)**, and the ffffc8a0/c89c/c904/c924 position/state cells; 1 unclassified pool word (0x3fffffff the half-max sentinel).\n'),
    ),
    dict(
        name='ot_update',
        method='OrangeTree -[update:accurateDT:isSimulation:]',
        types='v20@0:4f8f12c16',
        start=11109960,
        end=11111792,
        disasm='disasm_worldtileloader_ot_update.txt',
        base_add=11109976,
        base_literal=11111788,
        boundary='ARM.exidx end 0x00a98d70 (listing bound); next ObjC IMP 0x00a98d70 OrangeTree -[makeTileDead:]',
        selectors={
                 0xa98d10: (15226220, 'update:accurateDT:isSimulation:'),
                 0xa98d24: (15226196, 'worldTime'),
                 0xa98d30: (15226192, 'macroTiles'),
                 0xa98d38: (15226184, 'tileIsKindOfSelf:'),
                 0xa98d4c: (15226212, 'objectType'),
                 0xa98d50: (15226216, 'dynamicWorldChangedAtPos:objectType:'),
                 0xa98d60: (15226224, 'maxHeightGeneVariation'),
                 0xa98d64: (15226228, 'growthRateGeneVariation'),
                 0xa98d68: (15226232, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
        },
        imports={
                 0xa98d0c: (17151900, 'objc_msgSendSuper2'),
                 0xa98d20: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa98d18: (17155068, 'OBJC_IVAR_$_Tree.dead', 104),
                 0xa98d1c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xa98d28: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa98d2c: (17155056, 'OBJC_IVAR_$_Tree.fruitCount', 128),
                 0xa98d34: (17155036, 'OBJC_IVAR_$_Tree.treeFruits', 124),
                 0xa98d3c: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0xa98d48: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xa98d54: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
        },
        classes={
                 0xa98d14: (15253068, 'OBJC_CLASS_$_OrangeTree'),
        },
        instructions=[(11109960, 'push {r4, r5, fp, lr}'), (11111788, 'invalid')],
        calls=[(11110116, 'blx lr'), (11110240, 'blx r2'), (11110292, 'bl sym.seasonForWorldX_int__double__World_'), (11110484, 'blx r2'), (11110528, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (11110600, 'blx r3'), (11110776, 'bl sym.imp.__modsi3'), (11110956, 'bl loc.imp.objc_msgSend'), (11110988, 'bl loc.imp.objc_msgSend'), (11111068, 'bl loc.imp.objc_msgSend'), (11111136, 'bl loc.imp.objc_msgSend'), (11111172, 'bl loc.imp.objc_msgSend'), (11111288, 'bl loc.imp.objc_msgSend'), (11111324, 'bl loc.imp.objc_msgSend'), (11111612, 'bl loc.imp.objc_msgSend'), (11111648, 'bl loc.imp.objc_msgSend')],
        branches=[(11110152, 'bne', 11111680), (11110352, 'bge', 11111676), (11110548, 'beq', 11111656), (11110612, 'beq', 11111336), (11110676, 'bne', 11111336), (11110680, 'b', 11110684), (11110792, 'beq', 11110808), (11110804, 'bne', 11111180), (11110840, 'blt', 11111180), (11110856, 'bne', 11111176), (11111176, 'b', 11111332), (11111192, 'beq', 11111328), (11111328, 'b', 11111332), (11111332, 'b', 11111652), (11111384, 'bge', 11111504), (11111500, 'b', 11111344), (11111652, 'b', 11111656), (11111656, 'b', 11111660), (11111672, 'b', 11110316), (11111676, 'b', 11111680)],
        semantics=('[OrangeTree update:accurateDT:isSimulation:] (imp 0x00a98648, 458w): the per-tick frame - **`seasonForWorldX(int, double, World*)`** (the shared season query) + objc_msgSend x16 + tile probes + the ffffc908-style gate; tile probes + helper 0xa965f4. The blockhead-facing tick (spawn/fruit/season notifies) riding the ffffc8xx cells.\n'),
    ),
    dict(
        name='cn_growth',
        method='CoconutTree -[updateGrowth:]',
        types='v12@0:4c8',
        start=11115312,
        end=11119152,
        disasm='disasm_worldtileloader_cn_growth.txt',
        base_add=11115328,
        base_literal=11119148,
        boundary='ARM.exidx end 0x00a9aa30 (listing bound); next ObjC IMP 0x00a9aa30 CoconutTree -[update:accurateDT:isSimulation:]',
        selectors={
                 0xa9a9f8: (15226272, 'worldContentsChangedAtPos:'),
                 0xa9aa04: (15226276, 'removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:'),
                 0xa9aa10: (15226280, 'macroTiles'),
                 0xa9aa1c: (15226284, 'objectType'),
                 0xa9aa20: (15226288, 'dynamicWorldChangedAtPos:objectType:'),
        },
        imports={
                 0xa9aa00: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa9a9d8: (17155068, 'OBJC_IVAR_$_Tree.dead', 104),
                 0xa9a9dc: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0xa9a9e0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xa9a9e4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa9a9e8: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0xa9a9f0: (17155096, 'OBJC_IVAR_$_Tree.treeSeasonOffset', 84),
                 0xa9a9f4: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xa9aa14: (17155056, 'OBJC_IVAR_$_Tree.fruitCount', 128),
                 0xa9aa24: (17155036, 'OBJC_IVAR_$_Tree.treeFruits', 124),
        },
        classes={},
        instructions=[(11115312, 'push {r4, r5, r6, sl, fp, lr}'), (11119148, 'subseq r5, ip, ip, lsr 31')],
        calls=[(11115516, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11115560, 'bl sym.tileIsSolid_Tile_'), (11115596, 'bl sym.tileIsTree_Tile_'), (11116072, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11116120, 'bl sym.tileIsSolid_Tile_'), (11116164, 'bl sym.tileIsDeadTree_Tile_'), (11116216, 'bl sym.tileIsBush_Tile_'), (11116492, 'bl sym.makeIntpair_int__int_'), (11116520, 'bl loc.imp.objc_msgSend'), (11116700, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11116748, 'bl sym.tileIsSolid_Tile_'), (11116792, 'bl sym.tileIsDeadTree_Tile_'), (11116844, 'bl sym.tileIsBush_Tile_'), (11117120, 'bl sym.makeIntpair_int__int_'), (11117148, 'bl loc.imp.objc_msgSend'), (11117392, 'bl sym.makeIntpair_int__int_'), (11117420, 'bl loc.imp.objc_msgSend'), (11117560, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11117844, 'blx lr'), (11117944, 'bl sym.makeIntpair_int__int_'), (11118024, 'bl sym.makeIntpair_int__int_'), (11118132, 'blx r3'), (11118188, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (11118296, 'blx r3'), (11118352, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (11118632, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11118828, 'bl loc.imp.objc_msgSend'), (11118864, 'bl loc.imp.objc_msgSend'), (11119012, 'bl loc.imp.objc_msgSend'), (11119048, 'bl loc.imp.objc_msgSend')],
        branches=[(11115376, 'beq', 11115384), (11115380, 'b', 11119056), (11115432, 'bge', 11117896), (11115536, 'beq', 11115620), (11115552, 'bne', 11115612), (11115572, 'bne', 11115612), (11115588, 'beq', 11115616), (11115608, 'bne', 11115616), (11115612, 'b', 11117896), (11115616, 'b', 11115620), (11115660, 'ble', 11115728), (11115708, 'ble', 11115724), (11115724, 'b', 11115728), (11115772, 'blt', 11117196), (11115808, 'beq', 11115856), (11115852, 'bne', 11115876), (11115872, 'b', 11115952), (11115884, 'beq', 11115932), (11115928, 'bne', 11115948), (11115948, 'b', 11115952), (11115980, 'bge', 11116576), (11116092, 'beq', 11116556), (11116112, 'beq', 11116308), (11116132, 'bne', 11116160), (11116156, 'beq', 11116188), (11116208, 'bne', 11116304), (11116228, 'beq', 11116300), (11116252, 'bne', 11116272), (11116256, 'b', 11116260), (11116268, 'b', 11116296), (11116280, 'bge', 11116292), (11116292, 'b', 11116296), (11116296, 'b', 11116300), (11116300, 'b', 11116304), (11116304, 'b', 11116308), (11116316, 'beq', 11116548), (11116532, 'bne', 11116544), (11116544, 'b', 11116552), (11116548, 'b', 11116576), (11116552, 'b', 11116556), (11116556, 'b', 11116560), (11116572, 'b', 11115968), (11116584, 'beq', 11117192), (11116608, 'blt', 11117188), (11116720, 'beq', 11117164), (11116740, 'beq', 11116936), (11116760, 'bne', 11116788), (11116784, 'beq', 11116816), (11116836, 'bne', 11116932), (11116856, 'beq', 11116928), (11116880, 'bne', 11116900), (11116884, 'b', 11116888), (11116896, 'b', 11116924), (11116908, 'bge', 11116920), (11116920, 'b', 11116924), (11116924, 'b', 11116928), (11116928, 'b', 11116932), (11116932, 'b', 11116936), (11116944, 'beq', 11117156), (11117152, 'b', 11117160), (11117156, 'b', 11117188), (11117160, 'b', 11117164), (11117164, 'b', 11117168), (11117184, 'b', 11116596), (11117188, 'b', 11117192), (11117192, 'b', 11117876), (11117208, 'beq', 11117872), (11117468, 'bge', 11117868), (11117580, 'beq', 11117848), (11117644, 'beq', 11117680), (11117648, 'b', 11117652), (11117672, 'bne', 11117848), (11117676, 'b', 11117680), (11117692, 'bne', 11117848), (11117848, 'b', 11117852), (11117864, 'b', 11117456), (11117868, 'b', 11117872), (11117872, 'b', 11117876), (11117876, 'b', 11117880), (11117892, 'b', 11115396), (11118388, 'ble', 11118872), (11118544, 'bne', 11118868), (11118652, 'beq', 11118712), (11118668, 'beq', 11118704), (11118684, 'beq', 11118704), (11118700, 'bne', 11118712), (11118868, 'b', 11119056), (11118904, 'beq', 11119052), (11119052, 'b', 11119056)],
        semantics=('[CoconutTree updateGrowth:] (imp 0x00a99b30, 960w): the growth tick. Census: **objc_msgSend x7** + makeIntpair x5 + tileAtWorldPositionLoaded x5 + **`reloadDrawBlockGeometryForTile` x4** (the geometry-reload render tie - the growth invalidates the tile geometry; the sibling of the E84/E73 quad reloads) + __aeabi_idiv x0 + tileIsSolid + tileIsDeadTree x2 + tileIsBush x2 + the per-tree helper 0xa99938 x0. Window read (at_growth): the **ffffc908 gate** (ldrsb exit), the clamp constants **mvn 0x62 (-99) / movw 0x63 (99) / movw 8** (the growth clamp + divisor), the **rounding divide-by-2** (`add r5, r5, r5, lsr 31; sub r4, r4, r5, asr 1`) + `lsl r4, r4, 2` + __aeabi_idiv + **`add r0, r0, 0x7f` (+127 bias)**, and the ffffc8a0/c89c/c904/c924 position/state cells; 1 unclassified pool word (0x3fffffff the half-max sentinel).\n'),
    ),
    dict(
        name='cn_update',
        method='CoconutTree -[update:accurateDT:isSimulation:]',
        types='v20@0:4f8f12c16',
        start=11119152,
        end=11121256,
        disasm='disasm_worldtileloader_cn_update.txt',
        base_add=11119168,
        base_literal=11121252,
        boundary='ARM.exidx end 0x00a9b268 (listing bound); next ObjC IMP 0x00a9b268 CoconutTree -[makeTileDead:]',
        selectors={
                 0xa9b200: (15226292, 'update:accurateDT:isSimulation:'),
                 0xa9b218: (15226296, 'worldTime'),
                 0xa9b228: (15226300, 'tileIsKindOfSelf:'),
                 0xa9b23c: (15226284, 'objectType'),
                 0xa9b240: (15226288, 'dynamicWorldChangedAtPos:objectType:'),
                 0xa9b24c: (15226304, 'expertMode'),
                 0xa9b258: (15226308, 'maxHeightGeneVariation'),
                 0xa9b25c: (15226312, 'growthRateGeneVariation'),
                 0xa9b260: (15226316, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
        },
        imports={
                 0xa9b1fc: (17151900, 'objc_msgSendSuper2'),
                 0xa9b214: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa9b208: (17155068, 'OBJC_IVAR_$_Tree.dead', 104),
                 0xa9b20c: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0xa9b210: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xa9b21c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa9b220: (17155056, 'OBJC_IVAR_$_Tree.fruitCount', 128),
                 0xa9b224: (17155036, 'OBJC_IVAR_$_Tree.treeFruits', 124),
                 0xa9b22c: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0xa9b238: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xa9b244: (17155096, 'OBJC_IVAR_$_Tree.treeSeasonOffset', 84),
        },
        classes={
                 0xa9b204: (15253072, 'OBJC_CLASS_$_CoconutTree'),
        },
        instructions=[(11119152, 'push {r4, r5, fp, lr}'), (11121252, 'subseq r5, ip, ip, lsr 1')],
        calls=[(11119308, 'blx lr'), (11119468, 'blx r2'), (11119520, 'bl sym.seasonForWorldX_int__double__World_'), (11119684, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11119756, 'blx r3'), (11119964, 'bl sym.imp.__modsi3'), (11120128, 'bl sym.imp.__aeabi_idiv'), (11120172, 'blx r3'), (11120204, 'bl sym.imp.__aeabi_idiv'), (11120368, 'bl loc.imp.objc_msgSend'), (11120400, 'bl loc.imp.objc_msgSend'), (11120488, 'bl loc.imp.objc_msgSend'), (11120588, 'bl loc.imp.objc_msgSend'), (11120624, 'bl loc.imp.objc_msgSend'), (11120740, 'bl loc.imp.objc_msgSend'), (11120776, 'bl loc.imp.objc_msgSend'), (11121072, 'bl loc.imp.objc_msgSend'), (11121108, 'bl loc.imp.objc_msgSend')],
        branches=[(11119344, 'bne', 11121140), (11119380, 'blt', 11121140), (11119580, 'bge', 11121136), (11119704, 'beq', 11121116), (11119768, 'beq', 11120796), (11119832, 'bne', 11120796), (11119836, 'b', 11119840), (11119980, 'beq', 11120020), (11119992, 'beq', 11120020), (11120004, 'beq', 11120020), (11120016, 'bne', 11120632), (11120032, 'bne', 11120628), (11120184, 'beq', 11120264), (11120224, 'bge', 11120240), (11120236, 'b', 11120248), (11120288, 'bge', 11120508), (11120504, 'b', 11120276), (11120628, 'b', 11120784), (11120644, 'beq', 11120780), (11120780, 'b', 11120784), (11120784, 'b', 11121112), (11120844, 'bge', 11120964), (11120960, 'b', 11120804), (11121112, 'b', 11121116), (11121116, 'b', 11121120), (11121132, 'b', 11119544), (11121136, 'b', 11121140)],
        semantics=('[CoconutTree update:accurateDT:isSimulation:] (imp 0x00a9aa30, 526w): the per-tick frame - **`seasonForWorldX(int, double, World*)`** (the shared season query) + objc_msgSend x9 + census probes: 1x tile probes + the ffffc908-style gate; tileAtWorldPositionLoaded x1 + __aeabi_idiv x2. The blockhead-facing tick (spawn/fruit/season notifies) riding the ffffc8xx cells.\n'),
    ),
    dict(
        name='ct_growth',
        method='CactusTree -[updateGrowth:]',
        types='v12@0:4c8',
        start=11876944,
        end=11881568,
        disasm='disasm_worldtileloader_ct_growth.txt',
        base_add=11876960,
        base_literal=11880432,
        boundary='ARM.exidx end 0x00b54c60 (listing bound); next ObjC IMP 0x00b54c60 CactusTree -[update:accurateDT:isSimulation:]',
        selectors={
                 0xb54c10: (15231548, 'worldContentsChangedAtPos:'),
                 0xb54c1c: (15231560, 'tileIsKindOfSelf:'),
                 0xb54c34: (15231552, 'objectType'),
                 0xb54c38: (15231556, 'dynamicWorldChangedAtPos:objectType:'),
                 0xb54c54: (15231564, 'macroTiles'),
        },
        imports={
                 0xb54c18: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xb547f4: (17155068, 'OBJC_IVAR_$_Tree.dead', 104),
                 0xb547f8: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0xb547fc: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xb54800: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xb54804: (17155096, 'OBJC_IVAR_$_Tree.treeSeasonOffset', 84),
                 0xb54bf0: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0xb54bf4: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xb54bf8: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xb54bfc: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0xb54c04: (17165904, 'OBJC_IVAR_$_CactusTree.splitHeightA', 136),
                 0xb54c08: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xb54c14: (17165912, 'OBJC_IVAR_$_CactusTree.splitDirection', 144),
                 0xb54c28: (17155036, 'OBJC_IVAR_$_Tree.treeFruits', 124),
                 0xb54c30: (17155056, 'OBJC_IVAR_$_Tree.fruitCount', 128),
                 0xb54c40: (17165908, 'OBJC_IVAR_$_CactusTree.splitHeightB', 140),
        },
        classes={},
        instructions=[(11876944, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11881564, 'subseq fp, r0, r4, asr 32')],
        calls=[(11877200, 'bl sym.imp.__aeabi_idiv'), (11877300, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11877344, 'bl sym.tileIsSolid_Tile_'), (11877380, 'bl sym.tileIsTree_Tile_'), (11877424, 'bl sym.tileIsSolid_Tile_'), (11877460, 'bl sym.tileIsDeadTree_Tile_'), (11877532, 'bl 0xb533ac'), (11877800, 'bl sym.makeIntpair_int__int_'), (11877828, 'bl loc.imp.objc_msgSend'), (11878108, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11878132, 'bl sym.tileIsSolid_Tile_'), (11878168, 'bl sym.tileIsDeadTree_Tile_'), (11878432, 'bl sym.makeIntpair_int__int_'), (11878568, 'bl loc.imp.objc_msgSend'), (11878604, 'bl loc.imp.objc_msgSend'), (11878608, 'bl 0xb533ac'), (11878888, 'bl sym.makeIntpair_int__int_'), (11878916, 'bl loc.imp.objc_msgSend'), (11878980, 'blx r3'), (11879400, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11879424, 'bl sym.tileIsSolid_Tile_'), (11879460, 'bl sym.tileIsDeadTree_Tile_'), (11879724, 'bl sym.makeIntpair_int__int_'), (11879860, 'bl loc.imp.objc_msgSend'), (11879896, 'bl loc.imp.objc_msgSend'), (11879900, 'bl 0xb533ac'), (11880180, 'bl sym.makeIntpair_int__int_'), (11880208, 'bl loc.imp.objc_msgSend'), (11880272, 'blx r3'), (11880512, 'bl sym.makeIntpair_int__int_'), (11880592, 'bl sym.makeIntpair_int__int_'), (11880700, 'blx r3'), (11880756, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (11880864, 'blx r3'), (11880920, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (11881220, 'bl loc.imp.objc_msgSend'), (11881256, 'bl loc.imp.objc_msgSend'), (11881404, 'bl loc.imp.objc_msgSend'), (11881440, 'bl loc.imp.objc_msgSend')],
        branches=[(11877008, 'beq', 11877016), (11877012, 'b', 11881448), (11877076, 'bge', 11880464), (11877320, 'beq', 11877404), (11877336, 'bne', 11877396), (11877356, 'bne', 11877396), (11877372, 'beq', 11877400), (11877392, 'bne', 11877400), (11877396, 'b', 11880464), (11877400, 'b', 11877404), (11877416, 'beq', 11880412), (11877436, 'bne', 11877456), (11877452, 'beq', 11877476), (11877472, 'beq', 11880412), (11877636, 'bge', 11877652), (11877648, 'b', 11877696), (11877660, 'ble', 11877680), (11877672, 'b', 11877688), (11877860, 'blt', 11879116), (11877872, 'beq', 11879116), (11877980, 'ble', 11878020), (11878124, 'beq', 11878932), (11878144, 'bne', 11878164), (11878160, 'beq', 11878184), (11878180, 'beq', 11878932), (11878280, 'blt', 11878608), (11878324, 'bne', 11878608), (11878712, 'bge', 11878728), (11878724, 'b', 11878768), (11878736, 'ble', 11878752), (11878748, 'b', 11878760), (11878928, 'b', 11879088), (11878992, 'bne', 11879008), (11879004, 'b', 11879084), (11879028, 'bne', 11879080), (11879032, 'b', 11879036), (11879080, 'b', 11879084), (11879084, 'b', 11879088), (11879100, 'beq', 11879112), (11879112, 'b', 11879116), (11879152, 'blt', 11880408), (11879164, 'beq', 11880408), (11879272, 'ble', 11879312), (11879416, 'beq', 11880224), (11879436, 'bne', 11879456), (11879452, 'beq', 11879476), (11879472, 'beq', 11880224), (11879572, 'blt', 11879900), (11879616, 'bne', 11879900), (11880004, 'bge', 11880020), (11880016, 'b', 11880060), (11880028, 'ble', 11880044), (11880040, 'b', 11880052), (11880220, 'b', 11880380), (11880284, 'bne', 11880300), (11880296, 'b', 11880376), (11880320, 'bne', 11880372), (11880324, 'b', 11880328), (11880372, 'b', 11880376), (11880376, 'b', 11880380), (11880392, 'beq', 11880404), (11880404, 'b', 11880408), (11880408, 'b', 11880412), (11880412, 'b', 11880416), (11880428, 'b', 11877040), (11880956, 'ble', 11881264), (11881112, 'bne', 11881260), (11881260, 'b', 11881448), (11881296, 'beq', 11881444), (11881444, 'b', 11881448)],
        semantics=('[CactusTree updateGrowth:] (imp 0x00b53a50, 1156w): the growth tick. Census: **objc_msgSend x11** + makeIntpair x7 + tileAtWorldPositionLoaded x3 + **`reloadDrawBlockGeometryForTile` x4** (the geometry-reload render tie - the growth invalidates the tile geometry; the sibling of the E84/E73 quad reloads) + __aeabi_idiv x0 + tileIsSolid + tileIsDeadTree x3 + the per-tree helper 0xb533ac x3. Window read (at_growth): the **ffffc908 gate** (ldrsb exit), the clamp constants **mvn 0x62 (-99) / movw 0x63 (99) / movw 8** (the growth clamp + divisor), the **rounding divide-by-2** (`add r5, r5, r5, lsr 31; sub r4, r4, r5, asr 1`) + `lsl r4, r4, 2` + __aeabi_idiv + **`add r0, r0, 0x7f` (+127 bias)**, and the ffffc8a0/c89c/c904/c924 position/state cells; 1 unclassified pool word (0x3fffffff the half-max sentinel).\n'),
    ),
    dict(
        name='ct_update',
        method='CactusTree -[update:accurateDT:isSimulation:]',
        types='v20@0:4f8f12c16',
        start=11881568,
        end=11884060,
        disasm='disasm_worldtileloader_ct_update.txt',
        base_add=11881584,
        base_literal=11884056,
        boundary='ARM.exidx end 0x00b5561c (listing bound); next ObjC IMP 0x00b5561c CactusTree -[makeTileDead:]',
        selectors={
                 0xb555b0: (15231568, 'update:accurateDT:isSimulation:'),
                 0xb555cc: (15231572, 'tutorialActive'),
                 0xb555d8: (15231576, 'loadNPCAtPosition:type:saveDict:isAdult:wasPlaced:placedByClient:'),
                 0xb555dc: (15231580, 'worldTime'),
                 0xb555e8: (15231560, 'tileIsKindOfSelf:'),
                 0xb555f8: (15231552, 'objectType'),
                 0xb555fc: (15231556, 'dynamicWorldChangedAtPos:objectType:'),
                 0xb5560c: (15231584, 'maxHeightGeneVariation'),
                 0xb55610: (15231588, 'growthRateGeneVariation'),
                 0xb55614: (15231592, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
        },
        imports={
                 0xb555ac: (17151900, 'objc_msgSendSuper2'),
                 0xb555c8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xb555b8: (17155068, 'OBJC_IVAR_$_Tree.dead', 104),
                 0xb555bc: (17165916, 'OBJC_IVAR_$_CactusTree.availableFood', 148),
                 0xb555c0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xb555c4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xb555d0: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xb555e0: (17155056, 'OBJC_IVAR_$_Tree.fruitCount', 128),
                 0xb555e4: (17155036, 'OBJC_IVAR_$_Tree.treeFruits', 124),
                 0xb555ec: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
        },
        classes={
                 0xb555b4: (15253160, 'OBJC_CLASS_$_CactusTree'),
        },
        instructions=[(11881568, 'push {r4, r5, r6, r7, fp, lr}'), (11884056, 'subseq sl, r0, ip, ror lr')],
        calls=[(11881724, 'blx lr'), (11882000, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11882100, 'blx r2'), (11882236, 'bl loc.imp.objc_msgSend'), (11882336, 'blx r2'), (11882388, 'bl sym.seasonForWorldX_int__double__World_'), (11882552, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11882624, 'blx r3'), (11882812, 'bl sym.imp.__modsi3'), (11882956, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11883168, 'bl loc.imp.objc_msgSend'), (11883200, 'bl loc.imp.objc_msgSend'), (11883288, 'bl loc.imp.objc_msgSend'), (11883388, 'bl loc.imp.objc_msgSend'), (11883424, 'bl loc.imp.objc_msgSend'), (11883540, 'bl loc.imp.objc_msgSend'), (11883576, 'bl loc.imp.objc_msgSend'), (11883872, 'bl loc.imp.objc_msgSend'), (11883908, 'bl loc.imp.objc_msgSend')],
        branches=[(11881760, 'bne', 11883940), (11881812, 'bpl', 11881880), (11881864, 'b', 11882252), (11882020, 'beq', 11882248), (11882036, 'bne', 11882248), (11882112, 'bne', 11882244), (11882244, 'b', 11882248), (11882248, 'b', 11882252), (11882448, 'bge', 11883936), (11882572, 'beq', 11883916), (11882636, 'beq', 11883592), (11882700, 'bne', 11883592), (11882704, 'b', 11882708), (11882828, 'beq', 11882844), (11882840, 'bne', 11883432), (11882856, 'bne', 11883428), (11882976, 'beq', 11883036), (11882992, 'beq', 11883028), (11883008, 'beq', 11883028), (11883024, 'bne', 11883036), (11883052, 'beq', 11883064), (11883088, 'bge', 11883308), (11883304, 'b', 11883076), (11883428, 'b', 11883584), (11883444, 'beq', 11883580), (11883580, 'b', 11883584), (11883584, 'b', 11883912), (11883640, 'bge', 11883764), (11883756, 'b', 11883600), (11883912, 'b', 11883916), (11883916, 'b', 11883920), (11883932, 'b', 11882412), (11883936, 'b', 11883940)],
        semantics=('[CactusTree update:accurateDT:isSimulation:] (imp 0x00b54c60, 623w): the per-tick frame - **`seasonForWorldX(int, double, World*)`** (the shared season query) + objc_msgSend x10 + census probes: 3x tile probes + the ffffc908-style gate; tileAtWorldPositionLoaded x3 + __modsi3 x1. The blockhead-facing tick (spawn/fruit/season notifies) riding the ffffc8xx cells.\n'),
    ),
    dict(
        name='pt_growth',
        method='PineTree -[updateGrowth:]',
        types='v12@0:4c8',
        start=11948792,
        end=11956032,
        disasm='disasm_worldtileloader_pt_growth.txt',
        base_add=11948812,
        base_literal=11952904,
        boundary='ARM.exidx end 0x00b66f40 (listing bound); next ObjC IMP 0x00b66f40 PineTree -[makeTileDead:]',
        selectors={
                 0xb66414: (15232192, 'worldContentsChangedAtPos:'),
                 0xb6641c: (15232140, 'getX:Y:octaves:'),
                 0xb66428: (15232136, 'worldWidthMacro'),
                 0xb66ef8: (15232192, 'worldContentsChangedAtPos:'),
                 0xb66f00: (15232140, 'getX:Y:octaves:'),
                 0xb66f0c: (15232136, 'worldWidthMacro'),
                 0xb66f14: (15232204, 'tileIsKindOfSelf:'),
                 0xb66f18: (15232208, 'removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:'),
                 0xb66f2c: (15232196, 'objectType'),
                 0xb66f30: (15232200, 'dynamicWorldChangedAtPos:objectType:'),
                 0xb66f3c: (15232212, 'macroTiles'),
        },
        imports={
                 0xb66418: (17151904, 'objc_msgSend'),
                 0xb66efc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xb66310: (17155068, 'OBJC_IVAR_$_Tree.dead', 104),
                 0xb66314: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0xb66318: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xb663dc: (17155096, 'OBJC_IVAR_$_Tree.treeSeasonOffset', 84),
                 0xb663f8: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xb66400: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xb66404: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0xb6640c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xb66420: (17155032, 'OBJC_IVAR_$_Tree.treeDensityNoiseFunction', 76),
                 0xb66bf0: (17155056, 'OBJC_IVAR_$_Tree.fruitCount', 128),
                 0xb66bf8: (17155028, 'OBJC_IVAR_$_Tree.seasonOffsetNoiseFunction', 80),
                 0xb66edc: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0xb66ee0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xb66ee4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xb66ee8: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0xb66ef0: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xb66f04: (17155032, 'OBJC_IVAR_$_Tree.treeDensityNoiseFunction', 76),
                 0xb66f20: (17155056, 'OBJC_IVAR_$_Tree.fruitCount', 128),
                 0xb66f28: (17155036, 'OBJC_IVAR_$_Tree.treeFruits', 124),
        },
        classes={},
        instructions=[(11948792, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11956028, 'invalid')],
        calls=[(11948932, 'bl sym.imp.__aeabi_idiv'), (11949116, 'bl sym.imp.__aeabi_idiv'), (11949204, 'bl sym.makeIntpair_int__int_'), (11949256, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11949300, 'bl sym.tileIsSolid_Tile_'), (11949336, 'bl sym.tileIsTree_Tile_'), (11949560, 'bl 0xb64f38'), (11949832, 'bl loc.imp.objc_msgSend'), (11950080, 'bl loc.imp.objc_msgSend'), (11950192, 'bl loc.imp.objc_msgSend'), (11950300, 'bl loc.imp.objc_msgSend'), (11950440, 'blx lr'), (11950956, 'bl sym.makeIntpair_int__int_'), (11951008, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11951156, 'bl sym.tileIsSolid_Tile_'), (11951200, 'bl sym.tileIsDeadTree_Tile_'), (11951252, 'bl sym.tileIsBush_Tile_'), (11951684, 'blx r2'), (11951812, 'blx ip'), (11951908, 'blx lr'), (11952092, 'bl sym.makeIntpair_int__int_'), (11952252, 'bl loc.imp.objc_msgSend'), (11952288, 'bl loc.imp.objc_msgSend'), (11952296, 'bl 0xb64f38'), (11952572, 'bl loc.imp.objc_msgSend'), (11952668, 'blx r3'), (11952688, 'bl sym.tileIsTreeTrunk_Tile_'), (11952996, 'bl 0xb64f38'), (11953308, 'bl loc.imp.objc_msgSend'), (11953572, 'bl loc.imp.objc_msgSend'), (11953696, 'bl loc.imp.objc_msgSend'), (11953804, 'bl loc.imp.objc_msgSend'), (11953956, 'blx lr'), (11954328, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11954496, 'blx r3'), (11954660, 'blx lr'), (11954800, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11954968, 'blx r3'), (11955132, 'blx lr'), (11955252, 'bl sym.makeIntpair_int__int_'), (11955340, 'bl sym.makeIntpair_int__int_'), (11955428, 'blx r3'), (11955484, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (11955572, 'blx r3'), (11955628, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (11955716, 'blx r3'), (11955772, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (11955860, 'blx r3'), (11955916, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_')],
        branches=[(11948860, 'beq', 11948868), (11948864, 'b', 11955920), (11949004, 'bge', 11955196), (11949276, 'beq', 11949360), (11949292, 'bne', 11949352), (11949312, 'bne', 11949352), (11949328, 'beq', 11949356), (11949348, 'bne', 11949356), (11949352, 'b', 11955196), (11949356, 'b', 11949360), (11949372, 'bgt', 11949412), (11949408, 'bge', 11952924), (11949424, 'beq', 11949836), (11949512, 'bne', 11949548), (11949528, 'beq', 11949548), (11949544, 'b', 11949560), (11949664, 'bge', 11949680), (11949676, 'b', 11949756), (11949688, 'ble', 11949740), (11949700, 'b', 11949748), (11950644, 'ble', 11950656), (11950676, 'bge', 11950696), (11950740, 'blt', 11950768), (11950776, 'beq', 11952908), (11950800, 'bge', 11952884), (11950812, 'bne', 11950844), (11950824, 'beq', 11950844), (11950840, 'blt', 11950884), (11950852, 'bne', 11952864), (11950864, 'beq', 11952864), (11950880, 'bge', 11952864), (11951028, 'beq', 11952860), (11951056, 'beq', 11951128), (11951148, 'beq', 11951344), (11951168, 'bne', 11951196), (11951192, 'beq', 11951224), (11951244, 'bne', 11951340), (11951264, 'beq', 11951336), (11951288, 'bne', 11951308), (11951292, 'b', 11951296), (11951304, 'b', 11951332), (11951316, 'bge', 11951328), (11951328, 'b', 11951332), (11951332, 'b', 11951336), (11951336, 'b', 11951340), (11951340, 'b', 11951344), (11951352, 'beq', 11952620), (11951444, 'bge', 11952296), (11951944, 'ble', 11952292), (11952292, 'b', 11952296), (11952400, 'bge', 11952416), (11952412, 'b', 11952476), (11952424, 'ble', 11952460), (11952436, 'b', 11952468), (11952592, 'bne', 11952608), (11952604, 'b', 11952616), (11952616, 'b', 11952716), (11952680, 'beq', 11952704), (11952700, 'beq', 11952712), (11952712, 'b', 11952716), (11952728, 'beq', 11952740), (11952748, 'beq', 11952856), (11952812, 'beq', 11952856), (11952816, 'b', 11952820), (11952828, 'bne', 11952844), (11952840, 'b', 11952852), (11952852, 'b', 11952856), (11952856, 'b', 11952860), (11952860, 'b', 11952864), (11952864, 'b', 11952868), (11952880, 'b', 11950792), (11952884, 'b', 11952888), (11952900, 'b', 11950720), (11952908, 'b', 11955164), (11952936, 'beq', 11953312), (11953100, 'bge', 11953120), (11953112, 'b', 11953232), (11953128, 'ble', 11953216), (11953140, 'b', 11953224), (11954160, 'ble', 11954172), (11954192, 'bge', 11954212), (11954236, 'bge', 11954688), (11954348, 'beq', 11954664), (11954412, 'beq', 11954448), (11954416, 'b', 11954420), (11954440, 'bne', 11954664), (11954444, 'b', 11954448), (11954508, 'beq', 11954664), (11954664, 'b', 11954668), (11954680, 'b', 11954224), (11954708, 'bge', 11955160), (11954820, 'beq', 11955136), (11954884, 'beq', 11954920), (11954888, 'b', 11954892), (11954912, 'bne', 11955136), (11954916, 'b', 11954920), (11954980, 'beq', 11955136), (11955136, 'b', 11955140), (11955152, 'b', 11954696), (11955160, 'b', 11955164), (11955164, 'b', 11955168), (11955180, 'b', 11948968)],
        semantics=('[PineTree updateGrowth:] (imp 0x00b652f8, 1810w): the growth tick. Census: **objc_msgSend x11** + makeIntpair x5 + tileAtWorldPositionLoaded x4 + **`reloadDrawBlockGeometryForTile` x4** (the geometry-reload render tie - the growth invalidates the tile geometry; the sibling of the E84/E73 quad reloads) + __aeabi_idiv x2 + tileIsSolid + the per-tree helper 0xb64f38 x3. Window read (at_growth): the **ffffc908 gate** (ldrsb exit), the clamp constants **mvn 0x62 (-99) / movw 0x63 (99) / movw 8** (the growth clamp + divisor), the **rounding divide-by-2** (`add r5, r5, r5, lsr 31; sub r4, r4, r5, asr 1`) + `lsl r4, r4, 2` + __aeabi_idiv + **`add r0, r0, 0x7f` (+127 bias)**, and the ffffc8a0/c89c/c904/c924 position/state cells; 1 unclassified pool word (0x3fffffff the half-max sentinel).\n'),
    ),
    dict(
        name='pt_update',
        method='PineTree -[update:accurateDT:isSimulation:]',
        types='v20@0:4f8f12c16',
        start=11956136,
        end=11958808,
        disasm='disasm_worldtileloader_pt_update.txt',
        base_add=11956152,
        base_literal=11958804,
        boundary='ARM.exidx end 0x00b67a18 (listing bound); next ObjC IMP 0x00b67a18 PineTree -[treeType]',
        selectors={
                 0xb679a0: (15232216, 'update:accurateDT:isSimulation:'),
                 0xb679c4: (15232152, 'npcExistsAtPos:ignoreNPC:'),
                 0xb679cc: (15232156, 'tutorialActive'),
                 0xb679d4: (15232160, 'loadNPCAtPosition:type:saveDict:isAdult:wasPlaced:placedByClient:'),
                 0xb679d8: (15232176, 'worldTime'),
                 0xb679e0: (15232212, 'macroTiles'),
                 0xb679e8: (15232204, 'tileIsKindOfSelf:'),
                 0xb679f8: (15232196, 'objectType'),
                 0xb679fc: (15232200, 'dynamicWorldChangedAtPos:objectType:'),
                 0xb67a08: (15232220, 'maxHeightGeneVariation'),
                 0xb67a0c: (15232224, 'growthRateGeneVariation'),
                 0xb67a10: (15232228, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
        },
        imports={
                 0xb6799c: (17151900, 'objc_msgSendSuper2'),
                 0xb679c8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xb679a8: (17155068, 'OBJC_IVAR_$_Tree.dead', 104),
                 0xb679ac: (17166152, 'OBJC_IVAR_$_PineTree.availableFood', 136),
                 0xb679b0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xb679b4: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0xb679b8: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xb679bc: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xb679dc: (17155056, 'OBJC_IVAR_$_Tree.fruitCount', 128),
                 0xb679e4: (17155036, 'OBJC_IVAR_$_Tree.treeFruits', 124),
                 0xb679ec: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
        },
        classes={
                 0xb679a4: (15253176, 'OBJC_CLASS_$_PineTree'),
        },
        instructions=[(11956136, 'push {r4, r5, r6, r7, fp, lr}'), (11958804, 'subeq r8, pc, r4, lsr fp')],
        calls=[(11956292, 'blx lr'), (11956596, 'bl sym.imp.__wrap_fmodf'), (11956712, 'bl sym.makeIntpair_int__int_'), (11956764, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11956840, 'bl 0xb64f38'), (11956952, 'bl loc.imp.objc_msgSend'), (11957028, 'blx r2'), (11957136, 'bl loc.imp.objc_msgSend'), (11957236, 'blx r2'), (11957288, 'bl sym.seasonForWorldX_int__double__World_'), (11957480, 'blx r2'), (11957524, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (11957596, 'blx r3'), (11957768, 'bl sym.imp.__modsi3'), (11957948, 'bl loc.imp.objc_msgSend'), (11957980, 'bl loc.imp.objc_msgSend'), (11958060, 'bl loc.imp.objc_msgSend'), (11958128, 'bl loc.imp.objc_msgSend'), (11958164, 'bl loc.imp.objc_msgSend'), (11958280, 'bl loc.imp.objc_msgSend'), (11958316, 'bl loc.imp.objc_msgSend'), (11958604, 'bl loc.imp.objc_msgSend'), (11958640, 'bl loc.imp.objc_msgSend')],
        branches=[(11956328, 'bne', 11958672), (11956380, 'bpl', 11956468), (11956444, 'b', 11957152), (11956540, 'ble', 11956632), (11956784, 'beq', 11957148), (11956800, 'bne', 11957148), (11956836, 'blt', 11957148), (11956876, 'ble', 11957148), (11956964, 'bne', 11957144), (11957040, 'bne', 11957144), (11957144, 'b', 11957148), (11957148, 'b', 11957152), (11957348, 'bge', 11958668), (11957544, 'beq', 11958648), (11957608, 'beq', 11958328), (11957672, 'bne', 11958328), (11957676, 'b', 11957680), (11957784, 'beq', 11957800), (11957796, 'bne', 11958172), (11957832, 'blt', 11958172), (11957848, 'bne', 11958168), (11958168, 'b', 11958324), (11958184, 'beq', 11958320), (11958320, 'b', 11958324), (11958324, 'b', 11958644), (11958376, 'bge', 11958496), (11958492, 'b', 11958336), (11958644, 'b', 11958648), (11958648, 'b', 11958652), (11958664, 'b', 11957312), (11958668, 'b', 11958672)],
        semantics=('[PineTree update:accurateDT:isSimulation:] (imp 0x00b66fa8, 668w): the per-tick frame - **`seasonForWorldX(int, double, World*)`** (the shared season query) + objc_msgSend x11 + census probes: 1x tile probes + the ffffc908-style gate; **__wrap_fmodf x1** (the coordinate wrap) + makeIntpair x1 + tileAtWorldPosition (unloaded variant) x1 + the per-tree helper 0xb64f38 x1. The blockhead-facing tick (spawn/fruit/season notifies) riding the ffffc8xx cells.\n'),
    ),
    dict(
        name='ch_growth',
        method='CherryTree -[updateGrowth:]',
        types='v12@0:4c8',
        start=13688992,
        end=13696332,
        disasm='disasm_worldtileloader_ch_growth.txt',
        base_add=13689012,
        base_literal=13692908,
        boundary='ARM.exidx end 0x00d0fd4c (listing bound); next ObjC IMP 0x00d0fd4c CherryTree -[makeTileDead:]',
        selectors={
                 0xd0f168: (15238288, 'worldContentsChangedAtPos:'),
                 0xd0f170: (15238268, 'getX:Y:octaves:'),
                 0xd0f17c: (15238264, 'worldWidthMacro'),
                 0xd0fce8: (15238292, 'expertMode'),
                 0xd0fd04: (15238288, 'worldContentsChangedAtPos:'),
                 0xd0fd0c: (15238268, 'getX:Y:octaves:'),
                 0xd0fd18: (15238264, 'worldWidthMacro'),
                 0xd0fd20: (15238304, 'tileIsKindOfSelf:'),
                 0xd0fd24: (15238308, 'removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:'),
                 0xd0fd38: (15238296, 'objectType'),
                 0xd0fd3c: (15238300, 'dynamicWorldChangedAtPos:objectType:'),
                 0xd0fd48: (15238312, 'macroTiles'),
        },
        imports={
                 0xd0f16c: (17151904, 'objc_msgSend'),
                 0xd0fd08: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd0eff0: (17155068, 'OBJC_IVAR_$_Tree.dead', 104),
                 0xd0f100: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0xd0f144: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0xd0f148: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xd0f14c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xd0f150: (17155096, 'OBJC_IVAR_$_Tree.treeSeasonOffset', 84),
                 0xd0f158: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0xd0f160: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xd0f174: (17155032, 'OBJC_IVAR_$_Tree.treeDensityNoiseFunction', 76),
                 0xd0f9f8: (17155056, 'OBJC_IVAR_$_Tree.fruitCount', 128),
                 0xd0fa04: (17155028, 'OBJC_IVAR_$_Tree.seasonOffsetNoiseFunction', 80),
                 0xd0fcec: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0xd0fcf0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xd0fcf4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xd0fcf8: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0xd0fd00: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xd0fd10: (17155032, 'OBJC_IVAR_$_Tree.treeDensityNoiseFunction', 76),
                 0xd0fd2c: (17155056, 'OBJC_IVAR_$_Tree.fruitCount', 128),
                 0xd0fd34: (17155036, 'OBJC_IVAR_$_Tree.treeFruits', 124),
        },
        classes={},
        instructions=[(13688992, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13696328, 'invalid')],
        calls=[(13689132, 'bl sym.imp.__aeabi_idiv'), (13689328, 'bl sym.imp.__aeabi_idiv'), (13689428, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13689472, 'bl sym.tileIsSolid_Tile_'), (13689508, 'bl sym.tileIsTree_Tile_'), (13689760, 'bl 0xd0df1c'), (13689960, 'bl sym.makeIntpair_int__int_'), (13689988, 'bl loc.imp.objc_msgSend'), (13690252, 'bl loc.imp.objc_msgSend'), (13690376, 'bl loc.imp.objc_msgSend'), (13690484, 'bl loc.imp.objc_msgSend'), (13690636, 'blx lr'), (13691176, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13691324, 'bl sym.tileIsSolid_Tile_'), (13691368, 'bl sym.tileIsDeadTree_Tile_'), (13691420, 'bl sym.tileIsBush_Tile_'), (13691708, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13691920, 'bl loc.imp.objc_msgSend'), (13692036, 'bl loc.imp.objc_msgSend'), (13692132, 'bl loc.imp.objc_msgSend'), (13692212, 'bl loc.imp.objc_msgSend'), (13692404, 'bl sym.makeIntpair_int__int_'), (13692564, 'bl loc.imp.objc_msgSend'), (13692600, 'bl loc.imp.objc_msgSend'), (13692616, 'bl 0xd0df1c'), (13692828, 'bl sym.makeIntpair_int__int_'), (13692856, 'bl loc.imp.objc_msgSend'), (13692964, 'blx r3'), (13692984, 'bl sym.tileIsTreeTrunk_Tile_'), (13693400, 'bl 0xd0df1c'), (13693576, 'bl sym.makeIntpair_int__int_'), (13693604, 'bl loc.imp.objc_msgSend'), (13693868, 'bl loc.imp.objc_msgSend'), (13693992, 'bl loc.imp.objc_msgSend'), (13694100, 'bl loc.imp.objc_msgSend'), (13694252, 'blx lr'), (13694624, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13694792, 'blx r3'), (13694956, 'blx lr'), (13695100, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13695268, 'blx r3'), (13695432, 'blx lr'), (13695552, 'bl sym.makeIntpair_int__int_'), (13695640, 'bl sym.makeIntpair_int__int_'), (13695728, 'blx r3'), (13695784, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (13695872, 'blx r3'), (13695928, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (13696016, 'blx r3'), (13696072, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (13696160, 'blx r3'), (13696216, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_')],
        branches=[(13689060, 'beq', 13689068), (13689064, 'b', 13696220), (13689204, 'bge', 13695496), (13689448, 'beq', 13689532), (13689464, 'bne', 13689524), (13689484, 'bne', 13689524), (13689500, 'beq', 13689528), (13689520, 'bne', 13689528), (13689524, 'b', 13695496), (13689528, 'b', 13689532), (13689544, 'bgt', 13689584), (13689580, 'bge', 13693324), (13689596, 'beq', 13689992), (13689684, 'bne', 13689748), (13689700, 'beq', 13689748), (13689716, 'b', 13689760), (13690840, 'ble', 13690852), (13690872, 'bge', 13690892), (13690936, 'blt', 13690964), (13690972, 'beq', 13693248), (13690996, 'bge', 13693228), (13691008, 'bne', 13691040), (13691020, 'beq', 13691040), (13691036, 'blt', 13691080), (13691048, 'bne', 13693208), (13691060, 'beq', 13693208), (13691076, 'bge', 13693208), (13691196, 'beq', 13693204), (13691224, 'beq', 13691296), (13691316, 'beq', 13691520), (13691336, 'bne', 13691364), (13691360, 'beq', 13691392), (13691412, 'bne', 13691516), (13691432, 'beq', 13691512), (13691456, 'bne', 13691484), (13691460, 'b', 13691464), (13691472, 'b', 13691508), (13691492, 'bge', 13691504), (13691504, 'b', 13691508), (13691508, 'b', 13691512), (13691512, 'b', 13691516), (13691516, 'b', 13691520), (13691528, 'beq', 13692916), (13691620, 'bge', 13692608), (13691728, 'beq', 13691788), (13691744, 'beq', 13691780), (13691760, 'beq', 13691780), (13691776, 'bne', 13691788), (13692256, 'ble', 13692604), (13692604, 'b', 13692608), (13692876, 'bne', 13692892), (13692888, 'b', 13692900), (13692900, 'b', 13693012), (13692976, 'beq', 13693000), (13692996, 'beq', 13693008), (13693008, 'b', 13693012), (13693024, 'beq', 13693036), (13693044, 'beq', 13693200), (13693108, 'beq', 13693200), (13693112, 'b', 13693116), (13693124, 'bne', 13693188), (13693136, 'b', 13693196), (13693196, 'b', 13693200), (13693200, 'b', 13693204), (13693204, 'b', 13693208), (13693208, 'b', 13693212), (13693224, 'b', 13690988), (13693228, 'b', 13693232), (13693244, 'b', 13690916), (13693248, 'b', 13695460), (13693336, 'beq', 13693608), (13694456, 'ble', 13694468), (13694488, 'bge', 13694508), (13694532, 'bge', 13694988), (13694644, 'beq', 13694960), (13694708, 'beq', 13694744), (13694712, 'b', 13694716), (13694736, 'bne', 13694960), (13694740, 'b', 13694744), (13694804, 'beq', 13694960), (13694960, 'b', 13694964), (13694976, 'b', 13694520), (13695008, 'bge', 13695456), (13695120, 'beq', 13695436), (13695184, 'beq', 13695220), (13695188, 'b', 13695192), (13695212, 'bne', 13695436), (13695216, 'b', 13695220), (13695280, 'beq', 13695436), (13695436, 'b', 13695440), (13695452, 'b', 13694996), (13695456, 'b', 13695460), (13695460, 'b', 13695464), (13695476, 'b', 13689168)],
        semantics=('[CherryTree updateGrowth:] (imp 0x00d0e0a0, 1835w): the growth tick. Census: **objc_msgSend x15** + makeIntpair x6 + tileAtWorldPositionLoaded x5 + **`reloadDrawBlockGeometryForTile` x4** (the geometry-reload render tie - the growth invalidates the tile geometry; the sibling of the E84/E73 quad reloads) + __aeabi_idiv x2 + tileIsSolid + the per-tree helper 0xd0df1c x3. Window read (at_growth): the **ffffc908 gate** (ldrsb exit), the clamp constants **mvn 0x62 (-99) / movw 0x63 (99) / movw 8** (the growth clamp + divisor), the **rounding divide-by-2** (`add r5, r5, r5, lsr 31; sub r4, r4, r5, asr 1`) + `lsl r4, r4, 2` + __aeabi_idiv + **`add r0, r0, 0x7f` (+127 bias)**, and the ffffc8a0/c89c/c904/c924 position/state cells; 1 unclassified pool word (0x3fffffff the half-max sentinel).\n'),
    ),
    dict(
        name='ch_update',
        method='CherryTree -[update:accurateDT:isSimulation:]',
        types='v20@0:4f8f12c16',
        start=13696436,
        end=13698188,
        disasm='disasm_worldtileloader_ch_update.txt',
        base_add=13696452,
        base_literal=13698184,
        boundary='ARM.exidx end 0x00d1048c (listing bound); next ObjC IMP 0x00d1048c CherryTree -[treeType]',
        selectors={
                 0xd10430: (15238316, 'update:accurateDT:isSimulation:'),
                 0xd10444: (15238320, 'worldTime'),
                 0xd10454: (15238304, 'tileIsKindOfSelf:'),
                 0xd10468: (15238296, 'objectType'),
                 0xd1046c: (15238300, 'dynamicWorldChangedAtPos:objectType:'),
                 0xd1047c: (15238324, 'maxHeightGeneVariation'),
                 0xd10480: (15238328, 'growthRateGeneVariation'),
                 0xd10484: (15238332, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
        },
        imports={
                 0xd1042c: (17151900, 'objc_msgSendSuper2'),
                 0xd10440: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd10438: (17155068, 'OBJC_IVAR_$_Tree.dead', 104),
                 0xd1043c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xd10448: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xd1044c: (17155056, 'OBJC_IVAR_$_Tree.fruitCount', 128),
                 0xd10450: (17155036, 'OBJC_IVAR_$_Tree.treeFruits', 124),
                 0xd10458: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0xd10464: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xd10470: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
        },
        classes={
                 0xd10434: (15253256, 'OBJC_CLASS_$_CherryTree'),
        },
        instructions=[(13696436, 'push {r4, r5, fp, lr}'), (13698184, 'eorseq pc, r4, r8, lsr 26')],
        calls=[(13696592, 'blx lr'), (13696716, 'blx r2'), (13696768, 'bl sym.seasonForWorldX_int__double__World_'), (13696932, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13697004, 'blx r3'), (13697176, 'bl sym.imp.__modsi3'), (13697356, 'bl loc.imp.objc_msgSend'), (13697388, 'bl loc.imp.objc_msgSend'), (13697468, 'bl loc.imp.objc_msgSend'), (13697536, 'bl loc.imp.objc_msgSend'), (13697572, 'bl loc.imp.objc_msgSend'), (13697688, 'bl loc.imp.objc_msgSend'), (13697724, 'bl loc.imp.objc_msgSend'), (13698012, 'bl loc.imp.objc_msgSend'), (13698048, 'bl loc.imp.objc_msgSend')],
        branches=[(13696628, 'bne', 13698080), (13696828, 'bge', 13698076), (13696952, 'beq', 13698056), (13697016, 'beq', 13697736), (13697080, 'bne', 13697736), (13697084, 'b', 13697088), (13697192, 'beq', 13697208), (13697204, 'bne', 13697580), (13697240, 'blt', 13697580), (13697256, 'bne', 13697576), (13697576, 'b', 13697732), (13697592, 'beq', 13697728), (13697728, 'b', 13697732), (13697732, 'b', 13698052), (13697784, 'bge', 13697904), (13697900, 'b', 13697744), (13698052, 'b', 13698056), (13698056, 'b', 13698060), (13698072, 'b', 13696792), (13698076, 'b', 13698080)],
        semantics=('[CherryTree update:accurateDT:isSimulation:] (imp 0x00d0fdb4, 438w): the per-tick frame - **`seasonForWorldX(int, double, World*)`** (the shared season query) + objc_msgSend x15 + tile probes + the ffffc908-style gate; tile probes + helper 0xd0df1c. The blockhead-facing tick (spawn/fruit/season notifies) riding the ffffc8xx cells.\n'),
    ),
    dict(
        name='mg_growth',
        method='MangoTree -[updateGrowth:]',
        types='v12@0:4c8',
        start=13940328,
        end=13947668,
        disasm='disasm_worldtileloader_mg_growth.txt',
        base_add=13940348,
        base_literal=13944244,
        boundary='ARM.exidx end 0x00d4d314 (listing bound); next ObjC IMP 0x00d4d314 MangoTree -[update:accurateDT:isSimulation:]',
        selectors={
                 0xd4c730: (15239744, 'worldContentsChangedAtPos:'),
                 0xd4c738: (15239724, 'getX:Y:octaves:'),
                 0xd4c744: (15239720, 'worldWidthMacro'),
                 0xd4d2b0: (15239748, 'expertMode'),
                 0xd4d2cc: (15239744, 'worldContentsChangedAtPos:'),
                 0xd4d2d4: (15239724, 'getX:Y:octaves:'),
                 0xd4d2e0: (15239720, 'worldWidthMacro'),
                 0xd4d2e8: (15239760, 'tileIsKindOfSelf:'),
                 0xd4d2ec: (15239764, 'removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:'),
                 0xd4d300: (15239752, 'objectType'),
                 0xd4d304: (15239756, 'dynamicWorldChangedAtPos:objectType:'),
                 0xd4d310: (15239768, 'macroTiles'),
        },
        imports={
                 0xd4c734: (17151904, 'objc_msgSend'),
                 0xd4d2d0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd4c5b8: (17155068, 'OBJC_IVAR_$_Tree.dead', 104),
                 0xd4c6c8: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0xd4c70c: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0xd4c710: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xd4c714: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xd4c718: (17155096, 'OBJC_IVAR_$_Tree.treeSeasonOffset', 84),
                 0xd4c720: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0xd4c728: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xd4c73c: (17155032, 'OBJC_IVAR_$_Tree.treeDensityNoiseFunction', 76),
                 0xd4cfc0: (17155056, 'OBJC_IVAR_$_Tree.fruitCount', 128),
                 0xd4cfcc: (17155028, 'OBJC_IVAR_$_Tree.seasonOffsetNoiseFunction', 80),
                 0xd4d2b4: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0xd4d2b8: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xd4d2bc: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xd4d2c0: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0xd4d2c8: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xd4d2d8: (17155032, 'OBJC_IVAR_$_Tree.treeDensityNoiseFunction', 76),
                 0xd4d2f4: (17155056, 'OBJC_IVAR_$_Tree.fruitCount', 128),
                 0xd4d2fc: (17155036, 'OBJC_IVAR_$_Tree.treeFruits', 124),
        },
        classes={},
        instructions=[(13940328, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13947664, 'invalid')],
        calls=[(13940468, 'bl sym.imp.__aeabi_idiv'), (13940664, 'bl sym.imp.__aeabi_idiv'), (13940764, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13940808, 'bl sym.tileIsSolid_Tile_'), (13940844, 'bl sym.tileIsTree_Tile_'), (13941096, 'bl 0xd4b4e4'), (13941296, 'bl sym.makeIntpair_int__int_'), (13941324, 'bl loc.imp.objc_msgSend'), (13941588, 'bl loc.imp.objc_msgSend'), (13941712, 'bl loc.imp.objc_msgSend'), (13941820, 'bl loc.imp.objc_msgSend'), (13941972, 'blx lr'), (13942512, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13942660, 'bl sym.tileIsSolid_Tile_'), (13942704, 'bl sym.tileIsDeadTree_Tile_'), (13942756, 'bl sym.tileIsBush_Tile_'), (13943044, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13943256, 'bl loc.imp.objc_msgSend'), (13943372, 'bl loc.imp.objc_msgSend'), (13943468, 'bl loc.imp.objc_msgSend'), (13943548, 'bl loc.imp.objc_msgSend'), (13943740, 'bl sym.makeIntpair_int__int_'), (13943900, 'bl loc.imp.objc_msgSend'), (13943936, 'bl loc.imp.objc_msgSend'), (13943952, 'bl 0xd4b4e4'), (13944164, 'bl sym.makeIntpair_int__int_'), (13944192, 'bl loc.imp.objc_msgSend'), (13944300, 'blx r3'), (13944320, 'bl sym.tileIsTreeTrunk_Tile_'), (13944736, 'bl 0xd4b4e4'), (13944912, 'bl sym.makeIntpair_int__int_'), (13944940, 'bl loc.imp.objc_msgSend'), (13945204, 'bl loc.imp.objc_msgSend'), (13945328, 'bl loc.imp.objc_msgSend'), (13945436, 'bl loc.imp.objc_msgSend'), (13945588, 'blx lr'), (13945960, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13946128, 'blx r3'), (13946292, 'blx lr'), (13946436, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13946604, 'blx r3'), (13946768, 'blx lr'), (13946888, 'bl sym.makeIntpair_int__int_'), (13946976, 'bl sym.makeIntpair_int__int_'), (13947064, 'blx r3'), (13947120, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (13947208, 'blx r3'), (13947264, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (13947352, 'blx r3'), (13947408, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (13947496, 'blx r3'), (13947552, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_')],
        branches=[(13940396, 'beq', 13940404), (13940400, 'b', 13947556), (13940540, 'bge', 13946832), (13940784, 'beq', 13940868), (13940800, 'bne', 13940860), (13940820, 'bne', 13940860), (13940836, 'beq', 13940864), (13940856, 'bne', 13940864), (13940860, 'b', 13946832), (13940864, 'b', 13940868), (13940880, 'bgt', 13940920), (13940916, 'bge', 13944660), (13940932, 'beq', 13941328), (13941020, 'bne', 13941084), (13941036, 'beq', 13941084), (13941052, 'b', 13941096), (13942176, 'ble', 13942188), (13942208, 'bge', 13942228), (13942272, 'blt', 13942300), (13942308, 'beq', 13944584), (13942332, 'bge', 13944564), (13942344, 'bne', 13942376), (13942356, 'beq', 13942376), (13942372, 'blt', 13942416), (13942384, 'bne', 13944544), (13942396, 'beq', 13944544), (13942412, 'bge', 13944544), (13942532, 'beq', 13944540), (13942560, 'beq', 13942632), (13942652, 'beq', 13942856), (13942672, 'bne', 13942700), (13942696, 'beq', 13942728), (13942748, 'bne', 13942852), (13942768, 'beq', 13942848), (13942792, 'bne', 13942820), (13942796, 'b', 13942800), (13942808, 'b', 13942844), (13942828, 'bge', 13942840), (13942840, 'b', 13942844), (13942844, 'b', 13942848), (13942848, 'b', 13942852), (13942852, 'b', 13942856), (13942864, 'beq', 13944252), (13942956, 'bge', 13943944), (13943064, 'beq', 13943124), (13943080, 'beq', 13943116), (13943096, 'beq', 13943116), (13943112, 'bne', 13943124), (13943592, 'ble', 13943940), (13943940, 'b', 13943944), (13944212, 'bne', 13944228), (13944224, 'b', 13944236), (13944236, 'b', 13944348), (13944312, 'beq', 13944336), (13944332, 'beq', 13944344), (13944344, 'b', 13944348), (13944360, 'beq', 13944372), (13944380, 'beq', 13944536), (13944444, 'beq', 13944536), (13944448, 'b', 13944452), (13944460, 'bne', 13944524), (13944472, 'b', 13944532), (13944532, 'b', 13944536), (13944536, 'b', 13944540), (13944540, 'b', 13944544), (13944544, 'b', 13944548), (13944560, 'b', 13942324), (13944564, 'b', 13944568), (13944580, 'b', 13942252), (13944584, 'b', 13946796), (13944672, 'beq', 13944944), (13945792, 'ble', 13945804), (13945824, 'bge', 13945844), (13945868, 'bge', 13946324), (13945980, 'beq', 13946296), (13946044, 'beq', 13946080), (13946048, 'b', 13946052), (13946072, 'bne', 13946296), (13946076, 'b', 13946080), (13946140, 'beq', 13946296), (13946296, 'b', 13946300), (13946312, 'b', 13945856), (13946344, 'bge', 13946792), (13946456, 'beq', 13946772), (13946520, 'beq', 13946556), (13946524, 'b', 13946528), (13946548, 'bne', 13946772), (13946552, 'b', 13946556), (13946616, 'beq', 13946772), (13946772, 'b', 13946776), (13946788, 'b', 13946332), (13946792, 'b', 13946796), (13946796, 'b', 13946800), (13946812, 'b', 13940504)],
        semantics=('[MangoTree updateGrowth:] (imp 0x00d4b668, 1835w): the growth tick. Census: **objc_msgSend x15** + makeIntpair x6 + tileAtWorldPositionLoaded x5 + **`reloadDrawBlockGeometryForTile` x4** (the geometry-reload render tie - the growth invalidates the tile geometry; the sibling of the E84/E73 quad reloads) + __aeabi_idiv x2 + tileIsSolid + the per-tree helper 0xd4b4e4 x3. Window read (at_growth): the **ffffc908 gate** (ldrsb exit), the clamp constants **mvn 0x62 (-99) / movw 0x63 (99) / movw 8** (the growth clamp + divisor), the **rounding divide-by-2** (`add r5, r5, r5, lsr 31; sub r4, r4, r5, asr 1`) + `lsl r4, r4, 2` + __aeabi_idiv + **`add r0, r0, 0x7f` (+127 bias)**, and the ffffc8a0/c89c/c904/c924 position/state cells; 1 unclassified pool word (0x3fffffff the half-max sentinel).\n'),
    ),
    dict(
        name='mg_update',
        method='MangoTree -[update:accurateDT:isSimulation:]',
        types='v20@0:4f8f12c16',
        start=13947668,
        end=13949496,
        disasm='disasm_worldtileloader_mg_update.txt',
        base_add=13947684,
        base_literal=13949492,
        boundary='ARM.exidx end 0x00d4da38 (listing bound); next ObjC IMP 0x00d4da38 MangoTree -[makeTileDead:]',
        selectors={
                 0xd4d9d8: (15239772, 'update:accurateDT:isSimulation:'),
                 0xd4d9ec: (15239776, 'worldTime'),
                 0xd4d9f8: (15239768, 'macroTiles'),
                 0xd4da00: (15239760, 'tileIsKindOfSelf:'),
                 0xd4da14: (15239752, 'objectType'),
                 0xd4da18: (15239756, 'dynamicWorldChangedAtPos:objectType:'),
                 0xd4da28: (15239780, 'maxHeightGeneVariation'),
                 0xd4da2c: (15239784, 'growthRateGeneVariation'),
                 0xd4da30: (15239788, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
        },
        imports={
                 0xd4d9d4: (17151900, 'objc_msgSendSuper2'),
                 0xd4d9e8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd4d9e0: (17155068, 'OBJC_IVAR_$_Tree.dead', 104),
                 0xd4d9e4: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xd4d9f0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xd4d9f4: (17155056, 'OBJC_IVAR_$_Tree.fruitCount', 128),
                 0xd4d9fc: (17155036, 'OBJC_IVAR_$_Tree.treeFruits', 124),
                 0xd4da04: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0xd4da10: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xd4da1c: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
        },
        classes={
                 0xd4d9dc: (15253280, 'OBJC_CLASS_$_MangoTree'),
        },
        instructions=[(13947668, 'push {r4, r5, fp, lr}'), (13949492, 'eorseq r2, r1, r8, asr 15')],
        calls=[(13947824, 'blx lr'), (13947948, 'blx r2'), (13948000, 'bl sym.seasonForWorldX_int__double__World_'), (13948192, 'blx r2'), (13948236, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (13948308, 'blx r3'), (13948480, 'bl sym.imp.__modsi3'), (13948660, 'bl loc.imp.objc_msgSend'), (13948692, 'bl loc.imp.objc_msgSend'), (13948772, 'bl loc.imp.objc_msgSend'), (13948840, 'bl loc.imp.objc_msgSend'), (13948876, 'bl loc.imp.objc_msgSend'), (13948992, 'bl loc.imp.objc_msgSend'), (13949028, 'bl loc.imp.objc_msgSend'), (13949316, 'bl loc.imp.objc_msgSend'), (13949352, 'bl loc.imp.objc_msgSend')],
        branches=[(13947860, 'bne', 13949384), (13948060, 'bge', 13949380), (13948256, 'beq', 13949360), (13948320, 'beq', 13949040), (13948384, 'bne', 13949040), (13948388, 'b', 13948392), (13948496, 'beq', 13948512), (13948508, 'bne', 13948884), (13948544, 'blt', 13948884), (13948560, 'bne', 13948880), (13948880, 'b', 13949036), (13948896, 'beq', 13949032), (13949032, 'b', 13949036), (13949036, 'b', 13949356), (13949088, 'bge', 13949208), (13949204, 'b', 13949048), (13949356, 'b', 13949360), (13949360, 'b', 13949364), (13949376, 'b', 13948024), (13949380, 'b', 13949384)],
        semantics=('[MangoTree update:accurateDT:isSimulation:] (imp 0x00d4d314, 457w): the per-tick frame - **`seasonForWorldX(int, double, World*)`** (the shared season query) + objc_msgSend x16 + tile probes + the ffffc908-style gate; tile probes + helper 0xd4b4e4. The blockhead-facing tick (spawn/fruit/season notifies) riding the ffffc8xx cells.\n'),
    ),
    dict(
        name='mp_growth',
        method='MapleTree -[updateGrowth:]',
        types='v12@0:4c8',
        start=14377256,
        end=14385168,
        disasm='disasm_worldtileloader_mp_growth.txt',
        base_add=14377276,
        base_literal=14380132,
        boundary='ARM.exidx end 0x00db8010 (listing bound); next ObjC IMP 0x00db8010 MapleTree -[makeTileDead:]',
        selectors={
                 0xdb72b4: (15241080, 'worldContentsChangedAtPos:'),
                 0xdb72bc: (15241060, 'getX:Y:octaves:'),
                 0xdb72c8: (15241056, 'worldWidthMacro'),
                 0xdb7fd4: (15241080, 'worldContentsChangedAtPos:'),
                 0xdb7fdc: (15241060, 'getX:Y:octaves:'),
                 0xdb7fe8: (15241056, 'worldWidthMacro'),
                 0xdb7ff0: (15241092, 'tileIsKindOfSelf:'),
                 0xdb7ff4: (15241096, 'removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:'),
                 0xdb7ffc: (15241084, 'objectType'),
                 0xdb8000: (15241088, 'dynamicWorldChangedAtPos:objectType:'),
                 0xdb800c: (15241100, 'macroTiles'),
        },
        imports={
                 0xdb72b8: (17151904, 'objc_msgSend'),
                 0xdb7fd8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xdb6c68: (17155068, 'OBJC_IVAR_$_Tree.dead', 104),
                 0xdb7170: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0xdb7174: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xdb7178: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xdb717c: (17155096, 'OBJC_IVAR_$_Tree.treeSeasonOffset', 84),
                 0xdb72a4: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0xdb72ac: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xdb72c0: (17155032, 'OBJC_IVAR_$_Tree.treeDensityNoiseFunction', 76),
                 0xdb7ad8: (17155056, 'OBJC_IVAR_$_Tree.fruitCount', 128),
                 0xdb7cb0: (17155056, 'OBJC_IVAR_$_Tree.fruitCount', 128),
                 0xdb7cd0: (17155028, 'OBJC_IVAR_$_Tree.seasonOffsetNoiseFunction', 80),
                 0xdb7cd8: (17155036, 'OBJC_IVAR_$_Tree.treeFruits', 124),
                 0xdb7fbc: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0xdb7fc0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xdb7fc4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xdb7fc8: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0xdb7fd0: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xdb7fe0: (17155032, 'OBJC_IVAR_$_Tree.treeDensityNoiseFunction', 76),
        },
        classes={},
        instructions=[(14377256, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (14385164, 'invalid')],
        calls=[(14377396, 'bl sym.imp.__aeabi_idiv'), (14377592, 'bl sym.imp.__aeabi_idiv'), (14377692, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (14377736, 'bl sym.tileIsSolid_Tile_'), (14377772, 'bl sym.tileIsTree_Tile_'), (14378000, 'bl 0xdb5fa4'), (14378200, 'bl sym.makeIntpair_int__int_'), (14378228, 'bl loc.imp.objc_msgSend'), (14378512, 'bl loc.imp.objc_msgSend'), (14378636, 'bl loc.imp.objc_msgSend'), (14378744, 'bl loc.imp.objc_msgSend'), (14378896, 'blx lr'), (14379108, 'bl sym.imp.__aeabi_idiv'), (14379808, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (14379956, 'bl sym.tileIsSolid_Tile_'), (14380000, 'bl sym.tileIsDeadTree_Tile_'), (14380052, 'bl sym.tileIsBush_Tile_'), (14380516, 'blx r2'), (14380644, 'blx ip'), (14380740, 'blx lr'), (14380924, 'bl sym.makeIntpair_int__int_'), (14381084, 'bl loc.imp.objc_msgSend'), (14381120, 'bl loc.imp.objc_msgSend'), (14381136, 'bl 0xdb5fa4'), (14381348, 'bl sym.makeIntpair_int__int_'), (14381376, 'bl loc.imp.objc_msgSend'), (14381492, 'blx r3'), (14381512, 'bl sym.tileIsTreeTrunk_Tile_'), (14381852, 'bl 0xdb5fa4'), (14382028, 'bl sym.makeIntpair_int__int_'), (14382056, 'bl loc.imp.objc_msgSend'), (14382340, 'bl loc.imp.objc_msgSend'), (14382464, 'bl loc.imp.objc_msgSend'), (14382572, 'bl loc.imp.objc_msgSend'), (14382724, 'blx lr'), (14382936, 'bl sym.imp.__aeabi_idiv'), (14383472, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (14383640, 'blx r3'), (14383804, 'blx lr'), (14383948, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (14384116, 'blx r3'), (14384280, 'blx lr'), (14384404, 'bl sym.makeIntpair_int__int_'), (14384492, 'bl sym.makeIntpair_int__int_'), (14384580, 'blx r3'), (14384636, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (14384724, 'blx r3'), (14384780, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (14384868, 'blx r3'), (14384924, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (14385012, 'blx r3'), (14385068, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_')],
        branches=[(14377324, 'beq', 14377332), (14377328, 'b', 14385072), (14377468, 'bge', 14384348), (14377712, 'beq', 14377796), (14377728, 'bne', 14377788), (14377748, 'bne', 14377788), (14377764, 'beq', 14377792), (14377784, 'bne', 14377792), (14377788, 'b', 14384348), (14377792, 'b', 14377796), (14377808, 'bgt', 14377848), (14377844, 'bge', 14381776), (14377860, 'beq', 14378232), (14377948, 'bne', 14377988), (14377964, 'beq', 14377988), (14377980, 'b', 14378000), (14379136, 'bge', 14379160), (14379148, 'b', 14379168), (14379260, 'bpl', 14379292), (14379280, 'b', 14379300), (14379400, 'bpl', 14379428), (14379420, 'b', 14379436), (14379472, 'ble', 14379484), (14379504, 'bge', 14379524), (14379568, 'blt', 14379596), (14379604, 'beq', 14381728), (14379628, 'bge', 14381708), (14379640, 'bne', 14379672), (14379652, 'beq', 14379672), (14379668, 'blt', 14379712), (14379680, 'bne', 14381688), (14379692, 'beq', 14381688), (14379708, 'bge', 14381688), (14379828, 'beq', 14381684), (14379856, 'beq', 14379928), (14379948, 'beq', 14380176), (14379968, 'bne', 14379996), (14379992, 'beq', 14380024), (14380044, 'bne', 14380172), (14380064, 'beq', 14380168), (14380088, 'bne', 14380140), (14380092, 'b', 14380096), (14380104, 'b', 14380164), (14380148, 'bge', 14380160), (14380160, 'b', 14380164), (14380164, 'b', 14380168), (14380168, 'b', 14380172), (14380172, 'b', 14380176), (14380184, 'beq', 14381444), (14380276, 'bge', 14381128), (14380776, 'ble', 14381124), (14381124, 'b', 14381128), (14381396, 'bne', 14381412), (14381408, 'b', 14381420), (14381420, 'b', 14381540), (14381504, 'beq', 14381528), (14381524, 'beq', 14381536), (14381536, 'b', 14381540), (14381552, 'beq', 14381564), (14381572, 'beq', 14381680), (14381636, 'beq', 14381680), (14381640, 'b', 14381644), (14381652, 'bne', 14381668), (14381664, 'b', 14381676), (14381676, 'b', 14381680), (14381680, 'b', 14381684), (14381684, 'b', 14381688), (14381688, 'b', 14381692), (14381704, 'b', 14379620), (14381708, 'b', 14381712), (14381724, 'b', 14379548), (14381728, 'b', 14384316), (14381788, 'beq', 14382060), (14382964, 'bge', 14382992), (14382976, 'b', 14383000), (14383092, 'bpl', 14383124), (14383112, 'b', 14383132), (14383232, 'bpl', 14383260), (14383252, 'b', 14383268), (14383304, 'ble', 14383316), (14383336, 'bge', 14383356), (14383380, 'bge', 14383836), (14383492, 'beq', 14383808), (14383556, 'beq', 14383592), (14383560, 'b', 14383564), (14383584, 'bne', 14383808), (14383588, 'b', 14383592), (14383652, 'beq', 14383808), (14383808, 'b', 14383812), (14383824, 'b', 14383368), (14383856, 'bge', 14384312), (14383968, 'beq', 14384284), (14384032, 'beq', 14384068), (14384036, 'b', 14384040), (14384060, 'bne', 14384284), (14384064, 'b', 14384068), (14384128, 'beq', 14384284), (14384284, 'b', 14384288), (14384300, 'b', 14383844), (14384312, 'b', 14384316), (14384316, 'b', 14384320), (14384332, 'b', 14377432)],
        semantics=('[MapleTree updateGrowth:] (imp 0x00db6128, 1978w): the growth tick. Census: **objc_msgSend x11** + makeIntpair x6 + tileAtWorldPositionLoaded x4 + **`reloadDrawBlockGeometryForTile` x4** (the geometry-reload render tie - the growth invalidates the tile geometry; the sibling of the E84/E73 quad reloads) + __aeabi_idiv x4 + tileIsSolid + the per-tree helper 0xdb5fa4 x3. Window read (at_growth): the **ffffc908 gate** (ldrsb exit), the clamp constants **mvn 0x62 (-99) / movw 0x63 (99) / movw 8** (the growth clamp + divisor), the **rounding divide-by-2** (`add r5, r5, r5, lsr 31; sub r4, r4, r5, asr 1`) + `lsl r4, r4, 2` + __aeabi_idiv + **`add r0, r0, 0x7f` (+127 bias)**, and the ffffc8a0/c89c/c904/c924 position/state cells; 1 unclassified pool word (0x3fffffff the half-max sentinel).\n'),
    ),
    dict(
        name='mp_update',
        method='MapleTree -[update:accurateDT:isSimulation:]',
        types='v20@0:4f8f12c16',
        start=14385272,
        end=14387100,
        disasm='disasm_worldtileloader_mp_update.txt',
        base_add=14385288,
        base_literal=14387096,
        boundary='ARM.exidx end 0x00db879c (listing bound); next ObjC IMP 0x00db879c MapleTree -[treeType]',
        selectors={
                 0xdb873c: (15241104, 'update:accurateDT:isSimulation:'),
                 0xdb8750: (15241108, 'worldTime'),
                 0xdb875c: (15241100, 'macroTiles'),
                 0xdb8764: (15241092, 'tileIsKindOfSelf:'),
                 0xdb8778: (15241084, 'objectType'),
                 0xdb877c: (15241088, 'dynamicWorldChangedAtPos:objectType:'),
                 0xdb878c: (15241112, 'maxHeightGeneVariation'),
                 0xdb8790: (15241116, 'growthRateGeneVariation'),
                 0xdb8794: (15241120, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
        },
        imports={
                 0xdb8738: (17151900, 'objc_msgSendSuper2'),
                 0xdb874c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xdb8744: (17155068, 'OBJC_IVAR_$_Tree.dead', 104),
                 0xdb8748: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xdb8754: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xdb8758: (17155056, 'OBJC_IVAR_$_Tree.fruitCount', 128),
                 0xdb8760: (17155036, 'OBJC_IVAR_$_Tree.treeFruits', 124),
                 0xdb8768: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0xdb8774: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xdb8780: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
        },
        classes={
                 0xdb8740: (15253328, 'OBJC_CLASS_$_MapleTree'),
        },
        instructions=[(14385272, 'push {r4, r5, fp, lr}'), (14387096, 'eoreq r7, sl, r4, ror 20')],
        calls=[(14385428, 'blx lr'), (14385552, 'blx r2'), (14385604, 'bl sym.seasonForWorldX_int__double__World_'), (14385796, 'blx r2'), (14385840, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (14385912, 'blx r3'), (14386084, 'bl sym.imp.__modsi3'), (14386264, 'bl loc.imp.objc_msgSend'), (14386296, 'bl loc.imp.objc_msgSend'), (14386376, 'bl loc.imp.objc_msgSend'), (14386444, 'bl loc.imp.objc_msgSend'), (14386480, 'bl loc.imp.objc_msgSend'), (14386596, 'bl loc.imp.objc_msgSend'), (14386632, 'bl loc.imp.objc_msgSend'), (14386920, 'bl loc.imp.objc_msgSend'), (14386956, 'bl loc.imp.objc_msgSend')],
        branches=[(14385464, 'bne', 14386988), (14385664, 'bge', 14386984), (14385860, 'beq', 14386964), (14385924, 'beq', 14386644), (14385988, 'bne', 14386644), (14385992, 'b', 14385996), (14386100, 'beq', 14386116), (14386112, 'bne', 14386488), (14386148, 'blt', 14386488), (14386164, 'bne', 14386484), (14386484, 'b', 14386640), (14386500, 'beq', 14386636), (14386636, 'b', 14386640), (14386640, 'b', 14386960), (14386692, 'bge', 14386812), (14386808, 'b', 14386652), (14386960, 'b', 14386964), (14386964, 'b', 14386968), (14386980, 'b', 14385628), (14386984, 'b', 14386988)],
        semantics=('[MapleTree update:accurateDT:isSimulation:] (imp 0x00db8078, 457w): the per-tick frame - **`seasonForWorldX(int, double, World*)`** (the shared season query) + objc_msgSend x16 + tile probes + the ffffc908-style gate; tile probes + helper 0xdb5fa4. The blockhead-facing tick (spawn/fruit/season notifies) riding the ffffc8xx cells.\n'),
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
        'batch': 'Tree growth + update giants (E87): the ten updateGrowth and ten update bodies - the growth contract + season tick; 20 bodies',
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
                        default=NATIVE / 'tree_growth.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale tree_growth.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
