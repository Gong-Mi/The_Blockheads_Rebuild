#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The electricity line: the Workbench save/net/lifecycle cluster: the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 7590 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/WORKBENCH_LIFECYCLE.md for the prose and boundaries.
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
    'bl 0xae6c18': 0x00ae6c18,
    'bl 0xae99f0': 0x00ae99f0,
    'bl 0xafd4ac': 0x00afd4ac,
    'bl 0xafd54c': 0x00afd54c,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector.Vector_float__float__float__float_': 0x004d0d08,
    'bl method.Vector.operator_Vector_': 0x004d6538,
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__wrap_free': 0x001c2e64,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_': 0x00a19598,
    'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_': 0x00a197b4,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileIsHalfDepth_Tile__World__intpair_': 0x00a14450,
    'bl sym.tileIsSolid_Tile_': 0x00a1179c,
}

SPECS = [
    dict(
        name='wl_getsavedict',
        method='Workbench -[getSaveDict]',
        types='@8@0:4',
        start=11436496,
        end=11441424,
        disasm='disasm_worldtileloader_wl_getsavedict.txt',
        base_add=11436516,
        base_literal=11440016,
        boundary='ARM.exidx end 0x00ae9510 (listing bound); next ObjC IMP 0x00ae9510 Workbench -[updateNetDataForClient:]',
        selectors={
                 0xae8f98: (15228888, 'getSaveDict'),
                 0xae8fac: (15228896, 'setObject:forKey:'),
                 0xae8fb0: (15228912, 'numberWithDouble:'),
                 0xae8fc0: (15228904, 'numberWithBool:'),
                 0xae8fcc: (15228900, 'numberWithFloat:'),
                 0xae8fe0: (15228908, 'numberWithUnsignedInt:'),
                 0xae8fec: (15228892, 'numberWithInt:'),
                 0xae948c: (15228888, 'getSaveDict'),
                 0xae9498: (15228896, 'setObject:forKey:'),
                 0xae94a0: (15228892, 'numberWithInt:'),
                 0xae94a4: (15228796, 'countByEnumeratingWithState:objects:count:'),
                 0xae94a8: (15228828, 'blockheads'),
                 0xae94c0: (15228780, 'craftableItem'),
                 0xae94e4: (15228788, 'count'),
                 0xae94f8: (15228916, 'array'),
                 0xae94fc: (15228808, 'addObject:'),
                 0xae9500: (15228920, 'saveData'),
                 0xae9508: (15228784, 'stringWithFormat:'),
        },
        imports={
                 0xae8f94: (17151900, 'objc_msgSendSuper2'),
                 0xae8fa4: (16366216, '__CFConstantStringClassReference'),
                 0xae8fa8: (17151904, 'objc_msgSend'),
                 0xae8fbc: (16366024, '__CFConstantStringClassReference'),
                 0xae8fc8: (16366008, '__CFConstantStringClassReference'),
                 0xae8fd4: (16366200, '__CFConstantStringClassReference'),
                 0xae8fdc: (16366056, '__CFConstantStringClassReference'),
                 0xae8fe8: (16366184, '__CFConstantStringClassReference'),
                 0xae8ff4: (16366168, '__CFConstantStringClassReference'),
                 0xae8ffc: (16366152, '__CFConstantStringClassReference'),
                 0xae9004: (16366136, '__CFConstantStringClassReference'),
                 0xae93b0: (16366120, '__CFConstantStringClassReference'),
                 0xae93b8: (16366040, '__CFConstantStringClassReference'),
                 0xae93c0: (16366104, '__CFConstantStringClassReference'),
                 0xae93c8: (16366088, '__CFConstantStringClassReference'),
                 0xae93d0: (16366072, '__CFConstantStringClassReference'),
                 0xae9494: (17151904, 'objc_msgSend'),
                 0xae94b0: (16366248, '__CFConstantStringClassReference'),
                 0xae94bc: (16366264, '__CFConstantStringClassReference'),
                 0xae94c4: (16366344, '__CFConstantStringClassReference'),
                 0xae94cc: (16366328, '__CFConstantStringClassReference'),
                 0xae94d4: (16366312, '__CFConstantStringClassReference'),
                 0xae94e0: (16366376, '__CFConstantStringClassReference'),
                 0xae9504: (16366360, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xae8fa0: (17165444, 'OBJC_IVAR_$_Workbench.currentFuelBlockhead', 108),
                 0xae8fb4: (17165388, 'OBJC_IVAR_$_Workbench.lastWorldTime', 256),
                 0xae8fc4: (17165368, 'OBJC_IVAR_$_Workbench.hasFuel', 220),
                 0xae8fd0: (17165376, 'OBJC_IVAR_$_Workbench.fuelFraction', 212),
                 0xae8fd8: (17165384, 'OBJC_IVAR_$_Workbench.fireSpreadTimer', 208),
                 0xae8fe4: (17165380, 'OBJC_IVAR_$_Workbench.availableElectricity', 222),
                 0xae8ff0: (17165400, 'OBJC_IVAR_$_Workbench.hurryCost', 204),
                 0xae8ff8: (17165404, 'OBJC_IVAR_$_Workbench.hurrying', 200),
                 0xae9000: (17165408, 'OBJC_IVAR_$_Workbench.hurrySeconds', 196),
                 0xae93ac: (17165412, 'OBJC_IVAR_$_Workbench.hurryTimer', 192),
                 0xae93b4: (17165416, 'OBJC_IVAR_$_Workbench.craftProgressCount', 188),
                 0xae93bc: (17165348, 'OBJC_IVAR_$_Workbench.level', 176),
                 0xae93c4: (17165420, 'OBJC_IVAR_$_Workbench.xScroll', 172),
                 0xae93cc: (17165424, 'OBJC_IVAR_$_Workbench.selectedIndex', 136),
                 0xae93d4: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xae9490: (17165444, 'OBJC_IVAR_$_Workbench.currentFuelBlockhead', 108),
                 0xae94ac: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xae94b4: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0xae94b8: (17165428, 'OBJC_IVAR_$_Workbench.craftingItemObject', 180),
                 0xae94c8: (17165432, 'OBJC_IVAR_$_Workbench.countCreated', 236),
                 0xae94d0: (17165436, 'OBJC_IVAR_$_Workbench.countLeft', 232),
                 0xae94d8: (17165440, 'OBJC_IVAR_$_Workbench.count', 228),
                 0xae94dc: (17165372, 'OBJC_IVAR_$_Workbench.light', 100),
                 0xae94e8: (17165448, 'OBJC_IVAR_$_Workbench.sourceItems', 140),
        },
        classes={
                 0xae8f9c: (15253120, 'OBJC_CLASS_$_Workbench'),
                 0xae8fb8: (15249648, 'OBJC_CLASS_$_NSNumber'),
                 0xae949c: (15249648, 'OBJC_CLASS_$_NSNumber'),
                 0xae94f0: (15249640, 'OBJC_CLASS_$_NSMutableArray'),
                 0xae950c: (15249636, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(11436496, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11441420, 'invalid')],
        calls=[(11436584, 'blx ip'), (11437252, 'blx ip'), (11437288, 'blx ip'), (11437348, 'blx r3'), (11437384, 'blx ip'), (11437444, 'blx lr'), (11437480, 'blx ip'), (11437540, 'blx r3'), (11437576, 'blx ip'), (11437636, 'blx lr'), (11437672, 'blx ip'), (11437732, 'blx lr'), (11437768, 'blx ip'), (11437828, 'blx lr'), (11437864, 'blx ip'), (11437924, 'blx r3'), (11437960, 'blx ip'), (11438020, 'blx r3'), (11438056, 'blx ip'), (11438116, 'blx r3'), (11438152, 'blx ip'), (11438212, 'blx lr'), (11438248, 'blx ip'), (11438308, 'blx lr'), (11438344, 'blx ip'), (11438404, 'blx r3'), (11438440, 'blx ip'), (11438500, 'blx lr'), (11438536, 'blx ip'), (11438696, 'blx r2'), (11438736, 'bl sym.imp.memset'), (11438784, 'blx lr'), (11438884, 'bl sym.imp.objc_enumerationMutation'), (11439076, 'blx ip'), (11439212, 'blx lr'), (11439248, 'blx ip'), (11439404, 'blx r3'), (11439492, 'blx ip'), (11439716, 'blx lr'), (11439752, 'blx ip'), (11439812, 'blx r3'), (11439848, 'blx ip'), (11439908, 'blx r3'), (11439944, 'blx ip'), (11440008, 'bl loc.imp.objc_msgSend_stret'), (11440164, 'bl sym.imp.memset'), (11440316, 'blx r2'), (11440424, 'bl loc.imp.objc_msgSend'), (11440544, 'blx lr'), (11440644, 'bl sym.imp.objc_enumerationMutation'), (11440744, 'blx ip'), (11440776, 'blx r3'), (11440876, 'blx ip'), (11441008, 'blx ip'), (11441044, 'blx ip'), (11441188, 'blx r3'), (11441276, 'blx ip')],
        branches=[(11438568, 'beq', 11439256), (11438796, 'beq', 11439100), (11438876, 'beq', 11438888), (11438952, 'bne', 11438968), (11438964, 'b', 11439104), (11439004, 'blo', 11438840), (11439096, 'bne', 11438840), (11439100, 'b', 11439104), (11439112, 'beq', 11439252), (11439252, 'b', 11439256), (11439288, 'beq', 11441116), (11439328, 'beq', 11441116), (11439424, 'beq', 11439496), (11439992, 'beq', 11440136), (11440012, 'b', 11440168), (11440192, 'bge', 11441112), (11440228, 'beq', 11441048), (11440324, 'bls', 11441048), (11440556, 'beq', 11440900), (11440636, 'beq', 11440648), (11440804, 'blo', 11440600), (11440896, 'bne', 11440600), (11440900, 'b', 11440904), (11441048, 'b', 11441052), (11441064, 'b', 11440180), (11441112, 'b', 11441116), (11441208, 'beq', 11441280)],
        semantics=('[Workbench getSaveDict] (imp 0x00ae81d0, 1232w): the save-dict builder - the super call + **NSDictionary fast-enumeration** (`objc_enumerationMutation` x2 @the loops) + objc_msgSend/stret; the save fields ride the ffffbcac chain (14x) and the **save-key pool fff3bf94/bf84/bed4/bec4/bef4** with the fffff180/190/194/158/144/14c/154 state cells (fuel, level, crafting state).\n'),
    ),
    dict(
        name='wl_worldchanged',
        method='Workbench -[worldChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=11520824,
        end=11523244,
        disasm='disasm_worldtileloader_wl_worldchanged.txt',
        base_add=11520840,
        base_literal=11523240,
        boundary='ARM.exidx end 0x00afd4ac (listing bound); next ObjC IMP 0x00afd4e8 Workbench -[freeblockCreationItemType]',
        selectors={
                 0xafd470: (15229244, 'worldChanged:'),
                 0xafd484: (15229204, 'worldWidthMacro'),
                 0xafd4a4: (15229248, 'remove:'),
        },
        imports={
                 0xafd46c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xafd464: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xafd468: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xafd474: (17165372, 'OBJC_IVAR_$_Workbench.light', 100),
                 0xafd478: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xafd480: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(11520824, 'push {r4, r5, fp, lr}'), (11523240, 'subseq r2, r6, r4, lsr 31')],
        calls=[(11520976, 'blx r3'), (11521364, 'bl loc.imp.objc_msgSend'), (11521388, 'bl sym.imp.__aeabi_idiv'), (11521484, 'bl loc.imp.objc_msgSend'), (11521604, 'bl loc.imp.objc_msgSend'), (11521620, 'bl sym.imp.__aeabi_idiv'), (11521716, 'bl loc.imp.objc_msgSend'), (11521800, 'bl 0xafd4ac'), (11521972, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11522000, 'bl sym.tileIsSolid_Tile_'), (11522096, 'blx r3'), (11522192, 'bl sym.makeIntpair_int__int_'), (11522212, 'bl sym.tileIsHalfDepth_Tile__World__intpair_'), (11522316, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11522440, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11522504, 'bl sym.makeIntpair_int__int_'), (11522524, 'bl sym.tileIsHalfDepth_Tile__World__intpair_'), (11522560, 'bl sym.tileIsSolid_Tile_'), (11522660, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11522724, 'bl sym.makeIntpair_int__int_'), (11522744, 'bl sym.tileIsHalfDepth_Tile__World__intpair_'), (11522780, 'bl sym.tileIsSolid_Tile_'), (11522880, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11522944, 'bl sym.makeIntpair_int__int_'), (11522964, 'bl sym.tileIsHalfDepth_Tile__World__intpair_'), (11523000, 'bl sym.tileIsSolid_Tile_'), (11523060, 'blx r3')],
        branches=[(11520888, 'beq', 11520896), (11520892, 'b', 11523164), (11521004, 'beq', 11523164), (11521244, 'beq', 11523160), (11521400, 'blt', 11521516), (11521512, 'b', 11521796), (11521632, 'bge', 11521748), (11521744, 'b', 11521788), (11521808, 'bge', 11523096), (11521852, 'beq', 11521896), (11521892, 'blt', 11523096), (11521992, 'beq', 11523092), (11522012, 'bne', 11523092), (11522048, 'bne', 11522104), (11522100, 'b', 11523160), (11522224, 'bne', 11523084), (11522240, 'beq', 11523084), (11522336, 'beq', 11523080), (11522352, 'bne', 11523080), (11522536, 'bne', 11523076), (11522552, 'beq', 11523076), (11522572, 'bne', 11523076), (11522756, 'bne', 11523072), (11522772, 'beq', 11523072), (11522792, 'bne', 11523072), (11522976, 'bne', 11523068), (11522992, 'beq', 11523068), (11523012, 'bne', 11523068), (11523064, 'b', 11523160), (11523068, 'b', 11523072), (11523072, 'b', 11523076), (11523076, 'b', 11523080), (11523080, 'b', 11523084), (11523084, 'b', 11523088), (11523088, 'b', 11523092), (11523092, 'b', 11523096), (11523096, 'b', 11523100), (11523156, 'b', 11521092), (11523160, 'b', 11523164)],
        semantics=("[Workbench worldChanged:] (imp 0x00afcb38, 605w): the neighbourhood re-check - the **same solver shape as the Torch's worldContentsChanged (E72)**: `tileAtWorldPositionLoaded` x5 + `tileIsSolid` x4 + `makeIntpair` x4 + **`tileIsHalfDepth` x4** + `__aeabi_idiv` x2; the ffffc89c/c8a0 position cells + the ffffcacc gate (@0xafcb38+) and the fffff148 state feed the arm decisions (the workbench reacts to its support tiles changing).\n"),
    ),
    dict(
        name='wl_remove',
        method='Workbench -[remove:]',
        types='v12@0:4@8',
        start=11524212,
        end=11525828,
        disasm='disasm_worldtileloader_wl_remove.txt',
        base_add=11524228,
        base_literal=11525824,
        boundary='ARM.exidx end 0x00afdec4 (listing bound); next ObjC IMP 0x00afdec4 Workbench -[fuelCount]',
        selectors={
                 0xafde78: (15229104, 'isNet'),
                 0xafde88: (15229028, 'abortCraft'),
                 0xafde94: (15228704, 'release'),
                 0xafde98: (15229252, 'removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:'),
                 0xafdeb0: (15228888, 'getSaveDict'),
                 0xafdeb4: (15228992, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
                 0xafdeb8: (15229256, 'setNeedsRemoved:'),
        },
        imports={
                 0xafde74: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xafde64: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xafde68: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0xafde6c: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xafde70: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0xafde7c: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0xafde80: (17156816, 'OBJC_IVAR_$_InteractionObject.remoteBlockheadInUseUniqueID', 72),
                 0xafde8c: (17165396, 'OBJC_IVAR_$_Workbench.isInUseFuel', 112),
                 0xafde90: (17165444, 'OBJC_IVAR_$_Workbench.currentFuelBlockhead', 108),
                 0xafde9c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xafdea0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xafdea4: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xafdeac: (17165348, 'OBJC_IVAR_$_Workbench.level', 176),
                 0xafdebc: (17156820, 'OBJC_IVAR_$_InteractionObject.needsToBeRemovedWhenInteractionEnds', 96),
        },
        classes={},
        instructions=[(11524212, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11524268, 'cmp r0, 1'), (11524388, 'cmp r0, 0'), (11525824, 'subseq r2, r6, r8, ror 4')],
        calls=[(11524456, 'blx r2'), (11524596, 'blx r2'), (11524736, 'blx r3'), (11524940, 'bl 0xafd54c'), (11524972, 'bl loc.imp.objc_msgSend'), (11525060, 'bl loc.imp.objc_msgSend'), (11525152, 'blx ip'), (11525336, 'blx r5'), (11525432, 'blx ip'), (11525652, 'blx lr'), (11525720, 'blx ip')],
        branches=[(11524276, 'bne', 11524284), (11524280, 'b', 11525724), (11524316, 'bne', 11524356), (11524352, 'beq', 11524360), (11524356, 'b', 11525724), (11524392, 'beq', 11524604), (11524468, 'bne', 11524520), (11524512, 'beq', 11524556), (11524516, 'b', 11524520), (11524552, 'b', 11525724), (11524600, 'b', 11524604), (11524636, 'beq', 11524764), (11525180, 'bne', 11525440), (11525436, 'b', 11525660), (11525472, 'beq', 11525512), (11525508, 'bne', 11525656), (11525656, 'b', 11525660)],
        semantics=('[Workbench remove:] (imp 0x00afd874, 404w): the removal - **type == 1 exits early** (`cmp r0, 1; bne` @0xafd8ac: the type-1 variant is exempt from this path); then the ffffc8d4 + ffffcacc gates (@0xafd8dc/0xafd900), the ffffcffd8 record gate (@0xafd924) and the ffe265bc + ffffcffd0 crafting-record read; the teardown continues through the fffff120 type chain.\n'),
    ),
    dict(
        name='wl_ctor_save',
        method='Workbench -[initWithWorld:dynamicWorld:saveDict:cache:]',
        types='@24@0:4@8@12@16@20',
        start=11423448,
        end=11429008,
        disasm='disasm_worldtileloader_wl_ctor_save.txt',
        base_add=11423468,
        base_literal=11426560,
        boundary='ARM.exidx end 0x00ae6490 (listing bound); next ObjC IMP 0x00ae6490 Workbench -[initWithWorld:dynamicWorld:cache:netData:]',
        selectors={
                 0xae5b08: (15228760, 'initWithWorld:dynamicWorld:saveDict:cache:'),
                 0xae5b18: (15228724, 'objectForKey:'),
                 0xae5b24: (15228740, 'unsignedIntValue'),
                 0xae5b30: (15228732, 'boolValue'),
                 0xae5b3c: (15228764, 'doubleValue'),
                 0xae5b50: (15228728, 'floatValue'),
                 0xae60dc: (15228736, 'intValue'),
                 0xae63b8: (15228724, 'objectForKey:'),
                 0xae63c4: (15228736, 'intValue'),
                 0xae63d8: (15228776, 'initWithCraftableItem:'),
                 0xae63dc: (15228712, 'alloc'),
                 0xae63e4: (15228772, 'bytes'),
                 0xae63ec: (15228768, 'initWithSaveDict:'),
                 0xae63f8: (15228780, 'craftableItem'),
                 0xae6414: (15228812, 'setInteractionWorkbench:'),
                 0xae6438: (15228816, 'initWithWorld:dynamicWorld:saveDict:cache:parentObject:'),
                 0xae6444: (15228680, 'macroTiles'),
                 0xae6448: (15228752, 'initSubDerivedItems'),
                 0xae6454: (15228704, 'release'),
                 0xae6458: (15228788, 'count'),
                 0xae6460: (15228784, 'stringWithFormat:'),
                 0xae6468: (15228796, 'countByEnumeratingWithState:objects:count:'),
                 0xae6474: (15228792, 'init'),
                 0xae6478: (15228808, 'addObject:'),
                 0xae647c: (15228804, 'autorelease'),
                 0xae6488: (15228800, 'initWithSaveData:'),
        },
        imports={
                 0xae5b04: (17151900, 'objc_msgSendSuper2'),
                 0xae5b10: (16366248, '__CFConstantStringClassReference'),
                 0xae5b14: (17151904, 'objc_msgSend'),
                 0xae5b28: (16366056, '__CFConstantStringClassReference'),
                 0xae5b34: (16366232, '__CFConstantStringClassReference'),
                 0xae5b40: (16366216, '__CFConstantStringClassReference'),
                 0xae5b48: (16366024, '__CFConstantStringClassReference'),
                 0xae5b54: (16366008, '__CFConstantStringClassReference'),
                 0xae5b5c: (16366200, '__CFConstantStringClassReference'),
                 0xae60e0: (16366184, '__CFConstantStringClassReference'),
                 0xae60e8: (16366168, '__CFConstantStringClassReference'),
                 0xae60f0: (16366152, '__CFConstantStringClassReference'),
                 0xae60f8: (16366136, '__CFConstantStringClassReference'),
                 0xae6100: (16366120, '__CFConstantStringClassReference'),
                 0xae6108: (16366040, '__CFConstantStringClassReference'),
                 0xae6110: (16366104, '__CFConstantStringClassReference'),
                 0xae6118: (16366088, '__CFConstantStringClassReference'),
                 0xae6120: (16366072, '__CFConstantStringClassReference'),
                 0xae63b0: (16366248, '__CFConstantStringClassReference'),
                 0xae63b4: (17151904, 'objc_msgSend'),
                 0xae63cc: (16366264, '__CFConstantStringClassReference'),
                 0xae63d0: (16366296, '__CFConstantStringClassReference'),
                 0xae63e8: (16366280, '__CFConstantStringClassReference'),
                 0xae6400: (16366344, '__CFConstantStringClassReference'),
                 0xae6408: (16366328, '__CFConstantStringClassReference'),
                 0xae6410: (16366312, '__CFConstantStringClassReference'),
                 0xae6420: (16366376, '__CFConstantStringClassReference'),
                 0xae645c: (16366360, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xae5b1c: (17165392, 'OBJC_IVAR_$_Workbench.savedBlockheadIndexFuel', 116),
                 0xae5b20: (17165380, 'OBJC_IVAR_$_Workbench.availableElectricity', 222),
                 0xae5b2c: (17165396, 'OBJC_IVAR_$_Workbench.isInUseFuel', 112),
                 0xae5b38: (17165388, 'OBJC_IVAR_$_Workbench.lastWorldTime', 256),
                 0xae5b44: (17165368, 'OBJC_IVAR_$_Workbench.hasFuel', 220),
                 0xae5b4c: (17165376, 'OBJC_IVAR_$_Workbench.fuelFraction', 212),
                 0xae5b58: (17165384, 'OBJC_IVAR_$_Workbench.fireSpreadTimer', 208),
                 0xae5b60: (17165400, 'OBJC_IVAR_$_Workbench.hurryCost', 204),
                 0xae60e4: (17165404, 'OBJC_IVAR_$_Workbench.hurrying', 200),
                 0xae60ec: (17165408, 'OBJC_IVAR_$_Workbench.hurrySeconds', 196),
                 0xae60f4: (17165412, 'OBJC_IVAR_$_Workbench.hurryTimer', 192),
                 0xae60fc: (17165416, 'OBJC_IVAR_$_Workbench.craftProgressCount', 188),
                 0xae6104: (17165348, 'OBJC_IVAR_$_Workbench.level', 176),
                 0xae610c: (17165420, 'OBJC_IVAR_$_Workbench.xScroll', 172),
                 0xae6114: (17165424, 'OBJC_IVAR_$_Workbench.selectedIndex', 136),
                 0xae611c: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xae63bc: (17165392, 'OBJC_IVAR_$_Workbench.savedBlockheadIndexFuel', 116),
                 0xae63c0: (17165396, 'OBJC_IVAR_$_Workbench.isInUseFuel', 112),
                 0xae63c8: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0xae63d4: (17165428, 'OBJC_IVAR_$_Workbench.craftingItemObject', 180),
                 0xae63fc: (17165432, 'OBJC_IVAR_$_Workbench.countCreated', 236),
                 0xae6404: (17165436, 'OBJC_IVAR_$_Workbench.countLeft', 232),
                 0xae640c: (17165440, 'OBJC_IVAR_$_Workbench.count', 228),
                 0xae6418: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0xae641c: (17165444, 'OBJC_IVAR_$_Workbench.currentFuelBlockhead', 108),
                 0xae642c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xae6430: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xae6434: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0xae643c: (17165372, 'OBJC_IVAR_$_Workbench.light', 100),
                 0xae6440: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xae644c: (17165448, 'OBJC_IVAR_$_Workbench.sourceItems', 140),
        },
        classes={
                 0xae5b0c: (15253120, 'OBJC_CLASS_$_Workbench'),
                 0xae63e0: (15249632, 'OBJC_CLASS_$_CraftableItemObject'),
                 0xae63f0: (15249628, 'OBJC_CLASS_$_PaintingCraftableItemObject'),
                 0xae63f4: (15249624, 'OBJC_CLASS_$_BlockheadCraftableItemObject'),
                 0xae6424: (15249616, 'OBJC_CLASS_$_ArtificialLight'),
                 0xae6464: (15249636, 'OBJC_CLASS_$_NSString'),
                 0xae646c: (15249640, 'OBJC_CLASS_$_NSMutableArray'),
                 0xae6480: (15249644, 'OBJC_CLASS_$_InventoryItem'),
        },
        instructions=[(11423448, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11429004, 'andeq r0, r0, r4, ror r0')],
        calls=[(11423604, 'blx r6'), (11424324, 'blx ip'), (11424340, 'blx r2'), (11424384, 'blx r3'), (11424400, 'blx r2'), (11424444, 'blx r3'), (11424460, 'blx r2'), (11424508, 'blx r3'), (11424524, 'blx r2'), (11424568, 'blx r3'), (11424584, 'blx r2'), (11424632, 'blx r3'), (11424648, 'blx r2'), (11424696, 'blx r3'), (11424712, 'blx r2'), (11424760, 'blx r3'), (11424776, 'blx r2'), (11424820, 'blx r3'), (11424836, 'blx r2'), (11424880, 'blx r3'), (11424896, 'blx r2'), (11424944, 'blx r3'), (11424960, 'blx r2'), (11425008, 'blx r3'), (11425024, 'blx r2'), (11425068, 'blx r3'), (11425084, 'blx r2'), (11425132, 'blx r3'), (11425148, 'blx r2'), (11425192, 'blx r3'), (11425208, 'blx r2'), (11425276, 'blx lr'), (11425376, 'blx lr'), (11425392, 'blx r2'), (11425512, 'blx r3'), (11425608, 'blx ip'), (11425624, 'blx r2'), (11425716, 'blx r2'), (11425736, 'blx r3'), (11425848, 'blx r2'), (11425868, 'blx r3'), (11425968, 'blx r2'), (11425988, 'blx r3'), (11426080, 'blx r3'), (11426220, 'blx r4'), (11426244, 'bl sym.imp.memcpy'), (11426276, 'blx r3'), (11426304, 'bl sym.imp.memcpy'), (11426412, 'bl loc.imp.objc_msgSend'), (11426552, 'bl loc.imp.objc_msgSend_stret'), (11426688, 'bl sym.imp.memset'), (11426844, 'blx r3'), (11426860, 'blx r2'), (11426904, 'blx r3'), (11426920, 'blx r2'), (11426964, 'blx r3'), (11426980, 'blx r2'), (11427096, 'bl loc.imp.objc_msgSend'), (11427272, 'blx r4'), (11427304, 'blx r3'), (11427328, 'blx r2'), (11427452, 'bl loc.imp.objc_msgSend'), (11427468, 'bl loc.imp.objc_msgSend'), (11427524, 'bl sym.imp.memset'), (11427572, 'blx lr'), (11427672, 'bl sym.imp.objc_enumerationMutation'), (11427780, 'bl loc.imp.objc_msgSend'), (11427800, 'bl loc.imp.objc_msgSend'), (11427872, 'blx ip'), (11427904, 'blx r3'), (11428004, 'blx ip'), (11428204, 'blx r3'), (11428312, 'blx r3'), (11428376, 'blx r3'), (11428424, 'bl loc.imp.objc_msgSend'), (11428520, 'bl loc.imp.objc_msgSend'), (11428588, 'bl loc.imp.objc_msgSend'), (11428672, 'bl loc.imp.objc_msgSend'), (11428716, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_'), (11428760, 'blx r2')],
        branches=[(11423632, 'bne', 11423648), (11423644, 'b', 11428772), (11425288, 'beq', 11425416), (11425448, 'beq', 11428208), (11425532, 'beq', 11426020), (11425640, 'bne', 11425764), (11425760, 'b', 11426016), (11425772, 'bne', 11425896), (11425892, 'b', 11426012), (11426012, 'b', 11426016), (11426016, 'b', 11426440), (11426100, 'beq', 11426436), (11426392, 'bne', 11426356), (11426436, 'b', 11426440), (11426476, 'beq', 11428136), (11426536, 'beq', 11426660), (11426556, 'b', 11426692), (11427028, 'bge', 11428132), (11427152, 'beq', 11428040), (11427336, 'bls', 11428036), (11427584, 'beq', 11428028), (11427664, 'beq', 11427676), (11427932, 'blo', 11427628), (11428024, 'bne', 11427628), (11428028, 'b', 11428032), (11428032, 'b', 11428036), (11428036, 'b', 11428040), (11428040, 'b', 11428044), (11428056, 'b', 11427016), (11428132, 'b', 11428136), (11428240, 'beq', 11428316), (11428388, 'beq', 11428720)],
        semantics=("[Workbench initWithWorld:dynamicWorld:saveDict:cache:] (imp 0x00ae4ed8, 1390w): the save-dict ctor - super2 + nil gate + the fast-enumeration decode of the save fields (the fff3bf94/bfa4/bfb4/bef4/c034 key pool, fffff15c/160/180/194 state); and the punchline: the ctor calls **`reloadDrawBlockLightGlowQuadsForTile(intpair, MacroTile*, World*)`** - the SAME light-glow reload symbol as the GlowBlock (E68): workbenches (furnace/portal variants) are light contributors whose re-creation invalidates their tile's light-glow quads.\n"),
    ),
    dict(
        name='wl_ctor_net',
        method='Workbench -[initWithWorld:dynamicWorld:cache:netData:]',
        types='@24@0:4@8@12@16@20',
        start=11429008,
        end=11430936,
        disasm='disasm_worldtileloader_wl_ctor_net.txt',
        base_add=11429024,
        base_literal=11430932,
        boundary='ARM.exidx end 0x00ae6c18 (listing bound); next ObjC IMP 0x00ae6c3c Workbench -[dealloc]',
        selectors={
                 0xae6b98: (15228820, 'initWithWorld:dynamicWorld:cache:netData:'),
                 0xae6ba4: (15228796, 'countByEnumeratingWithState:objects:count:'),
                 0xae6ba8: (15228828, 'blockheads'),
                 0xae6bb4: (15228756, 'worldTime'),
                 0xae6bbc: (15228752, 'initSubDerivedItems'),
                 0xae6bd8: (15228824, 'getBytes:length:'),
                 0xae6bdc: (15228832, 'netInteractionObjectWasLoaded:'),
                 0xae6be0: (15228836, 'length'),
                 0xae6be8: (15228848, 'retain'),
                 0xae6bf0: (15228724, 'objectForKey:'),
                 0xae6bfc: (15228844, 'gzipInflate'),
                 0xae6c04: (15228840, 'subdataWithRange:'),
                 0xae6c10: (15228680, 'macroTiles'),
        },
        imports={
                 0xae6b94: (17151900, 'objc_msgSendSuper2'),
                 0xae6ba0: (17151904, 'objc_msgSend'),
                 0xae6bec: (16366408, '__CFConstantStringClassReference'),
                 0xae6bf8: (16366392, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xae6bac: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xae6bb0: (17165388, 'OBJC_IVAR_$_Workbench.lastWorldTime', 256),
                 0xae6bb8: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xae6bc0: (17165380, 'OBJC_IVAR_$_Workbench.availableElectricity', 222),
                 0xae6bc4: (17165376, 'OBJC_IVAR_$_Workbench.fuelFraction', 212),
                 0xae6bc8: (17165368, 'OBJC_IVAR_$_Workbench.hasFuel', 220),
                 0xae6bcc: (17165348, 'OBJC_IVAR_$_Workbench.level', 176),
                 0xae6bd0: (17165396, 'OBJC_IVAR_$_Workbench.isInUseFuel', 112),
                 0xae6bd4: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xae6be4: (17156788, 'OBJC_IVAR_$_InteractionObject.ownerName', 84),
                 0xae6bf4: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
                 0xae6c08: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={
                 0xae6b9c: (15253120, 'OBJC_CLASS_$_Workbench'),
        },
        instructions=[(11429008, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11429160, 'blx r6'), (11429248, 'movw r6, 0x20'), (11430932, 'subseq sb, r7, ip, asr 12')],
        calls=[(11429160, 'blx r6'), (11429580, 'blx ip'), (11429760, 'blx r6'), (11429796, 'blx r3'), (11429856, 'blx ip'), (11429880, 'bl sym.imp.memset'), (11429928, 'blx lr'), (11430028, 'bl sym.imp.objc_enumerationMutation'), (11430108, 'blx ip'), (11430208, 'blx ip'), (11430276, 'blx r2'), (11430348, 'bl loc.imp.objc_msgSend'), (11430416, 'bl loc.imp.objc_msgSend'), (11430440, 'blx r2'), (11430444, 'bl 0xae6c18'), (11430560, 'blx r3'), (11430576, 'blx r2'), (11430620, 'blx r3'), (11430636, 'blx r2'), (11430736, 'bl loc.imp.objc_msgSend'), (11430780, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_')],
        branches=[(11429188, 'bne', 11429208), (11429200, 'b', 11430792), (11429940, 'beq', 11430232), (11430020, 'beq', 11430032), (11430136, 'blo', 11429984), (11430228, 'bne', 11429984), (11430232, 'b', 11430236), (11430284, 'bls', 11430660)],
        semantics=('[Workbench initWithWorld:dynamicWorld:cache:netData:] (imp 0x00ae6490, 482w): the net ctor - super2 (@0xae6528) + nil gate; the constants **0x10 (16) / 0x20 (32)** (@0xae6560/0xae6580) size the record reads; the ffffc8a0/fffff150/fffff158 cells + ffe2645c/60/88/a0/a8 thread the decode.\n'),
    ),
    dict(
        name='wl_remoteupdate',
        method='Workbench -[remoteUpdate:]',
        types='v12@0:4@8',
        start=11532136,
        end=11538816,
        disasm='disasm_worldtileloader_wl_remoteupdate.txt',
        base_add=11532152,
        base_literal=11535264,
        boundary='ARM.exidx end 0x00b01180 (listing bound); next ObjC IMP 0x00b01180 Workbench -[remoteBlockheadRemovedWithID:]',
        selectors={
                 0xb003a8: (15229268, 'remoteUpdate:'),
                 0xb003b8: (15228824, 'getBytes:length:'),
                 0xb003c8: (15228872, 'objectType'),
                 0xb003cc: (15228876, 'dynamicWorldChangedAtPos:objectType:'),
                 0xb003d8: (15228928, 'uniqueID'),
                 0xb003dc: (15229272, 'isServer'),
                 0xb003e0: (15228704, 'release'),
                 0xb003e4: (15229240, 'stopInteracting'),
                 0xb003e8: (15229016, 'craftAbortedForWorkbench:withBlockhead:'),
                 0xb00b48: (15228796, 'countByEnumeratingWithState:objects:count:'),
                 0xb00b4c: (15228828, 'blockheads'),
                 0xb010c8: (15228872, 'objectType'),
                 0xb010cc: (15228876, 'dynamicWorldChangedAtPos:objectType:'),
                 0xb010d4: (15229272, 'isServer'),
                 0xb010d8: (15228704, 'release'),
                 0xb010f4: (15229104, 'isNet'),
                 0xb01100: (15229088, 'updateHasFuel'),
                 0xb0110c: (15228660, 'initLevelStuff'),
                 0xb01114: (15228692, 'updateTileGraphicForWorkbenchOfType:atPos:level:'),
                 0xb01118: (15229276, 'reloadCraftUI'),
                 0xb0111c: (15228880, 'uiManager'),
                 0xb01128: (15228960, 'instance'),
                 0xb0112c: (15229064, 'multiSoundNamed:'),
                 0xb01134: (15229156, 'playAtPosition:'),
                 0xb0113c: (15228748, 'updatePortalLight'),
                 0xb01140: (15228684, 'rendersDynamicObjectCubes'),
                 0xb01148: (15228680, 'macroTiles'),
                 0xb01150: (15228848, 'retain'),
                 0xb01158: (15228724, 'objectForKey:'),
                 0xb01164: (15228844, 'gzipInflate'),
                 0xb01168: (15228836, 'length'),
                 0xb01170: (15228840, 'subdataWithRange:'),
                 0xb0117c: (15229072, 'addParticleAtPos:velocity:color:gravityType:life:scale:center:'),
        },
        imports={
                 0xb003a4: (17151900, 'objc_msgSendSuper2'),
                 0xb003b4: (17151904, 'objc_msgSend'),
                 0xb010bc: (17151904, 'objc_msgSend'),
                 0xb01130: (16367000, '__CFConstantStringClassReference'),
                 0xb01154: (16366408, '__CFConstantStringClassReference'),
                 0xb01160: (16366392, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xb003b0: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0xb003bc: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xb003c4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xb003d0: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0xb003ec: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xb003f0: (17156816, 'OBJC_IVAR_$_InteractionObject.remoteBlockheadInUseUniqueID', 72),
                 0xb00b44: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xb00db4: (17165396, 'OBJC_IVAR_$_Workbench.isInUseFuel', 112),
                 0xb00db8: (17165444, 'OBJC_IVAR_$_Workbench.currentFuelBlockhead', 108),
                 0xb00dc0: (17165456, 'OBJC_IVAR_$_Workbench.remoteFuelBlockheadInUseUniqueID', 272),
                 0xb00dc8: (17165376, 'OBJC_IVAR_$_Workbench.fuelFraction', 212),
                 0xb010b8: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0xb010c0: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xb010c4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xb010d0: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0xb010dc: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xb010e0: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xb010e4: (17165396, 'OBJC_IVAR_$_Workbench.isInUseFuel', 112),
                 0xb010e8: (17165444, 'OBJC_IVAR_$_Workbench.currentFuelBlockhead', 108),
                 0xb010ec: (17165376, 'OBJC_IVAR_$_Workbench.fuelFraction', 212),
                 0xb010f0: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xb010f8: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xb010fc: (17165468, 'OBJC_IVAR_$_Workbench.particleCreateTimerSteamEngine', 280),
                 0xb01104: (17165348, 'OBJC_IVAR_$_Workbench.level', 176),
                 0xb01108: (17165380, 'OBJC_IVAR_$_Workbench.availableElectricity', 222),
                 0xb0114c: (17156788, 'OBJC_IVAR_$_InteractionObject.ownerName', 84),
                 0xb0115c: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
        },
        classes={
                 0xb003ac: (15253120, 'OBJC_CLASS_$_Workbench'),
                 0xb01120: (15249668, 'OBJC_CLASS_$_MJSoundManager'),
                 0xb01174: (15249672, 'OBJC_CLASS_$_ParticleEmitter'),
        },
        instructions=[(11532136, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11538812, 'invalid')],
        calls=[(11532228, 'blx lr'), (11532368, 'bl loc.imp.objc_msgSend'), (11532404, 'bl loc.imp.objc_msgSend'), (11532444, 'blx ip'), (11532620, 'bl loc.imp.objc_msgSend'), (11532716, 'blx r2'), (11532872, 'blx r5'), (11532908, 'blx r3'), (11532944, 'blx r3'), (11533304, 'blx r2'), (11533328, 'bl sym.imp.memset'), (11533376, 'blx lr'), (11533476, 'bl sym.imp.objc_enumerationMutation'), (11533516, 'bl loc.imp.objc_msgSend'), (11533768, 'blx ip'), (11533984, 'bl loc.imp.objc_msgSend'), (11534080, 'blx r2'), (11534200, 'blx lr'), (11534236, 'blx r3'), (11534796, 'blx r2'), (11534996, 'blx r2'), (11535492, 'blx r2'), (11535732, 'blx lr'), (11535768, 'blx r3'), (11535920, 'bl loc.imp.objc_msgSend'), (11536056, 'bl loc.imp.objc_msgSend'), (11536080, 'bl loc.imp.objc_msgSend'), (11536152, 'bl method.Vector2.Vector2_float__float_'), (11536180, 'bl loc.imp.objc_msgSend'), (11536252, 'bl loc.imp.objc_msgSend'), (11536288, 'bl loc.imp.objc_msgSend'), (11536324, 'blx r3'), (11536340, 'blx r2'), (11536424, 'bl method.Vector.Vector_float__float__float_'), (11536456, 'bl 0xae3c5c'), (11536556, 'bl method.Vector.Vector_float__float__float__float_'), (11536592, 'bl loc.imp.objc_msgSend'), (11536600, 'bl 0xae3c5c'), (11536636, 'bl 0xae3c5c'), (11536684, 'bl method.Vector.Vector_float__float__float_'), (11536724, 'bl method.Vector.operator_Vector_'), (11536728, 'bl 0xae3c5c'), (11536772, 'bl 0xae3c5c'), (11536828, 'bl method.Vector.Vector_float__float__float_'), (11536864, 'bl 0xae3c5c'), (11536904, 'bl 0xae3c5c'), (11537200, 'bl loc.imp.objc_msgSend'), (11537404, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11537916, 'blx r2'), (11537960, 'blx r2'), (11538052, 'bl loc.imp.objc_msgSend'), (11538096, 'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_'), (11538204, 'bl loc.imp.objc_msgSend'), (11538272, 'bl loc.imp.objc_msgSend'), (11538296, 'blx r2'), (11538300, 'bl 0xae6c18'), (11538448, 'blx r3'), (11538472, 'blx r3'), (11538488, 'blx r2'), (11538544, 'blx ip'), (11538568, 'blx r3'), (11538584, 'blx r2')],
        branches=[(11532512, 'beq', 11532976), (11532524, 'beq', 11532976), (11532580, 'beq', 11532972), (11532648, 'beq', 11532972), (11532652, 'b', 11532656), (11532728, 'bne', 11532972), (11532972, 'b', 11532976), (11533008, 'beq', 11533804), (11533048, 'bne', 11533804), (11533116, 'bne', 11533188), (11533120, 'b', 11533124), (11533184, 'b', 11533800), (11533388, 'beq', 11533792), (11533468, 'beq', 11533480), (11533564, 'bne', 11533668), (11533568, 'b', 11533572), (11533668, 'b', 11533672), (11533696, 'blo', 11533432), (11533788, 'bne', 11533432), (11533792, 'b', 11533796), (11533796, 'b', 11533800), (11533800, 'b', 11533804), (11533876, 'beq', 11534292), (11533888, 'beq', 11534292), (11533944, 'beq', 11534288), (11534012, 'beq', 11534288), (11534016, 'b', 11534020), (11534092, 'bne', 11534288), (11534288, 'b', 11534292), (11534324, 'beq', 11534408), (11534364, 'bne', 11534408), (11534488, 'bgt', 11534656), (11534540, 'bmi', 11534656), (11534552, 'bne', 11534600), (11534596, 'bgt', 11534656), (11534608, 'ble', 11535564), (11534652, 'bpl', 11535564), (11534696, 'beq', 11535024), (11534732, 'beq', 11534864), (11534808, 'bne', 11534864), (11534852, 'bpl', 11534864), (11534896, 'bne', 11535020), (11534932, 'beq', 11535020), (11535008, 'bne', 11535020), (11535020, 'b', 11535024), (11535036, 'bne', 11535560), (11535072, 'bne', 11535420), (11535116, 'ble', 11535416), (11535248, 'bpl', 11535368), (11535260, 'b', 11535376), (11535416, 'b', 11535420), (11535520, 'bne', 11535556), (11535556, 'b', 11535560), (11535560, 'b', 11535564), (11535628, 'ble', 11538104), (11535780, 'beq', 11535924), (11536452, 'bge', 11537256), (11537216, 'b', 11536444), (11537288, 'beq', 11537328), (11537324, 'bne', 11537920), (11537424, 'beq', 11537876), (11537468, 'bhi', 11537868), (11537572, 'b', 11537872), (11537640, 'b', 11537872), (11537704, 'b', 11537872), (11537772, 'b', 11537872), (11537840, 'b', 11537872), (11537868, 'b', 11537872), (11537872, 'b', 11537876), (11537972, 'beq', 11538100), (11538100, 'b', 11538104), (11538140, 'bne', 11538608)],
        semantics=("[Workbench remoteUpdate:] (imp 0x00aff768, 1670w): the network update - 34 calls: objc x16 + the **local position helper 0xae3c5c x7** (the wb_getlightrgb-family helper) + Vector/Vector2 packs (float,float,float ctors + operator+) + `tileAtWorldPositionLoaded` + **`reloadDrawBlockDynamicObjectStaticGeometryForTile(intpair, MacroTile*, World*)`** (the static-geometry reload - the workbench's geometry invalidates on type/level change); the key chain rides fffff120 (9x, the type) + fffff14c (8x, the fuel fraction) + the ffffc8b4/c89c/c8a0 position cells.\n"),
    ),
    dict(
        name='wl_bhloaded',
        method='Workbench -[blockheadsLoaded]',
        types='v8@0:4',
        start=11431640,
        end=11432520,
        disasm='disasm_worldtileloader_wl_bhloaded.txt',
        base_add=11431656,
        base_literal=11432516,
        boundary='ARM.exidx end 0x00ae7248 (listing bound); next ObjC IMP 0x00ae7248 Workbench -[blockheadWouldLikeToTakeOwnership:withSaveDict:]',
        selectors={
                 0xae7208: (15228860, 'blockheadsLoaded'),
                 0xae7218: (15228828, 'blockheads'),
                 0xae7220: (15228788, 'count'),
                 0xae7228: (15228848, 'retain'),
                 0xae722c: (15228864, 'objectAtIndex:'),
                 0xae7234: (15228868, 'setInteractionObject:'),
                 0xae7240: (15228812, 'setInteractionWorkbench:'),
        },
        imports={
                 0xae7204: (17151900, 'objc_msgSendSuper2'),
                 0xae7214: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xae7210: (17165392, 'OBJC_IVAR_$_Workbench.savedBlockheadIndexFuel', 116),
                 0xae721c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xae7224: (17165444, 'OBJC_IVAR_$_Workbench.currentFuelBlockhead', 108),
                 0xae7230: (17165396, 'OBJC_IVAR_$_Workbench.isInUseFuel', 112),
                 0xae7238: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0xae723c: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
        },
        classes={
                 0xae720c: (15253120, 'OBJC_CLASS_$_Workbench'),
        },
        instructions=[(11431640, 'push {r4, r5, r6, sl, fp, lr}'), (11431756, 'cmn r0, 1'), (11431860, 'blt 0xae7098'), (11432516, 'subseq r8, r7, r4, lsl 24')],
        calls=[(11431724, 'blx ip'), (11431828, 'blx r2'), (11431932, 'blx r2'), (11432048, 'blx lr'), (11432064, 'blx r2'), (11432220, 'blx r3'), (11432332, 'blx r3'), (11432440, 'blx r3')],
        branches=[(11431760, 'beq', 11432228), (11431860, 'blt', 11432088), (11431944, 'bhs', 11432088), (11432148, 'beq', 11432224), (11432224, 'b', 11432228), (11432260, 'beq', 11432336), (11432368, 'beq', 11432444)],
        semantics=('[Workbench blockheadsLoaded] (imp 0x00ae6ed8, 220w): the super call then the **fffff15c count with the `cmn r0, 1` -1 sentinel** (@0xae6f4c) and the `cmp r0, 0; blt` guard (@0xae6fb4); the fffe264a8/26480 per-blockhead notifies run for each loaded blockhead.\n'),
    ),
    dict(
        name='wl_updatenet',
        method='Workbench -[updateNetDataForClient:]',
        types='@12@0:4@8',
        start=11441424,
        end=11442672,
        disasm='disasm_worldtileloader_wl_updatenet.txt',
        base_add=11441440,
        base_literal=11442668,
        boundary='ARM.exidx end 0x00ae99f0 (listing bound); next ObjC IMP 0x00ae9b5c Workbench -[interactionObjectType]',
        selectors={
                 0xae9984: (15228924, 'interactionObjectCreationNetData'),
                 0xae99b8: (15228928, 'uniqueID'),
                 0xae99c4: (15228936, 'dictionary'),
                 0xae99cc: (15228932, 'dataWithBytes:length:'),
                 0xae99d8: (15228896, 'setObject:forKey:'),
                 0xae99e4: (15228944, 'appendData:'),
                 0xae99e8: (15228940, 'gzipDeflate'),
        },
        imports={
                 0xae99c0: (17151904, 'objc_msgSend'),
                 0xae99d4: (16366392, '__CFConstantStringClassReference'),
                 0xae99e0: (16366408, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xae9988: (17165396, 'OBJC_IVAR_$_Workbench.isInUseFuel', 112),
                 0xae998c: (17165380, 'OBJC_IVAR_$_Workbench.availableElectricity', 222),
                 0xae9990: (17165368, 'OBJC_IVAR_$_Workbench.hasFuel', 220),
                 0xae9994: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xae999c: (17165348, 'OBJC_IVAR_$_Workbench.level', 176),
                 0xae99a0: (17165376, 'OBJC_IVAR_$_Workbench.fuelFraction', 212),
                 0xae99a8: (17165444, 'OBJC_IVAR_$_Workbench.currentFuelBlockhead', 108),
                 0xae99ac: (17165456, 'OBJC_IVAR_$_Workbench.remoteFuelBlockheadInUseUniqueID', 272),
                 0xae99bc: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
                 0xae99dc: (17156788, 'OBJC_IVAR_$_InteractionObject.ownerName', 84),
        },
        classes={
                 0xae99c8: (15249656, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0xae99d0: (15249652, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(11441424, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11441528, 'movw r2, 0x28'), (11441720, 'strb ip, [fp, -0x2d]'), (11442668, 'subseq r6, r7, ip, asr 11')],
        calls=[(11441516, 'bl loc.imp.objc_msgSend_stret'), (11441552, 'bl sym.imp.memset'), (11441928, 'bl loc.imp.objc_msgSend'), (11442164, 'blx lr'), (11442200, 'blx r3'), (11442324, 'blx ip'), (11442452, 'blx ip'), (11442460, 'bl 0xae99f0'), (11442520, 'blx lr'), (11442548, 'blx r3')],
        branches=[(11441500, 'beq', 11441524), (11441520, 'b', 11441556), (11441848, 'beq', 11442008), (11441888, 'beq', 11441944), (11441940, 'b', 11441988), (11441984, 'b', 11441988), (11442004, 'b', 11442028), (11442024, 'b', 11442028), (11442236, 'beq', 11442328), (11442364, 'beq', 11442456)],
        semantics=('[Workbench updateNetDataForClient:] (imp 0x00ae9510, 312w): the **0x28 (40)-byte record** (`movw r2, 0x28` + memset @0xae9578) is filled from the fffff160/150/144 state; the record is copied to r8+0..0x24 (@0xae95e4-0xae9600) and the byte fields derived from type/dataA (`strb ip` @0xae9620/0xae9638); the stret arm handles the nil source.\n'),
    ),
    dict(
        name='wl_dealloc',
        method='Workbench -[dealloc]',
        types='v8@0:4',
        start=11430972,
        end=11431640,
        disasm='disasm_worldtileloader_wl_dealloc.txt',
        base_add=11430988,
        base_literal=11431636,
        boundary='ARM.exidx end 0x00ae6ed8 (listing bound); next ObjC IMP 0x00ae6ed8 Workbench -[blockheadsLoaded]',
        selectors={
                 0xae6ea8: (15228852, 'stop'),
                 0xae6eb0: (15228704, 'release'),
                 0xae6ec4: (15228856, 'dealloc'),
        },
        imports={
                 0xae6ea4: (17151904, 'objc_msgSend'),
                 0xae6ec0: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0xae6ea0: (17165452, 'OBJC_IVAR_$_Workbench.sound', 288),
                 0xae6eac: (17165444, 'OBJC_IVAR_$_Workbench.currentFuelBlockhead', 108),
                 0xae6eb4: (17165428, 'OBJC_IVAR_$_Workbench.craftingItemObject', 180),
                 0xae6eb8: (17165372, 'OBJC_IVAR_$_Workbench.light', 100),
                 0xae6ebc: (17165328, 'OBJC_IVAR_$_Workbench.craftableItems', 132),
                 0xae6ecc: (17165448, 'OBJC_IVAR_$_Workbench.sourceItems', 140),
        },
        classes={
                 0xae6ec8: (15253120, 'OBJC_CLASS_$_Workbench'),
        },
        instructions=[(11430972, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11431028, 'bl sym.imp.__wrap_free'), (11431636, 'subseq r8, r7, r0, lsr 29')],
        calls=[(11431028, 'bl sym.imp.__wrap_free'), (11431156, 'blx r3'), (11431216, 'blx lr'), (11431276, 'blx lr'), (11431336, 'blx lr'), (11431456, 'bl loc.imp.objc_msgSend'), (11431572, 'blx r3')],
        branches=[(11431380, 'bge', 11431508), (11431504, 'b', 11431372)],
        semantics=('[Workbench dealloc] (imp 0x00ae6c3c, 167w): frees the owned heap buffer first - **`__wrap_free`** (@0xae6c74) on the fffff11c pointer - then the fffff198/190/180/148 + ffe264c0/2c chain and super dealloc.\n'),
    ),
    dict(
        name='wl_upgrade',
        method='Workbench -[upgradeToNextLevel]',
        types='v8@0:4',
        start=11528928,
        end=11532136,
        disasm='disasm_worldtileloader_wl_upgrade.txt',
        base_add=11528944,
        base_literal=11532132,
        boundary='ARM.exidx end 0x00aff768 (listing bound); next ObjC IMP 0x00aff768 Workbench -[remoteUpdate:]',
        selectors={
                 0xaff6e0: (15228684, 'rendersDynamicObjectCubes'),
                 0xaff6f4: (15228660, 'initLevelStuff'),
                 0xaff704: (15228692, 'updateTileGraphicForWorkbenchOfType:atPos:level:'),
                 0xaff70c: (15228960, 'instance'),
                 0xaff710: (15229064, 'multiSoundNamed:'),
                 0xaff718: (15229156, 'playAtPosition:'),
                 0xaff720: (15228872, 'objectType'),
                 0xaff724: (15228876, 'dynamicWorldChangedAtPos:objectType:'),
                 0xaff72c: (15228680, 'macroTiles'),
                 0xaff734: (15228956, 'isClientBlockheadBeingControlledByServer'),
                 0xaff740: (15229060, 'reportAchievementWithIdentifier:'),
                 0xaff754: (15228748, 'updatePortalLight'),
                 0xaff760: (15229072, 'addParticleAtPos:velocity:color:gravityType:life:scale:center:'),
        },
        imports={
                 0xaff6dc: (17151904, 'objc_msgSend'),
                 0xaff714: (16367000, '__CFConstantStringClassReference'),
                 0xaff73c: (16367080, '__CFConstantStringClassReference'),
                 0xaff744: (16367064, '__CFConstantStringClassReference'),
                 0xaff748: (16367048, '__CFConstantStringClassReference'),
                 0xaff74c: (16367032, '__CFConstantStringClassReference'),
                 0xaff750: (16367016, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xaff6e4: (17165424, 'OBJC_IVAR_$_Workbench.selectedIndex', 136),
                 0xaff6e8: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xaff6ec: (17165348, 'OBJC_IVAR_$_Workbench.level', 176),
                 0xaff6f8: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xaff6fc: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xaff700: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xaff71c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xaff738: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
        },
        classes={
                 0xaff708: (15249668, 'OBJC_CLASS_$_MJSoundManager'),
                 0xaff758: (15249672, 'OBJC_CLASS_$_ParticleEmitter'),
        },
        instructions=[(11528928, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11532132, 'ldrsheq r0, [r6], -0xfc')],
        calls=[(11529084, 'bl loc.imp.objc_msgSend'), (11529220, 'bl loc.imp.objc_msgSend'), (11529244, 'bl loc.imp.objc_msgSend'), (11529268, 'bl loc.imp.objc_msgSend'), (11529324, 'bl method.Vector2.Vector2_float__float_'), (11529352, 'bl loc.imp.objc_msgSend'), (11529424, 'bl loc.imp.objc_msgSend'), (11529460, 'bl loc.imp.objc_msgSend'), (11529528, 'blx r4'), (11529620, 'bl loc.imp.objc_msgSend'), (11529664, 'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_'), (11529756, 'bl method.Vector.Vector_float__float__float_'), (11529788, 'bl 0xae3c5c'), (11529888, 'bl method.Vector.Vector_float__float__float__float_'), (11529924, 'bl loc.imp.objc_msgSend'), (11529932, 'bl 0xae3c5c'), (11529968, 'bl 0xae3c5c'), (11530016, 'bl method.Vector.Vector_float__float__float_'), (11530056, 'bl method.Vector.operator_Vector_'), (11530060, 'bl 0xae3c5c'), (11530104, 'bl 0xae3c5c'), (11530160, 'bl method.Vector.Vector_float__float__float_'), (11530196, 'bl 0xae3c5c'), (11530236, 'bl 0xae3c5c'), (11530532, 'bl loc.imp.objc_msgSend'), (11530724, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11530948, 'blx r2'), (11531044, 'blx ip'), (11531172, 'blx r2'), (11531268, 'blx ip'), (11531392, 'blx r2'), (11531488, 'blx ip'), (11531612, 'blx r2'), (11531708, 'blx ip'), (11531832, 'blx r2'), (11531928, 'blx ip'), (11531984, 'blx r2')],
        branches=[(11529540, 'beq', 11529668), (11529784, 'bge', 11530576), (11530548, 'b', 11529776), (11530608, 'beq', 11530648), (11530644, 'bne', 11531988), (11530744, 'beq', 11531944), (11530788, 'bhi', 11531936), (11530960, 'bne', 11531048), (11531048, 'b', 11531940), (11531184, 'bne', 11531272), (11531272, 'b', 11531940), (11531404, 'bne', 11531492), (11531492, 'b', 11531940), (11531624, 'bne', 11531712), (11531712, 'b', 11531940), (11531844, 'bne', 11531932), (11531932, 'b', 11531940), (11531936, 'b', 11531940), (11531940, 'b', 11531944)],
        semantics=('[Workbench upgradeToNextLevel] (imp 0x00afeae0, 802w): the level upgrade - 25 calls including the same 0xae3c5c x7 + Vector packs + `tileAtWorldPositionLoaded` + **`reloadDrawBlockDynamicObjectStaticGeometryForTile`**; the upgrade key family **fff3c2a4/c2b4/c2c4/c2d4/c2e4** + fffff120/130 (type/level) thread the state; the ffffc8a0/c89c position walk.\n'),
    ),
    dict(
        name='wl_setneedsremoved',
        method='Workbench -[setNeedsRemoved:]',
        types='v12@0:4c8',
        start=11527364,
        end=11527740,
        disasm='disasm_worldtileloader_wl_setneedsremoved.txt',
        base_add=11527380,
        base_literal=11527736,
        boundary='ARM.exidx end 0x00afe63c (listing bound); next ObjC IMP 0x00afe63c Workbench -[fractionComplete]',
        selectors={
                 0xafe618: (15229256, 'setNeedsRemoved:'),
                 0xafe628: (15228696, 'removeFromTiles'),
                 0xafe634: (15228680, 'macroTiles'),
        },
        imports={
                 0xafe614: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0xafe610: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xafe620: (17165372, 'OBJC_IVAR_$_Workbench.light', 100),
                 0xafe62c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xafe630: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={
                 0xafe61c: (15253120, 'OBJC_CLASS_$_Workbench'),
        },
        instructions=[(11527364, 'push {r4, sl, fp, lr}'), (11527428, 'bne 0xafe50c'), (11527516, 'cmp r0, 0'), (11527736, 'subseq r1, r6, r8, lsl r6')],
        calls=[(11527508, 'blx r3'), (11527564, 'bl loc.imp.objc_msgSend'), (11527640, 'bl loc.imp.objc_msgSend'), (11527684, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_')],
        branches=[(11527428, 'bne', 11527436), (11527432, 'b', 11527688), (11527520, 'beq', 11527688)],
        semantics=('[Workbench setNeedsRemoved:] (imp 0x00afe4c4, 94w): **type == 1 exits early** (@0xafe504: the type-1 exemption again); otherwise the ffffbca8 super notify + the sxtb flag gate (@0xafe55c) + fffff148 + ffe26424/14 (the remove notify + cache eviction).\n'),
    ),
    dict(
        name='wl_setpaused',
        method='Workbench -[setPaused:]',
        types='v12@0:4c8',
        start=11542624,
        end=11542836,
        disasm='disasm_worldtileloader_wl_setpaused.txt',
        base_add=11542640,
        base_literal=11542832,
        boundary='ARM.exidx end 0x00b02134 (listing bound); next ObjC IMP 0x00b02134 Workbench -[canDismissFuelUI]',
        selectors={
                 0xb0212c: (15228852, 'stop'),
        },
        imports={
                 0xb02128: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xb02120: (17165476, 'OBJC_IVAR_$_Workbench.paused', 292),
                 0xb02124: (17165452, 'OBJC_IVAR_$_Workbench.sound', 288),
        },
        classes={},
        instructions=[(11542624, 'push {r4, sl, fp, lr}'), (11542680, 'strb r0, [r1]'), (11542780, 'blx r3'), (11542832, 'subseq sp, r5, ip, ror sl')],
        calls=[(11542780, 'blx r3')],
        branches=[(11542708, 'beq', 11542808)],
        semantics=('[Workbench setPaused:] (imp 0x00b02060, 53w): the **fffff1b0 byte store** (@0xb02098) + the sxtb gate then the ffffbca8 super notify + fffff198 + ffe264c0 chain (@0xb020fc).\n'),
    ),
    dict(
        name='wl_remotebhremoved',
        method='Workbench -[remoteBlockheadRemovedWithID:]',
        types='v16@0:4Q8',
        start=11538816,
        end=11539076,
        disasm='disasm_worldtileloader_wl_remotebhremoved.txt',
        base_add=11538832,
        base_literal=11539072,
        boundary='ARM.exidx end 0x00b01284 (listing bound); next ObjC IMP 0x00b01284 Workbench -[availableElectricity]',
        selectors={
                 0xb01268: (15229280, 'remoteBlockheadRemovedWithID:'),
        },
        imports={},
        ivars={
                 0xb01270: (17165456, 'OBJC_IVAR_$_Workbench.remoteFuelBlockheadInUseUniqueID', 272),
                 0xb01278: (17165396, 'OBJC_IVAR_$_Workbench.isInUseFuel', 112),
        },
        classes={
                 0xb0126c: (15253120, 'OBJC_CLASS_$_Workbench'),
        },
        instructions=[(11538816, 'push {r4, r5, fp, lr}'), (11538904, 'bl loc.imp.objc_msgSendSuper2'), (11539072, 'subseq lr, r5, ip, asr sb')],
        calls=[(11538904, 'bl loc.imp.objc_msgSendSuper2')],
        branches=[(11538964, 'bne', 11539040), (11538968, 'b', 11538972)],
        semantics=('[Workbench remoteBlockheadRemovedWithID:] (imp 0x00b01180, 65w): super2 (@0xb011d8) then the fffff19c state chain (the remote blockhead ID removal).\n'),
    ),
    dict(
        name='wl_setlevel',
        method='Workbench -[setLevelSilently:]',
        types='v12@0:4i8',
        start=11528552,
        end=11528928,
        disasm='disasm_worldtileloader_wl_setlevel.txt',
        base_add=11528588,
        base_literal=11528888,
        boundary='ARM.exidx end 0x00afeae0 (listing bound); next ObjC IMP 0x00afeae0 Workbench -[upgradeToNextLevel]',
        selectors={
                 0xafeabc: (15228660, 'initLevelStuff'),
                 0xafeacc: (15228692, 'updateTileGraphicForWorkbenchOfType:atPos:level:'),
                 0xafead4: (15228872, 'objectType'),
                 0xafead8: (15228876, 'dynamicWorldChangedAtPos:objectType:'),
        },
        imports={},
        ivars={
                 0xafeab4: (17165348, 'OBJC_IVAR_$_Workbench.level', 176),
                 0xafeac0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xafeac4: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xafeac8: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xafead0: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={},
        instructions=[(11528552, 'push {r4, r5, r6, r7, fp, lr}'), (11528600, 'str r2, [r0, ip]'), (11528672, 'ldr r3, [0x00afeac8]'), (11528924, 'andeq r0, r0, r0')],
        calls=[(11528628, 'bl loc.imp.objc_msgSend'), (11528764, 'bl loc.imp.objc_msgSend'), (11528836, 'bl loc.imp.objc_msgSend'), (11528872, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[Workbench setLevelSilently:] (imp 0x00afe968, 94w): stores the level via the fffff130 cell (`str r2, [r0, ip]` @0xafe998) then the ffe26400 notify + the cocos position chain (ffffc8a0/c89c walk + fffff120 type read) - the level change without UI.\n'),
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
        'batch': 'Workbench save/net/lifecycle cluster (E77): the save pair, the remote update + upgrade with the static-geometry reload, worldChanged solver, dealloc/bhloaded and the type-1 exemptions; 14 bodies',
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
                        default=NATIVE / 'workbench_lifecycle.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale workbench_lifecycle.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
