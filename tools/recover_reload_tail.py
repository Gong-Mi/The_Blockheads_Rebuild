#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld reload-tail & lifecycle smalls (E29).

The DynamicWorld reload-tail and lifecycle smalls: the three reload-contract
instantiations (item/glow/egg), the C++ member destructor inventory, the
artificial-light contribution, the save-worthiness check, the unload
notification and the free-block position reader:
1 body, 2280 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/RELOAD_TAIL.md for the prose and boundaries.
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
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl method.std::__1::__hash_table_unsigned_int__std::__1::hash_unsigned_int___std::__1::equal_to_unsigned_int___std::__1::allocator_unsigned_int___.___hash_table__': 0x009152c0,
    'bl method.std::__1::__tree_node_base_void__const_std::__1::__tree_next_std::__1.__tree_node_base_void__const__std::__1::__tree_node_base_void__const_': 0x00730c74,
    'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__': 0x005dc5d8,
    'bl method.std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.___tree__': 0x00915100,
    'bl method.std::__1::__tree_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_______std::__1::__map_value_compare_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.___tree__': 0x00915160,
    'bl method.std::__1::__vector_base_DynamicObject__std::__1::allocator_DynamicObject___.___vector_base__': 0x009154b0,
    'bl method.std::__1::list_unsigned_long_long__std::__1::allocator_unsigned_long_long___._list__': 0x00628094,
    'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____._map__': 0x009071e8,
    'bl method.std::__1::map_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________._map__': 0x009071b8,
    'bl method.std::__1::map_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.operator___unsigned_long_long_': 0x008bd2e4,
    'bl method.std::__1::unordered_set_unsigned_int__std::__1::hash_unsigned_int___std::__1::equal_to_unsigned_int___std::__1::allocator_unsigned_int___._unordered_set__': 0x00907188,
    'bl method.std::__1::unordered_set_unsigned_long_long__std::__1::hash_unsigned_long_long___std::__1::equal_to_unsigned_long_long___std::__1::allocator_unsigned_long_long___._unordered_set__': 0x008d0194,
    'bl method.std::__1::vector_DynamicObject__std::__1::allocator_DynamicObject___._vector__': 0x00907150,
    'bl method.std::__1::vector_intpair__std::__1::allocator_intpair___._vector__': 0x0052b718,
    'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_______std::__1::__map_value_compare_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.__count_unique_unsigned_long_long__unsigned_long_long_const__const': 0x0090c648,
    'bl sym.imp.__wrap_exit': 0x001c2fd8,
    'bl sym.imp.__wrap_free': 0x001c2e64,
    'bl sym.imp.__wrap_malloc': 0x001c2e58,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.objectTypeMayHaveArtificalLight_int_': 0x00903420,
    'bl sym.worldIndexAtWorldPos_intpair__World_': 0x00a15838,
}

SPECS = [
    dict(
        name='dyn_reload_glow',
        method='DynamicWorld -[reloadLightGlowQuadsForMacroTile:]',
        types='v12@0:4^{MacroTile=CCC^{PhysicalBlock}^{DrawBlock}@f}8',
        start=9440416,
        end=9441664,
        disasm='disasm_worldtileloader_reloadlightglowquadsformacrotile_.txt',
        base_add=9440432,
        base_literal=9441660,
        boundary='ARM.exidx end 0x00901180 (listing bound); next ObjC IMP 0x00901180 DynamicWorld -[blockheadWillBeUnloaded:]',
        selectors={
                 0x90116c: (15215864, 'count'),
                 0x901170: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x901174: (15217264, 'lightGlowQuadCount'),
                 0x901178: (15217268, 'addLightGlowQuadData:fromIndex:'),
        },
        imports={
                 0x901168: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9440416, 'push {r4, r5, r6, sl, fp, lr}'), (9440508, 'ldr r0, [r0, 0x1d0]'), (9440600, 'cmp r0, 0'), (9440860, 'add r2, r2, r1'), (9441092, 'movw r1, 0'), (9441136, 'sub r0, fp, 0xb0'), (9441660, 'rsbseq lr, r5, ip, lsr lr')],
        calls=[(9440512, 'bl sym.imp.__wrap_free'), (9440596, 'blx r2'), (9440688, 'bl sym.imp.memset'), (9440740, 'blx lr'), (9440840, 'bl sym.imp.objc_enumerationMutation'), (9440912, 'blx r2'), (9441024, 'blx ip'), (9441088, 'bl sym.imp.__wrap_malloc'), (9441132, 'bl sym.imp.__wrap_exit'), (9441224, 'bl sym.imp.memset'), (9441276, 'blx lr'), (9441376, 'bl sym.imp.objc_enumerationMutation'), (9441472, 'blx ip'), (9441584, 'blx ip')],
        branches=[(9440468, 'bne', 9440476), (9440472, 'b', 9441632), (9440496, 'beq', 9440544), (9440604, 'bls', 9441632), (9440752, 'beq', 9441048), (9440832, 'beq', 9440844), (9440952, 'blo', 9440796), (9441044, 'bne', 9440796), (9441048, 'b', 9441052), (9441060, 'ble', 9441628), (9441124, 'bne', 9441136), (9441288, 'beq', 9441608), (9441368, 'beq', 9441380), (9441512, 'blo', 9441332), (9441604, 'bne', 9441332), (9441608, 'b', 9441612), (9441628, 'b', 9441632)],
        semantics=('reloadLightGlowQuadsForMacroTile: / reloadDynamicObjectItemQuadsForMacroTile: / reloadDodoEggQuadsForMacroTile: are THREE byte-identical instantiations of one reload contract (each differs from the others in only four words: the pc-base cell, two pool words and the per-family selector cell). Body shape (item variant, prologue 0x009007c0; glow 0x00900ca0; egg 0x008ff3dc; frames ~0x178; base 0x105faf4): `[r0+8]` null exits; `__wrap_free([tile+0x1c4])` + clear of the +0x1c4/+0x1c8 pair (@0x900818-0x90083c); the [r3+0xc] count gate (cell 0x900c8c ffe23204, @0x900874); the entity enumeration computes counts through the per-family selector (item: ffe23774 cell 0x900c94 @0x900978; siblings substitute their own selector); `for i in 0..2` with the ffffe54c segments; then `__wrap_malloc(count * 2 * 4 * 0x60)` (@0x900a48-0x900a60) stored at [tile+0x1c4] with `__wrap_exit(0)` on NULL (@0x900a8c); the fill enumeration follows. The trio completes the E25 reload family (quads/cylinders/geometry) with the item/glow/egg instantiations.\n'),
    ),
    dict(
        name='dyn_reload_item',
        method='DynamicWorld -[reloadDynamicObjectItemQuadsForMacroTile:]',
        types='v12@0:4^{MacroTile=CCC^{PhysicalBlock}^{DrawBlock}@f}8',
        start=9439168,
        end=9440416,
        disasm='disasm_worldtileloader_reloaddynamicobjectitemquadsformacrotile_.txt',
        base_add=9439184,
        base_literal=9440412,
        boundary='ARM.exidx end 0x00900ca0 (listing bound); next ObjC IMP 0x00900ca0 DynamicWorld -[reloadLightGlowQuadsForMacroTile:]',
        selectors={
                 0x900c8c: (15215864, 'count'),
                 0x900c90: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x900c94: (15217256, 'staticGeometryDrawItemQuadCount'),
                 0x900c98: (15217260, 'addDrawItemQuadData:fromIndex:'),
        },
        imports={
                 0x900c88: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9439168, 'push {r4, r5, r6, sl, fp, lr}'), (9439256, 'ldr r0, [r0, 8]'), (9439348, 'blx r2'), (9439608, 'ldr r2, [0x00900c94]'), (9439840, 'bl sym.imp.__wrap_malloc'), (9439884, 'bl sym.imp.__wrap_exit'), (9440412, 'rsbseq pc, r5, ip, lsl r3')],
        calls=[(9439264, 'bl sym.imp.__wrap_free'), (9439348, 'blx r2'), (9439440, 'bl sym.imp.memset'), (9439492, 'blx lr'), (9439592, 'bl sym.imp.objc_enumerationMutation'), (9439664, 'blx r2'), (9439776, 'blx ip'), (9439840, 'bl sym.imp.__wrap_malloc'), (9439884, 'bl sym.imp.__wrap_exit'), (9439976, 'bl sym.imp.memset'), (9440028, 'blx lr'), (9440128, 'bl sym.imp.objc_enumerationMutation'), (9440224, 'blx ip'), (9440336, 'blx ip')],
        branches=[(9439220, 'bne', 9439228), (9439224, 'b', 9440384), (9439248, 'beq', 9439296), (9439356, 'bls', 9440384), (9439504, 'beq', 9439800), (9439584, 'beq', 9439596), (9439704, 'blo', 9439548), (9439796, 'bne', 9439548), (9439800, 'b', 9439804), (9439812, 'ble', 9440380), (9439876, 'bne', 9439888), (9440040, 'beq', 9440360), (9440120, 'beq', 9440132), (9440264, 'blo', 9440084), (9440356, 'bne', 9440084), (9440360, 'b', 9440364), (9440380, 'b', 9440384)],
        semantics=('reloadLightGlowQuadsForMacroTile: / reloadDynamicObjectItemQuadsForMacroTile: / reloadDodoEggQuadsForMacroTile: are THREE byte-identical instantiations of one reload contract (each differs from the others in only four words: the pc-base cell, two pool words and the per-family selector cell). Body shape (item variant, prologue 0x009007c0; glow 0x00900ca0; egg 0x008ff3dc; frames ~0x178; base 0x105faf4): `[r0+8]` null exits; `__wrap_free([tile+0x1c4])` + clear of the +0x1c4/+0x1c8 pair (@0x900818-0x90083c); the [r3+0xc] count gate (cell 0x900c8c ffe23204, @0x900874); the entity enumeration computes counts through the per-family selector (item: ffe23774 cell 0x900c94 @0x900978; siblings substitute their own selector); `for i in 0..2` with the ffffe54c segments; then `__wrap_malloc(count * 2 * 4 * 0x60)` (@0x900a48-0x900a60) stored at [tile+0x1c4] with `__wrap_exit(0)` on NULL (@0x900a8c); the fill enumeration follows. The trio completes the E25 reload family (quads/cylinders/geometry) with the item/glow/egg instantiations.\n'),
    ),
    dict(
        name='dyn_reload_egg',
        method='DynamicWorld -[reloadDodoEggQuadsForMacroTile:]',
        types='v12@0:4^{MacroTile=CCC^{PhysicalBlock}^{DrawBlock}@f}8',
        start=9434076,
        end=9435324,
        disasm='disasm_worldtileloader_reloaddodoeggquadsformacrotile_.txt',
        base_add=9434092,
        base_literal=9435320,
        boundary='ARM.exidx end 0x008ff8bc (listing bound); next ObjC IMP 0x008ff8bc DynamicWorld -[reloadDynamicObjectQuadsForMacroTile:]',
        selectors={
                 0x8ff8a8: (15215864, 'count'),
                 0x8ff8ac: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8ff8b0: (15217228, 'staticGeometryDodoEggCount'),
                 0x8ff8b4: (15217232, 'addDodoEggDrawQuadData:fromIndex:'),
        },
        imports={
                 0x8ff8a4: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9434076, 'push {r4, r5, r6, sl, fp, lr}'), (9434136, 'movw r0, 0'), (9434228, 'str r3, [fp, -0x20]'), (9434488, 'str r1, [sp, 0x5c]'), (9434720, 'ble 0x8ff898'), (9434764, 'str r0, [r2, 0x1b0]'), (9435320, 'rsbseq r0, r6, r0, lsl 14')],
        calls=[(9434172, 'bl sym.imp.__wrap_free'), (9434256, 'blx r2'), (9434348, 'bl sym.imp.memset'), (9434400, 'blx lr'), (9434500, 'bl sym.imp.objc_enumerationMutation'), (9434572, 'blx r2'), (9434684, 'blx ip'), (9434748, 'bl sym.imp.__wrap_malloc'), (9434792, 'bl sym.imp.__wrap_exit'), (9434884, 'bl sym.imp.memset'), (9434936, 'blx lr'), (9435036, 'bl sym.imp.objc_enumerationMutation'), (9435132, 'blx ip'), (9435244, 'blx ip')],
        branches=[(9434128, 'bne', 9434136), (9434132, 'b', 9435292), (9434156, 'beq', 9434204), (9434264, 'bls', 9435292), (9434412, 'beq', 9434708), (9434492, 'beq', 9434504), (9434612, 'blo', 9434456), (9434704, 'bne', 9434456), (9434708, 'b', 9434712), (9434720, 'ble', 9435288), (9434784, 'bne', 9434796), (9434948, 'beq', 9435268), (9435028, 'beq', 9435040), (9435172, 'blo', 9434992), (9435264, 'bne', 9434992), (9435268, 'b', 9435272), (9435288, 'b', 9435292)],
        semantics=('reloadLightGlowQuadsForMacroTile: / reloadDynamicObjectItemQuadsForMacroTile: / reloadDodoEggQuadsForMacroTile: are THREE byte-identical instantiations of one reload contract (each differs from the others in only four words: the pc-base cell, two pool words and the per-family selector cell). Body shape (item variant, prologue 0x009007c0; glow 0x00900ca0; egg 0x008ff3dc; frames ~0x178; base 0x105faf4): `[r0+8]` null exits; `__wrap_free([tile+0x1c4])` + clear of the +0x1c4/+0x1c8 pair (@0x900818-0x90083c); the [r3+0xc] count gate (cell 0x900c8c ffe23204, @0x900874); the entity enumeration computes counts through the per-family selector (item: ffe23774 cell 0x900c94 @0x900978; siblings substitute their own selector); `for i in 0..2` with the ffffe54c segments; then `__wrap_malloc(count * 2 * 4 * 0x60)` (@0x900a48-0x900a60) stored at [tile+0x1c4] with `__wrap_exit(0)` on NULL (@0x900a8c); the fill enumeration follows. The trio completes the E25 reload family (quads/cylinders/geometry) with the item/glow/egg instantiations.\n'),
    ),
    dict(
        name='dyn_cxx_destruct',
        method='DynamicWorld -[.cxx_destruct]',
        types='v8@0:4',
        start=9465036,
        end=9466392,
        disasm='disasm_worldtileloader_cxx_destruct_dynamicworld.txt',
        base_add=9465052,
        base_literal=9466188,
        boundary='ARM.exidx end 0x00907218 (listing bound); next ObjC IMP 0x00907218 DynamicWorld -[.cxx_construct]',
        selectors={},
        imports={},
        ivars={
                 0x907100: (17162348, 'OBJC_IVAR_$_DynamicWorld.dynamicWorldChangedMacroPositions', 6540),
                 0x907104: (17162340, 'OBJC_IVAR_$_DynamicWorld.worldChangedMacroPositions', 7320),
                 0x907108: (17162428, 'OBJC_IVAR_$_DynamicWorld.avoidFreeblockDupeObjectIds', 9504),
                 0x90710c: (17162336, 'OBJC_IVAR_$_DynamicWorld.lightChangedSendUnreliablyMacroPositionsSingleClient', 6120),
                 0x907110: (17162420, 'OBJC_IVAR_$_DynamicWorld.waterChangedPositions', 6504),
                 0x907114: (17162424, 'OBJC_IVAR_$_DynamicWorld.worldContentsChangedPositions', 6516),
                 0x907118: (17162448, 'OBJC_IVAR_$_DynamicWorld.worldPartialContentChangedPositions', 6528),
                 0x90711c: (17162368, 'OBJC_IVAR_$_DynamicWorld.partialUpdateOrderedObjects', 5032),
                 0x907120: (17162412, 'OBJC_IVAR_$_DynamicWorld.worldChangedPositions', 6072),
                 0x907124: (17162344, 'OBJC_IVAR_$_DynamicWorld.worldChangedSendUnreliablyMacroPositions', 6084),
                 0x907128: (17162356, 'OBJC_IVAR_$_DynamicWorld.snowChangedMacroPositions', 6096),
                 0x90712c: (17162352, 'OBJC_IVAR_$_DynamicWorld.worldChangedDontSendMacroPositions', 6108),
                 0x907130: (17162388, 'OBJC_IVAR_$_DynamicWorld.currentlyLoadingMacroBlocks', 3732),
                 0x907134: (17162360, 'OBJC_IVAR_$_DynamicWorld.currentlyAddingObjectIDs', 2432),
                 0x907138: (17162312, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsByWorldPosIndex', 1620),
                 0x90713c: (17162364, 'OBJC_IVAR_$_DynamicWorld.freeBlocksByPosition', 2400),
                 0x907140: (17162432, 'OBJC_IVAR_$_DynamicWorld.currentlyAddingGlowBlocks', 2412),
                 0x907144: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
                 0x907148: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
        },
        classes={},
        instructions=[(9465036, 'push {fp, lr}'), (9465100, 'bl method.std::__1::list_unsigned_long_long__std::__1::allocator_unsigned_long_long___._list__'), (9465160, 'add r1, r3, r1'), (9465348, 'add r3, r1, 0x180'), (9465564, 'add r1, r3, r1'), (9465684, 'bl method.std::__1::unordered_set_unsigned_int__std::__1::hash_unsigned_int___std::__1::equal_to_unsigned_int___std::__1::allocator_unsigned_int___._unordered_set__'), (9465768, 'bl method.std::__1::unordered_set_unsigned_long_long__std::__1::hash_unsigned_long_long___std::__1::equal_to_unsigned_long_long___std::__1::allocator_unsigned_long_long___._unordered_set__'), (9466388, 'pop {fp, pc}')],
        calls=[(9465100, 'bl method.std::__1::list_unsigned_long_long__std::__1::allocator_unsigned_long_long___._list__'), (9465136, 'bl method.std::__1::vector_intpair__std::__1::allocator_intpair___._vector__'), (9465196, 'bl method.std::__1::vector_intpair__std::__1::allocator_intpair___._vector__'), (9465248, 'bl method.std::__1::vector_intpair__std::__1::allocator_intpair___._vector__'), (9465284, 'bl method.std::__1::vector_intpair__std::__1::allocator_intpair___._vector__'), (9465320, 'bl method.std::__1::vector_intpair__std::__1::allocator_intpair___._vector__'), (9465380, 'bl method.std::__1::vector_intpair__std::__1::allocator_intpair___._vector__'), (9465432, 'bl method.std::__1::vector_intpair__std::__1::allocator_intpair___._vector__'), (9465468, 'bl method.std::__1::vector_intpair__std::__1::allocator_intpair___._vector__'), (9465504, 'bl method.std::__1::vector_intpair__std::__1::allocator_intpair___._vector__'), (9465540, 'bl method.std::__1::vector_intpair__std::__1::allocator_intpair___._vector__'), (9465600, 'bl method.std::__1::vector_DynamicObject__std::__1::allocator_DynamicObject___._vector__'), (9465684, 'bl method.std::__1::unordered_set_unsigned_int__std::__1::hash_unsigned_int___std::__1::equal_to_unsigned_int___std::__1::allocator_unsigned_int___._unordered_set__'), (9465768, 'bl method.std::__1::unordered_set_unsigned_long_long__std::__1::hash_unsigned_long_long___std::__1::equal_to_unsigned_long_long___std::__1::allocator_unsigned_long_long___._unordered_set__'), (9465820, 'bl method.std::__1::unordered_set_unsigned_long_long__std::__1::hash_unsigned_long_long___std::__1::equal_to_unsigned_long_long___std::__1::allocator_unsigned_long_long___._unordered_set__'), (9465856, 'bl method.std::__1::map_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________._map__'), (9465916, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____._map__'), (9465996, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____._map__'), (9466076, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____._map__'), (9466224, 'bl method.std::__1::__vector_base_DynamicObject__std::__1::allocator_DynamicObject___.___vector_base__'), (9466272, 'bl method.std::__1::__hash_table_unsigned_int__std::__1::hash_unsigned_int___std::__1::equal_to_unsigned_int___std::__1::allocator_unsigned_int___.___hash_table__'), (9466320, 'bl method.std::__1::__tree_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_______std::__1::__map_value_compare_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.___tree__'), (9466368, 'bl method.std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.___tree__')],
        branches=[(9465220, 'bne', 9465180), (9465404, 'bne', 9465364), (9465624, 'bne', 9465584), (9465708, 'bne', 9465668), (9465792, 'bne', 9465752), (9465940, 'bne', 9465900), (9466020, 'bne', 9465980), (9466100, 'bne', 9466060)],
        semantics=(".cxx_destruct is the C++ member-destructor inventory of DynamicWorld. Prologue 0x00906ccc (frame 0xc0; base 0x105faf4).\nThe chain: `std::__1::list<unsigned long long>::~list()` on the ffffe5c8 member (@0x906d0c); then `~vector<intpair>` over: ffffe570 (@0x906d30), the **ffffe578 member with its 0x30c/12-byte 65-element loop** (@0x906d48-0x906d84: `add r3, r1, 0x30c; mvn r1, 0xb` per 12-byte element), ffffe5dc (@0x906da0), ffffe5c4 (@0x906dc4), ffffe5c0 (@0x906de8), the **ffffe56c member with its 0x180/12-byte loop (the 32 light-channel structs, 32 = 0x180/12)** (@0x906e04-0x906e3c), ffffe57c (@0x906e58), ffffe580 (@0x906e7c), ffffe574 (@0x906ea0), ffffe5b8 (@0x906ec4), and the **ffffe58c member with its own 0x30c loop** (@0x906edc-0x906f18); then `~vector<DynamicObject*>` on the ffffe5a0 member's 0x514/12 loop (@0x906f54: `add r0, r1, 0x514; mvn r1, 0x13` per 12-byte element); then `~unordered_set<unsigned int>` on ffffe5a0+0x514 (@0x906f6c) and `~unordered_set<unsigned long long>` on ffffe584 (@0x906fa8); the tail continues with the remaining members and the superclass call. This body enumerates the exact container member inventory (offsets + element strides + run lengths).\n"),
    ),
    dict(
        name='wtl_addartificiallightcont',
        method='DynamicWorld -[addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:]',
        types='v16@0:4i8i12',
        start=9449492,
        end=9450528,
        disasm='disasm_worldtileloader_addartificiallightcontributionforphysica.txt',
        base_add=9449508,
        base_literal=9450524,
        boundary='ARM.exidx end 0x00903420 (listing bound); next ObjC IMP 0x009034b8 DynamicWorld -[hasLightsToAdd]',
        selectors={
                 0x903418: (15217332, 'addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:'),
        },
        imports={
                 0x903414: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x903404: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x90340c: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
        },
        classes={},
        instructions=[(9449492, 'push {r4, r5, fp, lr}'), (9449544, 'cmp r0, 0x41'), (9449556, 'bl sym.objectTypeMayHaveArtificalLight_int_'), (9449964, 'ldr ip, [sp, 0xc]'), (9450020, 'sub r0, fp, 0x80'), (9450524, 'rsbseq ip, r5, r8, asr 21')],
        calls=[(9449556, 'bl sym.objectTypeMayHaveArtificalLight_int_'), (9449968, 'blx ip'), (9450004, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9450416, 'blx ip'), (9450452, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__')],
        branches=[(9449548, 'bge', 9450492), (9449568, 'beq', 9450472), (9449864, 'beq', 9450020), (9450016, 'b', 9449780), (9450312, 'beq', 9450468), (9450464, 'b', 9450228), (9450468, 'b', 9450472), (9450472, 'b', 9450476), (9450488, 'b', 9449540)],
        semantics=('addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos: propagates the artificial-light contribution of a loaded block. Prologue 0x00903014 (frame 0x188; base 0x105faf4). Arguments: objectType (r0), x/y.\nGate: `if (objectType >= 0x41) return` (cmp 0x41 @0x903048); `objectTypeMayHaveArtificalLight(int)` (C call @0x903054) must hold (@0x903060).\nScan: the ffffe54c segment for the type is iterated (tree, `std::__1::tree_next` @0x903214): per node the position member ([node+0x10]+8) feeds the **ffe237c0 call** (cell 0x903418, @0x9031ec) with the x/y args - the light-contribution adjust; then the ffffe550 segment repeats the pass (cell 0x90340c, @0x903224+). Exit 0x9033fc.\n'),
    ),
    dict(
        name='wtl_hasdynamicobjectstosav',
        method='DynamicWorld -[hasDynamicObjectsToSaveInMacroPos:]',
        types='c16@0:4{?=ii}8',
        start=9214112,
        end=9215148,
        disasm='disasm_worldtileloader_hasdynamicobjectstosaveinmacropos_.txt',
        base_add=9214124,
        base_literal=9215144,
        boundary='ARM.exidx end 0x008c9cac (listing bound); next ObjC IMP 0x008c9cac DynamicWorld -[loadAnyBlockheadsForDisconnectedClients]',
        selectors={},
        imports={},
        ivars={
                 0x8c9c9c: (17162252, 'OBJC_IVAR_$_DynamicWorld.client', 20),
                 0x8c9ca0: (17162340, 'OBJC_IVAR_$_DynamicWorld.worldChangedMacroPositions', 7320),
                 0x8c9ca4: (17162348, 'OBJC_IVAR_$_DynamicWorld.dynamicWorldChangedMacroPositions', 6540),
        },
        classes={},
        instructions=[(9214112, 'push {r4, r5, fp, lr}'), (9214180, 'beq 0x8c98f4'), (9214212, 'cmp r0, 0x41'), (9214596, 'movw r0, 1'), (9214692, 'add r0, sp, 0xd0'), (9215144, 'rsbseq r6, sb, r0, asr 4')],
        calls=[],
        branches=[(9214180, 'beq', 9214196), (9214192, 'b', 9215120), (9214216, 'bge', 9214692), (9214528, 'beq', 9214672), (9214576, 'bne', 9214608), (9214592, 'bne', 9214608), (9214604, 'b', 9215120), (9214608, 'b', 9214612), (9214668, 'b', 9214340), (9214672, 'b', 9214676), (9214688, 'b', 9214208), (9214968, 'beq', 9215112), (9215016, 'bne', 9215048), (9215032, 'bne', 9215048), (9215044, 'b', 9215120), (9215048, 'b', 9215052), (9215108, 'b', 9214796)],
        semantics=("hasDynamicObjectsToSaveInMacroPos: answers whether a macro position holds dynamic objects worth saving. Prologue 0x008c98a0 (frame 0x150; base 0x105faf4). Argument: macro pair.\nClient gate: self.client (ffffe518, cell 0x8c9c9c) != 0 -> false (@0x8c98e4-0x8c98f0).\nScan: `for i in 0..0x41 (65)` (cmp 0x41 @0x8c9904): the **ffffe578 member's 12-byte segments** (`movw r1, 0xc; mul` @0x8c9910-0x8c993c) are inspected; per segment the inner container count/except-check sets the found flag [sp,0x6b] (@0x8c9a84); the loop continues (@0x8c9ad8). When the 65-scan finds nothing the **ffffe570 queue** (cell 0x8c9ca0) is checked (@0x8c9ae4+); the result returns at 0x8c9c90.\n"),
    ),
    dict(
        name='wtl_blockheadwillbeunloade',
        method='DynamicWorld -[blockheadWillBeUnloaded:]',
        types='v12@0:4@8',
        start=9441664,
        end=9442656,
        disasm='disasm_worldtileloader_blockheadwillbeunloaded_.txt',
        base_add=9441680,
        base_literal=9442652,
        boundary='ARM.exidx end 0x00901560 (listing bound); next ObjC IMP 0x00901560 DynamicWorld -[requestPaintingDataForPainting:]',
        selectors={
                 0x901558: (15217272, 'blockheadUnloaded:'),
        },
        imports={
                 0x901554: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x901544: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x90154c: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
        },
        classes={},
        instructions=[(9441664, 'push {r4, r5, fp, lr}'), (9441712, 'cmp r0, 0x41'), (9442108, 'blx r3'), (9442160, 'sub r0, fp, 0x80'), (9442652, 'rsbseq lr, r5, ip, asr sb')],
        calls=[(9442108, 'blx r3'), (9442144, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9442548, 'blx r3'), (9442584, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__')],
        branches=[(9441716, 'bge', 9442620), (9442012, 'beq', 9442160), (9442156, 'b', 9441928), (9442452, 'beq', 9442600), (9442596, 'b', 9442368), (9442600, 'b', 9442604), (9442616, 'b', 9441708)],
        semantics=('blockheadWillBeUnloaded: notifies the object register that a blockhead is being unloaded. Prologue 0x00901180 (frame 0x180; base 0x105faf4). Argument: the blockhead.\nScan: `for i in 0..0x41 (65)` (cmp 0x41 @0x9011b0): the ffffe54c segments (cell 0x901544, 12-byte stride) are tree-iterated (@0x901288-0x90136c): per node the **ffe23784 call** (cell 0x901558, @0x90133c) runs with the pos member ([node+0x10]+8) and the blockhead argument; then the ffffe550 segments repeat (cell 0x90154c, @0x901370+). Exit 0x90153c.\n'),
    ),
    dict(
        name='wtl_freeblocksatpos_',
        method='DynamicWorld -[freeBlocksAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9377468,
        end=9378424,
        disasm='disasm_worldtileloader_freeblocksatpos_.txt',
        base_add=9377484,
        base_literal=9378420,
        boundary='ARM.exidx end 0x008f1a78 (listing bound); next ObjC IMP 0x008f1a78 DynamicWorld -[getNextDynamicObjectID]',
        selectors={
                 0x8f1a60: (15216144, 'array'),
                 0x8f1a68: (15215864, 'count'),
                 0x8f1a6c: (15216544, 'needsRemoved'),
                 0x8f1a70: (15216008, 'addObject:'),
        },
        imports={
                 0x8f1a64: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8f1a48: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8f1a50: (17162364, 'OBJC_IVAR_$_DynamicWorld.freeBlocksByPosition', 2400),
        },
        classes={
                 0x8f1a58: (15247780, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(9377468, 'push {r4, r5, fp, lr}'), (9377592, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9377656, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_______std::__1::__map_value_compare_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9377716, 'bl method.std::__1::map_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.operator___unsigned_long_long_'), (9378176, 'blx r2'), (9378204, 'ldr r2, [0x008f1a70]'), (9378420, 'rsbseq lr, r6, r0, lsr 8')],
        calls=[(9377592, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9377656, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_______std::__1::__map_value_compare_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9377716, 'bl method.std::__1::map_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.operator___unsigned_long_long_'), (9377812, 'bl loc.imp.objc_msgSend'), (9377864, 'bl method.std::__1::map_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.operator___unsigned_long_long_'), (9378176, 'blx r2'), (9378240, 'blx r3'), (9378272, 'bl method.std::__1::__tree_node_base_void__const_std::__1::__tree_next_std::__1.__tree_node_base_void__const__std::__1::__tree_node_base_void__const_'), (9378328, 'blx r2')],
        branches=[(9377664, 'bls', 9378356), (9377764, 'beq', 9378356), (9378108, 'beq', 9378288), (9378188, 'bne', 9378244), (9378244, 'b', 9378248), (9378284, 'b', 9378040), (9378336, 'bls', 9378352), (9378348, 'b', 9378364), (9378352, 'b', 9378356)],
        semantics=("freeBlocksAtPos: collects the free blocks registered at a world position. Prologue 0x008f16bc (frame 0x120; base 0x105faf4). Argument: pos pair.\nRegistry read: `worldIndexAtWorldPos(intpair, World*)` (@0x8f1738, world via ffffe4e4) -> the **ffffe588 map** (cell 0x8f1a50) `__count_unique(u64)` (@0x8f1778): empty exits (@0x8f1780); otherwise `map<u64, set<DynamicObject*>>::operator[](u64&&)` (@0x8f17b4) yields the set at [r0+8] (@0x8f17c8-0x8f17e0).\nCollect: the set is iterated (@0x8f18f8-0x8f193c): per element the **ffe234ac gate** (cell 0x8f1a6c, @0x8f1980) and `addObject:` (cell 0x8f1a70 ffe23294, @0x8f199c) collect the free blocks into the result collection. Exit 0x8f1a34.\nBoundary: this is the READER of the registration family written by E24's master FreeBlock factory (ffffe588 + worldIndexAtWorldPos).\n"),
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
        'batch': 'DynamicWorld reload-tail & lifecycle smalls (E29): reloadLightGlowQuadsForMacroTile:, reloadDynamicObjectItemQuadsForMacroTile:, reloadDodoEggQuadsForMacroTile:, .cxx_destruct, addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:, hasDynamicObjectsToSaveInMacroPos:, blockheadWillBeUnloaded: and freeBlocksAtPos:; 8 bodies',
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
                        default=NATIVE / 'reload_tail.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale reload_tail.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
