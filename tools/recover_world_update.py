#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld world-change propagation cluster (E23).

The DynamicWorld change-propagation and simulation cluster: the macro-position
light-change producer, the water-change producer with its water re-render hook,
the tree and plant sowing scans with their switch jump tables, the tree-life
fraction field, the ownership-pole restorer and the elevator-motor lookup:
1 body, 6053 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/WORLD_UPDATE.md for the prose and boundaries.
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
    'bl 0x8ad2a4': 0x008ad2a4,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector_float__float__float__float_': 0x004d0d08,
    'bl method.Vector.operator_float__': 0x004b5c08,
    'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__': 0x005dc5d8,
    'bl method.void_std::__1::vector_intpair__std::__1::allocator_intpair___.__push_back_slow_path_intpair_const__intpair_const_': 0x0052d84c,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__aeabi_memmove': 0x001c3f08,
    'bl sym.imp.__stack_chk_fail': 0x001c28b8,
    'bl sym.imp.__umodsi3': 0x001c2f9c,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.reloadDrawBlockWaterForTile_int__int__MacroTile__World_': 0x00a193a4,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileAtWorldPosition_int__int__MacroTile__World_': 0x00a16e68,
    'bl sym.tileIsAirOrSnow_Tile_': 0x00a12760,
    'bl sym.tileIsAirWaterOrSnow_Tile_': 0x00a126dc,
    'bl sym.tileIsTree_Tile_': 0x00a13214,
}

SPECS = [
    dict(
        name='wtl_lightchangedatmacropos',
        method='DynamicWorld -[lightChangedAtMacroPos:sendReliably:sendAtAll:]',
        types='v24@0:4{?=ii}8c16c20',
        start=9314072,
        end=9317292,
        disasm='disasm_worldtileloader_lightchangedatmacropos_sendreliably_send.txt',
        base_add=9314088,
        base_literal=9317288,
        boundary='ARM.exidx end 0x008e2bac (listing bound); next ObjC IMP 0x008e2bac DynamicWorld -[activeBlockhead]',
        selectors={},
        imports={},
        ivars={
                 0x8e2b98: (17162340, 'OBJC_IVAR_$_DynamicWorld.worldChangedMacroPositions', 7320),
                 0x8e2b9c: (17162344, 'OBJC_IVAR_$_DynamicWorld.worldChangedSendUnreliablyMacroPositions', 6084),
                 0x8e2ba0: (17162352, 'OBJC_IVAR_$_DynamicWorld.worldChangedDontSendMacroPositions', 6108),
        },
        classes={},
        instructions=[(9314072, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9314236, 'add r0, sp, 0xd0'), (9314552, 'ldrsb r0, [sp, 0xe5]'), (9314576, 'add r0, sp, 0xf0'), (9315480, 'bl sym.imp.__aeabi_memmove'), (9315740, 'sub r0, fp, 0x1f8'), (9316088, 'strb r0, [sp, 0xe5]'), (9316172, 'ldrsb r0, [sp, 0xe6]'), (9316500, 'add r0, sp, 0x1e8'), (9317288, 'rsbseq sp, r7, r4, asr 23')],
        calls=[(9314884, 'bl method.void_std::__1::vector_intpair__std::__1::allocator_intpair___.__push_back_slow_path_intpair_const__intpair_const_'), (9315480, 'bl sym.imp.__aeabi_memmove'), (9316492, 'bl method.void_std::__1::vector_intpair__std::__1::allocator_intpair___.__push_back_slow_path_intpair_const__intpair_const_'), (9317240, 'bl method.void_std::__1::vector_intpair__std::__1::allocator_intpair___.__push_back_slow_path_intpair_const__intpair_const_')],
        branches=[(9314408, 'beq', 9314552), (9314456, 'bne', 9314488), (9314472, 'bne', 9314488), (9314484, 'b', 9314552), (9314488, 'b', 9314492), (9314548, 'b', 9314236), (9314560, 'bne', 9317264), (9314572, 'beq', 9315740), (9314664, 'beq', 9314876), (9314812, 'beq', 9314856), (9314872, 'b', 9314888), (9315164, 'beq', 9315736), (9315212, 'bne', 9315672), (9315228, 'bne', 9315672), (9315564, 'beq', 9315660), (9315656, 'b', 9315548), (9315668, 'b', 9315736), (9315672, 'b', 9315676), (9315732, 'b', 9314992), (9315736, 'b', 9317260), (9316016, 'beq', 9316160), (9316064, 'bne', 9316096), (9316080, 'bne', 9316096), (9316092, 'b', 9316160), (9316096, 'b', 9316100), (9316156, 'b', 9315844), (9316168, 'bne', 9317256), (9316180, 'beq', 9316500), (9316272, 'beq', 9316484), (9316420, 'beq', 9316464), (9316480, 'b', 9316496), (9316496, 'b', 9317252), (9316776, 'beq', 9316920), (9316824, 'bne', 9316856), (9316840, 'bne', 9316856), (9316852, 'b', 9316920), (9316856, 'b', 9316860), (9316916, 'b', 9316604), (9316928, 'bne', 9317248), (9317020, 'beq', 9317232), (9317168, 'beq', 9317212), (9317228, 'b', 9317244), (9317244, 'b', 9317248), (9317248, 'b', 9317252), (9317252, 'b', 9317256), (9317256, 'b', 9317260), (9317260, 'b', 9317264)],
        semantics=("lightChangedAtMacroPos:sendReliably:sendAtAll: marks an already-macro position for the dirty queues. Prologue 0x008e1f18 (frame 0x4c0; base 0x105faf4). Arguments: macro pair [-0x268 region via r2], sendReliably byte [sp,0xe7], sendAtAll byte [sp,0xe6], found flag [sp,0xe5]=0.\nReliable-queue dedup: a local vector state at [sp,0xe0] iterates the vector inside ivar ffffe570 (cell 0x8e2b98, @0x8e1fbc-0x8e20ec) comparing the pair; a present pair sets [sp,0xe5]=1 and exits (0x8e20f8-0x8e2100 -> 0x8e2b90).\nRouting: when not present and sendReliably ([sp,0xe7]) is set the pair is deduped again (state at [sp,0xf0]) and pushed into ffffe570 (0x8e2110-0x8e2244, slow path 0x8e2244); the code then processes the ffffe574 vector (cell 0x8e2b9c): a matching entry there is removed via the libc++ erase path (__aeabi_memmove @0x8e2498 + the mvn -8 fixups), i.e. entries moved to the reliable queue leave the unreliable one.\nNon-reliable path / sendAtAll: 0x8e259c processes ffffe574's vector with its own dedup (flag [sp,0xe5] re-set at 0x8e26f8) and push (slow path 0x8e288c); 0x8e2894 continues over the ffffe57c vector (cell 0x8e2ba0) with dedup (0x8e29ec) and push (slow paths 0x8e2b78); the sendAtAll byte [sp,0xe6] gates the final block (0x8e274c-0x8e2890) which dedups+pushed into ffffe574 (0x8e2858-0x8e288c). Exit 0x8e2b90.\nBoundary: the exact micro-order of the three queues (570/574/57c) around the sendReliably and sendAtAll gates is recorded as observed; the queue family is shared with worldChangedAtPos (E22) and consumed by the E21 flush.\n"),
    ),
    dict(
        name='wtl_waterchangedatpos_full',
        method='DynamicWorld -[waterChangedAtPos:fullBlock:]',
        types='v20@0:4{?=ii}8c16',
        start=9308880,
        end=9311120,
        disasm='disasm_worldtileloader_waterchangedatpos_fullblock_.txt',
        base_add=9308896,
        base_literal=9311116,
        boundary='ARM.exidx end 0x008e1390 (listing bound); next ObjC IMP 0x008e1390 DynamicWorld -[dynamicWorldChangedAtPos:objectType:]',
        selectors={
                 0x8e1384: (15216036, 'macroTiles'),
        },
        imports={
                 0x8e1380: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8e1374: (17162420, 'OBJC_IVAR_$_DynamicWorld.waterChangedPositions', 6504),
                 0x8e1378: (17162340, 'OBJC_IVAR_$_DynamicWorld.worldChangedMacroPositions', 7320),
                 0x8e137c: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8e1388: (17162344, 'OBJC_IVAR_$_DynamicWorld.worldChangedSendUnreliablyMacroPositions', 6084),
        },
        classes={},
        instructions=[(9308880, 'push {r4, sl, fp, lr}'), (9308924, 'ldrsb r0, [sp, 0xb7]'), (9309052, 'add r0, sp, 0xa0'), (9309700, 'ldr r0, [0x008e137c]'), (9309820, 'bl sym.reloadDrawBlockWaterForTile_int__int__MacroTile__World_'), (9309844, 'bl sym.imp.__aeabi_idiv'), (9309888, 'bl sym.makeIntpair_int__int_'), (9310004, 'add r0, sp, 0x70'), (9310332, 'sub r0, fp, 0x140'), (9311116, 'rsbseq pc, r7, ip')],
        calls=[(9309688, 'bl method.void_std::__1::vector_intpair__std::__1::allocator_intpair___.__push_back_slow_path_intpair_const__intpair_const_'), (9309776, 'blx r2'), (9309820, 'bl sym.reloadDrawBlockWaterForTile_int__int__MacroTile__World_'), (9309844, 'bl sym.imp.__aeabi_idiv'), (9309864, 'bl sym.imp.__aeabi_idiv'), (9309888, 'bl sym.makeIntpair_int__int_'), (9311072, 'bl method.void_std::__1::vector_intpair__std::__1::allocator_intpair___.__push_back_slow_path_intpair_const__intpair_const_')],
        branches=[(9308936, 'beq', 9309700), (9309224, 'beq', 9309368), (9309272, 'bne', 9309304), (9309288, 'bne', 9309304), (9309300, 'b', 9309368), (9309304, 'b', 9309308), (9309364, 'b', 9309052), (9309376, 'bne', 9309696), (9309468, 'beq', 9309680), (9309616, 'beq', 9309660), (9309676, 'b', 9309692), (9309692, 'b', 9309696), (9309696, 'b', 9309700), (9310176, 'beq', 9310320), (9310224, 'bne', 9310256), (9310240, 'bne', 9310256), (9310252, 'b', 9310320), (9310256, 'b', 9310260), (9310316, 'b', 9310004), (9310328, 'bne', 9311084), (9310608, 'beq', 9310752), (9310656, 'bne', 9310688), (9310672, 'bne', 9310688), (9310684, 'b', 9310752), (9310688, 'b', 9310692), (9310748, 'b', 9310436), (9310760, 'bne', 9311080), (9310852, 'beq', 9311064), (9311000, 'beq', 9311044), (9311060, 'b', 9311076), (9311076, 'b', 9311080), (9311080, 'b', 9311084)],
        semantics=('waterChangedAtPos:fullBlock: records a water change and its macro tile. Prologue 0x008e0ad0 (frame 0x2f0; base 0x105faf4). Argument: fullBlock byte [sp,0xb7].\nGate: fullBlock == 0 jumps directly to the macro section 0x8e0e04 (skipping the water bookkeeping); fullBlock != 0 runs the ffffe5c0 water-position vector (cell 0x8e1374) dedup ([sp,0xb6] found flag, loop 0x8e0b7c-0x8e0cb4) and push (slow path @0x8e0df8).\nMacro section 0x8e0e04: `reloadDrawBlockWaterForTile(int, int, MacroTile*, World*)` (C call @0x8e0e7c, world via ffffe4e4, macroTiles sel ffe232b0) re-renders the water tile; then the position is divided by 32 (`movw r0, 0x20` + `__aeabi_idiv` @0x8e0e94) and packed with `makeIntpair` (@0x8e0ec0).\nQueue push: the macro pair is deduped (state at [sp,0x80], flag [sp,0x87]) and pushed into the ffffe570 vector (cell 0x8e1378, @0x8e0ec4-0x8e0e80 churn > push 0x8e0f34-0x8e0f60); then the ffffe574 vector (cell 0x8e1388, @0x8e107c+) runs its own dedup ([sp,0x87] re-set @0x8e1028) and push (slow path 0x8e12xx); exit path 0x8e1368/0x8e138c region.\n'),
    ),
    dict(
        name='wtl_sowtreenearparent_adul',
        method='DynamicWorld -[sowTreeNearParent:adult:adultMaxAge:]',
        types='v20@0:4@8c12f16',
        start=9317832,
        end=9320384,
        disasm='disasm_worldtileloader_sowtreenearparent_adult_adultmaxage_.txt',
        base_add=9317848,
        base_literal=9320380,
        boundary='ARM.exidx end 0x008e37c0 (listing bound); next ObjC IMP 0x008e37c0 DynamicWorld -[findBreedingPlantNearPlant:]',
        selectors={
                 0x8e3784: (15216012, 'pos'),
                 0x8e3790: (15216760, 'isRequiredSoilType:'),
                 0x8e3794: (15216764, 'maxHeightGeneVariation'),
                 0x8e379c: (15216768, 'growthRateGeneVariation'),
                 0x8e37a0: (15216772, 'treeType'),
                 0x8e37a4: (15216392, 'loadTreeAtPosition:type:maxHeight:growthRate:adultTree:adultMaxAge:'),
        },
        imports={
                 0x8e378c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8e3788: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8e37b0: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8e37b8: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
        },
        classes={},
        instructions=[(9317832, 'push {r4, r5, r6, sl, fp, lr}'), (9317984, 'cmp r0, 2'), (9318132, 'cmp r0, 0xb'), (9318164, 'ldr r1, [r2, r1, lsl 2]'), (9318772, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9319552, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9319684, 'cmp r0, 0x10'), (9319932, 'cmp r0, 8'), (9320048, 'ldrb r0, [r0, 3]'), (9320180, 'bl sym.makeIntpair_int__int_'), (9320380, 'rsbseq ip, r7, r4, lsl sp')],
        calls=[(9317928, 'bl loc.imp.objc_msgSend_stret'), (9317964, 'bl sym.imp.memset'), (9318008, 'bl 0x8ad2a4'), (9318552, 'bl loc.imp.objc_msgSend_stret'), (9318588, 'bl sym.imp.memset'), (9318664, 'bl loc.imp.objc_msgSend_stret'), (9318700, 'bl sym.imp.memset'), (9318772, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9319220, 'bl loc.imp.objc_msgSend_stret'), (9319256, 'bl sym.imp.memset'), (9319332, 'bl loc.imp.objc_msgSend_stret'), (9319368, 'bl sym.imp.memset'), (9319440, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9319552, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9319580, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (9319660, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9319776, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9319804, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (9319908, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9320028, 'blx r3'), (9320064, 'bl sym.tileIsAirOrSnow_Tile_'), (9320120, 'bl loc.imp.objc_msgSend'), (9320144, 'bl loc.imp.objc_msgSend'), (9320180, 'bl sym.makeIntpair_int__int_'), (9320200, 'bl loc.imp.objc_msgSend'), (9320292, 'bl loc.imp.objc_msgSend')],
        branches=[(9317912, 'beq', 9317936), (9317932, 'b', 9317968), (9317988, 'bge', 9320316), (9318080, 'blt', 9318100), (9318096, 'b', 9318112), (9318136, 'bge', 9319480), (9318444, 'beq', 9318796), (9318536, 'beq', 9318560), (9318556, 'b', 9318592), (9318608, 'ble', 9318736), (9318648, 'beq', 9318672), (9318668, 'b', 9318704), (9318720, 'bge', 9318736), (9318732, 'b', 9318796), (9318736, 'b', 9318740), (9318784, 'b', 9318360), (9318804, 'bne', 9319460), (9319112, 'beq', 9319456), (9319204, 'beq', 9319228), (9319224, 'b', 9319260), (9319276, 'ble', 9319404), (9319316, 'beq', 9319340), (9319336, 'b', 9319372), (9319388, 'bge', 9319404), (9319400, 'b', 9319456), (9319404, 'b', 9319408), (9319452, 'b', 9319028), (9319456, 'b', 9319460), (9319460, 'b', 9319464), (9319476, 'b', 9318128), (9319488, 'beq', 9319496), (9319492, 'b', 9320300), (9319592, 'beq', 9319708), (9319688, 'blt', 9319704), (9319700, 'b', 9319708), (9319704, 'b', 9319576), (9319716, 'beq', 9319724), (9319720, 'b', 9320300), (9319792, 'bne', 9319960), (9319796, 'b', 9319800), (9319832, 'beq', 9319956), (9319936, 'blt', 9319952), (9319948, 'b', 9319956), (9319952, 'b', 9319800), (9319956, 'b', 9319960), (9319968, 'beq', 9319976), (9319972, 'b', 9320300), (9320040, 'beq', 9320296), (9320056, 'bne', 9320296), (9320076, 'beq', 9320296), (9320092, 'bne', 9320296), (9320296, 'b', 9320300), (9320312, 'b', 9317980)],
        semantics=("sowTreeNearParent:adult:adultMaxAge: plants a tree of a given type near the parent position. Prologue 0x008e2dc8 (frame 0x258; base 0x105faf4). Arguments: tree type [sp,0x11b] (r3), adult float [sp,0x114] (vldr [fp,8]), plus the receiver's pos (stret getter ffe23298 @0x8e2e1c), adultMaxAge on the stack.\nLoop: `for i in 0..2` (cmp at 0x8e2e60): an offset for i is produced with the shared helper `bl 0x8ad2a4` (random @0x8ad2a4) through float math (cells 0x8e3184/0x8e3188 divisors) and converted to int with a +/-2 correction (0x8e2ec0-0x8e2ee0).\nType dispatch: `for j in 0..0xb (11)` (cmp 0xb @0x8e2ef4) with a SWITCH jump table: base via the dual cell pair 0x8e37a8 (0xffdeaf70) + 0x8e37ac (0x77cbe0) -> table @ 0x00E49A64, dispatch `ldr r1, [r2, r1, lsl 2]` (@0x8e2f14) - the eleven tree-block types.\nOccupancy pass 1 (map ffffe54c, cell 0x8e37b0): iterate the tree map slice keyed by the table's 12-byte segment (mul/add r1,r1,lsl1 / lsl 2 = 12-byte stride), compare positions (std::__tree_next @0x8e3174 / 0x8e3410): a match within the +/-2 neighbourhood (the sub/add 2 compares at 0x8e30c8-0x8e3148 and the second pair 0x8e3364-0x8e33e4) sets the found flag [sp,0xff].\nTile checks (0x8e3448+): `tileAtWorldPositionLoaded(int, int, World*)` (@0x8e3480/0x8e3560) + `tileIsAirWaterOrSnow(Tile*)` (@0x8e349c/0x8e357c); the tile below (y-1 / y+1 probes) is read and its height compared against 16 then 8 (`cmp r0, 0x10` @0x8e3504, `cmp r0, 8` @0x8e35fc).\nPlacement (0x8e3628+): `[? ffe23584 (cell 0x8e3790)]` gate + `tileIsAirOrSnow` + byte[+1]==2 gate (@0x8e3670-0x8e369c) then the planting calls: cells ffe23588 (0x8e3794), ffe2358c (0x8e379c), ffe23590 (0x8e37a0) + `makeIntpair` (@0x8e36f4) + the final load call at cell 0x8e37a4 ffe23414 with the packed args ([sp]=obj, +4=x, +8=y, +0xc=type (sxtb), +0x10=adult float). Epilogue 0x8e377c.\n"),
    ),
    dict(
        name='wtl_sowplantnearparent_',
        method='DynamicWorld -[sowPlantNearParent:]',
        types='v12@0:4@8',
        start=9322204,
        end=9325000,
        disasm='disasm_worldtileloader_sowplantnearparent_.txt',
        base_add=9322220,
        base_literal=9324996,
        boundary='ARM.exidx end 0x008e49c8 (listing bound); next ObjC IMP 0x008e49c8 DynamicWorld -[sowTreeOrPlantAtPosition:itemType:maxHeight:growthRate:]',
        selectors={
                 0x8e4988: (15216780, 'isClient'),
                 0x8e498c: (15216012, 'pos'),
                 0x8e49a8: (15216784, 'plantType'),
                 0x8e49ac: (15216760, 'isRequiredSoilType:'),
                 0x8e49b0: (15216788, 'maxAgeGeneVariation'),
                 0x8e49b8: (15216768, 'growthRateGeneVariation'),
                 0x8e49bc: (15216364, 'loadPlantAtPosition:type:maxAgeGene:growthRateGene:adult:'),
        },
        imports={
                 0x8e4984: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8e4998: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8e49a0: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
                 0x8e49a4: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
        },
        classes={},
        instructions=[(9322204, 'push {r4, r5, r6, sl, fp, lr}'), (9322392, 'cmp r0, 2'), (9322540, 'cmp r0, 0xa'), (9322572, 'ldr r1, [r2, r1, lsl 2]'), (9323064, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9323616, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9323768, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (9323872, 'cmp r0, 0x10'), (9324172, 'cmp r0, 8'), (9324432, 'bl sym.makeIntpair_int__int_'), (9324996, 'rsbseq fp, r7, r0, lsl 24')],
        calls=[(9322264, 'blx ip'), (9322336, 'bl loc.imp.objc_msgSend_stret'), (9322372, 'bl sym.imp.memset'), (9322400, 'bl 0x8ad2a4'), (9322960, 'bl loc.imp.objc_msgSend_stret'), (9322996, 'bl sym.imp.memset'), (9323064, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9323512, 'bl loc.imp.objc_msgSend_stret'), (9323548, 'bl sym.imp.memset'), (9323616, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9323740, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9323768, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (9323848, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9323964, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9324024, 'blx r2'), (9324044, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (9324148, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9324256, 'blx r2'), (9324320, 'blx r3'), (9324376, 'bl loc.imp.objc_msgSend'), (9324400, 'bl loc.imp.objc_msgSend'), (9324432, 'bl sym.makeIntpair_int__int_'), (9324452, 'bl loc.imp.objc_msgSend'), (9324532, 'bl loc.imp.objc_msgSend'), (9324592, 'blx r3'), (9324664, 'blx r2'), (9324736, 'bl loc.imp.objc_msgSend'), (9324760, 'bl loc.imp.objc_msgSend'), (9324796, 'bl sym.makeIntpair_int__int_'), (9324816, 'bl loc.imp.objc_msgSend'), (9324896, 'bl loc.imp.objc_msgSend')],
        branches=[(9322276, 'beq', 9322284), (9322280, 'b', 9324924), (9322320, 'beq', 9322344), (9322340, 'b', 9322376), (9322396, 'bge', 9324924), (9322488, 'blt', 9322508), (9322504, 'b', 9322520), (9322544, 'bge', 9323668), (9322852, 'beq', 9323080), (9322944, 'beq', 9322968), (9322964, 'b', 9323000), (9323012, 'bne', 9323028), (9323024, 'b', 9323080), (9323028, 'b', 9323032), (9323076, 'b', 9322768), (9323088, 'beq', 9323100), (9323092, 'b', 9323668), (9323404, 'beq', 9323632), (9323496, 'beq', 9323520), (9323516, 'b', 9323552), (9323564, 'bne', 9323580), (9323576, 'b', 9323632), (9323580, 'b', 9323584), (9323628, 'b', 9323320), (9323640, 'beq', 9323648), (9323644, 'b', 9323668), (9323648, 'b', 9323652), (9323664, 'b', 9322536), (9323676, 'beq', 9323684), (9323680, 'b', 9324908), (9323780, 'beq', 9323896), (9323876, 'blt', 9323892), (9323888, 'b', 9323896), (9323892, 'b', 9323764), (9323904, 'beq', 9323912), (9323908, 'b', 9324908), (9323980, 'bne', 9324200), (9324032, 'beq', 9324200), (9324036, 'b', 9324040), (9324072, 'beq', 9324196), (9324176, 'blt', 9324192), (9324188, 'b', 9324196), (9324192, 'b', 9324040), (9324196, 'b', 9324200), (9324208, 'beq', 9324216), (9324212, 'b', 9324908), (9324264, 'bne', 9324540), (9324332, 'beq', 9324536), (9324348, 'bne', 9324536), (9324536, 'b', 9324904), (9324604, 'beq', 9324900), (9324620, 'bne', 9324900), (9324672, 'bne', 9324696), (9324688, 'beq', 9324712), (9324692, 'b', 9324900), (9324708, 'bne', 9324900), (9324900, 'b', 9324904), (9324904, 'b', 9324908), (9324920, 'b', 9322388)],
        semantics=("sowPlantNearParent: plants a plant near the parent position. Prologue 0x008e3edc (frame 0x250; base 0x105faf4). Gate: `[? ffe23598 (cell 0x8e4988)]` must be zero (sxtb != 0 -> exit 0x8e497c).\nLoop: `for i in 0..2` (cmp @0x8e3f98) with the same `bl 0x8ad2a4` random helper and float math (cells 0x8e4258 divisors), +/-2 correction.\nType dispatch: `for j in 0..0xa (10)` (cmp 0xa @0x8e402c) with the SWITCH jump table set via 0x8e4990 (0xffdeaf48) + 0x8e4994 (0x77baa8) -> table @ 0x00E4AA3C (dispatch @0x8e404c) - the ten plant types (parity with E20's 10-class plant table).\nOccupancy pass 1 (map ffffe54c, cell 0x8e4998): iterate + exact-position compare (`cmp` then found flag [sp,0xfb] @0x8e4200-0x8e4210; std::__tree_next @0x8e4238); pass 2 over ffffe550 (cell 0x8e49a0) with the same iterate (@0x8e4460) and exact-compare (found flag @0x8e4430).\nTile checks (0x8e44a4+): `tileAtWorldPositionLoaded` + `tileIsAirWaterOrSnow` (@0x8e44f8/0x8e460c) + the below-tile height compare against 16 (@0x8e4560) then 8 (@0x8e468c).\nKelp special (0x8e45d0-0x8e46e8): `[? ffe2359c (cell 0x8e49a8)]` value == 7 gate then again at 0x8e46e0 (`cmp r0, 7`) opening the water-plant path (type-7 = kelp family); byte[+0xb] gate @0x8e4734-0x8e4740.\nPlacement: cells ffe235a0 (0x8e49b0), ffe2358c (0x8e49b8), ffe2359c + makeIntpair (@0x8e4790/0x8e48fc) + the final load call at cell 0x8e49bc ffe233f8 with packed args ([sp]=obj, +4=x, +8=y, +0xc=0, note the plant call packs a zero where the tree call packs the adult float); type 6/7 byte-values 3/2 gates at 0x8e487c-0x8e48a4 (kelp special under 0x8e4680-0x8e4960). Epilogue 0x8e4968.\n"),
    ),
    dict(
        name='wtl_gettreelifefractionfor',
        method='DynamicWorld -[getTreeLifeFractionForPos:]',
        types='{Vector=[4f]}16@0:4{?=ii}8',
        start=9411440,
        end=9416080,
        disasm='disasm_worldtileloader_gettreelifefractionforpos_.txt',
        base_add=9411456,
        base_literal=9415436,
        boundary='ARM.exidx end 0x008fad90 (listing bound); next ObjC IMP 0x008fad90 DynamicWorld -[newFoundListRecievedFromClient:list:]',
        selectors={
                 0x8fab1c: (15216036, 'macroTiles'),
                 0x8fad50: (15216144, 'array'),
                 0x8fad5c: (15215864, 'count'),
                 0x8fad60: (15216012, 'pos'),
                 0x8fad64: (15217136, 'height'),
                 0x8fad68: (15215808, 'objectAtIndex:'),
                 0x8fad78: (15216772, 'treeType'),
                 0x8fad80: (15216008, 'addObject:'),
                 0x8fad88: (15216036, 'macroTiles'),
        },
        imports={
                 0x8fab18: (17151904, 'objc_msgSend'),
                 0x8fad4c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8fab10: (17162252, 'OBJC_IVAR_$_DynamicWorld.client', 20),
                 0x8fab14: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8fad74: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8fad84: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8fad8c: (17162436, 'OBJC_IVAR_$_DynamicWorld.clientTreeLifeFraction', 9480),
        },
        classes={
                 0x8fad54: (15247780, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(9411440, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9411660, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (9411780, 'cmp r0, 3'), (9411864, 'ldr ip, [fp, -0xb8]'), (9412688, 'ldr ip, [fp, -0xb8]'), (9414040, 'ldr r0, [0x008fad8c]'), (9414300, 'movw r0, 0'), (9414420, 'ldr r1, [r2, r1, lsl 2]'), (9414960, 'vcvt.f32.s32 s4, s4'), (9415144, 'vldr s0, [fp, -0x14c]'), (9415996, 'bl method.Vector.Vector_float__float__float__float_'), (9416076, 'invalid')],
        calls=[(9411616, 'blx r2'), (9411660, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (9411700, 'bl sym.tileIsTree_Tile_'), (9411928, 'blx r2'), (9411972, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (9412000, 'bl sym.tileIsTree_Tile_'), (9412016, 'bl 0x8ad2a4'), (9412080, 'bl sym.makeIntpair_int__int_'), (9412200, 'blx r2'), (9412244, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (9412272, 'bl sym.tileIsTree_Tile_'), (9412288, 'bl 0x8ad2a4'), (9412344, 'bl sym.makeIntpair_int__int_'), (9412472, 'blx r2'), (9412516, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (9412544, 'bl sym.tileIsTree_Tile_'), (9412560, 'bl 0x8ad2a4'), (9412624, 'bl sym.makeIntpair_int__int_'), (9412744, 'blx r2'), (9412788, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (9412816, 'bl sym.tileIsTree_Tile_'), (9412832, 'bl 0x8ad2a4'), (9412896, 'bl sym.makeIntpair_int__int_'), (9413016, 'blx r2'), (9413060, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (9413088, 'bl sym.tileIsTree_Tile_'), (9413104, 'bl 0x8ad2a4'), (9413160, 'bl sym.makeIntpair_int__int_'), (9413288, 'blx r2'), (9413332, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (9413360, 'bl sym.tileIsTree_Tile_'), (9413376, 'bl 0x8ad2a4'), (9413440, 'bl sym.makeIntpair_int__int_'), (9413560, 'blx r2'), (9413604, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (9413632, 'bl sym.tileIsTree_Tile_'), (9413648, 'bl 0x8ad2a4'), (9413704, 'bl sym.makeIntpair_int__int_'), (9413832, 'blx r2'), (9413876, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (9413904, 'bl sym.tileIsTree_Tile_'), (9413920, 'bl 0x8ad2a4'), (9413984, 'bl sym.makeIntpair_int__int_'), (9414064, 'bl method.Vector.operator_float__'), (9414120, 'bl method.Vector.operator_float__'), (9414172, 'bl method.Vector.operator_float__'), (9414224, 'bl method.Vector.operator_float__'), (9414368, 'blx r3'), (9414796, 'blx r2'), (9414876, 'bl loc.imp.objc_msgSend_stret'), (9414916, 'bl sym.imp.memset'), (9415048, 'bl loc.imp.objc_msgSend_stret'), (9415088, 'bl sym.imp.memset'), (9415276, 'blx lr'), (9415356, 'blx r3'), (9415400, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9415516, 'blx r2'), (9415528, 'bl 0x8ad2a4'), (9415636, 'blx r4'), (9415656, 'bl sym.imp.__umodsi3'), (9415684, 'blx r3'), (9415708, 'blx r2'), (9415716, 'bl sym.imp.__aeabi_idiv'), (9415768, 'bl loc.imp.objc_msgSend_stret'), (9415804, 'bl sym.imp.memset'), (9415876, 'bl loc.imp.objc_msgSend_stret'), (9415916, 'bl sym.imp.memset'), (9415996, 'bl method.Vector.Vector_float__float__float__float_')],
        branches=[(9411520, 'beq', 9414300), (9411680, 'beq', 9411732), (9411684, 'b', 9411696), (9411712, 'beq', 9411732), (9411784, 'bge', 9414040), (9411992, 'beq', 9412116), (9412012, 'beq', 9412116), (9412048, 'bpl', 9412100), (9412264, 'beq', 9412380), (9412284, 'beq', 9412380), (9412320, 'bpl', 9412364), (9412536, 'beq', 9412660), (9412556, 'beq', 9412660), (9412592, 'bpl', 9412644), (9412808, 'beq', 9412932), (9412828, 'beq', 9412932), (9412864, 'bpl', 9412916), (9412868, 'b', 9412876), (9413080, 'beq', 9413196), (9413100, 'beq', 9413196), (9413136, 'bpl', 9413180), (9413352, 'beq', 9413476), (9413372, 'beq', 9413476), (9413408, 'bpl', 9413460), (9413624, 'beq', 9413740), (9413644, 'beq', 9413740), (9413680, 'bpl', 9413724), (9413896, 'beq', 9414020), (9413916, 'beq', 9414020), (9413952, 'bpl', 9414004), (9414020, 'b', 9414024), (9414036, 'b', 9411776), (9414296, 'b', 9416004), (9414392, 'bge', 9415456), (9414700, 'beq', 9415416), (9414804, 'beq', 9415364), (9414860, 'beq', 9414888), (9414880, 'b', 9414920), (9415032, 'beq', 9415060), (9415052, 'b', 9415092), (9415164, 'ble', 9415360), (9415180, 'ble', 9415360), (9415360, 'b', 9415364), (9415364, 'b', 9415368), (9415412, 'b', 9414616), (9415416, 'b', 9415420), (9415432, 'b', 9414384), (9415524, 'bls', 9415944), (9415752, 'beq', 9415776), (9415772, 'b', 9415808), (9415860, 'beq', 9415888), (9415880, 'b', 9415920)],
        semantics=("getTreeLifeFractionForPos: computes the tree-life quantity for a position, in two modes. Prologue 0x008f9b70 (frame 0x2d0; base 0x105faf4). Arguments: pos pair [-0xb8]/[-0xb4], macroTile [-0xbc].\nMode gate: the self client ivar ffffe518 (cell 0x8fab10) == 0 -> mode B (0x8fa69c); otherwise mode A.\nMODE A (fraction scan): frac = 0.0 (cell 0x8f9c68); `tileAtWorldPosition(int, int, MacroTile*, World*)` (@0x8f9c4c) + `tileIsTree(Tile*)` (@0x8f9c74) on the exact pos adds 5.0 (0x8f9c84-0x8f9c90). Ring loop `for i in 0..3` (cmp 3 @0x8f9cc4): the radius ([fp,-0xcc], init 2.0 @0x8f9c9c) is multiplied by 5 each iteration (2.0 -> 10.0 -> 50.0; `vmov.f64 d0, 1` + the double round-trip at 0x8f9cd0-0x8f9d14); the 8-neighbour Moore scan at spacing d=8 ([fp,-0xd0]) covers (x-8,y-8), (x-8,y), (x-8,y+8), (x,y-8), (x,y+8), (x+8,y-8), (x+8,y), (x+8,y+8) (@0x8f9d18, 0x8f9e38, 0x8f9f38, 0x8fa050, 0x8fa160, 0x8fa268, 0x8fa32c, 0x8fa388); each: tileAtWorldPosition + tileIsTree, then `bl 0x8ad2a4` (random) divided by 2^31 (cells 0x8f9c6c / 0x8fa108 / 0x8fa8e4, all 2147483648.0) giving u in [0,1); when `u < radius` the candidate is recorded via `makeIntpair(x', y')` into [-0xd8]/[-0xd4] and frac += radius.\nMode A end (0x8fa598): the ivar ffffe5d0 (a 4-float Vector, accessed via `Vector::operator float*()` @0x8fa5b0+): v.x = v.x*5.0 + frac*5.0; v.y = (float)x; v.z = (float)y; then a 16-byte copy [v] -> [r3] (@0x8fa674-0x8fa694) returns the struct by value.\nMODE B (clientless): `isKindOfClass:` (ffe2331c, class ffe2aeb0) + count (@0x8fa6e0); `for i in 0..0xb (11)` (cmp 0xb @0x8fa6f4) with the SWITCH jump table via 0x8fad6c (0xffdeaf70) + 0x8fad70 (0x7653e0) -> table @ 0x00E4AA60 (dispatch @0x8fa714), then the ffffe54c map slice (12-byte stride, per tree type). Per tree (std::__tree_next @0x8faae8): t1 = 1 - |x_tree - x|/32.0; t2 = 1 - |y_tree - y|/32.0 (double abs/div chains @0x8fa930-0x8fa948 / 0x8fa9c4-0x8fa9e4, the tree pos via two stret getters, falloff 32.0 cells 0x8faccc / 0x8fad7c); when t1 > 0 && t2 > 0 (0x8fa9e8-0x8faa0c): w = t1*t2 * (ffe236fc(tree) as int -> float / 32.0) (@0x8faa20-0x8faa88) and acc += w ([-0x124]). After the 11 types a randomized final pass (bl 0x8ad2a4 + __umodsi3/__aeabi_idiv @0x8fab68-0x8fac24) yields two floats (fx,fy) -> `Vector::Vector(float, float, float, float)` (0x8fad3c) with (acc, fx, fy, 0.0) returned. Epilogue 0x8fad44.\n"),
    ),
    dict(
        name='wtl_checkandrestorepoleite',
        method='DynamicWorld -[checkAndRestorePoleItems:]',
        types='v12@0:4f8',
        start=9452008,
        end=9457176,
        disasm='disasm_worldtileloader_checkandrestorepoleitems_.txt',
        base_add=9452024,
        base_literal=9455720,
        boundary='ARM.exidx end 0x00904e18 (listing bound); next ObjC IMP 0x00904e18 DynamicWorld -[removeDynamicObjectsBelongingToClient:]',
        selectors={
                 0x904874: (15215980, 'customRules'),
                 0x904888: (15215884, 'objectForKey:'),
                 0x904890: (15215816, 'stringWithFormat:'),
                 0x904d68: (15216384, 'lakeHeightForX:'),
                 0x904d74: (15216356, 'maxOfRockAndDirtHeightForX:'),
                 0x904d7c: (15216128, 'worldWidthMacro'),
                 0x904d8c: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x904d94: (15216144, 'array'),
                 0x904d9c: (15216488, 'worldTime'),
                 0x904da0: (15217348, 'doubleValue'),
                 0x904da4: (15215884, 'objectForKey:'),
                 0x904da8: (15217352, 'integerValue'),
                 0x904db4: (15216128, 'worldWidthMacro'),
                 0x904dc0: (15216384, 'lakeHeightForX:'),
                 0x904dc8: (15216356, 'maxOfRockAndDirtHeightForX:'),
                 0x904dcc: (15216036, 'macroTiles'),
                 0x904dd0: (15217340, 'freeBlocksAtPos:'),
                 0x904dd8: (15216452, 'itemType'),
                 0x904ddc: (15217344, 'hovers'),
                 0x904de0: (15216388, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
                 0x904de8: (15216008, 'addObject:'),
                 0x904dec: (15217356, 'removeObjectsForKeys:'),
                 0x904df4: (15215816, 'stringWithFormat:'),
                 0x904e00: (15215800, 'init'),
                 0x904e04: (15215804, 'alloc'),
                 0x904e0c: (15215944, 'setObject:forKey:'),
                 0x904e10: (15217336, 'numberWithDouble:'),
        },
        imports={
                 0x904870: (17151968, '__stack_chk_guard'),
                 0x904884: (17151904, 'objc_msgSend'),
                 0x90488c: (16334200, '__CFConstantStringClassReference'),
                 0x904d80: (17151968, '__stack_chk_guard'),
                 0x904d88: (17151904, 'objc_msgSend'),
                 0x904df0: (16334200, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x90486c: (17162252, 'OBJC_IVAR_$_DynamicWorld.client', 20),
                 0x904878: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x90487c: (17162440, 'OBJC_IVAR_$_DynamicWorld.poleItemRestoreRecheckTimer', 9520),
                 0x904880: (17162444, 'OBJC_IVAR_$_DynamicWorld.poleItemRestoreAddTimer', 9524),
                 0x904898: (17162328, 'OBJC_IVAR_$_DynamicWorld.poleItemTakenTimes', 9516),
                 0x904d70: (17162264, 'OBJC_IVAR_$_DynamicWorld.worldTileLoader', 8),
                 0x904d84: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x904d90: (17162328, 'OBJC_IVAR_$_DynamicWorld.poleItemTakenTimes', 9516),
                 0x904dc4: (17162264, 'OBJC_IVAR_$_DynamicWorld.worldTileLoader', 8),
        },
        classes={
                 0x904894: (15247792, 'OBJC_CLASS_$_NSString'),
                 0x904d98: (15247780, 'OBJC_CLASS_$_NSMutableArray'),
                 0x904df8: (15247792, 'OBJC_CLASS_$_NSString'),
                 0x904e08: (15247784, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x904e14: (15247832, 'OBJC_CLASS_$_NSNumber'),
        },
        instructions=[(9452008, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9452352, 'movw r0, 2'), (9452628, 'cmp r0, 4'), (9453272, 'sub r0, fp, 0xe0'), (9453736, 'ldr r0, [0x00904d88]'), (9454028, 'movw r0, 0'), (9454176, 'ldr r0, [0x00904d88]'), (9454832, 'movw r0, 0x8ca0'), (9455776, 'andeq r0, r0, r0'), (9455976, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (9457172, 'invalid')],
        calls=[(9452172, 'bl loc.imp.objc_msgSend_stret'), (9452208, 'bl sym.imp.memset'), (9452296, 'bl loc.imp.objc_msgSend_stret'), (9452332, 'bl sym.imp.memset'), (9452840, 'blx lr'), (9452872, 'blx r3'), (9453000, 'bl loc.imp.objc_msgSend'), (9453024, 'bl sym.imp.__aeabi_idiv'), (9453076, 'blx ip'), (9453128, 'blx ip'), (9453276, 'bl sym.makeIntpair_int__int_'), (9453356, 'blx r2'), (9453400, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (9453560, 'bl loc.imp.objc_msgSend'), (9453584, 'bl sym.imp.memset'), (9453632, 'blx lr'), (9453732, 'bl sym.imp.objc_enumerationMutation'), (9453804, 'blx r2'), (9453860, 'blx r2'), (9453988, 'blx ip'), (9454136, 'blx r2'), (9454152, 'blx r2'), (9454380, 'blx r8'), (9454412, 'blx ip'), (9454452, 'blx lr'), (9454488, 'blx ip'), (9454640, 'blx r2'), (9454664, 'bl sym.imp.memset'), (9454728, 'blx lr'), (9454828, 'bl sym.imp.objc_enumerationMutation'), (9454992, 'blx r5'), (9455008, 'blx r2'), (9455052, 'blx r3'), (9455104, 'bl loc.imp.objc_msgSend'), (9455232, 'bl loc.imp.objc_msgSend'), (9455256, 'bl sym.imp.__aeabi_idiv'), (9455328, 'bl loc.imp.objc_msgSend'), (9455352, 'bl sym.imp.__aeabi_idiv'), (9455432, 'bl loc.imp.objc_msgSend'), (9455456, 'bl sym.imp.__aeabi_idiv'), (9455564, 'blx ip'), (9455616, 'blx ip'), (9455824, 'bl sym.makeIntpair_int__int_'), (9455904, 'blx r2'), (9455948, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (9455976, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (9456128, 'bl loc.imp.objc_msgSend'), (9456152, 'bl sym.imp.memset'), (9456200, 'blx lr'), (9456300, 'bl sym.imp.objc_enumerationMutation'), (9456372, 'blx r2'), (9456428, 'blx r2'), (9456552, 'blx ip'), (9456700, 'bl loc.imp.objc_msgSend'), (9456752, 'blx r3'), (9456864, 'blx ip'), (9456960, 'blx r3'), (9457004, 'bl sym.imp.__stack_chk_fail')],
        branches=[(9452096, 'bne', 9452348), (9452156, 'beq', 9452180), (9452176, 'b', 9452212), (9452220, 'beq', 9452352), (9452280, 'beq', 9452304), (9452300, 'b', 9452336), (9452344, 'bne', 9452352), (9452348, 'b', 9456964), (9452464, 'ble', 9456964), (9452552, 'ble', 9454524), (9452632, 'bge', 9454520), (9452644, 'bne', 9452660), (9452656, 'b', 9452712), (9452668, 'bne', 9452684), (9452680, 'b', 9452708), (9452692, 'bne', 9452704), (9452704, 'b', 9452708), (9452708, 'b', 9452712), (9452884, 'bne', 9454500), (9453148, 'bge', 9453164), (9453160, 'b', 9453172), (9453216, 'bge', 9453236), (9453228, 'b', 9453244), (9453420, 'beq', 9454496), (9453644, 'beq', 9454012), (9453724, 'beq', 9453736), (9453816, 'bne', 9453888), (9453872, 'beq', 9453888), (9453884, 'b', 9454016), (9453888, 'b', 9453892), (9453916, 'blo', 9453688), (9454008, 'bne', 9453688), (9454012, 'b', 9454016), (9454024, 'bne', 9454492), (9454064, 'bne', 9454176), (9454492, 'b', 9454496), (9454496, 'b', 9454500), (9454500, 'b', 9454504), (9454516, 'b', 9452624), (9454520, 'b', 9454524), (9454740, 'beq', 9456888), (9454820, 'beq', 9454832), (9455080, 'ble', 9456764), (9455132, 'beq', 9455268), (9455136, 'b', 9455140), (9455148, 'beq', 9455364), (9455152, 'b', 9455156), (9455164, 'bne', 9455476), (9455168, 'b', 9455172), (9455264, 'b', 9455480), (9455360, 'b', 9455480), (9455472, 'b', 9455480), (9455476, 'b', 9455480), (9455636, 'bge', 9455652), (9455648, 'b', 9455660), (9455704, 'bge', 9455784), (9455716, 'b', 9455792), (9455968, 'beq', 9456760), (9455988, 'beq', 9456756), (9456212, 'beq', 9456576), (9456292, 'beq', 9456304), (9456384, 'bne', 9456452), (9456440, 'beq', 9456452), (9456452, 'b', 9456456), (9456480, 'blo', 9456256), (9456572, 'bne', 9456256), (9456576, 'b', 9456580), (9456592, 'bne', 9456704), (9456756, 'b', 9456760), (9456760, 'b', 9456764), (9456764, 'b', 9456768), (9456792, 'blo', 9454784), (9456884, 'bne', 9454784), (9456888, 'b', 9456892), (9456988, 'bne', 9457004)],
        semantics=('checkAndRestorePoleItems: periodically verifies the four ownership poles and restores missing ones. Prologue 0x009039e8 (frame 0x4b0; base 0x105faf4). Arguments: float dt [-0xac], self [-0xa4].\nGates: self client (ffffe518, cell 0x90486c) == 0 -> exit (0x903b3c -> 0x904d44). Two 0x40-byte stret reads from the world (ffffe4e4) with byte[0]==0 and byte[4]==1 required (0x903ab4-0x903b38).\nTimers (hysteresis pair): ivars ffffe5d4 (cell 0x90487c) and ffffe5d8 (cell 0x904880) both += dt (0x903b5c-0x903b90); if ffffe5d4 <= 2.0 -> exit; when ffffe5d8 > 2.0 it is reduced by 2.0 (0x903c28-0x903c3c).\nLoop: `for i in 0..4` (cmp 4 @0x903c54): pole item id per i (r1 defaults 0x8e @0x903c10; i==1 -> 0x8c @0x903c68; i==2 -> 0x8f @0x903c80; i==3 -> 0x8d @0x903c98).\nPer i: the pole registry dict ivar ffffe564 (cell 0x904d90) is queried with `objectForKey:` (ffe23218) on a `stringWithFormat:` key (ffe231d4 / NSString ffe2aebc, fmt 0xfff34284) built from the pole id (@0x903ca8-0x903d54).\nPole placement: posX = ((worldWidthMacro (ffe2330c) << 5) / den) * num per the id arm switch (cmp 0x8f/0x8d/0x8c @0x904610-0x904774 with the immediate pairs (4,5) / (2,5) / (3,4,5 + mul)); the value is clamped (min chain + the 0x200 (512) clamp @0x903e78-0x903ec0) and packed `makeIntpair(x, y+0x10)` (@0x903ed8); `tileAtWorldPosition` (@0x903f58) then the objects at the tile are enumerated: `[obj objectType]` (ffe23450) == the pole id + the ffe237cc gate set the found flag [-0xe5] (@0x9040a8-0x904138) - a present pole skips.\nRestore path (0x9041cc+): the fffe564 dict is lazily created (`[[NSMutableDictionary alloc] init]`, cells 0x904e00-0x904e08) when nil; `setObject:forKey:` (ffe23254) stores the entry with the `stringWithFormat` key and worldTime (ffe23474) (@0x904260-0x9042fc); the stale/rebuild check uses double math: (now - stored) compared > 36000.0 (the double cell behind `movw r0, 0x8ca0` @0x9048a0), with `tileIsAirWaterOrSnow` (@0x904968) and a second existing-pole scan (@0x904978-0x904b60, found flag [-0x205]) before creating; the create call packs 8 words (id + zeros + a 1 at +0x14; cells ffe23410 (0x904de0)) and the result is added via `addObject:` (ffe23294, 0x904de8) into the collection [-0x164]. Loop tail 0x9043a8-0x9043b4; exit 0x904d44.\nBoundary: the per-id numerator/denominator immediates are read from the arms (0x8e default arm (4,5) region, 0x8f (2,5), 0x8d (3,4,5), 0x8c (4,5)); the exact id->fraction mapping across both the first-create and restore arms is recorded as observed.\n'),
    ),
    dict(
        name='wtl_elevatormotorforshafta',
        method='DynamicWorld -[elevatorMotorForShaftAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9355072,
        end=9358668,
        disasm='disasm_worldtileloader_elevatormotorforshaftatpos_.txt',
        base_add=9355088,
        base_literal=9358664,
        boundary='ARM.exidx end 0x008ecd4c (listing bound); next ObjC IMP 0x008ecd4c DynamicWorld -[addElevatorMotorAtPos:ofType:saveDict:placedByClient:]',
        selectors={
                 0x8ecd0c: (15216928, 'elevatorShaftAtPos:'),
                 0x8ecd14: (15216944, 'lastKnownMotorPos'),
                 0x8ecd1c: (15216948, 'elevatorMotorAtPos:'),
                 0x8ecd20: (15216012, 'pos'),
                 0x8ecd28: (15216936, 'minY'),
                 0x8ecd2c: (15216940, 'maxY'),
        },
        imports={
                 0x8ecd24: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8eccf8: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8ecd00: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
                 0x8ecd08: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
        },
        classes={},
        instructions=[(9355072, 'push {r4, r5, fp, lr}'), (9355116, 'ldr r1, [0x008eccf8]'), (9355736, 'sub r0, fp, 0x68'), (9356408, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9357020, 'ldr r0, [0x008ecd08]'), (9357692, 'ldrb r0, [r0, 3]'), (9357792, 'ldr r0, [0x008ecd08]'), (9358664, 'invalid')],
        calls=[(9355504, 'bl loc.imp.objc_msgSend_stret'), (9355540, 'bl sym.imp.memset'), (9355600, 'blx r2'), (9355656, 'blx r2'), (9355720, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9356128, 'bl loc.imp.objc_msgSend_stret'), (9356164, 'bl sym.imp.memset'), (9356224, 'blx r2'), (9356280, 'blx r2'), (9356344, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9356408, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9356488, 'bl sym.makeIntpair_int__int_'), (9356520, 'bl loc.imp.objc_msgSend'), (9356596, 'bl loc.imp.objc_msgSend_stret'), (9356632, 'bl sym.imp.memset'), (9356696, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9356756, 'bl loc.imp.objc_msgSend'), (9356832, 'bl loc.imp.objc_msgSend_stret'), (9356868, 'bl sym.imp.memset'), (9356928, 'blx r2'), (9356984, 'blx r2'), (9357072, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9357156, 'bl sym.makeIntpair_int__int_'), (9357188, 'bl loc.imp.objc_msgSend'), (9357264, 'bl loc.imp.objc_msgSend_stret'), (9357300, 'bl sym.imp.memset'), (9357364, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9357424, 'bl loc.imp.objc_msgSend'), (9357500, 'bl loc.imp.objc_msgSend_stret'), (9357536, 'bl sym.imp.memset'), (9357596, 'blx r2'), (9357652, 'blx r2'), (9357732, 'bl sym.makeIntpair_int__int_'), (9357764, 'bl loc.imp.objc_msgSend'), (9357844, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9357928, 'bl sym.makeIntpair_int__int_'), (9357960, 'bl loc.imp.objc_msgSend'), (9358036, 'bl loc.imp.objc_msgSend_stret'), (9358072, 'bl sym.imp.memset'), (9358136, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9358196, 'bl loc.imp.objc_msgSend'), (9358272, 'bl loc.imp.objc_msgSend_stret'), (9358308, 'bl sym.imp.memset'), (9358368, 'blx r2'), (9358424, 'blx r2'), (9358504, 'bl sym.makeIntpair_int__int_'), (9358536, 'bl loc.imp.objc_msgSend')],
        branches=[(9355396, 'beq', 9355736), (9355488, 'beq', 9355512), (9355508, 'b', 9355544), (9355556, 'bne', 9355684), (9355612, 'bgt', 9355684), (9355668, 'blt', 9355684), (9355680, 'b', 9358572), (9355684, 'b', 9355688), (9355732, 'b', 9355312), (9356020, 'beq', 9356360), (9356112, 'beq', 9356136), (9356132, 'b', 9356168), (9356180, 'bne', 9356308), (9356236, 'bgt', 9356308), (9356292, 'blt', 9356308), (9356304, 'b', 9358572), (9356308, 'b', 9356312), (9356356, 'b', 9355936), (9356428, 'beq', 9357020), (9356444, 'bne', 9357020), (9356540, 'beq', 9357016), (9356580, 'beq', 9356604), (9356600, 'b', 9356636), (9356776, 'beq', 9357012), (9356816, 'beq', 9356840), (9356836, 'b', 9356872), (9356884, 'bne', 9357012), (9356940, 'bgt', 9357012), (9356996, 'blt', 9357012), (9357008, 'b', 9358572), (9357012, 'b', 9357016), (9357016, 'b', 9357020), (9357092, 'beq', 9357792), (9357108, 'bne', 9357688), (9357208, 'beq', 9357684), (9357248, 'beq', 9357272), (9357268, 'b', 9357304), (9357444, 'beq', 9357680), (9357484, 'beq', 9357508), (9357504, 'b', 9357540), (9357552, 'bne', 9357680), (9357608, 'bgt', 9357680), (9357664, 'blt', 9357680), (9357676, 'b', 9358572), (9357680, 'b', 9357684), (9357684, 'b', 9357788), (9357700, 'bne', 9357784), (9357780, 'b', 9358572), (9357784, 'b', 9357788), (9357788, 'b', 9357792), (9357864, 'beq', 9358564), (9357880, 'bne', 9358460), (9357980, 'beq', 9358456), (9358020, 'beq', 9358044), (9358040, 'b', 9358076), (9358216, 'beq', 9358452), (9358256, 'beq', 9358280), (9358276, 'b', 9358312), (9358324, 'bne', 9358452), (9358380, 'bgt', 9358452), (9358436, 'blt', 9358452), (9358448, 'b', 9358572), (9358452, 'b', 9358456), (9358456, 'b', 9358560), (9358472, 'bne', 9358556), (9358552, 'b', 9358572), (9358556, 'b', 9358560), (9358560, 'b', 9358564)],
        semantics=('elevatorMotorForShaftAtPos: finds the elevator motor object serving a shaft position. Prologue 0x008ebf40 (frame 0x320; base 0x105faf4). Arguments: shaft pos pair [-0x148]/[-0x144], self [-0x14c].\nRegistry search 1 (0x8ebf6c-0x8ec1d4): the +0x294 member slices of the ffffe54c map (cell 0x8eccf8) are iterated (std::__tree_next @0x8ec1c8); per node the object pos (pos getter ffe23298 with the [obj+0x10]+8 member) is compared against the shaft pair via the two getters ffe23634 / ffe23638 (@0x8ec128-0x8ec194); equality returns the node object [-0x13c] -> 0x8eccec.\nRegistry search 2 (0x8ec1d8-0x8ec448): the same over the ffffe550 map slices (+0x294, cell 0x8ecd00) with the same matched return.\nTile probes (0x8ec448+): `tileAtWorldPositionLoaded(int, int, World*)` (@0x8ec478/0x8ec598) at the shaft position: tile byte [tile+3] == 0x67 (elevator marker) gates the per-tile predicate call ffe2362c (cell 0x8ecd0c) with `makeIntpair`, then the ffe2363c member compare and the ffe23640 getter (cell 0x8ecd1c) with the matched pos check (ffe23634/38) returning the found object (@0x8ec500-0x8ec6d0).\nFurther probes: (x, y+1) at 0x8ec6dc-0x8ec974 (marker 0x67 again); (x, y+1) with tile byte [tile+3] == 0x68 at 0x8ec97c-0x8ec9d4 returning the result of the ffe23640 call; (x, y-1) at 0x8ec9e0-0x8ecc74 (marker 0x67 + the same chains, plus the 0x68 arm region 0x8ec980). When nothing matches the result is nil (0x8ecce4/0x8eccec region). Epilogue 0x8ecd44 region.\nNotes: 0x67 / 0x68 are the two shaft-adjacent tile marker bytes; the two registry maps are the same per-type object maps used by the E22 unloader.\n'),
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
        'batch': 'DynamicWorld change-propagation cluster (E23): lightChangedAtMacroPos:sendReliably:sendAtAll:, waterChangedAtPos:fullBlock:, sowTreeNearParent:adult:adultMaxAge:, sowPlantNearParent:, getTreeLifeFractionForPos:, checkAndRestorePoleItems: and elevatorMotorForShaftAtPos:; 7 bodies',
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
                        default=NATIVE / 'world_update.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale world_update.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
