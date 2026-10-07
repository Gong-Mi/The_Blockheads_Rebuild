#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld load-chain leaf bodies (E20).

The DynamicWorld load-chain leaves - the ten constructor workers the E19 load
chain calls into: trees (11 classes), plants (10 classes), NPCs, snow/surface
blocks, glow blocks, torches, the treasure/troll cave generator, the new-blockhead
spawner and the background conversion thread:
1 body, 5479 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/DYN_OBJECT_LEAVES.md for the prose and boundaries.
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
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector.Vector_float__float__float__float_': 0x004d0d08,
    'bl method.Vector.operator_Vector_': 0x004d6538,
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl method.std::__1::__hash_const_iterator_std::__1::__hash_node_unsigned_int__void__const__std::__1::__hash_table_unsigned_int__std::__1::hash_unsigned_int___std::__1::equal_to_unsigned_int___std::__1::allocator_unsigned_int___.find_unsigned_int__unsigned_int_const__const': 0x009123a4,
    'bl method.std::__1::__hash_const_iterator_std::__1::__hash_node_unsigned_long_long__void__const__std::__1::__hash_table_unsigned_long_long__std::__1::hash_unsigned_long_long___std::__1::equal_to_unsigned_long_long___std::__1::allocator_unsigned_long_long___.find_unsigned_long_long__unsigned_long_long_const__const': 0x00910798,
    'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__': 0x005dc5d8,
    'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_': 0x008bcf24,
    'bl method.std::__1::pair_std::__1::__hash_iterator_std::__1::__hash_node_unsigned_long_long__void____bool__std::__1::__hash_table_unsigned_long_long__std::__1::hash_unsigned_long_long___std::__1::equal_to_unsigned_long_long___std::__1::allocator_unsigned_long_long___.__insert_unique_unsigned_long_long__unsigned_long_long_': 0x00908560,
    'bl method.std::__1::vector_intpair__std::__1::allocator_intpair___._vector__': 0x0052b718,
    'bl method.unsigned_long_std::__1::__hash_table_unsigned_long_long__std::__1::hash_unsigned_long_long___std::__1::equal_to_unsigned_long_long___std::__1::allocator_unsigned_long_long___.__erase_unique_unsigned_long_long__unsigned_long_long_const_': 0x00913f9c,
    'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const': 0x00910a74,
    'bl method.void_std::__1::vector_intpair__std::__1::allocator_intpair___.__push_back_slow_path_intpair_const__intpair_const_': 0x0052d84c,
    'bl sym.clamp_float__float__float_': 0x004be068,
    'bl sym.classForNPCType_NPCType_': 0x006437e4,
    'bl sym.dynamicObjectTypeForNPCType_NPCType_': 0x006495a0,
    'bl sym.imp.NSLog': 0x001c2a5c,
    'bl sym.imp._Unwind_Resume': 0x001c29c0,
    'bl sym.imp.__modsi3': 0x001c3020,
    'bl sym.imp.__wrap_rename': 0x001c4184,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.macroIndexAtWorldIndex_int__World_': 0x00a173c4,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileIsAir_Tile_': 0x00a12300,
    'bl sym.tileIsSolid_Tile_': 0x00a1179c,
    'bl sym.worldIndexAtWorldPos_intpair__World_': 0x00a15838,
    'bl sym.worldIndexAtWorldPosition_int__int__World_': 0x00a156a8,
}

SPECS = [
    dict(
        name='wtl_conversionthread_',
        method='DynamicWorld -[conversionThread:]',
        types='v12@0:4@8',
        start=9102776,
        end=9104812,
        disasm='disasm_worldtileloader_conversionthread_.txt',
        base_add=9102792,
        base_literal=9104808,
        boundary='ARM.exidx end 0x008aedac (listing bound); next ObjC IMP 0x008aedac DynamicWorld -[loadDynamicObjects:repositionBlockheadLoadFailures:]',
        selectors={
                 0x8aed5c: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8aed60: (15215872, 'copy'),
                 0x8aed64: (15215800, 'init'),
                 0x8aed68: (15215804, 'alloc'),
                 0x8aed70: (15215868, 'setThreadPriority:'),
                 0x8aed7c: (15215876, 'sleepForTimeInterval:'),
                 0x8aed80: (15215852, 'release'),
                 0x8aed84: (15215884, 'objectForKey:'),
                 0x8aed88: (15215832, 'createDirectoryAtPath:withIntermediateDirectories:attributes:error:'),
                 0x8aed8c: (15215824, 'defaultManager'),
                 0x8aed94: (15215880, 'stringByAppendingPathComponent:'),
                 0x8aed9c: (15215888, 'UTF8String'),
                 0x8aeda0: (15215896, 'performSelectorOnMainThread:withObject:waitUntilDone:'),
                 0x8aeda4: (15215892, 'mainThreadRemoveDirFromConversionList:'),
        },
        imports={
                 0x8aed58: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8aed78: (17162280, 'OBJC_IVAR_$_DynamicWorld.versionOneToTwoConversionList', 9464),
                 0x8aed98: (17162196, 'OBJC_IVAR_$_DynamicWorld.worldSaveDirectory', 40),
        },
        classes={
                 0x8aed6c: (15247808, 'OBJC_CLASS_$_NSAutoreleasePool'),
                 0x8aed74: (15247804, 'OBJC_CLASS_$_NSThread'),
                 0x8aed90: (15247796, 'OBJC_CLASS_$_NSFileManager'),
        },
        instructions=[(9102776, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9103264, 'ldr r3, [0x008aed58]'), (9103844, 'bl sym.imp.memset'), (9104168, 'bl sym.imp.__wrap_rename'), (9104368, 'ldr ip, [sp, 0x30]'), (9104808, 'rsbseq r1, fp, r4, lsr 10')],
        calls=[(9102996, 'blx r5'), (9103028, 'blx r2'), (9103044, 'blx r2'), (9103068, 'blx r2'), (9103092, 'bl sym.imp.memset'), (9103140, 'blx lr'), (9103240, 'bl sym.imp.objc_enumerationMutation'), (9103352, 'blx ip'), (9103432, 'blx r3'), (9103452, 'blx r2'), (9103628, 'blx sl'), (9103664, 'blx r3'), (9103704, 'blx lr'), (9103740, 'blx ip'), (9103844, 'bl sym.imp.memset'), (9103892, 'blx lr'), (9103992, 'bl sym.imp.objc_enumerationMutation'), (9104092, 'blx ip'), (9104116, 'blx r2'), (9104148, 'blx r3'), (9104168, 'bl sym.imp.__wrap_rename'), (9104272, 'blx ip'), (9104384, 'blx lr'), (9104472, 'blx r4'), (9104504, 'blx r3'), (9104520, 'blx r2'), (9104624, 'blx ip'), (9104696, 'blx r3'), (9104716, 'blx r2')],
        branches=[(9103152, 'beq', 9104648), (9103232, 'beq', 9103244), (9103384, 'bne', 9103472), (9103456, 'b', 9104720), (9103760, 'beq', 9104388), (9103904, 'beq', 9104296), (9103984, 'beq', 9103996), (9104200, 'blo', 9103948), (9104292, 'bne', 9103948), (9104296, 'b', 9104300), (9104552, 'blo', 9103196), (9104644, 'bne', 9103196), (9104648, 'b', 9104652)],
        semantics=("conversionThread: is the background worker spawned by loadDynamicObjects: for the one-to-two save conversion. Prologue 0x008ae5b8 (frame 0x228); argument = the dictionary handed to the thread.\nSetup: `[[NSAutoreleasePool alloc] init]` (cells 0x008aed6c/0x008aed64), thread priority 5 via `[NSThread setThreadPriority:]` (cell 0x008aed70, double 5 materialised from 0x008ae868).\nPer item of self->versionOneToTwoConversionList (ivar cell 0x008aed78): fast enumeration (countByEnumeratingWithState:, cell 0x008aed5c); for each item: a paced sleep `[NSThread sleepForTimeInterval:]` (cell 0x008aed7c), then the directory + file migration: `[item objectForKey:...]` copies (cell 0x008aed84), `[[NSFileManager defaultManager] createDirectoryAtPath:...]` (cells 0x008aed8c/0x008aed88) under self->worldSaveDirectory (cell 0x008aed98), `stringByAppendingPathComponent:` (cell 0x008aed94) + `UTF8String` (cell 0x008aed9c) paths, and per inner element **`__wrap_rename(old, new)`** (0x008aeb28) - the actual file renames. When the item's file list is exhausted the item is handed back to the main thread with `[[NSThread mainThread] performSelectorOnMainThread:@selector(mainThreadRemoveDirFromConversionList:) withObject:item waitUntilDone:1]` (cells 0x008aeda0/0x008aeda4; waitUntilDone materialised as 1, 0x008aebac-0x008aebfc). The autorelease pool is drained at the end; the loop bound is the conversion list's count (0x008aeca8 loops while items remain).\n"),
    ),
    dict(
        name='wtl_loadtreeatposition_typ',
        method='DynamicWorld -[loadTreeAtPosition:type:maxHeight:growthRate:adultTree:adultMaxAge:]',
        types='v36@0:4{?=ii}8i16s20s24c28f32',
        start=9326148,
        end=9331280,
        disasm='disasm_worldtileloader_loadtreeatposition_type_maxheight_growth.txt',
        base_add=9326168,
        base_literal=9330140,
        boundary='ARM.exidx end 0x008e6250 (listing bound); next ObjC IMP 0x008e6250 DynamicWorld -[loadStandardDynamicObjectOfType:atPos:]',
        selectors={
                 0x8e5ef0: (15216012, 'pos'),
                 0x8e61cc: (15215804, 'alloc'),
                 0x8e61e0: (15216792, 'initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:'),
                 0x8e621c: (15216796, 'initWithWorld:dynamicWorld:atPosition:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:gemTreeType:'),
                 0x8e6238: (15216168, 'objectType'),
                 0x8e6244: (15216160, 'uniqueID'),
                 0x8e6248: (15216012, 'pos'),
        },
        imports={
                 0x8e61bc: (16333864, '__CFConstantStringClassReference'),
                 0x8e624c: (16333880, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x8e5de8: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8e61d0: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8e61d4: (17162232, 'OBJC_IVAR_$_DynamicWorld.cache', 7336),
                 0x8e61d8: (17162228, 'OBJC_IVAR_$_DynamicWorld.treeDensityNoiseFunction', 7340),
                 0x8e61dc: (17162224, 'OBJC_IVAR_$_DynamicWorld.seasonOffsetNoiseFunction', 7344),
                 0x8e6240: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
        },
        classes={
                 0x8e61c4: (15247928, 'OBJC_CLASS_$_CoffeeTree'),
                 0x8e61e4: (15247924, 'OBJC_CLASS_$_CherryTree'),
                 0x8e61ec: (15247920, 'OBJC_CLASS_$_LimeTree'),
                 0x8e61f4: (15247916, 'OBJC_CLASS_$_OrangeTree'),
                 0x8e61fc: (15247912, 'OBJC_CLASS_$_CoconutTree'),
                 0x8e6204: (15247908, 'OBJC_CLASS_$_CactusTree'),
                 0x8e620c: (15247904, 'OBJC_CLASS_$_MangoTree'),
                 0x8e6214: (15247900, 'OBJC_CLASS_$_GemTree'),
                 0x8e6220: (15247896, 'OBJC_CLASS_$_PineTree'),
                 0x8e6228: (15247892, 'OBJC_CLASS_$_MapleTree'),
                 0x8e6230: (15247888, 'OBJC_CLASS_$_AppleTree'),
        },
        instructions=[(9326148, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9326244, 'ldr r0, [fp, -0x174]'), (9326544, 'movw r0, 0'), (9327072, 'ldr r0, [0x008e61bc]'), (9330244, 'ldr ip, [fp, -0x15c]'), (9331276, 'invalid')],
        calls=[(9326668, 'bl loc.imp.objc_msgSend_stret'), (9326704, 'bl sym.imp.memset'), (9326776, 'bl loc.imp.objc_msgSend_stret'), (9326812, 'bl sym.imp.memset'), (9326888, 'bl loc.imp.objc_msgSend_stret'), (9326924, 'bl sym.imp.memset'), (9327016, 'bl loc.imp.objc_msgSend_stret'), (9327052, 'bl sym.imp.memset'), (9327084, 'bl sym.imp.NSLog'), (9327128, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9327556, 'bl loc.imp.objc_msgSend_stret'), (9327592, 'bl sym.imp.memset'), (9327664, 'bl loc.imp.objc_msgSend_stret'), (9327700, 'bl sym.imp.memset'), (9327776, 'bl loc.imp.objc_msgSend_stret'), (9327812, 'bl sym.imp.memset'), (9327904, 'bl loc.imp.objc_msgSend_stret'), (9327940, 'bl sym.imp.memset'), (9327972, 'bl sym.imp.NSLog'), (9328016, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9328104, 'bl loc.imp.objc_msgSend'), (9328308, 'bl loc.imp.objc_msgSend'), (9328364, 'bl loc.imp.objc_msgSend'), (9328568, 'bl loc.imp.objc_msgSend'), (9328624, 'bl loc.imp.objc_msgSend'), (9328828, 'bl loc.imp.objc_msgSend'), (9328932, 'bl loc.imp.objc_msgSend'), (9329088, 'bl loc.imp.objc_msgSend'), (9329144, 'bl loc.imp.objc_msgSend'), (9329348, 'bl loc.imp.objc_msgSend'), (9329404, 'bl loc.imp.objc_msgSend'), (9329608, 'bl loc.imp.objc_msgSend'), (9329664, 'bl loc.imp.objc_msgSend'), (9329868, 'bl loc.imp.objc_msgSend'), (9329924, 'bl loc.imp.objc_msgSend'), (9330128, 'bl loc.imp.objc_msgSend'), (9330200, 'bl loc.imp.objc_msgSend'), (9330404, 'bl loc.imp.objc_msgSend'), (9330464, 'bl loc.imp.objc_msgSend'), (9330668, 'bl loc.imp.objc_msgSend'), (9330724, 'bl loc.imp.objc_msgSend'), (9330928, 'bl loc.imp.objc_msgSend'), (9331032, 'bl loc.imp.objc_msgSend'), (9331092, 'bl loc.imp.objc_msgSend'), (9331112, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_')],
        branches=[(9326252, 'bge', 9328052), (9326560, 'beq', 9327144), (9326652, 'beq', 9326676), (9326672, 'b', 9326708), (9326720, 'bne', 9327092), (9326760, 'beq', 9326784), (9326780, 'b', 9326816), (9326832, 'blt', 9327092), (9326872, 'beq', 9326896), (9326892, 'b', 9326928), (9326944, 'bgt', 9327092), (9326960, 'bne', 9327072), (9327000, 'beq', 9327024), (9327020, 'b', 9327056), (9327068, 'bne', 9327092), (9327088, 'b', 9331124), (9327092, 'b', 9327096), (9327140, 'b', 9326476), (9327448, 'beq', 9328032), (9327540, 'beq', 9327564), (9327560, 'b', 9327596), (9327608, 'bne', 9327980), (9327648, 'beq', 9327672), (9327668, 'b', 9327704), (9327720, 'blt', 9327980), (9327760, 'beq', 9327784), (9327780, 'b', 9327816), (9327832, 'bgt', 9327980), (9327848, 'bne', 9327960), (9327888, 'beq', 9327912), (9327908, 'b', 9327944), (9327956, 'bne', 9327980), (9327976, 'b', 9331124), (9327980, 'b', 9327984), (9328028, 'b', 9327364), (9328032, 'b', 9328036), (9328048, 'b', 9326244), (9328068, 'bne', 9328320), (9328316, 'b', 9330976), (9328328, 'bne', 9328580), (9328576, 'b', 9330972), (9328588, 'bne', 9328840), (9328836, 'b', 9330968), (9328848, 'beq', 9328900), (9328860, 'beq', 9328900), (9328872, 'beq', 9328900), (9328884, 'beq', 9328900), (9328896, 'bne', 9329100), (9329096, 'b', 9330964), (9329108, 'bne', 9329360), (9329356, 'b', 9330960), (9329368, 'bne', 9329620), (9329616, 'b', 9330956), (9329628, 'bne', 9329880), (9329876, 'b', 9330952), (9329888, 'bne', 9330156), (9330136, 'b', 9330948), (9330164, 'bne', 9330420), (9330412, 'b', 9330944), (9330428, 'bne', 9330680), (9330676, 'b', 9330940), (9330688, 'bne', 9330936), (9330936, 'b', 9330940), (9330940, 'b', 9330944), (9330944, 'b', 9330948), (9330948, 'b', 9330952), (9330952, 'b', 9330956), (9330956, 'b', 9330960), (9330960, 'b', 9330964), (9330964, 'b', 9330968), (9330968, 'b', 9330972), (9330972, 'b', 9330976), (9330988, 'beq', 9331124)],
        semantics=('loadTreeAtPosition:type:maxHeight:growthRate:adultTree:adultMaxAge: instantiates one tree. Prologue 0x008e4e44 (frame 0x360). Arguments: position pair r2/r3, maxHeight short [fp,8], growthRate short [fp,0xc], adultTree byte [fp,0x10], adultMaxAge float [fp,0x14] (s0). The spills keep the shorts at [fp,-0x168]+2/[fp,-0x168], the byte at [fp,-0x169] and the float at [fp,-0x170].\n**Occupancy scan (0x008e4ea4-0x008e55a0)**: for i in 0..0xb (12 buckets) the body walks two 12-byte-stride maps: first the dynamicObjectsToAdd slice (cell 0x008e5de8 ffe54c) then the dynamicObjects slice (cell 0x008e6240 ffe550), each through a std::__1::__tree_next iterator walk (route 0x005dc5d8). Per object `[obj pos]` (selector cell 0x008e5ef0/0x008e6248) is fetched (stret 8) and compared: the x must differ from the requested x, the y must lie within [reqY-1, reqY+1], and - when the adult flag gate [fp,-0x69] is clear - not equal to reqY exactly; a collision logs (string 0xfff34134/frame[-0x118]) and jumps to the method tail (0x008e61b4) instead of placing a duplicate tree.\n**Type switch (11 arms)**: 1 -> AppleTree (cell 0x008e6230), 2 -> MangoTree (0x008e620c), 3 -> MapleTree (0x008e6228), 4 -> PineTree (0x008e6220), 5 -> CactusTree (0x008e6204), 6 -> CoconutTree (0x008e61fc), 7 -> OrangeTree (0x008e61f4), 8 -> CherryTree (0x008e61e4), 9 -> CoffeeTree (0x008e61c4), 0xa -> LimeTree (0x008e61ec), 0xf -> GemTree (0x008e6214). The ten non-gem arms: `[[Class alloc] initWithWorld:... dynamicWorld:self atPosition:pos cache:cache maxHeight:maxHeight growthRate:growthRate treeDensityNoiseFunction:... seasonOffsetNoiseFunction:... adultTree:adultTree adultMaxAge:adultMaxAge]` (selector cell 0x008e61e0) with sxth-ed shorts and the float stacked. The GemTree arm (0x008e5ef8-0x008e5ff4 region reads the same args through the second init) uses `initWithWorld:dynamicWorld:atPosition:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:gemTreeType:` (selector cell 0x008e621c).\nShared tail (0x008e6120-0x008e624c): `[obj objectType]` (cell 0x008e6238) -> operator[] on the type-strided dynamicObjectsToAdd slice, `[obj uniqueID]` (cell 0x008e6244) key -> store; then the net send follows the plant/torch tail shape.\n'),
    ),
    dict(
        name='wtl_loadplantatposition_ty',
        method='DynamicWorld -[loadPlantAtPosition:type:maxAgeGene:growthRateGene:adult:]',
        types='v32@0:4{?=ii}8i16s20s24c28',
        start=9333224,
        end=9336328,
        disasm='disasm_worldtileloader_loadplantatposition_type_maxagegene_grow.txt',
        base_add=9333240,
        base_literal=9336324,
        boundary='ARM.exidx end 0x008e7608 (listing bound); next ObjC IMP 0x008e7608 DynamicWorld -[workbenchPlacedAtPosition:ofType:saveDict:placedByClient:clientName:]',
        selectors={
                 0x8e7588: (15215804, 'alloc'),
                 0x8e759c: (15216824, 'initWithWorld:dynamicWorld:atPosition:cache:maxAgeGene:growthRateGene:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultPlant:'),
                 0x8e75ec: (15216020, 'sendNetDataIfNeededForObject:isCreation:'),
                 0x8e75f4: (15216168, 'objectType'),
                 0x8e75fc: (15216160, 'uniqueID'),
        },
        imports={
                 0x8e75e8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8e758c: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8e7590: (17162232, 'OBJC_IVAR_$_DynamicWorld.cache', 7336),
                 0x8e7594: (17162228, 'OBJC_IVAR_$_DynamicWorld.treeDensityNoiseFunction', 7340),
                 0x8e7598: (17162224, 'OBJC_IVAR_$_DynamicWorld.seasonOffsetNoiseFunction', 7344),
                 0x8e75f8: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
                 0x8e7600: (17162312, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsByWorldPosIndex', 1620),
        },
        classes={
                 0x8e7580: (15247968, 'OBJC_CLASS_$_VinePlant'),
                 0x8e75a0: (15247964, 'OBJC_CLASS_$_KelpPlant'),
                 0x8e75a8: (15247960, 'OBJC_CLASS_$_ChilliPlant'),
                 0x8e75b0: (15247956, 'OBJC_CLASS_$_TomatoPlant'),
                 0x8e75b8: (15247952, 'OBJC_CLASS_$_WheatPlant'),
                 0x8e75c0: (15247948, 'OBJC_CLASS_$_CornPlant'),
                 0x8e75c8: (15247944, 'OBJC_CLASS_$_TulipPlant'),
                 0x8e75d0: (15247940, 'OBJC_CLASS_$_CarrotPlant'),
                 0x8e75d8: (15247936, 'OBJC_CLASS_$_SunflowerPlant'),
                 0x8e75e0: (15247932, 'OBJC_CLASS_$_FlaxPlant'),
        },
        instructions=[(9333224, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9333312, 'bne 0x8e6b30'), (9333552, 'ldr r0, [fp, -0x34]'), (9336016, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9336104, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9336324, 'ldrshteq sb, [r7], -4')],
        calls=[(9333348, 'bl loc.imp.objc_msgSend'), (9333540, 'bl loc.imp.objc_msgSend'), (9333596, 'bl loc.imp.objc_msgSend'), (9333788, 'bl loc.imp.objc_msgSend'), (9333844, 'bl loc.imp.objc_msgSend'), (9334036, 'bl loc.imp.objc_msgSend'), (9334092, 'bl loc.imp.objc_msgSend'), (9334284, 'bl loc.imp.objc_msgSend'), (9334340, 'bl loc.imp.objc_msgSend'), (9334532, 'bl loc.imp.objc_msgSend'), (9334588, 'bl loc.imp.objc_msgSend'), (9334780, 'bl loc.imp.objc_msgSend'), (9334836, 'bl loc.imp.objc_msgSend'), (9335028, 'bl loc.imp.objc_msgSend'), (9335084, 'bl loc.imp.objc_msgSend'), (9335276, 'bl loc.imp.objc_msgSend'), (9335332, 'bl loc.imp.objc_msgSend'), (9335524, 'bl loc.imp.objc_msgSend'), (9335580, 'bl loc.imp.objc_msgSend'), (9335772, 'bl loc.imp.objc_msgSend'), (9335900, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9335936, 'bl loc.imp.objc_msgSend'), (9335996, 'bl loc.imp.objc_msgSend'), (9336016, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9336048, 'bl loc.imp.objc_msgSend'), (9336104, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9336180, 'blx r4')],
        branches=[(9333312, 'bne', 9333552), (9333548, 'b', 9335816), (9333560, 'bne', 9333800), (9333796, 'b', 9335812), (9333808, 'bne', 9334048), (9334044, 'b', 9335808), (9334056, 'bne', 9334296), (9334292, 'b', 9335804), (9334304, 'bne', 9334544), (9334540, 'b', 9335800), (9334552, 'bne', 9334792), (9334788, 'b', 9335796), (9334800, 'bne', 9335040), (9335036, 'b', 9335792), (9335048, 'bne', 9335288), (9335284, 'b', 9335788), (9335296, 'bne', 9335536), (9335532, 'b', 9335784), (9335544, 'bne', 9335780), (9335780, 'b', 9335784), (9335784, 'b', 9335788), (9335788, 'b', 9335792), (9335792, 'b', 9335796), (9335796, 'b', 9335800), (9335800, 'b', 9335804), (9335804, 'b', 9335808), (9335808, 'b', 9335812), (9335812, 'b', 9335816), (9335828, 'beq', 9336184)],
        semantics=('loadPlantAtPosition:type:maxAgeGene:growthRateGene:adult: instantiates one plant by type switch. Prologue 0x008e69e8 (frame 0x158). Arguments: position pair, type [fp,-0x34], maxAgeGene short [fp,-0x36], growthRateGene short [fp,-0x38], adult byte [fp,-0x39].\n**Type switch (10 arms)**: type 1 -> FlaxPlant (cell 0x008e75e0), 2 -> SunflowerPlant (0x008e75d8), 3 -> CornPlant (0x008e75c0), 4 -> CarrotPlant (0x008e75d0), 5 -> ChilliPlant (0x008e75a8), 6 -> KelpPlant (0x008e75a0), 7 -> VinePlant (0x008e7580), 8 -> TulipPlant (0x008e75c8), 9 -> WheatPlant (0x008e75b8), 0xa -> TomatoPlant (0x008e75b0); non-matching types fall through to the shared tail with the object still NULL. Every arm is the same shape: `[[Class alloc] initWithWorld:... dynamicWorld:self atPosition:pos cache:cache maxAgeGene:maxAgeGene growthRateGene:growthRateGene treeDensityNoiseFunction:... seasonOffsetNoiseFunction:... adultPlant:adult]` (selector cell 0x008e759c) with the two uxth-ed gene shorts and the sxtb adult byte stacked.\nShared tail (0x008e7400-0x008e757c): when the object is non-NULL: `[obj objectType]` -> map operator[] on the type-strided slice of dynamicObjectsToAdd -> `*map = obj`; `[obj uniqueID]` -> map operator[] on the world-index slice of dynamicObjectsByWorldPosIndex (cell 0x008e7600) -> `*map = obj`; `[obj sendNetDataIfNeededForObject:obj isCreation:1]` (cell 0x008e75ec).\n'),
    ),
    dict(
        name='wtl_loadnpcatposition_type',
        method='DynamicWorld -[loadNPCAtPosition:type:saveDict:isAdult:wasPlaced:placedByClient:]',
        types='c36@0:4{?=ii}8i16@20c24c28@32',
        start=9332436,
        end=9333224,
        disasm='disasm_worldtileloader_loadnpcatposition_type_savedict_isadult_.txt',
        base_add=9332452,
        base_literal=9333220,
        boundary='ARM.exidx end 0x008e69e8 (listing bound); next ObjC IMP 0x008e69e8 DynamicWorld -[loadPlantAtPosition:type:maxAgeGene:growthRateGene:adult:]',
        selectors={
                 0x8e69b0: (15216812, 'loadedCountOfObjectsOfType:'),
                 0x8e69b4: (15216816, 'tooManyNPCsToSpawnMoreNearPos:'),
                 0x8e69bc: (15215804, 'alloc'),
                 0x8e69cc: (15216820, 'initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:'),
                 0x8e69d0: (15216020, 'sendNetDataIfNeededForObject:isCreation:'),
                 0x8e69d4: (15216168, 'objectType'),
                 0x8e69e0: (15216160, 'uniqueID'),
        },
        imports={
                 0x8e69ac: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8e69c4: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8e69c8: (17162232, 'OBJC_IVAR_$_DynamicWorld.cache', 7336),
                 0x8e69dc: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
        },
        classes={},
        instructions=[(9332436, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9332544, 'bl sym.dynamicObjectTypeForNPCType_NPCType_'), (9332604, 'cmp r0, 0x200'), (9332828, 'ldr r6, [fp, -0x40]'), (9333040, 'ldr r1, [sp, 0x2c]'), (9333220, 'rsbseq sb, r7, r8, lsl 8')],
        calls=[(9332544, 'bl sym.dynamicObjectTypeForNPCType_NPCType_'), (9332600, 'blx r3'), (9332680, 'bl loc.imp.objc_msgSend'), (9332724, 'bl sym.classForNPCType_NPCType_'), (9332752, 'bl loc.imp.objc_msgSend'), (9332900, 'bl loc.imp.objc_msgSend'), (9332964, 'bl loc.imp.objc_msgSend'), (9333024, 'bl loc.imp.objc_msgSend'), (9333044, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9333120, 'blx r4')],
        branches=[(9332524, 'bne', 9332624), (9332608, 'ble', 9332624), (9332620, 'b', 9333152), (9332632, 'bne', 9332708), (9332692, 'beq', 9332708), (9332704, 'b', 9333152), (9332920, 'beq', 9333124)],
        semantics=('loadNPCAtPosition:type:saveDict:isAdult:wasPlaced:placedByClient: instantiates one NPC. Prologue 0x008e66d4 (frame 0x98). Arguments: position pair, type [fp,8], saveDict [fp,0xc], isAdult byte [fp,0x10], wasPlaced byte [fp,0x14], placedByClient [fp,0x18].\nGates (both only when wasPlaced == 0): (1) `dynamicObjectTypeForNPCType(NPCType)` (sym 0x008e6740) then `[self loadedCountOfObjectsOfType:type]` (cell 0x008e69b0) - a count above 0x200 (512) sets the result byte to 0 and returns (the per-type loaded-object cap); (2) `[self tooManyNPCsToSpawnMoreNearPos:pos]` (cell 0x008e69b4) - nonzero sets the result byte to 0 and returns (the NPC sparsity rule).\nConstruction: `classForNPCType(NPCType)` (sym 0x008e67f4) then `[[class alloc] initWithWorld:... dynamicWorld:self atPosition:pos cache:cache saveDict:saveDict isAdult:isAdult wasPlaced:wasPlaced placedByClient:placedByClient]` (selector cell 0x008e69cc). On success: `[obj objectType]` -> `std::map<u64,DynamicObject*>::operator[](uniqueID)` on dynamicObjectsToAdd (cell 0x008e69dc, route 0x008bcf24) stores the pointer; then `[obj sendNetDataIfNeededForObject:obj isCreation:1]` (cell 0x008e69d0). Returns (obj != 0).\n'),
    ),
    dict(
        name='wtl_loadsnowsurfaceblockat',
        method='DynamicWorld -[loadSnowSurfaceBlockAtPos:loadSnow:]',
        types='v20@0:4{?=ii}8c16',
        start=9332232,
        end=9332436,
        disasm='disasm_worldtileloader_loadsnowsurfaceblockatpos_loadsnow_.txt',
        base_add=9332248,
        base_literal=9332432,
        boundary='ARM.exidx end 0x008e66d4 (listing bound); next ObjC IMP 0x008e66d4 DynamicWorld -[loadNPCAtPosition:type:saveDict:isAdult:wasPlaced:placedByClient:]',
        selectors={
                 0x8e66c0: (15216804, 'loadStandardDynamicObjectOfType:atPos:'),
                 0x8e66cc: (15216808, 'updateInTimeSinceSaved'),
        },
        imports={
                 0x8e66c8: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9332232, 'push {r4, sl, fp, lr}'), (9332292, 'str r2, [sp, 0x14]'), (9332404, 'blx r2'), (9332432, 'ldrsbteq sb, [r7], -0x44')],
        calls=[(9332344, 'bl loc.imp.objc_msgSend'), (9332404, 'blx r2')],
        branches=[(9332360, 'beq', 9332408)],
        semantics=('loadSnowSurfaceBlockAtPos:loadSnow: forwards to `[self loadStandardDynamicObjectOfType:0x1d atPos:pos]` (the snow-surface type id 29) and, when the loadSnow byte argument is nonzero, sends `[result updateInTimeSinceSaved]` (selector cell 0x008e66cc) to the created object - the snow block absorbs the offline time delta. Two selectors, one call path; the picosec form of the loader family.\n'),
    ),
    dict(
        name='wtl_loadsurfaceblockatpos_',
        method='DynamicWorld -[loadSurfaceBlockAtPos:]',
        types='v16@0:4{?=ii}8',
        start=9332116,
        end=9332232,
        disasm='disasm_worldtileloader_loadsurfaceblockatpos_.txt',
        base_add=9332176,
        base_literal=9332228,
        boundary='ARM.exidx end 0x008e6608 (listing bound); next ObjC IMP 0x008e6608 DynamicWorld -[loadSnowSurfaceBlockAtPos:loadSnow:]',
        selectors={
                 0x8e6600: (15216804, 'loadStandardDynamicObjectOfType:atPos:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(9332116, 'push {fp, lr}'), (9332208, 'bl loc.imp.objc_msgSend'), (9332228, 'rsbseq sb, r7, ip, lsl r5')],
        calls=[(9332208, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=("loadSurfaceBlockAtPos: is a one-call forwarder: `[self loadStandardDynamicObjectOfType:0x16 atPos:pos]` (selector cell 0x008e6600; the position pair is the method's only argument). Type 0x16 (22) is the surface-block type id - cf. loadDynamicObjectsOfType:'s type gate, which admits 1..0x40 minus 0 and 0x15.\n"),
    ),
    dict(
        name='wtl_loadglowblockifneededa',
        method='DynamicWorld -[loadGlowBlockIfNeededAtPos:tile:]',
        types='v20@0:4{?=ii}8^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}16',
        start=9392008,
        end=9393456,
        disasm='disasm_worldtileloader_loadglowblockifneededatpos_tile_.txt',
        base_add=9392024,
        base_literal=9393452,
        boundary='ARM.exidx end 0x008f5530 (listing bound); next ObjC IMP 0x008f5530 DynamicWorld -[loadGatherBlockAtPos:]',
        selectors={
                 0x8f54ec: (15216036, 'macroTiles'),
                 0x8f5510: (15215804, 'alloc'),
                 0x8f5518: (15217072, 'initWithWorld:dynamicWorld:atPosition:cache:tile:'),
                 0x8f551c: (15216168, 'objectType'),
                 0x8f5528: (15216160, 'uniqueID'),
        },
        imports={
                 0x8f54e8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8f54f0: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8f54f4: (17162312, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsByWorldPosIndex', 1620),
                 0x8f54fc: (17162432, 'OBJC_IVAR_$_DynamicWorld.currentlyAddingGlowBlocks', 2412),
                 0x8f5504: (17162388, 'OBJC_IVAR_$_DynamicWorld.currentlyLoadingMacroBlocks', 3732),
                 0x8f5514: (17162232, 'OBJC_IVAR_$_DynamicWorld.cache', 7336),
                 0x8f5524: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
        },
        classes={
                 0x8f550c: (15248016, 'OBJC_CLASS_$_GlowBlock'),
        },
        instructions=[(9392008, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9392088, 'bl sym.worldIndexAtWorldPosition_int__int__World_'), (9392252, 'cmp r0, r1'), (9392344, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9392840, 'bl method.std::__1::pair_std::__1::__hash_iterator_std::__1::__hash_node_unsigned_long_long__void____bool__std::__1::__hash_table_unsigned_long_long__std::__1::hash_unsigned_long_long___std::__1::equal_to_unsigned_long_long___std::__1::allocator_unsigned_long_long___.__insert_unique_unsigned_long_long__unsigned_long_long_'), (9393268, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9393452, 'rsbseq sl, r6, r4, asr fp')],
        calls=[(9392088, 'bl sym.worldIndexAtWorldPosition_int__int__World_'), (9392128, 'bl sym.macroIndexAtWorldIndex_int__World_'), (9392216, 'blx r3'), (9392344, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9392440, 'bl method.std::__1::__hash_const_iterator_std::__1::__hash_node_unsigned_long_long__void__const__std::__1::__hash_table_unsigned_long_long__std::__1::hash_unsigned_long_long___std::__1::equal_to_unsigned_long_long___std::__1::allocator_unsigned_long_long___.find_unsigned_long_long__unsigned_long_long_const__const'), (9392624, 'bl method.std::__1::__hash_const_iterator_std::__1::__hash_node_unsigned_int__void__const__std::__1::__hash_table_unsigned_int__std::__1::hash_unsigned_int___std::__1::equal_to_unsigned_int___std::__1::allocator_unsigned_int___.find_unsigned_int__unsigned_int_const__const'), (9392840, 'bl method.std::__1::pair_std::__1::__hash_iterator_std::__1::__hash_node_unsigned_long_long__void____bool__std::__1::__hash_table_unsigned_long_long__std::__1::hash_unsigned_long_long___std::__1::equal_to_unsigned_long_long___std::__1::allocator_unsigned_long_long___.__insert_unique_unsigned_long_long__unsigned_long_long_'), (9392944, 'bl loc.imp.objc_msgSend'), (9393060, 'bl loc.imp.objc_msgSend'), (9393120, 'bl method.unsigned_long_std::__1::__hash_table_unsigned_long_long__std::__1::hash_unsigned_long_long___std::__1::equal_to_unsigned_long_long___std::__1::allocator_unsigned_long_long___.__erase_unique_unsigned_long_long__unsigned_long_long_const_'), (9393188, 'bl loc.imp.objc_msgSend'), (9393248, 'bl loc.imp.objc_msgSend'), (9393268, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9393300, 'bl loc.imp.objc_msgSend'), (9393356, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_')],
        branches=[(9392256, 'beq', 9393376), (9392272, 'beq', 9393376), (9392352, 'bne', 9393372), (9392544, 'bne', 9393372), (9392728, 'bne', 9393372), (9393140, 'beq', 9393368), (9393368, 'b', 9393372), (9393372, 'b', 9393376)],
        semantics=('loadGlowBlockIfNeededAtPos:tile: instantiates a GlowBlock for a tile that needs light. Prologue 0x008f4f88 (frame 0x180). Arguments: position pair, tile pointer [fp,8].\nMacro-tile gate: `worldIndexAtWorldPosition(x, y, world)` (route 0x00a15838) -> `macroIndexAtWorldIndex(worldIndex, world)` (route 0x00a174a4 region) -> `[[self.world macroTiles] ...]` (selector cell 0x008f54ec) - the 20-byte-stride macro record; `record[+4]` must equal the expected marker ([sp,0x54]) and `record[+2]` (a signed byte) must be nonzero, otherwise return.\nDedup gates (three): `__count_unique` on the +0xd8 slice of dynamicObjectsByWorldPosIndex (cell 0x008f54f4, route 0x00910a74); `std::__1::__hash_table<u64>::find` on currentlyAddingGlowBlocks (cell 0x008f54fc ffe5cc, route 0x00910798); `std::__1::__hash_table<u32>::find` on the +0x168 slice of currentlyLoadingMacroBlocks (cell 0x008f5504, route 0x009123a4). Any hit returns.\nInsert into currentlyAddingGlowBlocks (`__insert_unique<u64>`, route 0x0090f874); `[[GlowBlock alloc] initWithWorld:... dynamicWorld:self atPosition:pos cache:cache tile:tile]` (class cell 0x008f550c, selector cell 0x008f5518) with the tile stacked; erase from currentlyAddingGlowBlocks (`__erase_unique`, route 0x00913f9c); when the object exists: `[obj objectType]` -> operator[] on the type-strided dynamicObjectsToAdd slice, `[obj uniqueID]` key -> store; then `[obj sendNetDataIfNeededForObject:obj isCreation:1]`.\n'),
    ),
    dict(
        name='wtl_addtorchatpos_oftype_d',
        method='DynamicWorld -[addTorchAtPos:ofType:dataA:dataB:saveDict:placedByClient:]',
        types='v36@0:4{?=ii}8i16S20S24@28@32',
        start=9339680,
        end=9340596,
        disasm='disasm_worldtileloader_addtorchatpos_oftype_dataa_datab_savedic.txt',
        base_add=9339696,
        base_literal=9340592,
        boundary='ARM.exidx end 0x008e86b4 (listing bound); next ObjC IMP 0x008e86b4 DynamicWorld -[objectOfType:atPos:]',
        selectors={
                 0x8e8684: (15216544, 'needsRemoved'),
                 0x8e8694: (15215804, 'alloc'),
                 0x8e869c: (15216864, 'initWithWorld:dynamicWorld:atPosition:cache:type:dataA:dataB:saveDict:placedByClient:'),
                 0x8e86a0: (15216020, 'sendNetDataIfNeededForObject:isCreation:'),
                 0x8e86ac: (15216160, 'uniqueID'),
        },
        imports={
                 0x8e8680: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8e8674: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8e867c: (17162312, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsByWorldPosIndex', 1620),
                 0x8e8698: (17162232, 'OBJC_IVAR_$_DynamicWorld.cache', 7336),
                 0x8e86a4: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
        },
        classes={
                 0x8e868c: (15247972, 'OBJC_CLASS_$_Torch'),
        },
        instructions=[(9339680, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9339912, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9340052, 'movw r0, 0'), (9340372, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9340592, 'ldrhteq r7, [r7], -0x7c')],
        calls=[(9339844, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9339912, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9339984, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9340028, 'blx r3'), (9340096, 'bl loc.imp.objc_msgSend'), (9340260, 'bl loc.imp.objc_msgSend'), (9340352, 'bl loc.imp.objc_msgSend'), (9340372, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9340444, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9340520, 'blx r4')],
        branches=[(9339920, 'beq', 9340052), (9340040, 'bne', 9340048), (9340044, 'b', 9340524), (9340048, 'b', 9340052), (9340280, 'beq', 9340524)],
        semantics=('addTorchAtPos:ofType:dataA:dataB:saveDict:placedByClient: instantiates a Torch. Prologue 0x008e8320 (frame 0xc8). Arguments: position pair, type short [fp,-0x36], dataA short [fp,-0x38], dataB [fp,8], saveDict [fp,0xc], placedByClient [fp,0x10], plus [fp,0x14]/[fp,0x18].\nExisting-object check: `worldIndexAtWorldPos(pos, world)` (route 0x00a15838) -> `std::map<u64,DynamicObject*>::__count_unique` on the +0xcc slice of dynamicObjectsByWorldPosIndex (cell 0x008e867c, route 0x00910a74). On a hit the existing object is read via operator[] and queried with `[obj needsRemoved]` (cell 0x008e8684, route 0x008e8408): nonzero -> return immediately (the old torch is marked for removal); zero -> fall through and create.\nCreation: `[[Torch alloc] initWithWorld:... dynamicWorld:self atPosition:pos cache:cache type:type dataA:dataA dataB:dataB saveDict:saveDict placedByClient:placedByClient]` (class cell 0x008e868c, selector cell 0x008e869c) with uxth-ed shorts + sxtb byte stacked. Tail: `[obj uniqueID]` -> operator[] on the +0xcc slice of dynamicObjectsToAdd and of dynamicObjectsByWorldPosIndex -> `*map = obj` both; `[obj sendNetDataIfNeededForObject:obj isCreation:1]` (cell 0x008e86a0).\n'),
    ),
    dict(
        name='wtl_createtreasurechestort',
        method='DynamicWorld -[createTreasureChestOrTrollAtTile:atPos:loadTroll:loadTreasure:]',
        types='v28@0:4^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}8{?=ii}12c20c24',
        start=9343132,
        end=9348920,
        disasm='disasm_worldtileloader_createtreasurechestortrollattile_atpos_l.txt',
        base_add=9343148,
        base_literal=9347112,
        boundary='ARM.exidx end 0x008ea738 (listing bound); next ObjC IMP 0x008ea738 DynamicWorld -[eggAtPos:]',
        selectors={
                 0x8ea02c: (15216740, 'interactionObjectAtPos:'),
                 0x8ea244: (15216368, 'loadNPCAtPosition:type:saveDict:isAdult:wasPlaced:placedByClient:'),
                 0x8ea250: (15216060, 'instance'),
                 0x8ea254: (15216500, 'multiSoundNamed:'),
                 0x8ea25c: (15216888, 'playAtPosition:'),
                 0x8ea4f0: (15216404, 'addTorchAtPos:ofType:dataA:dataB:saveDict:placedByClient:'),
                 0x8ea6dc: (15215804, 'alloc'),
                 0x8ea6e0: (15216892, 'initWithType:dataA:dataB:subItems:dynamicObjectSaveDict:'),
                 0x8ea6e4: (15215968, 'autorelease'),
                 0x8ea6f0: (15216832, 'initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:'),
                 0x8ea6f4: (15216896, 'randomizeLocalTradeOffsets'),
                 0x8ea6fc: (15216168, 'objectType'),
                 0x8ea704: (15216160, 'uniqueID'),
                 0x8ea70c: (15216020, 'sendNetDataIfNeededForObject:isCreation:'),
                 0x8ea710: (15216860, 'worldChangedAtPos:sendReliably:'),
                 0x8ea724: (15216144, 'array'),
                 0x8ea730: (15216900, 'moveInventoryItemsFromArray:toIndex:count:'),
                 0x8ea734: (15216008, 'addObject:'),
        },
        imports={
                 0x8ea258: (16333912, '__CFConstantStringClassReference'),
                 0x8ea720: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8ea034: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8ea6d0: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8ea6ec: (17162232, 'OBJC_IVAR_$_DynamicWorld.cache', 7336),
                 0x8ea700: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
                 0x8ea708: (17162312, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsByWorldPosIndex', 1620),
        },
        classes={
                 0x8ea24c: (15247876, 'OBJC_CLASS_$_MJSoundManager'),
                 0x8ea6d4: (15247976, 'OBJC_CLASS_$_InventoryItem'),
                 0x8ea6e8: (15247980, 'OBJC_CLASS_$_TradePortal'),
                 0x8ea718: (15247984, 'OBJC_CLASS_$_Chest'),
                 0x8ea728: (15247780, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(9343132, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9343248, 'bl loc.imp.objc_msgSend'), (9343900, 'ldr r3, [0x008ea244]'), (9346168, 'movw r0, 0'), (9346876, 'vldr s0, [0x008ea26c]'), (9348564, 'sub r1, fp, 0x150'), (9348916, 'invalid')],
        calls=[(9343248, 'bl loc.imp.objc_msgSend'), (9343332, 'bl sym.imp.__modsi3'), (9343440, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9343452, 'bl sym.tileIsSolid_Tile_'), (9343516, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9343528, 'bl sym.tileIsSolid_Tile_'), (9343604, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9343616, 'bl sym.tileIsSolid_Tile_'), (9343692, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9343708, 'bl sym.tileIsAir_Tile_'), (9343808, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9343820, 'bl sym.tileIsAir_Tile_'), (9343984, 'bl loc.imp.objc_msgSend'), (9344024, 'bl loc.imp.objc_msgSend'), (9344048, 'bl loc.imp.objc_msgSend'), (9344088, 'bl method.Vector2.Vector2_float__float_'), (9344116, 'bl loc.imp.objc_msgSend'), (9344156, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9344168, 'bl sym.tileIsAir_Tile_'), (9344280, 'bl sym.makeIntpair_int__int_'), (9344344, 'bl loc.imp.objc_msgSend'), (9344416, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9344428, 'bl sym.tileIsAir_Tile_'), (9344540, 'bl sym.makeIntpair_int__int_'), (9344604, 'bl loc.imp.objc_msgSend'), (9344644, 'bl sym.imp.__modsi3'), (9344752, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9344764, 'bl sym.tileIsSolid_Tile_'), (9344828, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9344840, 'bl sym.tileIsSolid_Tile_'), (9344916, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9344928, 'bl sym.tileIsSolid_Tile_'), (9345004, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9345020, 'bl sym.tileIsAir_Tile_'), (9345120, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9345132, 'bl sym.tileIsAir_Tile_'), (9345232, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9345244, 'bl sym.tileIsAir_Tile_'), (9345340, 'bl loc.imp.objc_msgSend'), (9345384, 'bl loc.imp.objc_msgSend'), (9345400, 'bl loc.imp.objc_msgSend'), (9345428, 'bl loc.imp.objc_msgSend'), (9345496, 'bl sym.makeIntpair_int__int_'), (9345604, 'bl loc.imp.objc_msgSend'), (9345652, 'bl loc.imp.objc_msgSend'), (9345684, 'bl loc.imp.objc_msgSend'), (9345744, 'bl loc.imp.objc_msgSend'), (9345764, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9345792, 'bl sym.makeIntpair_int__int_'), (9345828, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9345856, 'bl loc.imp.objc_msgSend'), (9345912, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9345952, 'bl loc.imp.objc_msgSend'), (9346000, 'bl sym.makeIntpair_int__int_'), (9346048, 'bl loc.imp.objc_msgSend'), (9346080, 'bl sym.makeIntpair_int__int_'), (9346120, 'bl loc.imp.objc_msgSend'), (9346228, 'bl loc.imp.objc_msgSend'), (9346272, 'bl loc.imp.objc_msgSend'), (9346288, 'bl loc.imp.objc_msgSend'), (9346316, 'bl loc.imp.objc_msgSend'), (9346452, 'bl loc.imp.objc_msgSend'), (9346536, 'blx r3'), (9346552, 'bl 0x8ad2a4'), (9346576, 'bl 0x8ad2a4'), (9346608, 'bl 0x8ad2a4'), (9346796, 'bl 0x8ad2a4'), (9346960, 'bl 0x8ad2a4'), (9347160, 'bl 0x8ad2a4'), (9347184, 'bl 0x8ad2a4'), (9347284, 'bl sym.clamp_float__float__float_'), (9347444, 'blx ip'), (9347496, 'blx r4'), (9347512, 'blx r2'), (9347552, 'blx r3'), (9347640, 'blx ip'), (9347712, 'bl 0x8ad2a4'), (9347756, 'bl 0x8ad2a4'), (9347780, 'bl 0x8ad2a4'), (9347812, 'bl 0x8ad2a4'), (9347924, 'bl sym.clamp_float__float__float_'), (9347956, 'bl 0x8ad2a4'), (9348208, 'blx ip'), (9348260, 'blx r4'), (9348276, 'blx r2'), (9348316, 'blx r3'), (9348408, 'blx ip'), (9348492, 'bl loc.imp.objc_msgSend'), (9348552, 'bl loc.imp.objc_msgSend'), (9348572, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9348632, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9348660, 'bl loc.imp.objc_msgSend'), (9348716, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9348792, 'blx r4')],
        branches=[(9343268, 'beq', 9343276), (9343272, 'b', 9348800), (9343292, 'beq', 9346156), (9343304, 'bge', 9346156), (9343340, 'ble', 9343360), (9343356, 'b', 9343372), (9343464, 'beq', 9346152), (9343540, 'beq', 9343704), (9343628, 'beq', 9343700), (9343700, 'b', 9343704), (9343720, 'beq', 9346148), (9343736, 'bne', 9346148), (9343752, 'bne', 9346148), (9343832, 'beq', 9346144), (9343848, 'bne', 9346144), (9343864, 'bne', 9346144), (9344180, 'beq', 9344360), (9344196, 'bne', 9344360), (9344212, 'bne', 9344360), (9344228, 'bne', 9344360), (9344440, 'beq', 9344620), (9344456, 'bne', 9344620), (9344472, 'bne', 9344620), (9344488, 'bne', 9344620), (9344652, 'ble', 9344672), (9344668, 'b', 9344684), (9344776, 'beq', 9346140), (9344852, 'beq', 9345016), (9344940, 'beq', 9345012), (9345012, 'b', 9345016), (9345032, 'beq', 9346136), (9345048, 'bne', 9346136), (9345064, 'bne', 9346136), (9345144, 'beq', 9346132), (9345160, 'bne', 9346132), (9345176, 'bne', 9346132), (9345256, 'beq', 9346128), (9345272, 'bne', 9346128), (9345288, 'bne', 9346128), (9345624, 'beq', 9346124), (9346124, 'b', 9346128), (9346128, 'b', 9346132), (9346132, 'b', 9346136), (9346136, 'b', 9346140), (9346140, 'b', 9346144), (9346144, 'b', 9346148), (9346148, 'b', 9346152), (9346152, 'b', 9346156), (9346164, 'beq', 9348800), (9346472, 'beq', 9348796), (9346696, 'bpl', 9346712), (9346708, 'b', 9346728), (9346792, 'bge', 9348448), (9346828, 'beq', 9346856), (9346872, 'ble', 9347704), (9346900, 'ble', 9347160), (9346928, 'ble', 9347156), (9346956, 'ble', 9347152), (9347000, 'ble', 9347016), (9347012, 'b', 9347148), (9347032, 'ble', 9347048), (9347044, 'b', 9347144), (9347064, 'ble', 9347080), (9347076, 'b', 9347140), (9347096, 'ble', 9347128), (9347108, 'b', 9347136), (9347136, 'b', 9347140), (9347140, 'b', 9347144), (9347144, 'b', 9347148), (9347148, 'b', 9347152), (9347152, 'b', 9347156), (9347156, 'b', 9347160), (9347328, 'bge', 9347576), (9347568, 'b', 9347316), (9347648, 'b', 9348416), (9347744, 'ble', 9347756), (9347952, 'bne', 9348068), (9347996, 'ble', 9348064), (9348064, 'b', 9348068), (9348092, 'bge', 9348344), (9348332, 'b', 9348080), (9348440, 'b', 9346780), (9348796, 'b', 9348800)],
        semantics=("createTreasureChestOrTrollAtTile:atPos:loadTroll:loadTreasure: is the cave treasure generator behind the marker-6 scan (E19) and the E15 stage-A treasure path. Prologue 0x008e909c (frame 0x2d8). Arguments: tile word [fp,-0x20], atPos pair [fp,-0x20]/[fp,-0x1c], loadTroll byte [fp,-0x2d], loadTreasure byte [fp,-0x2e].\nExisting-interaction gate: `[self interactionObjectAtPos:...]` (selector cell 0x008ea02c) - a non-nil interaction object jumps to the tail (0x008ea6c0, return without placing).\n**Troll arm (loadTroll != 0, atPos.y < 0x100)**: the working x is jittered: x mod 32 (`__modsi3`), `> 0x10 ? -2 : +2`. Cave geometry gates over tileAtWorldPositionLoaded: solid tiles below/right, then air tiles (tileIsAir) with byte1 == 1 and byte3 == 0 at (x', y'-1) and (x'+1, y'+1) - the cave opening. On pass: `loadNPCAtPosition:type:saveDict:isAdult:wasPlaced:placedByClient:` with stacked (6, 0, 1, 0, 0) - **NPC type 6 (the troll), isAdult 1** (cell 0x008ea244); the result byte [fp,-0x41] records success. Then `[MJSoundManager instance]` (cell 0x008ea24c) `multiSoundNamed:` (cell 0x008ea254, string 0xfff34164) `playAtPosition:` (cell 0x008ea25c) with a Vector2(float,float) built by method.Vector2.Vector2 - the troll roar - and two corner torches: `addTorchAtPos:ofType:dataA:dataB:saveDict:placedByClient:` (cell 0x008ea4f0) at (x'-1, y'+1) and (x'+1, y'+1) with stacked (0xb7, 0, 0, 0, 0) and the tile byte0xb written.\n**Treasure arm (loadTreasure != 0)**: tile byte3 = 0x30 stamped at [fp,-0x2c]; `[[InventoryItem alloc] initWithType:... dataA:0 dataB:0 subItems:0 dynamicObjectSaveDict:0]` (class cell 0x008ea6d4, selector cell 0x008ea6e0) with r2 = 0x430 (the chest-key item type) then autorelease (cell 0x008ea6e4); `[[Chest alloc] initWithWorld:... dynamicWorld:self atPosition:pos cache:cache item:item flipped:... saveDict:... placedByClient:... clientName:...]` (class cell 0x008ea718, selector cell 0x008ea6f0); NULL chest returns. `[NSMutableArray array]` (cell 0x008ea724, class 0x008ea728) collects the loot; several lrand48 rolls (route 0x008ad2a4) produce normalized floats; when the troll flag is set the roll gets a +0.3 slope against 0.7; then **the rarity ladder picks the item type id** ([fp,-0x120]): 0x149 (top), 0x41, 0x48, 0x57, 0x56, 0x4c, 0x4b, 0x58 by descending thresholds (floats at 0x008ea260-0x008ea274); a second roll derives the count (clamped against 0xf/0x10 then +1). The fill loop (0x008ea0f4-0x008ea238) creates one `[[InventoryItem alloc] initWithType:<id> dataA:... dataB:... subItems:... dynamicObjectSaveDict:...]` per count (uxth args stacked), `addObject:` (cell 0x008ea734) + autorelease (cell 0x008ea6e4); then `[chest moveInventoryItemsFromArray:lootArray toIndex:0 count:count]` (cell 0x008ea730).\n**Second variant (0x008ea278-0x008ea538)**: for rolls at or below the 0x333333 threshold the body picks type **0xa6 or 0xa7** (two chest variants: the 0xa7 branch is taken when lrand48/2^31 > 0.5 of the following roll) and repeats the fill loop + moveInventoryItemsFromArray with its own count roll.\nShared tail (0x008ea540-0x008ea6bc): `[obj objectType]` -> operator[] on the type-strided dynamicObjectsToAdd slice with `[obj uniqueID]` key -> store; `worldIndexAtWorldPos(pair, world)` -> operator[] on dynamicObjectsByWorldPosIndex -> store; `[obj sendNetDataIfNeededForObject:obj isCreation:1]` (cell 0x008ea70c); epilogue 0x008ea6c0.\n"),
    ),
    dict(
        name='wtl_loadnewblockheadatpos_',
        method='DynamicWorld -[loadNewBlockheadAtPos:craftableItemObject:uniqueID:]',
        types='v28@0:4{?=ii}8@16Q20',
        start=9395056,
        end=9397440,
        disasm='disasm_worldtileloader_loadnewblockheadatpos_craftableitemobjec.txt',
        base_add=9395072,
        base_literal=9397436,
        boundary='ARM.exidx end 0x008f64c0 (listing bound); next ObjC IMP 0x008f64c0 DynamicWorld -[isClient]',
        selectors={
                 0x8f6434: (15215864, 'count'),
                 0x8f6444: (15215804, 'alloc'),
                 0x8f6450: (15217088, 'initWithWorld:dynamicWorld:atPosition:cache:blockheadNumber:craftableItemObject:uniqueID:'),
                 0x8f6454: (15215968, 'autorelease'),
                 0x8f6458: (15216008, 'addObject:'),
                 0x8f645c: (15216016, 'fullyLoadIfNeededAroundPos:clientLightBlockIndex:forBlockhead:'),
                 0x8f6464: (15216660, 'worldChanged:'),
                 0x8f6470: (15216636, 'uiManager'),
                 0x8f6474: (15217092, 'blockheadCountChanged'),
                 0x8f6484: (15216060, 'instance'),
                 0x8f6488: (15216500, 'multiSoundNamed:'),
                 0x8f6494: (15217080, 'play'),
                 0x8f649c: (15216020, 'sendNetDataIfNeededForObject:isCreation:'),
                 0x8f64b4: (15217084, 'addParticleAtPos:velocity:color:gravityType:life:scale:center:'),
        },
        imports={
                 0x8f6430: (17151904, 'objc_msgSend'),
                 0x8f6490: (16333944, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x8f6438: (17162220, 'OBJC_IVAR_$_DynamicWorld.blockheads', 44),
                 0x8f6448: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8f644c: (17162232, 'OBJC_IVAR_$_DynamicWorld.cache', 7336),
                 0x8f6460: (17162320, 'OBJC_IVAR_$_DynamicWorld.activeBlockheadIndex', 7360),
        },
        classes={
                 0x8f643c: (15247828, 'OBJC_CLASS_$_Blockhead'),
                 0x8f647c: (15247876, 'OBJC_CLASS_$_MJSoundManager'),
                 0x8f64a8: (15248020, 'OBJC_CLASS_$_ParticleEmitter'),
        },
        instructions=[(9395056, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9395324, 'ldr ip, [0x008f6450]'), (9395588, 'cmp r0, 1'), (9396024, 'bl method.void_std::__1::vector_intpair__std::__1::allocator_intpair___.__push_back_slow_path_intpair_const__intpair_const_'), (9397436, 'rsbseq sb, r6, ip, ror 30')],
        calls=[(9395188, 'bl loc.imp.objc_msgSend'), (9395308, 'bl loc.imp.objc_msgSend'), (9395396, 'bl loc.imp.objc_msgSend'), (9395412, 'bl loc.imp.objc_msgSend'), (9395464, 'bl loc.imp.objc_msgSend'), (9395548, 'bl loc.imp.objc_msgSend'), (9395584, 'blx r3'), (9396024, 'bl method.void_std::__1::vector_intpair__std::__1::allocator_intpair___.__push_back_slow_path_intpair_const__intpair_const_'), (9396064, 'bl loc.imp.objc_msgSend'), (9396108, 'bl loc.imp.objc_msgSend'), (9396140, 'bl loc.imp.objc_msgSend'), (9396172, 'bl loc.imp.objc_msgSend'), (9396224, 'bl loc.imp.objc_msgSend'), (9396256, 'bl loc.imp.objc_msgSend'), (9396292, 'bl loc.imp.objc_msgSend'), (9396340, 'bl method.Vector.Vector_float__float__float_'), (9396372, 'bl 0x8ad2a4'), (9396480, 'bl method.Vector.Vector_float__float__float__float_'), (9396512, 'bl loc.imp.objc_msgSend'), (9396524, 'bl 0x8ad2a4'), (9396568, 'bl 0x8ad2a4'), (9396624, 'bl method.Vector.Vector_float__float__float_'), (9396668, 'bl method.Vector.operator_Vector_'), (9396676, 'bl 0x8ad2a4'), (9396728, 'bl 0x8ad2a4'), (9396796, 'bl method.Vector.Vector_float__float__float_'), (9396836, 'bl 0x8ad2a4'), (9396888, 'bl 0x8ad2a4'), (9397192, 'bl loc.imp.objc_msgSend'), (9397236, 'bl method.std::__1::vector_intpair__std::__1::allocator_intpair___._vector__'), (9397252, 'bl method.std::__1::vector_intpair__std::__1::allocator_intpair___._vector__'), (9397272, 'bl sym.imp._Unwind_Resume')],
        branches=[(9395592, 'bne', 9395628), (9395804, 'beq', 9396016), (9395952, 'beq', 9395996), (9396012, 'b', 9396036), (9396028, 'b', 9396032), (9396032, 'b', 9396036), (9396036, 'b', 9396040), (9396068, 'b', 9396072), (9396116, 'b', 9396120), (9396144, 'b', 9396148), (9396180, 'b', 9396184), (9396232, 'b', 9396236), (9396260, 'b', 9396264), (9396296, 'b', 9396300), (9396344, 'b', 9396348), (9396368, 'bge', 9397248), (9396380, 'b', 9396384), (9396484, 'b', 9396488), (9396520, 'b', 9396524), (9396532, 'b', 9396536), (9396576, 'b', 9396580), (9396628, 'b', 9396632), (9396672, 'b', 9396676), (9396684, 'b', 9396688), (9396736, 'b', 9396740), (9396800, 'b', 9396804), (9396844, 'b', 9396848), (9396896, 'b', 9396900), (9397196, 'b', 9397200), (9397200, 'b', 9397204), (9397216, 'b', 9396360), (9397244, 'b', 9397268)],
        semantics=('loadNewBlockheadAtPos:craftableItemObject:uniqueID: instantiates one Blockhead (the player entity). Prologue 0x008f5b70 (frame 0x240). Arguments: position pair, blockheadNumber [fp,8], craftableItemObject [fp,0xc], uniqueID [fp,0x10]/[fp,0x14].\nConstruction: `[[Blockhead alloc] initWithWorld:... dynamicWorld:self atPosition:pos cache:cache blockheadNumber:number craftableItemObject:item uniqueID:id]` (class cell 0x008f643c, selector cell 0x008f6450) with the argument stack; `[bh autorelease]` (cell 0x008f6454); `[self.blockheads addObject:bh]` (cell 0x008f6458, ivar cell 0x008f6438); `[bh fullyLoadIfNeededAroundPos:pos clientLightBlockIndex:-1 forBlockhead:bh]` (cell 0x008f645c; -1 via mvn).\nFirst-blockhead activation: when `[self.blockheads count] == 1` (cell 0x008f6434) the body clears the activeBlockheadIndex slot (ivar cell 0x008f6460) - the first loaded blockhead becomes the active one.\nChange broadcast: a `std::vector<intpair>` of the affected positions is built with the libc++ push_back slow path (route `std::__1::vector<intpair>::__push_back_slow_path`, 0x008f5f38) and handed to `[self worldChanged:...]` (selector cell 0x008f6464); `[[self uiManager] blockheadCountChanged]` (cells 0x008f646c/0x008f6470); `[MJSoundManager instance]` (cell 0x008f647c) `multiSoundNamed:` (0x008f6484) `play` (0x008f6494); a ParticleEmitter spawn at the position via `addParticleAtPos:velocity:color:gravityType:life:scale:center:` (cell 0x008f64b4, class 0x008f64a8); and the net send `[bh sendNetDataIfNeededForObject:bh isCreation:1]` (cell 0x008f649c). The selector set accounts for every call row; the particle parameter values and the exact broadcast order are read at the call sites.\n'),
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
        'batch': 'DynamicWorld load-chain leaf batch (E20): the ten constructor workers behind E19 - loadTreeAtPosition: (11 tree classes), loadPlantAtPosition: (10 plant classes), loadNPCAtPosition:, loadSurfaceBlockAtPos:, loadSnowSurfaceBlockAtPos:loadSnow:, loadGlowBlockIfNeededAtPos:, addTorchAtPos:, createTreasureChestOrTrollAtTile:, loadNewBlockheadAtPos: and conversionThread:; 10 bodies',
        'claim': ('a static bounded-body map with per-instruction anchors; the item/marker/tile id names, '
                  'the C++ container member layouts behind the slice offsets and the gameplay thresholds of the '
                  'count gates are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'dyn_leaf.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale dyn_leaf.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
