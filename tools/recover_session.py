#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld client-request/session cluster (E28).

The DynamicWorld client-request and session cluster: the master constructor
with its 512-entry noise table, the harmable-object tap resolver, the client
blockhead lookup, the light-channel queue filler, the client pickup request and
the chest inventory sender:
1 body, 3047 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/CLIENT_SESSION.md for the prose and boundaries.
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
    'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__': 0x005dc5d8,
    'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_': 0x008bcb78,
    'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const': 0x00910a74,
    'bl sym.imp.NSSearchPathForDirectoriesInDomains': 0x001c3f20,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__aeabi_memmove': 0x001c3f08,
    'bl sym.imp.__stack_chk_fail': 0x001c28b8,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_': 0x00a16ccc,
    'bl sym.objectTypeIsInteractionObject_int_': 0x008bcacc,
}

SPECS = [
    dict(
        name='wtl_initwithworld_worldtil',
        method='DynamicWorld -[initWithWorld:worldTileLoader:clientTileLoader:server:client:serverClients:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:appDatabase:worldDatabase:dynamicObjectDatabase:]',
        types='@56@0:4@8@12@16@20@24@28@32@36@40@44@48@52',
        start=9095300,
        end=9097892,
        disasm='disasm_worldtileloader_initwithworld_worldtileloader_clienttile.txt',
        base_add=9095316,
        base_literal=9097888,
        boundary='ARM.exidx end 0x008ad2a4 (listing bound); next ObjC IMP 0x008ad2b4 DynamicWorld -[setServer:serverClients:]',
        selectors={
                 0x8ad1fc: (15215800, 'init'),
                 0x8ad208: (15215828, 'fileExistsAtPath:'),
                 0x8ad210: (15215824, 'defaultManager'),
                 0x8ad218: (15215820, 'retain'),
                 0x8ad220: (15215816, 'stringWithFormat:'),
                 0x8ad224: (15215812, 'saveID'),
                 0x8ad22c: (15215808, 'objectAtIndex:'),
                 0x8ad238: (15215804, 'alloc'),
                 0x8ad284: (15215832, 'createDirectoryAtPath:withIntermediateDirectories:attributes:error:'),
                 0x8ad290: (15215836, 'initWithWorld:'),
        },
        imports={
                 0x8ad1f8: (17151900, 'objc_msgSendSuper2'),
                 0x8ad204: (17151904, 'objc_msgSend'),
                 0x8ad21c: (16332808, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x8ad20c: (17162196, 'OBJC_IVAR_$_DynamicWorld.worldSaveDirectory', 40),
                 0x8ad228: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8ad234: (17162204, 'OBJC_IVAR_$_DynamicWorld.portalPositions', 7332),
                 0x8ad240: (17162208, 'OBJC_IVAR_$_DynamicWorld.clientBlockheadInventoriesToSave', 56),
                 0x8ad248: (17162212, 'OBJC_IVAR_$_DynamicWorld.netBlockheadsWithDisconnectedClients', 52),
                 0x8ad250: (17162216, 'OBJC_IVAR_$_DynamicWorld.netBlockheads', 48),
                 0x8ad254: (17162220, 'OBJC_IVAR_$_DynamicWorld.blockheads', 44),
                 0x8ad258: (17162224, 'OBJC_IVAR_$_DynamicWorld.seasonOffsetNoiseFunction', 7344),
                 0x8ad25c: (17162228, 'OBJC_IVAR_$_DynamicWorld.treeDensityNoiseFunction', 7340),
                 0x8ad260: (17162232, 'OBJC_IVAR_$_DynamicWorld.cache', 7336),
                 0x8ad264: (17162236, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectDatabase', 36),
                 0x8ad268: (17162240, 'OBJC_IVAR_$_DynamicWorld.worldDatabase', 32),
                 0x8ad26c: (17162244, 'OBJC_IVAR_$_DynamicWorld.appDatabase', 28),
                 0x8ad270: (17162248, 'OBJC_IVAR_$_DynamicWorld.serverClients', 24),
                 0x8ad274: (17162252, 'OBJC_IVAR_$_DynamicWorld.client', 20),
                 0x8ad278: (17162256, 'OBJC_IVAR_$_DynamicWorld.server', 16),
                 0x8ad27c: (17162260, 'OBJC_IVAR_$_DynamicWorld.clientTileLoader', 12),
                 0x8ad280: (17162264, 'OBJC_IVAR_$_DynamicWorld.worldTileLoader', 8),
                 0x8ad288: (17162268, 'OBJC_IVAR_$_DynamicWorld.clientFreeblockArrayToSend', 8412),
                 0x8ad28c: (17162272, 'OBJC_IVAR_$_DynamicWorld.wirePathCreator', 9496),
                 0x8ad298: (17162276, 'OBJC_IVAR_$_DynamicWorld.randomNumbers', 8416),
        },
        classes={
                 0x8ad200: (15252912, 'OBJC_CLASS_$_DynamicWorld'),
                 0x8ad214: (15247796, 'OBJC_CLASS_$_NSFileManager'),
                 0x8ad230: (15247792, 'OBJC_CLASS_$_NSString'),
                 0x8ad23c: (15247788, 'OBJC_CLASS_$_NSMutableIndexSet'),
                 0x8ad244: (15247784, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x8ad24c: (15247780, 'OBJC_CLASS_$_NSMutableArray'),
                 0x8ad294: (15247800, 'OBJC_CLASS_$_WirePathCreator'),
        },
        instructions=[(9095300, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9095392, 'ldr r0, [0x008ad1f8]'), (9095584, 'movw r0, 0xe'), (9095968, 'str r1, [r0]'), (9096720, 'bl sym.imp.NSSearchPathForDirectoriesInDomains'), (9097480, 'cmp r0, 0x200'), (9097536, 'strh r0, [r1]'), (9097888, 'rsbseq r3, fp, r8, asr r2')],
        calls=[(9095540, 'blx r5'), (9096376, 'blx r4'), (9096392, 'blx r2'), (9096444, 'blx ip'), (9096460, 'blx r2'), (9096512, 'blx ip'), (9096528, 'blx r2'), (9096580, 'blx ip'), (9096596, 'blx r2'), (9096648, 'blx ip'), (9096664, 'blx r2'), (9096720, 'bl sym.imp.NSSearchPathForDirectoriesInDomains'), (9096948, 'blx r3'), (9096996, 'blx ip'), (9097040, 'blx lr'), (9097056, 'blx r2'), (9097108, 'blx ip'), (9097144, 'blx r3'), (9097252, 'blx r2'), (9097308, 'blx lr'), (9097424, 'blx r2'), (9097440, 'blx r2'), (9097496, 'bl 0x8ad2a4'), (9097640, 'blx r2'), (9097676, 'blx r3')],
        branches=[(9095568, 'bne', 9095584), (9095580, 'b', 9097708), (9097156, 'bne', 9097316), (9097352, 'beq', 9097464), (9097484, 'bge', 9097556), (9097552, 'b', 9097476)],
        semantics=("initWithWorld:worldTileLoader:clientTileLoader:server:client:serverClients:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:appDatabase:worldDatabase:dynamicObjectDatabase: is the master constructor. Prologue 0x008ac884 (frame 0x1b0; base 0x105faf4). Eleven arguments stored to the frame first (fp-0x88..fp+0x2c region).\nStorage wiring: the arg guards (@0x8ac948-0x8ac99c) then the alloc/init (movw r0, 0xe = the initial count @0x8ac9a0) and the **ivar cascade**: the same result is written down the ffffe4e8 -> ffffe4ec -> ffffe4f0 -> ffffe4f4 -> ffffe4f8 -> ffffe4fc -> ffffe500 -> ffffe504 -> ffffe508 -> ffffe50c -> ffffe510 -> ffffe514 -> ffffe518 -> ffffe51c -> ffffe520 -> ffffe524 -> ffffe4e4 chain (`ldr r0,[cell]; add r0, r1+r0; str r1,[r0]` x17, cells 0x8ad234-0x8ad228 @0x8acb18-0x8acc9c) - the collection/map/database ivar graph.\nDirectory wiring: `NSSearchPathForDirectoriesInDomains` (@0x8ace10) + the NSFileManager path chain (cells ffe231e0/ffe231dc/ffe2aec0/ffffe4e0/ffe231d8/ffe231d4/ffe231d0, key 0xfff33d14) builds the world save directory (@0x8ace14-0x8acf94).\nPost steps: the fffe518-client branch (0x8ad064-0x8ad0f4) wires the client-side collection; then `for i in 0..0x200 (512)` (@0x8ad108-0x8ad150) fills the **uint16 array at ffffe530** (cell 0x8ad298, 2-byte stride `strh`) with `bl 0x8ad2a4` (the random helper) values - the 512-entry noise/jitter table created at construction (the random helper's seeding is outside this body). The ffffe52c/528/530 tail allocates the remaining tables (@0x8ad154+).\n"),
    ),
    dict(
        name='wtl_checkforharmabledynami',
        method='DynamicWorld -[checkForHarmableDynamicObjectUnderTap:ignoreLocalBlockheads:ignoreAllBlockheads:]',
        types='@24@0:4{Vector2=[2f]}8c16c20',
        start=9378508,
        end=9380852,
        disasm='disasm_worldtileloader_checkforharmabledynamicobjectundertap_ig.txt',
        base_add=9378524,
        base_literal=9380848,
        boundary='ARM.exidx end 0x008f23f4 (listing bound); next ObjC IMP 0x008f23f4 DynamicWorld -[npcWithID:]',
        selectors={
                 0x8f239c: (15216144, 'array'),
                 0x8f23a4: (15215864, 'count'),
                 0x8f23a8: (15217056, 'allBlockheadsIncludingNet'),
                 0x8f23ac: (15217052, 'arrayByAddingObjectsFromArray:'),
                 0x8f23b8: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8f23bc: (15216984, 'tapIsWithinBodyRadius:'),
                 0x8f23c4: (15217040, 'currentItem'),
                 0x8f23c8: (15217036, 'activeBlockhead'),
                 0x8f23cc: (15217044, 'goalInteractionForNPCChaseForNPC:withItemType:'),
                 0x8f23d0: (15216452, 'itemType'),
                 0x8f23d4: (15217048, 'canBeFedByBlockhead:'),
                 0x8f23d8: (15217032, 'lastObject'),
                 0x8f23ec: (15216008, 'addObject:'),
        },
        imports={
                 0x8f2398: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8f23b0: (17162212, 'OBJC_IVAR_$_DynamicWorld.netBlockheadsWithDisconnectedClients', 52),
                 0x8f23b4: (17162216, 'OBJC_IVAR_$_DynamicWorld.netBlockheads', 48),
                 0x8f23e4: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
        },
        classes={
                 0x8f23a0: (15247780, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(9378508, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9378624, 'cmp r0, 8'), (9378656, 'ldr r1, [r2, r1, lsl 2]'), (9378992, 'ldr r1, [0x008f23bc]'), (9379292, 'mov r0, r3'), (9379360, 'ldr r8, [0x008f23c4]'), (9380848, 'rsbseq lr, r6, r0, lsl r0')],
        calls=[(9378604, 'blx r6'), (9379016, 'bl loc.imp.objc_msgSend'), (9379080, 'blx r3'), (9379120, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9379196, 'blx r2'), (9379248, 'blx r2'), (9379300, 'blx r2'), (9379436, 'blx r2'), (9379476, 'blx r3'), (9379500, 'bl sym.imp.memset'), (9379548, 'blx lr'), (9379648, 'bl sym.imp.objc_enumerationMutation'), (9379756, 'blx ip'), (9379792, 'blx ip'), (9379860, 'blx r3'), (9380012, 'blx ip'), (9380108, 'blx r2'), (9380232, 'blx r3'), (9380284, 'blx r2'), (9380372, 'bl sym.imp.memset'), (9380420, 'blx lr'), (9380520, 'bl sym.imp.objc_enumerationMutation'), (9380580, 'bl loc.imp.objc_msgSend'), (9380708, 'blx ip')],
        branches=[(9378628, 'bge', 9379156), (9378936, 'beq', 9379136), (9379028, 'beq', 9379084), (9379084, 'b', 9379088), (9379132, 'b', 9378852), (9379136, 'b', 9379140), (9379152, 'b', 9378620), (9379204, 'bls', 9380120), (9379256, 'bne', 9379312), (9379308, 'b', 9380748), (9379560, 'beq', 9380036), (9379640, 'beq', 9379652), (9379808, 'bne', 9379888), (9379872, 'beq', 9379888), (9379884, 'b', 9380748), (9379896, 'bne', 9379908), (9379908, 'b', 9379912), (9379912, 'b', 9379916), (9379940, 'blo', 9379604), (9380032, 'bne', 9379604), (9380036, 'b', 9380040), (9380052, 'beq', 9380068), (9380064, 'b', 9380748), (9380116, 'b', 9380748), (9380128, 'bne', 9380740), (9380140, 'beq', 9380244), (9380240, 'b', 9380292), (9380432, 'beq', 9380732), (9380512, 'beq', 9380524), (9380592, 'beq', 9380608), (9380604, 'b', 9380748), (9380608, 'b', 9380612), (9380636, 'blo', 9380476), (9380728, 'bne', 9380476), (9380732, 'b', 9380736), (9380736, 'b', 9380740)],
        semantics=("checkForHarmableDynamicObjectUnderTap:ignoreLocalBlockheads:ignoreAllBlockheads: resolves the harmable object under a tap. Prologue 0x008f1acc (frame 0x2a8; base 0x105faf4). Arguments: tap object (r2), ignoreLocalBlockheads [fp,-0xd1], ignoreAllBlockheads [fp,0xc] -> [fp,-0xd2].\nGate: the tap object's family count check (isKindOfClass + count chain @0x8f1b14-0x8f1b40) with `cmp r0, 8; bge` exiting the family path; then the SWITCH jump table (cells 0x8f23dc 0xffdeaf28 + 0x8f23e0 0x76df94 -> table @ 0x00E4AA1C, dispatch @0x8f1b60) routes the ffffe54c segment.\nCollect: per node the ffe23664 gate (@0x8f1cb0) selects candidates and `addObject:` (ffe23294) collects them; `std::__1::tree_next` advances (@0x8f1d30).\nSelect: the count checks (@0x8f1d54-0x8f1db8): empty -> 0x8f2118; exactly 1 -> return via the ffe23694 call (cell 0x8f23d8, @0x8f1ddc) - the single candidate; more -> the ffe231ec enumeration (cells ffe2369c/ffe23698 @0x8f1e20-0x8f1e48) picks through the candidate list. The ignore flags ride each candidate call.\n"),
    ),
    dict(
        name='wtl_clientblockheadwithid_',
        method='DynamicWorld -[clientBlockheadWithID:fromClient:requestsDyamicObjectRemovalWithID:]',
        types='v28@0:4Q8@16Q20',
        start=9458440,
        end=9460524,
        disasm='disasm_worldtileloader_clientblockheadwithid_fromclient_request.txt',
        base_add=9458456,
        base_literal=9460520,
        boundary='ARM.exidx end 0x00905b2c (listing bound); next ObjC IMP 0x00905b2c DynamicWorld -[removeObjectDueToRepair:]',
        selectors={
                 0x905acc: (15216544, 'needsRemoved'),
                 0x905ad0: (15215992, 'blockheadWithIDIncludingNet:'),
                 0x905ad4: (15216280, 'isEqualToString:'),
                 0x905ad8: (15216440, 'clientID'),
                 0x905adc: (15217360, 'canBeRemovedByBlockhead:'),
                 0x905ae0: (15216168, 'objectType'),
                 0x905ae4: (15217364, 'freeblockCreationItemType'),
                 0x905ae8: (15216884, 'removeStandardObject:'),
                 0x905aec: (15216012, 'pos'),
                 0x905af4: (15217368, 'freeBlockCreationDataA'),
                 0x905af8: (15217372, 'freeBlockCreationDataB'),
                 0x905afc: (15217376, 'freeBlockCreationSaveDict'),
                 0x905b00: (15216388, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
                 0x905b04: (15217024, 'isInUse'),
                 0x905b08: (15217028, 'remove:'),
                 0x905b14: (15216160, 'uniqueID'),
        },
        imports={
                 0x905ac8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x905ac4: (17162256, 'OBJC_IVAR_$_DynamicWorld.server', 16),
                 0x905b0c: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x905b1c: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
        },
        classes={},
        instructions=[(9458440, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9458536, 'bne 0x905370'), (9458560, 'cmp r0, 0x41'), (9458916, 'bl loc.imp.objc_msgSend'), (9459016, 'sub r0, fp, 0x78'), (9459484, 'movw r0, 0'), (9460520, 'ldrsbteq sl, [r5], -0x74')],
        calls=[(9458916, 'bl loc.imp.objc_msgSend'), (9459000, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9459364, 'bl loc.imp.objc_msgSend'), (9459448, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9459540, 'blx r2'), (9459600, 'bl loc.imp.objc_msgSend'), (9459684, 'blx ip'), (9459704, 'blx r3'), (9459768, 'blx r3'), (9459824, 'blx r2'), (9459828, 'bl sym.objectTypeIsInteractionObject_int_'), (9459892, 'blx r2'), (9459956, 'blx r3'), (9460032, 'blx ip'), (9460052, 'blx r2'), (9460124, 'bl loc.imp.objc_msgSend_stret'), (9460160, 'bl sym.imp.memset'), (9460188, 'bl loc.imp.objc_msgSend'), (9460220, 'bl loc.imp.objc_msgSend'), (9460252, 'bl loc.imp.objc_msgSend'), (9460284, 'bl loc.imp.objc_msgSend'), (9460392, 'bl loc.imp.objc_msgSend')],
        branches=[(9458536, 'bne', 9458544), (9458540, 'b', 9460412), (9458564, 'bge', 9459484), (9458860, 'beq', 9459016), (9458944, 'bne', 9458964), (9458948, 'b', 9458952), (9458960, 'b', 9459016), (9458964, 'b', 9458968), (9459012, 'b', 9458776), (9459308, 'beq', 9459464), (9459392, 'bne', 9459412), (9459396, 'b', 9459400), (9459408, 'b', 9459464), (9459412, 'b', 9459416), (9459460, 'b', 9459224), (9459464, 'b', 9459468), (9459480, 'b', 9458556), (9459496, 'beq', 9460412), (9459552, 'bne', 9460412), (9459620, 'beq', 9460408), (9459716, 'beq', 9460408), (9459780, 'beq', 9460404), (9459840, 'beq', 9459964), (9459904, 'bne', 9459960), (9459960, 'b', 9460400), (9460060, 'beq', 9460396), (9460108, 'beq', 9460132), (9460128, 'b', 9460164), (9460396, 'b', 9460400), (9460400, 'b', 9460404), (9460404, 'b', 9460408), (9460408, 'b', 9460412)],
        semantics=("clientBlockheadWithID:fromClient:requestsDyamicObjectRemovalWithID: services a client's blockhead lookup + removal request. Prologue 0x00905308 (frame 0x218; base 0x105faf4). Arguments: blockheadID pair, client, removalID pair (r2/r3, [fp,0x14]).\nGate: the ffffe51c slot on the client (cell 0x905ac4) must be nonzero (@0x905354-0x905368).\nLookup: `for i in 0..0x41 (65)` (cmp 0x41 @0x905380) with the ffffe54c segments (cell 0x905b0c, 12-byte stride @0x9053a0-0x9053b0; the base cell 0x905b10 resolves as the pool partner): per node `[obj uniqueID]` (ffe2332c cell 0x905b14) eor/orr-matches the ID (@0x9054d4-0x9054fc); then the same pass over the ffffe550 segments (cell 0x905b1c, @0x905548-0x905708).\nPost: when a match exists the ffe234ac gate (cell 0x905acc) and the ffe23284 chain (@0x90571c+, cell 0x905ad0) run - the removal-request processing; no match exits at 0x905abc.\n"),
    ),
    dict(
        name='wtl_sendlightblockstoclien',
        method='DynamicWorld -[sendLightblocksToClients]',
        types='v8@0:4',
        start=9117140,
        end=9119052,
        disasm='disasm_worldtileloader_sendlightblockstoclients.txt',
        base_add=9117156,
        base_literal=9119048,
        boundary='ARM.exidx end 0x008b254c (listing bound); next ObjC IMP 0x008b254c DynamicWorld -[saveDynamicObjects]',
        selectors={
                 0x8b2534: (15216036, 'macroTiles'),
                 0x8b2540: (15216040, 'saveLightBlockForClientLightBlockIndex:physicalBlock:sendNow:'),
        },
        imports={
                 0x8b2530: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8b2528: (17162336, 'OBJC_IVAR_$_DynamicWorld.lightChangedSendUnreliablyMacroPositionsSingleClient', 6120),
                 0x8b252c: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8b2538: (17162340, 'OBJC_IVAR_$_DynamicWorld.worldChangedMacroPositions', 7320),
                 0x8b253c: (17162344, 'OBJC_IVAR_$_DynamicWorld.worldChangedSendUnreliablyMacroPositions', 6084),
        },
        classes={},
        instructions=[(9117140, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9117188, 'cmp r0, 0x20'), (9117248, 'add r2, r3, r2'), (9117552, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (9117596, 'movw ip, 1'), (9117928, 'movw r0, 0'), (9118016, 'sub r0, fp, 0xa0'), (9119048, 'rsbseq sp, sl, r8, lsl 26')],
        calls=[(9117280, 'bl sym.imp.__aeabi_idiv'), (9117384, 'blx r4'), (9117552, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (9118532, 'blx ip'), (9118796, 'bl sym.imp.__aeabi_memmove')],
        branches=[(9117192, 'bge', 9119008), (9117288, 'bls', 9118988), (9117572, 'beq', 9118536), (9117860, 'beq', 9118004), (9117908, 'bne', 9117940), (9117924, 'bne', 9117940), (9117936, 'b', 9118004), (9117940, 'b', 9117944), (9118000, 'b', 9117688), (9118012, 'beq', 9118440), (9118292, 'beq', 9118436), (9118340, 'bne', 9118372), (9118356, 'bne', 9118372), (9118368, 'b', 9118436), (9118372, 'b', 9118376), (9118432, 'b', 9118120), (9118436, 'b', 9118440), (9118880, 'beq', 9118976), (9118972, 'b', 9118864), (9118984, 'b', 9117204), (9118988, 'b', 9118992), (9119004, 'b', 9117184)],
        semantics=('sendLightblocksToClients fills the dirty queues for the light channels. Prologue 0x008b1dd4 (frame 0x290; base 0x105faf4).\nLight channels: `if (channel >= 0x20) return` (cmp 0x20 @0x8b1e04) - the 32 light channels; the per-light struct lives at the ffffe56c slice (cell 0x8b2528, 12-byte stride via `movw r2, 0xc; mul` @0x8b1e20-0x8b1e40) with the vector count via `__aeabi_idiv` (@0x8b1e60).\nQueue fill: per entry `macroTileAtMacroPostion(int, int, MacroTile*, World*)` (@0x8b1f70) - a NULL tile skips; otherwise the ffffe570 queue (cell 0x8b2538) dedup runs (found flag [sp,0x93] initialised to 1 at @0x8b1f9c and cleared to 0 on a found pair @0x8b20e8) and the macro pair is appended; the ffffe574 queue (cell 0x8b253c) repeats the pass (@0x8b2140+). Exit 0x8b250c/0x8b2520.\n'),
    ),
    dict(
        name='wtl_clientpickuprequest_co',
        method='DynamicWorld -[clientPickupRequest:count:clientID:blockheadRequesterUniqueID:]',
        types='v28@0:4^Q8i12@16Q20',
        start=9398612,
        end=9400320,
        disasm='disasm_worldtileloader_clientpickuprequest_count_clientid_block.txt',
        base_add=9398628,
        base_literal=9400316,
        boundary='ARM.exidx end 0x008f7000 (listing bound); next ObjC IMP 0x008f7000 DynamicWorld -[blockheadWithUniqueID:]',
        selectors={
                 0x8f6fb4: (15217100, 'sendNetworkData:toPeers:reliable:'),
                 0x8f6fb8: (15216588, 'arrayWithObject:'),
                 0x8f6fc4: (15216220, 'appendBytes:length:'),
                 0x8f6fd0: (15216180, 'dataWithBytes:length:'),
                 0x8f6fd8: (15217096, 'freeblockWithUniqueID:'),
                 0x8f6fdc: (15216544, 'needsRemoved'),
                 0x8f6fe0: (15216528, 'setNeedsRemoved:'),
                 0x8f6ff4: (15216884, 'removeStandardObject:'),
        },
        imports={
                 0x8f6fa8: (17151968, '__stack_chk_guard'),
                 0x8f6fb0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8f6fc0: (17162256, 'OBJC_IVAR_$_DynamicWorld.server', 16),
                 0x8f6ff0: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
        },
        classes={
                 0x8f6fbc: (15247880, 'OBJC_CLASS_$_NSArray'),
                 0x8f6fc8: (15247844, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(9398612, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9398720, 'mov sp, r0'), (9398788, 'ldr r1, [0x008f6fd8]'), (9398936, 'mov r2, 1'), (9399112, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9399216, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_'), (9399272, 'ldr ip, [fp, -0xbc]'), (9400316, 'rsbseq sb, r6, r8, lsl 3')],
        calls=[(9398836, 'bl loc.imp.objc_msgSend'), (9398900, 'blx r2'), (9398940, 'bl loc.imp.objc_msgSend'), (9399112, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9399216, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_'), (9399276, 'blx ip'), (9399632, 'bl loc.imp.objc_msgSend'), (9399676, 'blx ip'), (9399744, 'blx ip'), (9399796, 'blx lr'), (9400012, 'bl loc.imp.objc_msgSend'), (9400056, 'blx ip'), (9400124, 'blx ip'), (9400176, 'blx lr'), (9400228, 'bl sym.imp.__stack_chk_fail')],
        branches=[(9398780, 'bge', 9399424), (9398856, 'beq', 9398988), (9398912, 'bne', 9398988), (9398984, 'b', 9399404), (9399012, 'bge', 9399304), (9399120, 'beq', 9399284), (9399280, 'b', 9399304), (9399284, 'b', 9399288), (9399300, 'b', 9399004), (9399312, 'beq', 9399360), (9399356, 'b', 9399400), (9399400, 'b', 9399404), (9399404, 'b', 9399408), (9399420, 'b', 9398768), (9399432, 'ble', 9399804), (9399812, 'ble', 9400184), (9400216, 'bne', 9400228)],
        semantics=("clientPickupRequest:count:clientID:blockheadRequesterUniqueID: applies a client's pickup request. Prologue 0x008f6954 (frame 0x128; base 0x105faf4). Arguments: the requested items list, count, clientID, the requester blockhead ID.\nRequest decode: the argument items are walked (@0x8f69f0-0x8f6c7c) with a VLA of 8-byte pairs (`sub r0, r1, r0, lsl 3; mov sp, r0` @0x8f69b0-0x8f69d0); per item the ffe236d4 call (@0x8f6a04) + the ffe234ac gate + **`ffe2349c` flag 1** (@0x8f6a88-0x8f6a9c, the needsRemoved family) and the pair is appended to the VLA (@0x8f6ac0).\nApply: `for i in 0..0xb (11)` (cmp 0xb @0x8f6ae0) with the SWITCH jump table (cells 0x8f6fe8 0xffdb8610 + 0x8f6fec 0x768ff4 -> table @ 0x00E18104, dispatch @0x8f6b00): per arm the ffffe54c segment `__count_unique(u64)` (@0x8f6b48) and `operator[](u64)` (@0x8f6bb0) resolve the object, then the **ffe23600 pickup call** (cell 0x8f6ff4, @0x8f6bc0-0x8f6bec) runs when the object exists; the requester ID filters through the arg. The post-count branch (@0x8f6c84+) handles the found case.\n"),
    ),
    dict(
        name='wtl_sendchestinventoryforc',
        method='DynamicWorld -[sendChestInventoryForChest:toClientOwningBlockheadWithID:]',
        types='v20@0:4@8Q12',
        start=9444184,
        end=9445732,
        disasm='disasm_worldtileloader_sendchestinventoryforchest_toclientownin.txt',
        base_add=9444200,
        base_literal=9445728,
        boundary='ARM.exidx end 0x00902164 (listing bound); next ObjC IMP 0x00902164 DynamicWorld -[chestInventoryDataRecievedFromServer:]',
        selectors={
                 0x902110: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x902118: (15216160, 'uniqueID'),
                 0x902120: (15216440, 'clientID'),
                 0x902124: (15216260, 'chestType'),
                 0x902128: (15216280, 'isEqualToString:'),
                 0x90212c: (15216448, 'ownerID'),
                 0x902130: (15216428, 'playerIsAdminWithID:'),
                 0x902138: (15216264, 'inventoryDataAllowingEmpty:'),
                 0x90213c: (15217292, 'loadInventoryItemsFromDiskIfNeeded'),
                 0x902140: (15216220, 'appendBytes:length:'),
                 0x90214c: (15216180, 'dataWithBytes:length:'),
                 0x902150: (15216184, 'appendData:'),
                 0x902154: (15217100, 'sendNetworkData:toPeers:reliable:'),
                 0x902158: (15216588, 'arrayWithObject:'),
        },
        imports={
                 0x90210c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x902114: (17162216, 'OBJC_IVAR_$_DynamicWorld.netBlockheads', 48),
                 0x902134: (17162256, 'OBJC_IVAR_$_DynamicWorld.server', 16),
        },
        classes={
                 0x902144: (15247844, 'OBJC_CLASS_$_NSMutableData'),
                 0x90215c: (15247880, 'OBJC_CLASS_$_NSArray'),
        },
        instructions=[(9444184, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9444592, 'ldr r0, [0x0090210c]'), (9444828, 'blx r2'), (9444880, 'blx r2'), (9444936, 'mov r0, lr'), (9445728, 'rsbseq sp, r5, r4, lsl 31')],
        calls=[(9444356, 'bl sym.imp.memset'), (9444420, 'blx lr'), (9444520, 'bl sym.imp.objc_enumerationMutation'), (9444556, 'bl loc.imp.objc_msgSend'), (9444632, 'blx r2'), (9444744, 'blx ip'), (9444828, 'blx r2'), (9444880, 'blx r2'), (9444952, 'blx ip'), (9444972, 'blx r3'), (9445056, 'blx r3'), (9445264, 'bl loc.imp.objc_msgSend'), (9445288, 'bl loc.imp.objc_msgSend'), (9445336, 'blx ip'), (9445356, 'blx r2'), (9445384, 'blx r3'), (9445456, 'blx r3'), (9445584, 'blx lr'), (9445632, 'blx lr')],
        branches=[(9444432, 'beq', 9444768), (9444512, 'beq', 9444524), (9444584, 'bne', 9444644), (9444588, 'b', 9444592), (9444640, 'b', 9444772), (9444644, 'b', 9444648), (9444672, 'blo', 9444476), (9444764, 'bne', 9444476), (9444768, 'b', 9444772), (9444784, 'beq', 9445636), (9444836, 'beq', 9444892), (9444888, 'bne', 9445076), (9444984, 'bne', 9445076), (9445068, 'bne', 9445076), (9445072, 'b', 9445636), (9445404, 'beq', 9445460)],
        semantics=("sendChestInventoryForChest:toClientOwningBlockheadWithID: sends a chest inventory to its owner's client. Prologue 0x00901b58 (frame 0x168; base 0x105faf4). Arguments: chest, blockheadID.\nOwner lookup: netBlockheads ivar ffffe4f4 (cell 0x902114) are enumerated (@0x901b90); per bh `[bh uniqueID]` (ffe2332c cell 0x902118) eor/orr-matches the blockheadID (@0x901cbc-0x901ce4); on match `[bh clientID]` (ffe23444 cell 0x902120) yields the clientID target (@0x901cf0-0x901d20).\nState gates + send: the ffe23390 call is checked against **5 then 1** (@0x901ddc-0x901e18: the chest state codes); the ffe2344c (cell 0x90212c) and ffe23438 (cell 0x902130) gates then run the inventory-send chain (@0x901e1c+) with the chest's contents. No match exits at 0x902104.\n"),
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
        'batch': 'DynamicWorld client-request/session cluster (E28): initWithWorld:... (11 args), checkForHarmableDynamicObjectUnderTap:..., clientBlockheadWithID:fromClient:requestsDyamicObjectRemovalWithID:, sendLightblocksToClients, clientPickupRequest:count:clientID:... and sendChestInventoryForChest:...; 6 bodies',
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
                        default=NATIVE / 'client_session.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale client_session.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
