#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The DynamicWorld door/boat/train accessor family C (window/door/boat/trainCar): the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 1307 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/ACCESSOR_C.md for the prose and boundaries.
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
    'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__': 0x005dc5d8,
    'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_': 0x008bcf24,
    'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_': 0x008bcb78,
    'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const': 0x00910a74,
    'bl sym.macroTileAtWorldPostion_int__int__MacroTile__World_': 0x00a1770c,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.recalculateDrawBlockLightingForTile_int__int__MacroTile__World_': 0x00a18f68,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
}

SPECS = [
    dict(
        name='wtl_windowatpos_',
        method='DynamicWorld -[windowAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9360292,
        end=9360404,
        disasm='disasm_worldtileloader_windowatpos_.txt',
        base_add=9360352,
        base_literal=9360400,
        boundary='ARM.exidx end 0x008ed414 (listing bound); next ObjC IMP 0x008ed414 DynamicWorld -[addWindowAtPos:ofType:saveDict:placedByClient:]',
        selectors={
                 0x8ed40c: (15216868, 'objectOfType:atPos:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(9360292, 'push {fp, lr}'), (9360304, 'movw ip, 0x1f'), (9360344, 'ldr r1, [0x008ed40c]'), (9360380, 'str ip, [sp, 4]'), (9360400, 'rsbseq r2, r7, ip, lsl 14')],
        calls=[(9360384, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('windowAtPos: returns the window at a position. Prologue 0x008ed3a4 (frame 0x28; base 0x105faf4).\nBody: the type **0x1f (31)** (`movw ip, 0x1f` / `mov r2, 0x1f` @0x8ed3b0/0x8ed3f8) + the **ffe235f0 lookup** (@0x8ed3d8-0x8ed400).\n'),
    ),
    dict(
        name='wtl_addwindowatpos_oftype_',
        method='DynamicWorld -[addWindowAtPos:ofType:saveDict:placedByClient:]',
        types='v28@0:4{?=ii}8i16@20@24',
        start=9360404,
        end=9360568,
        disasm='disasm_worldtileloader_addwindowatpos_oftype_savedict_placedbyc.txt',
        base_add=9360496,
        base_literal=9360564,
        boundary='ARM.exidx end 0x008ed4b8 (listing bound); next ObjC IMP 0x008ed4b8 DynamicWorld -[removeWindowAtPos:]',
        selectors={
                 0x8ed4b0: (15216920, 'addStandardObjectAtPos:objectType:itemType:saveDict:placedByClient:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(9360404, 'push {r4, r5, fp, lr}'), (9360488, 'ldr ip, [0x008ed4b0]'), (9360528, 'mov r1, 0x1f'), (9360564, 'rsbseq r2, r7, ip, ror r6')],
        calls=[(9360548, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('addWindowAtPos:ofType:saveDict:placedByClient: creates a window. Prologue 0x008ed414 (frame 0x40; base 0x105faf4).\nBody: the type **0x1f (31)** (`mov r1, 0x1f` @0x8ed490) packed into the **ffe23624 add call** frame (@0x8ed468-0x8ed4a4) with ofType/saveDict/placedByClient - the window add leg.\n'),
    ),
    dict(
        name='wtl_removewindowatpos_',
        method='DynamicWorld -[removeWindowAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9360568,
        end=9360748,
        disasm='disasm_worldtileloader_removewindowatpos_.txt',
        base_add=9360584,
        base_literal=9360744,
        boundary='ARM.exidx end 0x008ed56c (listing bound); next ObjC IMP 0x008ed56c DynamicWorld -[addDoorAtPos:ofType:saveDict:placedByClient:]',
        selectors={
                 0x8ed55c: (15216884, 'removeStandardObject:'),
                 0x8ed560: (15216960, 'windowAtPos:'),
        },
        imports={
                 0x8ed558: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9360568, 'push {r4, sl, fp, lr}'), (9360596, 'ldr r4, [0x008ed55c]'), (9360736, 'invalid'), (9360744, 'rsbseq r2, r7, r4, lsr 12')],
        calls=[(9360672, 'bl loc.imp.objc_msgSend'), (9360712, 'blx r3')],
        branches=[],
        semantics=('removeWindowAtPos: removes the window at a position. Prologue 0x008ed4b8 (frame 0x38; base 0x105faf4).\nBody: the **ffe23600 gate** (cell 0x8ed55c) + the **ffe2364c remove call** (@0x8ed560-0x8ed548).\n'),
    ),
    dict(
        name='wtl_adddooratpos_oftype_sa',
        method='DynamicWorld -[addDoorAtPos:ofType:saveDict:placedByClient:]',
        types='v28@0:4{?=ii}8i16@20@24',
        start=9360748,
        end=9361344,
        disasm='disasm_worldtileloader_adddooratpos_oftype_savedict_placedbycli.txt',
        base_add=9360764,
        base_literal=9361340,
        boundary='ARM.exidx end 0x008ed7c0 (listing bound); next ObjC IMP 0x008ed7c0 DynamicWorld -[doorAtPos:]',
        selectors={
                 0x8ed7a8: (15216920, 'addStandardObjectAtPos:objectType:itemType:saveDict:placedByClient:'),
                 0x8ed7b4: (15216036, 'macroTiles'),
                 0x8ed7b8: (15216860, 'worldChangedAtPos:sendReliably:'),
        },
        imports={},
        ivars={
                 0x8ed7a4: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
        },
        classes={},
        instructions=[(9360748, 'push {r4, r5, r6, r7, fp, lr}'), (9360848, 'ldr lr, [0x008ed7a8]'), (9360948, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9360976, 'bne 0x8ed6ac'), (9361000, 'strb r2, [r3, 0xc]'), (9361044, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9361340, 'rsbseq r2, r7, r0, ror r5')],
        calls=[(9360916, 'bl loc.imp.objc_msgSend'), (9360948, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9361044, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (9361208, 'bl loc.imp.objc_msgSend'), (9361248, 'bl sym.recalculateDrawBlockLightingForTile_int__int__MacroTile__World_'), (9361304, 'bl loc.imp.objc_msgSend')],
        branches=[(9360964, 'beq', 9360980), (9360976, 'bne', 9361068), (9361064, 'b', 9361140), (9361076, 'beq', 9361092), (9361088, 'bne', 9361108), (9361104, 'b', 9361136), (9361116, 'bne', 9361132), (9361132, 'b', 9361136), (9361136, 'b', 9361140)],
        semantics=("addDoorAtPos:ofType:saveDict:placedByClient: creates a door and writes the tile state. Prologue 0x008ed56c (frame 0x78; base 0x105faf4).\nCreate: the type **0x14 (20)** (`mov r1, 0x14` @0x8ed5f8) + the **ffe23624 add call** (@0x8ed5d0-0x8ed614) with the four-argument frame (world via ffffe4e4).\nTile write: `tileAtWorldPositionLoaded(int, int, World*)` (@0x8ed634) -> the byte compared against **0x34 ('4') and 0xa4** (@0x8ed640-0x8ed650); the **0x46 ('F') marker** is written to [r3+0xc] (`movw r2, 0x46; strb r2, [r3, 0xc]` @0x8ed660-0x8ed668); the neighbouring tile is re-fetched (@0x8ed694) - the door tile-state write.\n"),
    ),
    dict(
        name='wtl_dooratpos_',
        method='DynamicWorld -[doorAtPos:]',
        types='@16@0:4{?=ii}8',
        start=9361344,
        end=9361744,
        disasm='disasm_worldtileloader_dooratpos_.txt',
        base_add=9361360,
        base_literal=9361740,
        boundary='ARM.exidx end 0x008ed950 (listing bound); next ObjC IMP 0x008ed950 DynamicWorld -[doorCanBeUsedByPathUser:atPos:]',
        selectors={
                 0x8ed938: (15216868, 'objectOfType:atPos:'),
                 0x8ed948: (15216452, 'itemType'),
        },
        imports={
                 0x8ed944: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9361344, 'push {r4, r5, fp, lr}'), (9361408, 'ldr r1, [0x008ed938]'), (9361512, 'sub ip, ip, 1'), (9361544, 'bl sym.makeIntpair_int__int_'), (9361588, 'bl loc.imp.objc_msgSend'), (9361740, 'rsbseq r2, r7, ip, lsl r3')],
        calls=[(9361456, 'bl loc.imp.objc_msgSend'), (9361544, 'bl sym.makeIntpair_int__int_'), (9361588, 'bl loc.imp.objc_msgSend'), (9361652, 'blx r2')],
        branches=[(9361476, 'beq', 9361492), (9361488, 'b', 9361708), (9361608, 'beq', 9361700), (9361668, 'beq', 9361684), (9361680, 'bne', 9361696), (9361692, 'b', 9361708), (9361696, 'b', 9361700)],
        semantics=('doorAtPos: returns the door at a position. Prologue 0x008ed7c0 (frame 0x60; base 0x105faf4).\nBody: the **ffe235f0 lookup** with type **0x14 (20)** (@0x8ed7d8-0x8ed830); on miss/absent: the **pos.y - 1 probe** (`sub ip, ip, 1` @0x8ed868) + `makeIntpair(int, int)` (@0x8ed888) + the second ffe235f0 fetch (@0x8ed88c-0x8ed8b4) + the ffe23450 read - doors resolve at the position or one below.\n'),
    ),
    dict(
        name='wtl_doorcanbeusedbypathuse',
        method='DynamicWorld -[doorCanBeUsedByPathUser:atPos:]',
        types='c20@0:4@8{?=ii}12',
        start=9361744,
        end=9362264,
        disasm='disasm_worldtileloader_doorcanbeusedbypathuser_atpos_.txt',
        base_add=9361760,
        base_literal=9362260,
        boundary='ARM.exidx end 0x008edb58 (listing bound); next ObjC IMP 0x008edb58 DynamicWorld -[doorIsOpenAtPos:]',
        selectors={
                 0x8edb30: (15216140, 'isKindOfClass:'),
                 0x8edb34: (15216136, 'class'),
                 0x8edb3c: (15216968, 'canBeUsedByBlockhead:'),
                 0x8edb48: (15216036, 'macroTiles'),
                 0x8edb4c: (15216132, 'loadDynamicObjectsIfNotAlreadyLoadedForMacroTile:includeSurfaceBlocks:'),
                 0x8edb50: (15216964, 'doorAtPos:'),
        },
        imports={
                 0x8edb2c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8edb40: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
        },
        classes={
                 0x8edb38: (15247828, 'OBJC_CLASS_$_Blockhead'),
        },
        instructions=[(9361744, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9361780, 'ldr r6, [0x008edb30]'), (9361920, 'ldr r2, [0x008edb3c]'), (9361952, 'ldr r3, [r3, r4]'), (9361984, 'mov r1, r5'), (9362260, 'rsbseq r2, r7, ip, lsl 3')],
        calls=[(9361860, 'blx r4'), (9361892, 'blx r3'), (9362008, 'bl loc.imp.objc_msgSend'), (9362048, 'bl sym.macroTileAtWorldPostion_int__int__MacroTile__World_'), (9362084, 'bl loc.imp.objc_msgSend'), (9362128, 'bl loc.imp.objc_msgSend'), (9362168, 'blx r3')],
        branches=[(9361904, 'beq', 9362200), (9362180, 'beq', 9362196), (9362192, 'b', 9362208), (9362196, 'b', 9362200)],
        semantics=('doorCanBeUsedByPathUser:atPos: answers whether a door can be used by a path user. Prologue 0x008ed950 (frame 0x78; base 0x105faf4).\nChecks: the ffe23318/ffe23314 pair (@0x8ed974-0x8ed9e4); the **ffe23654 door fetch** (cell 0x8edb3c, @0x8eda00); the world chain ffffe4e4 (@0x8eda0c-0x8eda20) + the **ffe232b0 call** (cell 0x8edb48, @0x8eda2c-0x8eda40) - the door-usage predicate.\n'),
    ),
    dict(
        name='wtl_doorisopenatpos_',
        method='DynamicWorld -[doorIsOpenAtPos:]',
        types='c16@0:4{?=ii}8',
        start=9362264,
        end=9362488,
        disasm='disasm_worldtileloader_doorisopenatpos_.txt',
        base_add=9362280,
        base_literal=9362484,
        boundary='ARM.exidx end 0x008edc38 (listing bound); next ObjC IMP 0x008edc38 DynamicWorld -[removeDoorAtPos:]',
        selectors={
                 0x8edc24: (15216964, 'doorAtPos:'),
                 0x8edc30: (15216972, 'isOpen'),
        },
        imports={
                 0x8edc2c: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9362264, 'push {fp, lr}'), (9362324, 'ldr r1, [0x008edc24]'), (9362392, 'ldr r2, [0x008edc30]'), (9362420, 'blx r2'), (9362452, 'strb r0, [fp, -1]'), (9362484, 'rsbseq r1, r7, r4, lsl 31')],
        calls=[(9362356, 'bl loc.imp.objc_msgSend'), (9362420, 'blx r2')],
        branches=[(9362376, 'beq', 9362448), (9362432, 'bne', 9362448), (9362444, 'b', 9362456)],
        semantics=('doorIsOpenAtPos: answers whether the door at a position is open. Prologue 0x008edb58 (frame 0x40; base 0x105faf4).\nBody: the **ffe23650 door fetch** (@0x8edb94-0x8edbb4) -> the **ffe23658 open check** (cell 0x8edc30, @0x8edbd8): true sets the byte 1, false 0 (@0x8edc04-0x8edc14); returns the boolean.\n'),
    ),
    dict(
        name='wtl_setdooratpos_toopen_di',
        method='DynamicWorld -[setDoorAtPos:toOpen:direction:]',
        types='v24@0:4{?=ii}8c16i20',
        start=9368520,
        end=9368712,
        disasm='disasm_worldtileloader_setdooratpos_toopen_direction_.txt',
        base_add=9368536,
        base_literal=9368708,
        boundary='ARM.exidx end 0x008ef488 (listing bound); next ObjC IMP 0x008ef488 DynamicWorld -[posOfDoorsOtherBlockAtPos:]',
        selectors={
                 0x8ef478: (15216992, 'setOpen:direction:'),
                 0x8ef47c: (15216964, 'doorAtPos:'),
        },
        imports={
                 0x8ef474: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9368520, 'push {r4, r5, r6, sl, fp, lr}'), (9368556, 'ldr r6, [0x008ef478]'), (9368616, 'add r2, pc, r2'), (9368640, 'bl loc.imp.objc_msgSend'), (9368680, 'blx lr'), (9368708, 'rsbseq r0, r7, r4, lsl r7')],
        calls=[(9368640, 'bl loc.imp.objc_msgSend'), (9368680, 'blx lr')],
        branches=[],
        semantics=("setDoorAtPos:toOpen:direction: sets a door's open state and direction. Prologue 0x008ef3c8 (frame 0x40; base 0x105faf4).\nBody: the **ffe2366c door fetch** (cell 0x8ef478, @0x8ef3ec) -> the **ffe23650 call** (@0x8ef47c-0x8ef440) -> the setter blx with the open byte [sp,0x1f] and the sxtb'd direction (@0x8ef444-0x8ef468) - the door state setter.\n"),
    ),
    dict(
        name='wtl_posofdoorsotherblockat',
        method='DynamicWorld -[posOfDoorsOtherBlockAtPos:]',
        types='{?=ii}16@0:4{?=ii}8',
        start=9368712,
        end=9369112,
        disasm='disasm_worldtileloader_posofdoorsotherblockatpos_.txt',
        base_add=9368776,
        base_literal=9369100,
        boundary='ARM.exidx end 0x008ef618 (listing bound); next ObjC IMP 0x008ef618 DynamicWorld -[treeAtPos:]',
        selectors={
                 0x8ef608: (15216964, 'doorAtPos:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(9368712, 'push {fp, lr}'), (9368768, 'ldr r2, [0x008ef608]'), (9368868, 'bl sym.makeIntpair_int__int_'), (9368976, 'bl sym.makeIntpair_int__int_'), (9369048, 'bl sym.makeIntpair_int__int_'), (9369108, 'rsbseq r0, r7, r0, asr r5')],
        calls=[(9368816, 'bl loc.imp.objc_msgSend'), (9368868, 'bl sym.makeIntpair_int__int_'), (9368900, 'bl loc.imp.objc_msgSend'), (9368940, 'bl sym.makeIntpair_int__int_'), (9368976, 'bl sym.makeIntpair_int__int_'), (9369008, 'bl loc.imp.objc_msgSend'), (9369048, 'bl sym.makeIntpair_int__int_'), (9369084, 'bl sym.makeIntpair_int__int_')],
        branches=[(9368836, 'beq', 9369060), (9368920, 'bne', 9368948), (9368944, 'b', 9369088), (9369028, 'bne', 9369056), (9369052, 'b', 9369088), (9369056, 'b', 9369060)],
        semantics=("posOfDoorsOtherBlockAtPos: finds the position of the door's other block. Prologue 0x008ef488 (frame 0x60; base 0x105faf4).\nProbe: the **ffe23650 door fetch** (@0x8ef4c0-0x8ef4f0); the four directions are probed with `makeIntpair` after +1/-1 adjustments: y+1 (@0x8ef514), then x+1 (@0x8ef564), x-1 (@0x8ef580-0x8ef590), y-1 (@0x8ef5d0-0x8ef5d8); each re-fetches via ffe23650 (cells @0x8ef608/0x8ef610/0x8ef614); no hit returns -1 (@0x8ef5e4 `mvn r0, 0`).\n"),
    ),
    dict(
        name='wtl_placeboatinwateratpos_',
        method='DynamicWorld -[placeBoatInWaterAtPos:saveDict:placedByClient:]',
        types='v24@0:4{?=ii}8@16@20',
        start=9363952,
        end=9364456,
        disasm='disasm_worldtileloader_placeboatinwateratpos_savedict_placedbyc.txt',
        base_add=9363968,
        base_literal=9364452,
        boundary='ARM.exidx end 0x008ee3e8 (listing bound); next ObjC IMP 0x008ee3e8 DynamicWorld -[checkForBoatUnderTap:]',
        selectors={
                 0x8ee3bc: (15215804, 'alloc'),
                 0x8ee3c8: (15216980, 'initWithWorld:dynamicWorld:atPosition:cache:saveDict:placedByClient:'),
                 0x8ee3d0: (15216020, 'sendNetDataIfNeededForObject:isCreation:'),
                 0x8ee3d4: (15216168, 'objectType'),
                 0x8ee3e0: (15216160, 'uniqueID'),
        },
        imports={
                 0x8ee3cc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8ee3c0: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8ee3c4: (17162232, 'OBJC_IVAR_$_DynamicWorld.cache', 7336),
                 0x8ee3dc: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
        },
        classes={
                 0x8ee3b4: (15248000, 'OBJC_CLASS_$_Boat'),
        },
        instructions=[(9363952, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9364008, 'ldr r0, [0x008ee3b4]'), (9364120, 'ldr r5, [0x008ee3c8]'), (9364172, 'bl loc.imp.objc_msgSend'), (9364204, 'ldr r2, [0x008ee3d4]'), (9364452, 'rsbseq r1, r7, ip, ror 17')],
        calls=[(9364048, 'bl loc.imp.objc_msgSend'), (9364172, 'bl loc.imp.objc_msgSend'), (9364236, 'bl loc.imp.objc_msgSend'), (9364296, 'bl loc.imp.objc_msgSend'), (9364316, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9364392, 'blx r4')],
        branches=[(9364192, 'beq', 9364396)],
        semantics=('placeBoatInWaterAtPos:saveDict:placedByClient: creates a boat. Prologue 0x008ee1f0 (frame 0x80; base 0x105faf4).\nCreate: class **ffe2af8c** alloc/init (cells ffe2af8c/ffe231c8 @0x8ee228-0x8ee250) + the world chain (ffffe4e4/ffffe504 @0x8ee258-0x8ee28c) + the **ffe23660 call** (cell 0x8ee3c8, @0x8ee298-0x8ee2cc) with the saveDict/placedByClient frame; the objectType read (ffe23334 @0x8ee2ec) follows - the boat placer.\n'),
    ),
    dict(
        name='wtl_checkforboatundertap_',
        method='DynamicWorld -[checkForBoatUnderTap:]',
        types='@16@0:4{Vector2=[2f]}8',
        start=9364456,
        end=9364964,
        disasm='disasm_worldtileloader_checkforboatundertap_.txt',
        base_add=9364500,
        base_literal=9364952,
        boundary='ARM.exidx end 0x008ee5e4 (listing bound); next ObjC IMP 0x008ee5e4 DynamicWorld -[boatWithID:]',
        selectors={
                 0x8ee5dc: (15216984, 'tapIsWithinBodyRadius:'),
        },
        imports={},
        ivars={
                 0x8ee5d4: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
        },
        classes={},
        instructions=[(9364456, 'push {fp, lr}'), (9364516, 'add r1, r0, 0x180'), (9364764, 'tst r0, 1'), (9364824, 'ldr r1, [0x008ee5dc]'), (9364912, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9364960, 'rsbseq r1, r7, ip, lsl 11')],
        calls=[(9364848, 'bl loc.imp.objc_msgSend'), (9364912, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__')],
        branches=[(9364768, 'beq', 9364928), (9364860, 'beq', 9364876), (9364872, 'b', 9364936), (9364876, 'b', 9364880), (9364924, 'b', 9364684)],
        semantics=("checkForBoatUnderTap: checks for a boat under a tap. Prologue 0x008ee3e8 (frame 0xe8; base 0x105faf4).\nWalk: the **ffffe54c member's +0x180 boat slice** (`add r1, r0, 0x180` @0x8ee424) tree-walked (the eor/tst guard @0x8ee50c-0x8ee51c); per node the **ffe23664 hit test** (cell 0x8ee5dc, @0x8ee558) runs with the node payload ([node+0x10]+8-0x18 @0x8ee538-0x8ee540); `__tree_next` advances (@0x8ee5b0) - the boat tap check.\n"),
    ),
    dict(
        name='wtl_boatwithid_',
        method='DynamicWorld -[boatWithID:]',
        types='@16@0:4Q8',
        start=9364964,
        end=9365248,
        disasm='disasm_worldtileloader_boatwithid_.txt',
        base_add=9364980,
        base_literal=9365244,
        boundary='ARM.exidx end 0x008ee700 (listing bound); next ObjC IMP 0x008ee700 DynamicWorld -[placeTrainCarAtPos:ofType:saveDict:placedByClient:]',
        selectors={},
        imports={},
        ivars={
                 0x8ee6f4: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8ee6f8: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
        },
        classes={},
        instructions=[(9364964, 'push {r4, sl, fp, lr}'), (9365024, 'add r0, r0, 0x180'), (9365048, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9365092, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_'), (9365156, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9365244, 'ldrshteq r1, [r7], -0x48')],
        calls=[(9365048, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9365092, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_'), (9365156, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9365200, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_')],
        branches=[(9365056, 'beq', 9365108), (9365104, 'b', 9365224), (9365164, 'beq', 9365216), (9365212, 'b', 9365224)],
        semantics=('boatWithID: resolves a boat by ID. Prologue 0x008ee5e4 (frame 0x38; base 0x105faf4).\nLookup 1: the **ffffe54c +0x180 slice** `__count_unique(u64)` (@0x8ee638): hit -> `operator[](u64 const&)` (@0x8ee664) returns.\nLookup 2: miss -> the **ffffe550 +0x180 slice** (@0x8ee674-0x8ee6a4) with the same pair; else nil (@0x8ee6e0) - the two-registry boat lookup.\n'),
    ),
    dict(
        name='wtl_checkfortraincarundert',
        method='DynamicWorld -[checkForTrainCarUnderTap:]',
        types='@16@0:4{Vector2=[2f]}8',
        start=9367376,
        end=9367948,
        disasm='disasm_worldtileloader_checkfortraincarundertap_.txt',
        base_add=9367440,
        base_literal=9367932,
        boundary='ARM.exidx end 0x008ef18c (listing bound); next ObjC IMP 0x008ef18c DynamicWorld -[trainCarWithID:]',
        selectors={
                 0x8ef184: (15216984, 'tapIsWithinBodyRadius:'),
        },
        imports={},
        ivars={
                 0x8ef180: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
        },
        classes={},
        instructions=[(9367376, 'push {fp, lr}'), (9367416, 'cmp r0, 4'), (9367476, 'add r3, r2, r1, lsl 2'), (9367728, 'beq 0x8ef150'), (9367784, 'ldr r1, [0x008ef184]'), (9367944, 'ldrshteq r0, [r7], -0x9c')],
        calls=[(9367808, 'bl loc.imp.objc_msgSend'), (9367872, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__')],
        branches=[(9367420, 'bge', 9367908), (9367728, 'beq', 9367888), (9367820, 'beq', 9367836), (9367832, 'b', 9367916), (9367836, 'b', 9367840), (9367884, 'b', 9367644), (9367888, 'b', 9367892), (9367904, 'b', 9367412)],
        semantics=('checkForTrainCarUnderTap: checks for a train car under a tap. Prologue 0x008eef50 (frame 0xf0; base 0x105faf4).\nGate: `if (arg >= 4) return` (@0x8eef78-0x8eef7c).\nWalk: the **0x00E4AA0C jump table** (cell 0x8ef178, 4 arms) selects the ffffe54c family slice (`add r1, r1, r1, lsl 1` <<2 12-byte striding @0x8eefb0); the tree walk (@0x8eefcc-0x8ef0b0) runs the **ffe23664 hit test** (cell 0x8ef184) per node - the train-car tap check by family.\n'),
    ),
    dict(
        name='wtl_traincarwithid_',
        method='DynamicWorld -[trainCarWithID:]',
        types='@16@0:4Q8',
        start=9367948,
        end=9368520,
        disasm='disasm_worldtileloader_traincarwithid_.txt',
        base_add=9367964,
        base_literal=9368516,
        boundary='ARM.exidx end 0x008ef3c8 (listing bound); next ObjC IMP 0x008ef3c8 DynamicWorld -[setDoorAtPos:toOpen:direction:]',
        selectors={},
        imports={},
        ivars={
                 0x8ef3a8: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8ef3b4: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
        },
        classes={},
        instructions=[(9367948, 'push {r4, r5, r6, sl, fp, lr}'), (9368004, 'bge 0x8ef394'), (9368084, 'add r1, r2, r1'), (9368112, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9368160, 'ldr r5, [0x008ef3ac]'), (9368516, 'rsbseq r0, r7, r0, asr sb')],
        calls=[(9368112, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9368212, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_'), (9368332, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9368432, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_')],
        branches=[(9368004, 'bge', 9368468), (9368120, 'beq', 9368228), (9368224, 'b', 9368476), (9368340, 'beq', 9368448), (9368444, 'b', 9368476), (9368448, 'b', 9368452), (9368464, 'b', 9367996)],
        semantics=('trainCarWithID: resolves a train car by ID across the families. Prologue 0x008ef18c (frame 0x60; base 0x105faf4).\nGate: `if (arg >= 4) return` (@0x8ef1c0-0x8ef1c4).\nLookup: the **0x00E4AA0C table** (cell 0x8ef3ac) selects the ffffe54c family slice (`movw r1, 0xc; mul` 12-byte striding @0x8ef1cc-0x8ef214) `__count_unique(u64)` (@0x8ef230): hit -> `operator[](u64 const&)` (@0x8ef260+) returns; the miss path continues into the ffffe550 segment (the tail from @0x8ef2a4) - the train-car ID lookup.\n'),
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
        'batch': 'DynamicWorld door/boat/train accessor family C (E38): windowAtPos:/addWindowAtPos:.../removeWindowAtPos:, addDoorAtPos:..., doorAtPos:, doorCanBeUsedByPathUser:atPos:, doorIsOpenAtPos:, setDoorAtPos:toOpen:direction:, posOfDoorsOtherBlockAtPos:, placeBoatInWaterAtPos:..., checkForBoatUnderTap:, boatWithID:, checkForTrainCarUnderTap: and trainCarWithID:; 14 bodies',
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
                        default=NATIVE / 'accessor_c.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale accessor_c.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
