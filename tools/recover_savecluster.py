#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The DynamicWorld save/remote/simulate cluster (save/remote-create/loader/simulate): the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 1297 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/SAVE_REMOTE_SIM.md for the prose and boundaries.
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
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_': 0x00a16ccc,
    'bl sym.objectTypeCanBeLoadedOnlyWhenClientOwnerOnline_int_': 0x008ba904,
    'bl sym.worldIndexAtWorldPos_intpair__World_': 0x00a15838,
}

SPECS = [
    dict(
        name='wtl_savedynamicobjects',
        method='DynamicWorld -[saveDynamicObjects]',
        types='v8@0:4',
        start=9119052,
        end=9120188,
        disasm='disasm_worldtileloader_savedynamicobjects.txt',
        base_add=9119068,
        base_literal=9120184,
        boundary='ARM.exidx end 0x008b29bc (listing bound); next ObjC IMP 0x008b29bc DynamicWorld -[saveGameWithWorldData:signOwnershipData:]',
        selectors={
                 0x8b29ac: (15216036, 'macroTiles'),
                 0x8b29b4: (15216044, 'saveDynamicObjectsForMacroTile:objectType:xPos:yPos:'),
        },
        imports={
                 0x8b29a8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8b29a0: (17162348, 'OBJC_IVAR_$_DynamicWorld.dynamicWorldChangedMacroPositions', 6540),
                 0x8b29a4: (17162252, 'OBJC_IVAR_$_DynamicWorld.client', 20),
                 0x8b29b0: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
        },
        classes={},
        instructions=[(9119052, 'push {r4, r5, r6, r7, fp, lr}'), (9119100, 'cmp r0, 0x41'), (9119152, 'add r2, r3, r2'), (9119232, 'beq 0x8b2610'), (9119240, 'cmp r0, 0x2e'), (9119256, 'beq 0x8b28a8'), (9120184, 'invalid')],
        calls=[(9119184, 'bl sym.imp.__aeabi_idiv'), (9119352, 'blx ip'), (9119744, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (9119840, 'blx ip')],
        branches=[(9119104, 'bge', 9120152), (9119192, 'bls', 9120132), (9119232, 'beq', 9119248), (9119244, 'bne', 9119912), (9119256, 'beq', 9119912), (9119652, 'beq', 9119908), (9119764, 'beq', 9119844), (9119844, 'b', 9119848), (9119904, 'b', 9119464), (9119908, 'b', 9119912), (9120028, 'beq', 9120124), (9120120, 'b', 9120012), (9120132, 'b', 9120136), (9120148, 'b', 9119096)],
        semantics=("saveDynamicObjects saves the world's dynamic objects. Prologue 0x008b254c (frame 0x150; base 0x105faf4). Argument: the object type (r0).\nGate: `if (objectType >= 0x41) return` (@0x8b257c-0x8b2580).\nWalk: the **ffffe578 member's 12-byte segments** (`movw r2, 0xc; mul` @0x8b258c-0x8b25b0); the segment count `(end - start) / 8` idiv (@0x8b25c4-0x8b25d4); skip conditions: the **ffffe518 client slot** non-null (@0x8b25e0-0x8b2600), **objectType == 0x2e (46)**, and **objectType == 0x18 (24)** (@0x8b2608-0x8b2618); per survivor the ffe232b0 + world chain run the save (@0x8b2634-0x8b269c) - the dynamic-object saver with the client/46/24 skips.\n"),
    ),
    dict(
        name='wtl_remotecreate_forobject',
        method='DynamicWorld -[remoteCreate:forObjectsOfType:clientID:]',
        types='v20@0:4@8i12@16',
        start=9190408,
        end=9191012,
        disasm='disasm_worldtileloader_remotecreate_forobjectsoftype_clientid_.txt',
        base_add=9190424,
        base_literal=9191008,
        boundary='ARM.exidx end 0x008c3e64 (listing bound); next ObjC IMP 0x008c3e64 DynamicWorld -[remoteCreationDataUpdate:forObjectsOfType:fromClient:]',
        selectors={
                 0x8c3e30: (15216420, 'isServer'),
                 0x8c3e44: (15215804, 'alloc'),
                 0x8c3e48: (15215800, 'init'),
                 0x8c3e4c: (15215884, 'objectForKey:'),
                 0x8c3e50: (15215944, 'setObject:forKey:'),
                 0x8c3e54: (15216144, 'array'),
                 0x8c3e5c: (15216424, 'addObjectsFromArray:'),
        },
        imports={
                 0x8c3e2c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8c3e34: (17162288, 'OBJC_IVAR_$_DynamicWorld.netCreateDynamicObjects', 7372),
        },
        classes={
                 0x8c3e3c: (15247784, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x8c3e58: (15247780, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(9190408, 'push {r4, r5, fp, lr}'), (9190500, 'cmp r0, 0xe'), (9190556, 'ldr r2, [r2]'), (9190580, 'movw r0, 2'), (9190676, 'str r0, [r1]'), (9191008, 'ldrsbteq fp, [sb], -0xe4')],
        calls=[(9190480, 'blx r4'), (9190624, 'bl loc.imp.objc_msgSend'), (9190640, 'bl loc.imp.objc_msgSend'), (9190744, 'blx r3'), (9190836, 'blx ip'), (9190892, 'blx lr'), (9190944, 'blx r3')],
        branches=[(9190492, 'beq', 9190512), (9190504, 'bne', 9190512), (9190508, 'b', 9190948), (9190576, 'bne', 9190684), (9190764, 'bne', 9190896)],
        semantics=('remoteCreate:forObjectsOfType:clientID: applies a remote creation. Prologue 0x008c3c08 (frame 0x58; base 0x105faf4).\nGate: the ffe23430 check (@0x8c3c28-0x8c3c5c) with the **== 0xe (14) skip** (@0x8c3c64-0x8c3c6c) - FreeBlock (type 14) creations are skipped.\nBucket: the **ffffe53c slot array** (`add r2, r3, r2, lsl 2` 4-byte pointer array @0x8c3c94-0x8c3c9c) lazily creates the **ffe2aeb4** class slot (@0x8c3cb4-0x8c3d14); the creation call follows (ffe23218 @0x8c3d2c+).\n'),
    ),
    dict(
        name='wtl_loadclientowneddynamic',
        method='DynamicWorld -[loadClientOwnedDynamicObjectsForClient:physicalBlock:]',
        types='v16@0:4@8^{PhysicalBlock=ii^{Tile}cCdII[32*][32C]}12',
        start=9164476,
        end=9165240,
        disasm='disasm_worldtileloader_loadclientowneddynamicobjectsforclient_p.txt',
        base_add=9164492,
        base_literal=9165236,
        boundary='ARM.exidx end 0x008bd9b8 (listing bound); next ObjC IMP 0x008bd9b8 DynamicWorld -[loadDynamicObjectsForMacroTile:includeSurfaceBlocks:]',
        selectors={
                 0x8bd990: (15215900, 'dataForKey:'),
                 0x8bd99c: (15215816, 'stringWithFormat:'),
                 0x8bd9a8: (15216036, 'macroTiles'),
                 0x8bd9ac: (15216132, 'loadDynamicObjectsIfNotAlreadyLoadedForMacroTile:includeSurfaceBlocks:'),
                 0x8bd9b0: (15216316, 'loadDynamicObjectsOfType:fromData:physicalBlock:loadedPortal:clientOwnedID:'),
        },
        imports={
                 0x8bd98c: (17151904, 'objc_msgSend'),
                 0x8bd998: (16333432, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x8bd994: (17162236, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectDatabase', 36),
                 0x8bd9a4: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
        },
        classes={
                 0x8bd9a0: (15247792, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(9164476, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9164540, 'bge 0x8bd984'), (9164548, 'bl sym.objectTypeCanBeLoadedOnlyWhenClientOwnerOnline_int_'), (9164604, 'add r4, r4, r2'), (9164716, 'blx r5'), (9165236, 'rsbseq r2, sl, r0, lsr 8')],
        calls=[(9164548, 'bl sym.objectTypeCanBeLoadedOnlyWhenClientOwnerOnline_int_'), (9164716, 'blx r5'), (9164760, 'blx ip'), (9164868, 'blx r2'), (9164912, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (9165056, 'blx ip'), (9165152, 'blx lr')],
        branches=[(9164540, 'bge', 9165188), (9164560, 'beq', 9165168), (9164780, 'beq', 9165164), (9164932, 'beq', 9165160), (9164952, 'bne', 9165160), (9164968, 'bne', 9165064), (9165060, 'b', 9165156), (9165156, 'b', 9165160), (9165160, 'b', 9165164), (9165164, 'b', 9165168), (9165168, 'b', 9165172), (9165184, 'b', 9164532)],
        semantics=('loadClientOwnedDynamicObjectsForClient:physicalBlock: loads the objects owned by a client. Prologue 0x008bd6bc (frame 0x80; base 0x105faf4).\nGate: `if (objectType >= 0x41) return` (@0x8bd6f8-0x8bd6fc); **`objectTypeCanBeLoadedOnlyWhenClientOwnerOnline(int)`** (C call @0x8bd704) must hold (@0x8bd70c-0x8bd710).\nLoad: the ffffe508 tracker + the **0xfff33f84** string (cell 0x8bd998) + ffe2aebc/ffe231d4 (@0x8bd714-0x8bd7ac) resolve the client-owned objects; the world chain ffffe4e4 + ffe232b0 (@0x8bd7f0-0x8bd814) completes.\n'),
    ),
    dict(
        name='wtl_finishsimulating',
        method='DynamicWorld -[finishSimulating]',
        types='v8@0:4',
        start=9223308,
        end=9224000,
        disasm='disasm_worldtileloader_finishsimulating.txt',
        base_add=9223324,
        base_literal=9223996,
        boundary='ARM.exidx end 0x008cbf40 (listing bound); next ObjC IMP 0x008cbf40 DynamicWorld -[update:accurateDT:isSimulation:]',
        selectors={
                 0x8cbf28: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8cbf30: (15216112, 'setInventoryNeedsSaving:'),
                 0x8cbf34: (15216108, 'saveBlockheadInventory:'),
                 0x8cbf38: (15216620, 'inventoryWasChanged:subIndex:wasUsage:'),
        },
        imports={
                 0x8cbf24: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8cbf2c: (17162220, 'OBJC_IVAR_$_DynamicWorld.blockheads', 44),
        },
        classes={},
        instructions=[(9223308, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9223356, 'ldr r6, [0x008cbf2c]'), (9223584, 'bl sym.imp.objc_enumerationMutation'), (9223636, 'bge 0x8cbe34'), (9223660, 'ldr ip, [0x008cbf38]'), (9223996, 'rsbseq r3, sb, r0, asr lr')],
        calls=[(9223420, 'bl sym.imp.memset'), (9223484, 'blx lr'), (9223584, 'bl sym.imp.objc_enumerationMutation'), (9223712, 'blx lr'), (9223808, 'blx lr'), (9223836, 'blx r3'), (9223936, 'blx ip')],
        branches=[(9223496, 'beq', 9223960), (9223576, 'beq', 9223588), (9223636, 'bge', 9223732), (9223728, 'b', 9223628), (9223864, 'blo', 9223540), (9223956, 'bne', 9223540), (9223960, 'b', 9223964)],
        semantics=('finishSimulating finishes a simulation step. Prologue 0x008cbc8c (frame 0xe8; base 0x105faf4).\nEnumerate: the **ffffe4f8 blockheads** collection (@0x8cbcbc) is enumerated (fast-enumeration walk + mutation guard @0x8cbda0).\nInner: `movw lr, 0x10` + the `cmp r0, 8` 8-slot loop (@0x8cbdd0-0x8cbdd4); per item the **ffe234f8** call (cell 0x8cbf38, @0x8cbdec) runs - the per-blockhead 8-slot finalisation.\n'),
    ),
    dict(
        name='wtl_removesavedinventoryfo',
        method='DynamicWorld -[removeSavedInventoryForChest:]',
        types='v12@0:4@8',
        start=9145792,
        end=9146308,
        disasm='disasm_worldtileloader_removesavedinventoryforchest_.txt',
        base_add=9145808,
        base_literal=9146304,
        boundary='ARM.exidx end 0x008b8fc4 (listing bound); next ObjC IMP 0x008b8fc4 DynamicWorld -[loadLocalInventoryDataForChest:]',
        selectors={
                 0x8b8fa0: (15216012, 'pos'),
                 0x8b8fac: (15216236, 'safeRemoveFromDynamicObjectDatabase:'),
                 0x8b8fb8: (15215816, 'stringWithFormat:'),
                 0x8b8fbc: (15216160, 'uniqueID'),
        },
        imports={
                 0x8b8fa8: (17151904, 'objc_msgSend'),
                 0x8b8fb0: (16333288, '__CFConstantStringClassReference'),
        },
        ivars={},
        classes={
                 0x8b8fa4: (15247792, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(9145792, 'push {r4, sl, fp, lr}'), (9145892, 'bl loc.imp.objc_msgSend_stret'), (9145972, 'bl sym.imp.__aeabi_idiv'), (9146084, 'ldr r3, [0x008b8fb0]'), (9146156, 'str r0, [sp, 0x14]'), (9146304, 'rsbseq r6, sl, ip, lsl sp')],
        calls=[(9145892, 'bl loc.imp.objc_msgSend_stret'), (9145928, 'bl sym.imp.memset'), (9145972, 'bl sym.imp.__aeabi_idiv'), (9146024, 'bl loc.imp.objc_msgSend_stret'), (9146060, 'bl sym.imp.memset'), (9146140, 'bl sym.imp.__aeabi_idiv'), (9146168, 'bl loc.imp.objc_msgSend'), (9146232, 'bl loc.imp.objc_msgSend'), (9146260, 'blx r3')],
        branches=[(9145876, 'beq', 9145900), (9145896, 'b', 9145932), (9146008, 'beq', 9146032), (9146028, 'b', 9146064)],
        semantics=("removeSavedInventoryForChest: removes a chest's saved inventory. Prologue 0x008b8dc0 (frame 0x88; base 0x105faf4).\nLocate: `[chest xPos]/[chest yPos]` (ffe23298 stret @0x8b8dd8-0x8b8e24) -> /32 (`__aeabi_idiv` @0x8b8e74) -> the ffe23378 + **0xfff33ef4** string (cell 0x8b8fb0 - the same string E31's loadLocalInventoryDataForChest: uses) + ffe2332c uniqueID (@0x8b8eec-0x8b8f2c) - the chest inventory removal (pair with E31's loader).\n"),
    ),
    dict(
        name='wtl_saferemovefromdynamico',
        method='DynamicWorld -[safeRemoveFromDynamicObjectDatabase:]',
        types='v12@0:4@8',
        start=9145432,
        end=9145792,
        disasm='disasm_worldtileloader_saferemovefromdynamicobjectdatabase_.txt',
        base_add=9145448,
        base_literal=9145788,
        boundary='ARM.exidx end 0x008b8dc0 (listing bound); next ObjC IMP 0x008b8dc0 DynamicWorld -[removeSavedInventoryForChest:]',
        selectors={
                 0x8b8da0: (15216232, 'removeItemAtPath:error:'),
                 0x8b8da4: (15215880, 'stringByAppendingPathComponent:'),
                 0x8b8dac: (15215824, 'defaultManager'),
                 0x8b8db4: (15216228, 'removeDataForKey:'),
        },
        imports={
                 0x8b8d9c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8b8da8: (17162196, 'OBJC_IVAR_$_DynamicWorld.worldSaveDirectory', 40),
                 0x8b8db8: (17162236, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectDatabase', 36),
        },
        classes={
                 0x8b8db0: (15247796, 'OBJC_CLASS_$_NSFileManager'),
        },
        instructions=[(9145432, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9145508, 'add r0, r0, r3'), (9145540, 'ldr r0, [0x008b8db8]'), (9145652, 'blx r2'), (9145684, 'ldr ip, [r3]'), (9145788, 'rsbseq r6, sl, r4, lsl 29')],
        calls=[(9145620, 'blx lr'), (9145652, 'blx r2'), (9145704, 'blx ip'), (9145740, 'blx ip')],
        branches=[],
        semantics=('safeRemoveFromDynamicObjectDatabase: safely removes an object from the dynamic-object database. Prologue 0x008b8c58 (frame 0x50; base 0x105faf4).\nChain: the ffffe4e0 + **ffffe508** database slots with the ffe23374/ffe23214/ffe231dc/ffe2aec0/ffe23370 calls (@0x8b8c7c-0x8b8d54) - the guarded removal (string-keyed db).\n'),
    ),
    dict(
        name='wtl_mainthreadremovedirfro',
        method='DynamicWorld -[mainThreadRemoveDirFromConversionList:]',
        types='v12@0:4@8',
        start=9102480,
        end=9102776,
        disasm='disasm_worldtileloader_mainthreadremovedirfromconversionlist_.txt',
        base_add=9102496,
        base_literal=9102772,
        boundary='ARM.exidx end 0x008ae5b8 (listing bound); next ObjC IMP 0x008ae5b8 DynamicWorld -[conversionThread:]',
        selectors={
                 0x8ae5a4: (15215864, 'count'),
                 0x8ae5ac: (15215860, 'removeObjectForKey:'),
                 0x8ae5b0: (15215852, 'release'),
        },
        imports={
                 0x8ae5a0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8ae5a8: (17162280, 'OBJC_IVAR_$_DynamicWorld.versionOneToTwoConversionList', 9464),
        },
        classes={},
        instructions=[(9102480, 'push {r4, r5, r6, sl, fp, lr}'), (9102520, 'ldr r5, [0x008ae5a8]'), (9102560, 'ldr r0, [r0]'), (9102636, 'blx r3'), (9102716, 'blx r3'), (9102772, 'rsbseq r1, fp, ip, asr 12')],
        calls=[(9102600, 'blx ip'), (9102636, 'blx r3'), (9102716, 'blx r3')],
        branches=[(9102644, 'bne', 9102744)],
        semantics=('mainThreadRemoveDirFromConversionList: removes a directory from the conversion list on the main thread. Prologue 0x008ae490 (frame 0x38; base 0x105faf4).\nChain: the **ffffe534** member + ffe23204/ffe23200/ffe231f8 calls (@0x8ae4b0-0x8ae57c) - the dispatch-based list removal.\n'),
    ),
    dict(
        name='wtl_removeportalfromlistat',
        method='DynamicWorld -[removePortalFromListAtPos:]',
        types='v16@0:4{?=ii}8',
        start=9145216,
        end=9145432,
        disasm='disasm_worldtileloader_removeportalfromlistatpos_.txt',
        base_add=9145232,
        base_literal=9145428,
        boundary='ARM.exidx end 0x008b8c58 (listing bound); next ObjC IMP 0x008b8c58 DynamicWorld -[safeRemoveFromDynamicObjectDatabase:]',
        selectors={
                 0x8b8c44: (15216224, 'removeIndex:'),
        },
        imports={
                 0x8b8c40: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8b8c48: (17162204, 'OBJC_IVAR_$_DynamicWorld.portalPositions', 7332),
                 0x8b8c50: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
        },
        classes={},
        instructions=[(9145216, 'push {fp, lr}'), (9145256, 'ldr r1, [0x008b8c48]'), (9145340, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9145384, 'mov r1, r3'), (9145428, 'rsbseq r6, sl, ip, asr pc')],
        calls=[(9145340, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9145396, 'blx r3')],
        branches=[],
        semantics=("removePortalFromListAtPos: removes a portal from the list at a position. Prologue 0x008b8b80 (frame 0x30; base 0x105faf4).\nBody: the **ffffe4e8 world-struct chain** (@0x8b8ba8-0x8b8be0) + `worldIndexAtWorldPos(intpair, World*)` (@0x8b8bfc) + the **ffe2336c call** (cell 0x8b8c44) - the portal-list remover (the ffe2336c pair with E35's portalIsBeingRemovedAtPos: query, and the counterpart of the portalPositions getter).\n"),
    ),
    dict(
        name='wtl_simulate_',
        method='DynamicWorld -[simulate:]',
        types='v12@0:4f8',
        start=9213760,
        end=9214112,
        disasm='disasm_worldtileloader_simulate_.txt',
        base_add=9213776,
        base_literal=9213964,
        boundary='ARM.exidx end 0x008c98a0 (listing bound); next ObjC IMP 0x008c9810 DynamicWorld -[update:accurateDT:]',
        selectors={
                 0x8c9808: (15216604, 'update:accurateDT:isSimulation:'),
                 0x8c9898: (15216604, 'update:accurateDT:isSimulation:'),
        },
        imports={
                 0x8c9804: (17151904, 'objc_msgSend'),
                 0x8c9894: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9213760, 'push {fp, lr}'), (9213788, 'movw ip, 8'), (9213816, 'vstr s0, [fp, -0x10]'), (9213844, 'bge 0x8c97fc'), (9213928, 'blx lr'), (9214108, 'rsbseq r6, sb, ip, asr 5')],
        calls=[(9213928, 'blx lr'), (9214088, 'blx lr')],
        branches=[(9213844, 'bge', 9213948), (9213944, 'b', 9213836)],
        semantics=('simulate: steps the world simulation by a delta time. Prologue 0x008c9740 (frame 0x30; base 0x105faf4). Argument: the delta float (r2).\nMath: the float is divided by **8.0** (`vmov.f32 s2, 8; vdiv.f32 s0, s0, s2` @0x8c9760-0x8c9778) - the per-family step.\nLoop: `for arg in 0..8` (@0x8c9790-0x8c9794): the **ffe234e8** call per family (cell 0x8c9808, @0x8c97a8-0x8c97e8) with the divided float (paired vldr s0/s2) + the sxtb flag; the counter increments (@0x8c97f0) - the 8-family simulator.\n'),
    ),
    dict(
        name='wtl_update_accuratedt_',
        method='DynamicWorld -[update:accurateDT:]',
        types='v16@0:4f8f12',
        start=9213968,
        end=9214112,
        disasm='disasm_worldtileloader_update_accuratedt_.txt',
        base_add=9213984,
        base_literal=9214108,
        boundary='ARM.exidx end 0x008c98a0 (listing bound); next ObjC IMP 0x008c98a0 DynamicWorld -[hasDynamicObjectsToSaveInMacroPos:]',
        selectors={
                 0x8c9898: (15216604, 'update:accurateDT:isSimulation:'),
        },
        imports={
                 0x8c9894: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9213968, 'push {fp, lr}'), (9213988, 'vmov s0, r3'), (9214060, 'vmov ip, s2'), (9214088, 'blx lr'), (9214108, 'rsbseq r6, sb, ip, asr 5')],
        calls=[(9214088, 'blx lr')],
        branches=[],
        semantics=('update:accurateDT: updates with the accurate delta time. Prologue 0x008c9810 (frame 0x28; base 0x105faf4). Args: delta floats (r2/r3).\nBody: the same **ffe234e8** call (cell 0x8c9898, @0x8c983c-0x8c9888) with both floats passed (paired vmov/vstr) + the sxtb flag - the update wrapper over the family step.\n'),
    ),
    dict(
        name='wtl_setserver_serverclient',
        method='DynamicWorld -[setServer:serverClients:]',
        types='v16@0:4@8@12',
        start=9097908,
        end=9098016,
        disasm='disasm_worldtileloader_setserver_serverclients_.txt',
        base_add=9097920,
        base_literal=9098012,
        boundary='ARM.exidx end 0x008ad320 (listing bound); next ObjC IMP 0x008ad320 DynamicWorld -[dealloc]',
        selectors={},
        imports={},
        ivars={
                 0x8ad314: (17162248, 'OBJC_IVAR_$_DynamicWorld.serverClients', 24),
                 0x8ad318: (17162256, 'OBJC_IVAR_$_DynamicWorld.server', 16),
        },
        classes={},
        instructions=[(9097908, 'push {r4, lr}'), (9097924, 'ldr lr, [0x008ad314]'), (9097972, 'str r0, [r1]'), (9097992, 'str r0, [r1]'), (9098012, 'rsbseq r2, fp, ip, lsr 16')],
        calls=[],
        branches=[],
        semantics=('setServer:serverClients: sets the server and serverClients slots. Prologue 0x008ad2b4 (frame 0x18; base 0x105faf4).\nBody: the server argument is stored to **ffffe51c** (`str r0, [r1]` @0x8ad2f4) and the serverClients argument to **ffffe514** (`str r0, [r1]` @0x8ad308) - the two-slot setter that confirms the ffffe51c=server / ffffe514=serverClients pair via the writes.\n'),
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
        'batch': 'DynamicWorld save/remote/simulate cluster (E40): saveDynamicObjects, remoteCreate:forObjectsOfType:clientID:, loadClientOwnedDynamicObjectsForClient:physicalBlock:, finishSimulating, removeSavedInventoryForChest:, safeRemoveFromDynamicObjectDatabase:, mainThreadRemoveDirFromConversionList:, removePortalFromListAtPos:, simulate:, update:accurateDT: and setServer:serverClients:; 11 bodies',
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
                        default=NATIVE / 'save_remote_sim.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale save_remote_sim.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
