#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld load/session smalls (E31).

The DynamicWorld load/session smalls: the kicked-client action stopper, the
client found-list receiver, the debug-log appender, the explore-light channel
recorder, the chest local-inventory loader, the ridable-object lookup cascade
and the standard-object loader:
1 body, 1671 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/LOAD_SESSION.md for the prose and boundaries.
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
    'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_': 0x008bcf24,
    'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_': 0x008bcb78,
    'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const': 0x00910a74,
    'bl method.void_std::__1::vector_intpair__std::__1::allocator_intpair___.__push_back_slow_path_intpair_const__intpair_const_': 0x0052d84c,
    'bl sym.classForDynamicObjectType_int_': 0x00b597bc,
    'bl sym.imp.NSStringFromClass': 0x001c2e1c,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.objectTypeHasStaticPosition_int_': 0x008b68ac,
    'bl sym.worldIndexAtWorldPos_intpair__World_': 0x00a15838,
}

SPECS = [
    dict(
        name='wtl_stopallblockheadaction',
        method='DynamicWorld -[stopAllBlockheadActionsForClientDueToKick:]',
        types='v12@0:4@8',
        start=9404680,
        end=9405856,
        disasm='disasm_worldtileloader_stopallblockheadactionsforclientduetokic.txt',
        base_add=9404696,
        base_literal=9405852,
        boundary='ARM.exidx end 0x008f85a0 (listing bound); next ObjC IMP 0x008f85a0 DynamicWorld -[clientDisconnected:simulate:]',
        selectors={
                 0x8f8584: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8f858c: (15216280, 'isEqualToString:'),
                 0x8f8590: (15216440, 'clientID'),
                 0x8f8594: (15217120, 'stopAllActions'),
        },
        imports={
                 0x8f8580: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8f8588: (17162216, 'OBJC_IVAR_$_DynamicWorld.netBlockheads', 48),
                 0x8f8598: (17162212, 'OBJC_IVAR_$_DynamicWorld.netBlockheadsWithDisconnectedClients', 52),
        },
        classes={},
        instructions=[(9404680, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9404728, 'ldr r7, [0x008f8588]'), (9404988, 'ldr ip, [0x008f8590]'), (9405076, 'sxtb r0, r0'), (9405100, 'ldr r2, [0x008f8594]'), (9405852, 'ldrsbteq r7, [r6], -0x94')],
        calls=[(9404796, 'bl sym.imp.memset'), (9404860, 'blx lr'), (9404960, 'bl sym.imp.objc_enumerationMutation'), (9405052, 'blx ip'), (9405072, 'blx r3'), (9405128, 'blx r2'), (9405232, 'blx ip'), (9405352, 'bl sym.imp.memset'), (9405416, 'blx lr'), (9405516, 'bl sym.imp.objc_enumerationMutation'), (9405608, 'blx ip'), (9405628, 'blx r3'), (9405684, 'blx r2'), (9405788, 'blx ip')],
        branches=[(9404872, 'beq', 9405256), (9404952, 'beq', 9404964), (9405084, 'beq', 9405132), (9405132, 'b', 9405136), (9405160, 'blo', 9404916), (9405252, 'bne', 9404916), (9405256, 'b', 9405260), (9405428, 'beq', 9405812), (9405508, 'beq', 9405520), (9405640, 'beq', 9405688), (9405688, 'b', 9405692), (9405716, 'blo', 9405472), (9405808, 'bne', 9405472), (9405812, 'b', 9405816)],
        semantics=("stopAllBlockheadActionsForClientDueToKick: stops the actions of a kicked client's blockheads. Prologue 0x008f8108 (frame 0x1a8; base 0x105faf4).\nEnumerate: the **ffffe4f4 netBlockheads collection** (@0x8f8138) is enumerated (the NSFastEnumeration walk with the mutation guard @0x8f8220); per blockhead `[bh clientID]` (ffe23444 @0x8f823c) is compared with the client argument; a match calls the **ffe236ec stop-all-actions selector** (@0x8f82ac) with the sxtb-processed result (@0x8f8294-0x8f829c).\n"),
    ),
    dict(
        name='wtl_newfoundlistrecievedfr',
        method='DynamicWorld -[newFoundListRecievedFromClient:list:]',
        types='v16@0:4@8@12',
        start=9416080,
        end=9417064,
        disasm='disasm_worldtileloader_newfoundlistrecievedfromclient_list_.txt',
        base_add=9416096,
        base_literal=9417060,
        boundary='ARM.exidx end 0x008fb168 (listing bound); next ObjC IMP 0x008fb168 DynamicWorld -[clientBlockheadsRecievedForPlayerID:data:]',
        selectors={
                 0x8fb118: (15217140, 'foundItemsList'),
                 0x8fb11c: (15215884, 'objectForKey:'),
                 0x8fb128: (15215816, 'stringWithFormat:'),
                 0x8fb130: (15215976, 'addIndexes:'),
                 0x8fb134: (15217144, 'removeAllIndexes'),
                 0x8fb138: (15216092, 'setData:forKey:'),
                 0x8fb140: (15215852, 'release'),
                 0x8fb144: (15216084, 'finishEncoding'),
                 0x8fb14c: (15216080, 'encodeObject:forKey:'),
                 0x8fb150: (15216076, 'initForWritingWithMutableData:'),
                 0x8fb154: (15215804, 'alloc'),
                 0x8fb15c: (15216072, 'data'),
        },
        imports={
                 0x8fb114: (17151904, 'objc_msgSend'),
                 0x8fb124: (16333960, '__CFConstantStringClassReference'),
                 0x8fb148: (16333976, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x8fb120: (17162248, 'OBJC_IVAR_$_DynamicWorld.serverClients', 24),
                 0x8fb13c: (17162240, 'OBJC_IVAR_$_DynamicWorld.worldDatabase', 32),
        },
        classes={
                 0x8fb12c: (15247792, 'OBJC_CLASS_$_NSString'),
                 0x8fb158: (15247848, 'OBJC_CLASS_$_NSKeyedArchiver'),
                 0x8fb160: (15247844, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(9416080, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9416136, 'ldr sl, [0x008fb120]'), (9416148, 'ldr r0, [0x008fb124]'), (9416540, 'cmp r0, r1'), (9416972, 'sub sp, fp, 0x18'), (9417060, 'rsbseq r4, r6, ip, asr 26')],
        calls=[(9416316, 'blx r7'), (9416332, 'blx r2'), (9416348, 'blx r2'), (9416388, 'blx ip'), (9416404, 'blx r2'), (9416424, 'blx r3'), (9416464, 'blx ip'), (9416508, 'blx ip'), (9416524, 'blx r2'), (9416780, 'blx r2'), (9416816, 'blx r3'), (9416836, 'blx r3'), (9416880, 'blx ip'), (9416900, 'blx r2'), (9416920, 'blx r2'), (9416964, 'blx lr')],
        branches=[(9416544, 'beq', 9416972)],
        semantics=("newFoundListRecievedFromClient:list: receives a client's newly-found-items list. Prologue 0x008fad90 (frame 0xc8; base 0x105faf4).\nSetup: the arg chain reads the ffffe514 **serverClients** member (@0x8fadc8) + ffe23700/ffe23218 dispatch cells; the `stringWithFormat:` key uses 0xfff34194 (cell 0x8fb124 @0x8fadd4) and the walk (ffe231d4/ffe2aebc/ffe23274 creation cells) builds the per-client message; the string compare (`isEqualToString:`-family, @0x8faf5c `cmp r0, r1; beq 0x8fb10c`) gates the list processing tail (the loop over the received list @0x8fb0xx region, joining the client's known-found set).\n"),
    ),
    dict(
        name='wtl_appenddebuglog_',
        method='DynamicWorld -[appendDebugLog:]',
        types='v12@0:4@8',
        start=9448236,
        end=9449216,
        disasm='disasm_worldtileloader_appenddebuglog_.txt',
        base_add=9448252,
        base_literal=9449212,
        boundary='ARM.exidx end 0x00902f00 (listing bound); next ObjC IMP 0x00902f00 DynamicWorld -[blockheads]',
        selectors={
                 0x902ecc: (15217328, 'appendFormat:'),
                 0x902ed0: (15215864, 'count'),
                 0x902ef4: (15216136, 'class'),
        },
        imports={
                 0x902ec4: (16334184, '__CFConstantStringClassReference'),
                 0x902ec8: (17151904, 'objc_msgSend'),
                 0x902ed8: (16334168, '__CFConstantStringClassReference'),
                 0x902ee0: (16334152, '__CFConstantStringClassReference'),
                 0x902ee8: (16334136, '__CFConstantStringClassReference'),
                 0x902ef0: (16334120, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x902ed4: (17162212, 'OBJC_IVAR_$_DynamicWorld.netBlockheadsWithDisconnectedClients', 52),
                 0x902edc: (17162216, 'OBJC_IVAR_$_DynamicWorld.netBlockheads', 48),
                 0x902ee4: (17162220, 'OBJC_IVAR_$_DynamicWorld.blockheads', 44),
                 0x902eec: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
        },
        classes={},
        instructions=[(9448236, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9448288, 'cmp r0, 0x41'), (9448328, 'mul r0, r3, r0'), (9448388, 'ble 0x902cf0'), (9448600, 'bl sym.imp.NSStringFromClass'), (9448684, 'blx lr'), (9449212, 'ldrhteq ip, [r5], -0xf0')],
        calls=[(9448596, 'blx r2'), (9448600, 'bl sym.imp.NSStringFromClass'), (9448684, 'blx lr'), (9448880, 'blx sl'), (9448932, 'blx ip'), (9448968, 'blx ip'), (9449020, 'blx ip'), (9449056, 'blx ip'), (9449108, 'blx ip'), (9449144, 'blx ip')],
        branches=[(9448292, 'bge', 9448708), (9448388, 'ble', 9448688), (9448688, 'b', 9448692), (9448704, 'b', 9448284)],
        semantics=("appendDebugLog: appends a dynamic-object debug line. Prologue 0x00902b2c (frame 0xe8; base 0x105faf4). Argument: the object type (r0).\nGate: `if (objectType >= 0x41) return` (@0x902b60).\nWalk: `for i in 0..0x41`, the **ffffe54c member's 12-byte segments** (`movw r0, 0xc; mul` @0x902b68-0x902b88); the segment's count at +8 must be > 0 (@0x902bc0-0x902bc4); then **`NSStringFromClass`** (@0x902c98) + the 0xfff34234 format (cell 0x902ef0) + the ffe237bc call (cell 0x902ecc) log the entry (@0x902cec).\n"),
    ),
    dict(
        name='wtl_explorelightchangedatm',
        method='DynamicWorld -[exploreLightChangedAtMacroPos:clientLightBlockIndex:]',
        types='v20@0:4{?=ii}8i16',
        start=9312172,
        end=9313128,
        disasm='disasm_worldtileloader_explorelightchangedatmacropos_clientligh.txt',
        base_add=9312188,
        base_literal=9313124,
        boundary='ARM.exidx end 0x008e1b68 (listing bound); next ObjC IMP 0x008e1b68 DynamicWorld -[lightChangedAtMacroPos:sendReliably:]',
        selectors={
                 0x8e1b5c: (15216376, 'lightChangedAtMacroPos:sendReliably:'),
        },
        imports={},
        ivars={
                 0x8e1b58: (17162336, 'OBJC_IVAR_$_DynamicWorld.lightChangedSendUnreliablyMacroPositionsSingleClient', 6120),
        },
        classes={},
        instructions=[(9312172, 'push {r4, r5, r6, r7, fp, lr}'), (9312220, 'cmn r0, 1'), (9312256, 'ldr r2, [0x008e1b60]'), (9312352, 'add r1, r2, r1'), (9312680, 'movw r0, 1'), (9313124, 'rsbseq lr, r7, r0, lsr r3')],
        calls=[(9312288, 'bl loc.imp.objc_msgSend'), (9313092, 'bl method.void_std::__1::vector_intpair__std::__1::allocator_intpair___.__push_back_slow_path_intpair_const__intpair_const_')],
        branches=[(9312228, 'bne', 9312296), (9312292, 'b', 9313104), (9312612, 'beq', 9312756), (9312660, 'bne', 9312692), (9312676, 'bne', 9312692), (9312688, 'b', 9312756), (9312692, 'b', 9312696), (9312752, 'b', 9312424), (9312764, 'bne', 9313100), (9312872, 'beq', 9313084), (9313020, 'beq', 9313064), (9313080, 'b', 9313096), (9313096, 'b', 9313100), (9313100, 'b', 9313104)],
        semantics=("exploreLightChangedAtMacroPos:clientLightBlockIndex: records an exploration-light change for a light channel. Prologue 0x008e17ac (frame 0x150; base 0x105faf4). Args: macro pos (intpair), channel index.\nSpecial arm: `if (channel == -1)` (`cmn r0, 1` @0x8e17dc) -> the ffe23404 call with argument 0 (@0x8e17fc-0x8e1824).\nGeneral arm: the **ffffe56c member's 12-byte light-channel structs** (`movw r1, 0xc; mul` @0x8e182c-0x8e1860): the per-channel entry is scanned and its touched/dedup bytes set (the strb at sp+0x3f @0x8e1844, the set from @0x8e19a8) - the changed-flag record feeding the E28 sendLightblocksToClients queue.\nBoundary: ffffe56c is the 32-entry light-channel array sized by E29's destructor (0x180/12 = 32).\n"),
    ),
    dict(
        name='wtl_loadlocalinventorydata',
        method='DynamicWorld -[loadLocalInventoryDataForChest:]',
        types='@12@0:4@8',
        start=9146308,
        end=9147196,
        disasm='disasm_worldtileloader_loadlocalinventorydataforchest_.txt',
        base_add=9146324,
        base_literal=9147192,
        boundary='ARM.exidx end 0x008b933c (listing bound); next ObjC IMP 0x008b933c DynamicWorld -[saveDynamicObjectsForMacroTile:objectType:xPos:yPos:]',
        selectors={
                 0x8b92fc: (15216012, 'pos'),
                 0x8b9308: (15215900, 'dataForKey:'),
                 0x8b9318: (15215816, 'stringWithFormat:'),
                 0x8b931c: (15216160, 'uniqueID'),
                 0x8b9320: (15216240, 'hasFinishedDatabaseMigrationTo17'),
                 0x8b9328: (15215904, 'dataWithContentsOfFile:'),
                 0x8b932c: (15215880, 'stringByAppendingPathComponent:'),
        },
        imports={
                 0x8b9304: (17151904, 'objc_msgSend'),
                 0x8b9310: (16333288, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x8b930c: (17162236, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectDatabase', 36),
                 0x8b9324: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8b9330: (17162196, 'OBJC_IVAR_$_DynamicWorld.worldSaveDirectory', 40),
        },
        classes={
                 0x8b9300: (15247792, 'OBJC_CLASS_$_NSString'),
                 0x8b9334: (15247812, 'OBJC_CLASS_$_NSData'),
        },
        instructions=[(9146308, 'push {r4, r5, r6, r7, fp, lr}'), (9146408, 'bl loc.imp.objc_msgSend_stret'), (9146488, 'bl sym.imp.__aeabi_idiv'), (9146628, 'ldr r5, [0x008b931c]'), (9146832, 'cmp r0, r1'), (9147192, 'rsbseq r6, sl, r8, lsl fp')],
        calls=[(9146408, 'bl loc.imp.objc_msgSend_stret'), (9146444, 'bl sym.imp.memset'), (9146488, 'bl sym.imp.__aeabi_idiv'), (9146540, 'bl loc.imp.objc_msgSend_stret'), (9146576, 'bl sym.imp.memset'), (9146680, 'bl sym.imp.__aeabi_idiv'), (9146708, 'bl loc.imp.objc_msgSend'), (9146772, 'bl loc.imp.objc_msgSend'), (9146816, 'blx ip'), (9146912, 'blx r2'), (9147040, 'blx lr'), (9147072, 'blx r3')],
        branches=[(9146392, 'beq', 9146416), (9146412, 'b', 9146448), (9146524, 'beq', 9146548), (9146544, 'b', 9146580), (9146836, 'beq', 9146852), (9146848, 'b', 9147120), (9146924, 'bne', 9147112), (9147092, 'beq', 9147108), (9147104, 'b', 9147120), (9147108, 'b', 9147112)],
        semantics=("loadLocalInventoryDataForChest: loads the local inventory of a chest. Prologue 0x008b8fc4 (frame 0xc0; base 0x105faf4). Argument: the chest.\nLocate: `[chest xPos]`/`[chest yPos]` (ffe23298 stret @0x8b8fdc-0x8b9028) -> /32 (`__aeabi_idiv` @0x8b9078) -> the ffffe508 + `worldIndexAtWorldPos` locator; `[chest uniqueID]` (ffe2332c @0x8b9104) and the 0xfff33ef4 string (cell 0x8b9310) feed the compare walk (@0x8b91d0 `cmp r0, r1; beq 0x8b91e4`): the tracker entry for the chest's world index is resolved and its inventory data applied.\n"),
    ),
    dict(
        name='wtl_ridableobjectwithid_',
        method='DynamicWorld -[ridableObjectWithID:]',
        types='@16@0:4Q8',
        start=9408460,
        end=9409324,
        disasm='disasm_worldtileloader_ridableobjectwithid_.txt',
        base_add=9408476,
        base_literal=9409320,
        boundary='ARM.exidx end 0x008f932c (listing bound); next ObjC IMP 0x008f932c DynamicWorld -[blockheadWithIDIncludingNet:]',
        selectors={
                 0x8f9324: (15217128, 'trainCarWithID:'),
        },
        imports={},
        ivars={
                 0x8f9320: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
        },
        classes={},
        instructions=[(9408460, 'push {r4, sl, fp, lr}'), (9408544, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9408588, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_'), (9408652, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9408868, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9408976, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9409320, 'rsbseq r6, r6, r0, lsl fp')],
        calls=[(9408544, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9408588, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_'), (9408652, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9408696, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_'), (9408760, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9408804, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_'), (9408868, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9408912, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_'), (9408976, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9409020, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_'), (9409084, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9409128, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_'), (9409192, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9409236, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_const_'), (9409292, 'bl loc.imp.objc_msgSend')],
        branches=[(9408552, 'beq', 9408604), (9408600, 'b', 9409300), (9408660, 'beq', 9408712), (9408708, 'b', 9409300), (9408768, 'beq', 9408820), (9408816, 'b', 9409300), (9408876, 'beq', 9408928), (9408924, 'b', 9409300), (9408984, 'beq', 9409036), (9409032, 'b', 9409300), (9409092, 'beq', 9409144), (9409140, 'b', 9409300), (9409200, 'beq', 9409252), (9409248, 'b', 9409300)],
        semantics=("ridableObjectWithID: resolves a ridable (mount/vehicle) object by uniqueID. Prologue 0x008f8fcc (frame 0x60; base 0x105faf4).\nCascade: the **ffffe54c member's 0x150 slice** `__count_unique(u64)` (@0x8f9020): hit -> `map<u64, DynamicObject*>::operator[]` (@0x8f904c) returns the object; miss -> the **+0x2f4 slice** (@0x8f908c) -> hit returns (@0x8f90b8); miss -> the **+0x9c slice** (@0x8f90f8) -> the **+0x264 slice** (@0x8f9164) -> the **+0x1d4 slice** (@0x8f91d0)... each per-family map is probed with the same uniqueID; a full miss continues the chain (the remaining family slices the listing shows to 0x8f9314).\nBoundary: this body proves the ffffe54c member is the per-family map structure (65 segments; the 0x150/0x2f4/0x9c/0x264/0x1d4 offsets are the family slices seen as dispatch cells across E21/E24).\n"),
    ),
    dict(
        name='wtl_loadstandarddynamicobj',
        method='DynamicWorld -[loadStandardDynamicObjectOfType:atPos:]',
        types='@20@0:4i8{?=ii}12',
        start=9331280,
        end=9332116,
        disasm='disasm_worldtileloader_loadstandarddynamicobjectoftype_atpos_.txt',
        base_add=9331296,
        base_literal=9332112,
        boundary='ARM.exidx end 0x008e6594 (listing bound); next ObjC IMP 0x008e6594 DynamicWorld -[loadSurfaceBlockAtPos:]',
        selectors={
                 0x8e6568: (15216544, 'needsRemoved'),
                 0x8e6570: (15215804, 'alloc'),
                 0x8e657c: (15216800, 'initWithWorld:dynamicWorld:atPosition:cache:'),
                 0x8e6588: (15216160, 'uniqueID'),
        },
        imports={
                 0x8e6564: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8e6558: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8e6560: (17162312, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsByWorldPosIndex', 1620),
                 0x8e6578: (17162232, 'OBJC_IVAR_$_DynamicWorld.cache', 7336),
                 0x8e6580: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
        },
        classes={},
        instructions=[(9331280, 'push {r4, r5, r6, sl, fp, lr}'), (9331340, 'bl sym.objectTypeHasStaticPosition_int_'), (9331428, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9331504, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9331576, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9331672, 'bl sym.classForDynamicObjectType_int_'), (9331848, 'ldr ip, [0x008e6580]'), (9332112, 'rsbseq sb, r7, ip, lsl 17')],
        calls=[(9331340, 'bl sym.objectTypeHasStaticPosition_int_'), (9331428, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9331504, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9331576, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9331620, 'blx r3'), (9331672, 'bl sym.classForDynamicObjectType_int_'), (9331700, 'bl loc.imp.objc_msgSend'), (9331808, 'bl loc.imp.objc_msgSend'), (9331904, 'bl loc.imp.objc_msgSend'), (9331924, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9332020, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_')],
        branches=[(9331352, 'beq', 9331656), (9331512, 'beq', 9331652), (9331632, 'bne', 9331648), (9331644, 'b', 9332044), (9331648, 'b', 9331652), (9331652, 'b', 9331656), (9331828, 'beq', 9332036), (9331944, 'beq', 9332032), (9332032, 'b', 9332036)],
        semantics=("loadStandardDynamicObjectOfType:atPos: loads a standard dynamic object of a type at a position. Prologue 0x008e6250 (frame 0xa8; base 0x105faf4).\nStatic-position gate: **`objectTypeHasStaticPosition(int)`** (C call @0x8e628c) != 0 -> the position-keyed path: `worldIndexAtWorldPos(intpair, World*)` (world via ffffe4e4 @0x8e62b4-0x8e62e4) -> the **ffffe554 member's 12-byte segment** (`add r1, r1, r1, lsl 1` <<2 @0x8e6308-0x8e630c) `__count_unique(u64)` (@0x8e6330): hit -> `operator[](u64&&)` (@0x8e6378) -> the **ffe234ac gate** (@0x8e6388): loaded -> return the object (@0x8e63a4); the not-loaded or non-static case creates: **`classForDynamicObjectType(int)`** (C call @0x8e63d8) + alloc/init (ffe231c8 @0x8e63e0) + the packed create (dispatch ffe235ac @0x8e6434) + registration into the ffffe550 map (@0x8e6488+).\n"),
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
        'batch': 'DynamicWorld load/session smalls (E31): stopAllBlockheadActionsForClientDueToKick:, newFoundListRecievedFromClient:list:, appendDebugLog:, exploreLightChangedAtMacroPos:clientLightBlockIndex:, loadLocalInventoryDataForChest:, ridableObjectWithID: and loadStandardDynamicObjectOfType:atPos:; 7 bodies',
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
                        default=NATIVE / 'load_session.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale load_session.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
