#!/usr/bin/env python3
"""Hash-gated recovery of the PortalChestManager closure batch (E11).

Closes the PortalChestManager class (the server-backed portal chest):
14 bodies, 3820 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/TRADE_PORTAL_ECON.md for the prose and boundaries.
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
    'bl 0x95894c': 0x0095894c,
    'bl 0x95926c': 0x0095926c,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.std::__1::__tree_int__std::__1::less_int___std::__1::allocator_int___.__insert_unique_int_const_': 0x0095baf4,
    'bl method.std::__1::__tree_int__std::__1::less_int___std::__1::allocator_int___.__tree_std::__1::less_int__const_': 0x006ea460,
    'bl method.std::__1::set_int__std::__1::less_int___std::__1::allocator_int___._set__': 0x006e9bf8,
    'bl sym.imp.NSLog': 0x001c2a5c,
    'bl sym.imp.NSSearchPathForDirectoriesInDomains': 0x001c3f20,
    'bl sym.imp._Unwind_Resume': 0x001c29c0,
    'bl sym.imp.__stack_chk_fail': 0x001c28b8,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.itemTypeIsStackable_ItemType__unsigned_short__unsigned_short_': 0x004ea3cc,
}

SPECS = [
    dict(
        name='pcm_initwithworld_',
        method='PortalChestManager -[initWithWorld:]',
        types='@12@0:4@8',
        start=9797044,
        end=9800012,
        disasm='disasm_portalchestmanager_initwithworld_.txt',
        base_add=9797060,
        base_literal=9800008,
        boundary='ARM.exidx end 0x0095894c; the next ObjC IMP (PortalChestManager -[dealloc]) is at 0x00958970, past 36 bytes of non-method code',
        selectors={
                 0x9588b0: (15219496, 'init'),
                 0x9588bc: (15219508, 'customRules'),
                 0x9588cc: (15219504, 'alloc'),
                 0x9588dc: (15219500, 'worldTime'),
                 0x9588e0: (15219520, 'dataWithContentsOfFile:'),
                 0x9588ec: (15219516, 'stringWithFormat:'),
                 0x9588f0: (15219512, 'objectAtIndex:'),
                 0x9588fc: (15219524, 'objectForKey:'),
                 0x958900: (15219552, 'client'),
                 0x958908: (15219556, 'saveID'),
                 0x95890c: (15219572, 'sendDataToServer:reliable:'),
                 0x958910: (15219568, 'appendBytes:length:'),
                 0x958914: (15219564, 'unsignedIntegerValue'),
                 0x95891c: (15219560, 'dataWithBytes:length:'),
                 0x95892c: (15219536, 'count'),
                 0x958930: (15219532, 'addObject:'),
                 0x958934: (15219528, 'array'),
                 0x958938: (15219540, 'countByEnumeratingWithState:objects:count:'),
                 0x95893c: (15219548, 'autorelease'),
                 0x958940: (15219544, 'initWithSaveData:'),
        },
        imports={
                 0x9588ac: (17151900, 'objc_msgSendSuper2'),
                 0x9588b8: (17151968, '__stack_chk_guard'),
                 0x9588c8: (17151904, 'objc_msgSend'),
                 0x9588e8: (16340392, '__CFConstantStringClassReference'),
                 0x9588f8: (16340408, '__CFConstantStringClassReference'),
                 0x958904: (16340424, '__CFConstantStringClassReference'),
                 0x958918: (16340440, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x9588c0: (17163028, 'OBJC_IVAR_$_PortalChestManager.world', 4),
                 0x9588c4: (17163032, 'OBJC_IVAR_$_PortalChestManager.portalChestInventoryItems', 8),
                 0x9588d4: (17163036, 'OBJC_IVAR_$_PortalChestManager.transactionIdentifierCount', 14),
                 0x958924: (17163040, 'OBJC_IVAR_$_PortalChestManager.pendingTransactionIsResend', 13),
                 0x958928: (17163044, 'OBJC_IVAR_$_PortalChestManager.pendingTransaction', 12),
        },
        classes={
                 0x9588b4: (15252936, 'OBJC_CLASS_$_PortalChestManager'),
                 0x9588d0: (15248324, 'OBJC_CLASS_$_NSMutableArray'),
                 0x9588e4: (15248332, 'OBJC_CLASS_$_NSData'),
                 0x9588f4: (15248328, 'OBJC_CLASS_$_NSString'),
                 0x958920: (15248340, 'OBJC_CLASS_$_NSMutableData'),
                 0x958944: (15248336, 'OBJC_CLASS_$_InventoryItem'),
        },
        instructions=[(9797044, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9797148, 'blx lr'), (9797300, 'str r8, [sl, r0]'), (9797372, 'vcvt.s32.f64 s2, d0'), (9797464, 'str r0, [r1]'), (9797528, 'bl loc.imp.objc_msgSend_stret'), (9797576, 'bne 0x958870'), (9797772, 'blx ip'), (9797912, 'blx r3'), (9798116, 'bne 0x958464'), (9798860, 'beq 0x95886c'), (9799508, 'strb r1, [r0]'), (9799532, 'strb r1, [r0]'), (9799780, 'blx ip'), (9800008, 'rsbseq r7, r0, r8, lsr 26')],
        calls=[(9797148, 'blx lr'), (9797364, 'bl loc.imp.objc_msgSend'), (9797428, 'blx ip'), (9797444, 'blx r2'), (9797528, 'bl loc.imp.objc_msgSend_stret'), (9797564, 'bl sym.imp.memset'), (9797616, 'bl sym.imp.NSSearchPathForDirectoriesInDomains'), (9797736, 'blx sl'), (9797772, 'blx ip'), (9797812, 'blx ip'), (9797844, 'bl 0x95894c'), (9797912, 'blx r3'), (9798044, 'blx r5'), (9798088, 'blx ip'), (9798108, 'blx r2'), (9798232, 'blx r7'), (9798256, 'bl sym.imp.memset'), (9798304, 'blx lr'), (9798404, 'bl sym.imp.objc_enumerationMutation'), (9798532, 'blx ip'), (9798552, 'blx r3'), (9798592, 'blx r3'), (9798624, 'blx r3'), (9798724, 'blx ip'), (9798848, 'blx r3'), (9798900, 'bl sym.imp.NSSearchPathForDirectoriesInDomains'), (9799060, 'blx r3'), (9799108, 'blx ip'), (9799152, 'blx lr'), (9799200, 'blx r3'), (9799228, 'bl 0x95894c'), (9799612, 'blx ip'), (9799640, 'blx r3'), (9799656, 'blx r2'), (9799704, 'blx ip'), (9799740, 'blx r3'), (9799780, 'blx ip'), (9799848, 'bl sym.imp.__stack_chk_fail')],
        branches=[(9797176, 'bne', 9797192), (9797188, 'b', 9799800), (9797512, 'beq', 9797536), (9797532, 'b', 9797568), (9797576, 'bne', 9799792), (9797836, 'beq', 9797852), (9797940, 'bge', 9798776), (9798116, 'bne', 9798756), (9798316, 'beq', 9798748), (9798396, 'beq', 9798408), (9798652, 'blo', 9798360), (9798744, 'bne', 9798360), (9798748, 'b', 9798752), (9798752, 'b', 9798756), (9798756, 'b', 9798760), (9798772, 'b', 9797932), (9798860, 'beq', 9799788), (9799220, 'beq', 9799236), (9799248, 'beq', 9799784), (9799784, 'b', 9799788), (9799788, 'b', 9799792), (9799832, 'bne', 9799848)],
        semantics=('initWithWorld: wires the manager to its world and restores the on-disk chest. [super init] through objc_msgSendSuper2 (import cell 0x009588ac, selector cell 0x009588b0, class cell 0x009588b4, call 0x00957e1c); a nil result returns nil (0x00957e38/0x00957e44). self->world@4 = the argument (cell 0x009588c0 at 0x00957eb4); self->transactionIdentifierCount@14 = (uint16)[world worldTime] (the double is converted by vcvt.s32.f64 at 0x00957efc and stored with strh at 0x00957f14); self->portalChestInventoryItems@8 = [[NSMutableArray alloc] init] (class cell 0x009588d0 at 0x00957f58). It then reads [world customRules] with objc_msgSend_stret into a 64-byte slot (0x00957f98; memset 0x40 at 0x00957fa4 when world is nil) and returns self early when the first signed byte is non-zero (ldrsb 0x00957fc0, bne 0x00957fc8). Otherwise dirs = NSSearchPathForDirectoriesInDomains(14 = NSApplicationSupportDirectory, 1, YES) and path = [NSString stringWithFormat:@"%@/portalChest" (CFString 0x00f955a8), dirs[0]] (0x0095808c); data = [NSData dataWithContentsOfFile:path] (class cell 0x009588e4, 0x009580b4); saveItemSlots = [data objectForKey:@"saveItemSlots" (CFString 0x00f955b8)] (0x00958118). A 16-iteration loop (cmp #0x10 at 0x00958130) appends a fresh [NSMutableArray array] per slot (0x009581c8) and, only when [saveItemSlots count] == 16 (0x009581e0/0x009581e4), fast-enumerates that slot adding [[[InventoryItem alloc] initWithSaveData:item] autorelease] (0x00958398). Finally, only when [world client] != nil (beq 0x009584cc), it builds txPath = [NSString stringWithFormat:@"%@/saves/%@/portalChestTransaction" (0x00f955c8), dirs[0], [world saveID]] (0x009585f0) and, if that loads, arms a resend: pendingTransaction@12 = 1 (0x00958754), pendingTransactionIsResend@13 = 1 (0x0095876c), then [[world client] sendDataToServer:[NSMutableData dataWithBytes:&0x40 length:1] + appendBytes:&ident length:8] reliable:YES] (0x009587bc/0x00958818/0x00958864), where ident is the uint16 read from txData[@"identifier"]. Returns self (0x00958870); stack canary compared at 0x00958890.'),
    ),
    dict(
        name='pcm_dealloc',
        method='PortalChestManager -[dealloc]',
        types='v8@0:4',
        start=9800048,
        end=9800244,
        disasm='disasm_portalchestmanager_dealloc.txt',
        base_add=9800064,
        base_literal=9800240,
        boundary='consecutive IMPs: next method follows at 0x00958a34',
        selectors={
                 0x958a1c: (15219580, 'dealloc'),
                 0x958a28: (15219576, 'release'),
        },
        imports={
                 0x958a18: (17151900, 'objc_msgSendSuper2'),
                 0x958a24: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x958a2c: (17163032, 'OBJC_IVAR_$_PortalChestManager.portalChestInventoryItems', 8),
        },
        classes={
                 0x958a20: (15252936, 'OBJC_CLASS_$_PortalChestManager'),
        },
        instructions=[(9800048, 'push {r4, r5, r6, r7, fp, lr}'), (9800164, 'blx r5'), (9800204, 'blx r2'), (9800240, 'rsbseq r7, r0, ip, ror 2')],
        calls=[(9800164, 'blx r5'), (9800204, 'blx r2')],
        branches=[],
        semantics=("dealloc: releases portalChestInventoryItems@8 (ivar cell 0x00958a2c, objc_msgSend 'release' cell 0x00958a28 at 0x009589e4) and then calls objc_msgSendSuper2 dealloc (import cell 0x00958a18, selector cell 0x00958a1c, class cell 0x00958a20 at 0x00958a0c). Nothing else is released."),
    ),
    dict(
        name='pcm_savewithmainthreadbloc',
        method='PortalChestManager -[saveWithMainThreadBlock:]',
        types='v12@0:4c8',
        start=9800244,
        end=9802348,
        disasm='disasm_portalchestmanager_savewithmainthreadblock_.txt',
        base_add=9800260,
        base_literal=9802344,
        boundary='ARM.exidx end 0x0095926c; the next ObjC IMP (PortalChestManager -[saveAnyPendingDataToDisk]) is at 0x009593d8, past 364 bytes of non-method code',
        selectors={
                 0x9591fc: (15219508, 'customRules'),
                 0x95920c: (15219540, 'countByEnumeratingWithState:objects:count:'),
                 0x959214: (15219528, 'array'),
                 0x95921c: (15219584, 'dictionary'),
                 0x959224: (15219532, 'addObject:'),
                 0x959228: (15219588, 'saveData'),
                 0x959230: (15219592, 'setObject:forKey:'),
                 0x959238: (15219576, 'release'),
                 0x95923c: (15219604, 'retain'),
                 0x959240: (15219600, 'writeToFile:atomically:'),
                 0x959248: (15219516, 'stringWithFormat:'),
                 0x95924c: (15219512, 'objectAtIndex:'),
                 0x95925c: (15219596, 'raise:format:'),
        },
        imports={
                 0x959204: (17151968, '__stack_chk_guard'),
                 0x959208: (17151904, 'objc_msgSend'),
                 0x95922c: (16340408, '__CFConstantStringClassReference'),
                 0x959244: (16340392, '__CFConstantStringClassReference'),
                 0x959254: (16340472, '__CFConstantStringClassReference'),
                 0x959258: (16340488, '__CFConstantStringClassReference'),
                 0x959264: (16340456, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x959200: (17163028, 'OBJC_IVAR_$_PortalChestManager.world', 4),
                 0x959210: (17163032, 'OBJC_IVAR_$_PortalChestManager.portalChestInventoryItems', 8),
                 0x959234: (17163048, 'OBJC_IVAR_$_PortalChestManager.pendingSaveData', 16),
        },
        classes={
                 0x959218: (15248324, 'OBJC_CLASS_$_NSMutableArray'),
                 0x959220: (15248344, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x959250: (15248328, 'OBJC_CLASS_$_NSString'),
                 0x959260: (15248348, 'OBJC_CLASS_$_NSException'),
        },
        instructions=[(9800244, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9800308, 'strb r2, [fp, -0x69]'), (9800364, 'bl loc.imp.objc_msgSend_stret'), (9800412, 'bne 0x9591d4'), (9800684, 'blx lr'), (9801044, 'blx lr'), (9801612, 'blx lr'), (9801632, 'bl 0x95926c'), (9801716, 'ldr ip, [0x0095925c]'), (9801888, 'beq 0x959188'), (9802108, 'blx ip'), (9802344, 'rsbseq r7, r0, r8, lsr 1')],
        calls=[(9800364, 'bl loc.imp.objc_msgSend_stret'), (9800400, 'bl sym.imp.memset'), (9800560, 'blx r2'), (9800596, 'blx r3'), (9800620, 'bl sym.imp.memset'), (9800684, 'blx lr'), (9800784, 'bl sym.imp.objc_enumerationMutation'), (9800936, 'blx r2'), (9800976, 'blx r3'), (9800996, 'bl sym.imp.memset'), (9801044, 'blx lr'), (9801144, 'bl sym.imp.objc_enumerationMutation'), (9801244, 'blx ip'), (9801276, 'blx r3'), (9801376, 'blx ip'), (9801504, 'blx ip'), (9801612, 'blx lr'), (9801632, 'bl 0x95926c'), (9801684, 'bl sym.imp.NSLog'), (9801776, 'blx r4'), (9801852, 'blx r3'), (9801928, 'bl sym.imp.NSSearchPathForDirectoriesInDomains'), (9802036, 'blx r7'), (9802072, 'blx ip'), (9802108, 'blx ip'), (9802164, 'blx r2'), (9802232, 'bl sym.imp.__stack_chk_fail')],
        branches=[(9800348, 'beq', 9800372), (9800368, 'b', 9800404), (9800412, 'bne', 9802196), (9800696, 'beq', 9801528), (9800776, 'beq', 9800788), (9801056, 'beq', 9801400), (9801136, 'beq', 9801148), (9801304, 'blo', 9801100), (9801396, 'bne', 9801100), (9801400, 'b', 9801404), (9801404, 'b', 9801408), (9801432, 'blo', 9800740), (9801524, 'bne', 9800740), (9801528, 'b', 9801532), (9801652, 'bne', 9801672), (9801668, 'bne', 9801784), (9801780, 'b', 9802192), (9801888, 'beq', 9802120), (9802116, 'b', 9802188), (9802188, 'b', 9802192), (9802192, 'b', 9802196), (9802220, 'bne', 9802232)],
        semantics=('saveWithMainThreadBlock: takes a char/BOOL (types v12@0:4c8), not a block: the argument is stored on the stack at 0x00958a74 and only read at 0x009590a0, and the body contains no NSOperationQueue/addOperationWithBlock: - the CrystalManager block idiom is explicitly NOT used here. It gate-returns when [world customRules] (stret into 64 bytes at 0x00958aac, memset 0 when world is nil at 0x00958ad0) has a non-zero first byte (bne 0x00958adc). Otherwise dict = [NSMutableDictionary dictionary] (0x00958b70) and slots = [NSMutableArray array] (0x00958b94); it nested-fast-enumerates self->portalChestInventoryItems@8 (outer state at fp-0x98, count 16, 0x00958bec) creating one [NSMutableArray array] per slot (0x00958ce8/0x00958d10) and appending each inner entry\'s saveData to it (inner enumeration 0x00958d54, \'saveData\' 0x00958e1c/0x00958e3c); then [dict setObject:slots forKey:@"saveItemSlots" (CFString 0x00f955b8)] (0x00958f8c). The dictionary is serialised by the out-of-body plist encoder at 0x00958fa0 (bl 0x95926c - the same helper the transaction request uses); a nil result NSLogs CFString 0x00f955e8 and raises [NSException raise:@"DataSaveException" (0x00f955f8) format:@"Failed to save portal chest data." (0x00f95608)] (0x00958fc8/0x00958ff4). When the flag is set it resolves <ApplicationSupport>/portalChest (NSSearchPathForDirectoriesInDomains(14,1,1) + stringWithFormat: CFString 0x00f955a8 at 0x009590e8) and writes [data writeToFile:path atomically:YES] (0x0095917c); when the flag is clear it only stores self->pendingSaveData@16 = [data retain] (0x009590a0/0x0095919c) for -saveAnyPendingDataToDisk to write later.'),
    ),
    dict(
        name='pcm_saveanypendingdatatodi',
        method='PortalChestManager -[saveAnyPendingDataToDisk]',
        types='v8@0:4',
        start=9802712,
        end=9803172,
        disasm='disasm_portalchestmanager_saveanypendingdatatodisk.txt',
        base_add=9802728,
        base_literal=9803168,
        boundary='consecutive IMPs: next method follows at 0x009595a4',
        selectors={
                 0x959588: (15219576, 'release'),
                 0x95958c: (15219600, 'writeToFile:atomically:'),
                 0x959594: (15219516, 'stringWithFormat:'),
                 0x959598: (15219512, 'objectAtIndex:'),
        },
        imports={
                 0x959584: (17151904, 'objc_msgSend'),
                 0x959590: (16340392, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x959580: (17163048, 'OBJC_IVAR_$_PortalChestManager.pendingSaveData', 16),
        },
        classes={
                 0x95959c: (15248328, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(9802712, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9802768, 'cmp r0, r3'), (9802816, 'bl sym.imp.NSSearchPathForDirectoriesInDomains'), (9803000, 'blx ip'), (9803052, 'blx lr'), (9803124, 'str r2, [r0]'), (9803168, 'rsbseq r6, r0, r4, lsl 14')],
        calls=[(9802816, 'bl sym.imp.NSSearchPathForDirectoriesInDomains'), (9802964, 'blx ip'), (9803000, 'blx ip'), (9803052, 'blx lr'), (9803100, 'blx ip')],
        branches=[(9802776, 'beq', 9803128)],
        semantics=('saveAnyPendingDataToDisk: returns immediately when pendingSaveData@16 is nil (ivar cell 0x00959580, cmp/beq at 0x00959410/0x00959418). Otherwise it resolves the document directory (NSSearchPathForDirectoriesInDomains(0xe = 14 = NSApplicationSupportDirectory - the same directory the other save paths use, 1 = NSUserDomainMask, 1 = YES) at 0x00959440), takes [paths objectAtIndex:0] (selector cell 0x00959598 at 0x009594d4), builds the file path with [NSString stringWithFormat:@"%@/portalChest" (CFString cell 0x00959590 -> slot 0x00f95ab4, length 14)] at 0x009594f8, writes the payload with [pendingSaveData writeToFile:path atomically:YES] (selector cell 0x0095958c, atomically = 1 from 0x00959468 via sxtb, dispatch 0x0095952c), releases the intermediate string (cell 0x00959588 at 0x0095955c) and clears pendingSaveData@16 (0x00959574).'),
    ),
    dict(
        name='pcm_savetransactionwithfai',
        method='PortalChestManager -[saveTransactionWithFailureCreation:itemsWereAdded:]',
        types='v16@0:4@8c12',
        start=9803172,
        end=9805672,
        disasm='disasm_portalchestmanager_savetransactionwithfailurecreation_ite.txt',
        base_add=9803188,
        base_literal=9805668,
        boundary='consecutive IMPs: next method follows at 0x00959f68',
        selectors={
                 0x959ecc: (15219508, 'customRules'),
                 0x959ee0: (15219552, 'client'),
                 0x959ee8: (15219592, 'setObject:forKey:'),
                 0x959eec: (15219612, 'numberWithUnsignedInt:'),
                 0x959ef8: (15219608, 'numberWithBool:'),
                 0x959efc: (15219584, 'dictionary'),
                 0x959f0c: (15219536, 'count'),
                 0x959f10: (15219540, 'countByEnumeratingWithState:objects:count:'),
                 0x959f14: (15219528, 'array'),
                 0x959f1c: (15219532, 'addObject:'),
                 0x959f20: (15219588, 'saveData'),
                 0x959f28: (15219572, 'sendDataToServer:reliable:'),
                 0x959f2c: (15219568, 'appendBytes:length:'),
                 0x959f30: (15219560, 'dataWithBytes:length:'),
                 0x959f38: (15219600, 'writeToFile:atomically:'),
                 0x959f40: (15219516, 'stringWithFormat:'),
                 0x959f44: (15219556, 'saveID'),
                 0x959f48: (15219512, 'objectAtIndex:'),
                 0x959f58: (15219596, 'raise:format:'),
        },
        imports={
                 0x959ed4: (17151968, '__stack_chk_guard'),
                 0x959edc: (17151904, 'objc_msgSend'),
                 0x959ee4: (16340440, '__CFConstantStringClassReference'),
                 0x959ef4: (16340504, '__CFConstantStringClassReference'),
                 0x959f24: (16340520, '__CFConstantStringClassReference'),
                 0x959f3c: (16340424, '__CFConstantStringClassReference'),
                 0x959f50: (16340472, '__CFConstantStringClassReference'),
                 0x959f54: (16340488, '__CFConstantStringClassReference'),
                 0x959f60: (16340536, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x959ed0: (17163028, 'OBJC_IVAR_$_PortalChestManager.world', 4),
                 0x959ed8: (17163044, 'OBJC_IVAR_$_PortalChestManager.pendingTransaction', 12),
                 0x959f04: (17163036, 'OBJC_IVAR_$_PortalChestManager.transactionIdentifierCount', 14),
                 0x959f08: (17163040, 'OBJC_IVAR_$_PortalChestManager.pendingTransactionIsResend', 13),
        },
        classes={
                 0x959ef0: (15248352, 'OBJC_CLASS_$_NSNumber'),
                 0x959f00: (15248344, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x959f18: (15248324, 'OBJC_CLASS_$_NSMutableArray'),
                 0x959f34: (15248340, 'OBJC_CLASS_$_NSMutableData'),
                 0x959f4c: (15248328, 'OBJC_CLASS_$_NSString'),
                 0x959f5c: (15248348, 'OBJC_CLASS_$_NSException'),
        },
        instructions=[(9803172, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9803296, 'bl loc.imp.objc_msgSend_stret'), (9803344, 'bne 0x959ea4'), (9803372, 'ldrsb r0, [r0]'), (9803456, 'blx r3'), (9803668, 'strb r1, [r0]'), (9803692, 'strb r1, [r0]'), (9803756, 'strh r1, [r0]'), (9803888, 'blx ip'), (9803968, 'blx ip'), (9804144, 'blx r2'), (9804640, 'blx ip'), (9804656, 'bl 0x95926c'), (9804800, 'blx r4'), (9805248, 'blx lr'), (9805464, 'blx ip'), (9805668, 'rsbseq r6, r0, r8, lsr r5')],
        calls=[(9803296, 'bl loc.imp.objc_msgSend_stret'), (9803332, 'bl sym.imp.memset'), (9803456, 'blx r3'), (9803804, 'blx r3'), (9803852, 'blx r3'), (9803888, 'blx ip'), (9803932, 'blx r3'), (9803968, 'blx ip'), (9804028, 'blx r2'), (9804144, 'blx r2'), (9804168, 'bl sym.imp.memset'), (9804216, 'blx lr'), (9804316, 'bl sym.imp.objc_enumerationMutation'), (9804416, 'blx ip'), (9804448, 'blx r3'), (9804548, 'blx ip'), (9804640, 'blx ip'), (9804656, 'bl 0x95926c'), (9804708, 'bl sym.imp.NSLog'), (9804800, 'blx r4'), (9804844, 'bl sym.imp.NSSearchPathForDirectoriesInDomains'), (9805156, 'blx r3'), (9805204, 'blx ip'), (9805248, 'blx lr'), (9805284, 'blx ip'), (9805332, 'blx lr'), (9805388, 'blx ip'), (9805424, 'blx r3'), (9805464, 'blx ip'), (9805512, 'bl sym.imp.__stack_chk_fail')],
        branches=[(9803280, 'beq', 9803304), (9803300, 'b', 9803336), (9803344, 'bne', 9805476), (9803380, 'bne', 9805472), (9803468, 'beq', 9805472), (9803984, 'beq', 9804644), (9804036, 'bls', 9804644), (9804228, 'beq', 9804572), (9804308, 'beq', 9804320), (9804476, 'blo', 9804272), (9804568, 'bne', 9804272), (9804572, 'b', 9804576), (9804676, 'bne', 9804696), (9804692, 'bne', 9804808), (9804804, 'b', 9805468), (9805468, 'b', 9805472), (9805472, 'b', 9805476), (9805500, 'bne', 9805512)],
        semantics=('saveTransactionWithFailureCreation:itemsWereAdded: is the transaction-creation request. Three guards return without doing anything: [world customRules] stret into 64 bytes with a non-zero first signed byte (0x00959620/0x00959650), (char)self->pendingTransaction@12 already set (ldrsb 0x0095966c, bne 0x00959674), and [world client] == nil (0x009596c0/0x009596cc). It then arms the state: pendingTransaction@12 = 1 (0x00959794), pendingTransactionIsResend@13 = 0 (0x009597ac), and post-increments the u16 transactionIdentifierCount@14 keeping the old value (ldrh 0x009597c0, strh 0x009597ec). dict = [NSMutableDictionary dictionary] (0x0095981c) receives numberWithBool:itemsWereAdded under CFString 0x00f95618 (0x0095984c/0x00959870) and numberWithUnsignedInt:(old count) under CFString 0x00f955d8 (0x009598c0); when failureCreation is non-nil with count > 0 (0x009598fc/0x00959904) it adds an NSMutableArray of [item saveData] under CFString 0x00f95628 (0x00959970/0x00959a80/0x00959b60). The dictionary is serialised by the helper at 0x00959b70 (bl 0x95926c, the same plist encoder saveWithMainThreadBlock: uses); a nil result logs CFString 0x00f95638 and raises [NSException raise:CFString 0x00f955f8 format:CFString 0x00f95608] (0x00959c00). On success it writes the payload to <ApplicationSupport>/saves/<saveID>/portalChestTransaction (NSSearchPathForDirectoriesInDomains(14,1,1) at 0x00959c2c, stringWithFormat: CFString 0x00f955c8 with [world saveID] at 0x00959dc0, writeToFile:atomically:YES) and sends [[world client] sendDataToServer:([NSMutableData dataWithBytes:&0x3e length:1] + appendBytes:&count16 length:8) reliable:YES] (0x00959e14/0x00959e4c/0x00959e98). The one-byte payload marker is 0x3e here, where initWithWorld: sends 0x40.'),
    ),
    dict(
        name='pcm_takeincominginventoryi',
        method='PortalChestManager -[takeIncomingInventoryItemsFromArray:toIndex:count:]',
        types='i20@0:4@8i12i16',
        start=9805672,
        end=9805880,
        disasm='disasm_portalchestmanager_takeincominginventoryitemsfromarray_to.txt',
        base_add=9805764,
        base_literal=9805876,
        boundary='consecutive IMPs: next method follows at 0x0095a038',
        selectors={
                 0x95a030: (15219616, 'takeIncomingInventoryItemsFromArray:toIndex:count:assignedIndexes:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(9805672, 'push {r4, sl, fp, lr}'), (9805736, 'bl method.std::__1::__tree_int__std::__1::less_int___std::__1::allocator_int___.__tree_std::__1::less_int__const_'), (9805792, 'bl loc.imp.objc_msgSend'), (9805816, 'bl method.std::__1::set_int__std::__1::less_int___std::__1::allocator_int___._set__'), (9805868, 'bl sym.imp._Unwind_Resume'), (9805876, 'rsbseq r5, r0, r8, lsr 22')],
        calls=[(9805736, 'bl method.std::__1::__tree_int__std::__1::less_int___std::__1::allocator_int___.__tree_std::__1::less_int__const_'), (9805792, 'bl loc.imp.objc_msgSend'), (9805816, 'bl method.std::__1::set_int__std::__1::less_int___std::__1::allocator_int___._set__'), (9805856, 'bl method.std::__1::set_int__std::__1::less_int___std::__1::allocator_int___._set__'), (9805868, 'bl sym.imp._Unwind_Resume')],
        branches=[(9805800, 'b', 9805804)],
        semantics=("takeIncomingInventoryItemsFromArray:toIndex:count: is a forwarder: it default-constructs a std::__1::set<int> on the frame (__tree constructor at 0x00959fa8; the set address is kept at [sp,0x18]), places a pointer to it as the assignedIndexes argument (str r4,[lr,4] at 0x00959fd4) and calls takeIncomingInventoryItemsFromArray:toIndex:count:assignedIndexes: (selector cell 0x0095a030, objc_msgSend at 0x00959fe0) with (array, toIndex, count) forwarded; the set is then destroyed (set<int>::~set at 0x00959ff8) and the callee's int result is returned (0x0095a008). An unwind path repeats the destructor and calls _Unwind_Resume (0x0095a020/0x0095a02c)."),
    ),
    dict(
        name='pcm_moveinventoryitemswith',
        method='PortalChestManager -[moveInventoryItemsWithinChestFromArray:toIndex:count:]',
        types='i20@0:4@8i12i16',
        start=9805880,
        end=9806088,
        disasm='disasm_portalchestmanager_moveinventoryitemswithinchestfromarray.txt',
        base_add=9805972,
        base_literal=9806084,
        boundary='consecutive IMPs: next method follows at 0x0095a108',
        selectors={
                 0x95a100: (15219620, 'moveInventoryItemsWithinChestFromArray:toIndex:count:assignedIndexes:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(9805880, 'push {r4, sl, fp, lr}'), (9805944, 'bl method.std::__1::__tree_int__std::__1::less_int___std::__1::allocator_int___.__tree_std::__1::less_int__const_'), (9806000, 'bl loc.imp.objc_msgSend'), (9806024, 'bl method.std::__1::set_int__std::__1::less_int___std::__1::allocator_int___._set__'), (9806076, 'bl sym.imp._Unwind_Resume'), (9806084, 'rsbseq r5, r0, r8, asr sl')],
        calls=[(9805944, 'bl method.std::__1::__tree_int__std::__1::less_int___std::__1::allocator_int___.__tree_std::__1::less_int__const_'), (9806000, 'bl loc.imp.objc_msgSend'), (9806024, 'bl method.std::__1::set_int__std::__1::less_int___std::__1::allocator_int___._set__'), (9806064, 'bl method.std::__1::set_int__std::__1::less_int___std::__1::allocator_int___._set__'), (9806076, 'bl sym.imp._Unwind_Resume')],
        branches=[(9806008, 'b', 9806012)],
        semantics=('moveInventoryItemsWithinChestFromArray:toIndex:count: is the same forwarder shape: a stack std::__1::set<int> (constructor at 0x0095a078) whose pointer goes into the assignedIndexes slot (0x0095a0a4), the call to moveInventoryItemsWithinChestFromArray:toIndex:count:assignedIndexes: (selector cell 0x0095a100, dispatch 0x0095a0b0), then the set destructor (0x0095a0c8) and the int result returned (0x0095a0d8); unwind path at 0x0095a0f0/0x0095a0fc.'),
    ),
    dict(
        name='pcm_portalchestserverackre',
        method='PortalChestManager -[portalChestServerAckReceivedWithSuccess:transactionIdentifier:]',
        types='v16@0:4c8S12',
        start=9806088,
        end=9808180,
        disasm='disasm_portalchestmanager_portalchestserverackreceivedwithsucces.txt',
        base_add=9806104,
        base_literal=9808176,
        boundary='consecutive IMPs: next method follows at 0x0095a934',
        selectors={
                 0x95a8b4: (15219520, 'dataWithContentsOfFile:'),
                 0x95a8c0: (15219516, 'stringWithFormat:'),
                 0x95a8c4: (15219556, 'saveID'),
                 0x95a8cc: (15219512, 'objectAtIndex:'),
                 0x95a8d8: (15219624, 'boolValue'),
                 0x95a8e0: (15219524, 'objectForKey:'),
                 0x95a8e4: (15219628, 'saveWithMainThreadBlock:'),
                 0x95a8e8: (15219536, 'count'),
                 0x95a8f0: (15219540, 'countByEnumeratingWithState:objects:count:'),
                 0x95a8f4: (15219528, 'array'),
                 0x95a8fc: (15219532, 'addObject:'),
                 0x95a900: (15219548, 'autorelease'),
                 0x95a904: (15219544, 'initWithSaveData:'),
                 0x95a908: (15219504, 'alloc'),
                 0x95a914: (15219632, 'moveInventoryItemsFromArray:toIndex:count:movedItems:assignedIndexes:'),
                 0x95a924: (15219640, 'removeItemAtPath:error:'),
                 0x95a928: (15219636, 'defaultManager'),
        },
        imports={
                 0x95a8b0: (17151904, 'objc_msgSend'),
                 0x95a8bc: (16340424, '__CFConstantStringClassReference'),
                 0x95a8dc: (16340504, '__CFConstantStringClassReference'),
                 0x95a8ec: (16340520, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x95a8c8: (17163028, 'OBJC_IVAR_$_PortalChestManager.world', 4),
                 0x95a8d4: (17163040, 'OBJC_IVAR_$_PortalChestManager.pendingTransactionIsResend', 13),
                 0x95a920: (17163044, 'OBJC_IVAR_$_PortalChestManager.pendingTransaction', 12),
        },
        classes={
                 0x95a8b8: (15248332, 'OBJC_CLASS_$_NSData'),
                 0x95a8d0: (15248328, 'OBJC_CLASS_$_NSString'),
                 0x95a8f8: (15248324, 'OBJC_CLASS_$_NSMutableArray'),
                 0x95a90c: (15248336, 'OBJC_CLASS_$_InventoryItem'),
                 0x95a92c: (15248356, 'OBJC_CLASS_$_NSFileManager'),
        },
        instructions=[(9806088, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9806140, 'strh r3, [fp, -0x30]'), (9806496, 'bl 0x95894c'), (9806512, 'ldrsb r0, [fp, -0x2d]'), (9806652, 'ldrsb r0, [r0]'), (9806736, 'blx ip'), (9806884, 'bne 0x95a430'), (9807020, 'bls 0x95a808'), (9807448, 'blx r3'), (9807792, 'bl loc.imp.objc_msgSend'), (9808000, 'blx ip'), (9808024, 'strb r3, [r1]'), (9808176, 'ldrsbteq r5, [r0], -0x94')],
        calls=[(9806168, 'bl sym.imp.NSSearchPathForDirectoriesInDomains'), (9806328, 'blx r3'), (9806376, 'blx ip'), (9806420, 'blx lr'), (9806468, 'blx r3'), (9806496, 'bl 0x95894c'), (9806596, 'blx ip'), (9806612, 'blx r2'), (9806736, 'blx ip'), (9806856, 'blx ip'), (9806872, 'blx r2'), (9806988, 'blx ip'), (9807012, 'blx r2'), (9807128, 'blx r2'), (9807152, 'bl sym.imp.memset'), (9807200, 'blx lr'), (9807300, 'bl sym.imp.objc_enumerationMutation'), (9807428, 'blx ip'), (9807448, 'blx r3'), (9807488, 'blx r3'), (9807520, 'blx r3'), (9807620, 'blx ip'), (9807680, 'bl method.std::__1::__tree_int__std::__1::less_int___std::__1::allocator_int___.__tree_std::__1::less_int__const_'), (9807724, 'bl loc.imp.objc_msgSend'), (9807792, 'bl loc.imp.objc_msgSend'), (9807828, 'bl loc.imp.objc_msgSend'), (9807840, 'bl method.std::__1::set_int__std::__1::less_int___std::__1::allocator_int___._set__'), (9807868, 'bl method.std::__1::set_int__std::__1::less_int___std::__1::allocator_int___._set__'), (9807976, 'blx ip'), (9808000, 'blx ip'), (9808044, 'bl sym.imp._Unwind_Resume')],
        branches=[(9806488, 'beq', 9806504), (9806520, 'beq', 9806748), (9806624, 'beq', 9806744), (9806660, 'beq', 9806676), (9806672, 'b', 9806740), (9806740, 'b', 9806744), (9806744, 'b', 9806904), (9806780, 'beq', 9806900), (9806884, 'bne', 9806896), (9806896, 'b', 9806900), (9806900, 'b', 9806904), (9806912, 'beq', 9807884), (9807020, 'bls', 9807880), (9807212, 'beq', 9807644), (9807292, 'beq', 9807304), (9807548, 'blo', 9807256), (9807640, 'bne', 9807256), (9807644, 'b', 9807648), (9807732, 'b', 9807736), (9807800, 'b', 9807804), (9807832, 'b', 9807836), (9807848, 'b', 9807880), (9807876, 'b', 9808040), (9807880, 'b', 9807884)],
        semantics=('portalChestServerAckReceivedWithSuccess:transactionIdentifier: applies the server\'s answer. It loads the transaction plist from <ApplicationSupport>/saves/<saveID>/portalChestTransaction (path at 0x0095a254, [NSData dataWithContentsOfFile:] at 0x0095a284, parsed by the out-of-body helper at 0x0095a2a0 / 0x95894c). The success char is stored at fp-0x2d and read once at 0x0095a2b0; the unsigned-short transactionIdentifier is stored at fp-0x30 (0x0095a13c) and never read in this body - a dead argument, so the handler keys only off the persisted plist. A local flag (fp-0x3d) decides whether the failure items are migrated: on success it is set when resend (pendingTransactionIsResend@13, ldrsb 0x0095a33c) is set and the plist\'s itemsWereAdded is true, otherwise [self saveWithMainThreadBlock:YES] is called instead (0x0095a390); on failure it is set only when resend is set and itemsWereAdded is false (0x0095a424). When the flag is set the handler reads plist[@"failureCreationItems"] (0x0095a45c) and, if non-empty (bls 0x0095a4ac), turns every element into [[[InventoryItem alloc] initWithSaveData:] autorelease] inside an NSMutableArray (0x0095a530/0x0095a658), applies them with [self moveInventoryItemsFromArray:arr toIndex:-1 count:[arr count] movedItems:nil assignedIndexes:&set<int>] (mvn r3,0 at 0x0095a7a4, call 0x0095a7b0) and then calls [self saveWithMainThreadBlock:YES]. Both paths converge on the same tail: [[NSFileManager defaultManager] removeItemAtPath:path error:NULL] (0x0095a880) and self->pendingTransaction@12 = 0 (strb 0 at 0x0095a898).'),
    ),
    dict(
        name='pcm_portalchestinventoryit',
        method='PortalChestManager -[portalChestInventoryItems]',
        types='@8@0:4',
        start=9808180,
        end=9808316,
        disasm='disasm_portalchestmanager_portalchestinventoryitems.txt',
        base_add=9808196,
        base_literal=9808312,
        boundary='consecutive IMPs: next method follows at 0x0095a9bc',
        selectors={
                 0x95a9ac: (15219548, 'autorelease'),
                 0x95a9b0: (15219644, 'copy'),
        },
        imports={
                 0x95a9a8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x95a9b4: (17163032, 'OBJC_IVAR_$_PortalChestManager.portalChestInventoryItems', 8),
        },
        classes={},
        instructions=[(9808180, 'push {r4, sl, fp, lr}'), (9808252, 'ldr r0, [r0]'), (9808268, 'blx r3'), (9808284, 'blx r2'), (9808312, 'rsbseq r5, r0, r8, lsr 3')],
        calls=[(9808268, 'blx r3'), (9808284, 'blx r2')],
        branches=[],
        semantics=("portalChestInventoryItems = [[self->portalChestInventoryItems@8 copy] autorelease]: the ivar is loaded through cell 0x0095a9b4 (0x0095a97c), 'copy' (cell 0x0095a9b0) is dispatched at 0x0095a98c and 'autorelease' (cell 0x0095a9ac) at 0x0095a99c - the getter hands out a copy."),
    ),
    dict(
        name='pcm_takeincominginventoryi_a9bc',
        method='PortalChestManager -[takeIncomingInventoryItemsFromArray:toIndex:count:assignedIndexes:]',
        types='i24@0:4@8i12i16^{set<int, std::__1::less<int>, std::__1::allocator<int> >={__tree<int, std::__1::less<int>, std::__1::allocator<int> >=^{__tree_node<int, void *>}{__compressed_pair<std::__1::__tree_end_node<std::__1::__tree_node_base<void *> *>, std::__1::allocator<std::__1::__tree_node<int, void *> > >={__tree_end_node<std::__1::__tree_node_base<void *> *>=^{__tree_node_base<void *>}}}{__compressed_pair<unsigned long, std::__1::less<int> >=L}}}20',
        start=9808316,
        end=9808804,
        disasm='disasm_portalchestmanager_takeincominginventoryitemsfromarray_to_a9bc.txt',
        base_add=9808332,
        base_literal=9808800,
        boundary='consecutive IMPs: next method follows at 0x0095aba4',
        selectors={
                 0x95ab84: (15219552, 'client'),
                 0x95ab8c: (15219632, 'moveInventoryItemsFromArray:toIndex:count:movedItems:assignedIndexes:'),
                 0x95ab90: (15219528, 'array'),
                 0x95ab98: (15219628, 'saveWithMainThreadBlock:'),
                 0x95ab9c: (15219648, 'saveTransactionWithFailureCreation:itemsWereAdded:'),
        },
        imports={
                 0x95ab80: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x95ab88: (17163028, 'OBJC_IVAR_$_PortalChestManager.world', 4),
        },
        classes={
                 0x95ab94: (15248324, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(9808316, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9808492, 'blx r6'), (9808560, 'blx ip'), (9808600, 'blx r3'), (9808676, 'blx ip'), (9808752, 'blx ip'), (9808756, 'ldr r0, [fp, -0x38]'), (9808800, 'rsbseq r5, r0, r0, lsr 2')],
        calls=[(9808492, 'blx r6'), (9808560, 'blx ip'), (9808600, 'blx r3'), (9808676, 'blx ip'), (9808752, 'blx ip')],
        branches=[(9808612, 'bne', 9808684), (9808680, 'b', 9808756)],
        semantics=("takeIncomingInventoryItemsFromArray:toIndex:count:assignedIndexes: builds a moved-items accumulator with [NSMutableArray array] (class cell 0x0095ab94, selector cell 0x0095ab90 at 0x0095aa6c), calls [self moveInventoryItemsFromArray:toIndex:count:movedItems:assignedIndexes:] passing it as movedItems (selector cell 0x0095ab8c, dispatch 0x0095aab0, result at [fp,-0x38]), and then branches on [[self->world@4 client] == nil] (world through ivar cell 0x0095ab88, 'client' cell 0x0095ab84, dispatch 0x0095aad8, cmp at 0x0095aae0): without a client it calls [self saveWithMainThreadBlock:0] (selector cell 0x0095ab98, BOOL 0 via sxtb at 0x0095ab1c, dispatch 0x0095ab24), with a client it calls [self saveTransactionWithFailureCreation:(moved items) itemsWereAdded:1] (selector cell 0x0095ab9c, BOOL 1 via sxtb at 0x0095ab68, dispatch 0x0095ab70). Either way it returns the forwarding call's int result (0x0095ab74)."),
    ),
    dict(
        name='pcm_itemsremovedtoinventor',
        method='PortalChestManager -[itemsRemovedToInventory:andOrDropped:]',
        types='v16@0:4@8@12',
        start=9808804,
        end=9809300,
        disasm='disasm_portalchestmanager_itemsremovedtoinventory_andordropped_.txt',
        base_add=9808820,
        base_literal=9809296,
        boundary='consecutive IMPs: next method follows at 0x0095ad94',
        selectors={
                 0x95ad74: (15219552, 'client'),
                 0x95ad7c: (15219628, 'saveWithMainThreadBlock:'),
                 0x95ad80: (15219652, 'arrayWithArray:'),
                 0x95ad88: (15219656, 'arrayByAddingObjectsFromArray:'),
                 0x95ad8c: (15219648, 'saveTransactionWithFailureCreation:itemsWereAdded:'),
        },
        imports={
                 0x95ad70: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x95ad78: (17163028, 'OBJC_IVAR_$_PortalChestManager.world', 4),
        },
        classes={
                 0x95ad84: (15248360, 'OBJC_CLASS_$_NSArray'),
        },
        instructions=[(9808804, 'push {r4, r5, r6, sl, fp, lr}'), (9808904, 'cmp r0, r1'), (9808972, 'blx ip'), (9809072, 'blx r4'), (9809180, 'blx r3'), (9809252, 'blx ip'), (9809296, 'rsbseq r4, r0, r8, lsr pc')],
        calls=[(9808896, 'blx r4'), (9808972, 'blx ip'), (9809072, 'blx r4'), (9809108, 'blx ip'), (9809180, 'blx r3'), (9809252, 'blx ip')],
        branches=[(9808908, 'bne', 9808980), (9808976, 'b', 9809256), (9809128, 'beq', 9809188)],
        semantics=("itemsRemovedToInventory:andOrDropped: branches on [[self->world@4 client] == nil] (ivar cell 0x0095ad78, 'client' cell 0x0095ad74, dispatch 0x0095ac00, cmp 0x0095ac08): without a client it calls [self saveWithMainThreadBlock:0] (cell 0x0095ad7c, sxtb 0 at 0x0095ac44, dispatch 0x0095ac4c) and returns. With a client it copies the inventory with [NSArray arrayWithArray:arg1] (class cell 0x0095ad84, selector cell 0x0095ad80 at 0x0095acb0), and when the andOrDropped argument is non-nil it extends that array with [arrayByAddingObjectsFromArray:andOrDropped] (cell 0x0095ad88, dispatch 0x0095ad1c), then calls [self saveTransactionWithFailureCreation:items itemsWereAdded:0] (cell 0x0095ad8c, sxtb 0 at 0x0095ad5c, dispatch 0x0095ad64)."),
    ),
    dict(
        name='pcm_moveinventoryitemswith_ad94',
        method='PortalChestManager -[moveInventoryItemsWithinChestFromArray:toIndex:count:assignedIndexes:]',
        types='i24@0:4@8i12i16^{set<int, std::__1::less<int>, std::__1::allocator<int> >={__tree<int, std::__1::less<int>, std::__1::allocator<int> >=^{__tree_node<int, void *>}{__compressed_pair<std::__1::__tree_end_node<std::__1::__tree_node_base<void *> *>, std::__1::allocator<std::__1::__tree_node<int, void *> > >={__tree_end_node<std::__1::__tree_node_base<void *> *>=^{__tree_node_base<void *>}}}{__compressed_pair<unsigned long, std::__1::less<int> >=L}}}20',
        start=9809300,
        end=9809520,
        disasm='disasm_portalchestmanager_moveinventoryitemswithinchestfromarray_ad94.txt',
        base_add=9809316,
        base_literal=9809516,
        boundary='consecutive IMPs: next method follows at 0x0095ae70',
        selectors={
                 0x95ae64: (15219628, 'saveWithMainThreadBlock:'),
                 0x95ae68: (15219632, 'moveInventoryItemsFromArray:toIndex:count:movedItems:assignedIndexes:'),
        },
        imports={
                 0x95ae60: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9809300, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9809456, 'blx r6'), (9809488, 'blx r3'), (9809492, 'ldr r0, [sp, 0x24]'), (9809516, 'rsbseq r4, r0, r8, asr 26')],
        calls=[(9809456, 'blx r6'), (9809488, 'blx r3')],
        branches=[],
        semantics=("moveInventoryItemsWithinChestFromArray:toIndex:count:assignedIndexes: forwards to moveInventoryItemsFromArray:toIndex:count:movedItems:assignedIndexes: (selector cell 0x0095ae68, dispatch 0x0095ae30, with the incoming arguments and the assignedIndexes pointer at [sp]) and then calls [self saveWithMainThreadBlock:0] (cell 0x0095ae64, BOOL 0 via sxtb at 0x0095ae48, dispatch 0x0095ae50), returning the first call's int result (0x0095ae54)."),
    ),
    dict(
        name='pcm_moveinventoryitemsfrom',
        method='PortalChestManager -[moveInventoryItemsFromArray:toIndex:count:movedItems:assignedIndexes:]',
        types='i28@0:4@8i12i16@20^{set<int, std::__1::less<int>, std::__1::allocator<int> >={__tree<int, std::__1::less<int>, std::__1::allocator<int> >=^{__tree_node<int, void *>}{__compressed_pair<std::__1::__tree_end_node<std::__1::__tree_node_base<void *> *>, std::__1::allocator<std::__1::__tree_node<int, void *> > >={__tree_end_node<std::__1::__tree_node_base<void *> *>=^{__tree_node_base<void *>}}}{__compressed_pair<unsigned long, std::__1::less<int> >=L}}}24',
        start=9809520,
        end=9812664,
        disasm='disasm_portalchestmanager_moveinventoryitemsfromarray_toindex_co.txt',
        base_add=9809536,
        base_literal=9812660,
        boundary='consecutive IMPs: next method follows at 0x0095bab8',
        selectors={
                 0x95ba90: (15219536, 'count'),
                 0x95ba94: (15219660, 'itemType'),
                 0x95ba98: (15219512, 'objectAtIndex:'),
                 0x95ba9c: (15219540, 'countByEnumeratingWithState:objects:count:'),
                 0x95baa4: (15219664, 'dataB'),
                 0x95baa8: (15219632, 'moveInventoryItemsFromArray:toIndex:count:movedItems:assignedIndexes:'),
                 0x95baac: (15219668, 'removeObjectAtIndex:'),
                 0x95bab0: (15219532, 'addObject:'),
        },
        imports={
                 0x95ba8c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x95baa0: (17163032, 'OBJC_IVAR_$_PortalChestManager.portalChestInventoryItems', 8),
        },
        classes={},
        instructions=[(9809520, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9809672, 'blx r2'), (9810612, 'str r0, [fp, -0x64]'), (9811128, 'str r0, [fp, -0x64]'), (9811284, 'cmn r0, 1'), (9811936, 'sub r0, r0, r1'), (9812428, 'blx ip'), (9812500, 'bl method.std::__1::__tree_int__std::__1::less_int___std::__1::allocator_int___.__insert_unique_int_const_'), (9812660, 'rsbseq r4, r0, ip, ror 24')],
        calls=[(9809672, 'blx r2'), (9809788, 'blx lr'), (9809804, 'blx r2'), (9809824, 'bl sym.itemTypeIsStackable_ItemType__unsigned_short__unsigned_short_'), (9809940, 'bl sym.imp.memset'), (9810004, 'blx lr'), (9810104, 'bl sym.imp.objc_enumerationMutation'), (9810176, 'blx r2'), (9810228, 'blx r2'), (9810316, 'blx r4'), (9810332, 'blx r2'), (9810376, 'blx r3'), (9810392, 'blx r2'), (9810492, 'blx r5'), (9810508, 'blx r2'), (9810544, 'blx r3'), (9810560, 'blx r2'), (9810592, 'bl sym.itemTypeIsStackable_ItemType__unsigned_short__unsigned_short_'), (9810732, 'blx ip'), (9810876, 'bl sym.imp.memset'), (9810940, 'blx lr'), (9811040, 'bl sym.imp.objc_enumerationMutation'), (9811112, 'blx r2'), (9811244, 'blx ip'), (9811416, 'blx r5'), (9811440, 'blx r2'), (9811468, 'blx r3'), (9811484, 'blx r2'), (9811580, 'blx ip'), (9811596, 'blx r2'), (9811696, 'blx r5'), (9811712, 'blx r2'), (9811748, 'blx r3'), (9811764, 'blx r2'), (9811796, 'bl sym.itemTypeIsStackable_ItemType__unsigned_short__unsigned_short_'), (9811864, 'blx r2'), (9811920, 'blx r2'), (9812052, 'blx r2'), (9812184, 'blx r4'), (9812224, 'blx r3'), (9812260, 'blx r3'), (9812284, 'blx r3'), (9812428, 'blx ip'), (9812500, 'bl method.std::__1::__tree_int__std::__1::less_int___std::__1::allocator_int___.__insert_unique_int_const_')],
        branches=[(9809616, 'bne', 9809632), (9809628, 'b', 9812608), (9809680, 'bne', 9809696), (9809692, 'b', 9812608), (9809704, 'beq', 9811280), (9809836, 'beq', 9810764), (9810016, 'beq', 9810756), (9810096, 'beq', 9810108), (9810184, 'bls', 9810624), (9810236, 'bhs', 9810624), (9810404, 'bne', 9810620), (9810604, 'beq', 9810620), (9810616, 'b', 9810760), (9810620, 'b', 9810624), (9810660, 'blo', 9810060), (9810752, 'bne', 9810060), (9810756, 'b', 9810760), (9810760, 'b', 9810764), (9810772, 'bne', 9811276), (9810952, 'beq', 9811268), (9811032, 'beq', 9811044), (9811120, 'bne', 9811136), (9811132, 'b', 9811272), (9811172, 'blo', 9810996), (9811264, 'bne', 9810996), (9811268, 'b', 9811272), (9811272, 'b', 9811276), (9811276, 'b', 9811280), (9811288, 'bne', 9811304), (9811300, 'b', 9812608), (9811500, 'ble', 9811824), (9811608, 'bne', 9811812), (9811808, 'bne', 9811824), (9811820, 'b', 9812608), (9811876, 'bhs', 9811928), (9811972, 'bge', 9811988), (9811984, 'b', 9811996), (9812092, 'bge', 9812304), (9812300, 'b', 9812080), (9812312, 'beq', 9812444), (9812324, 'ble', 9812444), (9812340, 'bge', 9812444), (9812452, 'ble', 9812600)],
        semantics=("moveInventoryItemsFromArray:toIndex:count:movedItems:assignedIndexes: moves up to count items from fromArray into one chest slot and records what it moved. It returns 0 immediately when count == 0, when [fromArray count] == 0 (0x0095af08), or when no slot was chosen (cmn r0,1 at 0x0095b554). When the caller passed toIndex == -1 (flag byte fp-0x71 written at 0x0095aec0) it searches for a destination: if [fromArray[0] itemType] is stackable (itemTypeIsStackable(type,0,0) at 0x0095afa0) it fast-enumerates the chest slots (self->portalChestInventoryItems@8 via cell 0x0095baa0) for one with 0 < count < 99 whose head itemType matches and itemTypeIsStackable(type,dataB(existing[0]),dataB(from[0])) (match at 0x0095b2a0/0x0095b2b4, skips at 0x0095b13c), otherwise - and as the fallback when nothing matched - it takes the first slot whose count == 0 (0x0095b4b8). dest = [portalChestInventoryItems objectAtIndex:toIndex] (0x0095b5d8); when [dest count] > 0 the source type must equal [dest[0] itemType] and be stackable with the destination's dataB or the method returns 0 (0x0095b5f0/0x0095b61c). count = MIN(count, [fromArray count]); num = MIN(count, 99 - [dest count]) (0x0095b7e0); the last num elements of fromArray are popped, appended to dest and to movedItems. When the caller's toIndex was -1 and 0 < num < count it recurses with toIndex -1 and count-num, adding the returned count (0x0095b9cc), and when num > 0 it records the slot with assignedIndexes->insert(toIndex) (std::__1::__tree::__insert_unique at 0x0095ba14)."),
    ),
    dict(
        name='pcm_haspendingtransaction',
        method='PortalChestManager -[hasPendingTransaction]',
        types='c8@0:4',
        start=9812664,
        end=9812724,
        disasm='disasm_portalchestmanager_haspendingtransaction.txt',
        base_add=9812672,
        base_literal=9812720,
        boundary='ARM.exidx end 0x0095baf4; the next ObjC IMP (Yak -[npcType]) is at 0x0095c7c4, past 3280 bytes of non-method code',
        selectors={},
        imports={},
        ivars={
                 0x95baec: (17163044, 'OBJC_IVAR_$_PortalChestManager.pendingTransaction', 12),
        },
        classes={},
        instructions=[(9812664, 'sub sp, sp, 8'), (9812704, 'ldrsb r0, [r0]'), (9812720, 'rsbseq r4, r0, ip, lsr 32')],
        calls=[],
        branches=[],
        semantics=('hasPendingTransaction = ldrsb of PortalChestManager.pendingTransaction@12 (ivar cell 0x0095baec, load at 0x0095bae0). No call, no branch.'),
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
        'batch': 'PortalChestManager closure batch (E11): the server-backed portal chest - -initWithWorld: (world wiring, on-disk chest restore, resend arming), -dealloc, -saveWithMainThreadBlock: (a char flag, NOT a block: writes now or parks pendingSaveData), -saveAnyPendingDataToDisk, -saveTransactionWithFailureCreation:itemsWereAdded: (payload marker 0x3e), -portalChestServerAckReceivedWithSuccess:transactionIdentifier: (ack, failure-item migration, transaction file removal), the take/move inventory family (two 4-arg forwarders that build a std::set<int> for assignedIndexes), -portalChestInventoryItems and -hasPendingTransaction; 14 bodies',
        'claim': ('static bounded-body maps with per-instruction anchors; the out-of-body plist '
                  'codecs (the serialiser at 0x0095926c and the parser behind 0x00958894c), the '
                  'world customRules struct beyond its first byte, and the server protocol outside '
                  'these messages are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'portalchest_closure.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale trade_portal_econ.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
