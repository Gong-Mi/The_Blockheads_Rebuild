#!/usr/bin/env python3
"""Hash-gated recovery of the CrystalManager closure batch (E10).

Closes the CrystalManager class (the crystal store the trade portal fingerprints):
12 bodies, 1305 instruction words, from the pinned original libApplication.so
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
    'bl 0x9f5e68': 0x009f5e68,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl sym.imp.__aeabi_d2lz': 0x001c2990,
    'bl sym.imp.time': 0x001c37f4,
}

SPECS = [
    dict(
        name='cm_instance',
        method='CrystalManager -[instance]',
        types='@8@0:4',
        start=10435348,
        end=10435548,
        disasm='disasm_crystalmanager_instance.txt',
        base_add=10435364,
        base_literal=10435544,
        boundary='consecutive IMPs: next method follows at 0x009f3bdc',
        selectors={
                 0x9f3bcc: (15223068, 'init'),
                 0x9f3bd0: (15223064, 'alloc'),
        },
        imports={
                 0x9f3bc8: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0x9f3bd4: (15248840, 'OBJC_CLASS_$_CrystalManager'),
        },
        instructions=[(10435348, 'push {fp, lr}'), (10435392, 'cmp r0, r3'), (10435472, 'blx r2'), (10435488, 'blx r2'), (10435512, 'ldr r0, [r0]'), (10435544, 'rsbeq fp, r6, r8, asr 31')],
        calls=[(10435472, 'blx r2'), (10435488, 'blx r2')],
        branches=[(10435400, 'bne', 10435500)],
        semantics=("CrystalManager +[instance] singleton: the static slot (cell 0x009f3bc4 -> 0x01064984) is tested against nil (cmp at 0x009f3b40); when it is already set the body falls through to the load at 0x009f3bb8 and returns it. When it is nil it dispatches [[CrystalManager alloc] init] - 'alloc' selector cell 0x009f3bd0 with the OBJC_CLASS_$_CrystalManager class cell 0x009f3bd4 at 0x009f3b90, then 'init' selector cell 0x009f3bcc through the saved IMP at 0x009f3ba0 - and stores the result back into the static (str r0, [r1] at 0x009f3ba8). Single-threaded lazy init: no lock, no dmb."),
    ),
    dict(
        name='cm_init',
        method='CrystalManager -[init]',
        types='@8@0:4',
        start=10435548,
        end=10435908,
        disasm='disasm_crystalmanager_init.txt',
        base_add=10435564,
        base_literal=10435904,
        boundary='consecutive IMPs: next method follows at 0x009f3d44',
        selectors={
                 0x9f3d24: (15223068, 'init'),
                 0x9f3d30: (15223072, 'setMaxConcurrentOperationCount:'),
                 0x9f3d38: (15223064, 'alloc'),
        },
        imports={
                 0x9f3d20: (17151900, 'objc_msgSendSuper2'),
                 0x9f3d2c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x9f3d34: (17164120, 'OBJC_IVAR_$_CrystalManager.saveQueue', 4),
        },
        classes={
                 0x9f3d28: (15253012, 'OBJC_CLASS_$_CrystalManager'),
                 0x9f3d3c: (15248844, 'OBJC_CLASS_$_NSOperationQueue'),
        },
        instructions=[(10435548, 'push {r4, r5, r6, sl, fp, lr}'), (10435632, 'blx ip'), (10435668, 'str r0, [fp, -0x14]'), (10435776, 'blx r5'), (10435792, 'blx r2'), (10435812, 'str r0, [r1]'), (10435676, 'movw r2, 1'), (10435848, 'blx r3'), (10435904, 'rsbeq fp, r6, r0, lsl 30')],
        calls=[(10435632, 'blx ip'), (10435776, 'blx r5'), (10435792, 'blx r2'), (10435848, 'blx r3')],
        branches=[(10435660, 'bne', 10435676), (10435672, 'b', 10435860)],
        semantics=("-[init]: objc_msgSendSuper2 init (import cell 0x009f3d20, selector cell 0x009f3d24, class cell 0x009f3d28) at 0x009f3c30, then the nil-self guard returns nil (0x009f3c50/0x009f3c54). Otherwise it builds a serial background queue: saveQueue@4 = [[NSOperationQueue alloc] init] (OBJC_CLASS_$_NSOperationQueue cell 0x009f3d3c, 'alloc' cell 0x009f3d38 at 0x009f3cc0, 'init' cell 0x009f3d24 at 0x009f3cd0, stored through the saveQueue ivar cell 0x009f3d34 at 0x009f3ce4) and then calls [saveQueue setMaxConcurrentOperationCount:1] (selector cell 0x009f3d30, argument 1 from movw r2, 1 at 0x009f3c5c, dispatch at 0x009f3d08). Returns self (0x009f3d0c/0x009f3d10)."),
    ),
    dict(
        name='cm_amount',
        method='CrystalManager -[amount]',
        types='i8@0:4',
        start=10437932,
        end=10437992,
        disasm='disasm_crystalmanager_amount.txt',
        base_add=10437940,
        base_literal=10437988,
        boundary='consecutive IMPs: next method follows at 0x009f4568',
        selectors={},
        imports={},
        ivars={
                 0x9f4560: (17164128, 'OBJC_IVAR_$_CrystalManager.crystalCount', 8),
        },
        classes={},
        instructions=[(10437932, 'sub sp, sp, 8'), (10437972, 'ldr r0, [r0]'), (10437988, 'strhteq fp, [r6], -0x58')],
        calls=[],
        branches=[],
        semantics=("amount = a plain load of CrystalManager.crystalCount@8 (ivar cell 0x009f4560 -> OBJC_IVAR_$_CrystalManager.crystalCount = 8, ldr r0, [r0] at 0x009f4554). No call, no branch, no barrier - the crystal count is the 'amount' the trade portal fingerprints."),
    ),
    dict(
        name='cm_commitsaveifneeded',
        method='CrystalManager -[commitSaveIfNeeded]',
        types='v8@0:4',
        start=10437992,
        end=10438264,
        disasm='disasm_crystalmanager_commitsaveifneeded.txt',
        base_add=10438008,
        base_literal=10438260,
        boundary='ARM.exidx end 0x009f4678; the next ObjC IMP (CrystalManager -[save]) is at 0x009f4f34, past 2236 bytes of non-method code',
        selectors={
                 0x9f465c: (15223160, 'addOperationWithBlock:'),
        },
        imports={
                 0x9f4658: (17151904, 'objc_msgSend'),
                 0x9f466c: (17151928, '_NSConcreteStackBlock'),
        },
        ivars={
                 0x9f4654: (17164132, 'OBJC_IVAR_$_CrystalManager.needsSave', 20),
                 0x9f4670: (17164120, 'OBJC_IVAR_$_CrystalManager.saveQueue', 4),
        },
        classes={},
        instructions=[(10437992, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10438040, 'ldrsb r0, [r0]'), (10438144, 'strb r8, [r1]'), (10438164, 'str r6, [sp, 8]'), (10438172, 'str r4, [sp, 0x10]'), (10438176, 'str lr, [sp, 0x14]'), (10438180, 'str ip, [sp, 0x18]'), (10438216, 'blx r3'), (10438260, 'rsbeq fp, r6, r4, ror r5')],
        calls=[(10438216, 'blx r3')],
        branches=[(10438052, 'beq', 10438220)],
        semantics=('commitSaveIfNeeded: returns immediately when the needsSave byte is clear (ldrsb at 0x009f4598, beq 0x009f464c; ivar cell 0x009f4654 -> needsSave = 20). Otherwise it clears the flag first (strb r8 = 0 at 0x009f4600) and enqueues a stack block on saveQueue@4 (ivar cell 0x009f4670) with addOperationWithBlock: (selector cell 0x009f465c, dispatch at 0x009f4648). The block literal is built on the frame at sp+8: isa = _NSConcreteStackBlock (0x009f4614), flags word 0xc2000000 (0x009f4618 = HAS_EXTENDED_LAYOUT|HAS_SIGNATURE|HAS_COPY_DISPOSE; the r2 listing misdecodes that pool word as an instruction), reserved 0, invoke = 0x009f4678 (r lr at 0x009f4620: the delta cell 0x009f4664 resolves to base-0x6b47c, and the word at 0x009f4678 is 0xe92d4df0, the push prologue of the block body - which is exactly the start of the non-method byte gap after this body), descriptor = 0x010524c0 (0x009f4624: delta cell 0x009f4660 -> base-0xd634, first word 0 in the file), and self captured at [sp,0x1c] (0x009f462c).'),
    ),
    dict(
        name='cm_save',
        method='CrystalManager -[save]',
        types='v8@0:4',
        start=10440500,
        end=10440564,
        disasm='disasm_crystalmanager_save.txt',
        base_add=10440508,
        base_literal=10440560,
        boundary='consecutive IMPs: next method follows at 0x009f4f74',
        selectors={},
        imports={},
        ivars={
                 0x9f4f6c: (17164132, 'OBJC_IVAR_$_CrystalManager.needsSave', 20),
        },
        classes={},
        instructions=[(10440500, 'sub sp, sp, 8'), (10440512, 'movw r3, 1'), (10440544, 'strb r3, [r0]'), (10440560, 'strhteq sl, [r6], -0xb0')],
        calls=[],
        branches=[],
        semantics=('save = sets CrystalManager.needsSave@20 to 1 (movw r3, 1 at 0x009f4f40, strb r3, [r0] at 0x009f4f60, ivar cell 0x009f4f6c -> needsSave = 20) and returns; it does not write the store itself - commitSaveIfNeeded: is what consumes the flag.'),
    ),
    dict(
        name='cm_modify_modifystring_',
        method='CrystalManager -[modify:modifyString:]',
        types='v16@0:4i8@12',
        start=10440564,
        end=10441324,
        disasm='disasm_crystalmanager_modify_modifystring_.txt',
        base_add=10440580,
        base_literal=10441320,
        boundary='consecutive IMPs: next method follows at 0x009f526c',
        selectors={
                 0x9f5238: (15223132, 'isEqualToString:'),
                 0x9f523c: (15223088, 'stringFromMD5'),
                 0x9f5244: (15223084, 'stringWithFormat:'),
                 0x9f5250: (15223168, 'save'),
                 0x9f5254: (15223164, 'crystalCountChanged:'),
                 0x9f5260: (15223092, 'retain'),
        },
        imports={
                 0x9f5234: (17151904, 'objc_msgSend'),
                 0x9f5240: (16346104, '__CFConstantStringClassReference'),
                 0x9f5264: (16345960, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x9f5248: (17164128, 'OBJC_IVAR_$_CrystalManager.crystalCount', 8),
                 0x9f5258: (17164136, 'OBJC_IVAR_$_CrystalManager.countWatcher', 16),
                 0x9f525c: (17164124, 'OBJC_IVAR_$_CrystalManager.amountString', 12),
        },
        classes={
                 0x9f524c: (15248852, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(10440564, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10440716, 'add r3, r0, 0x49'), (10440752, 'blx lr'), (10440768, 'blx r2'), (10440796, 'blx r3'), (10440800, 'sxtb r0, r0'), (10441028, 'sub r0, r1, r0'), (10441036, 'str r0, [r1]'), (10441140, 'blx ip'), (10441192, 'str r0, [r1]'), (10441236, 'blx lr'), (10441256, 'blx r2'), (10441320, 'rsbeq sl, r6, r8, ror 22')],
        calls=[(10440752, 'blx lr'), (10440768, 'blx r2'), (10440796, 'blx r3'), (10441140, 'blx ip'), (10441156, 'blx r2'), (10441172, 'blx r2'), (10441236, 'blx lr'), (10441256, 'blx r2')],
        branches=[(10440808, 'beq', 10441260)],
        semantics=('modify:modifyString: (int amount, NSString *fingerprint) gates on a fingerprint and then applies the delta. It recomputes the expected string [NSString stringWithFormat:@"7acfe93afc08c%d65ae2c54ecaf07f" (cell 0x009f5240 -> slot 0x00f96bf8), crystalCount@8 - amount + 73] at 0x009f5030 (the +0x49 is added at 0x009f500c; crystalCount through the ivar cell 0x009f5248) and compares [that stringFromMD5] (selector cell 0x009f523c at 0x009f5040) against the argument with isEqualToString: (cell 0x009f5238) at 0x009f505c; a mismatch returns immediately (beq 0x9f522c after sxtb at 0x009f5060). On a match it decrements crystalCount (sub r0, r1, r0 at 0x009f5144, stored at 0x009f514c), rewrites amountString@12 from the new count through the three dispatches at 0x009f51b4/0x009f51c4/0x009f51d4 (selector cells stringWithFormat: 0x009f5244, stringFromMD5 0x009f523c, retain 0x009f5260; the format string is @"7acfe93afc08%dc65ae2c54ecaf07f" at cell 0x009f5264 -> slot 0x00f96b68 - which is exactly the string the E9b consumer re-reads and compares), stores the result at 0x009f51e8 through the amountString ivar cell 0x009f525c, then notifies [countWatcher@16 crystalCountChanged:1] (selector cell 0x009f5254, watcher cell 0x009f5258, argument 1 via movw ip, 1 at 0x009f5084, dispatch at 0x009f5214) and calls [self save] (selector cell 0x009f5250 at 0x009f5228), which only raises the needsSave flag.'),
    ),
    dict(
        name='cm_icloudid',
        method='CrystalManager -[iCloudID]',
        types='@8@0:4',
        start=10441324,
        end=10444392,
        disasm='disasm_crystalmanager_icloudid.txt',
        base_add=10441340,
        base_literal=10444388,
        boundary='ARM.exidx end 0x009f5e68; the next ObjC IMP (CrystalManager -[iCloudServerRejoinID]) is at 0x009f5e78, past 16 bytes of non-method code',
        selectors={
                 0x9f5d98: (15223176, 'integerForKey:'),
                 0x9f5d9c: (15223172, 'standardUserDefaults'),
                 0x9f5da4: (15223180, 'decryptDepricatedKeychain'),
                 0x9f5dac: (15223192, 'release'),
                 0x9f5db4: (15223128, 'objectForKey:'),
                 0x9f5dc0: (15223188, 'setValue:forKey:'),
                 0x9f5dd4: (15223184, 'initWithCapacity:'),
                 0x9f5dd8: (15223064, 'alloc'),
                 0x9f5de0: (15223196, 'initWithData:encoding:'),
                 0x9f5de8: (15223204, 'count'),
                 0x9f5df0: (15223200, 'componentsSeparatedByString:'),
                 0x9f5df4: (15223096, 'objectAtIndex:'),
                 0x9f5dfc: (15223208, 'longLongValue'),
                 0x9f5e04: (15223216, 'stringForKey:'),
                 0x9f5e08: (15223212, 'defaultStore'),
                 0x9f5e18: (15223076, 'getPasswordForUsername:andServiceName:error:'),
                 0x9f5e2c: (15223108, 'currentDevice'),
                 0x9f5e30: (15223220, 'uniqueDeviceIdentifier'),
                 0x9f5e34: (15223116, 'stringByAppendingFormat:'),
                 0x9f5e3c: (15223088, 'stringFromMD5'),
                 0x9f5e44: (15223224, 'timeIntervalSinceReferenceDate'),
                 0x9f5e48: (15223136, 'storeUsername:andPassword:forServiceName:updateExisting:error:'),
                 0x9f5e4c: (15223228, 'setString:forKey:'),
                 0x9f5e58: (15223084, 'stringWithFormat:'),
        },
        imports={
                 0x9f5d90: (16346120, '__CFConstantStringClassReference'),
                 0x9f5d94: (17151904, 'objc_msgSend'),
                 0x9f5db0: (16346248, '__CFConstantStringClassReference'),
                 0x9f5db8: (16346216, '__CFConstantStringClassReference'),
                 0x9f5dbc: (16346232, '__CFConstantStringClassReference'),
                 0x9f5dc4: (16346152, '__CFConstantStringClassReference'),
                 0x9f5dc8: (16346200, '__CFConstantStringClassReference'),
                 0x9f5dcc: (16346184, '__CFConstantStringClassReference'),
                 0x9f5dd0: (16346168, '__CFConstantStringClassReference'),
                 0x9f5dec: (16346264, '__CFConstantStringClassReference'),
                 0x9f5e00: (16346280, '__CFConstantStringClassReference'),
                 0x9f5e10: (16346296, '__CFConstantStringClassReference'),
                 0x9f5e38: (16346312, '__CFConstantStringClassReference'),
                 0x9f5e50: (16346328, '__CFConstantStringClassReference'),
                 0x9f5e60: (16346136, '__CFConstantStringClassReference'),
        },
        ivars={},
        classes={
                 0x9f5da0: (15248872, 'OBJC_CLASS_$_NSUserDefaults'),
                 0x9f5da8: (15248876, 'OBJC_CLASS_$_NCKeychainCompatibility'),
                 0x9f5ddc: (15248880, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x9f5de4: (15248852, 'OBJC_CLASS_$_NSString'),
                 0x9f5e0c: (15248884, 'OBJC_CLASS_$_NSUbiquitousKeyValueStore'),
                 0x9f5e1c: (15248848, 'OBJC_CLASS_$_SFHFKeychainUtils'),
                 0x9f5e24: (15248856, 'OBJC_CLASS_$_UIDevice'),
                 0x9f5e40: (15248868, 'OBJC_CLASS_$_NSDate'),
        },
        instructions=[(10441324, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10441452, 'cmp r0, 3'), (10441580, 'blx r3'), (10442020, 'blx ip'), (10442220, 'blx ip'), (10442300, 'blx ip'), (10442520, 'blx r3'), (10443048, 'blx ip'), (10443348, 'bne 0x9f5a78'), (10443584, 'bl sym.imp.time'), (10443592, 'bl 0x9f5e68'), (10444076, 'blx ip'), (10444148, 'blx r6'), (10444164, 'ldr r0, [fp, -0x20]'), (10444388, 'rsbeq sl, r6, r0, ror r8')],
        calls=[(10441420, 'blx ip'), (10441440, 'blx r3'), (10441580, 'blx r3'), (10441884, 'blx r2'), (10441904, 'blx r3'), (10441936, 'blx ip'), (10441964, 'blx ip'), (10441992, 'blx ip'), (10442020, 'blx ip'), (10442056, 'blx r3'), (10442076, 'blx r3'), (10442100, 'blx r2'), (10442196, 'blx lr'), (10442220, 'blx ip'), (10442300, 'blx ip'), (10442324, 'blx r2'), (10442376, 'bl loc.imp.objc_msgSend'), (10442404, 'bl loc.imp.objc_msgSend'), (10442420, 'bl loc.imp.objc_msgSend'), (10442520, 'blx r3'), (10442540, 'blx r3'), (10442636, 'blx r2'), (10442656, 'blx r3'), (10442756, 'blx ip'), (10442780, 'blx r2'), (10442832, 'bl loc.imp.objc_msgSend'), (10442860, 'bl loc.imp.objc_msgSend'), (10442876, 'bl loc.imp.objc_msgSend'), (10443048, 'blx ip'), (10443144, 'blx ip'), (10443168, 'blx r2'), (10443220, 'bl loc.imp.objc_msgSend'), (10443248, 'bl loc.imp.objc_msgSend'), (10443264, 'bl loc.imp.objc_msgSend'), (10443548, 'bl loc.imp.objc_msgSend'), (10443564, 'bl loc.imp.objc_msgSend'), (10443584, 'bl sym.imp.time'), (10443592, 'bl 0x9f5e68'), (10443632, 'bl loc.imp.objc_msgSend'), (10443648, 'bl loc.imp.objc_msgSend'), (10443676, 'bl loc.imp.objc_msgSend'), (10443680, 'bl sym.imp.__aeabi_d2lz'), (10444016, 'bl loc.imp.objc_msgSend'), (10444052, 'blx r3'), (10444076, 'blx ip'), (10444148, 'blx r6')],
        branches=[(10441456, 'bne', 10441480), (10441476, 'b', 10444164), (10441600, 'beq', 10442436), (10442116, 'beq', 10442228), (10442332, 'bne', 10442432), (10442432, 'b', 10442436), (10442560, 'bne', 10442664), (10442788, 'bne', 10442892), (10442888, 'b', 10442928), (10442904, 'beq', 10442924), (10442924, 'b', 10442928), (10443068, 'beq', 10443280), (10443176, 'bne', 10443276), (10443276, 'b', 10443280), (10443292, 'beq', 10443384), (10443348, 'bne', 10443384), (10443352, 'b', 10443356), (10443380, 'b', 10443704), (10443396, 'beq', 10443428), (10443424, 'b', 10443700), (10443440, 'beq', 10443472), (10443468, 'b', 10443696), (10443484, 'beq', 10443516), (10443512, 'b', 10443692), (10443692, 'b', 10443696), (10443696, 'b', 10443700), (10443700, 'b', 10443704)],
        semantics=('iCloudID (767w) resolves the cloud id as a four-source min-selection. (1) GDPR gate: [NSUserDefaults standardUserDefaults] (cell 0x009f5d9c) integerForKey:@"gdprStatus" (0x009f52e0) == 3 returns @"gdpr_declined" (cmp at 0x009f52ec, early return 0x009f5304). (2) Legacy Keychain migration, only when +[NCKeychainCompatibility decryptDepricatedKeychain] (0x009f536c, nil-check 0x009f5380) answers: it builds a 4-entry query dictionary (kSecAttrAccount/kSecAttrLabel/kSecAttrService = @"com.majicjungle.blockheads.cloudid2", kSecClass = @"kSecClassGenericPassword"; 0x009f54d0 / 0x009f5524), reads [[result objectForKey:query] objectForKey:@"kSecValueData"] (0x009f5548 / 0x009f555c) and decodes it as UTF-8 ([[NSString alloc] initWithData:encoding:4] at 0x009f55ec), splitting on @"?" (0x009f563c) - exactly 2 parts required (0x009f5658) with [parts[1] longLongValue] as the 64-bit suffix (0x009f56b4). (3) Ubiquitous store: [NSUbiquitousKeyValueStore defaultStore] (0x009f5718) stringForKey:@"iCloudIDv2" (0x009f572c) with the @"iCloudID" fallback (0x009f57a0); a string without "?" yields suffix 100 (0x009f58a4). (4) Keychain: [SFHFKeychainUtils getPasswordForUsername:@"com.majicjungle.blockheads.cloudid2" andServiceName:same error:&err] (0x009f5928). The candidate with the smallest 64-bit suffix wins (branch at 0x009f5a54); when no candidate exists one is generated as MD5([[UIDevice currentDevice] (0x009f5e2c) uniqueDeviceIdentifier] + [NSString stringByAppendingFormat:@"%lu%d", time(NULL) (0x009f5b40), lrand48() through the thunk at 0x009f5e68 (0x009f5b48)]) (stringFromMD5 at 0x009f5b80), with the value taken from [NSDate timeIntervalSinceReferenceDate] converted by __aeabi_d2lz. Both stores are written before the bare id is returned at 0x009f5d84: [store setString:forKey:@"iCloudIDv2"] of [NSString stringWithFormat:@"%@?%lld", id, suffix] (0x009f5d2c) and [SFHFKeychainUtils storeUsername:...updatePassword:...updateExisting:1 error:] (0x009f5d74).'),
    ),
    dict(
        name='cm_icloudserverrejoinid',
        method='CrystalManager -[iCloudServerRejoinID]',
        types='@8@0:4',
        start=10444408,
        end=10444580,
        disasm='disasm_crystalmanager_icloudserverrejoinid.txt',
        base_add=10444424,
        base_literal=10444576,
        boundary='consecutive IMPs: next method follows at 0x009f5f24',
        selectors={
                 0x9f5f10: (15223088, 'stringFromMD5'),
                 0x9f5f18: (15223236, 'stringByAppendingString:'),
                 0x9f5f1c: (15223232, 'iCloudID'),
        },
        imports={
                 0x9f5f0c: (17151904, 'objc_msgSend'),
                 0x9f5f14: (16346344, '__CFConstantStringClassReference'),
        },
        ivars={},
        classes={},
        instructions=[(10444408, 'push {r4, r5, r6, sl, fp, lr}'), (10444508, 'blx ip'), (10444528, 'blx r3'), (10444544, 'blx r2'), (10444576, 'rsbeq sb, r6, r4, ror 24')],
        calls=[(10444508, 'blx ip'), (10444528, 'blx r3'), (10444544, 'blx r2')],
        branches=[],
        semantics=('iCloudServerRejoinID = [[[self iCloudID] stringByAppendingString:@"rejoin"] stringFromMD5]: objc_msgSend(self, \'iCloudID\', selector cell 0x009f5f1c) at 0x009f5edc, then \'stringByAppendingString:\' (cell 0x009f5f18) with the CFString @"rejoin" (cell 0x009f5f14 -> __CFConstantStringClassReference, slot 0x00f96ce8, data pointer 0x00f5be3d, length 6) at 0x009f5ef0, then \'stringFromMD5\' (cell 0x009f5f10) at 0x009f5f00 - the rejoin id is the MD5 of the iCloud id plus the literal salt "rejoin", the same fingerprint scheme the trade portal uses for the crystal amount.'),
    ),
    dict(
        name='cm_countwatcher',
        method='CrystalManager -[countWatcher]',
        types='@8@0:4',
        start=10444580,
        end=10444648,
        disasm='disasm_crystalmanager_countwatcher.txt',
        base_add=10444604,
        base_literal=10444644,
        boundary='body trimmed at the next IMP 0x009f5f68 (ARM.exidx over-covers into CrystalManager -[setCountWatcher:])',
        selectors={},
        imports={},
        ivars={
                 0x9f5f60: (17164136, 'OBJC_IVAR_$_CrystalManager.countWatcher', 16),
        },
        classes={},
        instructions=[(10444580, 'sub sp, sp, 0xc'), (10444616, 'ldr r0, [r0, r1]'), (10444620, 'dmb ish'), (10444644, 'strhteq sb, [r6], -0xb0')],
        calls=[],
        branches=[],
        semantics=('countWatcher = dmb ish atomic load of CrystalManager.countWatcher@16 (ivar cell 0x009f5f60; dmb at 0x009f5f4c, field load at 0x009f5f48).'),
    ),
    dict(
        name='cm_setcountwatcher_',
        method='CrystalManager -[setCountWatcher:]',
        types='v12@0:4@8',
        start=10444648,
        end=10444716,
        disasm='disasm_crystalmanager_setcountwatcher_.txt',
        base_add=10444676,
        base_literal=10444712,
        boundary='consecutive IMPs: next method follows at 0x009f5fac',
        selectors={},
        imports={},
        ivars={
                 0x9f5fa4: (17164136, 'OBJC_IVAR_$_CrystalManager.countWatcher', 16),
        },
        classes={},
        instructions=[(10444648, 'sub sp, sp, 0xc'), (10444688, 'dmb ish'), (10444692, 'str r2, [r0, r1]'), (10444696, 'dmb ish'), (10444712, 'rsbeq sb, r6, r8, ror 22')],
        calls=[],
        branches=[],
        semantics=('setCountWatcher: stores the object argument into CrystalManager.countWatcher@16 between two dmb ish barriers (dmb at 0x009f5f90, str r2, [r0, r1] at 0x009f5f94, dmb at 0x009f5f98; ivar cell 0x009f5fa4) - an explicitly atomic setter, matching the atomic getter in -[countWatcher].'),
    ),
    dict(
        name='cm_needssave',
        method='CrystalManager -[needsSave]',
        types='c8@0:4',
        start=10444716,
        end=10444776,
        disasm='disasm_crystalmanager_needssave.txt',
        base_add=10444724,
        base_literal=10444772,
        boundary='consecutive IMPs: next method follows at 0x009f5fe8',
        selectors={},
        imports={},
        ivars={
                 0x9f5fe0: (17164132, 'OBJC_IVAR_$_CrystalManager.needsSave', 20),
        },
        classes={},
        instructions=[(10444716, 'sub sp, sp, 8'), (10444756, 'ldrsb r0, [r0]'), (10444772, 'rsbeq sb, r6, r8, lsr fp')],
        calls=[],
        branches=[],
        semantics=('needsSave = ldrsb of CrystalManager.needsSave@20 (ivar cell 0x009f5fe0; signed-byte load at 0x009f5fd4) - the flag -[save] sets and -[commitSaveIfNeeded] clears.'),
    ),
    dict(
        name='cm_amountstring',
        method='CrystalManager -[amountString]',
        types='@8@0:4',
        start=10444776,
        end=10444844,
        disasm='disasm_crystalmanager_amountstring.txt',
        base_add=10444800,
        base_literal=10444840,
        boundary='ARM.exidx end 0x009f602c; the next ObjC IMP (MJControl -[initWithFrame:cache:windowInfo:]) is at 0x009f6198, past 364 bytes of non-method code',
        selectors={},
        imports={},
        ivars={
                 0x9f6024: (17164124, 'OBJC_IVAR_$_CrystalManager.amountString', 12),
        },
        classes={},
        instructions=[(10444776, 'sub sp, sp, 0xc'), (10444812, 'ldr r0, [r0, r1]'), (10444816, 'dmb ish'), (10444840, 'rsbeq sb, r6, ip, ror 21')],
        calls=[],
        branches=[],
        semantics=('amountString = dmb ish atomic load of CrystalManager.amountString@12 (object; ivar cell 0x009f6024, field load at 0x009f600c, dmb at 0x009f6010). This is the string the trade portal MD5-fingerprints before and after modify:modifyString: (which rewrites it as MD5 of the new count).'),
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
        'batch': 'CrystalManager closure batch (E10): the crystal store - +instance (lazy singleton), -init (serial NSOperationQueue, saveQueue@4), -amount (crystalCount@8), -amountString, -countWatcher/-setCountWatcher: (dmb ish pair), -needsSave/-save (flag pair), -commitSaveIfNeeded (clears the flag, then enqueues a _NSConcreteStackBlock), -modify:modifyString: (fingerprint gate over crystalCount - amount + 73), -iCloudID (four-source id resolver) and -iCloudServerRejoinID (MD5 of iCloudID + the literal salt rejoin); 12 bodies',
        'claim': ('static bounded-body maps with per-instruction anchors; runtime values, '
                  'the UI consumers and the trade-table contents are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'crystalmanager_closure.json')
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
