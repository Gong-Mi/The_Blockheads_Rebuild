#!/usr/bin/env python3
"""Hash-gated recovery of the Light-block persistence batch (E13).

Closes the named T2/T3 terrain slice of WorldTileLoader:
13 bodies, 2260 instruction words, from the pinned original libApplication.so
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
    'bl 0x859918': 0x00859918,
    'bl 0x866f0c': 0x00866f0c,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl sym.imp.NSLog': 0x001c2a5c,
    'bl sym.imp._Block_object_dispose': 0x001c2870,
    'bl sym.imp._Unwind_Resume': 0x001c29c0,
    'bl sym.imp.__wrap_calloc': 0x001c2fe4,
    'bl sym.imp.__wrap_malloc': 0x001c2e58,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.macroIndexAtMacroPosition_int__int__World_': 0x00a174a4,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
}

SPECS = [
    dict(
        name='wtl_unarchivelightblocksfo',
        method='WorldTileLoader -[unarchiveLightBlocksForClient:]',
        types='v12@0:4@8',
        start=8807724,
        end=8810252,
        disasm='disasm_worldtileloader_unarchivelightblocksforclient_.txt',
        base_add=8807740,
        base_literal=8810248,
        boundary='ARM.exidx end 0x00866f0c (listing bound); next ObjC IMP 0x00866f30 WorldTileLoader -[archiveLightBlocksForClient:]',
        selectors={
                 0x866e8c: (15213740, 'gzipInflate'),
                 0x866e90: (15213736, 'dataForKey:'),
                 0x866e9c: (15213488, 'stringWithFormat:'),
                 0x866ea4: (15213640, 'objectForKey:'),
                 0x866ea8: (15213636, 'serverClients'),
                 0x866eb0: (15213760, 'timeIntervalSinceReferenceDate'),
                 0x866ebc: (15213792, 'startBulkLightBlockTransaction'),
                 0x866ec0: (15213712, 'count'),
                 0x866ec4: (15213524, 'length'),
                 0x866ec8: (15213520, 'countByEnumeratingWithState:objects:count:'),
                 0x866ed0: (15213796, 'componentsSeparatedByString:'),
                 0x866ed4: (15213800, 'hasKey:'),
                 0x866edc: (15213708, 'setData:forKey:'),
                 0x866ee0: (15213804, 'subdataWithRange:'),
                 0x866ee8: (15213816, 'addIndex:'),
                 0x866eec: (15213812, 'allLightBlockIndices'),
                 0x866ef0: (15213808, 'integerValue'),
                 0x866ef4: (15213484, 'objectAtIndex:'),
                 0x866ef8: (15213820, 'saveLightBlockIndices'),
                 0x866f00: (15213824, 'removeDataForKey:'),
        },
        imports={
                 0x866e88: (17151904, 'objc_msgSend'),
                 0x866e98: (16327928, '__CFConstantStringClassReference'),
                 0x866eb8: (16327944, '__CFConstantStringClassReference'),
                 0x866ecc: (16327960, '__CFConstantStringClassReference'),
                 0x866ed8: (16327976, '__CFConstantStringClassReference'),
                 0x866efc: (16327992, '__CFConstantStringClassReference'),
                 0x866f04: (16328008, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x866e94: (17161580, 'OBJC_IVAR_$_WorldTileLoader.lightBlockDatabase', 252),
                 0x866eac: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
        },
        classes={
                 0x866ea0: (15247496, 'OBJC_CLASS_$_NSString'),
                 0x866eb4: (15247544, 'OBJC_CLASS_$_NSDate'),
        },
        instructions=[(8807724, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8807908, 'blx lr'), (8807968, 'blx r2'), (8808104, 'blx r6'), (8808180, 'blx r3'), (8808256, 'blx r3'), (8808272, 'bl 0x866f0c'), (8808464, 'blx r2'), (8808584, 'ldr r1, [sp, 0xc8]'), (8808944, 'blx ip'), (8809088, 'blx lr'), (8809144, 'bne 0x866b64'), (8809260, 'bl loc.imp.objc_msgSend'), (8809528, 'bl sym.macroIndexAtMacroPosition_int__int__World_'), (8809616, 'blx r3'), (8809808, 'blx ip'), (8809964, 'blx ip'), (8810108, 'bl sym.imp.NSLog'), (8810244, 'invalid')],
        calls=[(8807908, 'blx lr'), (8807952, 'blx ip'), (8807968, 'blx r2'), (8808104, 'blx r6'), (8808148, 'blx r3'), (8808180, 'blx r3'), (8808256, 'blx r3'), (8808272, 'bl 0x866f0c'), (8808404, 'blx r7'), (8808448, 'blx ip'), (8808464, 'blx r2'), (8808540, 'blx r3'), (8808580, 'blx r2'), (8808692, 'bl sym.imp.memset'), (8808740, 'blx lr'), (8808840, 'bl sym.imp.objc_enumerationMutation'), (8808944, 'blx ip'), (8808968, 'blx r2'), (8809088, 'blx lr'), (8809132, 'blx ip'), (8809260, 'bl loc.imp.objc_msgSend'), (8809308, 'blx lr'), (8809420, 'blx r5'), (8809436, 'blx r2'), (8809472, 'blx r3'), (8809488, 'blx r2'), (8809528, 'bl sym.macroIndexAtMacroPosition_int__int__World_'), (8809596, 'blx lr'), (8809616, 'blx r3'), (8809720, 'blx ip'), (8809808, 'blx ip'), (8809844, 'blx r3'), (8809880, 'bl sym.imp.NSLog'), (8809964, 'blx ip'), (8810016, 'blx ip'), (8810076, 'blx r2'), (8810108, 'bl sym.imp.NSLog')],
        branches=[(8807988, 'beq', 8810112), (8808200, 'beq', 8810024), (8808484, 'beq', 8809888), (8808600, 'bne', 8809888), (8808752, 'beq', 8809744), (8808832, 'beq', 8808844), (8808976, 'bne', 8809620), (8809144, 'bne', 8809316), (8809620, 'b', 8809624), (8809648, 'blo', 8808796), (8809740, 'bne', 8808796), (8809744, 'b', 8809748), (8809856, 'bne', 8809884), (8809884, 'b', 8809888)],
        semantics=('unarchiveLightBlocksForClient: migrates one client\'s legacy combined light-block archive in self->lightBlockDatabase@252 into per-block keys. key1 = [NSString stringWithFormat:@"%@_archiveKeys" (CFString 0x00f924f8), client] (0x008665e4) and data1 = [[db dataForKey:key1] gzipInflate] (0x00866610/0x00866620); nil returns (0x00866640). It takes t0 = [NSDate timeIntervalSinceReferenceDate] (0x008666a8), resolves clientObj = [[self->world@4 serverClients] objectForKey:client] (0x008666f4) - a nil record skips the per-block work, opens the bulk window with [self startBulkLightBlockTransaction] (0x00866740) and runs plistFromData(data1) through the out-of-body helper at 0x00866f0c = [NSPropertyListSerialization propertyListWithData:options:0 format:NULL error:NULL] (0x00866750), i.e. an NSArray of "a_b" strings. key2 = "%@_archiveData" (0x00f92508, 0x008667d4) and data2 = gzipInflate(db[key2]) (0x00866810); it requires [data2 length] == 1024 * [plist count] (mul at 0x00866888, bne 0x866da0) or it jumps straight to the removal tail. It then fast-enumerates the plist (batch 16, 0x00866924) and per item: comps = [item componentsSeparatedByString:@"_" (CFString 0x00f92518)] (0x008669f0) must have exactly 2 components (0x00866a10); itemkey = [NSString stringWithFormat:@"%@_%@" (0x00f92528), client, item] (0x00866a80); when ![db hasKey:itemkey] (0x00866ab8) it stores [data2 subdataWithRange:(1024*i, 1024)] (0x00866b2c) as the i-th packed 1024-byte light block, computes idx = macroIndexAtMacroPosition(comps[0].intValue, comps[1].intValue, world) (0x00866c38) and adds it to [clientObj allLightBlockIndices] (0x00866c90). Afterwards [clientObj saveLightBlockIndices] (0x00866d50) and, when every record migrated, NSLog(@"unarchived %d LightBlocks for client:%@", i, client) (0x00866d98). The tail (0x00866da0) always removes both legacy keys (0x008666dec for key1) and logs NSLog(@"unarchiveTime: %.4f", now - t0) (0x00866e7c). Measured caveat: the data2 == nil and length-mismatch paths jump to that same tail, so the legacy keys are deleted even when the migration did not happen.'),
    ),
    dict(
        name='wtl_archivelightblocksforc',
        method='WorldTileLoader -[archiveLightBlocksForClient:]',
        types='v12@0:4@8',
        start=8810288,
        end=8812112,
        disasm='disasm_worldtileloader_archivelightblocksforclient_.txt',
        base_add=8810304,
        base_literal=8812108,
        boundary='ARM.exidx end 0x00867650 (listing bound); next ObjC IMP 0x00867a58 WorldTileLoader -[loadLightBlockForClientLightBlockIndex:clientID:intoPhysicalBlock:]',
        selectors={
                 0x867590: (15213736, 'dataForKey:'),
                 0x867598: (15213488, 'stringWithFormat:'),
                 0x8675a4: (15213828, 'unarchiveLightBlocksForClient:'),
                 0x8675ac: (15213844, 'finishDecoding'),
                 0x8675b0: (15213840, 'autorelease'),
                 0x8675b4: (15213492, 'retain'),
                 0x8675bc: (15213836, 'decodeObjectForKey:'),
                 0x8675c0: (15213832, 'initForReadingWithData:'),
                 0x8675c4: (15213500, 'alloc'),
                 0x8675d4: (15213760, 'timeIntervalSinceReferenceDate'),
                 0x8675dc: (15213848, 'array'),
                 0x8675e0: (15213712, 'count'),
                 0x8675f0: (15213856, 'enumerateIndexesUsingBlock:'),
                 0x8675fc: (15213628, 'dataWithBytes:length:'),
                 0x867600: (15213688, 'gzipDeflate'),
                 0x867614: (15213708, 'setData:forKey:'),
                 0x86762c: (15213824, 'removeDataForKey:'),
                 0x867648: (15213588, 'release'),
        },
        imports={
                 0x86758c: (17151904, 'objc_msgSend'),
                 0x867594: (16328040, '__CFConstantStringClassReference'),
                 0x8675a8: (16328024, '__CFConstantStringClassReference'),
                 0x8675b8: (16328056, '__CFConstantStringClassReference'),
                 0x8675e4: (17151928, '_NSConcreteStackBlock'),
                 0x867610: (16327944, '__CFConstantStringClassReference'),
                 0x867620: (16327928, '__CFConstantStringClassReference'),
                 0x867634: (16328088, '__CFConstantStringClassReference'),
                 0x867640: (16328104, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x8675a0: (17161580, 'OBJC_IVAR_$_WorldTileLoader.lightBlockDatabase', 252),
        },
        classes={
                 0x86759c: (15247496, 'OBJC_CLASS_$_NSString'),
                 0x8675c8: (15247548, 'OBJC_CLASS_$_NSKeyedUnarchiver'),
                 0x8675cc: (15247544, 'OBJC_CLASS_$_NSDate'),
                 0x8675d8: (15247552, 'OBJC_CLASS_$_NSMutableArray'),
                 0x8675f4: (15247528, 'OBJC_CLASS_$_NSData'),
        },
        instructions=[(8810288, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8810340, 'bl sym.imp.NSLog'), (8810476, 'blx r8'), (8810592, 'beq 0x86757c'), (8810796, 'blx r3'), (8810972, 'bl sym.imp.__wrap_malloc'), (8811132, 'bl loc.imp.objc_msgSend'), (8811228, 'bl loc.imp.objc_msgSend'), (8811388, 'bl loc.imp.objc_msgSend'), (8811560, 'bl loc.imp.objc_msgSend'), (8811676, 'bl loc.imp.objc_msgSend'), (8812108, 'rsbseq r8, pc, ip, lsr 23')],
        calls=[(8810340, 'bl sym.imp.NSLog'), (8810476, 'blx r8'), (8810540, 'blx ip'), (8810572, 'blx r3'), (8810748, 'blx lr'), (8810768, 'blx r3'), (8810796, 'blx r3'), (8810812, 'blx r2'), (8810828, 'blx r2'), (8810852, 'blx r2'), (8810904, 'bl loc.imp.objc_msgSend'), (8810936, 'bl loc.imp.objc_msgSend'), (8810960, 'bl loc.imp.objc_msgSend'), (8810972, 'bl sym.imp.__wrap_malloc'), (8811132, 'bl loc.imp.objc_msgSend'), (8811196, 'bl loc.imp.objc_msgSend'), (8811228, 'bl loc.imp.objc_msgSend'), (8811252, 'bl 0x859918'), (8811284, 'bl loc.imp.objc_msgSend'), (8811388, 'bl loc.imp.objc_msgSend'), (8811428, 'bl loc.imp.objc_msgSend'), (8811520, 'bl loc.imp.objc_msgSend'), (8811560, 'bl loc.imp.objc_msgSend'), (8811640, 'bl loc.imp.objc_msgSend'), (8811676, 'bl loc.imp.objc_msgSend'), (8811716, 'bl sym.imp.NSLog'), (8811748, 'bl loc.imp.objc_msgSend'), (8811800, 'bl sym.imp.NSLog'), (8811836, 'bl sym.imp._Block_object_dispose'), (8811852, 'bl sym.imp._Block_object_dispose'), (8811896, 'blx r2'), (8811912, 'bl sym.imp._Unwind_Resume')],
        branches=[(8810592, 'beq', 8811900), (8810868, 'beq', 8811856), (8811136, 'b', 8811140), (8811152, 'ble', 8811844), (8811204, 'b', 8811208), (8811236, 'b', 8811240), (8811260, 'b', 8811264), (8811292, 'b', 8811296), (8811396, 'b', 8811400), (8811436, 'b', 8811440), (8811528, 'b', 8811532), (8811568, 'b', 8811572), (8811648, 'b', 8811652), (8811684, 'b', 8811688), (8811720, 'b', 8811724), (8811760, 'b', 8811764), (8811804, 'b', 8811808), (8811808, 'b', 8811844), (8811840, 'b', 8811908)],
        semantics=('archiveLightBlocksForClient: persists one client\'s light blocks into self->lightBlockDatabase@252. It logs CFString "archiveLightBlocksForClient:%@" (0x00866f64), first calls [self unarchiveLightBlocksForClient:client] (0x00866fec) to materialise any legacy data, takes t0 = [NSDate timeIntervalSinceReferenceDate] (0x00867198) and makes arr = [NSMutableArray array] (0x008671b8). It reads "%@_allIndexes" (CFString 0x00f92568) from the database (0x0086702c/0x0086704c) and returns when that data is nil (0x00867060); otherwise the blob is NSKeyedUnarchiver-decoded (initForReadingWithData: 0x00867110, decodeObjectForKey:@"all" 0x0086712c) into an NSIndexSet. It allocates buf = malloc([set count] << 10) (0x008671dc, 1024 bytes per index) and enumerates the index set (enumerateIndexesUsingBlock: 0x0086727c with the block at 0x008675e8/0x008675ec): the block maps each index through macroPosForMacroIndex(int, World*) (0x008676b0) and memcpys 0x400 bytes into buf+count*1024 (0x008678a4), incrementing a captured __block counter (0x008678bc); a counter <= 0 skips the write (0x00867290). Otherwise it stores [NSData dataWithBytes:buf length:count<<10] gzipDeflate (0x008672bc/0x008672dc) as "%@_archiveData" (CFString 0x00f92508, 0x0086737c) and the keys array serialised by the out-of-body helper 0x859918 = [NSPropertyListSerialization dataWithPropertyList:format:100(binary) options:error:] and then gzipDeflate (0x008672f4/0x00867314) as "%@_archiveKeys" (CFString 0x00f924f8, 0x00867428), removes "%@_allIndexes" (0x0086749c) and logs the count and elapsed time (0x008674c4/0x00867518).'),
    ),
    dict(
        name='wtl_loadlightblockforclien',
        method='WorldTileLoader -[loadLightBlockForClientLightBlockIndex:clientID:intoPhysicalBlock:]',
        types='v20@0:4i8@12^{PhysicalBlock=ii^{Tile}cCdII[32*][32C]}16',
        start=8813144,
        end=8815076,
        disasm='disasm_worldtileloader_loadlightblockforclientlightblockindex_c.txt',
        base_add=8813160,
        base_literal=8815072,
        boundary='ARM.exidx end 0x008681e4 (listing bound); next ObjC IMP 0x008681e4 WorldTileLoader -[sendLightBlockToClientWithoutSavingForBlock:pos:sendToClient:server:]',
        selectors={
                 0x868180: (15213736, 'dataForKey:'),
                 0x86818c: (15213488, 'stringWithFormat:'),
                 0x868194: (15213860, 'hasFinishedDatabaseMigrationTo17'),
                 0x86819c: (15213744, 'fileExistsAtPath:'),
                 0x8681a0: (15213512, 'defaultManager'),
                 0x8681a8: (15213536, 'stringByAppendingPathComponent:'),
                 0x8681bc: (15213532, 'substringWithRange:'),
                 0x8681c0: (15213524, 'length'),
                 0x8681c4: (15213740, 'gzipInflate'),
                 0x8681c8: (15213748, 'dataWithContentsOfFile:'),
                 0x8681d0: (15213864, 'startPortalPos'),
                 0x8681d8: (15213868, 'fullyLoadIfNeededAroundPos:clientLightBlockIndex:forBlockhead:'),
                 0x8681dc: (15213752, 'bytes'),
        },
        imports={
                 0x86817c: (17151904, 'objc_msgSend'),
                 0x868188: (16328120, '__CFConstantStringClassReference'),
                 0x8681b0: (16328136, '__CFConstantStringClassReference'),
                 0x8681b4: (16327608, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x868184: (17161580, 'OBJC_IVAR_$_WorldTileLoader.lightBlockDatabase', 252),
                 0x868198: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
                 0x8681ac: (17161576, 'OBJC_IVAR_$_WorldTileLoader.blockDirectory', 12),
        },
        classes={
                 0x868190: (15247496, 'OBJC_CLASS_$_NSString'),
                 0x8681a4: (15247508, 'OBJC_CLASS_$_NSFileManager'),
                 0x8681cc: (15247528, 'OBJC_CLASS_$_NSData'),
        },
        instructions=[(8813144, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8813384, 'blx ip'), (8813468, 'blx r2'), (8813404, 'bne 0x867ebc'), (8813968, 'blx r4'), (8814256, 'blx r2'), (8814372, 'str r0, [r1, 0x20]'), (8814504, 'strb r1, [r0]'), (8814600, 'str r0, [r1]'), (8814624, 'strb r1, [r0]'), (8814956, 'bl loc.imp.objc_msgSend'), (8815072, 'rsbseq r8, pc, r4, lsl 1')],
        calls=[(8813340, 'blx r5'), (8813384, 'blx ip'), (8813468, 'blx r2'), (8813748, 'bl loc.imp.objc_msgSend'), (8813812, 'bl loc.imp.objc_msgSend'), (8813848, 'bl loc.imp.objc_msgSend'), (8813916, 'bl loc.imp.objc_msgSend'), (8813968, 'blx r4'), (8814048, 'blx ip'), (8814092, 'blx ip'), (8814128, 'blx r3'), (8814148, 'blx r3'), (8814240, 'blx ip'), (8814256, 'blx r2'), (8814356, 'bl sym.imp.__wrap_malloc'), (8814424, 'blx r3'), (8814456, 'blx r3'), (8814480, 'bl sym.imp.memcpy'), (8814580, 'bl sym.imp.__wrap_calloc'), (8814688, 'bl loc.imp.objc_msgSend_stret'), (8814724, 'bl sym.imp.memset'), (8814956, 'bl loc.imp.objc_msgSend')],
        branches=[(8813404, 'bne', 8814268), (8813480, 'bne', 8814268), (8814160, 'beq', 8814264), (8814264, 'b', 8814268), (8814280, 'beq', 8814512), (8814508, 'b', 8814964), (8814672, 'beq', 8814696), (8814692, 'b', 8814728), (8814756, 'blt', 8814960), (8814792, 'bge', 8814960), (8814824, 'blt', 8814960), (8814860, 'bge', 8814960), (8814960, 'b', 8814964)],
        semantics=('loadLightBlockForClientLightBlockIndex:clientID:intoPhysicalBlock: resolves one light block into a PhysicalBlock. It builds the cache key [NSString stringWithFormat:@"%@_%d_%d" (CFString 0x00f925b8), clientID, physicalBlock->x (offset 0), physicalBlock->y (offset 4)] (0x00867b48) and reads [self->lightBlockDatabase@252 dataForKey:key] (0x00867b9c); a non-nil result skips the file path (bne 0x867ebc). When it is nil, the world exists and ![world hasFinishedDatabaseMigrationTo17] (0x00867b5c region), it composes the shard path [NSString stringWithFormat:@"playerLightBlocks/%@/%@/%@/" (0x00f923b8), clientID[0,1], clientID[1,1], clientID[2,len-2]] (0x00867d90) and the file name [NSString stringWithFormat:@"%@%d_%d_lightBlock" (0x00f925c8)] under self->blockDirectory@12 (0x00867e44 checks fileExistsAtPath:, 0x00867eb0 does [NSData dataWithContentsOfFile:] gzipInflate). Installation then writes the PhysicalBlock record the recursion below reveals: **x@0, y@4, tiles[32]@0x20, flags[32]@0xA0** - with data it sets tiles[lightBlockIndex] = malloc(0x400) (0x00867f14/0x00867f24) + memcpy(data.length) and flags[i] = 1 (0x00867fa8), without data it sets tiles[i] = calloc(1, 0x400) (0x00867ff4/0x00868008) and flags[i] = 0 (0x00868020). Finally, when the block contains world.startPortalPos (32 tiles per block, lsl r2,2,5 at 0x00868098; 8-byte IntPair zeroed at 0x0086806c), it calls [world fullyLoadIfNeededAroundPos:(startPortalPos) clientLightBlockIndex:lightBlockIndex forBlockhead:nil] (0x0086816c).'),
    ),
    dict(
        name='wtl_sendlightblocktoclient',
        method='WorldTileLoader -[sendLightBlockToClientWithoutSavingForBlock:pos:sendToClient:server:]',
        types='c28@0:4^{PhysicalBlock=ii^{Tile}cCdII[32*][32C]}8{?=ii}12@20@24',
        start=8815076,
        end=8816384,
        disasm='disasm_worldtileloader_sendlightblocktoclientwithoutsavingforbl.txt',
        base_add=8815092,
        base_literal=8816380,
        boundary='ARM.exidx end 0x00868700 (listing bound); next ObjC IMP 0x00868700 WorldTileLoader -[saveLightBlockForClientLightBlockIndex:clientID:physicalBlock:sendNow:]',
        selectors={
                 0x8686bc: (15213648, 'lightBlockIndex'),
                 0x8686c0: (15213640, 'objectForKey:'),
                 0x8686c4: (15213636, 'serverClients'),
                 0x8686cc: (15213644, 'connected'),
                 0x8686d0: (15213696, 'sendNetworkData:toPeers:reliable:'),
                 0x8686d4: (15213692, 'arrayWithObject:'),
                 0x8686dc: (15213632, 'appendData:'),
                 0x8686e0: (15213688, 'gzipDeflate'),
                 0x8686e4: (15213684, 'appendBytes:length:'),
                 0x8686e8: (15213628, 'dataWithBytes:length:'),
                 0x8686f0: (15213480, 'worldWidthMacro'),
        },
        imports={
                 0x8686b8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8686c8: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
        },
        classes={
                 0x8686d8: (15247536, 'OBJC_CLASS_$_NSArray'),
                 0x8686ec: (15247524, 'OBJC_CLASS_$_NSMutableData'),
                 0x8686f4: (15247528, 'OBJC_CLASS_$_NSData'),
        },
        instructions=[(8815076, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8815152, 'bne 0x868240'), (8815344, 'blx r2'), (8815464, 'ldr r2, [r2]'), (8815720, 'movw r1, 0x400'), (8816288, 'blx lr'), (8816048, 'strb r0, [fp, -0x3d]'), (8816376, 'rsbseq r7, pc, r8, ror 12')],
        calls=[(8815288, 'blx r5'), (8815320, 'blx r3'), (8815344, 'blx r2'), (8815408, 'blx r2'), (8815864, 'blx ip'), (8815920, 'blx lr'), (8815952, 'blx r3'), (8816020, 'blx ip'), (8816092, 'blx lr'), (8816136, 'blx ip'), (8816156, 'blx r2'), (8816184, 'blx r3'), (8816240, 'blx r3'), (8816288, 'blx lr')],
        branches=[(8815152, 'bne', 8815168), (8815164, 'b', 8816300), (8815364, 'beq', 8816292), (8815420, 'beq', 8816292), (8815436, 'beq', 8816292), (8815476, 'beq', 8816292)],
        semantics=("sendLightBlockToClientWithoutSavingForBlock:pos:sendToClient:server: sends one block's light data to a client without touching the database. Guards, each returning 0: sendToClient != nil (0x00868230), the client record exists ([[world serverClients] objectForKey:sendToClient], 0x008682b8/0x008682d8), [record lightBlockIndex] (0x008682f0), [record connected] (0x0086833c), server != nil (0x0086834c) and the block's pointer slot != 0 (*(block+0x20+idx*4) at 0x00868368). It then builds the payload as an NSMutableData/NSData from that pointer (dataWithBytes:length: 0x008686e8 with length 0x400 at 0x00868468, plus appendBytes:length:/appendData: 0x008686e4/0x008686dc and gzipDeflate 0x008686e0) and sends it with [server sendNetworkData:<data> toPeers:[NSArray arrayWithObject:sendToClient] reliable:(sxtb of [fp,-0x88] = 0)] (selector cell 0x008686d0, final dispatch 0x008686a0). The return value is the BOOL at [fp,-0x3d] (1 on the successful path at 0x008685b0). Nothing is written to lightBlockDatabase in this body."),
    ),
    dict(
        name='wtl_savelightblockforclien',
        method='WorldTileLoader -[saveLightBlockForClientLightBlockIndex:clientID:physicalBlock:sendNow:]',
        types='v24@0:4i8@12^{PhysicalBlock=ii^{Tile}cCdII[32*][32C]}16c20',
        start=8816384,
        end=8817520,
        disasm='disasm_worldtileloader_savelightblockforclientlightblockindex_c.txt',
        base_add=8816400,
        base_literal=8817516,
        boundary='ARM.exidx end 0x00868b70 (listing bound); next ObjC IMP 0x00868b70 WorldTileLoader -[startBulkLightBlockTransaction]',
        selectors={
                 0x868b24: (15213640, 'objectForKey:'),
                 0x868b28: (15213636, 'serverClients'),
                 0x868b30: (15213872, 'containsIndex:'),
                 0x868b34: (15213812, 'allLightBlockIndices'),
                 0x868b38: (15213708, 'setData:forKey:'),
                 0x868b44: (15213488, 'stringWithFormat:'),
                 0x868b4c: (15213628, 'dataWithBytes:length:'),
                 0x868b58: (15213820, 'saveLightBlockIndices'),
                 0x868b5c: (15213816, 'addIndex:'),
                 0x868b64: (15213496, 'server'),
                 0x868b68: (15213876, 'sendLightBlockToClientWithoutSavingForBlock:pos:sendToClient:server:'),
        },
        imports={
                 0x868b20: (17151904, 'objc_msgSend'),
                 0x868b40: (16328120, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x868b2c: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
                 0x868b3c: (17161580, 'OBJC_IVAR_$_WorldTileLoader.lightBlockDatabase', 252),
        },
        classes={
                 0x868b48: (15247496, 'OBJC_CLASS_$_NSString'),
                 0x868b50: (15247528, 'OBJC_CLASS_$_NSData'),
        },
        instructions=[(8816384, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8816460, 'ldr r0, [r0]'), (8816628, 'beq 0x868b18'), (8816844, 'blx r8'), (8816972, 'blx lr'), (8817128, 'bne 0x868a68'), (8817264, 'beq 0x868b14'), (8817420, 'bl loc.imp.objc_msgSend'), (8817512, 'invalid')],
        calls=[(8816576, 'blx lr'), (8816608, 'blx r3'), (8816844, 'blx r8'), (8816924, 'blx ip'), (8816972, 'blx lr'), (8817028, 'bl sym.macroIndexAtMacroPosition_int__int__World_'), (8817096, 'blx lr'), (8817116, 'blx r3'), (8817212, 'blx r4'), (8817232, 'blx r3'), (8817252, 'blx r2'), (8817308, 'bl sym.makeIntpair_int__int_'), (8817368, 'bl loc.imp.objc_msgSend'), (8817420, 'bl loc.imp.objc_msgSend')],
        branches=[(8816476, 'bne', 8816484), (8816480, 'b', 8817432), (8816628, 'beq', 8817432), (8817128, 'bne', 8817256), (8817264, 'beq', 8817428), (8817428, 'b', 8817432)],
        semantics=("saveLightBlockForClientLightBlockIndex:clientID:physicalBlock:sendNow: persists one client's light block. It gates on the block's pointer slot elem = *(block+0x20+idx*4) != 0 (0x0086874c/0x0086875c) and on the client record [world.serverClients objectForKey:clientID] != nil (0x008687f4), then writes unconditionally: [self->lightBlockDatabase@252 setData:[NSData dataWithBytes:elem length:0x400] forKey:[NSString stringWithFormat:cf, physicalBlock->x, physicalBlock->y]] (0x008688cc for the data, 0x0086891c for the key, 0x0086894c for the store). It maps the block through macroIndexAtMacroPosition (0x00868984) and, when ![record.allLightBlockIndices containsIndex:M] (0x008689e8), adds it and calls [record saveLightBlockIndices] (0x00868a50/0x00868a64). Only when the sendNow char is non-zero (strb at 0x00868738, test at 0x00868a70) does it re-broadcast through [self sendLightBlockToClientWithoutSavingForBlock:pos:makeIntpair(x,y) sendToClient:clientID server:[world server]] (0x00868a9c/0x00868ad8/0x00868b0c) - the database write is not gated by the flag."),
    ),
    dict(
        name='wtl_startbulklightblocktra',
        method='WorldTileLoader -[startBulkLightBlockTransaction]',
        types='v8@0:4',
        start=8817520,
        end=8817728,
        disasm='disasm_worldtileloader_startbulklightblocktransaction.txt',
        base_add=8817536,
        base_literal=8817620,
        boundary='ARM.exidx end 0x00868c40 (listing bound); next ObjC IMP 0x00868bd8 WorldTileLoader -[finishBulkLightBlockTransaction]',
        selectors={
                 0x868bcc: (15213880, 'startBulkTransaction'),
                 0x868c34: (15213884, 'finishBulkTransaction'),
        },
        imports={
                 0x868bc8: (17151904, 'objc_msgSend'),
                 0x868c30: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x868bd0: (17161584, 'OBJC_IVAR_$_WorldTileLoader.lightBlockDatabaseEnvironment', 248),
                 0x868c38: (17161584, 'OBJC_IVAR_$_WorldTileLoader.lightBlockDatabaseEnvironment', 248),
        },
        classes={},
        instructions=[(8817520, 'push {fp, lr}'), (8817584, 'ldr r0, [r0]'), (8817592, 'blx r3'), (8817724, 'rsbseq r6, pc, r4, lsl 30')],
        calls=[(8817592, 'blx r3'), (8817696, 'blx r3')],
        branches=[],
        semantics=('startBulkLightBlockTransaction opens the light-block database\'s bulk write window: it loads self->lightBlockDatabaseEnvironment@248 (declared type @"DatabaseEnvironment", ivar cell 0x00868bd0) and sends -startBulkTransaction (selector cell 0x00868bcc) at 0x00868bb8; the void result is spilled to [sp,4] and discarded (types v8@0:4).'),
    ),
    dict(
        name='wtl_finishbulklightblocktr',
        method='WorldTileLoader -[finishBulkLightBlockTransaction]',
        types='c8@0:4',
        start=8817624,
        end=8817728,
        disasm='disasm_worldtileloader_finishbulklightblocktransaction.txt',
        base_add=8817640,
        base_literal=8817724,
        boundary='ARM.exidx end 0x00868c40 (listing bound); next ObjC IMP 0x00868c40 WorldTileLoader -[randomSeed]',
        selectors={
                 0x868c34: (15213884, 'finishBulkTransaction'),
        },
        imports={
                 0x868c30: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x868c38: (17161584, 'OBJC_IVAR_$_WorldTileLoader.lightBlockDatabaseEnvironment', 248),
        },
        classes={},
        instructions=[(8817624, 'push {fp, lr}'), (8817688, 'ldr r0, [r0]'), (8817696, 'blx r3'), (8817700, 'sxtb r0, r0'), (8817724, 'rsbseq r6, pc, r4, lsl 30')],
        calls=[(8817696, 'blx r3')],
        branches=[],
        semantics=("finishBulkLightBlockTransaction closes/commits the same window: it sends -finishBulkTransaction (selector cell 0x00868c34) to self->lightBlockDatabaseEnvironment@248 (cell 0x00868c38) at 0x00868c20 and sign-extends the result (sxtb at 0x00868c24, types c8@0:4) - the char is the environment's finish result."),
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
        'batch': 'Light-block persistence batch (E13): the WorldTileLoader light-block store that intersects the save line - unarchiveLightBlocksForClient: (legacy combined archive migration into per-block keys), archiveLightBlocksForClient: (allIndexes -> archiveData/archiveKeys pair), loadLightBlockForClientLightBlockIndex:clientID:intoPhysicalBlock: (cache-or-disk load into PhysicalBlock tiles@0x20/flags@0xA0), saveLightBlockForClientLightBlockIndex:clientID:physicalBlock:sendNow:, sendLightBlockToClientWithoutSavingForBlock:pos:sendToClient:server: and the start/finishBulkLightBlockTransaction pair; 7 bodies',
        'claim': ('static bounded-body maps with per-instruction anchors; the DatabaseEnvironment '
                  'implementations behind start/finishBulkTransaction, the on-disk shard file layout '
                  'beyond the path construction, the class of the client record object and the '
                  'game-side meaning of the packed 1024-byte light chunk are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'lightblock_persistence.json')
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
