#!/usr/bin/env python3
"""Hash-gated recovery of the Physical-block save/sync batch (E14).

The WorldTileLoader physical-block write + client-sync pair - the main-block
counterpart of the light-block line:
2 bodies, 2079 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/BLOCK_SAVE_SYNC.md for the prose and boundaries.
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
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl sym.imp.NSLog': 0x001c2a5c,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
}

SPECS = [
    dict(
        name='wtl_savephysicalblock_macr',
        method='WorldTileLoader -[savePhysicalBlock:macroTile:sendToClients:server:sendReliably:]',
        types='v28@0:4^{PhysicalBlock=ii^{Tile}cCdII[32*][32C]}8^{MacroTile=CCC^{PhysicalBlock}^{DrawBlock}@f}12@16@20c24',
        start=8755844,
        end=8759372,
        disasm='disasm_worldtileloader_savephysicalblock_macrotile_sendtoclient.txt',
        base_add=8755860,
        base_literal=8759368,
        boundary='ARM.exidx end 0x0085a84c (listing bound); next ObjC IMP 0x0085a84c WorldTileLoader -[sandFractionForPos:highRes:]',
        selectors={
                 0x85a7a8: (15213688, 'gzipDeflate'),
                 0x85a7ac: (15213632, 'appendData:'),
                 0x85a7b0: (15213628, 'dataWithBytes:length:'),
                 0x85a7c8: (15213704, 'raise:format:'),
                 0x85a7d0: (15213520, 'countByEnumeratingWithState:objects:count:'),
                 0x85a7d4: (15213656, 'dictionary'),
                 0x85a7e4: (15213636, 'serverClients'),
                 0x85a7e8: (15213640, 'objectForKey:'),
                 0x85a7ec: (15213648, 'lightBlockIndex'),
                 0x85a7f0: (15213652, 'loadLightBlockForClientLightBlockIndex:clientID:intoPhysicalBlock:'),
                 0x85a7fc: (15213660, 'playerIsAdminWithID:'),
                 0x85a800: (15213488, 'stringWithFormat:'),
                 0x85a808: (15213664, 'stringFromMD5'),
                 0x85a80c: (15213668, 'setObject:forKey:'),
                 0x85a814: (15213672, 'getAndRemoveAllRecieptDataForMacroPos:world:'),
                 0x85a81c: (15213708, 'setData:forKey:'),
                 0x85a828: (15213712, 'count'),
                 0x85a82c: (15213480, 'worldWidthMacro'),
                 0x85a834: (15213684, 'appendBytes:length:'),
                 0x85a83c: (15213696, 'sendNetworkData:toPeers:reliable:'),
                 0x85a840: (15213692, 'arrayWithObject:'),
        },
        imports={
                 0x85a7a4: (17151904, 'objc_msgSend'),
                 0x85a7c0: (16327848, '__CFConstantStringClassReference'),
                 0x85a7c4: (16327864, '__CFConstantStringClassReference'),
                 0x85a804: (16327688, '__CFConstantStringClassReference'),
                 0x85a810: (16327704, '__CFConstantStringClassReference'),
                 0x85a818: (16327720, '__CFConstantStringClassReference'),
                 0x85a820: (16327880, '__CFConstantStringClassReference'),
                 0x85a830: (16327784, '__CFConstantStringClassReference'),
                 0x85a838: (16327800, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x85a7dc: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
                 0x85a824: (17161556, 'OBJC_IVAR_$_WorldTileLoader.blockDatabase', 256),
        },
        classes={
                 0x85a7b4: (15247528, 'OBJC_CLASS_$_NSData'),
                 0x85a7bc: (15247524, 'OBJC_CLASS_$_NSMutableData'),
                 0x85a7cc: (15247540, 'OBJC_CLASS_$_NSException'),
                 0x85a7d8: (15247532, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x85a7f8: (15247496, 'OBJC_CLASS_$_NSString'),
                 0x85a844: (15247536, 'OBJC_CLASS_$_NSArray'),
        },
        instructions=[(8755844, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8756096, 'blx r7'), (8756288, 'blx r2'), (8756400, 'blx r4'), (8756476, 'str ip, [sl, 0x18]'), (8756596, 'blx lr'), (8756928, 'blx ip'), (8757044, 'bl loc.imp.objc_msgSend'), (8757340, 'bl loc.imp.objc_msgSend'), (8757436, 'bl 0x859918'), (8757896, 'blx ip'), (8758112, 'mul r0, r1, r0'), (8759064, 'blx lr'), (8759368, 'addeq r6, r0, r8, asr r0')],
        calls=[(8756096, 'blx r7'), (8756152, 'blx lr'), (8756184, 'blx r3'), (8756236, 'blx lr'), (8756268, 'blx r3'), (8756288, 'blx r2'), (8756400, 'blx r4'), (8756524, 'blx r2'), (8756548, 'bl sym.imp.memset'), (8756596, 'blx lr'), (8756696, 'bl sym.imp.objc_enumerationMutation'), (8756780, 'bl loc.imp.objc_msgSend'), (8756800, 'bl loc.imp.objc_msgSend'), (8756820, 'bl loc.imp.objc_msgSend'), (8756928, 'blx ip'), (8757044, 'bl loc.imp.objc_msgSend'), (8757072, 'bl loc.imp.objc_msgSend'), (8757136, 'bl loc.imp.objc_msgSend'), (8757192, 'bl loc.imp.objc_msgSend'), (8757208, 'bl loc.imp.objc_msgSend'), (8757256, 'bl loc.imp.objc_msgSend'), (8757284, 'bl sym.makeIntpair_int__int_'), (8757340, 'bl loc.imp.objc_msgSend'), (8757428, 'blx ip'), (8757436, 'bl 0x859918'), (8757528, 'blx ip'), (8757580, 'blx lr'), (8757688, 'blx ip'), (8757860, 'blx lr'), (8757896, 'blx ip'), (8757960, 'blx r2'), (8758104, 'blx r2'), (8758144, 'bl sym.imp.memset'), (8758192, 'blx lr'), (8758292, 'bl sym.imp.objc_enumerationMutation'), (8758548, 'blx ip'), (8758592, 'blx ip'), (8758628, 'blx r3'), (8758664, 'blx r3'), (8758708, 'blx ip'), (8758800, 'blx r2'), (8758836, 'blx ip'), (8758844, 'bl 0x859918'), (8758960, 'blx r7'), (8759016, 'blx r3'), (8759064, 'blx lr'), (8759164, 'blx ip')],
        branches=[(8756308, 'bne', 8756404), (8756608, 'beq', 8757712), (8756688, 'beq', 8756700), (8756860, 'bne', 8756932), (8756968, 'beq', 8757588), (8757360, 'beq', 8757432), (8757456, 'beq', 8757584), (8757584, 'b', 8757588), (8757588, 'b', 8757592), (8757616, 'blo', 8756652), (8757708, 'bne', 8756652), (8757712, 'b', 8757716), (8757916, 'beq', 8759196), (8757968, 'bls', 8759196), (8758204, 'beq', 8759188), (8758284, 'beq', 8758296), (8758724, 'beq', 8758840), (8759092, 'blo', 8758248), (8759184, 'bne', 8758248), (8759188, 'b', 8759192), (8759192, 'b', 8759196)],
        semantics=("savePhysicalBlock:macroTile:sendToClients:server:sendReliably: is the server-side physical-block writer: it gzips the block's tile image plus two scalar fields into the block database and then pushes per-client update packets to connected clients. After the prologue (push at 0x00859a84, PIC base from the pool word at 0x00859a90) it spills self to [fp,-0x20], physicalBlock to [fp,-0x28], macroTile to [fp,-0x2c], sendToClients to [fp,-0x30], server to [fp,-0x34] and the sendReliably byte to [fp,-0x35] (0x00859b10-0x00859b2c; the _cmd and macroTile spills are never read again). It builds the gzip input from the block: first [NSMutableData dataWithBytes:(the ^{Tile} pointer read from physicalBlock+8 at 0x00859b54) length:0x10000 (65536; the length operand is the pool literal moved at 0x00859b68)] (blx r7 = objc_msgSend at 0x00859b80; receiver NSMutableData from cell 0x0085a7bc, selector dataWithBytes:length: from cell 0x0085a7b0), then [buffer appendData:[NSData dataWithBytes:physicalBlock+13 length:1]] (create blx lr at 0x00859bb8, append blx r3 at 0x00859bd8) and [buffer appendData:[NSData dataWithBytes:physicalBlock+24 length:4]] (create blx lr at 0x00859c0c, append blx r3 at 0x00859c2c) - 65536+1+4 = 65541 bytes total, sourcing the 'C' byte at offset 13 (add r3, r3, 0xd at 0x00859b98) and the 'I' word at offset 24 (add r3, r3, 0x18 at 0x00859bec) of ^{PhysicalBlock=ii^{Tile}cCdII[32*][32C]}. [buffer gzipDeflate] (blx r2 at 0x00859c40, selector cell 0x0085a7a8) yields the compressed payload; when it returns nil the method raises [NSException raise:(CFString cell 0x0085a7c0) format:(CFString cell 0x0085a7c4)] (receiver cell 0x0085a7cc, selector raise:format: cell 0x0085a7c8, blx r4 at 0x00859cb0; the compared-against-zero register is the 0 spilled to [fp,-0x17c] at 0x00859b70, and bne 0x00859c54 skips the raise when the result is non-nil). It then increments the int at physicalBlock+24 in place (ldr 0x00859cf4, add 0x00859cf8, str 0x00859cfc) - after that value was copied into the gzip input at 0x00859bec - and creates the send dictionary [NSMutableDictionary dictionary] (0x00859d2c, cells 0x0085a7d8/0x0085a7d4) kept at [fp,-0x4c]. A first NSFastEnumeration pass over sendToClients runs in batches of 16 ([sendToClients countByEnumeratingWithState:&state(fp-0x70) objects:&buf(fp-0xb0) count:16] at 0x00859d74, later batches re-entering at 0x0085a1b8; the 0x20-byte state is zeroed at 0x00859d44, and a *mutationsPtr mismatch calls objc_enumerationMutation at 0x00859dd8 after beq 0x00859dd0). For each element item: it reads [self->world serverClients] (0x00859e2c, world ivar cell 0x0085a7dc), [that objectForKey:item] (0x00859e40), [that value lightBlockIndex] (0x00859e54), and when tiles[lightBlockIndex] (the 32-slot pointer array at offset 0x20, entry read at 0x00859e6c) is nil (bne 0x00859e7c skips when non-nil) calls [self loadLightBlockForClientLightBlockIndex:lightBlockIndex clientID:item intoPhysicalBlock:physicalBlock] (blx ip at 0x00859ec0); it re-reads the entry at 0x00859ed8 and skips the element entirely while it is still nil (beq 0x00859ee8). Otherwise it copies the light block [NSMutableData dataWithBytes:tiles[lightBlockIndex] length:0x400] (0x00859f34), makes a fresh dictionary at [fp,-0xc0] ([NSMutableDictionary dictionary], 0x00859f50), computes admin=[server playerIsAdminWithID:item] (0x00859f90), builds key=[NSString stringWithFormat:(CFString cell 0x0085a804) with item, physicalBlock->x (offset 0), physicalBlock->y (offset 4), admin] (0x00859fc8, NSString cell 0x0085a7f8), stores [dict1 setObject:[key stringFromMD5] forKey:(CFString cell 0x0085a810)] (0x00859fd8/0x0085a008), and when [client getAndRemoveAllRecieptDataForMacroPos:(x,y) world:self->world] (pair built via makeIntpair at 0x0085a024, call at 0x0085a05c) returns non-nil (beq 0x0085a070 skips when nil) adds [dict1 setObject:receipt forKey:(CFString cell 0x0085a818)] (0x0085a0b4). The dict is then serialized by the local function at 0x00859918 (bl at 0x0085a0bc; body outside this listing); when that returns non-nil (beq 0x0085a0d0 skips when nil) the object is appended to the copied light block ([copy appendData:object] at 0x0085a118) and the extended copy is registered [sendDict setObject:copy forKey:item] (0x0085a14c). When the pass drains (0x0085a1cc/0x0085a1d0) it builds key2=[NSString stringWithFormat:(CFString cell 0x0085a820) with x, y] (0x0085a264) and persists the compressed payload [self->blockDatabase setData:payload forKey:key2] (0x0085a288, blockDatabase ivar cell 0x0085a824). Finally, only when server is non-nil (beq 0x0085a29c) and [sendToClients count] > 0 (bls 0x0085a2d0) it makes a second batched pass (state2 at fp-0x100 zeroed at 0x0085a380, countBy at 0x0085a3b0, later batches at 0x0085a77c, token guard beq 0x0085a40c / objc_enumerationMutation 0x0085a414): per element it computes linear = physicalBlock->y * [self->world worldWidthMacro] (0x0085a358) + physicalBlock->x (mul 0x0085a360, add 0x0085a368), allocates a header buffer [NSMutableData dataWithBytes:&0x04 length:1] (0x0085a514; the header byte stored at 0x0085a314) and appends the index ([header appendBytes:&linear length:4] at 0x0085a540), fetches clientBlock=[sendDict objectForKey:item] (0x0085a564), makes dict2=[NSMutableDictionary dictionary] (0x0085a588) with [dict2 setObject:payload forKey:(CFString cell 0x0085a830)] (0x0085a5b4) and, when clientBlock is non-nil (beq 0x0085a5c4 skips when nil), [dict2 setObject:[clientBlock gzipDeflate] forKey:(CFString cell 0x0085a838)] (0x0085a610/0x0085a634); it serializes dict2 via 0x00859918 (bl at 0x0085a63c), appends the result to the header (0x0085a6b0), wraps the peer list as [NSArray arrayWithObject:item] (0x0085a6e8, NSArray cell 0x0085a844) and sends [server sendNetworkData:header toPeers:peers reliable:1] (0x0085a718, selector cell 0x0085a83c; the reliable:1 constant is the movw r1,1 at 0x0085a640 carried to the stacked char argument at 0x0085a70c-0x0085a710, while the sendReliably: byte spilled to [fp,-0x35] at 0x00859b2c is never read). The body returns at 0x0085a79c (sub sp, fp, 0x18; pop at 0x0085a7a0)."),
    ),
    dict(
        name='wtl_sendblocktoclientwitho',
        method='WorldTileLoader -[sendBlockToClientWithoutSavingForBlock:pos:sendToClient:server:sendDynamicObjects:reliable:]',
        types='c36@0:4^{PhysicalBlock=ii^{Tile}cCdII[32*][32C]}8{?=ii}12@20@24c28c32',
        start=8750692,
        end=8755480,
        disasm='disasm_worldtileloader_sendblocktoclientwithoutsavingforblock_p.txt',
        base_add=8750712,
        base_literal=8752204,
        boundary='ARM.exidx end 0x00859918 (listing bound); next ObjC IMP 0x00859a84 WorldTileLoader -[savePhysicalBlock:macroTile:sendToClients:server:sendReliably:]',
        selectors={
                 0x858c54: (15213640, 'objectForKey:'),
                 0x858c58: (15213636, 'serverClients'),
                 0x858c60: (15213632, 'appendData:'),
                 0x858c64: (15213628, 'dataWithBytes:length:'),
                 0x859880: (15213640, 'objectForKey:'),
                 0x859888: (15213632, 'appendData:'),
                 0x85988c: (15213628, 'dataWithBytes:length:'),
                 0x859894: (15213644, 'connected'),
                 0x85989c: (15213648, 'lightBlockIndex'),
                 0x8598a4: (15213652, 'loadLightBlockForClientLightBlockIndex:clientID:intoPhysicalBlock:'),
                 0x8598b4: (15213656, 'dictionary'),
                 0x8598bc: (15213660, 'playerIsAdminWithID:'),
                 0x8598c0: (15213488, 'stringWithFormat:'),
                 0x8598c8: (15213664, 'stringFromMD5'),
                 0x8598cc: (15213668, 'setObject:forKey:'),
                 0x8598d4: (15213672, 'getAndRemoveAllRecieptDataForMacroPos:world:'),
                 0x8598e0: (15213480, 'worldWidthMacro'),
                 0x8598e4: (15213680, 'initialDynamicObjectsNetDataForMacroTileIndex:wireForClient:'),
                 0x8598e8: (15213676, 'dynamicWorld'),
                 0x8598f0: (15213688, 'gzipDeflate'),
                 0x8598f4: (15213684, 'appendBytes:length:'),
                 0x8598fc: (15213696, 'sendNetworkData:toPeers:reliable:'),
                 0x859900: (15213692, 'arrayWithObject:'),
                 0x859908: (15213520, 'countByEnumeratingWithState:objects:count:'),
                 0x859910: (15213700, 'unsignedIntValue'),
        },
        imports={
                 0x858c50: (17151904, 'objc_msgSend'),
                 0x85987c: (17151904, 'objc_msgSend'),
                 0x859898: (16327768, '__CFConstantStringClassReference'),
                 0x8598a8: (16327752, '__CFConstantStringClassReference'),
                 0x8598c4: (16327688, '__CFConstantStringClassReference'),
                 0x8598d0: (16327704, '__CFConstantStringClassReference'),
                 0x8598d8: (16327720, '__CFConstantStringClassReference'),
                 0x8598dc: (16327736, '__CFConstantStringClassReference'),
                 0x8598ec: (16327784, '__CFConstantStringClassReference'),
                 0x8598f8: (16327800, '__CFConstantStringClassReference'),
                 0x85990c: (16327816, '__CFConstantStringClassReference'),
                 0x859914: (16327832, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x858c5c: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
                 0x859884: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
        },
        classes={
                 0x858c68: (15247528, 'OBJC_CLASS_$_NSData'),
                 0x858c70: (15247524, 'OBJC_CLASS_$_NSMutableData'),
                 0x859890: (15247524, 'OBJC_CLASS_$_NSMutableData'),
                 0x8598b0: (15247532, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x8598b8: (15247496, 'OBJC_CLASS_$_NSString'),
                 0x859904: (15247536, 'OBJC_CLASS_$_NSArray'),
        },
        instructions=[(8750692, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8750796, 'beq 0x859868'), (8750812, 'beq 0x859868'), (8751024, 'blx ip'), (8751296, 'blx r3'), (8751372, 'beq 0x858c30'), (8751420, 'bl loc.imp.objc_msgSend'), (8751440, 'add r0, r2, r0, lsl 2'), (8751528, 'blx ip'), (8751644, 'bl loc.imp.objc_msgSend'), (8752364, 'beq 0x858d60'), (8752472, 'blx ip'), (8753252, 'blx lr'), (8755476, 'invalid')],
        calls=[(8751024, 'blx ip'), (8751080, 'blx lr'), (8751112, 'blx r3'), (8751164, 'blx lr'), (8751196, 'blx r3'), (8751264, 'blx ip'), (8751296, 'blx r3'), (8751360, 'blx r2'), (8751420, 'bl loc.imp.objc_msgSend'), (8751528, 'blx ip'), (8751644, 'bl loc.imp.objc_msgSend'), (8751672, 'bl loc.imp.objc_msgSend'), (8751736, 'bl loc.imp.objc_msgSend'), (8751792, 'bl loc.imp.objc_msgSend'), (8751808, 'bl loc.imp.objc_msgSend'), (8751856, 'bl loc.imp.objc_msgSend'), (8751936, 'bl loc.imp.objc_msgSend'), (8752024, 'blx ip'), (8752032, 'bl 0x859918'), (8752104, 'blx r3'), (8752124, 'bl sym.imp.NSLog'), (8752156, 'bl sym.imp.NSLog'), (8752188, 'bl sym.imp.NSLog'), (8752324, 'blx r3'), (8752448, 'blx ip'), (8752472, 'blx ip'), (8752732, 'blx ip'), (8752776, 'blx ip'), (8752808, 'blx r3'), (8752848, 'blx r3'), (8752884, 'blx ip'), (8752976, 'blx r2'), (8753012, 'blx ip'), (8753020, 'bl 0x859918'), (8753136, 'blx r7'), (8753192, 'blx r3'), (8753252, 'blx lr'), (8753388, 'blx r7'), (8753412, 'bl sym.imp.memset'), (8753460, 'blx lr'), (8753560, 'bl sym.imp.objc_enumerationMutation'), (8753772, 'blx r3'), (8753820, 'blx ip'), (8753844, 'blx r2'), (8753876, 'blx ip'), (8753884, 'bl 0x859918'), (8754016, 'blx r2'), (8754048, 'blx r3'), (8754104, 'blx r3'), (8754152, 'blx lr'), (8754252, 'blx ip'), (8754396, 'blx r7'), (8754420, 'bl sym.imp.memset'), (8754468, 'blx lr'), (8754568, 'bl sym.imp.objc_enumerationMutation'), (8754788, 'blx r3'), (8754836, 'blx ip'), (8754860, 'blx r2'), (8754892, 'blx ip'), (8754900, 'bl 0x859918'), (8755032, 'blx r2'), (8755064, 'blx r3'), (8755120, 'blx r3'), (8755168, 'blx lr'), (8755268, 'blx ip')],
        branches=[(8750796, 'beq', 8755304), (8750812, 'beq', 8755304), (8751316, 'beq', 8752176), (8751372, 'beq', 8752176), (8751460, 'bne', 8751532), (8751568, 'beq', 8752144), (8751956, 'beq', 8752028), (8752052, 'beq', 8752112), (8752108, 'b', 8752140), (8752136, 'b', 8755312), (8752140, 'b', 8752172), (8752168, 'b', 8755312), (8752172, 'b', 8752244), (8752200, 'b', 8755312), (8752364, 'beq', 8752480), (8752900, 'beq', 8753016), (8753268, 'beq', 8755300), (8753472, 'beq', 8754276), (8753552, 'beq', 8753564), (8754180, 'blo', 8753516), (8754272, 'bne', 8753516), (8754276, 'b', 8754280), (8754480, 'beq', 8755292), (8754560, 'beq', 8754572), (8755196, 'blo', 8754524), (8755288, 'bne', 8754524), (8755292, 'b', 8755296), (8755296, 'b', 8755300), (8755300, 'b', 8755304)],
        semantics=("sendBlockToClientWithoutSavingForBlock:pos:sendToClient:server:sendDynamicObjects:reliable: assembles one macro block's payload and sends it (plus optional dynamic-object packets) to a single peer without saving. It first spills its arguments into a 0x48+0x400 stack frame (sub sp,#0x48 at 0x0085866c, sub sp,#0x400 at 0x00858670): self [fp,-0x2c], block [fp,-0x34], the pos intpair's first word [fp,-0x28] and second word [fp,-0x24] (r3 and the first stacked word), sendToClient [fp,-0x38], server [fp,-0x3c], sendDynamicObjects as a byte [fp,-0x3d] and reliable as a byte [fp,-0x3e] (0x00858698-0x008586bc). Two nil guards short-circuit to the flag copy at 0x859868 (and return 0): server == nil (beq 0x859868 at 0x008586cc) and sendToClient == nil (beq 0x859868 at 0x008586dc). It then builds the block payload as [NSMutableData dataWithBytes:*(block+8) length:0x10000] (message 0x008587b0, class cell 0x00858c70, selector cell 0x00858c64; the 0x10000 is the word at pool slot 0x00858c6c loaded raw at 0x00858740, no pc fixup) and appendData:'s [NSData dataWithBytes:(block+0xd) length:1] (message 0x008587e8) and [NSData dataWithBytes:(block+0x18) length:4] (message 0x0085883c) into it (appends at 0x00858808 and 0x0085885c); the u32 at block+0x18 is incremented right afterwards (0x00858860-0x0085886c). The client record is [<self->world> serverClients] (message 0x008588a0, ivar cell 0x00858c5c, offset 4) followed by [<that> objectForKey:sendToClient] (message 0x008588c0) into [fp,-0x4c]; a nil record branches to the NSLog at 0x858c30 (CFString cell 0x00859898) and returns 0 (0x008588d4), and a false [record connected] (message 0x00858900, cell 0x00859894) does the same (0x0085890c). idx = [record lightBlockIndex] (message 0x0085893c, cell 0x0085989c, saved to [fp,-0x50]); when the slot *(block+0x20+idx*4) is 0 (0x00858948-0x00858964) the body first calls [self loadLightBlockForClientLightBlockIndex:idx clientID:sendToClient intoPhysicalBlock:block] (message 0x008589a8, cell 0x008598a4, result unused) and re-tests, returning 0 through the NSLog at 0x858c10 (cell 0x008598a8) if the slot is still empty (beq 0x008589d0 at 0x008589d0). The per-tile payload [fp,-0x48] is [NSMutableData dataWithBytes:*(block+0x20+idx*4) length:0x400] (message 0x00858a1c, movw lr,#0x400 at 0x00858a00). Dictionary [fp,-0x54] ([NSMutableDictionary dictionary], 0x00858a38) receives [[NSString stringWithFormat: (CFString 0x008598c4) with sendToClient, pos word0, pos word1 and the BOOL from [server playerIsAdminWithID:sendToClient] (0x00858a78)] stringFromMD5] (0x00858ab0, 0x00858ac0) under CFString 0x008598d0 (0x00858af0), plus, when non-nil, [record getAndRemoveAllRecieptDataForMacroPos:world:] (0x00858b40, cell 0x008598d4, world = self->world on the stack at 0x00858b34) under CFString 0x008598d8 (0x00858b98); the local function at 0x00859918 serializes that dictionary (bl 0x859918 at 0x00858ba0) and its result is appendData:'d into the per-tile payload (0x00858be8), a nil serialization returning 0 via the NSLog at 0x858bf0 (cell 0x008598dc, 0x00858bb4). macroIndex = pos word0 + pos word1 * [world worldWidthMacro] (message 0x00858cc4, stored [fp,-0x70] at 0x00858cd8); sendDynamicObjects gates only the dynamic-object fetch: non-zero runs [fp,-0x74] = [[world dynamicWorld] initialDynamicObjectsNetDataForMacroTileIndex:macroIndex wireForClient:sendToClient] (messages 0x00858d40 and 0x00858d58, cells 0x008598e8/0x008598e4), zero branches past it at 0x00858cec leaving [fp,-0x74] = 0. The wire message itself is [NSMutableData dataWithBytes:&(char)4 length:1] (message 0x00858e5c; the 4 moved at 0x00858df8 and stored at 0x00858dfc/0x00858e0c; the return flag [fp,-0x3f] set to 1 at 0x00858e00-0x00858e04) plus appendBytes:&macroIndex length:4 (0x00858e88); dictionary [fp,-0x80] ([NSMutableDictionary dictionary], 0x00858ea8) then takes gzipDeflate(block payload) under CFString 0x008598ec (messages 0x00858ed0/0x00858ef4) and gzipDeflate(per-tile payload) under CFString 0x008598f8 (messages 0x00858f50/0x00858f74, skipped when the per-tile payload is nil at 0x00858f04), the serialized dictionary (bl 0x859918 at 0x00858f7c, result not nil-checked) is appendData:'d to the header (0x00858ff0), and the packet goes out as [server sendNetworkData:<data> toPeers:[NSArray arrayWithObject:sendToClient] reliable:(char)[fp,-0x3e]] (arrayWithObject: at 0x00859028, ldrb of [fp,-0x3e] at 0x0085902c, send at 0x00859064) - reliable controls only this message. When [fp,-0x74] is nil the method returns [fp,-0x3f] (0x00859074); otherwise it enumerates [<[fp,-0x74]> objectForKey:CFString(0x0085990c)] in 16-entry batches (message 0x008590ec, 32-byte enumeration state zeroed at 0x00859104, countByEnumeratingWithState:objects:count: at 0x00859134) and per entry sends [NSMutableData dataWithBytes:&(char)7 length:1] (tag moved at 0x008591e0, stored at 0x00859244/0x00859278; message 0x0085929c) + appendBytes:&(byte)[entry unsignedIntValue] length:1 (0x008592b4, 0x008592d4) + appendData:gzipDeflate(<local function at 0x00859918 applied to [collection objectForKey:entry]>, 0x0085926c, 0x008592dc, 0x00859360, 0x00859380) via [server sendNetworkData:...toPeers:[NSArray arrayWithObject:sendToClient] reliable:1] (0x008593b8, 0x008593e8; reliable hardcoded 1, not the argument), followed by a second identical pass over objectForKey:CFString(0x00859914) (0x008594dc) that tags entries with byte 8 (movw r3,8 at 0x008595d8, stored at 0x0085963c/0x00859670; message 0x00859694) and sends at 0x008597e0. The return value is the byte copied from [fp,-0x3f] at 0x00859868 (ldrb) and read at 0x00859870 (ldrsb): 1 for every run that gets past 0x00858e04, since no later path clears the flag, and 0 for the guarded failures (each writing 0 into its own local flag slot). Nothing is written to lightBlockDatabase in this body."),
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
        'batch': 'Physical-block save/sync batch (E14): the WorldTileLoader physical-block writer and its client-sync path - savePhysicalBlock:macroTile:sendToClients:server:sendReliably: (the 0x10000-byte tile payload + byte13 + offset-24 word, gzip, database key) and sendBlockToClientWithoutSavingForBlock:pos:sendToClient:server:sendDynamicObjects:reliable: (the broadcast, including the dynamic-objects flag); 2 bodies',
        'claim': ('static bounded-body maps with per-instruction anchors; the concrete database and '
                  'network implementations behind setData:forKey:, gzipDeflate and sendNetworkData:, the '
                  'runtime layout beyond the offsets these bodies touch, the class of the client-record '
                  'object and the receiver-side use of the broadcast payload are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'block_save_sync.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale block_save_sync.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
