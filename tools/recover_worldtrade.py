#!/usr/bin/env python3
"""Hash-gated recovery of the World trade prices and IAP line (E108).

The World trade line: the prices-refresh engine, the pow-curve price
math with the unsent-transaction queues, the server relay and the
crystal/double-time store flow:
10 bodies, 2219 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/WORLD_TRADE.md for the prose and boundaries.
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
    'bl 0x55468c': 0x0055468c,
    'bl 0x559f54': 0x00559f54,
    'bl sym.imp.NSLog': 0x001c2a5c,
    'bl sym.imp.NSSearchPathForDirectoriesInDomains': 0x001c3f20,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.imp.pow': 0x001c3fec,
}

SPECS = [
    dict(
        name='wt_00',
        method='World -[updateTradePricesIfNeeded]',
        types='v8@0:4',
        start=6077488,
        end=6080316,
        disasm='disasm_worldtileloader_wt_00.txt',
        base_add=6077504,
        base_literal=6080312,
        boundary='ARM.exidx end 0x005cc73c (listing bound); next ObjC IMP 0x005cc73c World -[connection:didReceiveResponse:]',
        selectors={
                 0x5cc690: (15195812, 'dataWithContentsOfFile:'),
                 0x5cc69c: (15195708, 'stringWithFormat:'),
                 0x5cc6a0: (15195800, 'objectAtIndex:'),
                 0x5cc6a8: (15195732, 'retain'),
                 0x5cc6ac: (15198120, 'propertyListWithData:options:format:error:'),
                 0x5cc6b8: (15196032, 'stringByAppendingPathComponent:'),
                 0x5cc6c0: (15196028, 'resourcePath'),
                 0x5cc6c4: (15196024, 'mainBundle'),
                 0x5cc6d0: (15198124, 'doubleForKey:'),
                 0x5cc6d4: (15195916, 'standardUserDefaults'),
                 0x5cc6dc: (15195844, 'timeIntervalSinceReferenceDate'),
                 0x5cc6e8: (15195672, 'connected'),
                 0x5cc6ec: (15196616, 'connectionWithRequest:delegate:'),
                 0x5cc6f4: (15196600, 'requestWithURL:cachePolicy:timeoutInterval:'),
                 0x5cc6f8: (15196596, 'URLWithString:'),
                 0x5cc710: (15195748, 'data'),
                 0x5cc718: (15198128, 'setDouble:forKey:'),
                 0x5cc72c: (15195892, 'init'),
                 0x5cc730: (15195752, 'alloc'),
        },
        imports={
                 0x5cc68c: (17151904, 'objc_msgSend'),
                 0x5cc698: (16233096, '__CFConstantStringClassReference'),
                 0x5cc6b4: (16233112, '__CFConstantStringClassReference'),
                 0x5cc6bc: (16229880, '__CFConstantStringClassReference'),
                 0x5cc6cc: (16233128, '__CFConstantStringClassReference'),
                 0x5cc704: (16233144, '__CFConstantStringClassReference'),
                 0x5cc708: (16233160, '__CFConstantStringClassReference'),
                 0x5cc724: (16233176, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5cc688: (17156376, 'OBJC_IVAR_$_World.globalPrices', 3236),
                 0x5cc6e4: (17156732, 'OBJC_IVAR_$_World.getPricesConnection', 3228),
                 0x5cc70c: (17156736, 'OBJC_IVAR_$_World.getPricesRecieveData', 3232),
                 0x5cc71c: (17155940, 'OBJC_IVAR_$_World.worldPriceMultipliers', 3240),
                 0x5cc720: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5cc728: (17155900, 'OBJC_IVAR_$_World.saveID', 436),
        },
        classes={
                 0x5cc694: (15245320, 'OBJC_CLASS_$_NSData'),
                 0x5cc6a4: (15245304, 'OBJC_CLASS_$_NSString'),
                 0x5cc6b0: (15245468, 'OBJC_CLASS_$_NSPropertyListSerialization'),
                 0x5cc6c8: (15245376, 'OBJC_CLASS_$_NSBundle'),
                 0x5cc6d8: (15245352, 'OBJC_CLASS_$_NSUserDefaults'),
                 0x5cc6e0: (15245312, 'OBJC_CLASS_$_NSDate'),
                 0x5cc6f0: (15245456, 'OBJC_CLASS_$_NSURLConnection'),
                 0x5cc6fc: (15245452, 'OBJC_CLASS_$_NSURL'),
                 0x5cc700: (15245448, 'OBJC_CLASS_$_NSMutableURLRequest'),
                 0x5cc714: (15245284, 'OBJC_CLASS_$_NSMutableData'),
                 0x5cc734: (15245288, 'OBJC_CLASS_$_NSMutableDictionary'),
        },
        instructions=[(6077488, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6080312, 'adceq r3, sb, ip, lsr 29')],
        calls=[(6077592, 'bl sym.imp.NSSearchPathForDirectoriesInDomains'), (6077712, 'blx sl'), (6077748, 'blx ip'), (6077788, 'blx ip'), (6077916, 'blx lr'), (6077932, 'blx r2'), (6078156, 'blx r2'), (6078172, 'blx r2'), (6078192, 'blx r3'), (6078212, 'blx r3'), (6078252, 'blx ip'), (6078380, 'blx lr'), (6078396, 'blx r2'), (6078528, 'blx r2'), (6078568, 'blx r3'), (6078588, 'blx r3'), (6078752, 'blx r2'), (6079024, 'blx r3'), (6079068, 'blx ip'), (6079112, 'blx lr'), (6079128, 'blx r2'), (6079248, 'blx r2'), (6079264, 'blx r2'), (6079324, 'bl sym.imp.NSLog'), (6079400, 'blx r2'), (6079432, 'blx lr'), (6079556, 'bl sym.imp.NSSearchPathForDirectoriesInDomains'), (6079688, 'blx r3'), (6079760, 'blx lr'), (6079800, 'blx ip'), (6079932, 'blx lr'), (6079948, 'blx r2'), (6080084, 'blx r2'), (6080100, 'blx r2')],
        branches=[(6077552, 'bne', 6077960), (6077808, 'beq', 6077956), (6077956, 'b', 6077960), (6077996, 'bne', 6078424), (6078272, 'beq', 6078420), (6078420, 'b', 6078424), (6078616, 'ble', 6078636), (6078668, 'ble', 6079440), (6078708, 'bne', 6079440), (6078764, 'beq', 6079436), (6079176, 'beq', 6079312), (6079288, 'b', 6079328), (6079436, 'b', 6079440), (6079476, 'bne', 6080128), (6079516, 'bne', 6079976), (6079820, 'beq', 6079972), (6079972, 'b', 6079976), (6080012, 'bne', 6080124), (6080124, 'b', 6080128)],
        semantics=('[World updateTradePricesIfNeeded] (imp 0x005cbc30, 707w): the prices-refresh engine - loads the bundled price plist (dataWithContentsOfFile: + NSPropertyListSerialization propertyListWithData:options:format:error: with stringByAppendingPathComponent:/mainBundle resourcePath), checks the last-update timestamp via NSUserDefaults doubleForKey: + NSDate timeIntervalSinceReferenceDate (constants 0xe and 0x3c = 60), and when stale + connected + client builds the request (stringWithFormat: + URLWithString: + NSMutableURLRequest requestWithURL:cachePolicy:timeoutInterval:) and starts getPricesConnection via NSURLConnection connectionWithRequest:delegate:; persists the timestamp with setDouble:forKey:; 11 classes incl. NSBundle/NSPropertyListSerialization/NSDate.\n'),
    ),
    dict(
        name='wt_01',
        method='World -[updatePriceForItemBoughtOrSoldOfTypeKey:soldCount:]',
        types='v16@0:4@8f12',
        start=6084264,
        end=6086076,
        disasm='disasm_worldtileloader_wt_01.txt',
        base_add=6084280,
        base_literal=6086072,
        boundary='ARM.exidx end 0x005cddbc (listing bound); next ObjC IMP 0x005cdfbc World -[tutorialAlertDismissedWithContinue:]',
        selectors={
                 0x5cdd6c: (15195624, 'objectForKey:'),
                 0x5cdd74: (15195840, 'doubleValue'),
                 0x5cdd78: (15197220, 'addOperationWithBlock:'),
                 0x5cdd7c: (17111296, 'ELF'),
                 0x5cdd90: (15195584, 'setObject:forKey:'),
                 0x5cdd94: (15195560, 'numberWithDouble:'),
                 0x5cdda0: (15195892, 'init'),
                 0x5cdda4: (15195752, 'alloc'),
                 0x5cddb0: (15195836, 'floatValue'),
                 0x5cddb4: (15195564, 'numberWithFloat:'),
        },
        imports={
                 0x5cdd68: (17151904, 'objc_msgSend'),
                 0x5cdd88: (17151928, '_NSConcreteStackBlock'),
        },
        ivars={
                 0x5cdd64: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5cdd70: (17155940, 'OBJC_IVAR_$_World.worldPriceMultipliers', 3240),
                 0x5cdd8c: (17156308, 'OBJC_IVAR_$_World.saveQueue', 3188),
                 0x5cdd9c: (17156472, 'OBJC_IVAR_$_World.unsentGlobalTradeTransactions', 3248),
                 0x5cddac: (17156464, 'OBJC_IVAR_$_World.unsentMultiplayerTradeTransactions', 3244),
        },
        classes={
                 0x5cdd98: (15245292, 'OBJC_CLASS_$_NSNumber'),
                 0x5cdda8: (15245288, 'OBJC_CLASS_$_NSMutableDictionary'),
        },
        instructions=[(6084264, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6086072, 'adceq r2, sb, r4, lsr r4')],
        calls=[(6084520, 'blx r3'), (6084584, 'blx r2'), (6084616, 'bl sym.imp.pow'), (6084880, 'blx ip'), (6084928, 'blx ip'), (6085020, 'blx r5'), (6085132, 'blx r2'), (6085148, 'blx r2'), (6085280, 'blx r2'), (6085296, 'blx r2'), (6085408, 'blx r3'), (6085472, 'blx r2'), (6085640, 'blx r6'), (6085688, 'blx ip'), (6085736, 'blx ip'), (6085800, 'blx r2'), (6085928, 'blx ip'), (6085976, 'blx ip')],
        branches=[(6084328, 'bpl', 6084384), (6084352, 'ble', 6084384), (6084356, 'b', 6085980), (6084420, 'bne', 6085024), (6084540, 'beq', 6084596), (6085060, 'bne', 6085172), (6085208, 'bne', 6085320), (6085428, 'beq', 6085492), (6085756, 'beq', 6085820)],
        semantics=('[World updatePriceForItemBoughtOrSoldOfTypeKey:soldCount:] (imp 0x005cd6a8, 453w): the price-recompute math - objectForKey:/doubleValue/floatValue reads, a pow() curve over soldCount, numberWithDouble:/numberWithFloat: writeback into the price dictionaries and the saveQueue addOperationWithBlock: persist hook (the _NSConcreteStackBlock literal); touches unsentGlobalTradeTransactions / unsentMultiplayerTradeTransactions; pool constants 0x5cd708/0x5cd710/0x5cd718.\n'),
    ),
    dict(
        name='wt_02',
        method='World -[transactionDataRecieved:fromClient:]',
        types='v16@0:4@8@12',
        start=6087264,
        end=6088984,
        disasm='disasm_worldtileloader_wt_02.txt',
        base_add=6087280,
        base_literal=6088980,
        boundary='ARM.exidx end 0x005ce918 (listing bound); next ObjC IMP 0x005ceb18 World -[worldPriceOffsetsRecievedFromServer:]',
        selectors={
                 0x5ce8bc: (15195620, 'countByEnumeratingWithState:objects:count:'),
                 0x5ce8c0: (15195684, 'dictionary'),
                 0x5ce8c8: (15195836, 'floatValue'),
                 0x5ce8cc: (15195624, 'objectForKey:'),
                 0x5ce8d4: (15195840, 'doubleValue'),
                 0x5ce8d8: (15195584, 'setObject:forKey:'),
                 0x5ce8dc: (15195560, 'numberWithDouble:'),
                 0x5ce8e4: (15197220, 'addOperationWithBlock:'),
                 0x5ce8e8: (17111328, 'ELF'),
                 0x5ce8fc: (15195640, 'sendNetworkData:toPeers:reliable:'),
                 0x5ce904: (15195612, 'appendData:'),
                 0x5ce908: (15195608, 'gzipDeflate'),
                 0x5ce90c: (15195552, 'dataWithBytes:length:'),
        },
        imports={
                 0x5ce8b8: (17151904, 'objc_msgSend'),
                 0x5ce8f4: (17151928, '_NSConcreteStackBlock'),
        },
        ivars={
                 0x5ce8d0: (17155940, 'OBJC_IVAR_$_World.worldPriceMultipliers', 3240),
                 0x5ce8f8: (17156308, 'OBJC_IVAR_$_World.saveQueue', 3188),
                 0x5ce900: (17155916, 'OBJC_IVAR_$_World.server', 964),
        },
        classes={
                 0x5ce8c4: (15245288, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x5ce8e0: (15245292, 'OBJC_CLASS_$_NSNumber'),
                 0x5ce910: (15245284, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(6087264, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6088980, 'adceq r1, sb, ip, ror r8')],
        calls=[(6087424, 'blx r6'), (6087448, 'bl sym.imp.memset'), (6087496, 'blx lr'), (6087596, 'bl sym.imp.objc_enumerationMutation'), (6087704, 'blx ip'), (6087720, 'blx r2'), (6087896, 'blx r3'), (6087960, 'blx r2'), (6087992, 'bl sym.imp.pow'), (6088124, 'blx r5'), (6088172, 'blx ip'), (6088216, 'blx ip'), (6088264, 'blx ip'), (6088368, 'blx ip'), (6088460, 'blx ip'), (6088472, 'bl 0x55468c'), (6088692, 'blx r2'), (6088720, 'blx r3'), (6088776, 'blx lr'), (6088868, 'blx r5')],
        branches=[(6087508, 'beq', 6088392), (6087588, 'beq', 6087600), (6087752, 'bgt', 6087800), (6087756, 'b', 6087776), (6087796, 'bpl', 6088268), (6087916, 'beq', 6087972), (6088268, 'b', 6088272), (6088296, 'blo', 6087552), (6088388, 'bne', 6087552), (6088392, 'b', 6088396)],
        semantics=('[World transactionDataRecieved:fromClient:] (imp 0x005ce260, 430w): the server-side transaction intake - enumeration over the decoded list with pow()-scaled price multipliers, the saveQueue addOperationWithBlock: persist, gzipDeflate + appendData:/dataWithBytes:length: packing and the sendNetworkData:toPeers:reliable: relay; helper 0x55468c (the E103/E107 boundary helper); constants 0x10/0x20/0x2f.\n'),
    ),
    dict(
        name='wt_03',
        method='World -[crystalsPurchased]',
        types='v8@0:4',
        start=6046880,
        end=6047672,
        disasm='disasm_worldtileloader_wt_03.txt',
        base_add=6046896,
        base_literal=6047668,
        boundary='ARM.exidx end 0x005c47b8 (listing bound); next ObjC IMP 0x005c47b8 World -[reportAchievementWithIdentifier:]',
        selectors={
                 0x5c4794: (15196576, 'displayed'),
                 0x5c4798: (15197548, 'craftUI'),
                 0x5c47a0: (15197900, 'blockheadInventoryChanged'),
                 0x5c47a4: (15195620, 'countByEnumeratingWithState:objects:count:'),
                 0x5c47a8: (15195692, 'blockheads'),
                 0x5c47b0: (15196788, 'checkIfCanWarpInSecondBlockheadAfterItemAdded:dataB:'),
        },
        imports={
                 0x5c4790: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5c479c: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x5c47ac: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={},
        instructions=[(6046880, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6047668, 'adceq fp, sb, ip, lsr r6')],
        calls=[(6046976, 'blx r3'), (6046992, 'blx r2'), (6047088, 'blx ip'), (6047104, 'blx r2'), (6047224, 'blx r2'), (6047248, 'bl sym.imp.memset'), (6047296, 'blx lr'), (6047396, 'bl sym.imp.objc_enumerationMutation'), (6047476, 'blx ip'), (6047596, 'blx ip')],
        branches=[(6047004, 'beq', 6047108), (6047308, 'beq', 6047620), (6047388, 'beq', 6047400), (6047488, 'beq', 6047496), (6047492, 'b', 6047624), (6047496, 'b', 6047500), (6047524, 'blo', 6047352), (6047616, 'bne', 6047352), (6047620, 'b', 6047624)],
        semantics=('[World crystalsPurchased] (imp 0x005c44a0, 198w): after a crystal purchase - refreshes craftUI (displayed), fires blockheadInventoryChanged and walks the blockheads through checkIfCanWarpInSecondBlockheadAfterItemAdded:dataB: (the second-blockhead warp gate, the E105 warp-in flow\'s trigger); constants 0x10/0x20/0xb.\n'),
    ),
    dict(
        name='wt_04',
        method='World -[worldPriceOffsetsRecievedFromServer:]',
        types='v12@0:4@8',
        start=6089496,
        end=6090156,
        disasm='disasm_worldtileloader_wt_04.txt',
        base_add=6089512,
        base_literal=6090152,
        boundary='ARM.exidx end 0x005cedac (listing bound); next ObjC IMP 0x005cedac World -[tutorialActive]',
        selectors={
                 0x5ced94: (15196836, 'gzipInflate'),
                 0x5ced98: (15195620, 'countByEnumeratingWithState:objects:count:'),
                 0x5ced9c: (15195584, 'setObject:forKey:'),
                 0x5ceda0: (15195624, 'objectForKey:'),
        },
        imports={
                 0x5ced90: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5ceda4: (17155940, 'OBJC_IVAR_$_World.worldPriceMultipliers', 3240),
        },
        classes={},
        instructions=[(6089496, 'push {r4, r5, r6, r7, fp, lr}'), (6090152, 'adceq r0, sb, r4, asr 31')],
        calls=[(6089556, 'blx ip'), (6089560, 'bl 0x559f54'), (6089664, 'bl sym.imp.memset'), (6089712, 'blx lr'), (6089812, 'bl sym.imp.objc_enumerationMutation'), (6089940, 'blx ip'), (6089988, 'blx ip'), (6090088, 'blx ip')],
        branches=[(6089580, 'beq', 6090120), (6089724, 'beq', 6090112), (6089804, 'beq', 6089816), (6090016, 'blo', 6089768), (6090108, 'bne', 6089768), (6090112, 'b', 6090116), (6090116, 'b', 6090120)],
        semantics=('[World worldPriceOffsetsRecievedFromServer:] (imp 0x005ceb18, 165w): the server price-offset apply - gzipInflate decode, enumeration and setObject:forKey: writes into worldPriceMultipliers; helpers 0x559f54 + 0x10/0x20 constants.\n'),
    ),
    dict(
        name='wt_05',
        method='World -[purchaseDoubleTime]',
        types='v8@0:4',
        start=6046248,
        end=6046880,
        disasm='disasm_worldtileloader_wt_05.txt',
        base_add=6046264,
        base_literal=6046876,
        boundary='ARM.exidx end 0x005c44a0 (listing bound); next ObjC IMP 0x005c44a0 World -[crystalsPurchased]',
        selectors={
                 0x5c446c: (15196576, 'displayed'),
                 0x5c4470: (15197548, 'craftUI'),
                 0x5c447c: (15197896, 'storeUsername:andPassword:forServiceName:updateExisting:error:'),
                 0x5c4488: (15195708, 'stringWithFormat:'),
                 0x5c4494: (15195680, 'sendHeartbeatData'),
                 0x5c4498: (15197900, 'blockheadInventoryChanged'),
        },
        imports={
                 0x5c4468: (17151904, 'objc_msgSend'),
                 0x5c4478: (16231272, '__CFConstantStringClassReference'),
                 0x5c4484: (16232888, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5c4474: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x5c448c: (17156312, 'OBJC_IVAR_$_World.doubleTimeUnlocked', 3072),
        },
        classes={
                 0x5c4480: (15245428, 'OBJC_CLASS_$_SFHFKeychainUtils'),
                 0x5c4490: (15245304, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(6046248, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6046876, 'invalid')],
        calls=[(6046508, 'blx r3'), (6046564, 'blx ip'), (6046636, 'blx r5'), (6046684, 'blx ip'), (6046700, 'blx r2'), (6046796, 'blx ip'), (6046812, 'blx r2')],
        branches=[(6046712, 'beq', 6046816)],
        semantics=('[World purchaseDoubleTime] (imp 0x005c4228, 158w): the double-time purchase flow - stores the store credentials via SFHFKeychainUtils storeUsername:andPassword:forServiceName:updateExisting:error:, stringWithFormat: product string, sendHeartbeatData nudge and the craftUI displayed / blockheadInventoryChanged UI tail; doubleTimeUnlocked ivar.\n'),
    ),
    dict(
        name='wt_06',
        method='World -[IAPForWorldTopupSucceeeded:transactionID:]',
        types='v16@0:4@8@12',
        start=6107820,
        end=6107976,
        disasm='disasm_worldtileloader_wt_06.txt',
        base_add=6107836,
        base_literal=6107972,
        boundary='ARM.exidx end 0x005d3348 (listing bound); next ObjC IMP 0x005d3348 World -[shareURL:message:fromRect:]',
        selectors={
                 0x5d3338: (15198308, 'IAPForWorldTopupSucceeeded:transactionID:'),
                 0x5d333c: (15197116, 'pauseUI'),
        },
        imports={
                 0x5d3334: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5d3340: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
        },
        classes={},
        instructions=[(6107820, 'push {r4, r5, r6, r7, fp, lr}'), (6107972, 'adceq ip, r8, r0, lsr r8')],
        calls=[(6107920, 'blx lr'), (6107944, 'blx ip')],
        branches=[],
        semantics=('[World IAPForWorldTopupSucceeeded:transactionID:] (imp 0x005d32ac, 39w; original triple-e spelling): forwards the top-up success to the pauseUI (single blx).\n'),
    ),
    dict(
        name='wt_07',
        method='World -[doubleTimePurchaseTapped]',
        types='v8@0:4',
        start=6039640,
        end=6039780,
        disasm='disasm_worldtileloader_wt_07.txt',
        base_add=6039656,
        base_literal=6039776,
        boundary='ARM.exidx end 0x005c28e4 (listing bound); next ObjC IMP 0x005c28e4 World -[doubleTimeRestoreTapped]',
        selectors={
                 0x5c28d4: (15196464, 'pauseButtonTapped'),
                 0x5c28d8: (15197828, 'iapStarted'),
        },
        imports={
                 0x5c28d0: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(6039640, 'push {r4, sl, fp, lr}'), (6039776, 'adceq sp, sb, r4, lsl 5')],
        calls=[(6039728, 'blx r3'), (6039748, 'blx r2')],
        branches=[],
        semantics=('[World doubleTimePurchaseTapped] (imp 0x005c2858, 35w): the double-time button - pauseButtonTapped + iapStarted store hooks.\n'),
    ),
    dict(
        name='wt_08',
        method='World -[worldPriceMultipliers]',
        types='@8@0:4',
        start=6136144,
        end=6136212,
        disasm='disasm_worldtileloader_wt_08.txt',
        base_add=6136168,
        base_literal=6136208,
        boundary='ARM.exidx end 0x005da194 (listing bound); next ObjC IMP 0x005da194 World -[serverMinorVersion]',
        selectors={},
        imports={},
        ivars={
                 0x5da18c: (17155940, 'OBJC_IVAR_$_World.worldPriceMultipliers', 3240),
        },
        classes={},
        instructions=[(6136144, 'sub sp, sp, 0xc'), (6136208, 'adceq r5, r8, r4, lsl 19')],
        calls=[],
        branches=[],
        semantics=('[World worldPriceMultipliers] (imp 0x005da150, 17w): bare ivar getter.\n'),
    ),
    dict(
        name='wt_09',
        method='World -[globalPrices]',
        types='@8@0:4',
        start=6136076,
        end=6136144,
        disasm='disasm_worldtileloader_wt_09.txt',
        base_add=6136100,
        base_literal=6136140,
        boundary='ARM.exidx end 0x005da194; body trimmed at the next IMP 0x005da150 World -[worldPriceMultipliers]',
        selectors={},
        imports={},
        ivars={
                 0x5da148: (17156376, 'OBJC_IVAR_$_World.globalPrices', 3236),
        },
        classes={},
        instructions=[(6136076, 'sub sp, sp, 0xc'), (6136140, 'adceq r5, r8, r8, asr 19')],
        calls=[],
        branches=[],
        semantics=('[World globalPrices] (imp 0x005da10c, 17w): bare ivar getter (listing trimmed at the next IMP; header keeps the extracted end).\n'),
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
        'batch': 'World trade prices and IAP line (E108): the refresh engine and the price math; 10 bodies',
        'claim': ('a fully-read static map of the World trade prices/IAP line; the store/server side and the NSURLConnection / SFHFKeychainUtils contracts are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'world_trade.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale world_trade.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
