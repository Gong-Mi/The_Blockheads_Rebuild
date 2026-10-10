#!/usr/bin/env python3
"""Hash-gated recovery of the World lifecycle and cloud/prices IO (E106).

The World lifecycle and IO line: the constructor (census-grade), the
global-prices connection quartet, the cloud flags, the old-block
decommission pass and the DB bulk pair:
13 bodies, 3266 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/WORLD_LOAD.md for the prose and boundaries.
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
    'bl 0x559f54': 0x00559f54,
    'bl 0x559f78': 0x00559f78,
    'bl 0x564c54': 0x00564c54,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl method.std::__1::__hash_table_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___.__insert_unique_PhysicalBlock_const_': 0x005dd340,
    'bl method.std::__1::__hash_table_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___.erase_std::__1::__hash_const_iterator_std::__1::__hash_node_PhysicalBlock__void__const__': 0x005dbdcc,
    'bl method.std::__1::unordered_set_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___._unordered_set__': 0x0057598c,
    'bl method.unsigned_long_std::__1::__hash_table_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___.__erase_unique_PhysicalBlock__PhysicalBlock_const_': 0x005dce04,
    'bl sym.imp.NSLog': 0x001c2a5c,
    'bl sym.imp._Unwind_Resume': 0x001c29c0,
    'bl sym.imp.__stack_chk_fail': 0x001c28b8,
    'bl sym.imp.__wrap_calloc': 0x001c2fe4,
    'bl sym.imp.__wrap_free': 0x001c2e64,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_': 0x00a16ccc,
}

SPECS = [
    dict(
        name='wl_00',
        method='World -[initWithWindowInfo:cache:delegate:saveID:name:client:server:multiplayerWorldData:serverHostData:saveDelay:worldWidthMacro:customRules:expertMode:]',
        types='@60@0:4^{WindowInfo=ffffffff}8@12@16@20@24@28@32@36@40i44i48@52c56',
        start=5649924,
        end=5655636,
        disasm='disasm_worldtileloader_wl_00.txt',
        base_add=5649940,
        base_literal=5653324,
        boundary='ARM.exidx end 0x00564c54 (listing bound); next ObjC IMP 0x00564c64 World -[setServer:]',
        selectors={
                 0x56463c: (15195892, 'init'),
                 0x564720: (15195732, 'retain'),
                 0x56473c: (15195820, 'initWithDictionary:'),
                 0x564740: (15195752, 'alloc'),
                 0x564968: (15196156, 'boolForKey:'),
                 0x56496c: (15195916, 'standardUserDefaults'),
                 0x564984: (15196152, 'reset'),
                 0x564988: (15195544, 'instance'),
                 0x564990: (15196148, 'setWorld:'),
                 0x564994: (15196144, 'setWorldWidthMacro:'),
                 0x564b60: (15195892, 'init'),
                 0x564b70: (15195732, 'retain'),
                 0x564b7c: (15195752, 'alloc'),
                 0x564b8c: (15195544, 'instance'),
                 0x564b90: (15196148, 'setWorld:'),
                 0x564ba4: (15196164, 'getPasswordForUsername:andServiceName:error:'),
                 0x564bac: (15196160, 'setMaxConcurrentOperationCount:'),
                 0x564bbc: (15195848, 'intValue'),
                 0x564bd0: (15196172, 'statusBarOrientation'),
                 0x564bd4: (15196168, 'sharedApplication'),
                 0x564bdc: (15195768, 'release'),
                 0x564be8: (15195624, 'objectForKey:'),
                 0x564bf0: (15195828, 'boolValue'),
                 0x564c38: (15196180, 'startObservingMotionEvents'),
                 0x564c3c: (15196184, 'viewServerWelcomeMessage:customRules:allowEdit:'),
                 0x564c50: (15196176, 'addIndex:'),
        },
        imports={
                 0x564638: (17151900, 'objc_msgSendSuper2'),
                 0x564688: (17151968, '__stack_chk_guard'),
                 0x564710: (16231208, '__CFConstantStringClassReference'),
                 0x56471c: (17151904, 'objc_msgSend'),
                 0x564964: (16231240, '__CFConstantStringClassReference'),
                 0x564978: (16231224, '__CFConstantStringClassReference'),
                 0x564b64: (17151968, '__stack_chk_guard'),
                 0x564b6c: (17151904, 'objc_msgSend'),
                 0x564b9c: (16231256, '__CFConstantStringClassReference'),
                 0x564ba0: (16231272, '__CFConstantStringClassReference'),
                 0x564be4: (16228824, '__CFConstantStringClassReference'),
                 0x564bf4: (16228744, '__CFConstantStringClassReference'),
                 0x564bfc: (16228808, '__CFConstantStringClassReference'),
                 0x564c04: (16228792, '__CFConstantStringClassReference'),
                 0x564c0c: (16228840, '__CFConstantStringClassReference'),
                 0x564c1c: (16229080, '__CFConstantStringClassReference'),
                 0x564c24: (16229048, '__CFConstantStringClassReference'),
                 0x564c40: (16228872, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x564714: (17155896, 'OBJC_IVAR_$_World.expertMode', 228),
                 0x564718: (17155892, 'OBJC_IVAR_$_World.worldName', 440),
                 0x564724: (17155900, 'OBJC_IVAR_$_World.saveID', 436),
                 0x56472c: (17156132, 'OBJC_IVAR_$_World.cache', 408),
                 0x564730: (17155876, 'OBJC_IVAR_$_World.windowInfo', 152),
                 0x564734: (17156108, 'OBJC_IVAR_$_World.saveDelay', 3216),
                 0x564738: (17155952, 'OBJC_IVAR_$_World.customRulesDict', 224),
                 0x564748: (17156060, 'OBJC_IVAR_$_World.customRules', 160),
                 0x564960: (17156300, 'OBJC_IVAR_$_World.dpadDirectControlDisabled', 3373),
                 0x564974: (17156304, 'OBJC_IVAR_$_World.dpadControl', 3372),
                 0x56497c: (17156032, 'OBJC_IVAR_$_World.foundItemsList', 3376),
                 0x564998: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
                 0x564b68: (17155892, 'OBJC_IVAR_$_World.worldName', 440),
                 0x564b78: (17155952, 'OBJC_IVAR_$_World.customRulesDict', 224),
                 0x564b84: (17156304, 'OBJC_IVAR_$_World.dpadControl', 3372),
                 0x564b94: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
                 0x564bb0: (17156308, 'OBJC_IVAR_$_World.saveQueue', 3188),
                 0x564bb8: (17156312, 'OBJC_IVAR_$_World.doubleTimeUnlocked', 3072),
                 0x564bc0: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x564bc4: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x564bc8: (17156316, 'OBJC_IVAR_$_World.cloudMode', 3212),
                 0x564bcc: (17156320, 'OBJC_IVAR_$_World.interfaceOrientation', 8),
                 0x564be0: (17156088, 'OBJC_IVAR_$_World.multiplayerLoadDict', 952),
                 0x564bec: (17156036, 'OBJC_IVAR_$_World.isOwner', 3208),
                 0x564bf8: (17156324, 'OBJC_IVAR_$_World.isMod', 3210),
                 0x564c00: (17156328, 'OBJC_IVAR_$_World.isAdmin', 3209),
                 0x564c08: (17155936, 'OBJC_IVAR_$_World.pvpEnabled', 3268),
                 0x564c10: (17156332, 'OBJC_IVAR_$_World.freeClientLightBlockIndices', 496),
                 0x564c14: (17155964, 'OBJC_IVAR_$_World.serverClients', 956),
                 0x564c18: (17156016, 'OBJC_IVAR_$_World.maxPlayers', 448),
                 0x564c20: (17156012, 'OBJC_IVAR_$_World.hostPort', 444),
                 0x564c28: (17156336, 'OBJC_IVAR_$_World.motionManager', 4),
                 0x564c30: (17156340, 'OBJC_IVAR_$_World.macroTiles', 412),
                 0x564c48: (17156344, 'OBJC_IVAR_$_World.particleRandomNumbers', 1024),
        },
        classes={
                 0x564684: (15252576, 'OBJC_CLASS_$_World'),
                 0x564744: (15245288, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x564970: (15245352, 'OBJC_CLASS_$_NSUserDefaults'),
                 0x564980: (15245336, 'OBJC_CLASS_$_NSMutableIndexSet'),
                 0x56498c: (15245420, 'OBJC_CLASS_$_TipManager'),
                 0x56499c: (15245388, 'OBJC_CLASS_$_ParticleEmitter'),
                 0x5649a0: (15245280, 'OBJC_CLASS_$_MJSoundManager'),
                 0x564b80: (15245288, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x564b88: (15245336, 'OBJC_CLASS_$_NSMutableIndexSet'),
                 0x564b98: (15245388, 'OBJC_CLASS_$_ParticleEmitter'),
                 0x564ba8: (15245428, 'OBJC_CLASS_$_SFHFKeychainUtils'),
                 0x564bb4: (15245424, 'OBJC_CLASS_$_NSOperationQueue'),
                 0x564bd8: (15245432, 'OBJC_CLASS_$_UIApplication'),
                 0x564c2c: (15245436, 'OBJC_CLASS_$_CMMotionManager'),
        },
        instructions=[(5649924, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5655632, 'invalid')],
        calls=[(5650196, 'blx r5'), (5650260, 'bl sym.imp.NSLog'), (5650540, 'blx ip'), (5650580, 'blx r3'), (5650692, 'blx r2'), (5650712, 'blx r3'), (5650836, 'bl 0x559f78'), (5651264, 'bl sym.imp.memcpy'), (5651320, 'blx ip'), (5651356, 'blx r3'), (5651388, 'blx r3'), (5651424, 'blx r3'), (5651456, 'blx r3'), (5651476, 'blx r3'), (5651508, 'blx r3'), (5651524, 'blx r2'), (5651556, 'blx r3'), (5651572, 'blx r2'), (5651624, 'blx ip'), (5651644, 'blx r3'), (5651696, 'blx ip'), (5651716, 'blx r3'), (5651856, 'bl sym.imp.NSLog'), (5652060, 'blx ip'), (5652076, 'blx r2'), (5652132, 'blx r3'), (5652180, 'blx lr'), (5652264, 'blx r2'), (5652536, 'blx r3'), (5652556, 'blx r3'), (5652588, 'blx r3'), (5652604, 'blx r2'), (5652668, 'blx lr'), (5652708, 'blx r3'), (5652868, 'blx r3'), (5652884, 'blx r2'), (5652936, 'blx ip'), (5652952, 'blx r2'), (5653068, 'blx r3'), (5653152, 'bl 0x559f54'), (5653204, 'blx ip'), (5653308, 'blx r3'), (5653512, 'blx ip'), (5653528, 'blx r2'), (5653588, 'blx ip'), (5653604, 'blx r2'), (5653664, 'blx ip'), (5653680, 'blx r2'), (5653740, 'blx ip'), (5653860, 'blx lr'), (5653876, 'blx r2'), (5654004, 'blx lr'), (5654020, 'blx r2'), (5654132, 'blx r3'), (5654480, 'blx r6'), (5654496, 'blx r2'), (5654540, 'blx r3'), (5654556, 'blx r2'), (5654628, 'bl sym.imp.__wrap_calloc'), (5654732, 'blx ip'), (5654748, 'blx r2'), (5654804, 'bl 0x564c54'), (5655024, 'blx r2'), (5655252, 'blx r4'), (5655328, 'blx r4'), (5655388, 'bl sym.imp.__stack_chk_fail')],
        branches=[(5650224, 'bne', 5650240), (5650236, 'b', 5655340), (5650324, 'bge', 5650340), (5650336, 'b', 5650348), (5650616, 'beq', 5650736), (5651768, 'beq', 5651812), (5651808, 'bne', 5651872), (5651824, 'bne', 5651872), (5651840, 'bne', 5651872), (5651868, 'b', 5655340), (5652200, 'beq', 5652292), (5652216, 'bne', 5652292), (5652288, 'b', 5652324), (5652756, 'beq', 5653092), (5652996, 'bge', 5653088), (5653084, 'b', 5652988), (5653088, 'b', 5654164), (5653128, 'beq', 5654160), (5653144, 'beq', 5654080), (5653252, 'bne', 5653328), (5653320, 'b', 5655340), (5653752, 'beq', 5653900), (5654068, 'b', 5654156), (5654144, 'b', 5655340), (5654156, 'b', 5654160), (5654160, 'b', 5654164), (5654200, 'bne', 5654348), (5654284, 'b', 5654352), (5654348, 'b', 5654352), (5654364, 'beq', 5654580), (5654792, 'bge', 5654948), (5654876, 'b', 5654784), (5654980, 'bne', 5655028), (5655064, 'bne', 5655108), (5655104, 'beq', 5655332), (5655372, 'bne', 5655388)],
        semantics=('[World initWithWindowInfo:cache:delegate:saveID:name:client:server:multiplayerWorldData:serverHostData:saveDelay:worldWidthMacro:customRules:expertMode:] (imp 0x00563604, 1428w): the World constructor (census-grade reading): 66 call rows - register blx x56 + NSLog x2 + memcpy/calloc + stack-check guard x2; 26 selector cells across 14 classes - NSUserDefaults (saveDelay/boolForKey:), SFHFKeychainUtils getPasswordForUsername:andServiceName:error: (the server password), the singleton wiring (TipManager/ParticleEmitter/MJSoundManager instance + setWorld: + setWorldWidthMacro:), the saveQueue NSOperationQueue (setMaxConcurrentOperationCount:, constants 0x40/0x14), UIApplication statusBarOrientation -> interfaceOrientation, CMMotionManager + startObservingMotionEvents (dpad seeds), viewServerWelcomeMessage:customRules:allowEdit: and the NSMutableIndexSet addIndex: (foundItemsList); 34 ivars; not a per-instruction walkthrough.\n'),
    ),
    dict(
        name='wl_01',
        method='World -[setWindowInfo:]',
        types='v12@0:4^{WindowInfo=ffffffff}8',
        start=5986808,
        end=5987156,
        disasm='disasm_worldtileloader_wl_01.txt',
        base_add=5986824,
        base_literal=5987152,
        boundary='ARM.exidx end 0x005b5b54 (listing bound); next ObjC IMP 0x005b5b54 World -[timeCrystalButtonTapped]',
        selectors={
                 0x5b5b48: (15197536, 'windowInfoChanged:'),
        },
        imports={
                 0x5b5b44: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5b5b38: (17156140, 'OBJC_IVAR_$_World.tapViewport', 384),
                 0x5b5b40: (17155876, 'OBJC_IVAR_$_World.windowInfo', 152),
                 0x5b5b4c: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
        },
        classes={},
        instructions=[(5986808, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5987152, 'adceq sl, sl, r4, ror 1')],
        calls=[(5986964, 'blx r6')],
        branches=[],
        semantics=('[World setWindowInfo:] (imp 0x005b59f8, 87w): stores the window info and forwards windowInfoChanged: (blx); touches tapViewport and the uiManager.\n'),
    ),
    dict(
        name='wl_02',
        method='World -[connectionDidFinishLoading:]',
        types='v12@0:4@8',
        start=6081672,
        end=6083832,
        disasm='disasm_worldtileloader_wl_02.txt',
        base_add=6081688,
        base_literal=6083828,
        boundary='ARM.exidx end 0x005cd4f8 (listing bound); next ObjC IMP 0x005cd6a8 World -[updatePriceForItemBoughtOrSoldOfTypeKey:soldCount:]',
        selectors={
                 0x5cd47c: (15198136, 'JSONObjectWithData:options:error:'),
                 0x5cd488: (15195604, 'count'),
                 0x5cd48c: (15195620, 'countByEnumeratingWithState:objects:count:'),
                 0x5cd490: (15195684, 'dictionary'),
                 0x5cd49c: (15195624, 'objectForKey:'),
                 0x5cd4a4: (15195584, 'setObject:forKey:'),
                 0x5cd4a8: (15197220, 'addOperationWithBlock:'),
                 0x5cd4ac: (17111264, 'ELF'),
                 0x5cd4c0: (15198144, 'updatedPricesReceived'),
                 0x5cd4c4: (15196572, 'tradePortalUI'),
                 0x5cd4d0: (15198140, 'copy'),
                 0x5cd4d4: (15195860, 'autorelease'),
                 0x5cd4d8: (15195768, 'release'),
                 0x5cd4e0: (15196648, 'updateTradePricesIfNeeded'),
                 0x5cd4e8: (15198128, 'setDouble:forKey:'),
                 0x5cd4ec: (15195916, 'standardUserDefaults'),
        },
        imports={
                 0x5cd478: (17151904, 'objc_msgSend'),
                 0x5cd498: (16233240, '__CFConstantStringClassReference'),
                 0x5cd4a0: (16233224, '__CFConstantStringClassReference'),
                 0x5cd4b8: (17151928, '_NSConcreteStackBlock'),
                 0x5cd4e4: (16233128, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5cd470: (17156380, 'OBJC_IVAR_$_World.sendPricesConnection', 3220),
                 0x5cd474: (17156732, 'OBJC_IVAR_$_World.getPricesConnection', 3228),
                 0x5cd480: (17156736, 'OBJC_IVAR_$_World.getPricesRecieveData', 3232),
                 0x5cd4bc: (17156308, 'OBJC_IVAR_$_World.saveQueue', 3188),
                 0x5cd4c8: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x5cd4cc: (17156376, 'OBJC_IVAR_$_World.globalPrices', 3236),
                 0x5cd4dc: (17156480, 'OBJC_IVAR_$_World.sendPricesRecieveData', 3224),
        },
        classes={
                 0x5cd484: (15245444, 'OBJC_CLASS_$_NSJSONSerialization'),
                 0x5cd494: (15245288, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x5cd4f0: (15245352, 'OBJC_CLASS_$_NSUserDefaults'),
        },
        instructions=[(6081672, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6083828, 'adceq r2, sb, r4, asr lr')],
        calls=[(6081896, 'blx r3'), (6081928, 'blx lr'), (6081948, 'blx r2'), (6081984, 'blx r3'), (6082044, 'blx lr'), (6082228, 'blx lr'), (6082308, 'blx r2'), (6082440, 'blx r2'), (6082464, 'bl sym.imp.memset'), (6082512, 'blx lr'), (6082612, 'bl sym.imp.objc_enumerationMutation'), (6082720, 'blx r3'), (6082748, 'blx r3'), (6082844, 'blx ip'), (6082948, 'blx ip'), (6083016, 'blx r2'), (6083304, 'blx r2'), (6083336, 'blx r3'), (6083392, 'blx ip'), (6083408, 'blx r2'), (6083500, 'blx r5'), (6083596, 'blx r3'), (6083656, 'blx lr')],
        branches=[(6081740, 'bne', 6082076), (6082072, 'b', 6083688), (6082112, 'bne', 6083684), (6082248, 'bne', 6082320), (6082264, 'beq', 6082320), (6082316, 'bhs', 6082336), (6082320, 'b', 6083508), (6082524, 'beq', 6082972), (6082604, 'beq', 6082616), (6082768, 'beq', 6082848), (6082784, 'beq', 6082848), (6082848, 'b', 6082852), (6082876, 'blo', 6082568), (6082968, 'bne', 6082568), (6082972, 'b', 6082976), (6083024, 'bls', 6083504), (6083504, 'b', 6083508), (6083684, 'b', 6083688)],
        semantics=('[World connectionDidFinishLoading:] (imp 0x005ccc88, 540w): the global-prices fetch completion - NSJSONSerialization JSONObjectWithData:options:error:, merges the parsed dictionary into globalPrices (fast enumeration x2 + objc_enumerationMutation), persists via NSUserDefaults setDouble:forKey:, schedules addOperationWithBlock: on the saveQueue (the _NSConcreteStackBlock literal import) and fires updatedPricesReceived on the tradePortalUI + updateTradePricesIfNeeded.\n'),
    ),
    dict(
        name='wl_03',
        method='World -[connection:didFailWithError:]',
        types='v16@0:4@8@12',
        start=6080916,
        end=6081672,
        disasm='disasm_worldtileloader_wl_03.txt',
        base_add=6080932,
        base_literal=6081664,
        boundary='ARM.exidx end 0x005ccc88 (listing bound); next ObjC IMP 0x005ccc88 World -[connectionDidFinishLoading:]',
        selectors={
                 0x5ccc68: (15196584, 'localizedDescription'),
                 0x5ccc70: (15195768, 'release'),
                 0x5ccc74: (15196224, 'cancel'),
        },
        imports={
                 0x5ccc60: (16233208, '__CFConstantStringClassReference'),
                 0x5ccc64: (17151904, 'objc_msgSend'),
                 0x5ccc78: (16233192, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5ccc58: (17156380, 'OBJC_IVAR_$_World.sendPricesConnection', 3220),
                 0x5ccc5c: (17156732, 'OBJC_IVAR_$_World.getPricesConnection', 3228),
                 0x5ccc6c: (17156736, 'OBJC_IVAR_$_World.getPricesRecieveData', 3232),
                 0x5ccc7c: (17156480, 'OBJC_IVAR_$_World.sendPricesRecieveData', 3224),
        },
        classes={},
        instructions=[(6080916, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6081668, 'andeq r0, r0, r0')],
        calls=[(6081116, 'blx r2'), (6081152, 'blx r3'), (6081212, 'blx lr'), (6081256, 'blx ip'), (6081276, 'bl sym.imp.NSLog'), (6081448, 'blx r2'), (6081484, 'blx r3'), (6081544, 'blx lr'), (6081588, 'blx ip'), (6081608, 'bl sym.imp.NSLog')],
        branches=[(6080988, 'bne', 6081284), (6081280, 'b', 6081616), (6081320, 'bne', 6081612), (6081612, 'b', 6081616)],
        semantics=('[World connection:didFailWithError:] (imp 0x005cc994, 189w): the prices-connection failure path - matches the failed connection against send/getPricesConnection, logs localizedDescription via NSLog x2 and releases/clears the receive buffers.\n'),
    ),
    dict(
        name='wl_04',
        method='World -[connection:didReceiveData:]',
        types='v16@0:4@8@12',
        start=6080612,
        end=6080916,
        disasm='disasm_worldtileloader_wl_04.txt',
        base_add=6080628,
        base_literal=6080912,
        boundary='ARM.exidx end 0x005cc994 (listing bound); next ObjC IMP 0x005cc994 World -[connection:didFailWithError:]',
        selectors={
                 0x5cc984: (15195612, 'appendData:'),
        },
        imports={
                 0x5cc980: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5cc978: (17156380, 'OBJC_IVAR_$_World.sendPricesConnection', 3220),
                 0x5cc97c: (17156732, 'OBJC_IVAR_$_World.getPricesConnection', 3228),
                 0x5cc988: (17156736, 'OBJC_IVAR_$_World.getPricesRecieveData', 3232),
                 0x5cc98c: (17156480, 'OBJC_IVAR_$_World.sendPricesRecieveData', 3224),
        },
        classes={},
        instructions=[(6080612, 'push {fp, lr}'), (6080912, 'adceq r3, sb, r8, ror r2')],
        calls=[(6080756, 'blx r3'), (6080872, 'blx r3')],
        branches=[(6080684, 'bne', 6080764), (6080760, 'b', 6080880), (6080800, 'bne', 6080876), (6080876, 'b', 6080880)],
        semantics=('[World connection:didReceiveData:] (imp 0x005cc864, 76w): appends the received chunk to the matching prices buffer (getPricesRecieveData / sendPricesRecieveData) via appendData:.\n'),
    ),
    dict(
        name='wl_05',
        method='World -[connection:didReceiveResponse:]',
        types='v16@0:4@8@12',
        start=6080316,
        end=6080612,
        disasm='disasm_worldtileloader_wl_05.txt',
        base_add=6080332,
        base_literal=6080608,
        boundary='ARM.exidx end 0x005cc994; body trimmed at the next IMP 0x005cc864 World -[connection:didReceiveData:]',
        selectors={
                 0x5cc854: (15198132, 'setLength:'),
        },
        imports={
                 0x5cc850: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5cc848: (17156380, 'OBJC_IVAR_$_World.sendPricesConnection', 3220),
                 0x5cc84c: (17156732, 'OBJC_IVAR_$_World.getPricesConnection', 3228),
                 0x5cc858: (17156736, 'OBJC_IVAR_$_World.getPricesRecieveData', 3232),
                 0x5cc85c: (17156480, 'OBJC_IVAR_$_World.sendPricesRecieveData', 3224),
        },
        classes={},
        instructions=[(6080316, 'push {fp, lr}'), (6080608, 'adceq r3, sb, r0, lsr 7')],
        calls=[(6080456, 'blx r3'), (6080568, 'blx r3')],
        branches=[(6080388, 'bne', 6080464), (6080460, 'b', 6080576), (6080500, 'bne', 6080572), (6080572, 'b', 6080576)],
        semantics=('[World connection:didReceiveResponse:] (imp 0x005cc73c, 74w): resets the matching prices buffer length (setLength:); the listing is trimmed at the next IMP (exidx over-cover).\n'),
    ),
    dict(
        name='wl_06',
        method='World -[isCloudGame]',
        types='c8@0:4',
        start=6098220,
        end=6098516,
        disasm='disasm_worldtileloader_wl_06.txt',
        base_add=6098236,
        base_literal=6098512,
        boundary='ARM.exidx end 0x005d0e54 (listing bound); next ObjC IMP 0x005d0e54 World -[reportUserWithName:reporterName:reporterMessage:reportedAvatarImagePath:]',
        selectors={
                 0x5d0e4c: (15195740, 'isCloudMatch'),
        },
        imports={
                 0x5d0e48: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5d0e40: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5d0e44: (17155916, 'OBJC_IVAR_$_World.server', 964),
        },
        classes={},
        instructions=[(6098220, 'push {fp, lr}'), (6098512, 'invalid')],
        calls=[(6098348, 'blx r2'), (6098460, 'blx r2')],
        branches=[(6098284, 'beq', 6098360), (6098356, 'b', 6098484), (6098396, 'beq', 6098472), (6098468, 'b', 6098484), (6098472, 'b', 6098476)],
        semantics=('[World isCloudGame] (imp 0x005d0d2c, 74w): cloud-match boolean - checks the client/server pair and folds isCloudMatch into a single return.\n'),
    ),
    dict(
        name='wl_07',
        method='World -[cloudTopupSucceeded:]',
        types='v12@0:4f8',
        start=6107480,
        end=6107720,
        disasm='disasm_worldtileloader_wl_07.txt',
        base_add=6107496,
        base_literal=6107716,
        boundary='ARM.exidx end 0x005d3248 (listing bound); next ObjC IMP 0x005d3248 World -[cloudTopupFailed:]',
        selectors={
                 0x5d3230: (15198304, 'updateSelection'),
                 0x5d3234: (15197548, 'craftUI'),
        },
        imports={
                 0x5d322c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5d3238: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x5d323c: (17155988, 'OBJC_IVAR_$_World.clientsideCredit', 3300),
                 0x5d3240: (17155992, 'OBJC_IVAR_$_World.clientAddedCreditTimer', 3304),
        },
        classes={},
        instructions=[(6107480, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6107716, 'adceq ip, r8, r4, lsl 19')],
        calls=[(6107664, 'blx r2'), (6107680, 'blx r2')],
        branches=[],
        semantics=('[World cloudTopupSucceeded:] (imp 0x005d3158, 60w): credit top-up success - refreshes the store UI (craftUI updateSelection) and re-arms the credit timer (clientAddedCreditTimer, constant 0x1e = 30).\n'),
    ),
    dict(
        name='wl_08',
        method='World -[decommissionOldBlocks]',
        types='v8@0:4',
        start=6057720,
        end=6060228,
        disasm='disasm_worldtileloader_wl_08.txt',
        base_add=6057736,
        base_literal=6060224,
        boundary='ARM.exidx end 0x005c78c4 (listing bound); next ObjC IMP 0x005c78c4 World -[preUpdate:]',
        selectors={
                 0x5c78b8: (15196704, 'checkIfMacroTileCanBeDecommissioned:world:minAge:blockToSavePhyscialBlock:'),
        },
        imports={},
        ivars={
                 0x5c78a0: (17156364, 'OBJC_IVAR_$_World.usedPhysicalBlocks', 456),
                 0x5c78a4: (17156368, 'OBJC_IVAR_$_World.freePhysicalBlocks', 476),
                 0x5c78b4: (17156340, 'OBJC_IVAR_$_World.macroTiles', 412),
        },
        classes={
                 0x5c78ac: (15245460, 'OBJC_CLASS_$_WorldHelper'),
        },
        instructions=[(6057720, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6060224, 'adceq r8, sb, r4, ror 23')],
        calls=[(6058656, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (6058720, 'bl loc.imp.objc_msgSend'), (6058752, 'bl method.std::__1::unordered_set_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___._unordered_set__'), (6058816, 'bl method.std::__1::__hash_table_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___.__insert_unique_PhysicalBlock_const_'), (6059352, 'bl method.std::__1::__hash_table_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___.__insert_unique_PhysicalBlock_const_'), (6059524, 'bl method.unsigned_long_std::__1::__hash_table_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___.__erase_unique_PhysicalBlock__PhysicalBlock_const_'), (6059924, 'bl method.std::__1::__hash_table_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___.erase_std::__1::__hash_const_iterator_std::__1::__hash_node_PhysicalBlock__void__const__'), (6060072, 'bl sym.imp.__wrap_free'), (6060140, 'bl sym.imp.__wrap_free'), (6060152, 'bl sym.imp.__wrap_free'), (6060168, 'bl method.std::__1::unordered_set_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___._unordered_set__'), (6060188, 'bl sym.imp._Unwind_Resume')],
        branches=[(6058524, 'beq', 6058992), (6058528, 'b', 6058532), (6058580, 'beq', 6058764), (6058664, 'b', 6058668), (6058728, 'b', 6058732), (6058732, 'b', 6058764), (6058760, 'b', 6060184), (6058776, 'bne', 6058920), (6058820, 'b', 6058824), (6058916, 'b', 6058920), (6058920, 'b', 6058924), (6058988, 'b', 6058356), (6059264, 'beq', 6059612), (6059268, 'b', 6059272), (6059356, 'b', 6059360), (6059532, 'b', 6059536), (6059536, 'b', 6059540), (6059540, 'b', 6059544), (6059608, 'b', 6059116), (6059680, 'bls', 6060164), (6059932, 'b', 6059936), (6060012, 'bge', 6060132), (6060052, 'beq', 6060112), (6060076, 'b', 6060080), (6060112, 'b', 6060116), (6060128, 'b', 6060004), (6060144, 'b', 6060148), (6060156, 'b', 6060160), (6060160, 'b', 6060164)],
        semantics=('[World decommissionOldBlocks] (imp 0x005c6ef8, 627w): the old-block reclaim pass - walks the macroTiles through WorldHelper checkIfMacroTileCanBeDecommissioned:world:minAge:blockToSavePhyscialBlock: (original spelling), collecting old blocks in a std::unordered_set<PhysicalBlock> (insert x2, erase paths via __hash_table), macroTileAtMacroPostion lookups, __wrap_free x3 and an _Unwind_Resume tail; minAge immediate 0x1e (30).\n'),
    ),
    dict(
        name='wl_09',
        method='World -[incrementalLoadCount]',
        types='i8@0:4',
        start=6134948,
        end=6135008,
        disasm='disasm_worldtileloader_wl_09.txt',
        base_add=6134972,
        base_literal=6135004,
        boundary='ARM.exidx end 0x005d9ce0 (listing bound); next ObjC IMP 0x005d9ce0 World -[windowInfo]',
        selectors={},
        imports={},
        ivars={
                 0x5d9cd8: (17156084, 'OBJC_IVAR_$_World.incrementalLoadCount', 132),
        },
        classes={},
        instructions=[(6134948, 'sub sp, sp, 8'), (6135004, 'adceq r5, r8, r0, lsr lr')],
        calls=[],
        branches=[],
        semantics=('[World incrementalLoadCount] (imp 0x005d9ca4, 15w): bare ivar getter for the incremental-load counter.\n'),
    ),
    dict(
        name='wl_10',
        method='World -[startBulkDatabaseUpdate]',
        types='v8@0:4',
        start=6131004,
        end=6131108,
        disasm='disasm_worldtileloader_wl_10.txt',
        base_add=6131020,
        base_literal=6131104,
        boundary='ARM.exidx end 0x005d8da4 (listing bound); next ObjC IMP 0x005d8da4 World -[finishBulkDatabaseUpdate]',
        selectors={
                 0x5d8d98: (15197988, 'startBulkTransaction'),
        },
        imports={
                 0x5d8d94: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5d8d9c: (17156076, 'OBJC_IVAR_$_World.databaseEnvironment', 3392),
        },
        classes={},
        instructions=[(6131004, 'push {fp, lr}'), (6131104, 'adceq r6, r8, r0, lsr 27')],
        calls=[(6131076, 'blx r3')],
        branches=[],
        semantics=('[World startBulkDatabaseUpdate] (imp 0x005d8d3c, 26w): opens the DB bulk transaction (databaseEnvironment startBulkTransaction).\n'),
    ),
    dict(
        name='wl_11',
        method='World -[finishBulkDatabaseUpdate]',
        types='c8@0:4',
        start=6131108,
        end=6131288,
        disasm='disasm_worldtileloader_wl_11.txt',
        base_add=6131124,
        base_literal=6131284,
        boundary='ARM.exidx end 0x005d8e58 (listing bound); next ObjC IMP 0x005d8e58 World -[usedPhysicalBlocks]',
        selectors={
                 0x5d8e44: (15198032, 'finishBulkTransaction'),
                 0x5d8e4c: (15198380, 'saveAnyPendingDataToDisk'),
        },
        imports={
                 0x5d8e40: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5d8e48: (17156076, 'OBJC_IVAR_$_World.databaseEnvironment', 3392),
                 0x5d8e50: (17156264, 'OBJC_IVAR_$_World.portalChestManager', 3336),
        },
        classes={},
        instructions=[(6131108, 'push {r4, r5, r6, sl, fp, lr}'), (6131284, 'adceq r6, r8, r8, lsr sp')],
        calls=[(6131212, 'blx r3'), (6131248, 'blx r3')],
        branches=[],
        semantics=('[World finishBulkDatabaseUpdate] (imp 0x005d8da4, 45w): closes the DB bulk transaction and flushes the portal chest manager (saveAnyPendingDataToDisk).\n'),
    ),
    dict(
        name='wl_12',
        method='World -[appDatabase]',
        types='@8@0:4',
        start=6133696,
        end=6133796,
        disasm='disasm_worldtileloader_wl_12.txt',
        base_add=6133712,
        base_literal=6133792,
        boundary='ARM.exidx end 0x005d9824 (listing bound); next ObjC IMP 0x005d9824 World -[worldWidthMacro]',
        selectors={
                 0x5d9818: (15196068, 'appDatabase'),
        },
        imports={
                 0x5d9814: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(6133696, 'push {fp, lr}'), (6133792, 'adceq r6, r8, ip, lsl r3')],
        calls=[(6133768, 'blx r3')],
        branches=[],
        semantics=('[World appDatabase] (imp 0x005d97c0, 25w): forwards to the database environment appDatabase getter.\n'),
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
        'batch': 'World lifecycle and cloud/prices IO (E106): the constructor, the prices quartet and the decommission pass; 13 bodies',
        'claim': ('a census-plus-targeted static map of the World lifecycle and cloud/prices IO line; the per-branch logic inside the constructor is read at histogram level, and the SFHFKeychainUtils / NSOperationQueue / WorldHelper contracts are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'world_load.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale world_load.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
