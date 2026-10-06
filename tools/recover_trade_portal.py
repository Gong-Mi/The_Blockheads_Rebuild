#!/usr/bin/env python3
"""Hash-gated recovery of the TradePortal structure batch (E9a).

40 bodies, 4716 instruction words total, from the pinned original libApplication.so (1.7.6, armeabi-v7a).
Every instruction word is re-verified; tool refuses to emit on drift.
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from trace_objc_dispatch import ELFMemory
from recover_drawframe_slices import verify_disassembly

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
EXPECTED_SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
EXPECTED_BASE = 0x0105FAF4

ROUTE_TARGETS = {
    'bl 0xd37798': 0X00D37798,
    'bl 0xd38dfc': 0X00D38DFC,
    'bl 0xd391d4': 0X00D391D4,
    'bl 0xd3cd80': 0X00D3CD80,
    'bl loc.imp.objc_msgSend': 0X001C281C,
    'bl loc.imp.objc_msgSendSuper2': 0X001C29FC,
    'bl loc.imp.objc_msgSend_stret': 0X001C2918,
    'bl method.Vector.Vector_float__float__float_': 0X004B52AC,
    'bl method.Vector.Vector_float__float__float__float_': 0X004D0D08,
    'bl method.Vector.operator_Vector_': 0X004D6538,
    'bl method.Vector2.Vector2_float__float_': 0X004D0480,
    'bl method.Vector2.operator_float__': 0X004BDAAC,
    'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_': 0X00D948FC,
    'bl sym.imp.__aeabi_idiv': 0X001C3728,
    'bl sym.imp.__modsi3': 0X001C3020,
    'bl sym.imp.__stack_chk_fail': 0X001C28B8,
    'bl sym.imp.memcpy': 0X001C2894,
    'bl sym.imp.memset': 0X001C2924,
    'bl sym.imp.objc_enumerationMutation': 0X001C2E28,
    'bl sym.makeIntpair_int__int_': 0X004B49FC,
    'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_': 0X00A19670,
    'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_': 0X00A197B4,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0X00A12F24,
    'bl sym.updateQuadBufferTexCoords_float__int__float__float__float__float_': 0X00D91B30,
}

SPECS = [
    dict(
        name='tp_subderived',
        method='TradePortal -[initSubDerivedItems]',
        types='v8@0:4',
        start=13858200,
        end=13858712,
        disasm='disasm_tradeportal_initsubderiveditems.txt',
        base_add=13858216,
        base_literal=13858708,
        boundary='consecutive IMPs: next method follows at 0x00d37798',
        selectors={13858692: (15239132, 'updateTradePricesIfNeeded'), 13858704: (15239128, 'macroTiles')},
        imports={13858688: (17151904, 'objc_msgSend')},
        ivars={13858680: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4), 13858684: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16), 13858696: (17168464, 'OBJC_IVAR_$_TradePortal.animationLoopIndex', 108)},
        classes={},
        instructions=[(13858200, 'push {r4, sl, fp, lr}'), (13858232, 'bl 0xd37798'), (13858676, 'pop {r4, sl, fp, pc}')],
        semantics=('initSubDerivedItems: portal-shape helper (bl 0xd37798) result aligned down to a multiple of 8 stored via slot 0xfffffd5c; marks the portal column: tileAtWorldPositionLoaded(x, y) and (x, y+1) get tile[3] = 0x30; quads reload via the size-change chain (sel 0xffe28ce4).'),
        calls=[(13858232, 'bl 0xd37798'), (13858348, 'bl loc.imp.objc_msgSend'), (13858392, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (13858464, 'blx r3'), (13858524, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13858636, 'bl sym.tileAtWorldPositionLoaded_int__int__World_')],
        branches=[(13858544, 'beq', 13858560), (13858656, 'beq', 13858672)],
    ),
    dict(
        name='tp_objtype',
        method='TradePortal -[objectType]',
        types='i8@0:4',
        start=13858728,
        end=13858756,
        disasm='disasm_tradeportal_objecttype.txt',
        base_add=None,
        base_literal=None,
        boundary='consecutive IMPs: next method follows at 0x00d377c4',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13858728, 'sub sp, sp, 8'), (13858752, 'bx lr')],
        semantics=('objectType = 0x32 (50).'),
        calls=[],
        branches=[],
    ),
    dict(
        name='tp_lightrgb',
        method='TradePortal -[getLightRGB]',
        types='{Vector=[4f]}8@0:4',
        start=13858756,
        end=13858856,
        disasm='disasm_tradeportal_getlightrgb.txt',
        base_add=None,
        base_literal=None,
        boundary='consecutive IMPs: next method follows at 0x00d37828',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13858756, 'push {r4, sl, fp, lr}'), (13858828, 'bl method.Vector.Vector_float__float__float_'), (13858840, 'pop {r4, sl, fp, pc}')],
        semantics=('getLightRGB = Vector(255.0, 246.0, 64.0) (constants 255/246/64 from the literal pool).'),
        calls=[(13858828, 'bl method.Vector.Vector_float__float__float_')],
        branches=[],
    ),
    dict(
        name='tp_updlight',
        method='TradePortal -[updatePortalLight]',
        types='v8@0:4',
        start=13858856,
        end=13859448,
        disasm='disasm_tradeportal_updateportallight.txt',
        base_add=13858888,
        base_literal=13859404,
        boundary='consecutive IMPs: next method follows at 0x00d37a78',
        selectors={13859408: (15239136, 'removeFromTiles'), 13859412: (15239140, 'release'), 13859420: (15239144, 'alloc'), 13859440: (15239148, 'initWithWorld:dynamicWorld:atPosition:cache:parentObject:colorR:colorG:colorB:heat:radius:lightDirection:'), 13859444: (15239128, 'macroTiles')},
        imports={},
        ivars={13859400: (17168468, 'OBJC_IVAR_$_TradePortal.light', 100), 13859424: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4), 13859428: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8), 13859432: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16), 13859436: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32)},
        classes={13859416: (15251280, 'OBJC_CLASS_$_ArtificialLight')},
        instructions=[(13858856, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13858924, 'bl loc.imp.objc_msgSend'), (13859396, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('updatePortalLight: tears the old light down (sel 0xffe28cec via slot 0xfffffd60), zeroes the light ivar, then creates the portal light: [lightSystem createLight](sel 0xffe28cf4) + addLightAtPos:RGB: chain (sel 0xffe28cf8, packed 0xff/0xf6/0x40) at makeIntpair(pos.x, pos.y-1), stores it into slot 0xfffffd60, calls the light setup (sel 0xffe28ce4), reloadDrawBlockLightGlowQuadsForTile(intpair, macroTile, world).'),
        calls=[(13858924, 'bl loc.imp.objc_msgSend'), (13858956, 'bl loc.imp.objc_msgSend'), (13859028, 'bl loc.imp.objc_msgSend'), (13859144, 'bl sym.makeIntpair_int__int_'), (13859268, 'bl loc.imp.objc_msgSend'), (13859344, 'bl loc.imp.objc_msgSend'), (13859388, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_')],
        branches=[],
    ),
    dict(
        name='tp_initpos',
        method='TradePortal -[initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:]',
        types='@48@0:4@8@12{?=ii}16@24@28c32@36@40@44',
        start=13860236,
        end=13861628,
        disasm='disasm_tradeportal_initwithworld_atposition.txt',
        base_add=13860252,
        base_literal=13861624,
        boundary='consecutive IMPs: next method follows at 0x00d382fc',
        selectors={13861544: (15239172, 'initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:'), 13861556: (15239176, 'init'), 13861560: (15239144, 'alloc'), 13861572: (15239156, 'objectForKey:'), 13861576: (15239180, 'loadPriceOffsets:'), 13861584: (15239184, 'intValue'), 13861604: (15239196, 'updatePortalLight'), 13861608: (15239192, 'initSubDerivedItems'), 13861620: (15239188, 'updateSunLightRemovedForTile:atPos:world:')},
        imports={13861552: (17151904, 'objc_msgSend')},
        ivars={13861548: (17168472, 'OBJC_IVAR_$_TradePortal.localPriceOffsets', 128), 13861580: (17168476, 'OBJC_IVAR_$_TradePortal.level', 132), 13861592: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4), 13861596: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16)},
        classes={13861536: (15253272, 'OBJC_CLASS_$_TradePortal'), 13861612: (15251292, 'OBJC_CLASS_$_WorldHelper')},
        instructions=[(13860236, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13860528, 'bl loc.imp.objc_msgSendSuper2'), (13861532, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('Full placement: objc_msgSendSuper2 init with the clientName: arg; nil guard; stores item/flipped/placedByClient; when saveDict != nil: objectForKey: decode (key f4e724); tile at (pos.x, pos.y-1): tile[3] = 0, if tile[1] == 2 -> tile[1] = 0xa; then the LEVEL JUMP TABLE: switch (level @ slot 0xfffffd68, 0..5) writes tile[0] = {0x3c,0x3d,0x3e,0x3f,0x40,0x41}; makeIntpair(pos.x, pos.y-1) + register the glow (sel 0xffe28d20) + tail chain (sels 0xffe28d24/0xffe28d28); return self.'),
        calls=[(13860528, 'bl loc.imp.objc_msgSendSuper2'), (13860652, 'blx r3'), (13860668, 'blx r2'), (13860768, 'blx r3'), (13860840, 'blx r3'), (13860928, 'blx lr'), (13860944, 'blx r2'), (13861044, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13861408, 'bl sym.makeIntpair_int__int_'), (13861472, 'bl loc.imp.objc_msgSend'), (13861492, 'blx r2'), (13861512, 'blx r2')],
        branches=[(13860556, 'bne', 13860572), (13860568, 'b', 13861524), (13860704, 'beq', 13860968), (13860788, 'beq', 13860844), (13861064, 'beq', 13861296), (13861092, 'bne', 13861108), (13861144, 'bhi', 13861288), (13861204, 'b', 13861292), (13861220, 'b', 13861292), (13861236, 'b', 13861292), (13861252, 'b', 13861292), (13861268, 'b', 13861292), (13861284, 'b', 13861292), (13861288, 'b', 13861292), (13861292, 'b', 13861296)],
    ),
    dict(
        name='tp_initsave',
        method='TradePortal -[initWithWorld:dynamicWorld:saveDict:cache:]',
        types='@24@0:4@8@12@16@20',
        start=13861628,
        end=13862752,
        disasm='disasm_tradeportal_initwithworld_savedict.txt',
        base_add=13861644,
        base_literal=13862748,
        boundary='consecutive IMPs: next method follows at 0x00d38760',
        selectors={13862652: (15239200, 'initWithWorld:dynamicWorld:saveDict:cache:'), 13862668: (15239156, 'objectForKey:'), 13862676: (15239176, 'init'), 13862680: (15239144, 'alloc'), 13862688: (15239180, 'loadPriceOffsets:'), 13862700: (15239184, 'intValue'), 13862728: (15239204, 'initWithWorld:dynamicWorld:saveDict:cache:parentObject:'), 13862740: (15239128, 'macroTiles'), 13862744: (15239192, 'initSubDerivedItems')},
        imports={13862648: (17151900, 'objc_msgSendSuper2'), 13862664: (17151904, 'objc_msgSend')},
        ivars={13862672: (17168472, 'OBJC_IVAR_$_TradePortal.localPriceOffsets', 128), 13862696: (17168476, 'OBJC_IVAR_$_TradePortal.level', 132), 13862716: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4), 13862720: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8), 13862724: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32), 13862732: (17168468, 'OBJC_IVAR_$_TradePortal.light', 100), 13862736: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16)},
        classes={13862656: (15253272, 'OBJC_CLASS_$_TradePortal'), 13862708: (15251280, 'OBJC_CLASS_$_ArtificialLight')},
        instructions=[(13861628, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13861780, 'blx r6'), (13862644, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('Save-dict restore: objc_msgSendSuper2 init; localPriceOffsets = [NSMutableArray array] (sel 0xffe28cf4); objectForKey: decodes with keys f4e724/f4e734 (+f4e744 conditional) including the level; when the f4e744 key exists: light rebuild chain (sels 0xffe28d30/0xffe28d20) + reloadDrawBlockLightGlowQuadsForTile; tail (sel 0xffe28d24); return self.'),
        calls=[(13861780, 'blx r6'), (13861936, 'blx r3'), (13861952, 'blx r2'), (13861996, 'blx r3'), (13862068, 'blx r3'), (13862180, 'blx ip'), (13862196, 'blx r2'), (13862240, 'blx r3'), (13862288, 'bl loc.imp.objc_msgSend'), (13862384, 'bl loc.imp.objc_msgSend'), (13862452, 'bl loc.imp.objc_msgSend'), (13862536, 'bl loc.imp.objc_msgSend'), (13862580, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_'), (13862624, 'blx r2')],
        branches=[(13861808, 'bne', 13861824), (13861820, 'b', 13862636), (13862016, 'beq', 13862072), (13862252, 'beq', 13862584)],
    ),
    dict(
        name='tp_initnet',
        method='TradePortal -[initWithWorld:dynamicWorld:cache:netData:]',
        types='@24@0:4@8@12@16@20',
        start=13862752,
        end=13864444,
        disasm='disasm_tradeportal_initwithworld_netdata.txt',
        base_add=13862768,
        base_literal=13864440,
        boundary='consecutive IMPs: next method follows at 0x00d38dfc',
        selectors={13864320: (15239208, 'initWithWorld:dynamicWorld:cache:netData:'), 13864336: (15239176, 'init'), 13864340: (15239144, 'alloc'), 13864352: (15239156, 'objectForKey:'), 13864360: (15239228, 'retain'), 13864376: (15239224, 'gzipInflate'), 13864380: (15239212, 'getBytes:length:'), 13864392: (15239216, 'length'), 13864396: (15239220, 'subdataWithRange:'), 13864400: (15239180, 'loadPriceOffsets:'), 13864404: (15239152, 'countByEnumeratingWithState:objects:count:'), 13864408: (15239232, 'blockheads'), 13864416: (15239236, 'netInteractionObjectWasLoaded:'), 13864420: (15239192, 'initSubDerivedItems'), 13864436: (15239128, 'macroTiles')},
        imports={13864316: (17151900, 'objc_msgSendSuper2'), 13864332: (17151904, 'objc_msgSend')},
        ivars={13864328: (17168472, 'OBJC_IVAR_$_TradePortal.localPriceOffsets', 128), 13864356: (17156788, 'OBJC_IVAR_$_InteractionObject.ownerName', 84), 13864368: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36), 13864388: (17168476, 'OBJC_IVAR_$_TradePortal.level', 132), 13864412: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8), 13864428: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16), 13864432: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4)},
        classes={13864324: (15253272, 'OBJC_CLASS_$_TradePortal')},
        instructions=[(13862752, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13862904, 'blx r6'), (13864312, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('Network restore: objc_msgSendSuper2 init; getBytes:length: 0x30 decode into a stack buffer; level = payload byte; items array via sel 0xffe28d3c + sub 0x30/sel 0xffe28d40 pair; helper 0xd38dfc (price decode); localPriceOffsets rebuilt by fast-enumerating the decoded array (keys f4e724/f4e754/f4e764); light rebuild + glow reload; return self.'),
        calls=[(13862904, 'blx r6'), (13863024, 'bl loc.imp.objc_msgSend'), (13863072, 'bl loc.imp.objc_msgSend'), (13863140, 'bl loc.imp.objc_msgSend'), (13863164, 'blx r2'), (13863168, 'bl 0xd38dfc'), (13863388, 'blx ip'), (13863404, 'blx r2'), (13863448, 'blx r3'), (13863464, 'blx r2'), (13863508, 'blx r3'), (13863544, 'blx r3'), (13863560, 'blx r2'), (13863648, 'blx r3'), (13863768, 'blx r2'), (13863792, 'bl sym.imp.memset'), (13863840, 'blx lr'), (13863940, 'bl sym.imp.objc_enumerationMutation'), (13864020, 'blx ip'), (13864120, 'blx ip'), (13864172, 'bl loc.imp.objc_msgSend'), (13864248, 'bl loc.imp.objc_msgSend'), (13864292, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_')],
        branches=[(13862932, 'bne', 13862948), (13862944, 'b', 13864304), (13863596, 'beq', 13863652), (13863852, 'beq', 13864144), (13863932, 'beq', 13863944), (13864048, 'blo', 13863896), (13864140, 'bne', 13863896), (13864144, 'b', 13864148)],
    ),
    dict(
        name='tp_updnet',
        method='TradePortal -[updateNetDataForClient:]',
        types='@12@0:4@8',
        start=13864480,
        end=13865428,
        disasm='disasm_tradeportal_updatenetdata.txt',
        base_add=13864496,
        base_literal=13865424,
        boundary='consecutive IMPs: next method follows at 0x00d391d4',
        selectors={13865360: (15239240, 'interactionObjectCreationNetData'), 13865372: (15239248, 'dictionary'), 13865380: (15239244, 'dataWithBytes:length:'), 13865396: (15239168, 'setObject:forKey:'), 13865416: (15239256, 'appendData:'), 13865420: (15239252, 'gzipDeflate')},
        imports={13865368: (17151904, 'objc_msgSend')},
        ivars={13865364: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36), 13865388: (17168476, 'OBJC_IVAR_$_TradePortal.level', 132), 13865400: (17156788, 'OBJC_IVAR_$_InteractionObject.ownerName', 84), 13865408: (17168472, 'OBJC_IVAR_$_TradePortal.localPriceOffsets', 128)},
        classes={},
        instructions=[(13864480, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13864572, 'bl loc.imp.objc_msgSend_stret'), (13865356, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('updateNetDataForClient: super stret 0x28 net struct; encodes the level byte + the three conditional price fields (keys f4e754/f4e764/f4e724) via the setObject:forKey: chain; helper 0xd391d4 (gzip region); appendData pair (sels 0xffe28d64/0xffe28d60); returns the assembled data.'),
        calls=[(13864572, 'bl loc.imp.objc_msgSend_stret'), (13864608, 'bl sym.imp.memset'), (13864768, 'bl sym.imp.memcpy'), (13864832, 'blx lr'), (13864868, 'blx r3'), (13864992, 'blx ip'), (13865120, 'blx ip'), (13865248, 'blx ip'), (13865256, 'bl 0xd391d4'), (13865316, 'blx lr'), (13865344, 'blx r3')],
        branches=[(13864556, 'beq', 13864580), (13864576, 'b', 13864612), (13864904, 'beq', 13864996), (13865032, 'beq', 13865124), (13865160, 'beq', 13865252)],
    ),
    dict(
        name='tp_dealloc',
        method='TradePortal -[dealloc]',
        types='v8@0:4',
        start=13865792,
        end=13866080,
        disasm='disasm_tradeportal_dealloc.txt',
        base_add=13865808,
        base_literal=13866076,
        boundary='consecutive IMPs: next method follows at 0x00d39460',
        selectors={13866052: (15239260, 'dealloc'), 13866068: (15239140, 'release')},
        imports={13866048: (17151900, 'objc_msgSendSuper2'), 13866064: (17151904, 'objc_msgSend')},
        ivars={13866060: (17168468, 'OBJC_IVAR_$_TradePortal.light', 100), 13866072: (17168472, 'OBJC_IVAR_$_TradePortal.localPriceOffsets', 128)},
        classes={13866056: (15253272, 'OBJC_CLASS_$_TradePortal')},
        instructions=[(13865792, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13865936, 'blx r7'), (13866044, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('Teardown: release chain on slot 0xfffffd60 (light) + the array (0xfffffd64) + super2 dealloc.'),
        calls=[(13865936, 'blx r7'), (13865972, 'blx r3'), (13866036, 'blx ip')],
        branches=[],
    ),
    dict(
        name='tp_getsave',
        method='TradePortal -[getSaveDict]',
        types='@8@0:4',
        start=13866080,
        end=13866708,
        disasm='disasm_tradeportal_getsavedict_closure.txt',
        base_add=13866096,
        base_literal=13866704,
        boundary='consecutive IMPs: next method follows at 0x00d396d4',
        selectors={13866656: (15239264, 'getSaveDict'), 13866676: (15239168, 'setObject:forKey:'), 13866688: (15239268, 'numberWithInt:')},
        imports={13866652: (17151900, 'objc_msgSendSuper2'), 13866672: (17151904, 'objc_msgSend')},
        ivars={13866664: (17168472, 'OBJC_IVAR_$_TradePortal.localPriceOffsets', 128), 13866680: (17168468, 'OBJC_IVAR_$_TradePortal.light', 100), 13866692: (17168476, 'OBJC_IVAR_$_TradePortal.level', 132)},
        classes={13866660: (15253272, 'OBJC_CLASS_$_TradePortal')},
        instructions=[(13866080, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13866164, 'blx ip'), (13866648, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('getSaveDict: super stret dict + [dict setObject:...forKey:] pairs: conditional key f4e724 when the price array is non-empty, level key f4e734 (numberWithInt via slot 0xfffffd60 object fetch), conditional key f4e744 (sel 0xffe28d0c setObject chain); b2i-era CFString keys.'),
        calls=[(13866164, 'blx ip'), (13866304, 'blx ip'), (13866476, 'blx r8'), (13866512, 'blx ip'), (13866548, 'blx r3'), (13866636, 'blx ip')],
        branches=[(13866216, 'beq', 13866308), (13866568, 'beq', 13866640)],
    ),
    dict(
        name='tp_interobjtype',
        method='TradePortal -[interactionObjectType]',
        types='S8@0:4',
        start=13866708,
        end=13866736,
        disasm='disasm_tradeportal_interactionobjecttype.txt',
        base_add=None,
        base_literal=None,
        boundary='consecutive IMPs: next method follows at 0x00d396f0',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13866708, 'sub sp, sp, 8'), (13866732, 'bx lr')],
        semantics=('interactionObjectType = 7 (uxth).'),
        calls=[],
        branches=[],
    ),
    dict(
        name='tp_remoteupd',
        method='TradePortal -[remoteUpdate:]',
        types='v12@0:4@8',
        start=13866736,
        end=13869464,
        disasm='disasm_tradeportal_remoteupdate.txt',
        base_add=13866752,
        base_literal=13869456,
        boundary='consecutive IMPs: next method follows at 0x00d3a198',
        selectors={13869300: (15239272, 'remoteUpdate:'), 13869316: (15239212, 'getBytes:length:'), 13869332: (15239276, 'objectType'), 13869336: (15239280, 'dynamicWorldChangedAtPos:objectType:'), 13869348: (15239284, 'instance'), 13869352: (15239288, 'multiSoundNamed:'), 13869360: (15239292, 'playAtPosition:'), 13869380: (15239156, 'objectForKey:'), 13869388: (15239228, 'retain'), 13869396: (15239140, 'release'), 13869408: (15239224, 'gzipInflate'), 13869412: (15239216, 'length'), 13869420: (15239220, 'subdataWithRange:'), 13869424: (15239180, 'loadPriceOffsets:'), 13869432: (15239176, 'init'), 13869436: (15239144, 'alloc'), 13869452: (15239296, 'addParticleAtPos:velocity:color:gravityType:life:scale:center:')},
        imports={13869296: (17151900, 'objc_msgSendSuper2'), 13869312: (17151904, 'objc_msgSend')},
        ivars={13869308: (17168476, 'OBJC_IVAR_$_TradePortal.level', 132), 13869320: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8), 13869328: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16), 13869364: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4), 13869372: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56), 13869384: (17156788, 'OBJC_IVAR_$_InteractionObject.ownerName', 84), 13869400: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36), 13869428: (17168472, 'OBJC_IVAR_$_TradePortal.localPriceOffsets', 128)},
        classes={13869304: (15253272, 'OBJC_CLASS_$_TradePortal'), 13869344: (15251300, 'OBJC_CLASS_$_MJSoundManager'), 13869444: (15251304, 'OBJC_CLASS_$_ParticleEmitter')},
        instructions=[(13866736, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13866828, 'blx lr'), (13869292, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('remoteUpdate: objc_msgSendSuper2 + packet decode (0x228-byte frame); if packet level > current: apply level (slot 0xfffffd68), rebuild the price tables: eight-iteration loop calling the price helper 0xd37798 with 64.0f scaling and building a 0x40-byte item struct per slot (sel 0xffe28d8c store), then the LEVEL JUMP TABLE on (level-1, 0..4): tile[0] = {0x3d,0x3e,0x3f,0x40,0x41}; if slot 0xffffcfd0 == 0: getBytes:length: 0x30 + helper 0xd38dfc price decode + fast-enumeration rebuild of localPriceOffsets (keys f4e724/f4e754/f4e764) + duplicate jump table + tail chain (sel 0xffe28d18).'),
        calls=[(13866828, 'blx lr'), (13866968, 'bl loc.imp.objc_msgSend'), (13867004, 'bl loc.imp.objc_msgSend'), (13867044, 'blx ip'), (13867180, 'bl loc.imp.objc_msgSend'), (13867204, 'bl loc.imp.objc_msgSend'), (13867268, 'bl method.Vector2.Vector2_float__float_'), (13867296, 'bl loc.imp.objc_msgSend'), (13867380, 'bl method.Vector.Vector_float__float__float_'), (13867412, 'bl 0xd37798'), (13867512, 'bl method.Vector.Vector_float__float__float__float_'), (13867548, 'bl loc.imp.objc_msgSend'), (13867556, 'bl 0xd37798'), (13867592, 'bl 0xd37798'), (13867640, 'bl method.Vector.Vector_float__float__float_'), (13867680, 'bl method.Vector.operator_Vector_'), (13867684, 'bl 0xd37798'), (13867728, 'bl 0xd37798'), (13867784, 'bl method.Vector.Vector_float__float__float_'), (13867820, 'bl 0xd37798'), (13867860, 'bl 0xd37798'), (13868156, 'bl loc.imp.objc_msgSend'), (13868252, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13868580, 'bl loc.imp.objc_msgSend'), (13868648, 'bl loc.imp.objc_msgSend'), (13868672, 'blx r2'), (13868676, 'bl 0xd38dfc'), (13868856, 'blx ip'), (13868880, 'blx r3'), (13868896, 'blx r2'), (13868952, 'blx ip'), (13868976, 'blx r3'), (13868992, 'blx r2'), (13869036, 'blx r3'), (13869188, 'blx r7'), (13869220, 'blx r3'), (13869236, 'blx r2'), (13869280, 'blx r3')],
        branches=[(13867076, 'ble', 13868480), (13867408, 'bge', 13868176), (13868172, 'b', 13867400), (13868272, 'beq', 13868476), (13868316, 'bhi', 13868468), (13868372, 'b', 13868472), (13868388, 'b', 13868472), (13868404, 'b', 13868472), (13868420, 'b', 13868472), (13868436, 'b', 13868472), (13868468, 'b', 13868472), (13868472, 'b', 13868476), (13868476, 'b', 13868480), (13868516, 'bne', 13869288), (13869056, 'beq', 13869284), (13869284, 'b', 13869288)],
    ),
    dict(
        name='tp_draw',
        method='TradePortal -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        types='v156@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76i140i144i148i152',
        start=13869464,
        end=13871352,
        disasm='disasm_tradeportal_draw.txt',
        base_add=13869484,
        base_literal=13871348,
        boundary='consecutive IMPs: next method follows at 0x00d3a8f8',
        selectors={13871300: (15239304, 'stop'), 13871312: (15239300, 'setLooping:'), 13871320: (15239292, 'playAtPosition:')},
        imports={13871296: (17151904, 'objc_msgSend')},
        ivars={13871288: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68), 13871292: (17168480, 'OBJC_IVAR_$_TradePortal.sound', 112), 13871304: (17168484, 'OBJC_IVAR_$_TradePortal.paused', 116), 13871316: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24), 13871324: (17168488, 'OBJC_IVAR_$_TradePortal.animationLoopTimer', 104), 13871332: (17168492, 'OBJC_IVAR_$_TradePortal.savedDrawBuffer', 120), 13871336: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12), 13871340: (17168496, 'OBJC_IVAR_$_TradePortal.savedDrawBufferIndex', 124), 13871344: (17168464, 'OBJC_IVAR_$_TradePortal.animationLoopIndex', 108)},
        classes={},
        instructions=[(13869464, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13870200, 'bl loc.imp.objc_msgSend'), (13871260, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('Portal draw: gate byte slot 0xffffcfd8; light on/off transitions via sels 0xffe28d90/0xffe28d94 (light ivar 0xfffffd6c/0xfffffd70) + intpair register (sel 0xffe28d88); phase float slot 0xfffffd74 += pinchScale; while phase > 0.2f: subtract 0.2f + counter slot 0xfffffd5c += 1 (mod 8 at >= 8) + stepped-flag; when slot 0xfffffd78 != 0 and tile+0x1a4 matches and tile+0x1a8 > slot 0xfffffd7c: texture scroll via __modsi3/__aeabi_idiv + doubles {0.5, 0.25, 1.0} -> updateQuadBufferTexCoords(buf, 0x20, f, f, f, f).'),
        calls=[(13870200, 'bl loc.imp.objc_msgSend'), (13870280, 'bl loc.imp.objc_msgSend'), (13870396, 'blx r3'), (13871012, 'bl sym.imp.__modsi3'), (13871028, 'bl sym.imp.__aeabi_idiv'), (13871248, 'bl sym.updateQuadBufferTexCoords_float__int__float__float__float__float_')],
        branches=[(13870064, 'beq', 13870288), (13870104, 'bne', 13870284), (13870140, 'bne', 13870284), (13870284, 'b', 13870428), (13870324, 'beq', 13870424), (13870424, 'b', 13870428), (13870516, 'ble', 13870664), (13870620, 'blt', 13870660), (13870660, 'b', 13870476), (13870700, 'beq', 13871256), (13870744, 'beq', 13871256), (13870812, 'bne', 13871256), (13870880, 'ble', 13871256), (13870892, 'beq', 13871252), (13871252, 'b', 13871256)],
    ),
    dict(
        name='tp_worldcontents',
        method='TradePortal -[worldContentsChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=13873712,
        end=13873736,
        disasm='disasm_tradeportal_worldcontentschanged.txt',
        base_add=None,
        base_literal=None,
        boundary='consecutive IMPs: next method follows at 0x00d3b248',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13873712, 'sub sp, sp, 0xc'), (13873732, 'bx lr')],
        semantics=('worldContentsChanged: empty body (no-op).'),
        calls=[],
        branches=[],
    ),
    dict(
        name='tp_doubleheight',
        method='TradePortal -[isDoubleHeight]',
        types='c8@0:4',
        start=13873736,
        end=13873764,
        disasm='disasm_tradeportal_isdoubleheight.txt',
        base_add=None,
        base_literal=None,
        boundary='consecutive IMPs: next method follows at 0x00d3b264',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13873736, 'sub sp, sp, 8'), (13873760, 'bx lr')],
        semantics=('isDoubleHeight = 1.'),
        calls=[],
        branches=[],
    ),
    dict(
        name='tp_setneedsremoved',
        method='TradePortal -[setNeedsRemoved:]',
        types='v12@0:4c8',
        start=13873764,
        end=13874104,
        disasm='disasm_tradeportal_setneedsremoved.txt',
        base_add=13873780,
        base_literal=13874100,
        boundary='consecutive IMPs: next method follows at 0x00d3b3b8',
        selectors={13874068: (15239320, 'setNeedsRemoved:'), 13874084: (15239136, 'removeFromTiles'), 13874096: (15239128, 'macroTiles')},
        imports={13874064: (17151900, 'objc_msgSendSuper2')},
        ivars={13874076: (17168468, 'OBJC_IVAR_$_TradePortal.light', 100), 13874088: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16), 13874092: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4)},
        classes={13874072: (15253272, 'OBJC_CLASS_$_TradePortal')},
        instructions=[(13873764, 'push {r4, r5, fp, lr}'), (13873876, 'blx lr'), (13874060, 'pop {r4, r5, fp, pc}')],
        semantics=('setNeedsRemoved: objc_msgSendSuper2(super, setNeedsRemoved:); when the arg is true: light teardown (sel 0xffe28cec) + glow reload (sel 0xffe28ce4 + reloadDrawBlockLightGlowQuadsForTile).'),
        calls=[(13873876, 'blx lr'), (13873932, 'bl loc.imp.objc_msgSend'), (13874008, 'bl loc.imp.objc_msgSend'), (13874052, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_')],
        branches=[(13873888, 'beq', 13874056)],
    ),
    dict(
        name='tp_fbitem',
        method='TradePortal -[freeblockCreationItemType]',
        types='i8@0:4',
        start=13874104,
        end=13874132,
        disasm='disasm_tradeportal_freeblockcreationitemtype.txt',
        base_add=None,
        base_literal=None,
        boundary='consecutive IMPs: next method follows at 0x00d3b3d4',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13874104, 'sub sp, sp, 8'), (13874128, 'bx lr')],
        semantics=('freeblockCreationItemType = 0xd2 (210).'),
        calls=[],
        branches=[],
    ),
    dict(
        name='tp_fbsave',
        method='TradePortal -[freeBlockCreationSaveDict]',
        types='@8@0:4',
        start=13874132,
        end=13874208,
        disasm='disasm_tradeportal_freeblockcreationsavedict.txt',
        base_add=13874148,
        base_literal=13874204,
        boundary='consecutive IMPs: next method follows at 0x00d3b420',
        selectors={13874200: (15239264, 'getSaveDict')},
        imports={13874196: (17151904, 'objc_msgSend')},
        ivars={},
        classes={},
        instructions=[(13874132, 'push {fp, lr}'), (13874184, 'blx r3'), (13874192, 'pop {fp, pc}')],
        semantics=('freeBlockCreationSaveDict = single forward (sel 0xffe28d6c).'),
        calls=[(13874184, 'blx r3')],
        branches=[],
    ),
    dict(
        name='tp_fba',
        method='TradePortal -[freeBlockCreationDataA]',
        types='S8@0:4',
        start=13874208,
        end=13874236,
        disasm='disasm_tradeportal_freeblockcreationdataa.txt',
        base_add=None,
        base_literal=None,
        boundary='body trimmed at the next IMP 0x00d3b43c (ARM.exidx over-covers into the following method)',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13874208, 'sub sp, sp, 8'), (13874232, 'bx lr')],
        semantics=('freeBlockCreationDataA = 0 (uxth).'),
        calls=[],
        branches=[],
    ),
    dict(
        name='tp_fbb',
        method='TradePortal -[freeBlockCreationDataB]',
        types='S8@0:4',
        start=13874236,
        end=13874264,
        disasm='disasm_tradeportal_freeblockcreationdatab.txt',
        base_add=None,
        base_literal=None,
        boundary='consecutive IMPs: next method follows at 0x00d3b458',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13874236, 'sub sp, sp, 8'), (13874260, 'bx lr')],
        semantics=('freeBlockCreationDataB = 0 (uxth).'),
        calls=[],
        branches=[],
    ),
    dict(
        name='tp_remove',
        method='TradePortal -[remove:]',
        types='v12@0:4@8',
        start=13874264,
        end=13875296,
        disasm='disasm_tradeportal_remove.txt',
        base_add=13874280,
        base_literal=13875292,
        boundary='consecutive IMPs: next method follows at 0x00d3b860',
        selectors={13875236: (15239324, 'isNet'), 13875252: (15239328, 'stopInteracting'), 13875256: (15239320, 'setNeedsRemoved:'), 13875260: (15239336, 'removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:'), 13875280: (15239264, 'getSaveDict'), 13875284: (15239332, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:')},
        imports={13875232: (17151904, 'objc_msgSend')},
        ivars={13875220: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48), 13875224: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52), 13875228: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68), 13875240: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56), 13875244: (17156816, 'OBJC_IVAR_$_InteractionObject.remoteBlockheadInUseUniqueID', 72), 13875264: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16), 13875268: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4), 13875272: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8), 13875288: (17156820, 'OBJC_IVAR_$_InteractionObject.needsToBeRemovedWhenInteractionEnds', 96)},
        classes={},
        instructions=[(13874264, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13874468, 'blx r2'), (13875216, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('remove: gate byte 0xffffc8d4; net/server branch (sels 0xffe28da8/0xffe28dac); when the removal flag is 0: objc_msgSendSuper2(super, setNeedsRemoved:YES) + set byte 0xffffcfe0 = 1; else: rebuild the portal column: createFreeBlock-style calls (sel 0xffe28db0 with the 7-word struct {0xd2, 1, 0, res, 1, 0, arg}) at (pos.x, y), (pos.x, y-1), (pos.x, y+1), then the tail call with sxtb arg (sel from slot 0xffffcfe0 area).'),
        calls=[(13874468, 'blx r2'), (13874628, 'blx r2'), (13874808, 'bl loc.imp.objc_msgSend'), (13874896, 'bl loc.imp.objc_msgSend'), (13874988, 'blx ip'), (13875084, 'blx ip'), (13875180, 'blx ip'), (13875208, 'blx r3')],
        branches=[(13874328, 'bne', 13874368), (13874364, 'beq', 13874372), (13874368, 'b', 13875212), (13874404, 'beq', 13874636), (13874480, 'bne', 13874532), (13874524, 'beq', 13874568), (13874528, 'b', 13874532), (13874564, 'b', 13875212), (13874632, 'b', 13874636)],
    ),
    dict(
        name='tp_destroyitem',
        method='TradePortal -[destroyItemType]',
        types='i8@0:4',
        start=13875296,
        end=13875324,
        disasm='disasm_tradeportal_destroyitemtype.txt',
        base_add=None,
        base_literal=None,
        boundary='consecutive IMPs: next method follows at 0x00d3b87c',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13875296, 'sub sp, sp, 8'), (13875320, 'bx lr')],
        semantics=('destroyItemType = 0xd2 (210).'),
        calls=[],
        branches=[],
    ),
    dict(
        name='tp_title',
        method='TradePortal -[title]',
        types='@8@0:4',
        start=13875324,
        end=13875472,
        disasm='disasm_tradeportal_title.txt',
        base_add=13875340,
        base_literal=13875468,
        boundary='consecutive IMPs: next method follows at 0x00d3b910',
        selectors={13875456: (15239340, 'stringWithFormat:')},
        imports={13875452: (17151904, 'objc_msgSend')},
        ivars={13875460: (17168476, 'OBJC_IVAR_$_TradePortal.level', 132)},
        classes={},
        instructions=[(13875324, 'push {r4, r5, fp, lr}'), (13875436, 'blx ip'), (13875444, 'pop {r4, r5, fp, pc}')],
        semantics=('title: returns the localized portal title string: [X msg(msg sel 0xffe28db8, CFStringRef key f4e784+slide, [self+slot 0xfffffd68 (level)]+1)] - the level-dependent title lookup.'),
        calls=[(13875436, 'blx ip')],
        branches=[],
    ),
    dict(
        name='tp_actiontitle',
        method='TradePortal -[actionTitle]',
        types='@8@0:4',
        start=13875472,
        end=13876164,
        disasm='disasm_tradeportal_actiontitle.txt',
        base_add=13875488,
        base_literal=13876160,
        boundary='consecutive IMPs: next method follows at 0x00d3bbc4',
        selectors={13876136: (15239344, 'customRules')},
        imports={13876144: (17151968, '__stack_chk_guard')},
        ivars={13876140: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4)},
        classes={},
        instructions=[(13875472, 'push {r4, sl, fp, lr}'), (13875588, 'bl loc.imp.objc_msgSend_stret'), (13876128, 'pop {r4, sl, fp, pc}')],
        semantics=('actionTitle: stret getter (sel 0xffe28dbc) then returns one of the localized action strings by the interaction state byte: state==1 -> empty; state byte sp+0x9e == 3 -> CFString f4e794; sp+0x5e == 5 -> CFString f4e7a4; default CFString f4e7b4; stack-canary checked.'),
        calls=[(13875588, 'bl loc.imp.objc_msgSend_stret'), (13875624, 'bl sym.imp.memset'), (13875712, 'bl loc.imp.objc_msgSend_stret'), (13875748, 'bl sym.imp.memset'), (13875848, 'bl loc.imp.objc_msgSend_stret'), (13875884, 'bl sym.imp.memset'), (13875992, 'bl loc.imp.objc_msgSend_stret'), (13876028, 'bl sym.imp.memset'), (13876132, 'bl sym.imp.__stack_chk_fail')],
        branches=[(13875572, 'beq', 13875596), (13875592, 'b', 13875628), (13875636, 'beq', 13876068), (13875696, 'beq', 13875720), (13875716, 'b', 13875752), (13875760, 'bne', 13875776), (13875772, 'b', 13876084), (13875832, 'beq', 13875856), (13875852, 'b', 13875888), (13875896, 'bne', 13875920), (13875916, 'b', 13876084), (13875976, 'beq', 13876000), (13875996, 'b', 13876032), (13876040, 'bne', 13876064), (13876060, 'b', 13876084), (13876064, 'b', 13876068), (13876116, 'bne', 13876132)],
    ),
    dict(
        name='tp_secondtitle',
        method='TradePortal -[secondOptionTitle]',
        types='@8@0:4',
        start=13876164,
        end=13877332,
        disasm='disasm_tradeportal_secondoptiontitle.txt',
        base_add=13876180,
        base_literal=13877328,
        boundary='consecutive IMPs: next method follows at 0x00d3c054',
        selectors={13877308: (15239344, 'customRules')},
        imports={13877316: (17151968, '__stack_chk_guard')},
        ivars={13877312: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4)},
        classes={},
        instructions=[(13876164, 'push {r4, sl, fp, lr}'), (13876280, 'bl loc.imp.objc_msgSend_stret'), (13877300, 'pop {r4, sl, fp, pc}')],
        semantics=('secondOptionTitle: stret getters x6 (same selector 0xffe28dbc) and picks the localized string: state fields 2, 3, 4, 5 shortcut / field sp+0x8e == 5 -> CFString f4e7a4; else f4e794; stack-canary checked. (Levels 2..5 title selection.)'),
        calls=[(13876280, 'bl loc.imp.objc_msgSend_stret'), (13876316, 'bl sym.imp.memset'), (13876404, 'bl loc.imp.objc_msgSend_stret'), (13876440, 'bl sym.imp.memset'), (13876528, 'bl loc.imp.objc_msgSend_stret'), (13876564, 'bl sym.imp.memset'), (13876652, 'bl loc.imp.objc_msgSend_stret'), (13876688, 'bl sym.imp.memset'), (13876776, 'bl loc.imp.objc_msgSend_stret'), (13876812, 'bl sym.imp.memset'), (13876904, 'bl loc.imp.objc_msgSend_stret'), (13876940, 'bl sym.imp.memset'), (13877032, 'bl loc.imp.objc_msgSend_stret'), (13877068, 'bl sym.imp.memset'), (13877156, 'bl loc.imp.objc_msgSend_stret'), (13877192, 'bl sym.imp.memset'), (13877304, 'bl sym.imp.__stack_chk_fail')],
        branches=[(13876264, 'beq', 13876288), (13876284, 'b', 13876320), (13876328, 'beq', 13877240), (13876388, 'beq', 13876412), (13876408, 'b', 13876444), (13876452, 'beq', 13876960), (13876512, 'beq', 13876536), (13876532, 'b', 13876568), (13876576, 'beq', 13876960), (13876636, 'beq', 13876660), (13876656, 'b', 13876692), (13876700, 'beq', 13876960), (13876760, 'beq', 13876784), (13876780, 'b', 13876816), (13876828, 'beq', 13876960), (13876888, 'beq', 13876912), (13876908, 'b', 13876944), (13876956, 'bne', 13877240), (13877016, 'beq', 13877040), (13877036, 'b', 13877072), (13877080, 'beq', 13877208), (13877140, 'beq', 13877164), (13877160, 'b', 13877196), (13877204, 'bne', 13877220), (13877216, 'b', 13877256), (13877236, 'b', 13877256), (13877288, 'bne', 13877304)],
    ),
    dict(
        name='tp_thirdtitle',
        method='TradePortal -[thirdOptionTitle]',
        types='@8@0:4',
        start=13877332,
        end=13878220,
        disasm='disasm_tradeportal_thirdoptiontitle.txt',
        base_add=13877348,
        base_literal=13878216,
        boundary='consecutive IMPs: next method follows at 0x00d3c3cc',
        selectors={13878200: (15239344, 'customRules')},
        imports={13878208: (17151968, '__stack_chk_guard')},
        ivars={13878204: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4)},
        classes={},
        instructions=[(13877332, 'push {r4, sl, fp, lr}'), (13877448, 'bl loc.imp.objc_msgSend_stret'), (13878192, 'pop {r4, sl, fp, pc}')],
        semantics=('thirdOptionTitle: stret getters x6 (same selector 0xffe28dbc); states 2..5 shortcut; field sp+0x76 == 1 -> empty else CFString f4e7a4; stack-canary checked.'),
        calls=[(13877448, 'bl loc.imp.objc_msgSend_stret'), (13877484, 'bl sym.imp.memset'), (13877572, 'bl loc.imp.objc_msgSend_stret'), (13877608, 'bl sym.imp.memset'), (13877696, 'bl loc.imp.objc_msgSend_stret'), (13877732, 'bl sym.imp.memset'), (13877820, 'bl loc.imp.objc_msgSend_stret'), (13877856, 'bl sym.imp.memset'), (13877944, 'bl loc.imp.objc_msgSend_stret'), (13877980, 'bl sym.imp.memset'), (13878068, 'bl loc.imp.objc_msgSend_stret'), (13878104, 'bl sym.imp.memset'), (13878196, 'bl sym.imp.__stack_chk_fail')],
        branches=[(13877432, 'beq', 13877456), (13877452, 'b', 13877488), (13877496, 'beq', 13878132), (13877556, 'beq', 13877580), (13877576, 'b', 13877612), (13877620, 'beq', 13878120), (13877680, 'beq', 13877704), (13877700, 'b', 13877736), (13877744, 'beq', 13878120), (13877804, 'beq', 13877828), (13877824, 'b', 13877860), (13877868, 'beq', 13878120), (13877928, 'beq', 13877952), (13877948, 'b', 13877984), (13877992, 'beq', 13878120), (13878052, 'beq', 13878076), (13878072, 'b', 13878108), (13878116, 'bne', 13878132), (13878128, 'b', 13878148), (13878180, 'bne', 13878196)],
    ),
    dict(
        name='tp_setworkbench',
        method='TradePortal -[setWorkbenchChoiceUIOption:]',
        types='v12@0:4i8',
        start=13878220,
        end=13878792,
        disasm='disasm_tradeportal_setworkbenchchoiceuioption.txt',
        base_add=13878236,
        base_literal=13878788,
        boundary='consecutive IMPs: next method follows at 0x00d3c608',
        selectors={13878764: (15239356, 'thirdOptionTitle'), 13878768: (15239352, 'secondOptionTitle'), 13878772: (15239348, 'actionTitle'), 13878780: (15239360, 'isEqualToString:')},
        imports={13878760: (17151904, 'objc_msgSend')},
        ivars={13878748: (17168500, 'OBJC_IVAR_$_TradePortal.isSellInteraction', 136), 13878756: (17168504, 'OBJC_IVAR_$_TradePortal.isMissionInteraction', 137)},
        classes={},
        instructions=[(13878220, 'push {fp, lr}'), (13878404, 'blx r2'), (13878744, 'pop {fp, pc}')],
        semantics=('setWorkbenchChoiceUIOption: zeroes bytes slot 0xfffffd80/0xfffffd84; switch(arg) 0/1/2 gets the option object via sels 0xffe28dc0/0xffe28dc4/0xffe28dc8; then checks the option title (sel 0xffe28dcc) against CFString f4e794 -> byte 0xfffffd80 = 1 and CFString f4e7a4 -> byte 0xfffffd84 = 1.'),
        calls=[(13878404, 'blx r2'), (13878456, 'blx r2'), (13878508, 'blx r2'), (13878576, 'blx ip'), (13878688, 'blx ip')],
        branches=[(13878324, 'beq', 13878468), (13878328, 'b', 13878332), (13878340, 'beq', 13878416), (13878344, 'b', 13878348), (13878356, 'bne', 13878516), (13878360, 'b', 13878364), (13878412, 'b', 13878516), (13878464, 'b', 13878516), (13878588, 'beq', 13878628), (13878624, 'b', 13878740), (13878700, 'beq', 13878736), (13878736, 'b', 13878740)],
    ),
    dict(
        name='tp_requireshuman',
        method='TradePortal -[requiresHumanInteraction]',
        types='c8@0:4',
        start=13878792,
        end=13878820,
        disasm='disasm_tradeportal_requireshumaninteraction.txt',
        base_add=None,
        base_literal=None,
        boundary='consecutive IMPs: next method follows at 0x00d3c624',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13878792, 'sub sp, sp, 8'), (13878816, 'bx lr')],
        semantics=('requiresHumanInteraction = 1.'),
        calls=[],
        branches=[],
    ),
    dict(
        name='tp_sgcdc',
        method='TradePortal -[staticGeometryDrawCubeCount]',
        types='i8@0:4',
        start=13879736,
        end=13879768,
        disasm='disasm_tradeportal_staticgeometrydrawcubecount.txt',
        base_add=None,
        base_literal=None,
        boundary='consecutive IMPs: next method follows at 0x00d3c9d8',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13879736, 'sub sp, sp, 8'), (13879760, 'bx lr')],
        semantics=('staticGeometryDrawCubeCount = 1.'),
        calls=[],
        branches=[],
    ),
    dict(
        name='tp_addquad',
        method='TradePortal -[addDrawQuadData:fromIndex:forMacroPos:]',
        types='i24@0:4^f8i12{?=ii}16',
        start=13879768,
        end=13880704,
        disasm='disasm_tradeportal_adddrawquaddata.txt',
        base_add=13879840,
        base_literal=13880684,
        boundary='consecutive IMPs: next method follows at 0x00d3cd80',
        selectors={},
        imports={},
        ivars={13880680: (17168492, 'OBJC_IVAR_$_TradePortal.savedDrawBuffer', 120), 13880688: (17168496, 'OBJC_IVAR_$_TradePortal.savedDrawBufferIndex', 124), 13880692: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24), 13880696: (17168464, 'OBJC_IVAR_$_TradePortal.animationLoopIndex', 108), 13880700: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12)},
        classes={},
        instructions=[(13879768, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13879908, 'bl method.Vector2.operator_float__'), (13880648, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('addDrawQuadData:fromIndex:forMacroPos: stores the pair into slots 0xfffffd78/0xfffffd7c; Vector2 pos (-5y) + z = -0.99f (0xbf7d70a4); helper 0xd3cd80 (quad buffer position builder); texture scroll math: counter = (slot 0xfffffd5c + 0x2f0) mod 8 and /8 with doubles {0.03125, 0.5, 0.25} producing 4 scrolling texcoords; one fillQuadBuffer(...20 args) submission; returns index+1.'),
        calls=[(13879908, 'bl method.Vector2.operator_float__'), (13879944, 'bl method.Vector2.operator_float__'), (13879972, 'bl 0xd3cd80'), (13880624, 'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_')],
        branches=[],
    ),
    dict(
        name='tp_sgdq',
        method='TradePortal -[staticGeometryDrawQuadCountForMacroPos:]',
        types='i16@0:4{?=ii}8',
        start=13880820,
        end=13880856,
        disasm='disasm_tradeportal_staticgeometrydrawquadcount.txt',
        base_add=None,
        base_literal=None,
        boundary='consecutive IMPs: next method follows at 0x00d3ce18',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13880820, 'sub sp, sp, 0x10'), (13880852, 'bx lr')],
        semantics=('staticGeometryDrawQuadCountForMacroPos: = 1.'),
        calls=[],
        branches=[],
    ),
    dict(
        name='tp_rmmacro',
        method='TradePortal -[removeFromMacroBlock]',
        types='v8@0:4',
        start=13880856,
        end=13881120,
        disasm='disasm_tradeportal_removefrommacroblock.txt',
        base_add=13880872,
        base_literal=13881116,
        boundary='consecutive IMPs: next method follows at 0x00d3cf20',
        selectors={13881092: (15239380, 'removeFromMacroBlock'), 13881112: (15239128, 'macroTiles')},
        imports={13881088: (17151900, 'objc_msgSendSuper2')},
        ivars={13881100: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16), 13881108: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4)},
        classes={13881096: (15253272, 'OBJC_CLASS_$_TradePortal')},
        instructions=[(13880856, 'push {fp, lr}'), (13880964, 'bl loc.imp.objc_msgSend'), (13881084, 'pop {fp, pc}')],
        semantics=('removeFromMacroBlock: light teardown (sel 0xffe28ce4) + reloadDrawBlockDynamicObjectQuadsForTile + objc_msgSendSuper2(super, removeFromMacroBlock).'),
        calls=[(13880964, 'bl loc.imp.objc_msgSend'), (13881008, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (13881076, 'blx r3')],
        branches=[],
    ),
    dict(
        name='tp_lightglow',
        method='TradePortal -[lightGlowQuadCount]',
        types='i8@0:4',
        start=13890444,
        end=13890472,
        disasm='disasm_tradeportal_lightglowquadcount.txt',
        base_add=None,
        base_literal=None,
        boundary='consecutive IMPs: next method follows at 0x00d3f3a8',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13890444, 'sub sp, sp, 8'), (13890468, 'bx lr')],
        semantics=('lightGlowQuadCount = 1.'),
        calls=[],
        branches=[],
    ),
    dict(
        name='tp_lightpos',
        method='TradePortal -[lightPos]',
        types='{Vector=[4f]}8@0:4',
        start=13890472,
        end=13890656,
        disasm='disasm_tradeportal_lightpos.txt',
        base_add=13890488,
        base_literal=13890652,
        boundary='consecutive IMPs: next method follows at 0x00d3f460',
        selectors={},
        imports={},
        ivars={13890648: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24)},
        classes={},
        instructions=[(13890472, 'push {fp, lr}'), (13890532, 'bl method.Vector2.operator_float__'), (13890644, 'pop {fp, pc}')],
        semantics=('lightPos = Vector(pos.x, pos.y+1, -1.0) built from Vector2 operator float* + Vector(float,float,float).'),
        calls=[(13890532, 'bl method.Vector2.operator_float__'), (13890568, 'bl method.Vector2.operator_float__'), (13890632, 'bl method.Vector.Vector_float__float__float_')],
        branches=[],
    ),
    dict(
        name='tp_interrender',
        method='TradePortal -[interactionRenderItemType]',
        types='i8@0:4',
        start=13891500,
        end=13891528,
        disasm='disasm_tradeportal_interactionrenderitemtype.txt',
        base_add=None,
        base_literal=None,
        boundary='body trimmed at the next IMP 0x00d3f7c8 (ARM.exidx over-covers into the following method)',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13891500, 'sub sp, sp, 8'), (13891524, 'bx lr')],
        semantics=('interactionRenderItemType = 0xa7 (167).'),
        calls=[],
        branches=[],
    ),
    dict(
        name='tp_occnormal',
        method='TradePortal -[occupiesNormalContents]',
        types='c8@0:4',
        start=13891528,
        end=13891556,
        disasm='disasm_tradeportal_occupiesnormalcontents.txt',
        base_add=None,
        base_literal=None,
        boundary='consecutive IMPs: next method follows at 0x00d3f7e4',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13891528, 'sub sp, sp, 8'), (13891552, 'bx lr')],
        semantics=('occupiesNormalContents = 1.'),
        calls=[],
        branches=[],
    ),
    dict(
        name='tp_addlight',
        method='TradePortal -[addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:]',
        types='v16@0:4i8i12',
        start=13891556,
        end=13891672,
        disasm='disasm_tradeportal_addartificiallightcontribution.txt',
        base_add=13891572,
        base_literal=13891668,
        boundary='consecutive IMPs: next method follows at 0x00d3f858',
        selectors={13891660: (15239468, 'addContributionForPhysicalBlockLoadedAtXPos:yPos:')},
        imports={13891656: (17151904, 'objc_msgSend')},
        ivars={13891664: (17168468, 'OBJC_IVAR_$_TradePortal.light', 100)},
        classes={},
        instructions=[(13891556, 'push {r4, r5, fp, lr}'), (13891644, 'blx lr'), (13891652, 'pop {r4, r5, fp, pc}')],
        semantics=('addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos: forwards to the slot 0xfffffd60 object (sel 0xffe28e38) with (x, y).'),
        calls=[(13891644, 'blx lr')],
        branches=[],
    ),
    dict(
        name='tp_expertmode',
        method='TradePortal -[canBeUsedInExpertModeWhenNotOwned]',
        types='c8@0:4',
        start=13891672,
        end=13891700,
        disasm='disasm_tradeportal_canbeusedinexpertmode.txt',
        base_add=None,
        base_literal=None,
        boundary='consecutive IMPs: next method follows at 0x00d3f874',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13891672, 'sub sp, sp, 8'), (13891696, 'bx lr')],
        semantics=('canBeUsedInExpertModeWhenNotOwned = 1.'),
        calls=[],
        branches=[],
    ),
    dict(
        name='tp_localoffsets',
        method='TradePortal -[localPriceOffsets]',
        types='@8@0:4',
        start=13891700,
        end=13891768,
        disasm='disasm_tradeportal_localpriceoffsets.txt',
        base_add=13891724,
        base_literal=13891764,
        boundary='consecutive IMPs: next method follows at 0x00d3f8b8',
        selectors={},
        imports={},
        ivars={13891760: (17168472, 'OBJC_IVAR_$_TradePortal.localPriceOffsets', 128)},
        classes={},
        instructions=[(13891700, 'sub sp, sp, 0xc'), (13891756, 'bx lr')],
        semantics=('localPriceOffsets = dmb ish atomic load of the array ivar (slot 0xfffffd64).'),
        calls=[],
        branches=[],
    ),
    dict(
        name='tp_level',
        method='TradePortal -[level]',
        types='i8@0:4',
        start=13891768,
        end=13891828,
        disasm='disasm_tradeportal_level.txt',
        base_add=13891792,
        base_literal=13891824,
        boundary='body trimmed at the next IMP 0x00d3f8f4 (ARM.exidx over-covers into the following method)',
        selectors={},
        imports={},
        ivars={13891820: (17168476, 'OBJC_IVAR_$_TradePortal.level', 132)},
        classes={},
        instructions=[(13891768, 'sub sp, sp, 8'), (13891816, 'bx lr')],
        semantics=('level = dmb ish atomic load of the level ivar (slot 0xfffffd68).'),
        calls=[],
        branches=[],
    ),]

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

    def cstr(addr):
        off = memory.offset(addr, 1)
        if off is None:
            return None
        end = data.find(b'\0', off, off + 256)
        return data[off:end].decode('utf-8', 'replace') if end >= 0 else None

    dynsym = {}
    for sec in ELFFile(io.BytesIO(data)).iter_sections():
        if sec.name == '.dynsym':
            for s in sec.iter_symbols():
                if s['st_value']:
                    dynsym.setdefault(s['st_value'], s.name)

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

        for cell, (expected_slot, expected_symbol) in spec.get('classes', {}).items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: class cell {cell:#x} -> {slot:#x}")
            entry = memory.word(slot)
            got = dynsym.get(entry, '')
            if got != expected_symbol:
                raise ValueError(f"{spec['name']}: class drifted at {cell:#x}: {got!r}")
            selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'class': got}

        for cell, (expected_slot, expected_name) in spec['imports'].items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: import cell {cell:#x} -> {slot:#x}")
            got = memory.imports.get(slot)
            if got != expected_name:
                raise ValueError(f"{spec['name']}: import drifted at {cell:#x}: {got!r}")
            selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'import': got}

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

        listed_branches = {(a, m.group(1), int(m.group(2), 16))
                           for a, ins in inrange.items()
                           for m in [re.match(r'^(b\w*)\s+(0x[0-9a-f]+)', ins)]
                           if m and m.group(1) not in ('bl', 'blx')}
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
            'semantics': spec['semantics'],
        })

    return {
        'schema': 1,
        'elf_sha256': sha,
        'batch': 'TradePortal structure batch: placement trio (atPosition: 348w / saveDict: 281w / netData: 423w), getSaveDict/updateNetDataForClient/remoteUpdate with level jump tables and price arrays, portal light (getLightRGB 255/246/64, updatePortalLight, lightPos, glow), draw (lights + phase scroll), 4 localized title/option bodies, remove:/dealloc, freeblock quartet, static geometry (40 bodies)',
        'claim': ('static bounded-body maps with per-instruction anchors; '
                  'runtime values and the render consumers are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'trade_portal.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale trade_portal.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
