#!/usr/bin/env python3
"""Hash-gated recovery of the TradingPost (E151).

TradingPost lands: the batch sweeps tradingpost surface:
46 bodies, 10576 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/TRADINGPOST.md for the prose and boundaries.
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
    'bl 0x5e60a4': 0x005e60a4,
    'bl 0x5e67cc': 0x005e67cc,
    'bl 0x5e9844': 0x005e9844,
    'bl 0x5e9a2c': 0x005e9a2c,
    'bl 0x5e9a78': 0x005e9a78,
    'bl 0x5ea29c': 0x005ea29c,
    'bl 0x5ec428': 0x005ec428,
    'bl 0x5ec7e0': 0x005ec7e0,
    'bl 0x5ecdec': 0x005ecdec,
    'bl 0x5ed6b0': 0x005ed6b0,
    'bl 0x5eff44': 0x005eff44,
    'bl 0x5f00c4': 0x005f00c4,
    'bl 0x5f0524': 0x005f0524,
    'bl 0x5f0f4c': 0x005f0f4c,
    'bl 0x5f17a4': 0x005f17a4,
    'bl 0x5f17f0': 0x005f17f0,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector.Vector_float__float__float__float_': 0x004d0d08,
    'bl method.Vector.operator_float__': 0x004b5c08,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl sym.clothingItemPasivelyUsedRate_ItemType__int__int__signed_char_': 0x005e9fa4,
    'bl sym.drawShaderQuadNoTexture': 0x007c4790,
    'bl sym.fillQuadBufferColored_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__Vector__int__int_': 0x00d94c88,
    'bl sym.fillQuadBufferDodoEgg_float__int___GLKMatrix4__float__float__float__float__float__int__signed_char__int__int_': 0x00d94218,
    'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_': 0x00d948fc,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__wrap_glDisable': 0x001c2c48,
    'bl sym.imp.__wrap_glEnable': 0x001c2b04,
    'bl sym.imp.__wrap_glEnableVertexAttribArray': 0x001c2d5c,
    'bl sym.imp.__wrap_glUniform1i': 0x001c2de0,
    'bl sym.imp.__wrap_glUniform4f': 0x001c3d64,
    'bl sym.imp.__wrap_glUniformMatrix4fv': 0x001c2dd4,
    'bl sym.imp.__wrap_glUseProgram': 0x001c2d38,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.itemTypeIsBlock_ItemType_': 0x004cc11c,
    'bl sym.itemTypeIsStackable_ItemType__unsigned_short__unsigned_short_': 0x004ea3cc,
    'bl sym.itemTypeIsWorkbench_ItemType_': 0x005b2aa0,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.paintedIndexForImageIndex_int_': 0x00a15e28,
    'bl sym.popDepthMaskState': 0x007c57ec,
    'bl sym.pushDepthMaskState': 0x007c55e4,
    'bl sym.reloadDrawBlockDodoEggQuadsForTile_intpair__MacroTile__World_': 0x00a196dc,
    'bl sym.reloadDrawBlockDynamicObjectItemQuadsForTile_intpair__MacroTile__World_': 0x00a19748,
    'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_': 0x00a19670,
    'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_': 0x00a19598,
    'bl sym.texCoordsForImageIndex_int_': 0x004d6820,
    'bl sym.texCoordsForItemType_ItemType_': 0x004d6040,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileIsHalfDepth_Tile__World__intpair_': 0x00a14450,
    'bl sym.tileIsSolid_Tile_': 0x00a1179c,
    'bl sym.tileTexCoordsForItemType_ItemType__signed_char_': 0x005f0450,
    'bl sym.tileTexCoordsForWorkbenchTypeAndLevel_WorkbenchType__int__signed_char__signed_char_': 0x005effb8,
    'bl sym.usageIncrementPerUse_ItemType__int__signed_char__signed_char_': 0x005e9c30,
}

SPECS = [
    dict(
        name='tp_00',
        method='TradingPost -[actionTitle]',
        types='@8@0:4',
        start=6216504,
        end=6216684,
        disasm='disasm_worldtileloader_tp_00.txt',
        base_add=6216520,
        base_literal=6216680,
        boundary='ARM.exidx end 0x005edbec (listing bound); next ObjC IMP 0x005edbec TradingPost -[requiresHumanInteraction]',
        selectors={
                 0x5edbdc: (15198704, 'stringWithFormat:'),
                 0x5edbe0: (15198700, 'title'),
        },
        imports={
                 0x5edbd4: (16245048, '__CFConstantStringClassReference'),
                 0x5edbd8: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0x5edbe4: (15245580, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(6216504, 'push {r4, r5, r6, sl, fp, lr}'), (6216680, 'adceq r1, r7, r4, lsr 31')],
        calls=[(6216612, 'blx ip'), (6216648, 'blx ip')],
        branches=[],
        semantics=('[TradingPost -[actionTitle]] (imp 0x005edb38, 45w): -[actionTitle] (0x5edb38, 45w): returns [NSString stringWithFormat:@"USE %@", [self title]] (CFSTR \'USE %@\' cell 0x5edbd4, class cell NSString 0x5edbe4) - the same one-line pattern as Chest ce_00; title is the constant \'SHOP\', so the action label is \'USE SHOP\'..\n'),
    ),
    dict(
        name='tp_01',
        method='TradingPost -[addDodoEggDrawQuadData:fromIndex:]',
        types='i16@0:4^f8i12',
        start=6234660,
        end=6235624,
        disasm='disasm_worldtileloader_tp_01.txt',
        base_add=6234680,
        base_literal=6235620,
        boundary='ARM.exidx end 0x005f25e8 (listing bound); next ObjC IMP 0x005f25e8 TradingPost -[removeFromMacroBlock]',
        selectors={
                 0x5f25c4: (15198620, 'count'),
                 0x5f25cc: (15198440, 'itemType'),
                 0x5f25d0: (15198612, 'lastObject'),
                 0x5f25d4: (15198624, 'dataB'),
        },
        imports={
                 0x5f25c0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5f25c8: (17156760, 'OBJC_IVAR_$_TradingPost.sellSlot', 100),
                 0x5f25d8: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x5f25e0: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12),
        },
        classes={},
        instructions=[(6234660, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6235620, 'invalid')],
        calls=[(6234756, 'blx lr'), (6234860, 'blx ip'), (6234884, 'blx r2'), (6234936, 'blx r2'), (6234988, 'bl method.Vector2.operator_float__'), (6235024, 'bl method.Vector2.operator_float__'), (6235052, 'bl 0x5eff44'), (6235232, 'bl loc.imp.objc_msgSend'), (6235548, 'bl sym.fillQuadBufferDodoEgg_float__int___GLKMatrix4__float__float__float__float__float__int__signed_char__int__int_')],
        branches=[(6234764, 'bne', 6234780), (6234776, 'b', 6235572), (6234892, 'bne', 6235564), (6234948, 'beq', 6235564)],
        semantics=('[TradingPost -[addDodoEggDrawQuadData:fromIndex:]] (imp 0x005f2224, 241w): -[addDodoEggDrawQuadData:fromIndex:] (0x5f2224, 241w): emits exactly one dodo-egg quad when the LAST sell-slot item is a live dodo egg. Early-outs return 0: [sellSlot count]==0 (0x5f228c), [last itemType]!=0x5b (0x5f230c), (u16)[last dataB]==0 (0x5f2344). Center = (floatPos.x-5, floatPos.y, -0.9) built from two Vector2::operator float* reads (vmov.f32 s2,-5) and the local matrix builder 0x5eff44; the item\'s dataB is passed as the egg datum (SEND [last dataB]); tex/color block copied from [sp,0xf0..0x100]; macro world = macroTileOwner.x*32 / .y*32 (lsl 5). Fill = sym.fillQuadBufferDodoEgg_float__int___GLKMatrix4__float__float__float__float__float__int__signed_char__int__int_ with 0.9f (0x3f666666) / 0.1f (0x3dcccccd) extents; returns 1 (counter), 0 when skipped..\n'),
    ),
    dict(
        name='tp_02',
        method='TradingPost -[addDrawCubeData:fromIndex:]',
        types='i16@0:4^f8i12',
        start=6220568,
        end=6225732,
        disasm='disasm_worldtileloader_tp_02.txt',
        base_add=6220592,
        base_literal=6224320,
        boundary='ARM.exidx end 0x005eff44 (listing bound); next ObjC IMP 0x005f08e4 TradingPost -[staticGeometryDrawQuadCountForMacroPos:]',
        selectors={
                 0x5ef9d0: (15198620, 'count'),
                 0x5ef9e4: (15198748, 'fillBuffer:fromIndex:matrix:width:height:depth:centerX:centerY:centerZ:topMinS:topMaxS:topMinT:topMaxT:sideMinS:sideMaxS:sideMinT:sideMaxT:macroWorldX:macroWorldY:paintColor:'),
                 0x5eff1c: (15198440, 'itemType'),
                 0x5eff20: (15198612, 'lastObject'),
                 0x5eff24: (15198752, 'expertMode'),
                 0x5eff2c: (15198600, 'intValue'),
                 0x5eff34: (15198424, 'objectForKey:'),
                 0x5eff38: (15198628, 'dynamicObjectSaveDict'),
                 0x5eff40: (15198756, 'fillBuffer:fromIndex:matrix:width:height:depth:centerX:centerY:centerZ:topMinS:topMaxS:topMinT:topMaxT:sideMinS:sideMaxS:sideMinT:sideMaxT:macroWorldX:macroWorldY:'),
        },
        imports={
                 0x5ef9cc: (17151904, 'objc_msgSend'),
                 0x5eff0c: (17151904, 'objc_msgSend'),
                 0x5eff30: (16245144, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5ef9c4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x5ef9c8: (17156800, 'OBJC_IVAR_$_InteractionObject.paintColor', 88),
                 0x5ef9d4: (17156760, 'OBJC_IVAR_$_TradingPost.sellSlot', 100),
                 0x5ef9e0: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12),
                 0x5eff08: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x5eff10: (17156760, 'OBJC_IVAR_$_TradingPost.sellSlot', 100),
                 0x5eff18: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12),
                 0x5eff28: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={
                 0x5ef9d8: (15245584, 'OBJC_CLASS_$_DrawCube'),
                 0x5eff14: (15245584, 'OBJC_CLASS_$_DrawCube'),
        },
        instructions=[(6220568, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6225728, 'invalid')],
        calls=[(6220716, 'bl 0x5eff44'), (6220784, 'bl method.Vector.Vector_float__float__float__float_'), (6220832, 'bl sym.paintedIndexForImageIndex_int_'), (6220844, 'bl sym.paintedIndexForImageIndex_int_'), (6220896, 'bl 0x5ec7e0'), (6220984, 'bl sym.texCoordsForImageIndex_int_'), (6220996, 'bl sym.texCoordsForImageIndex_int_'), (6221720, 'bl loc.imp.objc_msgSend'), (6221744, 'bl sym.texCoordsForImageIndex_int_'), (6221952, 'bl 0x5eff44'), (6222756, 'bl loc.imp.objc_msgSend'), (6222860, 'bl 0x5eff44'), (6223664, 'bl loc.imp.objc_msgSend'), (6223712, 'blx r3'), (6223804, 'blx ip'), (6223828, 'blx r2'), (6223840, 'bl sym.itemTypeIsBlock_ItemType_'), (6223860, 'bl sym.itemTypeIsWorkbench_ItemType_'), (6223968, 'blx r5'), (6223988, 'blx r3'), (6224004, 'blx r2'), (6224016, 'bl 0x5f00c4'), (6224096, 'blx r3'), (6224128, 'bl sym.tileTexCoordsForWorkbenchTypeAndLevel_WorkbenchType__int__signed_char__signed_char_'), (6224168, 'bl 0x5f00c4'), (6224248, 'blx r3'), (6224280, 'bl sym.tileTexCoordsForWorkbenchTypeAndLevel_WorkbenchType__int__signed_char__signed_char_'), (6224372, 'bl sym.tileTexCoordsForItemType_ItemType__signed_char_'), (6224420, 'bl sym.tileTexCoordsForItemType_ItemType__signed_char_'), (6224568, 'bl 0x5eff44'), (6224948, 'bl 0x5f0524'), (6225628, 'bl loc.imp.objc_msgSend')],
        branches=[(6220824, 'beq', 6220932), (6222796, 'b', 6222812), (6223720, 'bls', 6225648), (6223852, 'beq', 6225644), (6223872, 'beq', 6224360), (6224316, 'b', 6224456), (6225644, 'b', 6225648)],
        semantics=('[TradingPost -[addDrawCubeData:fromIndex:]] (imp 0x005eeb18, 1291w): [census] -[addDrawCubeData:fromIndex:] (0x5eeb18, 1291w, 7 branches, 32 call rows; 0x5f0-byte frame): fills the shared DrawCube buffer for the post via the DrawCube class methods fillBuffer:fromIndex:matrix:...macroWorldX:macroWorldY: (19-arg, cell @0x5eef94) and ...macroWorldX:macroWorldY:paintColor: (20-arg, cell @0x5eefd8); returns the number of fills performed. Phase 1 (0x5eeb18-0x5ef3cc): static body - matrix center (pos.x+5, pos.y+5, -1.5) via 0x5eff44, white Vector(1,1,1,1), image ids 0xc4/0x131/0x130 (196/305/304) at [sp,0x584/0x588/0x58c], paint overrides (paintedIndexForImageIndex x2 + packed-16 -> RGBA via 0x5ec7e0 replacing the white vector at [sp,0x570]), texCoordsForImageIndex x3, one send at 0x5eef98. Phase 2 (0x5ef3dc-0x5ef764): second face block (second 0x5eff44 matrix @0x5ef40c; fillBuffer send @0x5ef730; counter++ @0x5ef734). Phase 3 (0x5ef768-0x5efef0): sell-slot item - if [sellSlot count]>0: last=[sellSlot lastObject]; itemTypeIsBlock -> skip (0x5efeec); itemTypeIsWorkbench -> read [last dynamicObjectSaveDict] intValue (level) + tileTexCoordsForWorkbenchTypeAndLevel (real symbol @0x5effb8) + index helper 0x5f00c4 (switch over types 15/133/134..140/220/269/...); otherwise tileTexCoordsForItemType (real symbol @0x5f0450) x2 (front/top faces), center z=-1.0 (0xbf800000), x/y nudge -0.18 (0xbe3851ec); [world expertMode] consulted (0x5ef8e0/0x5ef950); cube emit via local bridge 0x5f0524 + DrawCube fillBuffer send @0x5efedc; counter++ @0x5efee0. Constants seen: -1.5 (0xbfc00000), -0.98 (0xbf83d70a), 0.05/0.1 (0x3d4ccccd/0x3dcccccd), 0.2/0.4 (0x3e4ccccd/0x3ecccccd)..\n'),
    ),
    dict(
        name='tp_03',
        method='TradingPost -[addDrawItemQuadData:fromIndex:]',
        types='i16@0:4^f8i12',
        start=6229916,
        end=6231972,
        disasm='disasm_worldtileloader_tp_03.txt',
        base_add=6229936,
        base_literal=6231968,
        boundary='ARM.exidx end 0x005f17a4 (listing bound); next ObjC IMP 0x005f20e0 TradingPost -[staticGeometryDodoEggCount]',
        selectors={
                 0x5f1768: (15198620, 'count'),
                 0x5f1770: (15198440, 'itemType'),
                 0x5f1774: (15198612, 'lastObject'),
                 0x5f1778: (15198624, 'dataB'),
                 0x5f178c: (15198712, 'isEqualToString:'),
                 0x5f1790: (15198708, 'localNetID'),
        },
        imports={
                 0x5f1764: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5f176c: (17156760, 'OBJC_IVAR_$_TradingPost.sellSlot', 100),
                 0x5f177c: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x5f1784: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12),
                 0x5f1788: (17156784, 'OBJC_IVAR_$_TradingPost.coinCount', 104),
                 0x5f1794: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x5f1798: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
        },
        classes={},
        instructions=[(6229916, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6231968, 'adceq lr, r6, ip, lsr fp')],
        calls=[(6230012, 'blx lr'), (6230104, 'blx ip'), (6230128, 'blx r2'), (6230140, 'bl sym.itemTypeIsBlock_ItemType_'), (6230196, 'blx r2'), (6230248, 'blx r2'), (6230300, 'bl method.Vector2.operator_float__'), (6230336, 'bl method.Vector2.operator_float__'), (6230364, 'bl 0x5eff44'), (6230408, 'bl 0x5f17a4'), (6230628, 'bl loc.imp.objc_msgSend'), (6230968, 'bl 0x5f17f0'), (6231132, 'blx ip'), (6231164, 'blx r3'), (6231204, 'bl method.Vector2.operator_float__'), (6231240, 'bl method.Vector2.operator_float__'), (6231280, 'bl 0x5eff44'), (6231400, 'bl sym.texCoordsForItemType_ItemType_'), (6231880, 'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_')],
        branches=[(6230020, 'bls', 6230988), (6230152, 'bne', 6230984), (6230204, 'bne', 6230264), (6230260, 'bne', 6230984), (6230984, 'b', 6230988), (6231020, 'ble', 6231896), (6231176, 'beq', 6231896), (6231324, 'ble', 6231392), (6231364, 'blt', 6231380), (6231376, 'b', 6231388), (6231388, 'b', 6231392)],
        semantics=('[TradingPost -[addDrawItemQuadData:fromIndex:]] (imp 0x005f0f9c, 514w): -[addDrawItemQuadData:fromIndex:] (0x5f0f9c, 514w, int return): if [sellSlot count]==0 -> 0; last=[sellSlot lastObject]; it=[last itemType]; skip the item quad when itemTypeIsBlock(it) or (it==0x5b and (u16)[last dataB]!=0). Item quad: center=(floatPos.x-5, floatPos.y, -0.9) (0xbf666666) via 0x5eff44; Vec4 dest helper 0x5f17a4(out,0.1,0.1,0.9,0.9); emitted by local bridge 0x5f17f0 which returns 1 or 2 quads (2 for itemType==103 or itemTypeCanBeColored - helper 0x5f0f4c); counter += ret. Coin pile (0x5f13cc-0x5f1754): drawn only when coinCount@104 > 0 AND [[dynamicWorld localNetID] isEqualToString:ownerID@36]; center=(floatPos.x, floatPos.y+5, -0.8) (0xbf4ccccc); image id = coinCount>99 ? (coinCount>=10000 ? 0x104(260) : 0xa7(167)) : 0xa6(166); sym.texCoordsForItemType(that id); sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_ with 0.45f (0x3ee66666) / 0.05f (0x3d4ccccd); counter+=1. Returns total quads..\n'),
    ),
    dict(
        name='tp_04',
        method='TradingPost -[addDrawQuadData:fromIndex:forMacroPos:]',
        types='i24@0:4^f8i12{?=ii}16',
        start=6228232,
        end=6229212,
        disasm='disasm_worldtileloader_tp_04.txt',
        base_add=6228252,
        base_literal=6229208,
        boundary='ARM.exidx end 0x005f0cdc (listing bound); next ObjC IMP 0x005f0cdc TradingPost -[staticGeometryDrawItemQuadCount]',
        selectors={},
        imports={},
        ivars={
                 0x5f0cc8: (17156800, 'OBJC_IVAR_$_InteractionObject.paintColor', 88),
                 0x5f0ccc: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x5f0cd4: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12),
        },
        classes={},
        instructions=[(6228232, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6229208, 'invalid')],
        calls=[(6228348, 'bl method.Vector.Vector_float__float__float__float_'), (6228396, 'bl sym.paintedIndexForImageIndex_int_'), (6228444, 'bl 0x5ec7e0'), (6228488, 'bl sym.texCoordsForImageIndex_int_'), (6228528, 'bl method.Vector2.operator_float__'), (6228560, 'bl method.Vector2.operator_float__'), (6228596, 'bl 0x5eff44'), (6229164, 'bl sym.fillQuadBufferColored_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__Vector__int__int_')],
        branches=[(6228388, 'beq', 6228480)],
        semantics=('[TradingPost -[addDrawQuadData:fromIndex:forMacroPos:]] (imp 0x005f0908, 245w): -[addDrawQuadData:fromIndex:forMacroPos:] (0x5f0908, 245w, int return): emits exactly one quad of image index 0xb8 (184) at center (floatPos.x, floatPos.y+1.0, -0.99 (0xbf7d70a4)) built via helper 0x5eff44; white Vector(1,1,1,1) is replaced by the packed-16 paint RGBA (0x5ec7e0(paintColor,0), image then paintedIndexForImageIndex(0xb8)) when paintColor@88 != 0; texCoordsForImageIndex -> 4 floats, maxS=u0+u2, maxT=v0+v2; macro = macroTileOwner.x*32/.y*32 (lsl 5); fill = sym.fillQuadBufferColored_... with scale 1.0 (0x3f800000) and +-0.5 (0x3f000000/0xbf000000), dest-arg 0; counter++ -> returns 1 (fromIndex used as the starting index of the emitted data)..\n'),
    ),
    dict(
        name='tp_05',
        method='TradingPost -[blockheadIsSeller:]',
        types='c12@0:4@8',
        start=6216712,
        end=6217288,
        disasm='disasm_worldtileloader_tp_05.txt',
        base_add=6216728,
        base_literal=6217284,
        boundary='ARM.exidx end 0x005ede48 (listing bound); next ObjC IMP 0x005ede48 TradingPost -[price]',
        selectors={
                 0x5ede28: (15198708, 'localNetID'),
                 0x5ede30: (15198712, 'isEqualToString:'),
                 0x5ede34: (15198716, 'isClient'),
                 0x5ede40: (15198720, 'isClientBlockheadBeingControlledByServer'),
        },
        imports={
                 0x5ede24: (17151904, 'objc_msgSend'),
                 0x5ede3c: (16245064, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5ede2c: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
                 0x5ede38: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={},
        instructions=[(6216712, 'push {r4, sl, fp, lr}'), (6217284, 'invalid')],
        calls=[(6216780, 'blx lr'), (6216912, 'blx r3'), (6217000, 'blx r2'), (6217136, 'blx ip'), (6217192, 'blx r2')],
        branches=[(6216800, 'bne', 6216844), (6216840, 'beq', 6217232), (6216924, 'beq', 6216940), (6216936, 'b', 6217240), (6217012, 'bne', 6217220), (6217052, 'beq', 6217152), (6217148, 'beq', 6217220), (6217204, 'bne', 6217220), (6217216, 'b', 6217240), (6217228, 'b', 6217240)],
        semantics=('[TradingPost -[blockheadIsSeller:]] (imp 0x005edc08, 144w): -[blockheadIsSeller:] (0x5edc08, 144w, BOOL): nid=[blockhead localNetID]. YES when nid==0 and self.ownerID@36==nil (0x5edc88->0x5ede10); YES when [nid isEqualToString:self.ownerID]; otherwise if [self.dynamicWorld isClient] -> NO (0x5edd34); on the server side: if ownerID!=nil and ![ownerID isEqualToString:@"server"] -> NO (CFSTR \'server\' @0x5ede3c), else YES iff ![blockhead isClientBlockheadBeingControlledByServer] (0x5eddf4)..\n'),
    ),
    dict(
        name='tp_06',
        method='TradingPost -[buyButtonTappedWithQuantity:]',
        types='v12@0:4i8',
        start=6218296,
        end=6219952,
        disasm='disasm_worldtileloader_tp_06.txt',
        base_add=6218312,
        base_literal=6219948,
        boundary='ARM.exidx end 0x005ee8b0 (listing bound); next ObjC IMP 0x005ee8b0 TradingPost -[sellTitle]',
        selectors={
                 0x5ee82c: (15198620, 'count'),
                 0x5ee834: (15198724, 'totalCash'),
                 0x5ee838: (15198664, 'price'),
                 0x5ee83c: (15198728, 'subtractCash:'),
                 0x5ee848: (15198744, 'reportAchievementWithIdentifier:'),
                 0x5ee85c: (15198628, 'dynamicObjectSaveDict'),
                 0x5ee860: (15198612, 'lastObject'),
                 0x5ee868: (15198736, 'removeObjectForKey:'),
                 0x5ee880: (15198732, 'dictionaryWithDictionary:'),
                 0x5ee888: (15198440, 'itemType'),
                 0x5ee898: (15198616, 'dataA'),
                 0x5ee89c: (15198624, 'dataB'),
                 0x5ee8a0: (15198632, 'subItems'),
                 0x5ee8a4: (15198636, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
                 0x5ee8a8: (15198740, 'removeLastObject'),
        },
        imports={
                 0x5ee828: (17151904, 'objc_msgSend'),
                 0x5ee844: (16245112, '__CFConstantStringClassReference'),
                 0x5ee864: (16244968, '__CFConstantStringClassReference'),
                 0x5ee86c: (16244952, '__CFConstantStringClassReference'),
                 0x5ee870: (16245096, '__CFConstantStringClassReference'),
                 0x5ee874: (16245080, '__CFConstantStringClassReference'),
                 0x5ee878: (16244920, '__CFConstantStringClassReference'),
                 0x5ee87c: (16244936, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5ee824: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0x5ee830: (17156760, 'OBJC_IVAR_$_TradingPost.sellSlot', 100),
                 0x5ee840: (17156784, 'OBJC_IVAR_$_TradingPost.coinCount', 104),
                 0x5ee84c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x5ee850: (17156792, 'OBJC_IVAR_$_TradingPost.inventoryNeedsToBeSentWithUpdate', 125),
                 0x5ee854: (17156764, 'OBJC_IVAR_$_TradingPost.needsToUpdateBitmapString', 124),
                 0x5ee858: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0x5ee88c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x5ee894: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={
                 0x5ee884: (15245564, 'OBJC_CLASS_$_NSMutableDictionary'),
        },
        instructions=[(6218296, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6219948, 'adceq r1, r7, r4, lsr 17')],
        calls=[(6218436, 'blx r2'), (6218516, 'blx ip'), (6218572, 'blx r3'), (6218708, 'blx r3'), (6218832, 'blx lr'), (6218856, 'blx r2'), (6219040, 'blx sl'), (6219068, 'blx r3'), (6219092, 'blx r3'), (6219116, 'blx r3'), (6219140, 'blx r3'), (6219164, 'blx r3'), (6219188, 'blx r3'), (6219240, 'blx r2'), (6219332, 'bl loc.imp.objc_msgSend'), (6219364, 'bl loc.imp.objc_msgSend'), (6219396, 'bl loc.imp.objc_msgSend'), (6219428, 'bl loc.imp.objc_msgSend'), (6219556, 'bl loc.imp.objc_msgSend'), (6219620, 'blx r2'), (6219796, 'blx ip')],
        branches=[(6218364, 'beq', 6219804), (6218448, 'bhi', 6219804), (6218592, 'bgt', 6219800), (6218736, 'bge', 6219640), (6218876, 'beq', 6219200), (6219248, 'beq', 6219560), (6219636, 'b', 6218724), (6219800, 'b', 6219804)],
        semantics=('[TradingPost -[buyButtonTappedWithQuantity:]] (imp 0x005ee238, 414w): -[buyButtonTappedWithQuantity:] (0x5ee238, 414w): if currentBlockhead@56==nil -> return; if q > [sellSlot count] -> return; total = q * [self price]; if total > [currentBlockhead totalCash] -> return. Then self.coinCount@104 += total and [currentBlockhead subtractCash:total]; loop q times: item=[sellSlot lastObject]; sd=[item dynamicObjectSaveDict]; if sd!=nil copy = [NSMutableDictionary dictionaryWithDictionary:sd] minus keys ownerName/ownerID/sellerClientName/sellerClientID/safeClientID/ironPlaceClientID; if [item itemType] != 0xb -> [self.dynamicWorld createFreeBlockAtPosition:self.pos ofType:[item itemType] dataA:(u16)[item dataA] dataB:(u16)[item dataB] subItems:[item subItems] dynamicObjectSaveDict:sd hovers:0 playSound:4 priorityBlockhead:self.currentBlockhead]; [sellSlot removeLastObject]. Then updateNeedsToBeSent@49=1, needsToUpdateBitmapString@124=1, inventoryNeedsToBeSentWithUpdate@125=1 and [self.world reportAchievementWithIdentifier:@"grp.tycoon"] (CFSTR @0x5ee844)..\n'),
    ),
    dict(
        name='tp_07',
        method='TradingPost -[coinCount]',
        types='i8@0:4',
        start=6236688,
        end=6236748,
        disasm='disasm_worldtileloader_tp_07.txt',
        base_add=6236712,
        base_literal=6236744,
        boundary='ARM.exidx end 0x005f2a4c (listing bound); next ObjC IMP 0x005f2a4c TradingPost -[setCoinCount:]',
        selectors={},
        imports={},
        ivars={
                 0x5f2a44: (17156784, 'OBJC_IVAR_$_TradingPost.coinCount', 104),
        },
        classes={},
        instructions=[(6236688, 'sub sp, sp, 8'), (6236744, 'adceq sp, r6, r4, asr 1')],
        calls=[],
        branches=[],
        semantics=('[TradingPost -[coinCount]] (imp 0x005f2a10, 15w): -[coinCount] (0x5f2a10, 15w): Apportable offset-cell getter for coinCount@104 - cell 0x5f2a44 -> (PIC base + signed word) -> descriptor word -> ldr behind a single dmb ish; plain int return..\n'),
    ),
    dict(
        name='tp_08',
        method='TradingPost -[contentsDidChange]',
        types='v8@0:4',
        start=6208484,
        end=6209176,
        disasm='disasm_worldtileloader_tp_08.txt',
        base_add=6208516,
        base_literal=6209140,
        boundary='ARM.exidx end 0x005ebe98 (listing bound); next ObjC IMP 0x005ebe98 TradingPost -[update:accurateDT:isSimulation:]',
        selectors={
                 0x5ebe84: (15198652, 'objectType'),
                 0x5ebe88: (15198656, 'dynamicWorldChangedAtPos:objectType:'),
                 0x5ebe94: (15198468, 'macroTiles'),
        },
        imports={},
        ivars={
                 0x5ebe70: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0x5ebe78: (17156792, 'OBJC_IVAR_$_TradingPost.inventoryNeedsToBeSentWithUpdate', 125),
                 0x5ebe7c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x5ebe80: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x5ebe8c: (17156764, 'OBJC_IVAR_$_TradingPost.needsToUpdateBitmapString', 124),
                 0x5ebe90: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(6208484, 'push {fp, lr}'), (6209172, 'invalid')],
        calls=[(6208636, 'bl loc.imp.objc_msgSend'), (6208672, 'bl loc.imp.objc_msgSend'), (6208768, 'bl loc.imp.objc_msgSend'), (6208812, 'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_'), (6208872, 'bl loc.imp.objc_msgSend'), (6208916, 'bl sym.reloadDrawBlockDynamicObjectItemQuadsForTile_intpair__MacroTile__World_'), (6208976, 'bl loc.imp.objc_msgSend'), (6209020, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (6209080, 'bl loc.imp.objc_msgSend'), (6209124, 'bl sym.reloadDrawBlockDodoEggQuadsForTile_intpair__MacroTile__World_')],
        branches=[],
        semantics=('[TradingPost -[contentsDidChange]] (imp 0x005ebbe4, 173w): -[contentsDidChange] (0x5ebbe4, 173w): DynamicObject.updateNeedsToBeSent@49=1; inventoryNeedsToBeSentWithUpdate@125=1; SEND [self objectType] then [self.dynamicWorld dynamicWorldChangedAtPos:self.pos objectType:type]; needsToUpdateBitmapString@124=1; then the 4 static-geometry reloads for self.pos with [world macroTiles]: reloadDrawBlockDynamicObjectStaticGeometryForTile / ItemQuadsForTile / QuadsForTile / DodoEggQuadsForTile (0x5ebd2c/0x5ebd94/0x5ebdfc/0x5ebe64). No proxyObjectOwner check (unlike Chest ce_07)..\n'),
    ),
    dict(
        name='tp_09',
        method='TradingPost -[creationNetDataForClient:]',
        types='@12@0:4@8',
        start=6187320,
        end=6187436,
        disasm='disasm_worldtileloader_tp_09.txt',
        base_add=6187336,
        base_literal=6187432,
        boundary='ARM.exidx end 0x005e69ac (listing bound); next ObjC IMP 0x005e69ac TradingPost -[dealloc]',
        selectors={
                 0x5e69a0: (15198556, 'updateNetDataForClient:'),
        },
        imports={
                 0x5e699c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5e69a4: (17156792, 'OBJC_IVAR_$_TradingPost.inventoryNeedsToBeSentWithUpdate', 125),
        },
        classes={},
        instructions=[(6187320, 'push {r4, r5, fp, lr}'), (6187432, 'adceq sb, r7, r4, lsr 3')],
        calls=[(6187408, 'blx ip')],
        branches=[],
        semantics=('[TradingPost -[creationNetDataForClient:]] (imp 0x005e6938, 29w): -[creationNetDataForClient:] (0x5e6938, 29w): sets inventoryNeedsToBeSentWithUpdate@125 = 1 then tail-calls [self updateNetDataForClient:data]; the return is that call\'s NSData blob..\n'),
    ),
    dict(
        name='tp_10',
        method='TradingPost -[currentBlockheadCash]',
        types='i8@0:4',
        start=6218120,
        end=6218296,
        disasm='disasm_worldtileloader_tp_10.txt',
        base_add=6218136,
        base_literal=6218292,
        boundary='ARM.exidx end 0x005ee238 (listing bound); next ObjC IMP 0x005ee238 TradingPost -[buyButtonTappedWithQuantity:]',
        selectors={
                 0x5ee230: (15198724, 'totalCash'),
        },
        imports={
                 0x5ee22c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5ee228: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
        },
        classes={},
        instructions=[(6218120, 'push {fp, lr}'), (6218292, 'adceq r1, r7, r4, asr sb')],
        calls=[(6218260, 'blx r2')],
        branches=[(6218184, 'bne', 6218200), (6218196, 'b', 6218268)],
        semantics=('[TradingPost -[currentBlockheadCash]] (imp 0x005ee188, 44w): -[currentBlockheadCash] (0x5ee188, 44w): if InteractionObject.currentBlockhead@56 == nil -> 0; else returns [currentBlockhead totalCash] (cash the interacting player has to spend)..\n'),
    ),
    dict(
        name='tp_11',
        method='TradingPost -[dealloc]',
        types='v8@0:4',
        start=6187436,
        end=6187784,
        disasm='disasm_worldtileloader_tp_11.txt',
        base_add=6187452,
        base_literal=6187780,
        boundary='ARM.exidx end 0x005e6b08 (listing bound); next ObjC IMP 0x005e6b08 TradingPost -[getSaveDict]',
        selectors={
                 0x5e6ae8: (15198564, 'dealloc'),
                 0x5e6af8: (15198560, 'release'),
        },
        imports={
                 0x5e6ae4: (17151900, 'objc_msgSendSuper2'),
                 0x5e6af4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5e6af0: (17156796, 'OBJC_IVAR_$_TradingPost.bitmapString', 120),
                 0x5e6afc: (17156760, 'OBJC_IVAR_$_TradingPost.sellSlot', 100),
                 0x5e6b00: (17156768, 'OBJC_IVAR_$_TradingPost.sellerClientName', 112),
        },
        classes={
                 0x5e6aec: (15252580, 'OBJC_CLASS_$_TradingPost'),
        },
        instructions=[(6187436, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6187780, 'adceq sb, r7, r0, lsr r1')],
        calls=[(6187600, 'blx r7'), (6187636, 'blx r3'), (6187672, 'blx r3'), (6187736, 'blx ip')],
        branches=[],
        semantics=('[TradingPost -[dealloc]] (imp 0x005e69ac, 87w): -[dealloc] (0x5e69ac, 87w): MRR teardown - releases sellerClientName@112, sellSlot@100 and bitmapString@120 and nils bitmapString, then objc_msgSendSuper2 -dealloc with class ref TradingPost (0x5e6aec). usageShader@116 is deliberately NOT released (cache/shader-owned)..\n'),
    ),
    dict(
        name='tp_12',
        method='TradingPost -[destroyItemType]',
        types='i8@0:4',
        start=6216428,
        end=6216456,
        disasm='disasm_worldtileloader_tp_12.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x005edb38; body trimmed at the next IMP 0x005edb08 TradingPost -[title]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6216428, 'sub sp, sp, 8'), (6216452, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TradingPost -[destroyItemType]] (imp 0x005edaec, 7w): -[destroyItemType] (0x5edaec, 7w, listing TRIMMED at the next IMP): returns the constant 0xa8 = 168 - the item type the post swallows into (matches freeblockCreationItemType tp_17; the free block created by remove:/buy paths uses ofType 0xa8)..\n'),
    ),
    dict(
        name='tp_13',
        method='TradingPost -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        types='v156@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76i140i144i148i152',
        start=6190920,
        end=6199364,
        disasm='disasm_worldtileloader_tp_13.txt',
        base_add=6190948,
        base_literal=6193572,
        boundary='ARM.exidx end 0x005e9844 (listing bound); next ObjC IMP 0x005ea85c TradingPost -[moveInventoryItemsToSellSlotFromArray:count:]',
        selectors={
                 0x5e81b0: (15198472, 'updateBitmapString'),
                 0x5e81c0: (15198580, 'worldWidthMacro'),
                 0x5e81f4: (15198584, 'dayColor'),
                 0x5e820c: (15198588, 'program'),
                 0x5e8210: (15198592, 'uniformLocations'),
                 0x5e8214: (15198596, 'objectAtIndex:'),
                 0x5e8218: (15198600, 'intValue'),
                 0x5e8b60: (15198604, 'setColor:'),
                 0x5e9804: (15198588, 'program'),
                 0x5e9808: (15198592, 'uniformLocations'),
                 0x5e980c: (15198596, 'objectAtIndex:'),
                 0x5e9810: (15198600, 'intValue'),
                 0x5e9814: (15198608, 'renderWithProjectionMatrix:modelViewMatrix:'),
                 0x5e9818: (15198440, 'itemType'),
                 0x5e981c: (15198612, 'lastObject'),
                 0x5e9824: (15198616, 'dataA'),
        },
        imports={
                 0x5e81ac: (17151904, 'objc_msgSend'),
                 0x5e9800: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5e81a8: (17156764, 'OBJC_IVAR_$_TradingPost.needsToUpdateBitmapString', 124),
                 0x5e81b4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x5e81bc: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x5e81e0: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x5e8204: (17156776, 'OBJC_IVAR_$_InteractionObject.shader', 60),
                 0x5e821c: (17156796, 'OBJC_IVAR_$_TradingPost.bitmapString', 120),
                 0x5e9820: (17156760, 'OBJC_IVAR_$_TradingPost.sellSlot', 100),
                 0x5e9838: (17156772, 'OBJC_IVAR_$_TradingPost.usageShader', 116),
        },
        classes={},
        instructions=[(6190920, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6199360, 'strmi r0, [r0], r0')],
        calls=[(6191584, 'blx r2'), (6191680, 'bl loc.imp.objc_msgSend'), (6191704, 'bl sym.imp.__aeabi_idiv'), (6191772, 'bl loc.imp.objc_msgSend'), (6191892, 'bl loc.imp.objc_msgSend'), (6191908, 'bl sym.imp.__aeabi_idiv'), (6191976, 'bl loc.imp.objc_msgSend'), (6192100, 'bl loc.imp.objc_msgSend'), (6192124, 'bl sym.imp.__aeabi_idiv'), (6192192, 'bl loc.imp.objc_msgSend'), (6192312, 'bl loc.imp.objc_msgSend'), (6192328, 'bl sym.imp.__aeabi_idiv'), (6192396, 'bl loc.imp.objc_msgSend'), (6192660, 'bl method.Vector2.operator_float__'), (6192720, 'bl loc.imp.objc_msgSend'), (6192744, 'bl sym.imp.__aeabi_idiv'), (6192832, 'bl loc.imp.objc_msgSend'), (6192864, 'bl method.Vector2.operator_float__'), (6192912, 'bl method.Vector2.operator_float__'), (6192976, 'bl loc.imp.objc_msgSend'), (6192992, 'bl sym.imp.__aeabi_idiv'), (6193080, 'bl loc.imp.objc_msgSend'), (6193112, 'bl method.Vector2.operator_float__'), (6193208, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6193312, 'bl loc.imp.objc_msgSend_stret'), (6193352, 'bl sym.imp.memset'), (6193912, 'bl method.Vector.Vector_float__float__float_'), (6193920, 'bl method.Vector.operator_float__'), (6193976, 'bl method.Vector.operator_float__'), (6194008, 'bl method.Vector.operator_float__'), (6194052, 'bl method.Vector.operator_float__'), (6194084, 'bl method.Vector.operator_float__'), (6194128, 'bl method.Vector.operator_float__'), (6194184, 'bl method.Vector.Vector_float__float__float_'), (6194236, 'bl loc.imp.objc_msgSend'), (6194240, 'bl sym.imp.__wrap_glUseProgram'), (6194276, 'bl loc.imp.objc_msgSend'), (6194312, 'bl loc.imp.objc_msgSend'), (6194336, 'bl loc.imp.objc_msgSend'), (6194344, 'bl sym.imp.__wrap_glUniform1i'), (6194376, 'bl loc.imp.objc_msgSend'), (6194404, 'bl loc.imp.objc_msgSend'), (6194420, 'bl loc.imp.objc_msgSend'), (6194436, 'bl method.Vector.operator_float__'), (6194452, 'bl method.Vector.operator_float__'), (6194468, 'bl method.Vector.operator_float__'), (6194500, 'bl sym.imp.__wrap_glUniform4f'), (6194508, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (6194516, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (6194656, 'bl method.Vector2.operator_float__'), (6194672, 'bl method.Vector2.operator_float__'), (6194896, 'bl 0x5e9844'), (6194904, 'bl sym.imp.__wrap_glEnable'), (6194916, 'bl sym.pushDepthMaskState'), (6195016, 'bl method.Vector.operator_float__'), (6195048, 'bl method.Vector.operator_float__'), (6195080, 'bl method.Vector.operator_float__'), (6195160, 'bl 0x5e9a2c'), (6195208, 'bl loc.imp.objc_msgSend'), (6195564, 'bl 0x5e9844'), (6196032, 'bl 0x5e9a78'), (6196932, 'bl loc.imp.objc_msgSend'), (6196940, 'bl sym.imp.__wrap_glDisable'), (6197036, 'blx lr'), (6197060, 'blx r2'), (6197120, 'bl sym.usageIncrementPerUse_ItemType__int__signed_char__signed_char_'), (6197164, 'bl sym.clothingItemPasivelyUsedRate_ItemType__int__int__signed_char_'), (6197224, 'blx r2'), (6197376, 'bl method.Vector2.operator_float__'), (6197400, 'bl method.Vector2.operator_float__'), (6197624, 'bl 0x5e9844'), (6198324, 'bl 0x5ea29c'), (6198388, 'blx r2'), (6198392, 'bl sym.imp.__wrap_glUseProgram'), (6198532, 'blx r3'), (6198552, 'blx r3'), (6198568, 'blx r2'), (6198600, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (6198740, 'blx r6'), (6198760, 'blx r3'), (6198776, 'blx r2'), (6198808, 'bl sym.imp.__wrap_glUniform4f'), (6198920, 'blx r3'), (6199012, 'bl sym.drawShaderQuadNoTexture'), (6199152, 'blx r6'), (6199172, 'blx r3'), (6199188, 'blx r2'), (6199220, 'bl sym.imp.__wrap_glUniform4f'), (6199280, 'bl sym.drawShaderQuadNoTexture'), (6199284, 'bl sym.popDepthMaskState')],
        branches=[(6191540, 'beq', 6191588), (6191716, 'blt', 6191804), (6191800, 'b', 6192008), (6191920, 'bge', 6192004), (6192004, 'b', 6192008), (6192136, 'blt', 6192224), (6192220, 'b', 6192428), (6192340, 'bge', 6192424), (6192424, 'b', 6192428), (6192464, 'blt', 6192588), (6192504, 'bgt', 6192588), (6192544, 'blt', 6192588), (6192584, 'ble', 6192592), (6192588, 'b', 6199288), (6192768, 'ble', 6192888), (6192884, 'b', 6193136), (6193016, 'bpl', 6193132), (6193132, 'b', 6193136), (6193228, 'bne', 6193236), (6193232, 'b', 6199288), (6193292, 'beq', 6193320), (6193316, 'b', 6193356), (6193476, 'bpl', 6193496), (6193492, 'b', 6193508), (6193552, 'bpl', 6193700), (6193568, 'b', 6193712), (6193756, 'ble', 6193828), (6194956, 'beq', 6196936), (6196036, 'b', 6196068), (6197080, 'beq', 6199284), (6197128, 'bgt', 6197184), (6197180, 'ble', 6199284), (6197236, 'ble', 6199284), (6198416, 'b', 6198424)],
        semantics=('[TradingPost -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]] (imp 0x005e7748, 2111w): [census] -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:] (0x5e7748, 2111w, 90 call rows / 28 targets; void). O0 spill of (float, 2x GLKMatrix4, 4 camera ints) into a 0x8c0-byte frame. (1) lazy refresh: if needsToUpdateBitmapString@124 -> [self updateBitmapString] (0x5e799c-0x5e79e4). (2) camera->macro clamp math with __aeabi_idiv x6 over [world worldWidthMacro] (+ tileAtWorldPositionLoaded probe @0x5e8038, objc_msgSend_stret + memset for a struct at 0x5e80a0/0x5e80c8). (3) main pass with self.shader@60: [shader program] -> glUseProgram (0x5e8440); [shader uniformLocations] objectAtIndex:intValue -> glUniform1i (0x5e84a8); [world dayColor] read into floats -> glUniform4f (x3: 0x5e8544, 0x5e9618, 0x5e97b4); glEnableVertexAttribArray x2; geometry built with local 16-arg transform helper 0x5e9844 (x3: 0x5e86d0, 0x5e896c, 0x5e9178; vmul/vadd float math writing matrix columns) and Vector4 stores 0x5e9a2c; [shader setColor:] (0x5e87dc); glEnable + pushDepthMaskState (0x5e86d8/0x5e86e4). (4) bitmapString: if bitmapString@120 -> [bitmapString renderWithProjectionMatrix:modelViewMatrix:] (0x5e8cf4) under the depth mask; glDisable(0xbe2 = GL_BLEND) @0x5e8ecc. (5) usage overlay with self.usageShader@116 (the \'ColoredNoTexture\' shader built in tp_18) - gated by: last=[sellSlot lastObject], [last itemType]!=0xb, rate=usageIncrementPerUse(ItemType,0,2,0) (real symbol @0x5e9c30; 0x5e8f80) or clothingItemPasivelyUsedRate(ItemType,0,2,0) (@0x5e9fa4; 0x5e8fac) if rate<=0, and [last dataA] > 0 (0x5e8ff0); then [usageShader program] -> glUseProgram (0x5e9478), glUniformMatrix4fv (0x5e9548) + glUniform4f, drawShaderQuadNoTexture x2 (0x5e96e4, 0x5e97f0). (6) popDepthMaskState (0x5e97f4)..\n'),
    ),
    dict(
        name='tp_14',
        method='TradingPost -[freeBlockCreationDataA]',
        types='S8@0:4',
        start=6215532,
        end=6215560,
        disasm='disasm_worldtileloader_tp_14.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x005ed7a4; body trimmed at the next IMP 0x005ed788 TradingPost -[freeBlockCreationDataB]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6215532, 'sub sp, sp, 8'), (6215556, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TradingPost -[freeBlockCreationDataA]] (imp 0x005ed76c, 7w): -[freeBlockCreationDataA] (0x5ed76c, 7w, listing TRIMMED at the next IMP): returns 0 - the post contributes no dataA to its free-block creation record..\n'),
    ),
    dict(
        name='tp_15',
        method='TradingPost -[freeBlockCreationDataB]',
        types='S8@0:4',
        start=6215560,
        end=6215588,
        disasm='disasm_worldtileloader_tp_15.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x005ed7a4 (listing bound); next ObjC IMP 0x005ed7a4 TradingPost -[remove:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6215560, 'sub sp, sp, 8'), (6215584, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TradingPost -[freeBlockCreationDataB]] (imp 0x005ed788, 7w): -[freeBlockCreationDataB] (0x5ed788, 7w): returns 0 - twin of freeBlockCreationDataA; no dataB either..\n'),
    ),
    dict(
        name='tp_16',
        method='TradingPost -[freeBlockCreationSaveDict]',
        types='@8@0:4',
        start=6215456,
        end=6215532,
        disasm='disasm_worldtileloader_tp_16.txt',
        base_add=6215472,
        base_literal=6215528,
        boundary='ARM.exidx end 0x005ed76c (listing bound); next ObjC IMP 0x005ed76c TradingPost -[freeBlockCreationDataA]',
        selectors={
                 0x5ed764: (15198568, 'getSaveDict'),
        },
        imports={
                 0x5ed760: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(6215456, 'push {fp, lr}'), (6215528, 'invalid')],
        calls=[(6215508, 'blx r3')],
        branches=[],
        semantics=('[TradingPost -[freeBlockCreationSaveDict]] (imp 0x005ed720, 19w): -[freeBlockCreationSaveDict] (0x5ed720, 19w): tail-calls [self getSaveDict] (sel cell 0x5ed764) and returns its result; no extra keys added here..\n'),
    ),
    dict(
        name='tp_17',
        method='TradingPost -[freeblockCreationItemType]',
        types='i8@0:4',
        start=6215428,
        end=6215456,
        disasm='disasm_worldtileloader_tp_17.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x005ed720 (listing bound); next ObjC IMP 0x005ed720 TradingPost -[freeBlockCreationSaveDict]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6215428, 'sub sp, sp, 8'), (6215452, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TradingPost -[freeblockCreationItemType]] (imp 0x005ed704, 7w): -[freeblockCreationItemType] (0x5ed704, 7w): returns 0xa8 = 168 (same constant as destroyItemType) - the free block the post turns into when removed/bought out..\n'),
    ),
    dict(
        name='tp_18',
        method='TradingPost -[initSubDerivedItems]',
        types='v8@0:4',
        start=6180064,
        end=6181564,
        disasm='disasm_worldtileloader_tp_18.txt',
        base_add=6180080,
        base_literal=6181560,
        boundary='ARM.exidx end 0x005e52bc (listing bound); next ObjC IMP 0x005e52bc TradingPost -[initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:]',
        selectors={
                 0x5e525c: (15198452, 'shaderNamed:attributes:uniforms:'),
                 0x5e5268: (15198448, 'arrayWithObjects:'),
                 0x5e528c: (15198464, 'retain'),
                 0x5e5294: (15198424, 'objectForKey:'),
                 0x5e5298: (15198460, 'playerInfoForPeerID:'),
                 0x5e52a0: (15198456, 'server'),
                 0x5e52a8: (15198472, 'updateBitmapString'),
                 0x5e52b4: (15198468, 'macroTiles'),
        },
        imports={
                 0x5e5254: (16244840, '__CFConstantStringClassReference'),
                 0x5e5258: (17151904, 'objc_msgSend'),
                 0x5e5260: (16244792, '__CFConstantStringClassReference'),
                 0x5e5264: (16244856, '__CFConstantStringClassReference'),
                 0x5e5270: (16244760, '__CFConstantStringClassReference'),
                 0x5e527c: (16244744, '__CFConstantStringClassReference'),
                 0x5e5280: (16244808, '__CFConstantStringClassReference'),
                 0x5e5284: (16244824, '__CFConstantStringClassReference'),
                 0x5e5288: (16244776, '__CFConstantStringClassReference'),
                 0x5e5290: (16244872, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5e524c: (17156768, 'OBJC_IVAR_$_TradingPost.sellerClientName', 112),
                 0x5e5250: (17156772, 'OBJC_IVAR_$_TradingPost.usageShader', 116),
                 0x5e5274: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0x5e5278: (17156776, 'OBJC_IVAR_$_InteractionObject.shader', 60),
                 0x5e529c: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
                 0x5e52a4: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x5e52ac: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={
                 0x5e526c: (15245556, 'OBJC_CLASS_$_NSArray'),
        },
        instructions=[(6180064, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6181560, 'invalid')],
        calls=[(6180380, 'blx r5'), (6180436, 'blx r4'), (6180480, 'blx lr'), (6180560, 'blx ip'), (6180608, 'blx lr'), (6180652, 'blx lr'), (6180856, 'blx r2'), (6180892, 'blx r3'), (6180912, 'blx r3'), (6180928, 'blx r2'), (6181040, 'bl loc.imp.objc_msgSend'), (6181084, 'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_'), (6181144, 'bl loc.imp.objc_msgSend'), (6181188, 'bl sym.reloadDrawBlockDynamicObjectItemQuadsForTile_intpair__MacroTile__World_'), (6181248, 'bl loc.imp.objc_msgSend'), (6181292, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (6181352, 'bl loc.imp.objc_msgSend'), (6181396, 'bl sym.reloadDrawBlockDodoEggQuadsForTile_intpair__MacroTile__World_'), (6181440, 'blx r2')],
        branches=[(6180704, 'bne', 6180952)],
        semantics=('[TradingPost -[initSubDerivedItems]] (imp 0x005e4ce0, 375w): -[initSubDerivedItems] (0x5e4ce0, 375w): builds the two shaders and refreshes the sign text. shader@60 = [self.cache@32 shaderNamed:@"WorldObject" attributes:[NSArray arrayWithObjects:@"position",@"texCoord",nil] uniforms:[... @"mvp_matrix",@"texture",@"light",nil]] (CFSTRs at 0x5e5254/0x5e5260/0x5e5264/0x5e5270/0x5e527c/0x5e5280/0x5e5284/0x5e5288); usageShader@116 = [self.cache shaderNamed:@"ColoredNoTexture" attributes:[NSArray arrayWithObjects:@"position",nil] uniforms:[... @"mvp_matrix",@"color",nil]]. If sellerClientName@112 != nil it is re-derived as [[[self.world server] playerInfoForPeerID:self.ownerID@36] objectForKey:@"alias"] retain (CFSTRs \'alias\' 0x5e5290, \'server\' 0x5e52a0). Then the 4 reload calls for self.pos + [self updateBitmapString] (0x5e5240)..\n'),
    ),
    dict(
        name='tp_19',
        method='TradingPost -[initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:]',
        types='@48@0:4@8@12{?=ii}16@24@28c32@36@40@44',
        start=6181564,
        end=6182680,
        disasm='disasm_worldtileloader_tp_19.txt',
        base_add=6181580,
        base_literal=6182676,
        boundary='ARM.exidx end 0x005e5718 (listing bound); next ObjC IMP 0x005e5718 TradingPost -[initWithWorld:dynamicWorld:saveDict:cache:]',
        selectors={
                 0x5e56d8: (15198476, 'initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:'),
                 0x5e56e4: (15198484, 'integerValue'),
                 0x5e56ec: (15198424, 'objectForKey:'),
                 0x5e56f8: (15198480, 'initSlotsWithSaveDict:'),
                 0x5e5700: (15198464, 'retain'),
                 0x5e5710: (15198488, 'initSubDerivedItems'),
        },
        imports={
                 0x5e56e0: (17151904, 'objc_msgSend'),
                 0x5e56e8: (16244904, '__CFConstantStringClassReference'),
                 0x5e56f4: (16244888, '__CFConstantStringClassReference'),
                 0x5e5704: (16244920, '__CFConstantStringClassReference'),
                 0x5e570c: (16244936, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5e56dc: (17156780, 'OBJC_IVAR_$_TradingPost.priceTier', 108),
                 0x5e56f0: (17156784, 'OBJC_IVAR_$_TradingPost.coinCount', 104),
                 0x5e56fc: (17156768, 'OBJC_IVAR_$_TradingPost.sellerClientName', 112),
                 0x5e5708: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
        },
        classes={
                 0x5e56d0: (15252580, 'OBJC_CLASS_$_TradingPost'),
        },
        instructions=[(6181564, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6182676, 'adceq sl, r7, r0, lsr 16')],
        calls=[(6181856, 'bl loc.imp.objc_msgSendSuper2'), (6182044, 'blx r3'), (6182068, 'blx r3'), (6182084, 'blx r2'), (6182128, 'blx r3'), (6182144, 'blx r2'), (6182228, 'blx r2'), (6182340, 'blx lr'), (6182356, 'blx r2'), (6182504, 'blx lr'), (6182520, 'blx r2'), (6182584, 'blx r2')],
        branches=[(6181884, 'bne', 6181900), (6181896, 'b', 6182596), (6182180, 'beq', 6182256), (6182252, 'b', 6182380), (6182416, 'bne', 6182544)],
        semantics=('[TradingPost -[initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:]] (imp 0x005e52bc, 279w): -[initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:] (0x5e52bc, 279w): full 9-arg passthrough to objc_msgSendSuper2 (struct {self, class TradingPost}) - it re-stacks world/dynamicWorld/pos{int,int}/cache/item/flipped(char)/saveDict/placedByClient/clientName and returns nil if super returns nil. Then [self initSlotsWithSaveDict:saveDict]; coinCount@104 = [[saveDict objectForKey:@"coinCount"] integerValue] (CFSTR 0x5e56f4); priceTier@108 = [[saveDict objectForKey:@"priceTier"] integerValue] (CFSTR 0x5e56e8); if clientName==nil -> sellerClientName@112 = [[saveDict objectForKey:@"sellerClientName"] retain] (CFSTR 0x5e5704) else sellerClientName = [clientName retain]; if ownerID@36==nil -> ownerID = [[saveDict objectForKey:@"sellerClientID"] retain] (CFSTR 0x5e570c); [self initSubDerivedItems]; return self..\n'),
    ),
    dict(
        name='tp_20',
        method='TradingPost -[initWithWorld:dynamicWorld:cache:netData:]',
        types='@24@0:4@8@12@16@20',
        start=6183572,
        end=6185124,
        disasm='disasm_worldtileloader_tp_20.txt',
        base_add=6183588,
        base_literal=6185120,
        boundary='ARM.exidx end 0x005e60a4 (listing bound); next ObjC IMP 0x005e60c8 TradingPost -[updateNetDataForClient:]',
        selectors={
                 0x5e6040: (15198496, 'initWithWorld:dynamicWorld:cache:netData:'),
                 0x5e604c: (15198428, 'countByEnumeratingWithState:objects:count:'),
                 0x5e6050: (15198516, 'blockheads'),
                 0x5e6060: (15198480, 'initSlotsWithSaveDict:'),
                 0x5e6068: (15198464, 'retain'),
                 0x5e6070: (15198424, 'objectForKey:'),
                 0x5e6084: (15198512, 'gzipInflate'),
                 0x5e6088: (15198500, 'getBytes:length:'),
                 0x5e6090: (15198504, 'length'),
                 0x5e6094: (15198508, 'subdataWithRange:'),
                 0x5e6098: (15198520, 'netInteractionObjectWasLoaded:'),
                 0x5e609c: (15198488, 'initSubDerivedItems'),
        },
        imports={
                 0x5e603c: (17151900, 'objc_msgSendSuper2'),
                 0x5e6048: (17151904, 'objc_msgSend'),
                 0x5e606c: (16244920, '__CFConstantStringClassReference'),
                 0x5e6078: (16244968, '__CFConstantStringClassReference'),
                 0x5e6080: (16244952, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5e6054: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x5e6058: (17156780, 'OBJC_IVAR_$_TradingPost.priceTier', 108),
                 0x5e605c: (17156784, 'OBJC_IVAR_$_TradingPost.coinCount', 104),
                 0x5e6064: (17156768, 'OBJC_IVAR_$_TradingPost.sellerClientName', 112),
                 0x5e6074: (17156788, 'OBJC_IVAR_$_InteractionObject.ownerName', 84),
                 0x5e607c: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
        },
        classes={
                 0x5e6044: (15252580, 'OBJC_CLASS_$_TradingPost'),
        },
        instructions=[(6183572, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6185120, 'adceq sl, r7, r8, asr 32')],
        calls=[(6183724, 'blx r6'), (6183844, 'bl loc.imp.objc_msgSend'), (6183868, 'bl loc.imp.objc_msgSend'), (6183936, 'bl loc.imp.objc_msgSend'), (6183960, 'blx r2'), (6183964, 'bl 0x5e60a4'), (6184312, 'blx ip'), (6184328, 'blx r2'), (6184372, 'blx r3'), (6184388, 'blx r2'), (6184432, 'blx r3'), (6184448, 'blx r2'), (6184492, 'blx r3'), (6184576, 'blx lr'), (6184600, 'bl sym.imp.memset'), (6184648, 'blx lr'), (6184748, 'bl sym.imp.objc_enumerationMutation'), (6184828, 'blx ip'), (6184928, 'blx ip'), (6184996, 'blx r2')],
        branches=[(6183752, 'bne', 6183768), (6183764, 'b', 6185008), (6184660, 'beq', 6184952), (6184740, 'beq', 6184752), (6184856, 'blo', 6184704), (6184948, 'bne', 6184704), (6184952, 'b', 6184956)],
        semantics=('[TradingPost -[initWithWorld:dynamicWorld:cache:netData:]] (imp 0x005e5a94, 388w): -[initWithWorld:dynamicWorld:cache:netData:] (0x5e5a94, 388w): super init passthrough (objc_msgSendSuper2, class TradingPost); nil -> nil. Parses the net record: [netData getBytes:buf length:0x30]; coinCount@104 = buf+0x28; priceTier@108 = (u16)buf+0x2c; dict = plistFromData([[netData subdataWithRange:{0x30, len-0x30}] gzipInflate]) (local helper 0x5e60a4); ownerID = [[dict objectForKey:@"ownerID"] retain]; ownerName@84 = [[dict objectForKey:@"ownerName"] retain]; sellerClientName@112 = [[dict objectForKey:@"sellerClientName"] retain]; [self initSlotsWithSaveDict:dict]; then for each bh in [self.dynamicWorld blockheads] -> [bh netInteractionObjectWasLoaded:self] (0x5e5f3c-0x5e5f7c); finally [self initSubDerivedItems] (which itself calls updateBitmapString) and returns self..\n'),
    ),
    dict(
        name='tp_21',
        method='TradingPost -[interactionObjectType]',
        types='S8@0:4',
        start=6189092,
        end=6189120,
        disasm='disasm_worldtileloader_tp_21.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x005e7040 (listing bound); next ObjC IMP 0x005e7040 TradingPost -[remoteUpdate:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6189092, 'sub sp, sp, 8'), (6189116, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TradingPost -[interactionObjectType]] (imp 0x005e7024, 7w): -[interactionObjectType] (0x5e7024, 7w): returns 5 (the InteractionObject type slot for the trading post)..\n'),
    ),
    dict(
        name='tp_22',
        method='TradingPost -[interactionRenderItemType]',
        types='i8@0:4',
        start=6236212,
        end=6236240,
        disasm='disasm_worldtileloader_tp_22.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x005f2850 (listing bound); next ObjC IMP 0x005f2850 TradingPost -[paint:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6236212, 'sub sp, sp, 8'), (6236236, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TradingPost -[interactionRenderItemType]] (imp 0x005f2834, 7w): -[interactionRenderItemType] (0x5f2834, 7w): returns 0xa7 = 167 (item rendered for the post in inventories/hand)..\n'),
    ),
    dict(
        name='tp_23',
        method='TradingPost -[isPaintable]',
        types='c8@0:4',
        start=6236564,
        end=6236592,
        disasm='disasm_worldtileloader_tp_23.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x005f29cc; body trimmed at the next IMP 0x005f29b0 TradingPost -[occupiesNormalContents]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6236564, 'sub sp, sp, 8'), (6236588, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TradingPost -[isPaintable]] (imp 0x005f2994, 7w): -[isPaintable] (0x5f2994, 7w, listing TRIMMED at the next IMP): returns YES (1) - the post accepts paint colors..\n'),
    ),
    dict(
        name='tp_24',
        method='TradingPost -[moveInventoryItemsToSellSlotFromArray:count:]',
        types='i16@0:4@8i12',
        start=6203484,
        end=6208484,
        disasm='disasm_worldtileloader_tp_24.txt',
        base_add=6203504,
        base_literal=6206564,
        boundary='ARM.exidx end 0x005ebbe4 (listing bound); next ObjC IMP 0x005ebbe4 TradingPost -[contentsDidChange]',
        selectors={
                 0x5eb46c: (15198620, 'count'),
                 0x5eb470: (15198440, 'itemType'),
                 0x5eb474: (15198596, 'objectAtIndex:'),
                 0x5eb47c: (15198624, 'dataB'),
                 0x5ebb7c: (15198620, 'count'),
                 0x5ebb80: (15198440, 'itemType'),
                 0x5ebb84: (15198596, 'objectAtIndex:'),
                 0x5ebb8c: (15198624, 'dataB'),
                 0x5ebb90: (15198648, 'contentsDidChange'),
                 0x5ebb94: (15198428, 'countByEnumeratingWithState:objects:count:'),
                 0x5ebb98: (15198632, 'subItems'),
                 0x5ebba8: (15198616, 'dataA'),
                 0x5ebbac: (15198628, 'dynamicObjectSaveDict'),
                 0x5ebbb4: (15198636, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
                 0x5ebbb8: (15198436, 'autorelease'),
                 0x5ebbbc: (15198640, 'initWithType:dataA:dataB:subItems:dynamicObjectSaveDict:'),
                 0x5ebbc0: (15198416, 'alloc'),
                 0x5ebbcc: (15198424, 'objectForKey:'),
                 0x5ebbd4: (15198644, 'removeObjectAtIndex:'),
                 0x5ebbd8: (15198444, 'addObject:'),
                 0x5ebbdc: (15198432, 'initWithSaveData:'),
        },
        imports={
                 0x5eb468: (17151904, 'objc_msgSend'),
                 0x5ebb78: (17151904, 'objc_msgSend'),
                 0x5ebbc8: (16245000, '__CFConstantStringClassReference'),
                 0x5ebbd0: (16244984, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5eb478: (17156760, 'OBJC_IVAR_$_TradingPost.sellSlot', 100),
                 0x5ebb88: (17156760, 'OBJC_IVAR_$_TradingPost.sellSlot', 100),
                 0x5ebb9c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x5ebba4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x5ebbb0: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
        },
        classes={
                 0x5ebbc4: (15245552, 'OBJC_CLASS_$_InventoryItem'),
        },
        instructions=[(6203484, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6208480, 'invalid')],
        calls=[(6203592, 'blx r2'), (6203712, 'blx r2'), (6203740, 'blx r3'), (6203756, 'blx r2'), (6203872, 'blx ip'), (6203888, 'blx r2'), (6204000, 'blx r6'), (6204016, 'blx r2'), (6204068, 'blx ip'), (6204084, 'blx r2'), (6204116, 'bl sym.itemTypeIsStackable_ItemType__unsigned_short__unsigned_short_'), (6204184, 'blx r2'), (6204240, 'blx r2'), (6204372, 'blx r2'), (6204492, 'blx lr'), (6204516, 'blx r2'), (6204572, 'blx r2'), (6204624, 'blx r2'), (6204688, 'blx r3'), (6204744, 'blx r2'), (6204796, 'blx r2'), (6204848, 'blx r2'), (6204912, 'blx r3'), (6204984, 'blx r2'), (6205064, 'blx ip'), (6205084, 'blx r3'), (6205156, 'blx ip'), (6205240, 'blx r2'), (6205368, 'blx r7'), (6205392, 'bl sym.imp.memset'), (6205440, 'blx lr'), (6205540, 'bl sym.imp.objc_enumerationMutation'), (6205668, 'blx ip'), (6205688, 'blx r3'), (6205704, 'blx r2'), (6205728, 'blx r2'), (6205820, 'bl loc.imp.objc_msgSend'), (6205852, 'bl loc.imp.objc_msgSend'), (6205884, 'bl loc.imp.objc_msgSend'), (6205916, 'bl loc.imp.objc_msgSend'), (6205948, 'bl loc.imp.objc_msgSend'), (6206072, 'bl loc.imp.objc_msgSend'), (6206176, 'blx ip'), (6206376, 'blx r2'), (6206408, 'blx r3'), (6206440, 'blx r3'), (6206472, 'blx r3'), (6206536, 'blx r4'), (6206552, 'blx r2'), (6206632, 'blx r2'), (6206740, 'blx r2'), (6206764, 'bl sym.imp.memset'), (6206812, 'blx lr'), (6206912, 'bl sym.imp.objc_enumerationMutation'), (6207024, 'bl sym.imp.memset'), (6207072, 'blx lr'), (6207172, 'bl sym.imp.objc_enumerationMutation'), (6207244, 'blx r2'), (6207336, 'bl loc.imp.objc_msgSend'), (6207368, 'bl loc.imp.objc_msgSend'), (6207400, 'bl loc.imp.objc_msgSend'), (6207432, 'bl loc.imp.objc_msgSend'), (6207464, 'bl loc.imp.objc_msgSend'), (6207588, 'bl loc.imp.objc_msgSend'), (6207692, 'blx ip'), (6207820, 'blx ip'), (6207992, 'blx r2'), (6208024, 'blx r3'), (6208056, 'blx r3'), (6208088, 'blx r3'), (6208152, 'blx r4'), (6208168, 'blx r2'), (6208268, 'blx ip'), (6208292, 'blx r3'), (6208352, 'blx r2')],
        branches=[(6203536, 'bne', 6203552), (6203548, 'b', 6208364), (6203600, 'bne', 6203616), (6203612, 'b', 6208364), (6203772, 'ble', 6204144), (6203900, 'bne', 6204132), (6204128, 'bne', 6204144), (6204140, 'b', 6208364), (6204196, 'bhs', 6204248), (6204292, 'bge', 6204308), (6204304, 'b', 6204316), (6204412, 'bge', 6208312), (6204528, 'beq', 6204860), (6204580, 'beq', 6204860), (6204632, 'beq', 6204860), (6204700, 'beq', 6204860), (6204752, 'beq', 6204860), (6204804, 'beq', 6204860), (6204856, 'bne', 6206592), (6204932, 'beq', 6206232), (6204992, 'bne', 6205096), (6205092, 'b', 6205164), (6205176, 'beq', 6206228), (6205252, 'bhs', 6206224), (6205452, 'beq', 6206200), (6205532, 'beq', 6205544), (6205736, 'beq', 6206076), (6206076, 'b', 6206080), (6206104, 'blo', 6205496), (6206196, 'bne', 6205496), (6206200, 'b', 6206204), (6206204, 'b', 6206208), (6206220, 'b', 6205192), (6206224, 'b', 6206228), (6206228, 'b', 6206232), (6206560, 'b', 6208180), (6206640, 'bne', 6208176), (6206824, 'beq', 6207844), (6206904, 'beq', 6206916), (6207084, 'beq', 6207716), (6207164, 'beq', 6207176), (6207252, 'beq', 6207592), (6207592, 'b', 6207596), (6207620, 'blo', 6207128), (6207712, 'bne', 6207128), (6207716, 'b', 6207720), (6207720, 'b', 6207724), (6207748, 'blo', 6206868), (6207840, 'bne', 6206868), (6207844, 'b', 6207848), (6208176, 'b', 6208180), (6208308, 'b', 6204400)],
        semantics=('[TradingPost -[moveInventoryItemsToSellSlotFromArray:count:]] (imp 0x005ea85c, 1250w): [census] -[moveInventoryItemsToSellSlotFromArray:count:] (0x5ea85c, 1250w, ~58 branches, 75 call rows; int return): moves up to count entries from the passed inventory array into sellSlot, merging stacks, and spills the leftovers into the world. Early-outs: count==0 -> 0 (0x5ea894); [array count]==0 -> 0 (0x5ea8d4). Merge scan: it0=[[array objectAtIndex:0] itemType]; if [sellSlot count]>0 scan sellSlot entries comparing itemType/dataA/dataB and gating on itemTypeIsStackable(it,dataA,dataB) (real symbol @0x5eaad4) with a 99 (0x63) cap compare (0x5eab58), excluding itemType 1043 (0x413, 0x5eac00) and 1065 (0x429, 0x5eacdc) from merging and special-casing itemType 12 (0xc, 0x5eb4ac) with a subItems fast-enumeration (0x5eb55c/0x5eb660). New entries: [[InventoryItem alloc] initWithType:dataA:dataB:subItems:dynamicObjectSaveDict:] (class ref OBJC_CLASS_$_InventoryItem; cells 0x5eb44x/0x5ebbdc) - with an initWithSaveData: variant used at 0x5eb0f8 - then [sellSlot addObject:] (0x5ebb0c) and [array removeObjectAtIndex:] (0x5ebb24) so the source shrinks. Spill path: for entries that do not go in, [[InventoryItem alloc] initWithSaveData:...] and if itemType != 0xb -> [self.dynamicWorld createFreeBlockAtPosition:self.pos ofType:itemType dataA:dataA dataB:dataB subItems:subItems dynamicObjectSaveDict:saveDict hovers:0 playSound:2 priorityBlockhead:self.currentBlockhead] (0x5eb278) - i.e. leftovers fall out as free blocks at the post. Loop head 0x5eabf0, exits when moved >= count (0x5eabfc bge 0x5ebb38) or the array drains; finishes with [self contentsDidChange] (0x5ebb60) and returns the moved count..\n'),
    ),
    dict(
        name='tp_25',
        method='TradingPost -[occupiesNormalContents]',
        types='c8@0:4',
        start=6236592,
        end=6236620,
        disasm='disasm_worldtileloader_tp_25.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x005f29cc (listing bound); next ObjC IMP 0x005f29cc TradingPost -[sellSlot]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6236592, 'sub sp, sp, 8'), (6236616, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TradingPost -[occupiesNormalContents]] (imp 0x005f29b0, 7w): -[occupiesNormalContents] (0x5f29b0, 7w): returns YES (1) - the post occupies the normal contents path (dynamic-object inventory semantics rather than an extended container)..\n'),
    ),
    dict(
        name='tp_26',
        method='TradingPost -[paint:]',
        types='v12@0:4S8',
        start=6236240,
        end=6236564,
        disasm='disasm_worldtileloader_tp_26.txt',
        base_add=6236256,
        base_literal=6236560,
        boundary='ARM.exidx end 0x005f2994 (listing bound); next ObjC IMP 0x005f2994 TradingPost -[isPaintable]',
        selectors={
                 0x5f2970: (15198472, 'updateBitmapString'),
                 0x5f2988: (15198652, 'objectType'),
                 0x5f298c: (15198656, 'dynamicWorldChangedAtPos:objectType:'),
        },
        imports={
                 0x5f296c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5f2968: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x5f2974: (17156800, 'OBJC_IVAR_$_InteractionObject.paintColor', 88),
                 0x5f2978: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0x5f2980: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x5f2984: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={},
        instructions=[(6236240, 'push {r4, r5, fp, lr}'), (6236560, 'adceq sp, r6, ip, lsl 5')],
        calls=[(6236336, 'blx lr'), (6236472, 'bl loc.imp.objc_msgSend'), (6236508, 'bl loc.imp.objc_msgSend')],
        branches=[(6236364, 'bne', 6236512)],
        semantics=('[TradingPost -[paint:]] (imp 0x005f2850, 81w): -[paint:] (0x5f2850, 81w): self.paintColor@88 = (u16)color (strh); [self updateBitmapString] (sign text color may flip to black); if !self.isNet@52: DynamicObject.updateNeedsToBeSent@49=1 and [self.dynamicWorld dynamicWorldChangedAtPos:self.pos objectType:[self objectType]]. Same shape as Sign sg_22..\n'),
    ),
    dict(
        name='tp_27',
        method='TradingPost -[price]',
        types='i8@0:4',
        start=6217288,
        end=6217396,
        disasm='disasm_worldtileloader_tp_27.txt',
        base_add=6217296,
        base_literal=6217392,
        boundary='ARM.exidx end 0x005edeb4 (listing bound); next ObjC IMP 0x005edeb4 TradingPost -[priceTier]',
        selectors={},
        imports={},
        ivars={
                 0x5edea8: (17156780, 'OBJC_IVAR_$_TradingPost.priceTier', 108),
        },
        classes={},
        instructions=[(6217288, 'sub sp, sp, 0x10'), (6217392, 'umlaleq r1, r7, ip, ip')],
        calls=[],
        branches=[],
        semantics=('[TradingPost -[price]] (imp 0x005ede48, 27w): -[price] (0x5ede48, 27w): returns the coin price of the current priceTier@108 from a static int table - table base = PIC base (0x0105faf4) + signed word at cell 0x5edea4 = 0xe13a90; entries 1,2,3,4,5,6,7,8,9,10,15,20,25,30,35,40,45,50,60,70,80,90,100,125,150,175,200,250,300,350,400,450,... (index = tier)..\n'),
    ),
    dict(
        name='tp_28',
        method='TradingPost -[priceTier]',
        types='i8@0:4',
        start=6217396,
        end=6217456,
        disasm='disasm_worldtileloader_tp_28.txt',
        base_add=6217404,
        base_literal=6217452,
        boundary='ARM.exidx end 0x005edef0 (listing bound); next ObjC IMP 0x005edef0 TradingPost -[setPriceTier:]',
        selectors={},
        imports={},
        ivars={
                 0x5edee8: (17156780, 'OBJC_IVAR_$_TradingPost.priceTier', 108),
        },
        classes={},
        instructions=[(6217396, 'sub sp, sp, 8'), (6217452, 'adceq r1, r7, r0, lsr ip')],
        calls=[],
        branches=[],
        semantics=('[TradingPost -[priceTier]] (imp 0x005edeb4, 15w): -[priceTier] (0x5edeb4, 15w): Apportable offset-cell getter for priceTier@108 (cell 0x5edeec -> descriptor -> ldr), plain int return..\n'),
    ),
    dict(
        name='tp_29',
        method='TradingPost -[remoteUpdate:]',
        types='v12@0:4@8',
        start=6189120,
        end=6190920,
        disasm='disasm_worldtileloader_tp_29.txt',
        base_add=6189136,
        base_literal=6190916,
        boundary='ARM.exidx end 0x005e7748 (listing bound); next ObjC IMP 0x005e7748 TradingPost -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        selectors={
                 0x5e76c8: (15198576, 'remoteUpdate:'),
                 0x5e76e0: (15198424, 'objectForKey:'),
                 0x5e76e8: (15198464, 'retain'),
                 0x5e76f0: (15198560, 'release'),
                 0x5e7704: (15198512, 'gzipInflate'),
                 0x5e7708: (15198500, 'getBytes:length:'),
                 0x5e7718: (15198504, 'length'),
                 0x5e771c: (15198508, 'subdataWithRange:'),
                 0x5e7724: (15198480, 'initSlotsWithSaveDict:'),
                 0x5e773c: (15198468, 'macroTiles'),
                 0x5e7740: (15198472, 'updateBitmapString'),
        },
        imports={
                 0x5e76c4: (17151900, 'objc_msgSendSuper2'),
                 0x5e76d8: (16244728, '__CFConstantStringClassReference'),
                 0x5e76dc: (17151904, 'objc_msgSend'),
                 0x5e76ec: (16244920, '__CFConstantStringClassReference'),
                 0x5e76f8: (16244968, '__CFConstantStringClassReference'),
                 0x5e7700: (16244952, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5e76d0: (17156800, 'OBJC_IVAR_$_InteractionObject.paintColor', 88),
                 0x5e76d4: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0x5e76e4: (17156768, 'OBJC_IVAR_$_TradingPost.sellerClientName', 112),
                 0x5e76f4: (17156788, 'OBJC_IVAR_$_InteractionObject.ownerName', 84),
                 0x5e76fc: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
                 0x5e7710: (17156784, 'OBJC_IVAR_$_TradingPost.coinCount', 104),
                 0x5e7714: (17156780, 'OBJC_IVAR_$_TradingPost.priceTier', 108),
                 0x5e7720: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x5e7728: (17156760, 'OBJC_IVAR_$_TradingPost.sellSlot', 100),
                 0x5e772c: (17156792, 'OBJC_IVAR_$_TradingPost.inventoryNeedsToBeSentWithUpdate', 125),
                 0x5e7730: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x5e7738: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={
                 0x5e76cc: (15252580, 'OBJC_CLASS_$_TradingPost'),
        },
        instructions=[(6189120, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6190916, 'umlaleq r8, r7, ip, sl')],
        calls=[(6189240, 'blx lr'), (6189360, 'bl loc.imp.objc_msgSend'), (6189432, 'bl loc.imp.objc_msgSend'), (6189500, 'bl loc.imp.objc_msgSend'), (6189524, 'blx r2'), (6189528, 'bl 0x5e60a4'), (6189744, 'blx ip'), (6189768, 'blx r3'), (6189784, 'blx r2'), (6189840, 'blx ip'), (6189864, 'blx r3'), (6189880, 'blx r2'), (6189936, 'blx ip'), (6189960, 'blx r3'), (6189976, 'blx r2'), (6190020, 'blx r3'), (6190132, 'blx r2'), (6190180, 'blx ip'), (6190336, 'bl loc.imp.objc_msgSend'), (6190380, 'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_'), (6190440, 'bl loc.imp.objc_msgSend'), (6190484, 'bl sym.reloadDrawBlockDynamicObjectItemQuadsForTile_intpair__MacroTile__World_'), (6190544, 'bl loc.imp.objc_msgSend'), (6190588, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (6190648, 'bl loc.imp.objc_msgSend'), (6190692, 'bl sym.reloadDrawBlockDodoEggQuadsForTile_intpair__MacroTile__World_'), (6190776, 'blx r2')],
        branches=[(6189280, 'bne', 6190696), (6190032, 'beq', 6190248), (6190208, 'bne', 6190244), (6190244, 'b', 6190248), (6190732, 'beq', 6190780)],
        semantics=('[TradingPost -[remoteUpdate:]] (imp 0x005e7040, 450w): -[remoteUpdate:] (0x5e7040, 450w): saves old paintColor@88 (ldrh), then [super remoteUpdate:data] via objc_msgSendSuper2 (class TradingPost). If currentBlockhead@56 != nil skip straight to the paint-change tail; else: [data getBytes:buf length:0x30]; coinCount@104=buf+0x28; priceTier@108=(u16)buf+0x2c; dict = plistFromData([[data subdataWithRange:{0x30, len-0x30}] gzipInflate]) (helper 0x5e60a4); release+reassign ownerID/ownerName@84/sellerClientName@112 from dict keys (retain each); if [dict objectForKey:@"sellSlot"] != nil -> [sellSlot release]; sellSlot=nil; [self initSlotsWithSaveDict:dict]; and if !isNet@52 set inventoryNeedsToBeSentWithUpdate@125=1. Then the 4 static-geometry reloads; tail (0x5e7668): if saved != paintColor@88 -> [self updateBitmapString]. Mirror of tp_20/tp_43 over the same 0x30-byte record..\n'),
    ),
    dict(
        name='tp_30',
        method='TradingPost -[remove:]',
        types='v12@0:4@8',
        start=6215588,
        end=6216428,
        disasm='disasm_worldtileloader_tp_30.txt',
        base_add=6215604,
        base_literal=6216424,
        boundary='ARM.exidx end 0x005edaec (listing bound); next ObjC IMP 0x005edaec TradingPost -[destroyItemType]',
        selectors={
                 0x5edab0: (15198684, 'isNet'),
                 0x5edac0: (15198688, 'stopInteracting'),
                 0x5edac4: (15198696, 'setNeedsRemoved:'),
                 0x5edac8: (15198692, 'removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:'),
                 0x5edadc: (15198568, 'getSaveDict'),
                 0x5edae0: (15198636, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
        },
        imports={
                 0x5edaac: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5edaa0: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0x5edaa4: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x5edaa8: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0x5edab4: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0x5edab8: (17156816, 'OBJC_IVAR_$_InteractionObject.remoteBlockheadInUseUniqueID', 72),
                 0x5edacc: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x5edad0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x5edad4: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x5edae4: (17156820, 'OBJC_IVAR_$_InteractionObject.needsToBeRemovedWhenInteractionEnds', 96),
        },
        classes={},
        instructions=[(6215588, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6216424, 'adceq r2, r7, r8, lsr r3')],
        calls=[(6215792, 'blx r2'), (6215952, 'blx r2'), (6216132, 'bl loc.imp.objc_msgSend'), (6216220, 'bl loc.imp.objc_msgSend'), (6216312, 'blx ip'), (6216340, 'blx r3')],
        branches=[(6215652, 'bne', 6215692), (6215688, 'beq', 6215696), (6215692, 'b', 6216344), (6215728, 'beq', 6215960), (6215804, 'bne', 6215856), (6215848, 'beq', 6215892), (6215852, 'b', 6215856), (6215888, 'b', 6216344), (6215956, 'b', 6215960)],
        semantics=('[TradingPost -[remove:]] (imp 0x005ed7a4, 210w): -[remove:] (0x5ed7a4, 210w): early-return when needsRemoved@48 or isNet@52. If InteractionObject.isInUse@68: when [currentBlockhead isNet] or remoteBlockheadInUseUniqueID@72 != 0 -> set needsToBeRemovedWhenInteractionEnds@96=1 and return (defer); otherwise [currentBlockhead stopInteracting]. Removal: sd=[self getSaveDict]; [self.dynamicWorld createFreeBlockAtPosition:self.pos ofType:0xa8 dataA:0 dataB:0 subItems:0 dynamicObjectSaveDict:sd hovers:0 playSound:1 priorityBlockhead:<remove: arg>] (stack block at 0x5eda00-0x5eda1c); [self.world removeTileAtWorldX:pos.x worldY:pos.y createContentsFreeblockCount:0 createForegroundContentsFreeblockCount:0 removeBlockhead:<arg>]; then [self setNeedsRemoved:1]..\n'),
    ),
    dict(
        name='tp_31',
        method='TradingPost -[removeFromMacroBlock]',
        types='v8@0:4',
        start=6235624,
        end=6236212,
        disasm='disasm_worldtileloader_tp_31.txt',
        base_add=6235640,
        base_literal=6236208,
        boundary='ARM.exidx end 0x005f2834 (listing bound); next ObjC IMP 0x005f2834 TradingPost -[interactionRenderItemType]',
        selectors={
                 0x5f2818: (15198760, 'removeFromMacroBlock'),
                 0x5f282c: (15198468, 'macroTiles'),
        },
        imports={
                 0x5f2814: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0x5f2820: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x5f2828: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={
                 0x5f281c: (15252580, 'OBJC_CLASS_$_TradingPost'),
        },
        instructions=[(6235624, 'push {r4, sl, fp, lr}'), (6236208, 'invalid')],
        calls=[(6235744, 'bl loc.imp.objc_msgSend'), (6235788, 'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_'), (6235848, 'bl loc.imp.objc_msgSend'), (6235892, 'bl sym.reloadDrawBlockDynamicObjectItemQuadsForTile_intpair__MacroTile__World_'), (6235952, 'bl loc.imp.objc_msgSend'), (6235996, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (6236056, 'bl loc.imp.objc_msgSend'), (6236100, 'bl sym.reloadDrawBlockDodoEggQuadsForTile_intpair__MacroTile__World_'), (6236168, 'blx r3')],
        branches=[],
        semantics=('[TradingPost -[removeFromMacroBlock]] (imp 0x005f25e8, 147w): -[removeFromMacroBlock] (0x5f25e8, 147w): for self.pos it calls the 4 static-geometry reloads with [world macroTiles] - reloadDrawBlockDynamicObjectStaticGeometryForTile / ItemQuadsForTile / QuadsForTile / DodoEggQuadsForTile (0x5f268c/0x5f26f4/0x5f275c/0x5f27c4) - then objc_msgSendSuper2 -removeFromMacroBlock (class TradingPost)..\n'),
    ),
    dict(
        name='tp_32',
        method='TradingPost -[requiresHumanInteraction]',
        types='c8@0:4',
        start=6216684,
        end=6216712,
        disasm='disasm_worldtileloader_tp_32.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x005edc08 (listing bound); next ObjC IMP 0x005edc08 TradingPost -[blockheadIsSeller:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6216684, 'sub sp, sp, 8'), (6216708, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TradingPost -[requiresHumanInteraction]] (imp 0x005edbec, 7w): -[requiresHumanInteraction] (0x5edbec, 7w): returns YES (1)..\n'),
    ),
    dict(
        name='tp_33',
        method='TradingPost -[sellSlot]',
        types='@8@0:4',
        start=6236620,
        end=6236688,
        disasm='disasm_worldtileloader_tp_33.txt',
        base_add=6236644,
        base_literal=6236684,
        boundary='ARM.exidx end 0x005f2a10 (listing bound); next ObjC IMP 0x005f2a10 TradingPost -[coinCount]',
        selectors={},
        imports={},
        ivars={
                 0x5f2a08: (17156760, 'OBJC_IVAR_$_TradingPost.sellSlot', 100),
        },
        classes={},
        instructions=[(6236620, 'sub sp, sp, 0xc'), (6236684, 'adceq sp, r6, r8, lsl 2')],
        calls=[],
        branches=[],
        semantics=('[TradingPost -[sellSlot]] (imp 0x005f29cc, 17w): -[sellSlot] (0x5f29cc, 17w): Apportable offset-cell getter for sellSlot@100 (NSMutableArray) behind dmb ish; plain pointer return..\n'),
    ),
    dict(
        name='tp_34',
        method='TradingPost -[sellTitle]',
        types='@8@0:4',
        start=6219952,
        end=6220284,
        disasm='disasm_worldtileloader_tp_34.txt',
        base_add=6219968,
        base_literal=6220280,
        boundary='ARM.exidx end 0x005ee9fc (listing bound); next ObjC IMP 0x005ee9fc TradingPost -[staticGeometryDrawCubeCount]',
        selectors={
                 0x5ee9e8: (15198700, 'title'),
                 0x5ee9f0: (15198704, 'stringWithFormat:'),
        },
        imports={
                 0x5ee9e4: (17151904, 'objc_msgSend'),
                 0x5ee9ec: (16245128, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5ee9e0: (17156768, 'OBJC_IVAR_$_TradingPost.sellerClientName', 112),
        },
        classes={
                 0x5ee9f4: (15245580, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(6219952, 'push {r4, r5, r6, sl, fp, lr}'), (6220280, 'adceq r1, r7, ip, lsr 4')],
        calls=[(6220060, 'blx r2'), (6220164, 'blx r2'), (6220236, 'blx lr')],
        branches=[(6220016, 'bne', 6220072), (6220068, 'b', 6220244)],
        semantics=('[TradingPost -[sellTitle]] (imp 0x005ee8b0, 83w): -[sellTitle] (0x5ee8b0, 83w): if sellerClientName@112 == nil -> returns [self title] (\'SHOP\'); else returns [NSString stringWithFormat:@"%@ (%@)", [self title], sellerClientName] (CFSTR \'%@ (%@)\' @0x5ee9ec) - i.e. \'SHOP (name)\' when the post is player-consigned..\n'),
    ),
    dict(
        name='tp_35',
        method='TradingPost -[setCoinCount:]',
        types='v12@0:4i8',
        start=6236748,
        end=6236816,
        disasm='disasm_worldtileloader_tp_35.txt',
        base_add=6236776,
        base_literal=6236812,
        boundary='ARM.exidx end 0x005f2a90 (listing bound); next ObjC IMP 0x005f4218 InteractionObject -[objectType]',
        selectors={},
        imports={},
        ivars={
                 0x5f2a88: (17156784, 'OBJC_IVAR_$_TradingPost.coinCount', 104),
        },
        classes={},
        instructions=[(6236748, 'sub sp, sp, 0xc'), (6236812, 'adceq sp, r6, r4, lsl 1')],
        calls=[],
        branches=[],
        semantics=('[TradingPost -[setCoinCount:]] (imp 0x005f2a4c, 17w): -[setCoinCount:] (0x5f2a4c, 17w): Apportable offset-cell setter for coinCount@104 - dmb ish; str; dmb ish..\n'),
    ),
    dict(
        name='tp_36',
        method='TradingPost -[setPriceTier:]',
        types='v12@0:4i8',
        start=6217456,
        end=6218120,
        disasm='disasm_worldtileloader_tp_36.txt',
        base_add=6217492,
        base_literal=6218088,
        boundary='ARM.exidx end 0x005ee238; body trimmed at the next IMP 0x005ee188 TradingPost -[currentBlockheadCash]',
        selectors={
                 0x5ee174: (15198652, 'objectType'),
                 0x5ee178: (15198656, 'dynamicWorldChangedAtPos:objectType:'),
                 0x5ee184: (15198468, 'macroTiles'),
        },
        imports={},
        ivars={
                 0x5ee164: (17156780, 'OBJC_IVAR_$_TradingPost.priceTier', 108),
                 0x5ee16c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x5ee170: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x5ee17c: (17156764, 'OBJC_IVAR_$_TradingPost.needsToUpdateBitmapString', 124),
                 0x5ee180: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(6217456, 'push {fp, lr}'), (6218116, 'invalid')],
        calls=[(6217584, 'bl loc.imp.objc_msgSend'), (6217620, 'bl loc.imp.objc_msgSend'), (6217716, 'bl loc.imp.objc_msgSend'), (6217760, 'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_'), (6217820, 'bl loc.imp.objc_msgSend'), (6217864, 'bl sym.reloadDrawBlockDynamicObjectItemQuadsForTile_intpair__MacroTile__World_'), (6217924, 'bl loc.imp.objc_msgSend'), (6217968, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (6218028, 'bl loc.imp.objc_msgSend'), (6218072, 'bl sym.reloadDrawBlockDodoEggQuadsForTile_intpair__MacroTile__World_')],
        branches=[],
        semantics=('[TradingPost -[setPriceTier:]] (imp 0x005edef0, 166w): -[setPriceTier:] (0x5edef0, 166w, listing TRIMMED at the next IMP): self.priceTier@108 = arg; [self.dynamicWorld dynamicWorldChangedAtPos:self.pos objectType:[self objectType]]; needsToUpdateBitmapString@124=1; then the 4 static-geometry reloads. No isNet gate (server-authoritative setter)..\n'),
    ),
    dict(
        name='tp_37',
        method='TradingPost -[staticGeometryDodoEggCount]',
        types='i8@0:4',
        start=6234336,
        end=6234660,
        disasm='disasm_worldtileloader_tp_37.txt',
        base_add=6234352,
        base_literal=6234656,
        boundary='ARM.exidx end 0x005f2224 (listing bound); next ObjC IMP 0x005f2224 TradingPost -[addDodoEggDrawQuadData:fromIndex:]',
        selectors={
                 0x5f220c: (15198620, 'count'),
                 0x5f2214: (15198440, 'itemType'),
                 0x5f2218: (15198612, 'lastObject'),
                 0x5f221c: (15198624, 'dataB'),
        },
        imports={
                 0x5f2208: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5f2210: (17156760, 'OBJC_IVAR_$_TradingPost.sellSlot', 100),
        },
        classes={},
        instructions=[(6234336, 'push {r4, sl, fp, lr}'), (6234656, 'invalid')],
        calls=[(6234420, 'blx r3'), (6234512, 'blx ip'), (6234536, 'blx r2'), (6234588, 'blx r2')],
        branches=[(6234428, 'bls', 6234620), (6234544, 'bne', 6234616), (6234600, 'beq', 6234616), (6234616, 'b', 6234620)],
        semantics=('[TradingPost -[staticGeometryDodoEggCount]] (imp 0x005f20e0, 81w): -[staticGeometryDodoEggCount] (0x5f20e0, 81w): count=0; if [sellSlot count] != 0: obj=[sellSlot lastObject]; if [obj itemType]==0x5b and (u16)[obj dataB]!=0 -> 1. So 1 iff the last sell-slot item is a live dodo egg (the same predicate tp_01 renders for)..\n'),
    ),
    dict(
        name='tp_38',
        method='TradingPost -[staticGeometryDrawCubeCount]',
        types='i8@0:4',
        start=6220284,
        end=6220568,
        disasm='disasm_worldtileloader_tp_38.txt',
        base_add=6220300,
        base_literal=6220560,
        boundary='ARM.exidx end 0x005eeb18 (listing bound); next ObjC IMP 0x005eeb18 TradingPost -[addDrawCubeData:fromIndex:]',
        selectors={
                 0x5eeb00: (15198620, 'count'),
                 0x5eeb08: (15198440, 'itemType'),
                 0x5eeb0c: (15198612, 'lastObject'),
        },
        imports={
                 0x5eeafc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5eeb04: (17156760, 'OBJC_IVAR_$_TradingPost.sellSlot', 100),
        },
        classes={},
        instructions=[(6220284, 'push {r4, sl, fp, lr}'), (6220564, 'andeq r0, r0, r0')],
        calls=[(6220368, 'blx r3'), (6220460, 'blx ip'), (6220484, 'blx r2'), (6220496, 'bl sym.itemTypeIsBlock_ItemType_')],
        branches=[(6220376, 'bls', 6220528), (6220508, 'beq', 6220524), (6220524, 'b', 6220528)],
        semantics=('[TradingPost -[staticGeometryDrawCubeCount]] (imp 0x005ee9fc, 71w): -[staticGeometryDrawCubeCount] (0x5ee9fc, 71w): count=3 (the post body cubes); if [sellSlot count]!=0 and itemTypeIsBlock([sellSlot lastObject].itemType) -> count++ (itemTypeIsBlock check at 0x5eead0). Returns 3 or 4 - the DrawCube count tp_02 will emit for this post..\n'),
    ),
    dict(
        name='tp_39',
        method='TradingPost -[staticGeometryDrawItemQuadCount]',
        types='i8@0:4',
        start=6229212,
        end=6229836,
        disasm='disasm_worldtileloader_tp_39.txt',
        base_add=6229228,
        base_literal=6229832,
        boundary='ARM.exidx end 0x005f0f4c (listing bound); next ObjC IMP 0x005f0f9c TradingPost -[addDrawItemQuadData:fromIndex:]',
        selectors={
                 0x5f0f20: (15198620, 'count'),
                 0x5f0f28: (15198440, 'itemType'),
                 0x5f0f2c: (15198612, 'lastObject'),
                 0x5f0f30: (15198624, 'dataB'),
                 0x5f0f38: (15198712, 'isEqualToString:'),
                 0x5f0f3c: (15198708, 'localNetID'),
        },
        imports={
                 0x5f0f1c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5f0f24: (17156760, 'OBJC_IVAR_$_TradingPost.sellSlot', 100),
                 0x5f0f34: (17156784, 'OBJC_IVAR_$_TradingPost.coinCount', 104),
                 0x5f0f40: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x5f0f44: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
        },
        classes={},
        instructions=[(6229212, 'push {r4, r5, fp, lr}'), (6229832, 'adceq lr, r6, r0, lsl 28')],
        calls=[(6229296, 'blx r3'), (6229388, 'blx ip'), (6229412, 'blx r2'), (6229424, 'bl sym.itemTypeIsBlock_ItemType_'), (6229480, 'blx r2'), (6229532, 'blx r2'), (6229552, 'bl 0x5f0f4c'), (6229716, 'blx ip'), (6229748, 'blx r3')],
        branches=[(6229304, 'bls', 6229572), (6229436, 'bne', 6229568), (6229488, 'bne', 6229548), (6229544, 'bne', 6229568), (6229568, 'b', 6229572), (6229604, 'ble', 6229776), (6229760, 'beq', 6229776)],
        semantics=('[TradingPost -[staticGeometryDrawItemQuadCount]] (imp 0x005f0cdc, 156w): -[staticGeometryDrawItemQuadCount] (0x5f0cdc, 156w): count=0; if sellSlot non-empty: it=[[sellSlot lastObject] itemType]; if !itemTypeIsBlock(it) and !(it==0x5b && (u16)dataB!=0) -> count += helper 0x5f0f4c(it) = (it==103 || itemTypeCanBeColored(it)) ? 2 : 1; then if coinCount@104 > 0 and [[dynamicWorld localNetID] isEqualToString:ownerID@36] -> count++ (the coin pile). Exact per-item quad budget for tp_03..\n'),
    ),
    dict(
        name='tp_40',
        method='TradingPost -[staticGeometryDrawQuadCountForMacroPos:]',
        types='i16@0:4{?=ii}8',
        start=6228196,
        end=6228232,
        disasm='disasm_worldtileloader_tp_40.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x005f0908 (listing bound); next ObjC IMP 0x005f0908 TradingPost -[addDrawQuadData:fromIndex:forMacroPos:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6228196, 'sub sp, sp, 0x10'), (6228228, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TradingPost -[staticGeometryDrawQuadCountForMacroPos:]] (imp 0x005f08e4, 9w): -[staticGeometryDrawQuadCountForMacroPos:] (0x5f08e4, 9w): returns 1 - one plain quad slot per macro position..\n'),
    ),
    dict(
        name='tp_41',
        method='TradingPost -[title]',
        types='@8@0:4',
        start=6216456,
        end=6216504,
        disasm='disasm_worldtileloader_tp_41.txt',
        base_add=6216464,
        base_literal=6216500,
        boundary='ARM.exidx end 0x005edb38 (listing bound); next ObjC IMP 0x005edb38 TradingPost -[actionTitle]',
        selectors={},
        imports={
                 0x5edb30: (16245032, '__CFConstantStringClassReference'),
        },
        ivars={},
        classes={},
        instructions=[(6216456, 'sub sp, sp, 8'), (6216500, 'invalid')],
        calls=[],
        branches=[],
        semantics=('[TradingPost -[title]] (imp 0x005edb08, 12w): -[title] (0x5edb08, 12w): returns the constant CFSTR \'SHOP\' (cell 0x5edb30)..\n'),
    ),
    dict(
        name='tp_42',
        method='TradingPost -[updateBitmapString]',
        types='v8@0:4',
        start=6209392,
        end=6210600,
        disasm='disasm_worldtileloader_tp_42.txt',
        base_add=6209408,
        base_literal=6210596,
        boundary='ARM.exidx end 0x005ec428 (listing bound); next ObjC IMP 0x005ece18 TradingPost -[worldChanged:]',
        selectors={
                 0x5ec3e0: (15198620, 'count'),
                 0x5ec3f0: (15198560, 'release'),
                 0x5ec3f8: (15198664, 'price'),
                 0x5ec404: (15198416, 'alloc'),
                 0x5ec40c: (15198672, 'embossedFont'),
                 0x5ec414: (15198668, 'blackFont'),
                 0x5ec420: (15198676, 'initWithString:dimensions:horizontalAlignment:font:cache:color:'),
        },
        imports={
                 0x5ec3dc: (17151904, 'objc_msgSend'),
                 0x5ec3e8: (16245016, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5ec3e4: (17156760, 'OBJC_IVAR_$_TradingPost.sellSlot', 100),
                 0x5ec3ec: (17156796, 'OBJC_IVAR_$_TradingPost.bitmapString', 120),
                 0x5ec3f4: (17156764, 'OBJC_IVAR_$_TradingPost.needsToUpdateBitmapString', 124),
                 0x5ec3fc: (17156800, 'OBJC_IVAR_$_InteractionObject.paintColor', 88),
                 0x5ec400: (17156808, 'OBJC_IVAR_$_TradingPost.blackText', 126),
                 0x5ec418: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
        },
        classes={
                 0x5ec408: (15245572, 'OBJC_CLASS_$_BitmapString'),
                 0x5ec410: (15245576, 'OBJC_CLASS_$_BitmapFont'),
        },
        instructions=[(6209392, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6210596, 'adceq r3, r7, ip, ror 22')],
        calls=[(6209568, 'blx r3'), (6209640, 'blx r3'), (6209692, 'blx r2'), (6209704, 'bl 0x5ec428'), (6209832, 'bl method.Vector.Vector_float__float__float__float_'), (6209884, 'bl 0x5ec7e0'), (6209924, 'bl method.Vector.operator_float__'), (6209948, 'bl method.Vector.operator_float__'), (6209968, 'bl method.Vector.operator_float__'), (6210104, 'blx r2'), (6210148, 'bl 0x5ecdec'), (6210236, 'blx r2'), (6210296, 'blx r2'), (6210396, 'bl 0x5e9a2c'), (6210492, 'bl loc.imp.objc_msgSend')],
        branches=[(6209648, 'bls', 6209712), (6209724, 'beq', 6210516), (6209788, 'beq', 6210056), (6210016, 'ble', 6210052), (6210052, 'b', 6210056), (6210184, 'beq', 6210248), (6210244, 'b', 6210304)],
        semantics=('[TradingPost -[updateBitmapString]] (imp 0x005ebf70, 302w): -[updateBitmapString] (0x5ebf70, 302w): clears needsToUpdateBitmapString@124; releases+nils bitmapString@120; str = @"CLOSED" (CFSTR 0x5ec3e8) or, when [sellSlot count] > 0, priceString([self price]) via local helper 0x5ec428; if str==nil return. blackText@126=0; if paintColor@88 != 0 build a white Vector then replace it with the packed-16 RGBA (0x5ec7e0) and set blackText = (green > 0.75 - 0.25*(red+blue)) - VFP truth from the _gl listing: vmov.f64 d1,#104 = 0.75, d2,#80 = 0.25, vcmpe+ble at 0x5ec1d8 - exactly the Sign sg_33 luminance rule. Then bitmapString@120 = [[BitmapString alloc] initWithString:str dimensions:{128.0f (0x43000000), 48.0f (0x42400000)} (Vec2 store 0x5ecdec) horizontalAlignment:1 font:(blackText ? [BitmapFont blackFont] : [BitmapFont embossedFont]) cache:self.cache@32 color:(1,1,1,1) (Vector via 0x5e9a2c)]. price helper 0x5ec428 formats with [NSString stringWithUTF8String:] + stringWithFormat: and currency glyphs: <100 -> "%d¥"; 100..9999 -> "%d€ %d¥" (units,rem) or "%d€" when rem==0; >=10000 -> "%d₽ %d€" (big,rem2) or "%d₽" (the yen remainder is dropped in this branch; U+20AC euro / U+20BD ruble-sign glyphs as compiled)..\n'),
    ),
    dict(
        name='tp_43',
        method='TradingPost -[updateNetDataForClient:]',
        types='@12@0:4@8',
        start=6185160,
        end=6186956,
        disasm='disasm_worldtileloader_tp_43.txt',
        base_add=6185176,
        base_literal=6186952,
        boundary='ARM.exidx end 0x005e67cc (listing bound); next ObjC IMP 0x005e6938 TradingPost -[creationNetDataForClient:]',
        selectors={
                 0x5e6760: (15198524, 'interactionObjectCreationNetData'),
                 0x5e676c: (15198532, 'dictionary'),
                 0x5e6774: (15198528, 'dataWithBytes:length:'),
                 0x5e678c: (15198536, 'setObject:forKey:'),
                 0x5e67a0: (15198428, 'countByEnumeratingWithState:objects:count:'),
                 0x5e67a8: (15198540, 'array'),
                 0x5e67b0: (15198440, 'itemType'),
                 0x5e67b4: (15198444, 'addObject:'),
                 0x5e67b8: (15198544, 'saveData'),
                 0x5e67c0: (15198552, 'appendData:'),
                 0x5e67c4: (15198548, 'gzipDeflate'),
        },
        imports={
                 0x5e6768: (17151904, 'objc_msgSend'),
                 0x5e6788: (16244952, '__CFConstantStringClassReference'),
                 0x5e6790: (16244920, '__CFConstantStringClassReference'),
                 0x5e6798: (16244968, '__CFConstantStringClassReference'),
                 0x5e67bc: (16244728, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5e6764: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
                 0x5e677c: (17156780, 'OBJC_IVAR_$_TradingPost.priceTier', 108),
                 0x5e6780: (17156784, 'OBJC_IVAR_$_TradingPost.coinCount', 104),
                 0x5e6784: (17156768, 'OBJC_IVAR_$_TradingPost.sellerClientName', 112),
                 0x5e6794: (17156788, 'OBJC_IVAR_$_InteractionObject.ownerName', 84),
                 0x5e679c: (17156792, 'OBJC_IVAR_$_TradingPost.inventoryNeedsToBeSentWithUpdate', 125),
                 0x5e67a4: (17156760, 'OBJC_IVAR_$_TradingPost.sellSlot', 100),
        },
        classes={
                 0x5e6770: (15245564, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x5e6778: (15245560, 'OBJC_CLASS_$_NSMutableData'),
                 0x5e67ac: (15245548, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(6185160, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6186952, 'adceq sb, r7, r4, lsl sl')],
        calls=[(6185252, 'bl loc.imp.objc_msgSend_stret'), (6185288, 'bl sym.imp.memset'), (6185472, 'bl sym.imp.memcpy'), (6185560, 'blx ip'), (6185596, 'blx r3'), (6185728, 'blx ip'), (6185848, 'blx ip'), (6185980, 'blx ip'), (6186136, 'blx r2'), (6186160, 'bl sym.imp.memset'), (6186224, 'blx lr'), (6186324, 'bl sym.imp.objc_enumerationMutation'), (6186396, 'blx r2'), (6186476, 'blx ip'), (6186508, 'blx r3'), (6186612, 'blx ip'), (6186712, 'blx ip'), (6186744, 'bl 0x5e67cc'), (6186804, 'blx lr'), (6186832, 'blx r3')],
        branches=[(6185236, 'beq', 6185260), (6185256, 'b', 6185292), (6185632, 'beq', 6185856), (6185760, 'beq', 6185852), (6185852, 'b', 6185856), (6185892, 'beq', 6185984), (6186016, 'beq', 6186740), (6186236, 'beq', 6186636), (6186316, 'beq', 6186328), (6186404, 'beq', 6186512), (6186512, 'b', 6186516), (6186540, 'blo', 6186280), (6186632, 'bne', 6186280), (6186636, 'b', 6186640)],
        semantics=('[TradingPost -[updateNetDataForClient:]] (imp 0x005e60c8, 449w): [census-lite] -[updateNetDataForClient:] (0x5e60c8, 449w): builds the wire blob. block = NSMutableData dataWithBytes:... length:0x30 = {[self interactionObjectCreationNetData] 0x28-byte super struct (objc_msgSend_stret, memset 0 when self nil) + coinCount@104 int at +0x28 + priceTier@108 short at +0x2c}. dict = [NSMutableDictionary dictionary]; if ownerID@36 != nil: [dict setObject:ownerID forKey:@"ownerID"] and (if sellerClientName != nil) [dict setObject:sellerClientName forKey:@"sellerClientName"]; if ownerName@84 != nil -> forKey:@"ownerName". If inventoryNeedsToBeSentWithUpdate@125: arr=[NSMutableArray array]; fast-enumerate sellSlot (countByEnumeratingWithState, objc_enumerationMutation guarded); per item: if [item itemType] != 0xb -> [arr addObject:[item saveData]]; [dict setObject:arr forKey:@"sellSlot"]; flag=0. Finally [block appendData:[[plistFromObject helper 0x5e67cc] gzipDeflate]] and return block; 0x5e67cc = @try [NSPropertyListSerialization dataWithPropertyList:obj format:100 options:0 error:&err] @catch NSLog(name,reason)..\n'),
    ),
    dict(
        name='tp_44',
        method='TradingPost -[worldChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=6213144,
        end=6215344,
        disasm='disasm_worldtileloader_tp_44.txt',
        base_add=6213160,
        base_literal=6215340,
        boundary='ARM.exidx end 0x005ed6b0 (listing bound); next ObjC IMP 0x005ed6ec TradingPost -[worldContentsChanged:]',
        selectors={
                 0x5ed684: (15198580, 'worldWidthMacro'),
                 0x5ed6a8: (15198680, 'remove:'),
        },
        imports={
                 0x5ed6a4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5ed674: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x5ed678: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x5ed680: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(6213144, 'push {r4, r5, fp, lr}'), (6215340, 'adceq r2, r7, r4, asr 25')],
        calls=[(6213572, 'bl loc.imp.objc_msgSend'), (6213596, 'bl sym.imp.__aeabi_idiv'), (6213692, 'bl loc.imp.objc_msgSend'), (6213812, 'bl loc.imp.objc_msgSend'), (6213828, 'bl sym.imp.__aeabi_idiv'), (6213924, 'bl loc.imp.objc_msgSend'), (6214008, 'bl 0x5ed6b0'), (6214180, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6214208, 'bl sym.tileIsSolid_Tile_'), (6214312, 'bl sym.makeIntpair_int__int_'), (6214332, 'bl sym.tileIsHalfDepth_Tile__World__intpair_'), (6214436, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6214560, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6214624, 'bl sym.makeIntpair_int__int_'), (6214644, 'bl sym.tileIsHalfDepth_Tile__World__intpair_'), (6214680, 'bl sym.tileIsSolid_Tile_'), (6214780, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6214844, 'bl sym.makeIntpair_int__int_'), (6214864, 'bl sym.tileIsHalfDepth_Tile__World__intpair_'), (6214900, 'bl sym.tileIsSolid_Tile_'), (6215000, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6215064, 'bl sym.makeIntpair_int__int_'), (6215084, 'bl sym.tileIsHalfDepth_Tile__World__intpair_'), (6215120, 'bl sym.tileIsSolid_Tile_'), (6215180, 'blx r3')],
        branches=[(6213208, 'beq', 6213216), (6213212, 'b', 6215276), (6213452, 'beq', 6215276), (6213608, 'blt', 6213724), (6213720, 'b', 6214004), (6213840, 'bge', 6213956), (6213952, 'b', 6213996), (6214016, 'bge', 6215212), (6214060, 'beq', 6214104), (6214100, 'blt', 6215212), (6214200, 'beq', 6215208), (6214220, 'bne', 6215208), (6214344, 'bne', 6215204), (6214360, 'beq', 6215204), (6214456, 'beq', 6215200), (6214472, 'bne', 6215200), (6214656, 'bne', 6215196), (6214672, 'beq', 6215196), (6214692, 'bne', 6215196), (6214876, 'bne', 6215192), (6214892, 'beq', 6215192), (6214912, 'bne', 6215192), (6215096, 'bne', 6215188), (6215112, 'beq', 6215188), (6215132, 'bne', 6215188), (6215184, 'b', 6215276), (6215188, 'b', 6215192), (6215192, 'b', 6215196), (6215196, 'b', 6215200), (6215200, 'b', 6215204), (6215204, 'b', 6215208), (6215208, 'b', 6215212), (6215212, 'b', 6215216), (6215272, 'b', 6213300)],
        semantics=('[TradingPost -[worldChanged:]] (imp 0x005ece18, 550w): [census-lite] -[worldChanged:](std::vector<intpair>*) (0x5ece18, 550w): early-return when isNet@52. Iterates the changed-position vector (begin/end pair at [fp,-0x50]/[fp,-0x90], 8-byte stride): dx = self.pos.x - p.x wrapped toroidally by +-worldWidthMacro*32 (two idiv-by-2 comparisons, 0x5ecfe4/0x5ed0d0; helper 0x5ed6b0 = abs); if |dx| >= 2 -> next position; then require p.y == pos.y-1 or p.y >= pos.y; support probe: tile = tileAtWorldPositionLoaded(pos.x, pos.y-1, world); if !tile or tileIsSolid(tile) -> continue; then 4 neighbour probes (pos.x,pos.y-1)/(pos.x-1,pos.y)/(pos.x+1,pos.y)/(pos.x,pos.y+1): each tileAtWorldPositionLoaded + tileIsHalfDepth(tile,world,pair) + tile byte+3 == 0x60 + tileIsSolid - any hit -> continue; when all four probes pass it calls [self remove:nil] (0x5ed60c). Pure client-side unsupported-object cleanup, no network write..\n'),
    ),
    dict(
        name='tp_45',
        method='TradingPost -[worldContentsChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=6215404,
        end=6215428,
        disasm='disasm_worldtileloader_tp_45.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x005ed704 (listing bound); next ObjC IMP 0x005ed704 TradingPost -[freeblockCreationItemType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6215404, 'sub sp, sp, 0xc'), (6215424, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TradingPost -[worldContentsChanged:]] (imp 0x005ed6ec, 6w): -[worldContentsChanged:] (0x5ed6ec, 6w): empty void override - the post ignores world contents changes (all its reaction lives in tp_08 contentsDidChange / tp_44 worldChanged:)..\n'),
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
        'batch': 'TradingPost (E151): the consignment shop; 46 bodies',
        'claim': ('the consignment trading post (sell slot, price table, coin settlement)'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'tradingpost.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale tradingpost.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
